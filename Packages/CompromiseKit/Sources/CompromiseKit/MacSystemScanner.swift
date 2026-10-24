#if os(macOS)
import AppKit
import Darwin
import Foundation
import Security

/// One row of the Mac scan: a setting, or a group of things we looked at.
public struct SystemCheck: Identifiable, Codable, Hashable, Sendable {
    public enum Status: String, Codable, Comparable, Sendable {
        case good, info, unknown, warning, alert
        private var rank: Int { [.good: 0, .info: 1, .unknown: 2, .warning: 3, .alert: 4][self]! }
        public static func < (a: Status, b: Status) -> Bool { a.rank < b.rank }
    }

    public var id: String
    public var title: String
    public var status: Status
    public var detail: String
    /// What was found, one line each, for the detail screen.
    public var items: [String] = []
}

public struct MacScanReport: Codable, Sendable {
    public var scannedAt: Date
    public var fullAccess: Bool
    public var checks: [SystemCheck]
    public var findings: [Finding]
    public var indicatorCount: Int

    public var matches: [Finding] { findings.filter { $0.level == .match } }
    public var worstStatus: SystemCheck.Status {
        if !matches.isEmpty { return .alert }
        return checks.map(\.status).max() ?? .unknown
    }
}

/// Looks at this Mac for known spyware traces and weak settings.
///
/// `fullAccess` is the direct-download build: it reads system folders, runs
/// Apple's command-line tools and inspects every process. The App Store build
/// runs sandboxed and gets only what the sandbox allows.
public struct MacSystemScanner {
    let indicators: IndicatorSet
    let scanner: LogScanner
    let fullAccess: Bool

    public init(indicators: IndicatorSet, fullAccess: Bool) {
        self.indicators = indicators
        self.scanner = LogScanner(indicators: indicators)
        self.fullAccess = fullAccess
    }

    public func scan(progress: @Sendable (Double, String) -> Void = { _, _ in }) -> MacScanReport {
        var checks: [SystemCheck] = []
        var findings: [Finding] = []
        let steps: [(String, () -> Void)] = fullAccess
            ? [
                ("Security settings", { checks += securitySettings() }),
                ("Running programs", { let r = processes(); checks.append(r.0); findings += r.1 }),
                ("Startup items", { let r = launchItems(); checks.append(r.0); findings += r.1 }),
                ("Profiles and device management", { checks.append(profiles()) }),
                ("System extensions", { checks.append(systemExtensions()) }),
                ("Hosts file", { let r = hostsFile(); checks.append(r.0); findings += r.1 }),
                ("Crash reports", { let r = diagnosticLogs(); checks.append(r.0); findings += r.1 }),
            ]
            : [
                ("Running apps", { let r = runningApps(); checks.append(r.0); findings += r.1 }),
            ]
        for (i, (name, step)) in steps.enumerated() {
            progress(Double(i) / Double(steps.count), name)
            step()
        }
        progress(1, "Done")
        return MacScanReport(scannedAt: Date(), fullAccess: fullAccess, checks: checks,
                             findings: findings, indicatorCount: indicators.total)
    }

    // MARK: Security settings

    func securitySettings() -> [SystemCheck] {
        var out: [SystemCheck] = []

        let sip = run("/usr/bin/csrutil", ["status"])
        out.append(SystemCheck(
            id: "sip", title: "System Integrity Protection",
            status: sip.contains("enabled") ? .good : (sip.isEmpty ? .unknown : .alert),
            detail: sip.contains("enabled")
                ? "On. Protects system files from being changed, even by administrators."
                : "Off or reduced. Malware can modify the system. Turn it back on from Recovery unless you turned it off on purpose."))

        let gk = run("/usr/sbin/spctl", ["--status"])
        out.append(SystemCheck(
            id: "gatekeeper", title: "Gatekeeper",
            status: gk.contains("enabled") ? .good : (gk.isEmpty ? .unknown : .warning),
            detail: gk.contains("enabled")
                ? "On. Only apps from the App Store or identified developers open without a warning."
                : "Off. Any app can run without Apple's check. Turn it on in System Settings › Privacy & Security."))

        let fv = run("/usr/bin/fdesetup", ["isactive"]).trimmingCharacters(in: .whitespacesAndNewlines)
        out.append(SystemCheck(
            id: "filevault", title: "FileVault",
            status: fv == "true" ? .good : (fv.isEmpty ? .unknown : .warning),
            detail: fv == "true"
                ? "On. Your disk is encrypted when the Mac is off."
                : "Off. Someone with physical access can read your files. Turn it on in System Settings › Privacy & Security."))

        let fw = run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"])
        let fwOn = fw.contains("enabled") || fw.contains("State = 1") || fw.contains("State = 2")
        out.append(SystemCheck(
            id: "firewall", title: "Firewall",
            status: fwOn ? .good : (fw.isEmpty ? .unknown : .info),
            detail: fwOn ? "On." : "Off. Worth turning on in System Settings › Network › Firewall, especially on public Wi-Fi."))

        let critical = run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let responsesOff = critical == "0"
        out.append(SystemCheck(
            id: "responses", title: "Security responses",
            status: responsesOff ? .warning : .good,
            detail: responsesOff
                ? "Automatic security responses are off. Turn on \"Install Security Responses and system files\" in System Settings › General › Software Update › Automatic Updates."
                : "Security responses and system data files install automatically."))

        let ldm = run("/usr/bin/defaults", ["read", ".GlobalPreferences", "LDMGlobalEnabled"])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        out.append(SystemCheck(
            id: "lockdown", title: "Lockdown Mode",
            status: .info,
            detail: ldm == "1"
                ? "On. Blocks most of the ways mercenary spyware gets in."
                : "Off. If you might be targeted (journalist, activist, lawyer, official), turn it on in System Settings › Privacy & Security."))
        return out
    }

    // MARK: Processes

    /// Folders where legitimate software rarely runs from.
    static let unusualDirs = ["/tmp/", "/private/tmp/", "/private/var/tmp/", "/var/tmp/", "/Users/Shared/"]

    func processes() -> (SystemCheck, [Finding]) {
        var findings = Findings(file: "Running programs")
        var unsigned: [String] = [], unusual: [String] = []
        var seen = Set<String>()
        for path in Self.runningExecutables() where seen.insert(path).inserted {
            if let c = scanner.campaign(forProcess: path) ?? scanner.campaign(forPath: path) {
                findings.add(.match, "Running process", path, c, "A running program has the name or location of this spyware's components.")
            }
            let signature = Self.signature(of: path)
            guard signature == .unsigned else { continue }
            // Signed code in an odd folder (game launchers in /Users/Shared,
            // ~/.pyenv) is common; unsigned code there is what we flag.
            if Self.unusualDirs.contains(where: path.hasPrefix) || path.contains("/.") {
                unusual.append(path)
            } else {
                unsigned.append(path)
            }
        }
        for path in unusual {
            findings.add(.suspicious, "Program in an unusual place", path, nil,
                         "Unsigned and running from a temporary, shared or hidden folder, which malware often uses. Some developer tools do this too.")
        }
        let status: SystemCheck.Status = !findings.items.filter({ $0.level == .match }).isEmpty ? .alert
            : (!unusual.isEmpty || !unsigned.isEmpty) ? .warning : .good
        var detail = "Checked \(seen.count) running programs against the indicator lists."
        if !unsigned.isEmpty { detail += " \(unsigned.count) aren't signed by a known developer; that's normal for some developer and open-source tools, but worth a look." }
        return (SystemCheck(id: "processes", title: "Running programs", status: status, detail: detail,
                            items: unusual + unsigned.map { "Unsigned: \($0)" }), findings.items)
    }

    /// Executable path of every process we're allowed to see.
    static func runningExecutables() -> [String] {
        var pids = [pid_t](repeating: 0, count: 4096)
        let count = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        guard count > 0 else { return [] }
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        return pids.prefix(Int(count)).compactMap { pid in
            guard pid > 0, proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
            return String(cString: buffer)
        }
    }

    // MARK: Running apps (sandboxed build)

    func runningApps() -> (SystemCheck, [Finding]) {
        var findings = Findings(file: "Running apps")
        var unsigned: [String] = []
        let apps = NSWorkspace.shared.runningApplications
        for app in apps {
            guard let path = app.executableURL?.path else { continue }
            if let c = scanner.campaign(forProcess: path) ?? app.bundleIdentifier.flatMap(scanner.campaign(forApp:)) {
                findings.add(.match, "Running app", app.localizedName ?? path, c, "A running app matches this spyware's indicators.")
            }
            if case .unsigned = Self.signature(of: path) { unsigned.append(app.localizedName ?? path) }
        }
        let status: SystemCheck.Status = !findings.items.isEmpty ? .alert : (unsigned.isEmpty ? .good : .warning)
        return (SystemCheck(id: "apps", title: "Running apps", status: status,
                            detail: "Checked \(apps.count) running apps. Apps from the Mac App Store can only see other apps, not background programs or startup items.",
                            items: unsigned.map { "Unsigned: \($0)" }), findings.items)
    }

    // MARK: Startup items

    func launchItems() -> (SystemCheck, [Finding]) {
        var findings = Findings(file: "Startup items")
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let folders = ["\(home)/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"]
        var thirdParty: [String] = [], flagged: [String] = []
        for folder in folders {
            for name in (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? [] where name.hasSuffix(".plist") {
                let plistPath = "\(folder)/\(name)"
                guard let dict = NSDictionary(contentsOfFile: plistPath) as? [String: Any] else { continue }
                let label = dict["Label"] as? String ?? name
                let program = dict["Program"] as? String ?? (dict["ProgramArguments"] as? [String])?.first ?? ""
                thirdParty.append("\(label) → \(program.isEmpty ? "(no program)" : program)")

                if let c = scanner.campaign(forPath: plistPath) ?? scanner.campaign(forPath: program)
                    ?? scanner.campaign(forProcess: program) ?? scanner.campaign(forApp: label) {
                    findings.add(.match, "Startup item", "\(label) (\(program))", c, "This startup item matches this spyware's indicators.")
                    continue
                }
                guard !program.isEmpty, FileManager.default.fileExists(atPath: program),
                      Self.signature(of: program) == .unsigned else { continue }
                if Self.unusualDirs.contains(where: program.hasPrefix) || program.contains("/.") {
                    flagged.append(program)
                    findings.add(.suspicious, "Startup item in an unusual place", "\(label) → \(program)", nil,
                                 "Unsigned and starts automatically from a temporary, shared or hidden folder, a common malware trick.")
                } else {
                    flagged.append(program)
                    findings.add(.suspicious, "Unsigned startup item", "\(label) → \(program)", nil,
                                 "Starts automatically and isn't signed by an identified developer (Homebrew tools and some utilities aren't). Fine if you installed it; otherwise look it up.")
                }
            }
        }
        let hasMatch = findings.items.contains { $0.level == .match }
        return (SystemCheck(
            id: "launch", title: "Startup items",
            status: hasMatch ? .alert : (flagged.isEmpty ? .good : .warning),
            detail: "\(thirdParty.count) non-Apple programs start automatically. Persistence like this is how most Mac malware survives a restart.",
            items: thirdParty), findings.items)
    }

    // MARK: Profiles, extensions, hosts

    func profiles() -> SystemCheck {
        let enrollment = run("/usr/bin/profiles", ["status", "-type", "enrollment"])
        let mdm = enrollment.range(of: "MDM enrollment: Yes", options: .caseInsensitive) != nil
        let list = run("/usr/bin/profiles", ["list"])
        let ids = list.split(separator: "\n").compactMap { line -> String? in
            guard let r = line.range(of: "profileIdentifier:") else { return nil }
            return line[r.upperBound...].trimmingCharacters(in: .whitespaces)
        }
        return SystemCheck(
            id: "profiles", title: "Profiles and device management",
            status: mdm ? .warning : (ids.isEmpty ? .good : .info),
            detail: mdm
                ? "This Mac is managed by an organisation (MDM). That's normal for a work Mac; if it's your personal Mac and you didn't set this up, investigate."
                : (ids.isEmpty ? "No configuration profiles installed for your account."
                               : "\(ids.count) configuration profile(s) installed. Remove any you don't recognise in System Settings › General › Device Management."),
            items: ids)
    }

    func systemExtensions() -> SystemCheck {
        let lines = run("/usr/bin/systemextensionsctl", ["list"]).split(separator: "\n")
            .filter { $0.contains("[activated enabled]") }
            .map { String($0).trimmingCharacters(in: .whitespaces) }
        return SystemCheck(
            id: "sysext", title: "System extensions",
            status: lines.isEmpty ? .good : .info,
            detail: lines.isEmpty
                ? "No third-party system extensions are active."
                : "\(lines.count) active. These run with deep access (network filters, security tools, drivers). Make sure you recognise each one.",
            items: lines)
    }

    func hostsFile() -> (SystemCheck, [Finding]) {
        var findings = Findings(file: "/etc/hosts")
        let text = (try? String(contentsOfFile: "/etc/hosts", encoding: .utf8)) ?? ""
        var custom: [String] = []
        for raw in text.split(separator: "\n") {
            let line = raw.split(separator: "#", maxSplits: 1).first.map(String.init)?
                .trimmingCharacters(in: .whitespaces) ?? ""
            let parts = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard parts.count >= 2 else { continue }
            // macOS's own entries are single-label aliases for this machine;
            // anything with a dot was added by someone.
            for host in parts.dropFirst() where host.contains(".") {
                custom.append("\(host) → \(parts[0])")
                if let c = scanner.campaign(forDomain: host) {
                    findings.add(.match, "Domain in hosts file", host, c, "Your hosts file mentions a domain used by this spyware.")
                } else if ["apple.com", "icloud.com", "mzstatic.com", "google.com"].contains(where: { host == $0 || host.hasSuffix("." + $0) }),
                          !Self.isBlockAddress(parts[0]) {
                    findings.add(.suspicious, "Redirected domain", "\(host) → \(parts[0])", nil,
                                 "Traffic for this well-known domain is sent to another address, which can be used to intercept it.")
                }
            }
        }
        let status: SystemCheck.Status = findings.items.contains { $0.level == .match } ? .alert
            : (findings.items.isEmpty ? (custom.isEmpty ? .good : .info) : .warning)
        return (SystemCheck(id: "hosts", title: "Hosts file", status: status,
                            detail: custom.isEmpty ? "No custom entries." : "\(custom.count) custom entries. Ad blockers and developer tools add these.",
                            items: custom), findings.items)
    }

    /// True for loopback and "unspecified" addresses, which ad blockers use to
    /// block a domain rather than redirect it.
    static func isBlockAddress(_ address: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            let value = UInt32(bigEndian: v4.s_addr)
            return value == 0 || value >> 24 == 127
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, address, &v6) == 1 {
            return withUnsafeBytes(of: &v6) { bytes in bytes.dropLast().allSatisfy { $0 == 0 } && (bytes.last ?? 0) <= 1 }
        }
        return false
    }

    // MARK: Logs

    func diagnosticLogs() -> (SystemCheck, [Finding]) {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var all: [Finding] = []
        var count = 0
        for folder in ["\(home)/Library/Logs/DiagnosticReports", "/Library/Logs/DiagnosticReports"] {
            let url = URL(fileURLWithPath: folder)
            guard FileManager.default.fileExists(atPath: folder),
                  let report = try? SysdiagnoseScanner.scan(url, indicators: indicators) else { continue }
            count += report.filesScanned
            all += report.findings.map { var f = $0; f.file = folder + "/" + f.file; return f }
        }
        let status: SystemCheck.Status = all.contains { $0.level == .match } ? .alert : (all.isEmpty ? .good : .warning)
        return (SystemCheck(id: "logs", title: "Crash reports", status: status,
                            detail: "Scanned \(count) crash reports for known spyware names, domains and paths."),
                all)
    }

    // MARK: Helpers

    enum Signature { case apple, developer, unsigned, unknown }

    /// Whether the executable carries a valid signature. Resources aren't
    /// re-validated: that would take minutes for big apps and doesn't change
    /// the answer to "who made this".
    static func signature(of path: String) -> Signature {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return .unknown }
        let flags = SecCSFlags(rawValue: kSecCSDoNotValidateResources)
        let status = SecStaticCodeCheckValidity(code, flags, nil)
        if status == errSecCSUnsigned { return .unsigned }
        guard status == errSecSuccess else { return .unsigned }
        var requirement: SecRequirement?
        if SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
           SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess {
            return .apple
        }
        // Ad-hoc signatures are valid but say nothing about who made the code.
        var info: CFDictionary?
        SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let teamID = (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String
        return teamID == nil ? .unsigned : .developer
    }

    /// Runs a system tool and returns its output; empty if it can't run.
    func run(_ tool: String, _ args: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }
}
#endif

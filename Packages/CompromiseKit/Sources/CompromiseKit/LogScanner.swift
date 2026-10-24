import Foundation

public struct Finding: Identifiable, Hashable, Codable, Sendable {
    public enum Level: String, Codable, Sendable {
        /// The value is on a published indicator list.
        case match
        /// Not on any list, but matches a pattern seen in past spyware.
        case suspicious
    }

    public var id = UUID()
    public var level: Level
    public var kind: String
    public var value: String
    public var campaign: String?
    public var file: String
    public var detail: String
}

/// Matches the contents of one log file against an `IndicatorSet`.
///
/// Process names are only checked where a process list is known to be
/// (ps.txt, shutdown.log, crash log names): some indicators are short names
/// like "bh" that would match ordinary text anywhere else.
public struct LogScanner {
    private let set: IndicatorSet
    private let domains: [String: String]
    private let processes: [String: String]
    private let exactPaths: [String: String]
    private let dirPaths: [(String, String)]
    private let fileNames: [String: String]
    private let profileIDs: [String: String]
    private let appIDs: [String: String]
    private let emails: [String: String]
    private let urls: [String: String]

    /// Locations Pegasus and similar implants have run from. A process here
    /// at shutdown is unusual, so the Kaspersky "iShutdown" method flags it.
    static let suspiciousLaunchDirs = ["/private/var/db/", "/private/var/tmp/", "/private/var/tmp/com.apple."]

    public init(indicators: IndicatorSet) {
        set = indicators
        domains = indicators.all(.domain)
        processes = indicators.all(.process)
        fileNames = indicators.all(.fileName)
        profileIDs = indicators.all(.profileID)
        appIDs = indicators.all(.appID)
        emails = indicators.all(.email)
        urls = indicators.all(.url)
        var exact: [String: String] = [:], dirs: [(String, String)] = []
        for (path, campaign) in indicators.all(.filePath) {
            if path.hasSuffix("/") {
                if path.count > 10 { dirs.append((path, campaign)) }
            } else {
                exact[path] = campaign
            }
        }
        exactPaths = exact
        dirPaths = dirs
    }

    public func scan(path: String, data: Data) -> [Finding] {
        var out = Findings(file: path)
        let name = (path as NSString).lastPathComponent

        if let c = fileNames[name] {
            out.add(.match, "File name", name, c, "A file with this name is listed as a trace of this spyware.")
        }
        if let process = Self.crashLogProcess(name), let c = processes[process] {
            out.add(.match, "Crashed process", process, c, "A crash log exists for a process named like this spyware's components.")
        }

        let text = String(decoding: data, as: UTF8.self)
        switch name {
        case "ps.txt", "ps_thread.txt":
            scanProcessList(text, into: &out)
        case "shutdown.log":
            scanShutdownLog(text, into: &out)
        default:
            break
        }
        scanTokens(data, into: &out)
        return out.items
    }

    // MARK: Process lists

    static func crashLogProcess(_ fileName: String) -> String? {
        guard fileName.hasSuffix(".ips"),
              let m = fileName.firstMatch(of: #/^(.+?)-\d{4}-\d{2}-\d{2}-\d{6}/#) else { return nil }
        return String(m.1)
    }

    private func scanProcessList(_ text: String, into out: inout Findings) {
        let lines = text.split(separator: "\n")
        guard let header = lines.first(where: { $0.contains("COMMAND") }),
              let column = header.range(of: "COMMAND")?.lowerBound else { return }
        let offset = header.distance(from: header.startIndex, to: column)
        for line in lines where line.count > offset {
            let command = line.dropFirst(offset).split(separator: " ").first.map(String.init) ?? ""
            let process = (command as NSString).lastPathComponent
            if let c = processes[process] {
                out.add(.match, "Running process", command, c, "This process was running when the sysdiagnose was taken.")
            }
        }
    }

    private func scanShutdownLog(_ text: String, into out: inout Findings) {
        for m in text.matches(of: #/remaining client pid: \d+ \((.+?)\)/#) {
            let path = String(m.1)
            let process = (path as NSString).lastPathComponent
            if let c = processes[process] {
                out.add(.match, "Process at shutdown", path, c, "This process was still running when the phone was last restarted.")
            } else if Self.suspiciousLaunchDirs.contains(where: { path.hasPrefix($0) }) {
                out.add(.suspicious, "Unusual process at shutdown", path, nil,
                        "A program was running from a folder where past spyware has hidden (Kaspersky's iShutdown method). It is not on any list and may be harmless.")
            }
        }
    }

    // MARK: Tokens

    /// One pass over the bytes, splitting on punctuation that can't appear in
    /// a domain, path, address or ID. Only tokens that could be one of those
    /// become Strings.
    private func scanTokens(_ data: Data, into out: inout Findings) {
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            var start = 0
            var hasDot = false, hasAt = false, lettersAfterDot = false
            func flush(_ end: Int) {
                let length = end - start
                if length >= 4, length <= 300,
                   (hasDot && lettersAfterDot) || hasAt || bytes[start] == 0x2f || length == 36 {
                    let token = String(decoding: UnsafeBufferPointer(rebasing: bytes[start..<end]), as: UTF8.self)
                    check(token, into: &out)
                }
                hasDot = false; hasAt = false; lettersAfterDot = false
                start = end + 1
            }
            for i in 0..<bytes.count {
                let b = bytes[i]
                switch b {
                case 0, 9, 10, 13, 32, 34, 39, 40, 41, 44, 59, 60, 61, 62, 91, 93, 96, 123, 124, 125:
                    flush(i)
                case 46:
                    hasDot = true; lettersAfterDot = false
                case 64:
                    hasAt = true
                case 65...90, 97...122:
                    if hasDot { lettersAfterDot = true }
                default:
                    break
                }
            }
            flush(bytes.count)
        }
    }

    /// Reverse-DNS IDs like com.example.app. Checked against app IDs, never
    /// against domains, so "com.update.app" can't match a domain "update.app".
    private static let reverseDNSRoots: Set<String> = ["com", "org", "net", "io", "edu", "gov", "co", "de", "fr", "uk"]

    private func check(_ raw: String, into out: inout Findings) {
        var token = raw
        while let last = token.last, ".:/\\".contains(last) { token.removeLast() }
        guard token.count >= 4 else { return }

        if token.first == "/" {
            if let c = exactPaths[token] {
                out.add(.match, "File path", token, c, "This path appears in the logs and is listed as a trace of this spyware.")
            } else if let (dir, c) = dirPaths.first(where: { token.hasPrefix($0.0) }) {
                out.add(.match, "File path", token, c, "This path is inside a folder (\(dir)) listed as a trace of this spyware.")
            }
            return
        }

        if token.count == 36, token.filter({ $0 == "-" }).count == 4, let c = profileIDs[token.uppercased()] {
            out.add(.match, "Configuration profile", token, c, "A configuration profile with this ID is linked to this spyware.")
            return
        }

        let lower = token.lowercased()
        if lower.contains("@") {
            let address = lower.hasPrefix("mailto:") ? String(lower.dropFirst(7)) : lower
            if let c = emails[address] {
                out.add(.match, "Email address", address, c, "This address is linked to this spyware.")
            }
            return
        }

        var host = lower
        if let scheme = lower.range(of: "://") {
            if let c = urls[token] {
                out.add(.match, "Web address", token, c, "This link is listed as a trace of this spyware.")
                return
            }
            host = String(lower[scheme.upperBound...])
        }
        host = String(host.prefix { $0 != "/" && $0 != "?" && $0 != ":" })

        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, !labels.contains(where: \.isEmpty) else { return }

        if Self.reverseDNSRoots.contains(String(labels[0])), labels.count >= 3, !lower.contains("://") {
            if let c = appIDs[token] {
                out.add(.match, "App ID", token, c, "An app with this ID is listed as spyware or stalkerware.")
            }
            return
        }

        guard host.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." }) else { return }
        // A subdomain of a listed domain counts too.
        for i in 0...(labels.count - 2) {
            let candidate = labels[i...].joined(separator: ".")
            if let c = domains[candidate] {
                out.add(.match, "Domain", host, c, "This domain appears in the logs and is listed as infrastructure of this spyware.")
                return
            }
        }
    }
}

/// Collects findings for one file, one per kind and value.
struct Findings {
    let file: String
    var items: [Finding] = []
    private var seen: Set<String> = []

    init(file: String) { self.file = file }

    mutating func add(_ level: Finding.Level, _ kind: String, _ value: String, _ campaign: String?, _ detail: String) {
        guard seen.insert(kind + "\u{0}" + value).inserted else { return }
        items.append(Finding(level: level, kind: kind, value: value, campaign: campaign, file: file, detail: detail))
    }
}

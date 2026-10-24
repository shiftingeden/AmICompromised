import AppKit
import CompromiseKit
import Foundation
import Observation

/// Which build this is. The App Store build is sandboxed; the direct
/// download (notarized, from GitHub) can inspect the whole Mac and talk to a
/// connected iPhone.
enum Build {
    #if FULL_SCAN
    static let fullAccess = true
    #else
    static let fullAccess = false
    #endif

    static let fullDiskAccessSettings = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!
}

@MainActor @Observable
final class MacModel {
    private let store = DataStore()

    var indicators: IndicatorSet?
    var catalog: ExploitedBugCatalog = .bundled
    var macAssessment: ExploitedBugCatalog.Assessment?
    var lastUpdateSummary: String?

    /// Non-nil while a scan runs: what it's doing and how far along.
    var activity: (String, Double?)?
    var macReport: MacScanReport? = Saved.load("mac-scan.json")
    var backupReport: BackupScanReport? = Saved.load("backup-scan.json")
    var logReport: LogScanReport?
    var error: String?

    var backups: [BackupInfo] = []
    var needsFullDiskAccess = false

    var isBusy: Bool { activity != nil }

    func start() async {
        indicators = await store.cachedIndicators()
        catalog = await store.catalog()
        macAssessment = catalog.assess(.current, on: .macOS)
        loadBackups()
        if indicators?.updated.map({ Date().timeIntervalSince($0) > 12 * 3600 }) ?? true {
            await refreshData()
        }
    }

    // MARK: Lists

    func refreshData() async {
        let oldCount = indicators?.total ?? 0
        let oldBugs = Set(catalog.entries.map(\.cve))
        async let catalogTask = store.updateCatalog()
        var failed = false
        do {
            indicators = try await store.updateIndicators().set
        } catch {
            failed = true
        }
        catalog = await catalogTask
        macAssessment = catalog.assess(.current, on: .macOS)

        if failed {
            lastUpdateSummary = indicators == nil
                ? "Couldn't download the lists. Connect to the internet and try again."
                : "Offline: using the lists saved \(indicators!.updated?.formatted(.relative(presentation: .named)) ?? "earlier")."
        } else {
            let added = (indicators?.total ?? 0) - oldCount
            let newBugs = catalog.entries.filter { !oldBugs.contains($0.cve) }.count
            var changes: [String] = []
            if oldCount > 0, added > 0 { changes.append("\(added) new spyware indicators") }
            if newBugs > 0 { changes.append("\(newBugs) newly exploited bugs") }
            lastUpdateSummary = changes.isEmpty
                ? "Lists up to date (\((indicators?.total ?? 0).formatted()) indicators)."
                : "Updated: " + changes.joined(separator: ", ") + "."
        }
    }

    private var indicatorsAreStale: Bool {
        guard let updated = indicators?.updated else { return true }
        return Date().timeIntervalSince(updated) > 3600
    }

    /// Every scan starts by refreshing the lists if they're over an hour old.
    private func freshIndicators() async -> IndicatorSet? {
        if indicatorsAreStale {
            activity = ("Checking for indicator updates…", nil)
            await refreshData()
        }
        guard let indicators, indicators.total > 0 else {
            error = "The indicator lists haven't downloaded yet. Connect to the internet and try again."
            activity = nil
            return nil
        }
        return indicators
    }

    // MARK: Mac scan

    func scanMac() async {
        error = nil
        activity = ("Checking for indicator updates…", nil)
        await refreshData()
        guard let indicators = await freshIndicators() else { return }
        let fullAccess = Build.fullAccess
        let report = await Task.detached(priority: .userInitiated) { [weak self] in
            MacSystemScanner(indicators: indicators, fullAccess: fullAccess).scan { fraction, step in
                Task { @MainActor in self?.activity = ("Scanning: \(step)…", fraction) }
            }
        }.value
        macReport = report
        Saved.save(report, "mac-scan.json")
        activity = nil
    }

    // MARK: iPhone backups

    func loadBackups() {
        guard Build.fullAccess else { return }
        do {
            backups = try BackupInfo.finderBackups()
            needsFullDiskAccess = false
        } catch {
            // No folder at all just means no backups yet.
            let missing = (error as NSError).code == NSFileReadNoSuchFileError
            needsFullDiskAccess = !missing
            backups = []
        }
    }

    /// App Store build: the person picks the backup folder, which the
    /// sandbox then lets us read.
    func chooseBackupFolder() -> BackupInfo? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.message = "Choose an iPhone backup folder (it contains Manifest.db)."
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/MobileSync/Backup")
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        _ = url.startAccessingSecurityScopedResource()
        do {
            return try BackupInfo(folder: url)
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            return nil
        }
    }

    /// Returns false if the password was wrong or missing, so the UI can ask
    /// again. The password lives only for the length of this call.
    @discardableResult
    func scanBackup(_ info: BackupInfo, password: String?) async -> Bool {
        error = nil
        guard let indicators = await freshIndicators() else { return true }
        activity = (info.isEncrypted ? "Unlocking the backup…" : "Opening the backup…", nil)
        let result = await Task.detached(priority: .userInitiated) { [weak self] in
            Result {
                try BackupScanner(info: info, indicators: indicators, password: password).scan { fraction, step in
                    Task { @MainActor in self?.activity = ("Scanning: \(step)…", fraction) }
                }
            }
        }.value
        activity = nil
        switch result {
        case .success(let report):
            backupReport = report
            Saved.save(report, "backup-scan.json")
            return true
        case .failure(let failure):
            error = (failure as? LocalizedError)?.errorDescription ?? failure.localizedDescription
            if case BackupError.wrongPassword = failure { return false }
            if case BackupError.needsPassword = failure { return false }
            return true
        }
    }

    // MARK: Sysdiagnose / log folders

    func chooseAndScanLogs() async {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowedContentTypes = [.gzip, .folder, .archive]
        panel.message = "Choose a sysdiagnose (.tar.gz) from an iPhone or Mac, or a folder of logs."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard let indicators = await freshIndicators() else { return }
        activity = ("Scanning logs…", 0)
        let access = url.startAccessingSecurityScopedResource()
        let result = await Task.detached(priority: .userInitiated) { [weak self] in
            Result {
                try SysdiagnoseScanner.scan(url, indicators: indicators) { fraction in
                    Task { @MainActor in self?.activity = ("Scanning logs…", fraction) }
                }
            }
        }.value
        if access { url.stopAccessingSecurityScopedResource() }
        activity = nil
        switch result {
        case .success(let report): logReport = report
        case .failure(let failure): error = (failure as? LocalizedError)?.errorDescription ?? failure.localizedDescription
        }
    }

    // MARK: Summary

    var updateStatus: SystemCheck.Status {
        guard let macAssessment else { return .unknown }
        return macAssessment.affecting.isEmpty ? .good : .alert
    }

    var overallStatus: SystemCheck.Status {
        var all: [SystemCheck.Status] = [updateStatus]
        if let macReport { all.append(macReport.worstStatus) }
        if let backupReport { all.append(backupReport.matches.isEmpty ? .good : .alert) }
        return all.filter { $0 != .unknown }.max() ?? .unknown
    }
}

/// Last results, kept in Application Support so they survive a relaunch.
enum Saved {
    static func url(_ name: String) -> URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AmICompromised", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent(name)
    }

    static func load<T: Decodable>(_ name: String) -> T? {
        guard let data = try? Data(contentsOf: url(name)) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    static func save<T: Encodable>(_ value: T, _ name: String) {
        try? JSONEncoder().encode(value).write(to: url(name), options: .atomic)
    }
}

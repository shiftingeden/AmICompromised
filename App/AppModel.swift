import CompromiseKit
import Foundation
import Observation

enum CheckStatus: Comparable {
    case good, info, unknown, warning, alert
}

@MainActor @Observable
final class AppModel {
    private let store = DataStore()

    var indicators: IndicatorSet?
    var failedSources: [String] = []
    var isUpdatingIndicators = false
    var indicatorError: String?

    var catalog: ExploitedBugCatalog = .bundled
    var assessment: ExploitedBugCatalog.Assessment?

    var deviceChecks: [DeviceCheck] = []
    var lastQuickScan: Date?

    var logReport: LogScanReport?
    var logScanProgress: Double?
    var logScanError: String?

    enum ScanPhase { case updating, checking }
    /// Where Scan Now is: first the lists are updated, then the checks run.
    var scanPhase: ScanPhase?
    var isScanning: Bool { scanPhase != nil }
    /// What the last update did, e.g. "Lists up to date".
    var lastUpdateSummary: String?
    /// True while a log scan waits for the lists to update.
    var logScanUpdating = false
    /// Set when the "sysdiagnose is ready" notification is tapped.
    var showLogScan = false
    /// Matches found later by background re-checks of saved traces.
    var recheckFindings: [Finding] = Saved.recheck()

    /// When the person pressed the sysdiagnose button combo, if we saw it.
    var sysdiagnoseStartedAt: Date? {
        didSet { UserDefaults.standard.set(sysdiagnoseStartedAt, forKey: "sysdiagnoseStartedAt") }
    }

    init() {
        logReport = Self.loadReport()
        sysdiagnoseStartedAt = UserDefaults.standard.object(forKey: "sysdiagnoseStartedAt") as? Date
        // An old capture is either done or abandoned; don't keep counting.
        if let started = sysdiagnoseStartedAt, Date().timeIntervalSince(started) > 2 * 3600 {
            sysdiagnoseStartedAt = nil
        }
    }

    /// The home screen's Scan Now: fresh lists, then every automatic check.
    func scanNow() async {
        scanPhase = .updating
        await refreshData()
        scanPhase = .checking
        // Long enough to read as a scan, not a flicker.
        try? await Task.sleep(for: .seconds(1))
        runQuickScan()
        SharedStatus.defaults.set(Date(), forKey: "lastScan")
        recheckFindings = Saved.recheck()
        publishStatus()
        scanPhase = nil
    }

    /// Updates the widget.
    func publishStatus() {
        if let assessment { BackgroundMonitor.publishStatus(assessment: assessment, deviceChecks: deviceChecks) }
    }

    /// Whether the lists are old enough to fetch again before a log scan.
    private var indicatorsAreStale: Bool {
        guard let updated = indicators?.updated else { return true }
        return Date().timeIntervalSince(updated) > 3600
    }

    func start() async {
        indicators = await store.cachedIndicators()
        catalog = await store.catalog()
        runQuickScan()
        if indicators?.updated.map({ Date().timeIntervalSince($0) > 12 * 3600 }) ?? true {
            await refreshData()
        }
    }

    func refreshData() async {
        isUpdatingIndicators = true
        defer { isUpdatingIndicators = false }
        let oldIndicators = indicators?.total ?? 0
        let oldBugs = Set(catalog.entries.map(\.cve))
        async let catalogTask = store.updateCatalog()
        do {
            let update = try await store.updateIndicators()
            indicators = update.set
            failedSources = update.failedSources
            indicatorError = nil
        } catch {
            indicatorError = "Couldn't download the latest indicator lists. Check your connection and try again."
        }
        catalog = await catalogTask
        runQuickScan()

        if indicatorError != nil {
            lastUpdateSummary = indicators == nil
                ? "Couldn't download the lists. Connect to the internet and try again."
                : "Offline: using the lists saved \(indicators!.updated?.formatted(.relative(presentation: .named)) ?? "earlier")."
        } else {
            var changes: [String] = []
            let added = (indicators?.total ?? 0) - oldIndicators
            if oldIndicators > 0, added > 0 { changes.append("\(added) new spyware indicator\(added == 1 ? "" : "s")") }
            let newBugs = catalog.entries.filter { !oldBugs.contains($0.cve) }.count
            if newBugs > 0 { changes.append("\(newBugs) newly exploited iOS bug\(newBugs == 1 ? "" : "s")") }
            lastUpdateSummary = changes.isEmpty
                ? "Lists up to date (\((indicators?.total ?? 0).formatted()) indicators)."
                : "Updated: " + changes.joined(separator: ", ") + "."
        }
    }

    func runQuickScan() {
        assessment = catalog.assess(.current)
        deviceChecks = DeviceCheck.runAll()
        lastQuickScan = Date()
        publishStatus()
    }

    // MARK: Status summaries

    var updateStatus: CheckStatus {
        guard let assessment else { return .unknown }
        return assessment.affecting.isEmpty ? .good : .alert
    }

    var deviceStatus: CheckStatus {
        deviceChecks.map(\.status).max() ?? .unknown
    }

    var logStatus: CheckStatus {
        if !recheckFindings.isEmpty { return .alert }
        guard let logReport else { return .unknown }
        if !logReport.matches.isEmpty { return .alert }
        if !logReport.suspicious.isEmpty { return .warning }
        return .good
    }

    var overallStatus: CheckStatus {
        [updateStatus, deviceStatus, logStatus].filter { $0 != .unknown }.max() ?? .unknown
    }

    // MARK: Log scan

    /// Results of the bundled sample scan. Kept apart from `logReport` so a
    /// demo never colours the person's own status.
    var sampleReport: LogScanReport?

    /// Scans a small bundled sample with two planted traces, so people (and
    /// App Review) can see what results look like without a sysdiagnose.
    func scanSample() async {
        guard let url = Bundle.main.url(forResource: "sample-sysdiagnose", withExtension: "tar.gz") else { return }
        await scanLogs(at: url, sample: true)
    }

    func scanLogs(at url: URL, sample: Bool = false) async {
        logScanError = nil
        if indicatorsAreStale {
            logScanUpdating = true
            await refreshData()
            logScanUpdating = false
        }
        guard let indicators, indicators.total > 0 else {
            logScanError = "The indicator lists haven't downloaded yet. Connect to the internet, then tap Update in Indicator Sources."
            return
        }
        logScanError = nil
        logScanProgress = 0

        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }

        let recorder = sample ? nil : TraceRecorder(source: url.lastPathComponent)
        let result = await Task.detached(priority: .userInitiated) { [weak self] in
            Result {
                try SysdiagnoseScanner.scan(url, indicators: indicators, recorder: recorder) { fraction in
                    Task { @MainActor in self?.logScanProgress = fraction }
                }
            }
        }.value

        logScanProgress = nil
        switch result {
        case .success(var report):
            if sample {
                report.archiveName = "Sample data (not from your phone)"
                sampleReport = report
                return
            }
            sampleReport = nil
            logReport = report
            Self.saveReport(report)
            // Keep this scan's traces for background re-checks; a fresh scan
            // replaces earlier traces and earlier re-check results.
            if let recorder { Saved.saveTraces(recorder.traces) }
            Saved.clearRecheck()
            recheckFindings = []
            publishStatus()
            cancelSysdiagnoseCapture()
            if SharedInbox.contains(url) { try? FileManager.default.removeItem(at: url) }
        case .failure(let error):
            logScanError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }

    private static var reportURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("last-log-scan.json")
    }

    private static func loadReport() -> LogScanReport? {
        guard let data = try? Data(contentsOf: reportURL) else { return nil }
        return try? JSONDecoder().decode(LogScanReport.self, from: data)
    }

    private static func saveReport(_ report: LogScanReport) {
        try? FileManager.default.createDirectory(at: reportURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? JSONEncoder().encode(report).write(to: reportURL, options: .atomic)
    }
}

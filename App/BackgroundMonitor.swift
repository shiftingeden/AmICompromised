import BackgroundTasks
import CompromiseKit
import Foundation
import UIKit
import UserNotifications
import WidgetKit

/// Background protection. iOS decides when a background refresh actually
/// runs (often every few hours, less on low battery), so the interval is a
/// request, not a schedule. Each run:
///  1. downloads the latest indicator lists and exploited-bug catalog,
///  2. re-checks the traces saved from the last sysdiagnose against them,
///  3. warns about newly exploited bugs affecting this iOS version,
///  4. reminds the person to restart when it's been a while,
///  5. updates the widget.
/// Apps can't read system logs in the background, so this can't take a new
/// sysdiagnose; that still needs the person.
enum BackgroundMonitor {
    static let taskID = "com.techbitsmix.AmICompromised.refresh"
    static let alertCategory = "SPYWARE_ALERT"
    static let cutAction = "CUT_CONNECTIONS"
    static let laterAction = "NOT_NOW"
    /// The Shortcut the person creates once; it turns on Airplane Mode.
    static let emergencyShortcut = "Am I Compromised Emergency"

    static var enabled: Bool {
        get { SharedStatus.defaults.bool(forKey: "backgroundEnabled") }
        set { SharedStatus.defaults.set(newValue, forKey: "backgroundEnabled"); if newValue { schedule() } else { cancel() } }
    }

    /// Requested gap between checks, in hours.
    static var intervalHours: Int {
        get { SharedStatus.defaults.object(forKey: "intervalHours") as? Int ?? 3 }
        set { SharedStatus.defaults.set(newValue, forKey: "intervalHours"); schedule() }
    }

    static var lastRun: Date? { SharedStatus.defaults.object(forKey: "lastBackgroundCheck") as? Date }

    // MARK: Scheduling

    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: taskID, using: nil) { task in
            guard let task = task as? BGAppRefreshTask else { return }
            schedule()
            let work = Task {
                await run()
                task.setTaskCompleted(success: true)
            }
            task.expirationHandler = { work.cancel() }
        }
        let center = UNUserNotificationCenter.current()
        center.setNotificationCategories([
            UNNotificationCategory(identifier: alertCategory, actions: [
                UNNotificationAction(identifier: cutAction, title: "Cut connections", options: [.foreground, .destructive]),
                UNNotificationAction(identifier: laterAction, title: "Not now", options: []),
            ], intentIdentifiers: [], options: []),
        ])
    }

    static func schedule() {
        guard enabled else { return }
        let request = BGAppRefreshTaskRequest(identifier: taskID)
        request.earliestBeginDate = Date(timeIntervalSinceNow: TimeInterval(intervalHours * 3600))
        try? BGTaskScheduler.shared.submit(request)
    }

    static func cancel() {
        BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: taskID)
    }

    // MARK: The check

    @discardableResult
    static func run() async -> [Finding] {
        let store = DataStore()
        async let catalogTask = store.updateCatalog()
        var indicators = try? await store.updateIndicators().set
        if indicators == nil { indicators = await store.cachedIndicators() }
        let catalog = await catalogTask
        if Task.isCancelled { return [] }

        var newMatches: [Finding] = []
        if let indicators, let traces = Saved.traces() {
            let found = traces.recheck(against: indicators)
            var alerted = Set(SharedStatus.defaults.stringArray(forKey: "alertedTraces") ?? [])
            newMatches = found.filter { !alerted.contains($0.kind + "|" + $0.value) }
            if !newMatches.isEmpty {
                alerted.formUnion(newMatches.map { $0.kind + "|" + $0.value })
                SharedStatus.defaults.set(Array(alerted), forKey: "alertedTraces")
                Saved.saveRecheck(found)
                await notifySpyware(newMatches)
            }
        }

        let assessment = catalog.assess(.current)
        var knownBugs = Set(SharedStatus.defaults.stringArray(forKey: "notifiedBugs") ?? [])
        let newBugs = assessment.affecting.filter { !knownBugs.contains($0.cve) }
        if !newBugs.isEmpty {
            knownBugs.formUnion(newBugs.map(\.cve))
            SharedStatus.defaults.set(Array(knownBugs), forKey: "notifiedBugs")
            await notify(id: "new-bugs", title: "Update iOS soon",
                         body: "\(newBugs.count) newly reported bug\(newBugs.count == 1 ? " is" : "s are") being used in real attacks against iOS \(assessment.version)." + (assessment.updateTo.map { " Update to iOS \($0) or later." } ?? ""),
                         timeSensitive: false)
        }

        await remindRestartIfDue()

        SharedStatus.defaults.set(Date(), forKey: "lastBackgroundCheck")
        await MainActor.run { publishStatus(assessment: assessment) }
        return newMatches
    }

    static func remindRestartIfDue() async {
        guard SharedStatus.restartDue else { return }
        let last = SharedStatus.defaults.object(forKey: "lastRestartReminder") as? Date ?? .distantPast
        guard Date().timeIntervalSince(last) > 20 * 3600 else { return }
        SharedStatus.defaults.set(Date(), forKey: "lastRestartReminder")
        await notify(id: "restart", title: "Time to restart your iPhone",
                     body: "It's been \(SharedStatus.daysSinceRestart) days. Many spyware implants only live in memory, so a restart removes them until the attacker gets back in.",
                     timeSensitive: false)
    }

    // MARK: Notifications

    static func notifySpyware(_ findings: [Finding]) async {
        let campaigns = Set(findings.compactMap(\.campaign)).map { $0.replacingOccurrences(of: " Indicators of Compromise", with: "") }
        await notify(id: "spyware-\(UUID().uuidString)", title: "Possible spyware traces found",
                     body: "A newly published list matches \(findings.count) trace\(findings.count == 1 ? "" : "s") from your last sysdiagnose" + (campaigns.isEmpty ? "." : " (\(campaigns.sorted().joined(separator: ", ")))." ) + " This is a lead, not proof. Tap Cut connections to turn on Airplane Mode.",
                     timeSensitive: true, category: alertCategory)
    }

    static func notify(id: String, title: String, body: String, timeSensitive: Bool, category: String? = nil) async {
        let center = UNUserNotificationCenter.current()
        guard await center.notificationSettings().authorizationStatus == .authorized else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default    // also vibrates, following the person's sound settings
        if timeSensitive { content.interruptionLevel = .timeSensitive }
        if let category { content.categoryIdentifier = category }
        try? await center.add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
    }

    // MARK: Emergency

    /// Runs the person's emergency Shortcut. Returns false if Shortcuts
    /// couldn't be opened.
    @MainActor @discardableResult
    static func runEmergencyShortcut() async -> Bool {
        var components = URLComponents(string: "shortcuts://run-shortcut")!
        components.queryItems = [URLQueryItem(name: "name", value: emergencyShortcut)]
        guard let url = components.url else { return false }
        return await UIApplication.shared.open(url)
    }

    // MARK: Widget status

    @MainActor
    static func publishStatus(assessment: ExploitedBugCatalog.Assessment, deviceChecks: [DeviceCheck] = DeviceCheck.runAll()) {
        let report = Saved.logReport()
        let recheck = Saved.recheck()
        var lines: [String] = []
        var level = SharedStatus.Level.good

        if assessment.affecting.isEmpty {
            lines.append("iOS \(assessment.version): up to date")
        } else {
            lines.append("iOS \(assessment.version): \(assessment.affecting.count) exploited bug\(assessment.affecting.count == 1 ? "" : "s")")
            level = .alert
        }
        if !recheck.isEmpty || !(report?.matches.isEmpty ?? true) {
            lines.append("Logs: possible spyware traces")
            level = .alert
        } else if let report {
            lines.append(report.suspicious.isEmpty ? "Logs: no known traces" : "Logs: something unusual")
            if !report.suspicious.isEmpty, level == .good { level = .warning }
        } else {
            lines.append("Logs: not scanned yet")
        }
        if deviceChecks.contains(where: { $0.status == .alert }) {
            lines.append("Device: needs attention")
            level = .alert
        }

        let headline: String = switch level {
        case .alert: "Needs attention"
        case .warning: "Worth a closer look"
        case .good: "No known threats"
        case .unknown: "Not scanned yet"
        }
        SharedStatus(level: level, headline: headline, lines: lines,
                     lastScan: SharedStatus.defaults.object(forKey: "lastScan") as? Date,
                     lastBackgroundCheck: lastRun).save()
        WidgetCenter.shared.reloadAllTimelines()
    }
}

/// Files the background monitor shares with the app.
enum Saved {
    private static var dir: URL {
        let d = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    static func traces() -> TraceSet? { load("traces.json") }
    static func saveTraces(_ t: TraceSet) { save(t, "traces.json") }
    static func logReport() -> LogScanReport? { load("last-log-scan.json") }
    static func recheck() -> [Finding] { load("recheck.json") ?? [] }
    static func saveRecheck(_ f: [Finding]) { save(f, "recheck.json") }
    static func clearRecheck() { try? FileManager.default.removeItem(at: dir.appendingPathComponent("recheck.json")) }

    private static func load<T: Decodable>(_ name: String) -> T? {
        guard let data = try? Data(contentsOf: dir.appendingPathComponent(name)) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    private static func save<T: Encodable>(_ value: T, _ name: String) {
        try? JSONEncoder().encode(value).write(to: dir.appendingPathComponent(name), options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}

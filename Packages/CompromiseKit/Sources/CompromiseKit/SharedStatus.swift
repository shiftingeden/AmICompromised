import Foundation

/// What the widget shows. The app writes it to the App Group after every
/// scan or background check; the widget only reads it.
public struct SharedStatus: Codable, Sendable {
    public enum Level: String, Codable, Sendable { case good, warning, alert, unknown }

    public var level: Level
    public var headline: String
    /// Short lines like "iOS 26.5: 1 exploited bug" or "Logs: no known traces".
    public var lines: [String]
    public var lastScan: Date?
    public var lastBackgroundCheck: Date?

    public init(level: Level, headline: String, lines: [String], lastScan: Date?, lastBackgroundCheck: Date?) {
        self.level = level
        self.headline = headline
        self.lines = lines
        self.lastScan = lastScan
        self.lastBackgroundCheck = lastBackgroundCheck
    }

    public static let placeholder = SharedStatus(level: .unknown, headline: "Not scanned yet",
                                                 lines: ["Open the app and tap Scan Now."],
                                                 lastScan: nil, lastBackgroundCheck: nil)

    private static var url: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: SharedInbox.appGroup)?
            .appendingPathComponent("status.json")
    }

    public static func load() -> SharedStatus? {
        guard let url, let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(SharedStatus.self, from: data)
    }

    public func save() {
        guard let url = Self.url, let data = try? JSONEncoder().encode(self) else { return }
        try? data.write(to: url, options: .atomic)
    }

    /// Settings shared by the app and the widget.
    public static var defaults: UserDefaults { UserDefaults(suiteName: SharedInbox.appGroup) ?? .standard }

    /// Restart reminder: suggest a restart after this many days. 0 = off.
    public static var restartEveryDays: Int {
        get { defaults.object(forKey: "restartEveryDays") as? Int ?? 3 }
        set { defaults.set(newValue, forKey: "restartEveryDays") }
    }

    /// When this device last started, from its uptime.
    public static var bootDate: Date {
        Date(timeIntervalSinceNow: -ProcessInfo.processInfo.systemUptime)
    }

    public static var daysSinceRestart: Int {
        Int(ProcessInfo.processInfo.systemUptime / 86_400)
    }

    public static var restartDue: Bool {
        restartEveryDays > 0 && daysSinceRestart >= restartEveryDays
    }

    // MARK: Background checks (set in the app, shown by the widget)

    public static var backgroundEnabled: Bool {
        get { defaults.bool(forKey: "backgroundEnabled") }
        set { defaults.set(newValue, forKey: "backgroundEnabled") }
    }

    /// Requested gap between background checks, in hours.
    public static var backgroundIntervalHours: Int {
        get { defaults.object(forKey: "intervalHours") as? Int ?? 3 }
        set { defaults.set(newValue, forKey: "intervalHours") }
    }

    public static var lastBackgroundCheck: Date? {
        get { defaults.object(forKey: "lastBackgroundCheck") as? Date }
        set { defaults.set(newValue, forKey: "lastBackgroundCheck") }
    }

    /// When the next background check is due, if they're on. iOS picks the
    /// actual moment, so this is the earliest it can run.
    public static var nextBackgroundCheck: Date? {
        guard backgroundEnabled else { return nil }
        let from = lastBackgroundCheck ?? defaults.object(forKey: "lastScan") as? Date ?? Date()
        return from.addingTimeInterval(TimeInterval(backgroundIntervalHours * 3600))
    }

    // MARK: Scan requests from the lock screen, Control Center and Siri

    /// Set by the Scan Now intent; the app runs a scan when it next becomes
    /// active and clears it.
    public static func requestScan() {
        defaults.set(true, forKey: "scanRequested")
    }

    /// True once per request.
    public static func takeScanRequest() -> Bool {
        guard defaults.bool(forKey: "scanRequested") else { return false }
        defaults.removeObject(forKey: "scanRequested")
        return true
    }

    /// Set by the Cut Connections intent; the app runs the person's
    /// emergency Shortcut (Airplane Mode) when it next becomes active.
    public static func requestCutConnections() {
        defaults.set(true, forKey: "cutRequested")
    }

    /// True once per request.
    public static func takeCutConnectionsRequest() -> Bool {
        guard defaults.bool(forKey: "cutRequested") else { return false }
        defaults.removeObject(forKey: "cutRequested")
        return true
    }
}

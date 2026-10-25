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
}

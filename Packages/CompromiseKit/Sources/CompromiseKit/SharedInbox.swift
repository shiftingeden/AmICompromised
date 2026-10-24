import Foundation

/// The App Group folder where the Share action drops a sysdiagnose for the
/// app to pick up. Extensions are short-lived and memory-limited, so the
/// action only copies the file; the app does the scan.
public enum SharedInbox {
    public static let appGroup = "group.com.techbitsmix.AmICompromised"

    public static var folder: URL? {
        guard let base = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else {
            return nil
        }
        let inbox = base.appendingPathComponent("Inbox", isDirectory: true)
        try? FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
        return inbox
    }

    /// Copies an archive in, replacing anything older: only the newest
    /// sysdiagnose is worth scanning.
    public static func store(_ source: URL) throws -> URL {
        guard let folder else { throw CocoaError(.fileWriteNoPermission) }
        for old in (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)) ?? [] {
            try? FileManager.default.removeItem(at: old)
        }
        let target = folder.appendingPathComponent(source.lastPathComponent)
        try FileManager.default.copyItem(at: source, to: target)
        return target
    }

    /// The archive waiting to be scanned, if any.
    public static func pending() -> URL? {
        guard let folder else { return nil }
        return (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil))?.first
    }

    public static func contains(_ url: URL) -> Bool {
        guard let folder else { return false }
        return url.standardizedFileURL.path.hasPrefix(folder.standardizedFileURL.path)
    }
}

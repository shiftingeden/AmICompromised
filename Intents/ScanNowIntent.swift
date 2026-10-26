import AppIntents
import CompromiseKit
import Foundation

extension Notification.Name {
    static let scanRequested = Notification.Name("AmICompromisedScanRequested")
}

/// Scan Now from the lock screen, Control Center, the Action button, Siri or
/// Shortcuts. Built into both the app and the widget extension; it opens the
/// app, which runs the scan (updating the lists first, as always).
struct ScanNowIntent: AppIntent {
    static var title: LocalizedStringResource = "Scan Now"
    static var description = IntentDescription("Opens Am I Compromised?, updates the spyware lists and runs every check.")
    static var openAppWhenRun = true

    func perform() async throws -> some IntentResult {
        SharedStatus.requestScan()
        // Reaches the app when it's already running; otherwise it picks the
        // request up as it becomes active.
        await MainActor.run { NotificationCenter.default.post(name: .scanRequested, object: nil) }
        return .result()
    }
}

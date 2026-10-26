import AppIntents
import CompromiseKit
import Foundation

extension Notification.Name {
    static let scanRequested = Notification.Name("AmICompromisedScanRequested")
    static let cutConnectionsRequested = Notification.Name("AmICompromisedCutConnectionsRequested")
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

/// Cut connections from a widget, the lock screen, Control Center, the Action
/// button or Siri. iOS doesn't let apps switch on Airplane Mode, so this opens
/// the app, which runs the Shortcut the person set up once (Protection screen).
struct CutConnectionsIntent: AppIntent {
    static var title: LocalizedStringResource = "Cut Connections"
    static var description = IntentDescription("Runs your \"Am I Compromised Emergency\" Shortcut, which turns on Airplane Mode.")
    static var openAppWhenRun = true

    func perform() async throws -> some IntentResult {
        SharedStatus.requestCutConnections()
        await MainActor.run { NotificationCenter.default.post(name: .cutConnectionsRequested, object: nil) }
        return .result()
    }
}

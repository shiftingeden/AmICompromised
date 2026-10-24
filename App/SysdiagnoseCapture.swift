import Foundation
import UserNotifications

/// iOS gives apps no way to create a sysdiagnose or read Analytics Data, so
/// the app guides the person through it instead. The button combo also takes
/// a screenshot, which is how we notice it was pressed.
extension AppModel {
    /// iOS usually finishes in 3 to 10 minutes; we wait for the slow end.
    static let sysdiagnoseDuration: TimeInterval = 10 * 60
    private static let notificationID = "sysdiagnose-ready"

    var sysdiagnoseReadyAt: Date? {
        sysdiagnoseStartedAt?.addingTimeInterval(Self.sysdiagnoseDuration)
    }

    func sysdiagnoseStarted() async {
        // A second press within the window is the same capture.
        if let readyAt = sysdiagnoseReadyAt, readyAt > Date() { return }
        sysdiagnoseStartedAt = Date()

        let center = UNUserNotificationCenter.current()
        guard (try? await center.requestAuthorization(options: [.alert, .sound])) == true else { return }
        let content = UNMutableNotificationContent()
        content.title = "Your sysdiagnose should be ready"
        content.body = "Open Settings › Privacy & Security › Analytics & Improvements › Analytics Data, then share the newest sysdiagnose file to Am I Compromised?."
        content.sound = .default
        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: Self.sysdiagnoseDuration, repeats: false)
        try? await center.add(UNNotificationRequest(identifier: Self.notificationID, content: content, trigger: trigger))
    }

    func cancelSysdiagnoseCapture() {
        sysdiagnoseStartedAt = nil
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [Self.notificationID])
    }
}

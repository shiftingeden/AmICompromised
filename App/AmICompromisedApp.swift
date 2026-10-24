import SwiftUI
import UserNotifications

@main
struct AmICompromisedApp: App {
    @UIApplicationDelegateAdaptor private var delegate: AppDelegate
    @State private var incomingArchive: URL?

    var body: some Scene {
        WindowGroup {
            HomeView(incomingArchive: $incomingArchive)
                .environment(delegate.model)
                .task { await delegate.model.start() }
                // A sysdiagnose shared from Settings › Analytics Data lands here.
                .onOpenURL { url in
                    if url.isFileURL { incomingArchive = url }
                }
        }
    }
}

/// Owns the model so notification taps can reach it.
@MainActor
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    let model = AppModel()

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        model.showLogScan = true
    }
}

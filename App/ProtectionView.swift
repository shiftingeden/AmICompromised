import CompromiseKit
import SwiftUI
import UserNotifications

struct ProtectionView: View {
    @Environment(AppModel.self) private var model
    @State private var enabled = BackgroundMonitor.enabled
    @State private var interval = BackgroundMonitor.intervalHours
    @State private var restartDays = SharedStatus.restartEveryDays
    @State private var notificationsAllowed: Bool?
    @State private var checking = false
    @State private var checkResult: String?
    @State private var shortcutFailed = false

    var body: some View {
        Form {
            Section {
                Toggle("Background checks", isOn: $enabled)
                    .onChange(of: enabled) { _, on in
                        BackgroundMonitor.enabled = on
                        if on { Task { await requestNotifications() } }
                    }
                if enabled {
                    Picker("Check about every", selection: $interval) {
                        Text("Hour").tag(1)
                        Text("3 hours").tag(3)
                        Text("6 hours").tag(6)
                        Text("12 hours").tag(12)
                        Text("Day").tag(24)
                    }
                    .onChange(of: interval) { _, h in BackgroundMonitor.intervalHours = h }
                }
                if notificationsAllowed == false {
                    Label("Notifications are off, so alerts can't reach you. Turn them on in Settings › Notifications › Am I Compromised?.",
                          systemImage: "bell.slash").foregroundStyle(.orange).font(.footnote)
                }
            } header: {
                Text("Background protection")
            } footer: {
                Text("Each check downloads newly published spyware lists, re-checks the traces saved from your last sysdiagnose, and warns you about newly exploited iOS bugs. iOS decides when checks actually run (often every few hours, less on low battery), and apps can't read your logs in the background, so it can't replace a fresh sysdiagnose now and then.")
            }

            Section {
                LabeledContent("Last background check", value: BackgroundMonitor.lastRun?.formatted(.relative(presentation: .named)) ?? "Not yet")
                LabeledContent("Saved traces", value: Saved.traces().map { "\($0.count.formatted()) from \($0.capturedAt.formatted(date: .abbreviated, time: .omitted))" } ?? "Scan a sysdiagnose first")
                Button {
                    Task { await checkNow() }
                } label: {
                    if checking { HStack { ProgressView(); Text("Checking…") } } else { Text("Run a check now") }
                }
                .disabled(checking)
                if let checkResult { Text(checkResult).font(.footnote).foregroundStyle(.secondary) }
            }

            Section {
                Picker("Remind me to restart", selection: $restartDays) {
                    Text("Off").tag(0)
                    Text("Every 2 days").tag(2)
                    Text("Every 3 days").tag(3)
                    Text("Every 5 days").tag(5)
                    Text("Every week").tag(7)
                }
                .onChange(of: restartDays) { _, d in SharedStatus.restartEveryDays = d }
                LabeledContent("Last restart", value: "\(SharedStatus.daysSinceRestart) day\(SharedStatus.daysSinceRestart == 1 ? "" : "s") ago")
            } header: {
                Text("Restart reminder")
            } footer: {
                Text("Many spyware implants live only in memory, so restarting removes them until the attacker gets back in. Restarting every few days is one of the simplest defences.")
            }

            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Text("iOS doesn't let apps turn on Airplane Mode, so the alert offers a \"Cut connections\" button that runs a Shortcut you set up once:").font(.subheadline)
                    step(1, "Open the Shortcuts app and tap + to create a new shortcut.")
                    step(2, "Add the action \"Set Airplane Mode\" and set it to On. Optionally add \"Set Wi-Fi\" and \"Set Bluetooth\" set to Off.")
                    step(3, "Name the shortcut exactly: \(BackgroundMonitor.emergencyShortcut)")
                    step(4, "Tap Test below. The first time, iOS asks to allow it; tap Allow.")
                }
                .padding(.vertical, 4)
                Button {
                    UIPasteboard.general.string = BackgroundMonitor.emergencyShortcut
                } label: { Label("Copy the shortcut name", systemImage: "doc.on.doc") }
                Button {
                    Task { shortcutFailed = !(await BackgroundMonitor.runEmergencyShortcut()) }
                } label: { Label("Test: cut connections now", systemImage: "airplane") }
                if shortcutFailed {
                    Text("Couldn't open Shortcuts. Make sure the Shortcuts app is installed.").font(.footnote).foregroundStyle(.red)
                }
            } header: {
                Text("Emergency: cut connections")
            } footer: {
                Text("To undo it, turn Airplane Mode off in Control Center. Cutting connections stops spyware sending data out while you get help, but it doesn't remove anything.")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Protection")
        .task {
            // Only warn after the person has actually said no.
            notificationsAllowed = await UNUserNotificationCenter.current().notificationSettings().authorizationStatus != .denied
        }
    }

    private func step(_ n: Int, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("\(n).").font(.subheadline.monospacedDigit()).foregroundStyle(.secondary)
            Text(text).font(.subheadline)
        }
    }

    private func requestNotifications() async {
        let granted = (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])) ?? false
        notificationsAllowed = granted
    }

    private func checkNow() async {
        checking = true
        checkResult = nil
        let found = await BackgroundMonitor.run()
        model.recheckFindings = Saved.recheck()
        checking = false
        checkResult = found.isEmpty
            ? "Done. No new matches in your saved traces."
            : "Found \(found.count) new match\(found.count == 1 ? "" : "es"). See Spyware Log Scan."
    }
}

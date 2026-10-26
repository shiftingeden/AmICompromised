import AppIntents

/// "Scan with Compromised?" in Siri, Spotlight, Shortcuts and the Action button.
struct ScanShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: ScanNowIntent(),
                    phrases: ["Scan with \(.applicationName)",
                              "Check \(.applicationName) for spyware",
                              "Run \(.applicationName)"],
                    shortTitle: "Scan Now",
                    systemImageName: "shield.lefthalf.filled.badge.checkmark")
        AppShortcut(intent: CutConnectionsIntent(),
                    phrases: ["Cut connections with \(.applicationName)",
                              "Emergency \(.applicationName)"],
                    shortTitle: "Cut Connections",
                    systemImageName: "airplane")
    }
}

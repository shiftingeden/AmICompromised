import SwiftUI

/// "Suggest a feature" and "Report a bug" links. The email is pre-filled
/// with the app and OS version only; nothing from scans is included.
struct FeedbackSection: View {
    static let address = "TechBitsMix@gmail.com"

    var body: some View {
        Section {
            if let url = Self.mail(subject: "Am I Compromised? suggestion", body: "My suggestion:\n\n") {
                Link(destination: url) { Label("Suggest a feature", systemImage: "lightbulb") }
            }
            if let url = Self.mail(subject: "Am I Compromised? bug report",
                                   body: "What happened:\n\nWhat I expected:\n\nSteps to reproduce:\n\n") {
                Link(destination: url) { Label("Report a bug", systemImage: "ladybug") }
            }
            Link(destination: URL(string: "https://github.com/shiftingeden/AmICompromised/issues")!) {
                Label("Open an issue on GitHub", systemImage: "chevron.left.forwardslash.chevron.right")
            }
        } header: {
            Text("Contact")
        } footer: {
            Text("Email \(Self.address). Please don't attach a sysdiagnose or backup: they contain personal data.")
        }
    }

    static var versionLine: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "?"
        let build = info["CFBundleVersion"] as? String ?? "?"
        let os = ProcessInfo.processInfo.operatingSystemVersion
        #if os(macOS)
        let platform = "macOS"
        #else
        let platform = "iOS"
        #endif
        return "App \(version) (\(build)), \(platform) \(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
    }

    static func mail(subject: String, body: String) -> URL? {
        var components = URLComponents()
        components.scheme = "mailto"
        components.path = address
        components.queryItems = [
            URLQueryItem(name: "subject", value: subject),
            URLQueryItem(name: "body", value: body + "\n---\n" + versionLine),
        ]
        return components.url
    }
}

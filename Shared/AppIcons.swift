import SwiftUI
#if os(iOS)
import UIKit
#else
import AppKit
#endif

/// App icons. Navy is everyone's; Orange and Gold are a thank-you for tipping.
enum AppIconChoice: String, CaseIterable, Identifiable {
    case navy, orange, gold

    var id: String { rawValue }
    var name: String { rawValue.capitalized }
    var needsSupporter: Bool { self != .navy }

    var swatch: Color {
        switch self {
        case .navy: Color(red: 0.16, green: 0.18, blue: 0.56)
        case .orange: Color(red: 0.98, green: 0.45, blue: 0.09)
        case .gold: Color(red: 0.79, green: 0.60, blue: 0.12)
        }
    }

    /// Alternate icon name in the asset catalog; nil is the primary icon.
    var alternateName: String? { self == .navy ? nil : "AppIcon-\(name)" }

    static let storageKey = "appIcon"

    /// Applies an icon. iOS changes the home-screen icon; a Mac app can only
    /// change its Dock icon while it's running, so it's reapplied at launch.
    @MainActor
    static func apply(_ choice: AppIconChoice) {
        #if os(iOS)
        guard UIApplication.shared.supportsAlternateIcons,
              UIApplication.shared.alternateIconName != choice.alternateName else { return }
        UIApplication.shared.setAlternateIconName(choice.alternateName)
        #else
        NSApplication.shared.applicationIconImage = choice == .navy ? nil : NSImage(named: "DockIcon-\(choice.name)")
        #endif
    }

    /// Puts back the free icon if the person is no longer a supporter (for
    /// example after a refund).
    @MainActor
    static func restore(supporter: Bool) {
        let saved = AppIconChoice(rawValue: UserDefaults.standard.string(forKey: storageKey) ?? "") ?? .navy
        let choice = saved.needsSupporter && !supporter ? .navy : saved
        #if os(iOS)
        if choice != saved || UIApplication.shared.alternateIconName != choice.alternateName { apply(choice) }
        #else
        apply(choice)
        #endif
    }
}

struct AppIconPicker: View {
    @AppStorage(AppIconChoice.storageKey) private var selection = AppIconChoice.navy.rawValue
    var unlocked: Bool

    var body: some View {
        HStack(spacing: 22) {
            ForEach(AppIconChoice.allCases) { icon in
                let locked = icon.needsSupporter && !unlocked
                Button {
                    guard !locked else { return }
                    selection = icon.rawValue
                    AppIconChoice.apply(icon)
                } label: {
                    VStack(spacing: 6) {
                        ZStack {
                            Image("IconPreview-\(icon.name)")
                                .resizable()
                                .frame(width: 56, height: 56)
                                .clipShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
                            if locked {
                                Image(systemName: "lock.fill").font(.body).foregroundStyle(.white)
                                    .shadow(radius: 2)
                            }
                        }
                        .overlay(RoundedRectangle(cornerRadius: 17)
                            .stroke(selection == icon.rawValue ? icon.swatch : .clear, lineWidth: 2).padding(-4))
                        Text(icon.name).font(.caption).foregroundStyle(locked ? .secondary : .primary)
                    }
                    .opacity(locked ? 0.55 : 1)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(icon.name + " icon" + (locked ? ", locked" : ""))
            }
        }
        .padding(.vertical, 6)
    }
}

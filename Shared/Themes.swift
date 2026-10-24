import SwiftUI

/// Accent colours. Ocean is everyone's; the rest are a thank-you for tipping.
enum Theme: String, CaseIterable, Identifiable {
    case ocean, teal, violet, sunset, forest, rose, graphite

    var id: String { rawValue }

    var name: String {
        switch self {
        case .ocean: "Ocean"
        case .teal: "Teal"
        case .violet: "Violet"
        case .sunset: "Sunset"
        case .forest: "Forest"
        case .rose: "Rose"
        case .graphite: "Graphite"
        }
    }

    var color: Color {
        switch self {
        case .ocean: Color("AccentColor")
        case .teal: Color(red: 0.08, green: 0.62, blue: 0.58)
        case .violet: Color(red: 0.45, green: 0.33, blue: 0.86)
        case .sunset: Color(red: 0.93, green: 0.42, blue: 0.20)
        case .forest: Color(red: 0.18, green: 0.55, blue: 0.30)
        case .rose: Color(red: 0.86, green: 0.25, blue: 0.47)
        case .graphite: Color(red: 0.38, green: 0.40, blue: 0.45)
        }
    }

    var needsSupporter: Bool { self != .ocean }
}

extension View {
    /// Applies the chosen theme, falling back to Ocean if it's locked (for
    /// example after a refunded tip).
    func appTheme(_ raw: String, supporter: Bool) -> some View {
        let theme = Theme(rawValue: raw) ?? .ocean
        return tint(theme.needsSupporter && !supporter ? Theme.ocean.color : theme.color)
    }
}

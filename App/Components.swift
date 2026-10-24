import SwiftUI

extension CheckStatus {
    var symbol: String {
        switch self {
        case .good: "checkmark.shield.fill"
        case .info: "info.circle.fill"
        case .unknown: "questionmark.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .alert: "exclamationmark.octagon.fill"
        }
    }

    var color: Color {
        switch self {
        case .good: .green
        case .info, .unknown: .secondary
        case .warning: .orange
        case .alert: .red
        }
    }
}

struct StatusIcon: View {
    var status: CheckStatus
    var body: some View {
        Image(systemName: status.symbol)
            .foregroundStyle(status.color)
            .font(.title3)
            .accessibilityLabel(Text(verbatim: "\(status)"))
    }
}

struct StatusRow: View {
    var status: CheckStatus
    var title: String
    var detail: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            StatusIcon(status: status)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline)
                Text(detail).font(.subheadline).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

/// The caveat that sits under every result. Short on purpose so it gets read.
struct NoGuaranteeNote: View {
    var body: some View {
        Label {
            Text("A clean result means no **known** traces were found. New spyware has no public indicators until researchers catch it, so this can't prove your phone is clean.")
        } icon: {
            Image(systemName: "exclamationmark.bubble")
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
    }
}

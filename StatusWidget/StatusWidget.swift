import CompromiseKit
import SwiftUI
import WidgetKit

/// Home screen and lock screen widget: the last result, when the phone was
/// last restarted, and a Scan Now button that opens the app and scans.
@main
struct StatusWidgetBundle: WidgetBundle {
    var body: some Widget { StatusWidget() }
}

struct StatusEntry: TimelineEntry {
    var date: Date
    var status: SharedStatus
    var daysSinceRestart: Int
    var restartDue: Bool
}

struct StatusProvider: TimelineProvider {
    func placeholder(in context: Context) -> StatusEntry { entry() }
    func getSnapshot(in context: Context, completion: @escaping (StatusEntry) -> Void) { completion(entry()) }

    func getTimeline(in context: Context, completion: @escaping (Timeline<StatusEntry>) -> Void) {
        // Hourly, so "days since restart" and relative times stay current;
        // the app also reloads the widget after every scan.
        completion(Timeline(entries: [entry()], policy: .after(Date(timeIntervalSinceNow: 3600))))
    }

    private func entry() -> StatusEntry {
        StatusEntry(date: Date(), status: SharedStatus.load() ?? .placeholder,
                    daysSinceRestart: SharedStatus.daysSinceRestart, restartDue: SharedStatus.restartDue)
    }
}

struct StatusWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "AmICompromisedStatus", provider: StatusProvider()) { entry in
            StatusWidgetView(entry: entry)
                .containerBackground(.fill.tertiary, for: .widget)
                .widgetURL(URL(string: "amicompromised://scan"))
        }
        .configurationDisplayName("Am I Compromised?")
        .description("Your last check, restart reminder and a Scan Now button.")
        .supportedFamilies([.systemSmall, .systemMedium, .accessoryRectangular, .accessoryCircular])
    }
}

extension SharedStatus.Level {
    var symbol: String {
        switch self {
        case .good: "checkmark.shield.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .alert: "exclamationmark.octagon.fill"
        case .unknown: "shield.lefthalf.filled"
        }
    }

    var color: Color {
        switch self {
        case .good: .green
        case .warning: .orange
        case .alert: .red
        case .unknown: .secondary
        }
    }
}

struct StatusWidgetView: View {
    @Environment(\.widgetFamily) private var family
    var entry: StatusEntry

    var body: some View {
        switch family {
        case .accessoryCircular:
            ZStack {
                AccessoryWidgetBackground()
                Image(systemName: entry.restartDue ? "arrow.clockwise" : entry.status.level.symbol)
                    .font(.title2)
            }
        case .accessoryRectangular:
            VStack(alignment: .leading, spacing: 1) {
                Label(entry.status.headline, systemImage: entry.status.level.symbol).font(.headline)
                Text(restartLine).font(.caption)
                if let last = entry.status.lastScan {
                    Text("Scanned \(last, style: .relative) ago").font(.caption2)
                }
            }
        case .systemMedium:
            HStack(alignment: .top, spacing: 14) {
                VStack(alignment: .leading, spacing: 6) {
                    header
                    ForEach(entry.status.lines.prefix(3), id: \.self) { Text($0).font(.caption).lineLimit(1) }
                    Spacer(minLength: 0)
                    lastScanLine
                }
                Spacer(minLength: 0)
                VStack(alignment: .trailing, spacing: 8) {
                    restartBadge
                    Spacer(minLength: 0)
                    Link(destination: URL(string: "amicompromised://scan")!) {
                        Label("Scan Now", systemImage: "shield.lefthalf.filled.badge.checkmark")
                            .font(.caption.bold())
                            .padding(.horizontal, 10).padding(.vertical, 7)
                            .background(Capsule().fill(Color.accentColor))
                            .foregroundStyle(.white)
                    }
                }
            }
        default:
            VStack(alignment: .leading, spacing: 6) {
                header
                Text(entry.status.lines.first ?? "").font(.caption2).lineLimit(2)
                Spacer(minLength: 0)
                restartBadge
                Text("Tap to scan").font(.caption2.bold()).foregroundStyle(.tint)
            }
        }
    }

    private var header: some View {
        HStack(spacing: 6) {
            Image(systemName: entry.status.level.symbol).foregroundStyle(entry.status.level.color)
            Text(entry.status.headline).font(.subheadline.bold()).lineLimit(2).minimumScaleFactor(0.8)
        }
    }

    private var restartLine: String {
        entry.restartDue ? "Restart recommended (\(entry.daysSinceRestart)d)"
            : "Restarted \(entry.daysSinceRestart == 0 ? "today" : "\(entry.daysSinceRestart)d ago")"
    }

    private var restartBadge: some View {
        Label(restartLine, systemImage: entry.restartDue ? "arrow.clockwise.circle.fill" : "arrow.clockwise")
            .font(.caption2.bold())
            .foregroundStyle(entry.restartDue ? .orange : .secondary)
            .lineLimit(1).minimumScaleFactor(0.8)
    }

    @ViewBuilder private var lastScanLine: some View {
        if let last = entry.status.lastScan {
            Text("Last scan \(last, style: .relative) ago").font(.caption2).foregroundStyle(.secondary)
        } else {
            Text("Not scanned yet").font(.caption2).foregroundStyle(.secondary)
        }
    }
}

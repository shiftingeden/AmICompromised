import CompromiseKit
import SwiftUI
import WidgetKit

/// Home screen and lock screen widget: the last result, when the phone was
/// last restarted, and a Scan Now button that opens the app and scans. On
/// iOS 18 and later there's also a Scan Now control for the lock screen,
/// Control Center and the Action button.
@main
struct StatusWidgetBundle: WidgetBundle {
    var body: some Widget {
        StatusWidget()
        if #available(iOS 18.0, *) {
            ScanControl()
            CutConnectionsControl()
        }
    }
}

struct StatusEntry: TimelineEntry {
    var date: Date
    var status: SharedStatus
    var daysSinceRestart: Int
    var restartDue: Bool
    var restartEveryDays: Int
    var nextCheck: Date?

    /// The most recent scan or background check.
    var lastChecked: Date? {
        [status.lastScan, status.lastBackgroundCheck, SharedStatus.lastBackgroundCheck].compactMap { $0 }.max()
    }
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
                    daysSinceRestart: SharedStatus.daysSinceRestart, restartDue: SharedStatus.restartDue,
                    restartEveryDays: SharedStatus.restartEveryDays, nextCheck: SharedStatus.nextBackgroundCheck)
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
        .description("Your status, when it last checked, the next background check and a restart reminder. Tap to scan.")
        .supportedFamilies([.systemSmall, .systemMedium, .systemLarge,
                            .accessoryRectangular, .accessoryCircular, .accessoryInline])
    }
}

/// A Scan Now button for the lock screen, Control Center and the Action button.
@available(iOS 18.0, *)
struct ScanControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "AmICompromisedScan") {
            ControlWidgetButton(action: ScanNowIntent()) {
                Label("Spyware Scan", systemImage: "shield.lefthalf.filled.badge.checkmark")
            }
        }
        .displayName("Spyware Scan")
        .description("Opens Am I Compromised? and scans.")
    }
}

/// Runs the person's emergency Shortcut (Airplane Mode) via the app.
@available(iOS 18.0, *)
struct CutConnectionsControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "AmICompromisedCutConnections") {
            ControlWidgetButton(action: CutConnectionsIntent()) {
                Label("Cut Connections", systemImage: "airplane")
            }
        }
        .displayName("Cut Connections")
        .description("Runs your Am I Compromised Emergency Shortcut to turn on Airplane Mode.")
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
            if entry.restartEveryDays > 0 {
                // The ring fills up towards the next suggested restart.
                Gauge(value: Double(min(entry.daysSinceRestart, entry.restartEveryDays)),
                      in: 0...Double(entry.restartEveryDays)) {
                    Text("Restart")
                } currentValueLabel: {
                    Image(systemName: entry.restartDue ? "arrow.clockwise" : entry.status.level.symbol)
                }
                .gaugeStyle(.accessoryCircular)
                .widgetAccentable()
            } else {
                ZStack {
                    AccessoryWidgetBackground()
                    Image(systemName: entry.status.level.symbol).font(.title2)
                }
            }
        case .accessoryInline:
            if let last = entry.lastChecked {
                Label { Text("\(entry.status.headline) · \(last, style: .relative)") } icon: { Image(systemName: entry.status.level.symbol) }
            } else {
                Label(entry.status.headline, systemImage: entry.status.level.symbol)
            }
        case .accessoryRectangular:
            VStack(alignment: .leading, spacing: 1) {
                Label(entry.status.headline, systemImage: entry.status.level.symbol)
                    .font(.headline).widgetAccentable()
                if let last = entry.lastChecked {
                    Text("Checked \(last, style: .relative) ago").font(.caption)
                } else {
                    Text("Tap to scan").font(.caption)
                }
                if entry.restartDue {
                    Text(restartLine).font(.caption2.bold())
                } else if let next = entry.nextCheck, next > entry.date {
                    Text("Next check \(next, style: .timer)").font(.caption2.monospacedDigit())
                } else {
                    Text(restartLine).font(.caption2)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        case .systemMedium:
            HStack(alignment: .top, spacing: 14) {
                VStack(alignment: .leading, spacing: 6) {
                    header
                    ForEach(entry.status.lines.prefix(3), id: \.self) { Text($0).font(.caption).lineLimit(1) }
                    Spacer(minLength: 0)
                    lastScanLine
                    if let next = entry.nextCheck, next > entry.date {
                        Text("Next check in \(next, style: .timer)")
                            .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 0)
                VStack(alignment: .trailing, spacing: 8) {
                    restartBadge
                    Spacer(minLength: 0)
                    scanButton
                    cutButton
                }
            }
        case .systemLarge:
            VStack(alignment: .leading, spacing: 10) {
                header.font(.title3)
                ForEach(entry.status.lines, id: \.self) { line in
                    Label(line, systemImage: "circle.fill")
                        .labelStyle(BulletLabelStyle())
                        .font(.subheadline)
                        .lineLimit(1)
                }
                Divider()
                VStack(alignment: .leading, spacing: 4) {
                    lastScanLine
                    if let next = entry.nextCheck, next > entry.date {
                        Text("Next background check in \(next, style: .timer)")
                            .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    } else if entry.nextCheck == nil {
                        Text("Background checks are off").font(.caption).foregroundStyle(.secondary)
                    }
                    restartBadge
                }
                Spacer(minLength: 0)
                HStack(spacing: 10) {
                    scanButton.frame(maxWidth: .infinity)
                    cutButton.frame(maxWidth: .infinity)
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

    private var scanButton: some View {
        Link(destination: URL(string: "amicompromised://scan")!) {
            Label("Scan Now", systemImage: "shield.lefthalf.filled.badge.checkmark")
                .font(.caption.bold())
                .lineLimit(1)
                .padding(.horizontal, 10).padding(.vertical, 7)
                .frame(maxWidth: family == .systemLarge ? .infinity : nil)
                .background(Capsule().fill(Color.accentColor))
                .foregroundStyle(.white)
        }
    }

    /// Opens the app, which runs the emergency Shortcut (Airplane Mode).
    private var cutButton: some View {
        Link(destination: URL(string: "amicompromised://cut")!) {
            Label("Cut", systemImage: "airplane")
                .font(.caption.bold())
                .lineLimit(1)
                .padding(.horizontal, 10).padding(.vertical, 7)
                .frame(maxWidth: family == .systemLarge ? .infinity : nil)
                .background(Capsule().fill(Color.red.opacity(0.85)))
                .foregroundStyle(.white)
        }
        .accessibilityLabel("Cut connections")
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
        if let last = entry.lastChecked {
            Text("Checked \(last, style: .relative) ago").font(.caption2).foregroundStyle(.secondary)
        } else {
            Text("Not scanned yet").font(.caption2).foregroundStyle(.secondary)
        }
    }
}

/// A small coloured dot before each status line.
private struct BulletLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 6) {
            configuration.icon.font(.system(size: 5)).foregroundStyle(.secondary)
            configuration.title
        }
    }
}

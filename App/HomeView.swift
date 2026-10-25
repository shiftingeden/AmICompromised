import CompromiseKit
import SwiftUI

struct HomeView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("acceptedDisclaimer") private var acceptedDisclaimer = false
    @Binding var incomingArchive: URL?
    @State private var path: [Screen] = []

    enum Screen: Hashable { case updates, device, logs, sources, about, mac, support, protection }

    var body: some View {
        NavigationStack(path: $path) {
            List {
                Section {
                    summary
                    scanButton
                } footer: {
                    NoGuaranteeNote().padding(.top, 6)
                }

                Section("Quick Scan") {
                    NavigationLink(value: Screen.updates) {
                        StatusRow(status: model.updateStatus, title: "Software update check", detail: updateSummary)
                    }
                    NavigationLink(value: Screen.device) {
                        StatusRow(status: model.deviceStatus, title: "Device checks", detail: "Passcode, jailbreak signs and a settings checklist.")
                    }
                    NavigationLink(value: Screen.logs) {
                        StatusRow(status: model.logStatus, title: "Spyware log scan", detail: logSummary)
                    }
                }

                Section("Protection") {
                    NavigationLink(value: Screen.protection) {
                        StatusRow(status: BackgroundMonitor.enabled ? .good : .info,
                                  title: "Background checks & alerts",
                                  detail: protectionSummary)
                    }
                    if SharedStatus.restartDue {
                        StatusRow(status: .warning, title: "Time to restart",
                                  detail: "Your iPhone has been on for \(SharedStatus.daysSinceRestart) days. Restarting removes spyware that lives only in memory.")
                    }
                }

                Section("Thorough Scan") {
                    NavigationLink(value: Screen.mac) {
                        StatusRow(status: .info, title: "Deep scan on a Mac",
                                  detail: "Use this app on a Mac to scan a full backup of your iPhone.")
                    }
                }

                Section {
                    NavigationLink(value: Screen.support) {
                        Label("Support & colour themes", systemImage: "heart")
                    }
                    NavigationLink(value: Screen.sources) {
                        Label("Indicator sources", systemImage: "list.bullet.rectangle")
                    }
                    NavigationLink(value: Screen.about) {
                        Label("What this app can and can't do", systemImage: "info.circle")
                    }
                }
            }
            .navigationTitle("Am I Compromised?")
            .refreshable { await model.refreshData() }
            .navigationDestination(for: Screen.self) { screen in
                switch screen {
                case .updates: UpdateCheckView()
                case .device: DeviceChecksView()
                case .logs: LogScanView(incomingArchive: $incomingArchive)
                case .sources: SourcesView()
                case .about: AboutView()
                case .mac: MacScanView()
                case .protection: ProtectionView()
                case .support: TipJarView()
                }
            }
        }
        .fullScreenCover(isPresented: .constant(!acceptedDisclaimer)) {
            DisclaimerView { acceptedDisclaimer = true }
        }
        .onChange(of: incomingArchive) { _, url in
            if url != nil, path.last != .logs { path = [.logs] }
        }
        // Tapping the "sysdiagnose is ready" notification.
        .onChange(of: model.showLogScan) { _, show in
            if show, path.last != .logs { path = [.logs] }
            model.showLogScan = false
        }
    }

    private var scanButton: some View {
        VStack(spacing: 8) {
            Button {
                guard !model.isScanning else { return }
                Task { await model.scanNow() }
            } label: {
                HStack(spacing: 10) {
                    if let phase = model.scanPhase {
                        ProgressView().tint(.white)
                        Text(phase == .updating ? "Checking for updates…" : "Scanning…")
                    } else {
                        Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                        Text("Scan Now")
                    }
                }
                .font(.headline)
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)

            Text("Updates the spyware lists from their repos, then runs every check.")
                .font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if let summary = model.lastUpdateSummary, !model.isScanning {
                Text(summary).font(.caption.bold()).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .listRowSeparator(.hidden)
        .padding(.vertical, 4)
    }

    private var summary: some View {
        let status = model.overallStatus
        let (title, detail): (String, String) = switch status {
        case .alert: ("Something needs your attention", "One or more checks found a problem. Open it below to see what it means and what to do.")
        case .warning: ("Worth a closer look", "Nothing matched a known spyware list, but something looked unusual.")
        case .good: ("No known threats found", "Your checks came back clean against today's public lists.")
        default: ("Not scanned yet", "Run the checks below.")
        }
        return HStack(spacing: 16) {
            Image(systemName: status.symbol)
                .font(.system(size: 44))
                .foregroundStyle(status.color)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.title3.bold())
                Text(detail).font(.subheadline).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 8)
    }

    private var updateSummary: String {
        guard let a = model.assessment else { return "Checking…" }
        if a.affecting.isEmpty { return "iOS \(a.version) has no known actively exploited bugs." }
        return "iOS \(a.version) has \(a.affecting.count) bug\(a.affecting.count == 1 ? "" : "s") used in real attacks. Update now."
    }

    private var protectionSummary: String {
        guard BackgroundMonitor.enabled else { return "Off. Turn on to re-check your last logs against new spyware lists and get alerts." }
        let last = BackgroundMonitor.lastRun.map { "Last check \($0.formatted(.relative(presentation: .named)))." } ?? "Waiting for the first check."
        return "On. " + last
    }

    private var logSummary: String {
        if !model.recheckFindings.isEmpty { return "\(model.recheckFindings.count) match\(model.recheckFindings.count == 1 ? "" : "es") found by a background re-check." }
        guard let r = model.logReport else { return "Scan a sysdiagnose for known traces of mercenary spyware." }
        let when = r.scannedAt.formatted(date: .abbreviated, time: .shortened)
        if !r.matches.isEmpty { return "\(r.matches.count) match\(r.matches.count == 1 ? "" : "es") found (\(when))." }
        if !r.suspicious.isEmpty { return "\(r.suspicious.count) unusual item\(r.suspicious.count == 1 ? "" : "s") (\(when))." }
        return "No known indicators found (\(when))."
    }
}

struct DisclaimerView: View {
    var accept: () -> Void
    @State private var understood = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 56))
                    .foregroundStyle(.tint)
                Text("Before you start").font(.largeTitle.bold())

                point("magnifyingglass", "It looks for known traces",
                      "This app checks your phone against public lists of spyware traces published by human-rights and security researchers, and against bugs known to be used in real attacks.")
                point("exclamationmark.triangle", "There is no guarantee",
                      "New spyware has no public traces until researchers catch it. A clean result does not prove your phone is clean, and a match is a lead, not proof.")
                point("lock.iphone", "iOS limits what any app can see",
                      "Apps can't look inside other apps or the system. That's why part of the scan uses a diagnostic file you create yourself.")
                point("hand.raised", "Everything stays on your phone",
                      "Your logs are scanned on this device. The app only downloads the indicator lists.")

                Toggle("I understand this app can't guarantee my phone is clean.", isOn: $understood)
                    .padding(.top, 8)

                Button(action: accept) {
                    Text("Continue").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!understood)
            }
            .padding(24)
        }
        .interactiveDismissDisabled()
    }

    private func point(_ symbol: String, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: symbol).font(.title2).frame(width: 32).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                Text(text).foregroundStyle(.secondary)
            }
        }
    }
}

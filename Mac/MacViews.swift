import CompromiseKit
import SwiftUI

enum SidebarItem: String, CaseIterable, Identifiable {
    case overview = "Overview", mac = "This Mac", iphone = "iPhone", logs = "Log Files", sources = "Indicator Sources", support = "Support", about = "About"
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .overview: "shield.lefthalf.filled"
        case .mac: "desktopcomputer"
        case .iphone: "iphone"
        case .logs: "doc.text.magnifyingglass"
        case .sources: "list.bullet.rectangle"
        case .support: "heart"
        case .about: "info.circle"
        }
    }
}

struct MacRootView: View {
    @Environment(MacModel.self) private var model
    @State private var section: SidebarItem? = .overview

    var body: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $section) { s in
                Label(s.rawValue, systemImage: s.symbol).tag(s)
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 210)
        } detail: {
            VStack(spacing: 0) {
                if let (text, fraction) = model.activity {
                    HStack(spacing: 10) {
                        if let fraction { ProgressView(value: fraction).frame(width: 140) } else { ProgressView().controlSize(.small) }
                        Text(text).font(.callout)
                        Spacer()
                    }
                    .padding(.horizontal).padding(.vertical, 8)
                    .background(.bar)
                }
                if let error = model.error {
                    HStack {
                        Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
                        Text(error)
                        Spacer()
                        Button("Dismiss") { model.error = nil }
                    }
                    .padding(.horizontal).padding(.vertical, 8)
                    .background(.red.opacity(0.08))
                }
                switch section ?? .overview {
                case .overview: OverviewView(section: $section)
                case .mac: ThisMacView()
                case .iphone: IPhoneView()
                case .logs: LogFilesView()
                case .sources: MacSourcesView()
                case .support: TipJarView()
                case .about: MacAboutView()
                }
            }
        }
    }
}

// MARK: Overview

struct OverviewView: View {
    @Environment(MacModel.self) private var model
    @Binding var section: SidebarItem?

    var body: some View {
        Form {
            Section {
                HStack(spacing: 18) {
                    let status = model.overallStatus
                    Image(systemName: status.symbol).font(.system(size: 52)).foregroundStyle(status.color)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(headline(status)).font(.title2.bold())
                        Text(subline(status)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 6) {
                        Button {
                            Task { await model.scanMac() }
                        } label: {
                            Label("Scan Now", systemImage: "shield.lefthalf.filled.badge.checkmark")
                                .padding(.horizontal, 8).padding(.vertical, 3)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .disabled(model.isBusy)
                        Text("Updates the lists from their repos, then scans this Mac.")
                            .font(.caption).foregroundStyle(.secondary)
                        if let s = model.lastUpdateSummary { Text(s).font(.caption.bold()).foregroundStyle(.secondary) }
                    }
                }
                .padding(.vertical, 6)
                MacNoGuarantee()
            }

            Section("Results") {
                row(.mac, status: model.updateStatus == .alert ? .alert : (model.macReport?.worstStatus ?? model.updateStatus),
                    title: "This Mac", detail: macSummary)
                row(.iphone, status: model.backupReport.map { $0.matches.isEmpty ? .good : .alert } ?? .unknown,
                    title: "iPhone", detail: iphoneSummary)
            }

            if !Build.fullAccess {
                Section {
                    StatusLine(status: .info, title: "Want the full Mac scan?",
                               detail: "Apps from the Mac App Store can't look at background programs, startup items or a connected iPhone. The free direct download from GitHub can. It's the same open-source app, notarized by Apple.")
                    Link("Get the free full version", destination: Build.directDownloadURL)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Am I Compromised?")
    }

    private func row(_ target: SidebarItem, status: SystemCheck.Status, title: String, detail: String) -> some View {
        Button { section = target } label: {
            HStack {
                StatusLine(status: status, title: title, detail: detail)
                Spacer()
                Image(systemName: "chevron.right").foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func headline(_ s: SystemCheck.Status) -> String {
        switch s {
        case .alert: "Something needs your attention"
        case .warning: "Worth a closer look"
        case .good: "No known threats found"
        default: "Not scanned yet"
        }
    }

    private func subline(_ s: SystemCheck.Status) -> String {
        switch s {
        case .alert: "A check found a problem. Open it to see what it means and what to do."
        case .warning: "Nothing matched a spyware list, but something looked unusual."
        case .good: "Your checks came back clean against today's public lists."
        default: "Click Scan Now to check this Mac."
        }
    }

    private var macSummary: String {
        var parts: [String] = []
        if let a = model.macAssessment {
            parts.append(a.affecting.isEmpty
                ? "macOS \(a.version) has no known actively exploited bugs."
                : "macOS \(a.version) has \(a.affecting.count) bug(s) used in real attacks. Update now.")
        }
        if let r = model.macReport {
            parts.append("Last scan \(r.scannedAt.formatted(.relative(presentation: .named))): \(r.matches.isEmpty ? "no known indicators" : "\(r.matches.count) match(es)").")
        }
        return parts.joined(separator: " ")
    }

    private var iphoneSummary: String {
        guard let r = model.backupReport else { return "Scan a backup of your iPhone for traces of Pegasus, Predator and others." }
        return "\(r.device.deviceName), backup scanned \(r.scannedAt.formatted(.relative(presentation: .named))): \(r.matches.isEmpty ? "no known indicators" : "\(r.matches.count) match(es)")."
    }
}

// MARK: This Mac

struct ThisMacView: View {
    @Environment(MacModel.self) private var model

    var body: some View {
        Form {
            if let a = model.macAssessment {
                Section("Software update") {
                    if a.affecting.isEmpty {
                        StatusLine(status: .good, title: "macOS \(a.version)",
                                   detail: "None of the bugs on CISA's Known Exploited Vulnerabilities list affect this version.")
                    } else {
                        StatusLine(status: .alert, title: "macOS \(a.version) needs an update",
                                   detail: "\(a.affecting.count) bug(s) on this version have been used in real attacks." + (a.updateTo.map { " Update to macOS \($0) or later." } ?? ""))
                        Button("Open Software Update") {
                            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension")!)
                        }
                        ForEach(a.affecting) { bug in
                            Link(destination: bug.nvdURL) {
                                VStack(alignment: .leading) {
                                    Text(bug.cve).font(.headline.monospaced())
                                    Text(bug.summary).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
            }

            if let report = model.macReport {
                if !report.findings.isEmpty {
                    MacFindingsSection(findings: report.findings)
                }
                Section("Checks · \(report.scannedAt.formatted(date: .abbreviated, time: .shortened))") {
                    ForEach(report.checks) { check in
                        if check.items.isEmpty {
                            StatusLine(status: check.status, title: check.title, detail: check.detail)
                        } else {
                            DisclosureGroup {
                                ForEach(check.items, id: \.self) { Text($0).font(.callout.monospaced()).textSelection(.enabled) }
                            } label: {
                                StatusLine(status: check.status, title: check.title, detail: check.detail)
                            }
                        }
                    }
                }
            } else {
                Section {
                    Text("Not scanned yet.")
                    Button("Scan This Mac") { Task { await model.scanMac() } }.disabled(model.isBusy)
                }
            }
            Section { MacNoGuarantee() }
        }
        .formStyle(.grouped)
        .navigationTitle("This Mac")
        .toolbar {
            Button { Task { await model.scanMac() } } label: { Label("Scan", systemImage: "arrow.clockwise") }
                .disabled(model.isBusy)
        }
    }
}

struct MacFindingsSection: View {
    var findings: [Finding]

    var body: some View {
        Section("Findings") {
            ForEach(findings) { f in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Image(systemName: f.level == .match ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(f.level == .match ? .red : .orange)
                        Text(f.kind).font(.headline)
                        if let c = f.campaign {
                            Text(c.replacingOccurrences(of: " Indicators of Compromise", with: "")).font(.subheadline.bold())
                        }
                    }
                    Text(f.value).font(.callout.monospaced()).textSelection(.enabled)
                    Text(f.detail).foregroundStyle(.secondary)
                    Text(f.file).font(.caption.monospaced()).foregroundStyle(.tertiary)
                }
                .padding(.vertical, 3)
            }
            if findings.contains(where: { $0.level == .match }) {
                Text("A match is a lead, not proof. Keep the evidence and contact the Access Now Digital Security Helpline or Amnesty's Security Lab for a free expert check.")
                    .foregroundStyle(.secondary)
                HStack {
                    Link("Access Now Helpline", destination: URL(string: "https://www.accessnow.org/help/")!)
                    Link("Amnesty Security Lab", destination: URL(string: "https://securitylab.amnesty.org/get-help/")!)
                }
            }
        }
    }
}

// MARK: iPhone

struct IPhoneView: View {
    @Environment(MacModel.self) private var model
    #if FULL_SCAN
    @Environment(DeviceWatcher.self) private var watcher
    #endif
    @State private var passwordFor: BackupInfo?
    @State private var password = ""

    var body: some View {
        Form {
            #if FULL_SCAN
            connectedSection
            backupsSection
            #else
            Section("Scan an iPhone backup") {
                Text("1. Connect your iPhone, open Finder and select it in the sidebar.\n2. Turn on **Encrypt local backup** (it includes far more data to check), then click **Back Up Now**.\n3. Click below and choose the backup folder. Finder keeps backups in ~/Library/Application Support/MobileSync/Backup.")
                Button("Choose Backup Folder…") {
                    if let info = model.chooseBackupFolder() { start(info) }
                }
                .disabled(model.isBusy)
            }
            #endif

            if let report = model.backupReport {
                Section("Last backup scan · \(report.device.deviceName) · iOS \(report.device.iOSVersion)") {
                    if report.matches.isEmpty {
                        StatusLine(status: .good, title: "No known indicators found",
                                   detail: "Checked against \(report.indicatorCount.formatted()) indicators on \(report.scannedAt.formatted(date: .abbreviated, time: .shortened)).")
                    } else {
                        StatusLine(status: .alert, title: "Possible spyware traces found",
                                   detail: "\(report.matches.count) item(s) match a published spyware list. This is a lead, not proof.")
                    }
                    let a = model.catalog.assess(OSVersion(report.device.iOSVersion) ?? OSVersion([0]), on: .iOS)
                    if !a.affecting.isEmpty {
                        StatusLine(status: .alert, title: "iOS \(report.device.iOSVersion) needs an update",
                                   detail: "\(a.affecting.count) bug(s) on this version have been used in real attacks." + (a.updateTo.map { " Update to iOS \($0) or later." } ?? ""))
                    }
                    DisclosureGroup("What was checked") {
                        ForEach(report.coverage, id: \.self) { Text($0) }
                    }
                    if !report.device.isEncrypted {
                        StatusLine(status: .info, title: "This backup isn't encrypted",
                                   detail: "Unencrypted backups leave out Safari history and other data. For a deeper scan, turn on Encrypt local backup in Finder and back up again.")
                    }
                }
                if !report.findings.isEmpty { MacFindingsSection(findings: report.findings) }
            }
            Section { MacNoGuarantee() }
        }
        .formStyle(.grouped)
        .navigationTitle("iPhone")
        .sheet(item: $passwordFor) { info in
            VStack(alignment: .leading, spacing: 14) {
                Text("Backup password").font(.title2.bold())
                Text("\(info.deviceName)'s backup is encrypted. Enter the password you set in Finder when you turned on encryption. It's used only to unlock the backup on this Mac and is never saved.")
                SecureField("Backup password", text: $password).onSubmit { submit(info) }
                HStack {
                    Spacer()
                    Button("Cancel") { passwordFor = nil; password = "" }
                    Button("Scan") { submit(info) }.keyboardShortcut(.defaultAction).disabled(password.isEmpty)
                }
            }
            .padding(24)
            .frame(width: 440)
        }
    }

    private func start(_ info: BackupInfo) {
        if info.isEncrypted { passwordFor = info } else { Task { await model.scanBackup(info, password: nil) } }
    }

    private func submit(_ info: BackupInfo) {
        let entered = password
        password = ""
        passwordFor = nil
        Task {
            if !(await model.scanBackup(info, password: entered)) { passwordFor = info }
        }
    }

    #if FULL_SCAN
    @ViewBuilder private var connectedSection: some View {
        Section("Connected iPhone") {
            if let device = watcher.device {
                StatusLine(status: .info, title: device.name, detail: "Connected by USB. Back it up and scan it in one step.")
                if watcher.isBackingUp {
                    HStack { ProgressView().controlSize(.small); Text("Backing up… Unlock your iPhone and tap Trust if asked.") }
                    if !watcher.backupLog.isEmpty {
                        Text(watcher.backupLog.split(separator: "\n").suffix(3).joined(separator: "\n"))
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                } else if DeviceWatcher.canBackUp {
                    Button("Back Up and Scan") { Task { await backUpAndScan(device) } }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.isBusy || model.needsFullDiskAccess)
                    Text("Tip: turn on Encrypt local backup in Finder first. Encrypted backups include much more to check.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("Back it up from Finder, then pick it below.").foregroundStyle(.secondary)
                }
                if let failed = watcher.backupFailed { Text(failed).foregroundStyle(.red) }
            } else {
                StatusLine(status: .unknown, title: "No iPhone connected",
                           detail: "Connect your iPhone with a cable to back it up and scan it, or scan an existing backup below.")
            }
        }
    }

    @ViewBuilder private var backupsSection: some View {
        Section("Backups on this Mac") {
            if model.needsFullDiskAccess {
                StatusLine(status: .warning, title: "Full Disk Access needed",
                           detail: "macOS protects the folder where Finder keeps iPhone backups. Turn on Full Disk Access for Am I Compromised?, then come back.")
                HStack {
                    Button("Open Privacy Settings") { NSWorkspace.shared.open(Build.fullDiskAccessSettings) }
                    Button("Check Again") { model.loadBackups() }
                }
            } else if model.backups.isEmpty {
                Text("No backups yet. Use Back Up and Scan above, or back up from Finder.").foregroundStyle(.secondary)
            } else {
                ForEach(model.backups, id: \.folder) { info in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(info.deviceName).font(.headline)
                            Text("iOS \(info.iOSVersion) · \(info.lastBackup?.formatted(date: .abbreviated, time: .shortened) ?? "unknown date") · \(info.isEncrypted ? "encrypted" : "not encrypted")")
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Scan") { start(info) }.disabled(model.isBusy)
                    }
                }
            }
        }
    }

    private func backUpAndScan(_ device: DeviceWatcher.Device) async {
        guard await watcher.backUp(device) else { return }
        model.loadBackups()
        let id = device.serial.replacingOccurrences(of: "-", with: "")
        if let info = model.backups.first(where: { $0.udid.replacingOccurrences(of: "-", with: "") == id }) ?? model.backups.first {
            start(info)
        }
    }
    #endif
}

extension BackupInfo: Identifiable {
    public var id: URL { folder }
}

// MARK: Logs, sources, about

struct LogFilesView: View {
    @Environment(MacModel.self) private var model

    var body: some View {
        Form {
            Section("Scan a sysdiagnose or log folder") {
                Text("Works with a sysdiagnose from an iPhone (AirDrop it to this Mac) or from this Mac (run `sudo sysdiagnose` in Terminal), or any folder of logs.")
                Button("Choose File or Folder…") { Task { await model.chooseAndScanLogs() } }.disabled(model.isBusy)
            }
            if let r = model.logReport {
                Section("\(r.archiveName) · \(r.filesScanned) files") {
                    if r.findings.isEmpty {
                        StatusLine(status: .good, title: "No known indicators found",
                                   detail: "Checked against \(r.indicatorCount.formatted()) indicators.")
                    }
                }
                if !r.findings.isEmpty { MacFindingsSection(findings: r.findings) }
            }
            Section { MacNoGuarantee() }
        }
        .formStyle(.grouped)
        .navigationTitle("Log Files")
    }
}

struct MacSourcesView: View {
    @Environment(MacModel.self) private var model

    var body: some View {
        Form {
            Section {
                if let set = model.indicators, let updated = set.updated {
                    LabeledContent("Indicators", value: set.total.formatted())
                    LabeledContent("Last updated", value: updated.formatted(date: .abbreviated, time: .shortened))
                }
                LabeledContent("Exploited Apple bugs", value: model.catalog.entries.count.formatted())
                Button("Update Now") { Task { await model.refreshData() } }.disabled(model.isBusy)
            } footer: {
                Text("Spyware indicators come from the public mvt-indicators index; exploited bugs from CISA's KEV catalog with NVD version data. New campaigns appear without an app update.")
            }
            if let set = model.indicators {
                Section("Campaigns") {
                    ForEach(set.sourceCounts.sorted { $0.key < $1.key }, id: \.key) { name, count in
                        LabeledContent(name.replacingOccurrences(of: " Indicators of Compromise", with: ""), value: count.formatted())
                    }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Indicator Sources")
    }
}

struct MacAboutView: View {
    var body: some View {
        Form {
            Section("What it checks") {
                Text("Whether macOS and your iPhone's iOS have bugs being used in real attacks.")
                Text(Build.fullAccess
                     ? "This Mac: security settings, running programs, startup items, profiles, system extensions, the hosts file and crash logs."
                     : "This Mac: running apps (the full version also checks background programs, startup items and settings).")
                Text("iPhone backups: installed apps, messages, Safari and Chrome history, WhatsApp, data usage and configuration profiles, matched against published spyware traces.")
            }
            Section("What it can't do") {
                Text("Find spyware nobody has published traces for yet. Zero-day attacks are unknown until someone catches them.")
                Text("Prove a device is clean, or prove it's infected. A match is a strong lead for an expert to look at.")
            }
            Section("Open source") {
                Link("Source code on GitHub", destination: URL(string: "https://github.com/shiftingeden/AmICompromised")!)
                Link("Mobile Verification Toolkit (Amnesty International)", destination: URL(string: "https://github.com/mvt-project/mvt")!)
            }
            Section { MacNoGuarantee() }
        }
        .formStyle(.grouped)
        .navigationTitle("About")
    }
}

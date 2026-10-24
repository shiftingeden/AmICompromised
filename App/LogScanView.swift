import CompromiseKit
import SwiftUI
import UniformTypeIdentifiers

struct LogScanView: View {
    @Environment(AppModel.self) private var model
    @Binding var incomingArchive: URL?
    @State private var importing = false

    var body: some View {
        List {
            if model.logScanUpdating {
                Section {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Checking for indicator updates before scanning…").font(.subheadline)
                    }
                }
            } else if let progress = model.logScanProgress {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Scanning your logs…").font(.headline)
                        ProgressView(value: progress)
                        Text("This takes a minute or two. Everything stays on this phone.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            } else {
                captureSteps
            }

            if let error = model.logScanError {
                Section { Text(error).foregroundStyle(.red).font(.footnote) }
            }

            if let report = model.logReport, model.logScanProgress == nil {
                ReportSections(report: report)
            }

            Section {
                Text("A sysdiagnose is a bundle of system logs that iOS creates for Apple support. It includes the list of running processes, crash reports and the shutdown log, which is where traces of past spyware have been found. iOS doesn't let apps create or open one themselves, so it takes these three steps.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Spyware Log Scan")
        .fileImporter(isPresented: $importing, allowedContentTypes: [.gzip, .archive, .data]) { result in
            if case .success(let url) = result { Task { await model.scanLogs(at: url) } }
        }
        .task(id: incomingArchive) {
            guard let url = incomingArchive else { return }
            incomingArchive = nil
            await model.scanLogs(at: url)
        }
        // The sysdiagnose button combo also takes a screenshot.
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
            Task { await model.sysdiagnoseStarted() }
        }
    }

    @ViewBuilder private var captureSteps: some View {
        let started = model.sysdiagnoseStartedAt != nil
        Section {
            step(1, done: started, title: "Start a sysdiagnose",
                 text: started
                    ? "Started \(model.sysdiagnoseStartedAt!.formatted(date: .omitted, time: .shortened))."
                    : "Stay on this screen. Press both volume buttons and the side button together for about one second, then let go. The screen flashes like a screenshot.")
            if !started {
                Button("I pressed the buttons") { Task { await model.sysdiagnoseStarted() } }
                    .font(.subheadline)
            }

            step(2, done: false, title: "Wait while iOS collects its logs",
                 text: started ? "" : "Takes up to 10 minutes. You can leave the app; we'll send a notification when it should be ready.")
            if let readyAt = model.sysdiagnoseReadyAt {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    countdown(readyAt: readyAt, now: context.date)
                }
            }

            step(3, done: false, title: "Share it to this app",
                 text: "Open Settings › Privacy & Security › Analytics & Improvements › Analytics Data. Search for \"sysdiagnose\", tap the newest file, tap Share, then pick Am I Compromised?. The scan starts by itself.")
            Button {
                importing = true
            } label: {
                Label("Or choose a file you saved", systemImage: "doc.badge.plus")
            }
            .font(.subheadline)
        } header: {
            Text("Scan a new sysdiagnose")
        } footer: {
            if started {
                Button("Start over") { model.cancelSysdiagnoseCapture() }
                    .font(.footnote)
            }
        }
    }

    private func countdown(readyAt: Date, now: Date) -> some View {
        let remaining = readyAt.timeIntervalSince(now)
        let elapsed = AppModel.sysdiagnoseDuration - remaining
        return VStack(alignment: .leading, spacing: 6) {
            ProgressView(value: min(1, max(0, elapsed / AppModel.sysdiagnoseDuration)))
            if remaining > 0 {
                let minutes = Int((remaining / 60).rounded(.up))
                Text("About \(minutes) min left. We'll notify you when it should be ready.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else {
                Label("It should be ready now. Go to step 3.", systemImage: "checkmark.circle.fill")
                    .font(.footnote.bold()).foregroundStyle(.green)
            }
        }
        .padding(.leading, 38)
        .padding(.bottom, 4)
    }

    private func step(_ n: Int, done: Bool, title: String, text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                Circle().fill(done ? AnyShapeStyle(.green) : AnyShapeStyle(.tint.opacity(0.15)))
                if done {
                    Image(systemName: "checkmark").font(.caption.bold()).foregroundStyle(.white)
                } else {
                    Text("\(n)").font(.subheadline.bold())
                }
            }
            .frame(width: 26, height: 26)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline)
                if !text.isEmpty {
                    Text(text).font(.subheadline).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 2)
    }
}

private struct ReportSections: View {
    var report: LogScanReport

    var body: some View {
        Section {
            if !report.matches.isEmpty {
                StatusRow(status: .alert, title: "Possible spyware traces found",
                          detail: "\(report.matches.count) item\(report.matches.count == 1 ? "" : "s") in your logs \(report.matches.count == 1 ? "matches" : "match") a published spyware list. This is a lead, not proof. Read what to do below.")
            } else if !report.suspicious.isEmpty {
                StatusRow(status: .warning, title: "Nothing matched, but something looked unusual",
                          detail: "No published indicator matched. The items below look like patterns seen in past attacks and are often harmless.")
            } else {
                StatusRow(status: .good, title: "No known indicators found",
                          detail: "Checked against \(report.indicatorCount.formatted()) published indicators.")
            }
            if report.looksIncomplete {
                StatusRow(status: .warning, title: "This file may not be a full sysdiagnose",
                          detail: "It didn't contain the process list or shutdown log, so the scan covered less than usual.")
            }
        } header: {
            Text("Last scan · \(report.scannedAt.formatted(date: .abbreviated, time: .shortened))")
        } footer: {
            // A match already says "a lead, not proof"; the clean-result
            // caveat only makes sense when nothing matched.
            if report.matches.isEmpty { NoGuaranteeNote().padding(.top, 6) }
        }

        if !report.matches.isEmpty {
            findings("Matches", report.matches, status: .alert)
            Section("What to do now") {
                Text("Don't delete the sysdiagnose file. An expert can confirm or rule out an infection from it.")
                Text("Contact a helpline that examines phones for free.")
                Link("Access Now Digital Security Helpline", destination: URL(string: "https://www.accessnow.org/help/")!)
                Link("Amnesty International Security Lab", destination: URL(string: "https://securitylab.amnesty.org/get-help/")!)
                Text("Meanwhile, update iOS, turn on Lockdown Mode, and restart your phone.")
            }
        }
        if !report.suspicious.isEmpty {
            findings("Unusual", report.suspicious, status: .warning)
        }

        Section("Scan details") {
            LabeledContent("File", value: report.archiveName)
            LabeledContent("Log files scanned", value: report.filesScanned.formatted())
            LabeledContent("Data scanned", value: ByteCountFormatter.string(fromByteCount: Int64(report.bytesScanned), countStyle: .file))
            LabeledContent("Process list", value: report.sawProcessList ? "Checked" : "Not found")
            LabeledContent("Shutdown log", value: report.sawShutdownLog ? "Checked" : "Not found")
            LabeledContent("Crash reports", value: report.crashLogCount.formatted())
            ShareLink(item: summaryText) { Label("Share report", systemImage: "square.and.arrow.up") }
        }
    }

    private func findings(_ title: String, _ items: [Finding], status: CheckStatus) -> some View {
        Section(title) {
            ForEach(items) { f in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        StatusIcon(status: status)
                        Text(f.kind).font(.headline)
                    }
                    Text(f.value).font(.callout.monospaced()).textSelection(.enabled)
                    if let campaign = f.campaign {
                        Text(campaign.replacingOccurrences(of: " Indicators of Compromise", with: ""))
                            .font(.subheadline.bold())
                    }
                    Text(f.detail).font(.footnote).foregroundStyle(.secondary)
                    Text(f.file).font(.caption2.monospaced()).foregroundStyle(.tertiary).lineLimit(2)
                }
                .padding(.vertical, 4)
            }
        }
    }

    private var summaryText: String {
        var lines = [
            "Am I Compromised? log scan",
            "File: \(report.archiveName)",
            "Scanned: \(report.scannedAt.formatted())",
            "Indicators checked: \(report.indicatorCount)",
            "Files scanned: \(report.filesScanned)",
            "",
        ]
        for f in report.findings {
            lines.append("[\(f.level == .match ? "MATCH" : "UNUSUAL")] \(f.kind): \(f.value)")
            if let c = f.campaign { lines.append("  Campaign: \(c)") }
            lines.append("  In: \(f.file)")
        }
        if report.findings.isEmpty { lines.append("No known indicators found.") }
        lines += ["", "A clean result can't prove a phone is clean: new spyware has no public indicators until it is discovered."]
        return lines.joined(separator: "\n")
    }
}

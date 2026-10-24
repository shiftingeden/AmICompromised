import CompromiseKit
import SwiftUI

struct UpdateCheckView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        List {
            if let a = model.assessment {
                Section {
                    if a.affecting.isEmpty {
                        StatusRow(status: .good, title: "iOS \(a.version)",
                                  detail: "None of the bugs on CISA's Known Exploited Vulnerabilities list affect this version.")
                    } else {
                        StatusRow(status: .alert, title: "iOS \(a.version) needs an update",
                                  detail: updateAdvice(a))
                        Button("Open Software Update") { openSettings() }
                    }
                } footer: {
                    Text("Bug list from CISA's Known Exploited Vulnerabilities catalog, with fixed versions from the US National Vulnerability Database. Updated \(a.catalogDate.prefix(10)).")
                }

                if !a.affecting.isEmpty {
                    Section("Bugs used in real attacks that affect this phone") {
                        ForEach(a.affecting) { bug in
                            Link(destination: bug.nvdURL) {
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Text(bug.cve).font(.headline.monospaced())
                                        Spacer()
                                        if let fixed = bug.fixedVersion(for: a.version) {
                                            Text("Fixed in \(fixed.description)").font(.caption).foregroundStyle(.secondary)
                                        }
                                    }
                                    Text(bug.summary).font(.subheadline).foregroundStyle(.secondary)
                                }
                            }
                            .foregroundStyle(.primary)
                        }
                    }
                }

                Section {
                    Text("An affected version doesn't mean your phone was attacked. It means attackers have a known way in that an update closes.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Software Update")
    }

    private func updateAdvice(_ a: ExploitedBugCatalog.Assessment) -> String {
        let count = "\(a.affecting.count) bug\(a.affecting.count == 1 ? "" : "s") on this version \(a.affecting.count == 1 ? "has" : "have") been used in real attacks."
        if let target = a.updateTo { return count + " Update to iOS \(target) or later." }
        return count + " Install the latest iOS update."
    }

    private func openSettings() {
        if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
    }
}

struct DeviceChecksView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("manualChecksDone") private var doneRaw = ""

    private var done: Set<String> { Set(doneRaw.split(separator: ",").map(String.init)) }

    var body: some View {
        List {
            Section("Checked automatically") {
                ForEach(model.deviceChecks) { check in
                    StatusRow(status: check.status, title: check.title, detail: check.detail)
                    if !check.fix.isEmpty {
                        FixSteps(steps: check.fix)
                    }
                }
            }
            Section {
                ForEach(ManualCheck.all) { check in
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(check.path).font(.subheadline)
                            Text(check.why).font(.footnote).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 4)
                    } label: {
                        Button {
                            toggle(check.id)
                        } label: {
                            Label(check.title, systemImage: done.contains(check.id) ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(done.contains(check.id) ? .green : .primary)
                        }
                        .buttonStyle(.plain)
                    }
                }
            } header: {
                Text("Check these yourself")
            } footer: {
                Text("iOS doesn't let apps read these settings. Tap a row for where to find it, then tick it off.")
            }
        }
        .navigationTitle("Device Checks")
        .onAppear { model.runQuickScan() }
    }

    private func toggle(_ id: String) {
        var set = done
        if !set.insert(id).inserted { set.remove(id) }
        doneRaw = set.sorted().joined(separator: ",")
    }
}

/// Numbered "what to do" steps under a check that found a problem.
struct FixSteps: View {
    var steps: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("What to do").font(.subheadline.bold())
            ForEach(Array(steps.enumerated()), id: \.offset) { i, step in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(i + 1).").font(.subheadline.monospacedDigit()).foregroundStyle(.secondary)
                    Text(step).font(.subheadline)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

struct SourcesView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        List {
            Section {
                if let set = model.indicators, let updated = set.updated {
                    LabeledContent("Indicators", value: set.total.formatted())
                    LabeledContent("Last updated", value: updated.formatted(date: .abbreviated, time: .shortened))
                } else {
                    Text("Not downloaded yet.")
                }
                Button {
                    Task { await model.refreshData() }
                } label: {
                    if model.isUpdatingIndicators {
                        HStack { ProgressView(); Text("Updating…") }
                    } else {
                        Text("Update now")
                    }
                }
                .disabled(model.isUpdatingIndicators)
                if let error = model.indicatorError {
                    Text(error).foregroundStyle(.red).font(.footnote)
                }
            } footer: {
                Text("Lists come from the public mvt-indicators index maintained by the Mobile Verification Toolkit project. New campaigns appear here as soon as they're published, without an app update.")
            }

            if let set = model.indicators {
                Section("Campaigns") {
                    ForEach(set.sourceCounts.sorted { $0.key < $1.key }, id: \.key) { name, count in
                        LabeledContent(name.replacingOccurrences(of: " Indicators of Compromise", with: ""),
                                       value: count.formatted())
                    }
                }
            }
            if !model.failedSources.isEmpty {
                Section("Couldn't update") {
                    ForEach(model.failedSources, id: \.self) { Text($0) }
                }
            }
            Section("Credits") {
                Link("Mobile Verification Toolkit (Amnesty International)", destination: URL(string: "https://github.com/mvt-project/mvt-indicators")!)
                Link("Citizen Lab malware indicators", destination: URL(string: "https://github.com/citizenlab/malware-indicators")!)
                Link("CISA Known Exploited Vulnerabilities", destination: URL(string: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")!)
            }
        }
        .navigationTitle("Indicator Sources")
    }
}

struct AboutView: View {
    var body: some View {
        List {
            Section("What it checks") {
                Text("Whether your iOS version has bugs that are being used in real attacks.")
                Text("Basic device security: passcode and signs of a jailbreak.")
                Text("A sysdiagnose (system logs you create) for known traces of mercenary spyware and stalkerware: domains, process names, file paths and more.")
            }
            Section("What it can't do") {
                Text("Find spyware nobody has published traces for yet. Zero-day attacks are, by definition, unknown until someone catches them.")
                Text("Look inside other apps or the system directly. iOS doesn't allow any app to do that.")
                Text("Prove your phone is clean, or prove it's infected. A match is a strong lead that an expert should look at.")
            }
            Section("If you think you're targeted") {
                Link("Access Now Digital Security Helpline (free, 24/7)", destination: URL(string: "https://www.accessnow.org/help/")!)
                Link("Amnesty International Security Lab", destination: URL(string: "https://securitylab.amnesty.org/get-help/")!)
                Text("Keep your sysdiagnose file: experts can examine it further. Turn on Lockdown Mode and update iOS.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            FeedbackSection()
            Section {
                NoGuaranteeNote()
            }
        }
        .navigationTitle("About")
    }
}

struct MacScanView: View {
    var body: some View {
        List {
            Section {
                Text("Am I Compromised? also runs on a Mac. Plug in your iPhone and it backs it up and scans the backup, which holds far more than a sysdiagnose: messages, browsing history, data usage and installed apps. It checks the Mac itself too.")
            } header: {
                Text("Deep scan on a Mac")
            }
            Section {
                Label("Mac App Store: the same free app. Scans a backup you make in Finder.", systemImage: "bag")
                Label("Full version from GitHub: also scans the whole Mac and backs up a connected iPhone for you.", systemImage: "arrow.down.circle")
                Link("Get the full Mac version", destination: URL(string: "https://github.com/shiftingeden/AmICompromised/releases/latest")!)
            } footer: {
                Text("Turn on Encrypt local backup in Finder for the deepest scan. Your backup and its password never leave your Mac.")
            }
        }
        .navigationTitle("Thorough Scan")
    }
}

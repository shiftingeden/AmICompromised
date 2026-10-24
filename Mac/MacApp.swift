import CompromiseKit
import SwiftUI

@main
struct AmICompromisedMacApp: App {
    @State private var model = MacModel()
    @AppStorage("acceptedDisclaimer") private var acceptedDisclaimer = false
    @AppStorage("theme") private var theme = Theme.ocean.rawValue
    @State private var jar = TipJar.shared
    #if FULL_SCAN
    @State private var watcher = DeviceWatcher()
    #endif

    var body: some Scene {
        WindowGroup {
            MacRootView()
                .environment(model)
                .appTheme(theme, supporter: jar.isSupporter)
                .task(id: jar.isSupporter) { AppIconChoice.restore(supporter: jar.isSupporter) }
                #if FULL_SCAN
                .environment(watcher)
                .onAppear { watcher.start() }
                #endif
                .task { await model.start() }
                .sheet(isPresented: .constant(!acceptedDisclaimer)) {
                    MacDisclaimer { acceptedDisclaimer = true }
                }
                .frame(minWidth: 860, minHeight: 560)
        }
        .windowToolbarStyle(.unified)
    }
}

extension SystemCheck.Status {
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

struct StatusLine: View {
    var status: SystemCheck.Status
    var title: String
    var detail: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: status.symbol).foregroundStyle(status.color).font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(detail).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 3)
    }
}

struct MacNoGuarantee: View {
    var body: some View {
        Label("A clean result means no **known** traces were found. New spyware has no public indicators until researchers catch it, so this can't prove a device is clean.",
              systemImage: "exclamationmark.bubble")
            .font(.callout)
            .foregroundStyle(.secondary)
    }
}

struct MacDisclaimer: View {
    var accept: () -> Void
    @State private var understood = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Before you start").font(.largeTitle.bold())
            Text("Am I Compromised? checks your Mac and iPhone against public lists of spyware traces published by human-rights and security researchers, and against bugs known to be used in real attacks.")
            Text("**There is no guarantee.** New spyware has no public traces until researchers catch it. A clean result doesn't prove a device is clean, and a match is a lead, not proof.")
            Text("**Everything stays on your Mac.** Logs and backups are scanned locally; the app only downloads the indicator lists.")
            Toggle("I understand this app can't guarantee my devices are clean.", isOn: $understood)
            HStack {
                Spacer()
                Button("Continue", action: accept).keyboardShortcut(.defaultAction).disabled(!understood)
            }
        }
        .padding(28)
        .frame(width: 520)
        .interactiveDismissDisabled()
    }
}

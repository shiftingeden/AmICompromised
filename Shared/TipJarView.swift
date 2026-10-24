import StoreKit
import SwiftUI

struct TipJarView: View {
    @State private var jar = TipJar.shared
    @AppStorage("theme") private var theme = Theme.ocean.rawValue

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Image(systemName: "heart.circle.fill").font(.system(size: 44)).foregroundStyle(.pink)
                    Text("Am I Compromised? is free").font(.title2.bold())
                    Text("No ads, no tracking, no scan limits, and the code is open source. If it helped you, a tip keeps it maintained. Tipping once also unlocks the Orange and Gold app icons and the colour themes below as a thank-you.")
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 6)
            }

            if jar.isSupporter, TipJar.storeAvailable {
                Section {
                    Label(jar.justTipped ? "Thank you! Icons and themes unlocked." : "You're a supporter. Thank you!",
                          systemImage: "sparkles")
                        .font(.headline)
                        .foregroundStyle(.pink)
                }
            }

            if TipJar.storeAvailable {
                Section("Leave a tip") {
                    if jar.isLoading {
                        HStack { ProgressView(); Text("Loading…").foregroundStyle(.secondary) }
                    }
                    ForEach(jar.products) { product in
                        let (symbol, name) = TipJar.label(for: product)
                        Button {
                            Task { await jar.tip(product) }
                        } label: {
                            HStack {
                                Label(name, systemImage: symbol)
                                Spacer()
                                Text(product.displayPrice).bold()
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .padding(.vertical, 2)
                    }
                    if let message = jar.message {
                        Text(message).font(.footnote).foregroundStyle(.secondary)
                    }
                    Button("Restore Earlier Tip") { Task { await jar.restore() } }
                        .font(.footnote)
                }
            } else {
                Section {
                    Text("This free download isn't from the App Store, so it can't take tips, and the themes are unlocked for you. If you'd like to support the developer, you can tip in the iPhone or Mac App Store version.")
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                AppIconPicker(unlocked: jar.isSupporter)
            } header: {
                Text("App icon")
            } footer: {
                if !jar.isSupporter { Text("Navy is free. Orange and Gold unlock with any tip.") }
            }

            Section {
                ThemePicker(selection: $theme, unlocked: jar.isSupporter)
            } header: {
                Text("Colour theme")
            } footer: {
                if !jar.isSupporter { Text("Ocean is free. The others unlock with any tip.") }
            }

            FeedbackSection()
        }
        .formStyle(.grouped)
        .navigationTitle("Support")
        .task { await jar.loadProducts() }
    }
}

struct ThemePicker: View {
    @Binding var selection: String
    var unlocked: Bool

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 64), spacing: 12)], spacing: 14) {
            ForEach(Theme.allCases) { theme in
                let locked = theme.needsSupporter && !unlocked
                Button {
                    if !locked { selection = theme.rawValue }
                } label: {
                    VStack(spacing: 6) {
                        ZStack {
                            Circle().fill(theme.color).frame(width: 40, height: 40)
                            if locked {
                                Image(systemName: "lock.fill").font(.caption).foregroundStyle(.white)
                            } else if selection == theme.rawValue {
                                Image(systemName: "checkmark").font(.headline).foregroundStyle(.white)
                            }
                        }
                        .overlay(Circle().stroke(selection == theme.rawValue ? theme.color : .clear, lineWidth: 2).padding(-4))
                        Text(theme.name).font(.caption).foregroundStyle(locked ? .secondary : .primary)
                    }
                    .opacity(locked ? 0.55 : 1)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(theme.name + (locked ? ", locked" : ""))
            }
        }
        .padding(.vertical, 6)
    }
}

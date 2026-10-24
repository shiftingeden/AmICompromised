import CompromiseKit
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import UserNotifications

/// "Scan with Am I Compromised?" in the Share sheet's action row.
///
/// It copies the sysdiagnose into the App Group inbox and posts a
/// notification that opens the app, which runs the scan. Action extensions
/// can't open their app directly, and a 300 MB scan would outlive the
/// extension's time and memory limits anyway.
final class ActionViewController: UIViewController {
    private let state = ActionState()

    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: ActionView(state: state) { [weak self] in
            self?.extensionContext?.completeRequest(returningItems: nil)
        })
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        Task { await receive() }
    }

    private func receive() async {
        let providers = (extensionContext?.inputItems as? [NSExtensionItem] ?? [])
            .flatMap { $0.attachments ?? [] }
        let types = [UTType.gzip, UTType("public.tar-archive"), .archive, .data].compactMap { $0?.identifier }
        guard let provider = providers.first,
              let type = types.first(where: provider.hasItemConformingToTypeIdentifier) else {
            state.phase = .failed("This doesn't look like a sysdiagnose archive.")
            return
        }

        // The provider's temporary file disappears when the handler returns,
        // so the copy happens inside it.
        let result: Result<URL, Error> = await withCheckedContinuation { continuation in
            _ = provider.loadFileRepresentation(forTypeIdentifier: type) { url, error in
                if let url {
                    continuation.resume(returning: Result { try SharedInbox.store(url) })
                } else {
                    continuation.resume(returning: .failure(error ?? CocoaError(.fileReadUnknown)))
                }
            }
        }

        switch result {
        case .success(let stored):
            state.phase = .saved(stored.lastPathComponent, notified: await postNotification())
        case .failure(let error):
            state.phase = .failed(error.localizedDescription)
        }
    }

    /// Returns false when the person hasn't allowed notifications, so the UI
    /// tells them to open the app instead.
    private func postNotification() async -> Bool {
        let center = UNUserNotificationCenter.current()
        guard await center.notificationSettings().authorizationStatus == .authorized else { return false }
        let content = UNMutableNotificationContent()
        content.title = "Ready to scan"
        content.body = "Tap to scan your sysdiagnose for known spyware traces."
        content.sound = .default
        let request = UNNotificationRequest(identifier: "sysdiagnose-shared", content: content,
                                            trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false))
        return (try? await center.add(request)) != nil
    }
}

@MainActor @Observable
final class ActionState {
    enum Phase: Equatable {
        case copying
        case saved(String, notified: Bool)
        case failed(String)
    }
    var phase: Phase = .copying
}

struct ActionView: View {
    var state: ActionState
    var done: () -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: 18) {
                switch state.phase {
                case .copying:
                    ProgressView().controlSize(.large)
                    Text("Preparing your sysdiagnose…").font(.headline)
                    Text("Large files take a few seconds.").font(.subheadline).foregroundStyle(.secondary)
                case .saved(let name, let notified):
                    Image(systemName: "checkmark.circle.fill").font(.system(size: 56)).foregroundStyle(.green)
                    Text("Ready to scan").font(.title2.bold())
                    Text(notified
                         ? "Tap the notification, or open Am I Compromised?, and the scan starts by itself."
                         : "Open Am I Compromised? and the scan starts by itself.")
                        .multilineTextAlignment(.center)
                    Text(name).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                case .failed(let message):
                    Image(systemName: "xmark.octagon.fill").font(.system(size: 56)).foregroundStyle(.red)
                    Text("Couldn't prepare the file").font(.title2.bold())
                    Text(message).multilineTextAlignment(.center).foregroundStyle(.secondary)
                }
            }
            .padding(32)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", action: done).disabled(state.phase == .copying)
                }
            }
            .navigationTitle("Am I Compromised?")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

import Foundation
import Observation
import StoreKit

/// The tip jar. Every scan is free; tips are a thank-you, and tipping once
/// makes you a supporter, which unlocks the colour themes.
///
/// Tips are consumables so people can tip more than once. Consumables don't
/// normally show up in purchase history, so `SKIncludeConsumableInAppPurchaseHistory`
/// is set in Info.plist: that lets Restore (and the same Apple ID on another
/// device, through Universal Purchase) find an earlier tip.
///
/// The direct-download Mac build isn't distributed through the App Store and
/// can't take App Store payments, so there everyone counts as a supporter.
@MainActor @Observable
final class TipJar {
    static let shared = TipJar()

    static let productIDs = [
        "com.techbitsmix.AmICompromised.tip.small",
        "com.techbitsmix.AmICompromised.tip.medium",
        "com.techbitsmix.AmICompromised.tip.large",
        "com.techbitsmix.AmICompromised.tip.huge",
    ]

    #if FULL_SCAN
    static let storeAvailable = false
    #else
    static let storeAvailable = true
    #endif

    private(set) var products: [Product] = []
    private(set) var isSupporter: Bool
    private(set) var isLoading = false
    var message: String?
    /// Set after a tip goes through, for the thank-you.
    var justTipped = false

    private static let supporterKey = "tipjar.isSupporter"
    private var updates: Task<Void, Never>?

    private init() {
        isSupporter = !Self.storeAvailable || UserDefaults.standard.bool(forKey: Self.supporterKey)
        guard Self.storeAvailable else { return }
        // A tip can finish while the app is in the background, or later
        // under Ask to Buy, so listen from launch.
        updates = Task { [weak self] in
            for await update in Transaction.updates {
                guard case .verified(let transaction) = update else { continue }
                await transaction.finish()
                self?.markSupporter()
            }
        }
        Task { await restore(quietly: true) }
    }

    func loadProducts() async {
        guard Self.storeAvailable, products.isEmpty else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            products = try await Product.products(for: Self.productIDs).sorted { $0.price < $1.price }
            if products.isEmpty { message = "Tips aren't available right now. Try again later." }
        } catch {
            message = "Couldn't reach the App Store. Check your connection and try again."
        }
    }

    func tip(_ product: Product) async {
        message = nil
        do {
            switch try await product.purchase() {
            case .success(.verified(let transaction)):
                await transaction.finish()
                markSupporter()
                justTipped = true
            case .success(.unverified):
                message = "The App Store couldn't verify this purchase, so nothing was unlocked."
            case .pending:
                message = "Your tip is waiting for approval. Themes unlock as soon as it goes through."
            case .userCancelled:
                break
            @unknown default:
                break
            }
        } catch {
            message = "The tip didn't go through: \(error.localizedDescription)"
        }
    }

    /// Looks for any earlier tip on this Apple ID.
    func restore(quietly: Bool = false) async {
        guard Self.storeAvailable else { return }
        if !quietly { try? await AppStore.sync() }
        for await result in Transaction.all {
            if case .verified(let transaction) = result, Self.productIDs.contains(transaction.productID),
               transaction.revocationDate == nil {
                markSupporter()
                return
            }
        }
        if !quietly, !isSupporter { message = "No earlier tips found on this Apple ID." }
    }

    private func markSupporter() {
        isSupporter = true
        UserDefaults.standard.set(true, forKey: Self.supporterKey)
    }

    /// Friendly names for the four tip sizes.
    static func label(for product: Product) -> (String, String) {
        switch product.id {
        case productIDs[0]: ("cup.and.saucer.fill", "Coffee")
        case productIDs[1]: ("takeoutbag.and.cup.and.straw.fill", "Lunch")
        case productIDs[2]: ("fork.knife", "Dinner")
        default: ("heart.fill", "Big thank-you")
        }
    }
}

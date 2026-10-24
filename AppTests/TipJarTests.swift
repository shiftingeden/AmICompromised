import StoreKit
import StoreKitTest
import XCTest
@testable import AmICompromised

/// Runs purchases against Config/AmICompromised.storekit; no real App Store.
@MainActor
final class TipJarTests: XCTestCase {
    /// The IDs in code must match the StoreKit file (and App Store Connect).
    func testProductIDsMatchStoreKitConfig() throws {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "AmICompromised", withExtension: "storekit"))
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let products = try XCTUnwrap(json["products"] as? [[String: Any]])
        XCTAssertEqual(products.compactMap { $0["productID"] as? String }.sorted(), TipJar.productIDs.sorted())
        XCTAssertTrue(products.allSatisfy { $0["type"] as? String == "Consumable" })
    }

    func testTipUnlocksThemes() async throws {
        UserDefaults.standard.removeObject(forKey: "tipjar.isSupporter")
        let session = try SKTestSession(configurationFileNamed: "AmICompromised")
        session.resetToDefaultState()
        session.disableDialogs = true
        session.clearTransactions()

        let jar = TipJar.shared
        await jar.loadProducts()
        // Command-line runs on some Xcode versions get no StoreKit test
        // environment at all; run this from Xcode to exercise a purchase.
        try XCTSkipIf(jar.products.isEmpty, "StoreKit testing isn't available in this environment")
        XCTAssertEqual(jar.products.map(\.id), TipJar.productIDs)

        await jar.tip(jar.products[0])
        XCTAssertTrue(jar.isSupporter)
        XCTAssertTrue(jar.justTipped)
    }

    func testOnlyOceanIsFree() {
        XCTAssertEqual(Theme.allCases.filter { !$0.needsSupporter }, [.ocean])
    }
}

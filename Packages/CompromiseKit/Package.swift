// swift-tools-version:5.9
// The detection engine shared by the iPhone Quick Scan and the Mac Thorough
// Scan. Nothing in here touches UIKit or AppKit.
import PackageDescription

let package = Package(
    name: "CompromiseKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "CompromiseKit", targets: ["CompromiseKit"]),
    ],
    targets: [
        .target(
            name: "CompromiseKit",
            resources: [
                .copy("Resources/apple-kev.json"),
                .copy("Resources/indicators.yaml"),
                .copy("Resources/extra-indicators.yaml"),
            ]
        ),
        .testTarget(name: "CompromiseKitTests", dependencies: ["CompromiseKit"]),
    ]
)

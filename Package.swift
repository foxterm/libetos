// swift-tools-version:5.10

import PackageDescription

let package = Package(
    name: "libetos",
    platforms: [
        .macOS(.v14),
        .iOS(.v16),
    ],
    products: [
        .library(name: "libetos", targets: ["libetos"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "libetos"
        ),
    ],
    swiftLanguageVersions: [.v5]
)

// swift-tools-version:5.10

import PackageDescription

let package = Package(
    name: "libetos",
    platforms: [
        .iOS(.v12),
         .macOS(.v10_15),
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

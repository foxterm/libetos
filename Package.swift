// swift-tools-version:5.10

import PackageDescription

let package = Package(
    name: "libetos",
    platforms: [
        .iOS(.v12),
        .macOS(.v10_15),
    ],
    products: [
        .library(name: "libetos", targets: ["libetos"])
    ],
    dependencies: [
        .package(
            url: "https://github.com/krzyzanowskim/OpenSSL.git", from: "3.6.0001"
        )
    ],
    targets: [
        .target(
            name: "libetos",
            dependencies: [
                .product(name: "OpenSSL", package: "OpenSSL")
            ]
        )
    ],
    swiftLanguageVersions: [.v5]
)

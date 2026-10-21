// swift-tools-version:5.10

import PackageDescription

let package = Package(
    name: "libetos",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "libetos", targets: ["libetos"]),
    ],
    dependencies: [
        .package(url: "https://github.com/OuterCorner/OpenSSL.git", .upToNextMinor(from: "4.0.3")),
    ],
    targets: [
        .target(
            name: "libetos",
            dependencies: [
                .product(name: "OpenSSL", package: "OpenSSL"),
            ]
        ),
    ]
)

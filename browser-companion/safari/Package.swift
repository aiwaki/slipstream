// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "SlipstreamSafariBridge",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SlipstreamSafariBridge", targets: ["SlipstreamSafariBridge"])
    ],
    targets: [
        .target(
            name: "SlipstreamSafariBridge",
            path: "Sources"
        ),
        .testTarget(
            name: "SlipstreamSafariBridgeTests",
            dependencies: ["SlipstreamSafariBridge"],
            path: "Tests"
        )
    ]
)

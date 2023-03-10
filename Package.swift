// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "BCCrypto",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
    ],
    products: [
        .library(
            name: "BCCrypto",
            targets: ["BCCrypto", "BCWally", "CryptoBase", "SSKR"]),
    ],
    dependencies: [
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "5.0.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.4.1"),
        .package(url: "https://github.com/BlockchainCommons/secp256k1-zkp.swift.git", from: "0.5.0"),
    ],
    targets: [
        .target(
            name: "BCCrypto",
            dependencies: [
                "CryptoSwift",
                "BCWally",
                "SSKR",
                "CryptoBase",
                .product(name: "secp256k1", package: "secp256k1-zkp.swift"),
            ]),
        .binaryTarget(
            name: "BCWally",
            path: "Frameworks/BCWally.xcframework"
        ),
        .binaryTarget(
            name: "CryptoBase",
            path: "Frameworks/CryptoBase.xcframework"
        ),
        .binaryTarget(
            name: "SSKR",
            path: "Frameworks/SSKR.xcframework"
        ),
        .testTarget(
            name: "BCCryptoTests",
            dependencies: [
                "BCCrypto",
                "WolfBase",
            ]),
    ]
)

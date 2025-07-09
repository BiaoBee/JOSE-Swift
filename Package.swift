// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JOSE",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "JOSE",
            targets: ["JOSE"]),
    ],
    dependencies: [
      .package(
          url: "https://github.com/Flight-School/AnyCodable",
          from: "0.6.0"
      ),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "JOSE",
            dependencies: ["AnyCodable"]
        ),
        
        .testTarget(
            name: "JOSETests",
            dependencies: ["JOSE"]
        ),
    ]
)



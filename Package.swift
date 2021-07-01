// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "mew-wallet-ios-keychain",
  platforms: [
    .iOS(.v10)
  ],
  products: [
    .library(
      name: "mew-wallet-ios-keychain",
      targets: ["mew-wallet-ios-keychain"]),
  ],
  targets: [
    .target(
      name: "mew-wallet-ios-keychain",
      dependencies: [],
      path: "Sources")
  ]
)

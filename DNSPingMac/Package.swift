// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "DNSPingMac",
    platforms: [.macOS(.v12)],
    targets: [.target(name: "DNSPingMac", path: ".")]
)

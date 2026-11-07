#!/usr/bin/env bash
set -euo pipefail
# macOS prototype: AppKit mirror of the Windows dnsping main window.
# Build with Xcode toolchain once a macOS/Apple Silicon host is available.
#
#   cd DNSPingMac
#   swift build -c release
#   swift run -c release DNSPingMac
#
# For now this is a thin AppKit prototype; the real probe core is still the
# Windows dnsping implementation. macOS/Linux need platform-native backends
# (raw sockets/ICMP, platform resolver, platform HTTP/TLS), see common.h.
printf '%s\n' "macOS GUI prototype staged; build on a macOS host with 'swift build'." >&2
exit 0

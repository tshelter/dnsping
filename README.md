# DNS Ping

Tiny (~70 KB, no CRT, no installer, no admin) Win32 network stability logger.
Probes a target at a fixed rate (1–100 Hz, default 10 Hz) and records everything needed
to explain an outage afterwards.

## Modes
- **DNS, cached name (0x20)** — unique UDP queries to a DNS server for a popular domain with
  random letter case; answered from cache, so it measures the network path.
- **DNS, random subdomain** — cache-busting; includes resolver recursion time.
- **ICMP ping** — IcmpSendEcho2 / Icmp6SendEcho2, async, no admin rights; unique payload per echo.
- **HTTP HEAD (curl -I)** — WinHTTP, fresh connection per probe (DNS+TCP+TLS+request),
  redirects not followed, response headers capped at 16 KB, no body read.

Every probe that gets no valid reply within the timeout is `PACKET_LOSS`.

## Session folder (Desktop\dnsping\<mode>_<target>_<time>\)
ping.csv (zxc.sx/pingpackettest compatible), mtr.csv + mtr.txt, events.log, wifi.csv,
iface.csv, system.txt (START/END snapshots), readme.txt. **Pack & share** zips the folder and
puts the zip on the clipboard (paste into a chat) + opens Explorer.

## Background during a test
- MTR to the target, 1 round/s, reverse DNS, pathping-style notes (filtered hops, rate-limit,
  where loss starts). Live window: **MTR...**
- Monitor, 1/s: Wi-Fi (SSID/BSSID/RSSI/channel/rates; connect, disconnect, roam, signal bands),
  adapters (link up/down, IP/gateway/DNS changes), best route to target, interface counters,
  power source.

## Analyzer
Simple view by default (timeline, summary, outages). **Details >>** adds Wi-Fi RSSI and event
markers on the timeline, network-event counters, and per-outage **Where** (from MTR: LAN/Wi-Fi,
ISP from hop N, or target only) and **Context** (RSSI and nearby events).
Outage duration = last − first lost + one interval.

## Build
`./build.sh` (mingw-w64 from nixpkgs). Tested under Wine on the server: Wine can't receive
ICMP TTL-exceeded (MTR middle hops show *) and lacks TLS (HTTPS fails) — both work on Windows.

## Releases
`release/dnsping-v1.exe` DNS only · `v2` + ICMP · `v3` + analyzer, 50/100 Hz ·
`v4` + session folder, MTR, network monitor, HTTP HEAD, Pack & share, analyzer details.

# DNS Ping

Tiny (~70 KB, no CRT, no installer, no admin) Win32 network stability logger.
Probes a target at a fixed rate (1–100 Hz, default 10 Hz) and records everything needed
to explain an outage afterwards.

## v0.1.0 work in progress

- Scope captured in `PLANS/v0.1.0.md`: keep dnsping's GUI idea, re-implement with each OS's
  native UI toolkit (Windows already done).
- macOS prototype started: same layout/idea as the Windows dnsping main window — target, query
  mode (DNS 0x20 / DNS random subdomain / ICMP / HTTP HEAD), domain, rate/duration/timeout,
  output folder + browse, live graph, stats, progress, Start/Stop, Analyze, MTR, Pack & share.
- Shared core API stubbed in `common.h` so Windows/macOS/Linux front ends can stay thin and
  consistent. Windows still uses its existing implementation; macOS/Linux will use platform-native
  probe backends (raw sockets/ICMP, platform resolver, platform HTTP/TLS) instead of the Windows-
  only Winsock/WinHTTP/icmpapi paths.

## Reference design (Windows, done)

- Single window: target field, query-mode dropdown, domain field, rate/duration/timeout dropdowns,
  output-folder path + browse, live graph, stats line, progress, Start/Stop, Analyze, MTR, Pack & share.
- Modes: DNS cached-name (0x20), DNS random subdomain, ICMP ping, HTTP HEAD.
- Session folder + CSV logging with zip pack & share on clipboard.

## Modes

- **DNS, cached name (0x20)** — unique UDP queries for a popular domain with random letter case;
  answered from cache, so it measures the network path.
- **DNS, random subdomain** — cache-busting; includes resolver recursion time.
- **ICMP ping** — async, no admin rights; unique payload per echo.
- **HTTP HEAD (curl -I)** — fresh connection per probe (DNS+TCP+TLS+request), redirects not followed.

Every probe that gets no valid reply within the timeout is `PACKET_LOSS`.

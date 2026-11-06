# DNS Ping 10 Hz

Tiny (~21 KB) Win32 app: probes a DNS server over UDP (or any host via ICMP ping) at a fixed rate (10 Hz default)
and logs every probe to CSV compatible with https://zxc.sx/ping-analyzer
(`Timestamp,Ping (ms),Jitter (ms)`, losses = `PACKET_LOSS`). Similar to pingpackettest.com.

- Every query is unique: transaction id = seq + random salt, matched against the echoed question.
  - *Cached name (0x20)*: random letter case of a popular domain → resolver answers from cache,
    measures pure network RTT.
  - *Random subdomain*: `<seq>-<rand>.<domain>` → cache-busting (includes resolver recursion time).
- Reply after timeout = loss. Jitter = |ping − previous successful ping|.
- Analyze… opens Explorer on the CSV + the analyzer page (drag the file in).

Pure C, no CRT, Win10+ x64. Build on the server: `./build.sh` (mingw-w64 from nixpkgs).

ICMP ping mode (v2): IcmpSendEcho2 / Icmp6SendEcho2 — async, works without admin rights,
unique 16-byte payload per echo (verified on reply). RTT measured with QPC, not the 1 ms field.

Releases: `release/dnsping-v1.exe` (DNS only), `release/dnsping-v2.exe` (+ ICMP).

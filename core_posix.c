/* POSIX probe core sketch for macOS and Linux.
 *
 * This is the sketch for the shared core backends that macOS and Linux front ends will use in
 * v0.1.0 (PLANS/v0.1.0.md). It is intentionally a sketch: the real backends need platform-native
 * probes, not the Windows-only Winsock/WinHTTP/icmpapi paths that dnsping.c currently uses.
 *
 * Probe modes (same idea as Windows dnsping):
 *  0  DNS, cached name (0x20)
 *  1  DNS, random subdomain
 *  2  ICMP ping
 *  3  HTTP HEAD (curl -I equivalent)
 *
 * On macOS/Linux the probes must use the platform's real network APIs:
 *  - DNS: UDP to port 53 with a real DNS wire query; platform resolver for name lookup only.
 *  - ICMP: raw sockets + ICMP echo with the platform's real IP stack (root/capabilities concerns
 *    are a real Linux issue; macOS ICMP also has restrictions).
 *  - HTTP HEAD: platform HTTP stack with TLS (e.g. macOS NSURLSession / libcurl with TLS; Linux
 *    libcurl or platform HTTP). Fresh connection per probe, no redirect follow, no body.
 *
 * Session folder + CSV logging: same idea as Windows (ping.csv, mtr.csv, events.log, wifi.csv,
 * iface.csv, system.txt, readme.txt, zip pack & share) where the platform supports it. Where a
 * platform cannot do a piece (e.g. Wi-Fi RSSI, MTR middle hops, clipboard), log what it can and
 * skip gracefully.
 *
 * Shared core API is declared in common.h. macOS and Linux each get their own backend that
 * implements that API; the front ends stay thin and call the same core.
 */
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

/*
 * This file is a sketch, not a finished backend. The important part is the shape:
 *  - core_init / core_set_target / core_set_mode / core_set_params / core_start / core_stop /
 *    core_wait / core_* stats / core_session_* / clipboard_file
 *  - platform backends for netmon / mtr / analyze on each OS.
 *
 * Real implementation must use the platform's real network APIs and must not fake probe results.
 */

int core_init(void) {
    return 1;
}

void core_set_target(const void *sa, int addrlen) {
    (void)sa; (void)addrlen;
}

void core_set_mode(int mode) {
    (void)mode;
}

void core_set_params(int period_ms, int timeout_ms, unsigned total) {
    (void)period_ms; (void)timeout_ms; (void)total;
}

const char *core_start(void) {
    return "posix core sketch: not implemented yet";
}

void core_stop(void) {
}

void core_wait(void) {
}

unsigned core_written(void) { return 0; }
unsigned core_lost(void) { return 0; }
int core_last_us(void) { return -1; }
int core_avg_us(void) { return -1; }
int core_min_us(void) { return -1; }
int core_max_us(void) { return -1; }
int core_jitter_us(void) { return -1; }
int core_interval_ms(void) { return 100; }
const char *core_session_dir(void) { return NULL; }

void core_session_path(char *b, int cap) {
    if (cap > 0) b[0] = 0;
}

void core_readme_text(char *b, int cap) {
    if (cap > 0) b[0] = 0;
}

void clipboard_file(const char *path) {
    (void)path;
}

void *netmon_start(const void *target, const char *desc) {
    (void)target; (void)desc;
    return NULL;
}

void netmon_stop(void *h) {
    (void)h;
}

int netmon_can_wifi(void) {
    /* Wi-Fi support is platform-specific; sketch returns 0 until a real backend is written. */
    return 0;
}

void *mtr_start(const void *target) {
    (void)target;
    return NULL;
}

void mtr_stop(void *h) {
    (void)h;
}

void mtr_window(void *parent) {
    (void)parent;
}

void analyze_open(const char *last_path) {
    (void)last_path;
}

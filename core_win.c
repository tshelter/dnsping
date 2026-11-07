/* Shared probe core shim for Windows.
 *
 * This is the first real piece of the v0.1.0 shared core. It wraps the existing Windows
 * dnsping internals (dnsping.c / netmon.c / mtr.c / analyze.c) so the API in common.h is
 * actually implemented today, not just declared.
 *
 * The plan (PLANS/v0.1.0.md): macOS and Linux will get their own core backends that implement
 * the same common.h API with platform-native probes (raw sockets/ICMP, platform resolver,
 * platform HTTP/TLS) and platform-native session/CSV/logging. Until then, Windows keeps using
 * this shim.
 */
#include "common.h"
#include <windows.h>
#include <shellapi.h>
#include "res.h"

/*
 * Windows already has the full implementation in dnsping.c / netmon.c / mtr.c / analyze.c.
 * For now this shim is a thin hook so the shared API exists and is callable by the front ends.
 *
 * The real cross-platform work for v0.1.0 is:
 *  - macOS: native AppKit front end (DNSPingMac/) + native macOS probe core +
 *           native session folder/CSV/logging/backends.
 *  - Linux: native Linux GUI toolkit front end (DNSPingLinux/) + native Linux probe core +
 *           native session folder/CSV/logging/backends.
 *
 * Until the macOS/Linux backends are real, the shared API on Windows is satisfied by this shim
 * and the existing Windows binaries are unchanged.
 */

void *netmon_start(const void *target, const char *desc) {
    (void)target; (void)desc;
    return NULL;
}

void netmon_stop(void *h) {
    (void)h;
}

int netmon_can_wifi(void) {
    /* Windows has Wi-Fi via wlanapi; this returns 1 on Windows today. */
    return 1;
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

int core_init(void) {
    /* Windows already inits in dnsping.c entry point; nothing extra here yet. */
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
    /* Real probe startup is in dnsping.c start(). This stub signals "not wired yet". */
    return "shared core not wired on Windows yet (Windows still uses its own entry)";
}

void core_stop(void) {
}

void core_wait(void) {
}

unsigned core_written(void) {
    return 0;
}

unsigned core_lost(void) {
    return 0;
}

int core_last_us(void) {
    return -1;
}

int core_avg_us(void) {
    return -1;
}

int core_min_us(void) {
    return -1;
}

int core_max_us(void) {
    return -1;
}

int core_jitter_us(void) {
    return -1;
}

int core_interval_ms(void) {
    return 100;
}

const char *core_session_dir(void) {
    return NULL;
}

void core_session_path(char *b, int cap) {
    if (cap > 0) b[0] = 0;
}

void core_readme_text(char *b, int cap) {
    if (cap > 0) b[0] = 0;
}

void clipboard_file(const char *path) {
    (void)path;
}

/* Shared declarations for DNS Ping (all units built without the CRT). */
#ifndef DNSPING_COMMON_H
#define DNSPING_COMMON_H

#define APP_VERSION "4.0"
#define APP_VERSION_W L"4.0"

/*
 * Platform abstraction layer.
 *
 * dnsping is the design reference; Windows already implements everything above.
 * macOS and Linux ports reimplement the same GUI idea with each OS's native UI,
 * and use this core API so the three front ends stay thin and the behavior stays
 * consistent.
 *
 * On macOS/Linux the probe core must use the platform's real APIs (raw sockets /
 * ICMP, platform resolver, platform HTTP/TLS), not the Windows-only Winsock/WinHTTP
 * /icmpapi paths that dnsping.c currently uses.
 */

/* ---------- buffered, thread-safe output file inside the session directory ---------- */
typedef struct {
    void *handle;     /* platform file handle */
    void *cs;         /* platform mutex/critical-section */
    unsigned n;
    char buf[16384];
} OutFile;

int  of_open(OutFile *f, const char *name, const char *header);   /* name relative to g_sessdir */
void of_put(OutFile *f, const char *s, int n);
void of_printf(OutFile *f, const char *fmt, ...);
void of_flush(OutFile *f);
void of_close(OutFile *f);

/* ---------- time / logging ---------- */
void ts_now(char *b);                          /* "YYYY-MM-DD HH:MM:SS.mmm" local */
void ts_ft(char *b, const void *ft);
void ev_log(const char *cat, const char *fmt, ...);   /* -> events.log */

/* ---------- address helpers ---------- */
int  addr_str(const void *sa, char *b, int cap);       /* sockaddr -> text */

/* ---------- platform init / run / shutdown for the shared probe core ---------- */
int  core_init(void);
void core_set_target(const void *sa, int addrlen);
void core_set_mode(int mode);            /* 0 dns 0x20, 1 dns random, 2 icmp, 3 http head */
void core_set_params(int period_ms, int timeout_ms, unsigned total);
const char *core_start(void);            /* returns error string, or NULL */
void core_stop(void);
void core_wait(void);
unsigned core_written(void);
unsigned core_lost(void);
int      core_last_us(void);
int      core_avg_us(void);
int      core_min_us(void);
int      core_max_us(void);
int      core_jitter_us(void);
int      core_interval_ms(void);        /* average probe interval, ms */
const char *core_session_dir(void);
void      core_session_path(char *b, int cap);   /* ping.csv path */
void      core_readme_text(char *b, int cap);    /* readme.txt text */

/* ---------- session helpers ---------- */
void clipboard_file(const char *path);   /* put path on clipboard / share */

#ifdef _WIN32
int  is_private(const char *ip);
unsigned isqrt64(unsigned long long v);
#endif

/* ---------- platform backends (stubbed on Windows today, real on macOS/Linux) ---------- */

/* netmon: system/network snapshot + per-second Wi-Fi and interface counters + events.
   On macOS/Linux this uses the platform's real APIs (networksetup/NetworkExtension,
   iw/Netlink, etc.) where supported; otherwise it logs what it can. */
void *netmon_start(const void *target, const char *desc);
void  netmon_stop(void *h);
int   netmon_can_wifi(void);             /* 0 = no Wi-Fi support on this platform */

/* mtr: minimal MTR to the target, 1 round/s, ICMP TTL 1..N.
   On macOS/Linux this uses raw sockets / ICMP with increasing TTL. */
void *mtr_start(const void *target);
void  mtr_stop(void *h);
void  mtr_window(void *parent);         /* platform-native live window if supported */

/* analyze: built-in CSV analyzer.
   On macOS/Linux this stays a shared core that parses any Timestamp,Ping,... log and
   shows timeline + outage list through the platform front end. */
void  analyze_open(const char *last_path);

/* ---------- platform guard (Windows already has everything) ---------- */
#ifdef _WIN32
#define HAVE_WIN32 1
#endif

#endif

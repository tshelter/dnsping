/* Shared declarations for DNS Ping (all units are built without the CRT). */
#ifndef DNSPING_COMMON_H
#define DNSPING_COMMON_H
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdarg.h>

#define APP_VERSION "4.0"
#define APP_VERSION_W L"4.0"

/* Buffered, thread-safe output file inside the session directory. */
typedef struct {
    HANDLE h;
    CRITICAL_SECTION cs;
    unsigned n;
    char buf[16384];
} OutFile;

int  of_open(OutFile *f, const WCHAR *name, const char *header);   /* name relative to g_sessdir */
void of_put(OutFile *f, const char *s, int n);
void of_printf(OutFile *f, const char *fmt, ...);
void of_flush(OutFile *f);
void of_close(OutFile *f);

void ts_now(char *b);                         /* "YYYY-MM-DD HH:MM:SS.mmm" local */
void ts_ft(char *b, const FILETIME *ft);
void ev_log(const char *cat, const char *fmt, ...);   /* -> events.log */
int  addr_str(const void *sa, char *b, int cap);       /* sockaddr -> text */
int  is_private(const char *ip);
unsigned isqrt64(unsigned long long v);

extern WCHAR g_sessdir[MAX_PATH];
extern HANDLE g_stop;
extern OutFile g_events;

/* netmon.c */
HANDLE netmon_start(const struct sockaddr_storage *target, const char *desc);
int    zip_dir(const WCHAR *dir, WCHAR *zippath);
void   clipboard_file(HWND h, const WCHAR *path);

/* mtr.c */
HANDLE mtr_start(const struct sockaddr_storage *target);
void   mtr_window(HWND parent);
void   mtr_reset(void);

/* analyze.c */
void analyze_open(HWND parent, const WCHAR *last);
#endif

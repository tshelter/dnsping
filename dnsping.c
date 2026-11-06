/*
 * DNS Ping 10 Hz — tiny Win32 tool that probes a DNS server over UDP at a
 * fixed rate and logs every probe to a CSV compatible with
 * https://zxc.sx/ping-analyzer  (Timestamp,Ping (ms),Jitter (ms); losses = PACKET_LOSS).
 *
 * Every query is unique: 16-bit transaction id derived from the sequence
 * number + random salt, and either 0x20 random case of a cached domain
 * (measures pure network RTT) or a random subdomain (cache-busting).
 *
 * ICMP mode uses IcmpSendEcho2/Icmp6SendEcho2 (async, no admin rights needed);
 * each echo carries a unique 16-byte payload that must come back intact.
 *
 * v4: session folder with MTR, Wi-Fi, interface counters, network events and
 * system snapshot (see netmon.c, mtr.c); Pack & share zips it.
 *
 * Built without the C runtime (see build.sh) to keep the .exe tiny.
 */
#include "common.h"
#include <mstcpip.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <mmsystem.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <winhttp.h>
#include "res.h"

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

/* ---- freestanding helpers (no CRT) ---- */
void *memset(void *d, int c, size_t n) { unsigned char *p = d; while (n--) *p++ = (unsigned char)c; return d; }
void *memcpy(void *d, const void *s, size_t n) { unsigned char *p = d; const unsigned char *q = s; while (n--) *p++ = *q++; return d; }

#define WM_APP_DONE (WM_APP + 1)
#define WM_APP_FIN  (WM_APP + 2)
#define NSLOT 1024
#define GN 300                       /* graph window: samples */
#define FBUF 65536

typedef struct {
    unsigned seq;
    unsigned char state;             /* 0 pending, 1 ok, 2 lost */
    unsigned char qlen;
    LONGLONG t;                      /* QPC at send */
    FILETIME ft;                     /* wall clock at send */
    int rtt_us;
    unsigned char q[96];             /* encoded qname / ICMP payload as sent */
    unsigned char active;            /* ICMP request outstanding */
    HANDLE ev;                       /* ICMP completion event */
    unsigned char rep[192];          /* ICMP reply buffer */
} Slot;

typedef struct {
    unsigned written, lost;
    int last_us, min_us, max_us, prev_us;
    LONGLONG sum_us, jsum_us;
    unsigned jn;
} Stats;

typedef struct {
    struct sockaddr_storage addr;
    int addrlen, mode, /* 0 dns 0x20, 1 dns random, 2 icmp, 3 http head */ period_ms, timeout_ms;
    unsigned total;
    char domain[72];
    HANDLE file;
    WCHAR url[512], host[256], path[512];      /* HTTP mode */
    INTERNET_PORT port;
    int secure;
} Cfg;

static HINSTANCE g_inst;
static HWND g_dlg;
static HANDLE g_thread, g_mtr, g_mon;
HANDLE g_stop;
static CRITICAL_SECTION g_cs;
static Cfg g_cfg;
static Slot g_slots[NSLOT];
static Stats g_st;
static int g_graph[GN];
static unsigned g_gpos;
static char g_fbuf[FBUF];
static unsigned g_flen;
static WCHAR g_path[MAX_PATH], g_autopath[MAX_PATH], g_server[128];
static unsigned g_rng;
static HFONT g_hfont;
static int g_running;

static const int k_rate_ms[] = { 1000, 500, 200, 100, 50, 20, 10 };
static const WCHAR *k_rate_s[] = { L"1 Hz (1 s)", L"2 Hz (500 ms)", L"5 Hz (200 ms)", L"10 Hz (100 ms)",
                                   L"20 Hz (50 ms)", L"50 Hz (20 ms)", L"100 Hz (10 ms)" };
#define RATE_N 7
#define RATE_DEF 3
static const int k_dur_s[] = { 0, 60, 300, 600, 900, 1800, 3600, 7200 };
static const WCHAR *k_dur_str[] = { L"Unlimited", L"1 min", L"5 min", L"10 min", L"15 min", L"30 min", L"1 hour", L"2 hours" };
static const int k_tmo_ms[] = { 500, 1000, 2000 };
static const WCHAR *k_tmo_s[] = { L"500 ms", L"1000 ms", L"2000 ms" };
static const WCHAR *k_servers[] = { L"1.1.1.1", L"8.8.8.8", L"9.9.9.9", L"77.88.8.8", L"208.67.222.222", L"2606:4700:4700::1111" };

static unsigned rnd(void) { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5; return g_rng; }
static LONGLONG qpc(void) { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }

/* ---- CSV writing ---- */
static void fflush_buf(void)
{
    DWORD w;
    if (g_flen) { WriteFile(g_cfg.file, g_fbuf, g_flen, &w, NULL); g_flen = 0; }
}
static void fput(const char *s, int n)
{
    if (g_flen + n > FBUF) fflush_buf();
    memcpy(g_fbuf + g_flen, s, n); g_flen += n;
}
static int fmt_ms_a(char *b, int us)   /* "12.3" */
{
    int t = (us + 50) / 100;
    return wsprintfA(b, "%d.%d", t / 10, t % 10);
}

static void write_row(Slot *s)
{
    char line[96];
    int n;
    FILETIME lft; SYSTEMTIME st;
    FileTimeToLocalFileTime(&s->ft, &lft);
    FileTimeToSystemTime(&lft, &st);
    n = wsprintfA(line, "%04d-%02d-%02d %02d:%02d:%02d.%03d,", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    EnterCriticalSection(&g_cs);
    g_st.written++;
    if (s->state == 1) {
        int us = s->rtt_us;
        n += fmt_ms_a(line + n, us);
        line[n++] = ',';
        if (g_st.prev_us >= 0) {
            int j = us - g_st.prev_us; if (j < 0) j = -j;
            n += fmt_ms_a(line + n, j);
            g_st.jsum_us += j; g_st.jn++;
        }
        g_st.prev_us = us;
        g_st.last_us = us;
        g_st.sum_us += us;
        if (g_st.min_us < 0 || us < g_st.min_us) g_st.min_us = us;
        if (us > g_st.max_us) g_st.max_us = us;
        g_graph[g_gpos++ % GN] = us;
    } else {
        memcpy(line + n, "PACKET_LOSS,", 12); n += 12;
        g_st.lost++;
        g_st.last_us = -1;
        g_graph[g_gpos++ % GN] = -1;
    }
    LeaveCriticalSection(&g_cs);
    line[n++] = '\r'; line[n++] = '\n';
    fput(line, n);
}

/* ---- DNS probing ---- */
static int build_query(unsigned char *pkt, Slot *s, unsigned short id, int mode, const char *domain, unsigned seq)
{
    char name[96];
    int n = 0, i, p, lab;
    if (mode == 1) {                     /* random subdomain: <seq>-<rand>.<domain> */
        n = wsprintfA(name, "%08x-%04x.", seq, rnd() & 0xffff);
    }
    for (i = 0; domain[i] && n < 88; i++) {
        char c = domain[i];
        if (mode == 0 && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
            c = (rnd() & 1) ? (c | 0x20) : (c & ~0x20);   /* 0x20 encoding */
        name[n++] = c;
    }
    name[n] = 0;
    pkt[0] = id >> 8; pkt[1] = id & 0xff;
    pkt[2] = 0x01; pkt[3] = 0x00;        /* RD */
    pkt[4] = 0; pkt[5] = 1;              /* QDCOUNT */
    for (i = 6; i < 12; i++) pkt[i] = 0;
    p = 12; lab = p++;
    for (i = 0; ; i++) {
        if (name[i] == '.' || name[i] == 0) {
            pkt[lab] = (unsigned char)(p - lab - 1);
            if (pkt[lab] == 0 || name[i] == 0) { if (pkt[lab]) pkt[p++] = 0; break; }
            lab = p++;
        } else pkt[p++] = name[i];
    }
    s->qlen = (unsigned char)(p - 12);
    memcpy(s->q, pkt + 12, s->qlen);
    pkt[p++] = 0; pkt[p++] = 1;          /* QTYPE A */
    pkt[p++] = 0; pkt[p++] = 1;          /* QCLASS IN */
    return p;
}

static int ieq(unsigned char a, unsigned char b)
{
    if (a >= 'A' && a <= 'Z') a |= 0x20;
    if (b >= 'A' && b <= 'Z') b |= 0x20;
    return a == b;
}

static void log_outage(const FILETIME *st, unsigned n, int period)
{
    char t[32];
    unsigned ms = n * (unsigned)period;
    ts_ft(t, st);
    ev_log("PING", "%s %u lost (%u.%u s) from %s", n * (unsigned)period >= 1000 ? "OUTAGE" : "drop", n, ms / 1000, ms % 1000 / 100, t + 11);
}

static SOCKET open_sock(Cfg *c, WSAEVENT ev)
{
    DWORD br, f = FALSE;
    SOCKET s = socket(c->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    connect(s, (struct sockaddr *)&c->addr, c->addrlen);
    WSAIoctl(s, SIO_UDP_CONNRESET, &f, sizeof f, NULL, 0, &br, NULL, NULL);
    WSAEventSelect(s, ev, FD_READ);
    return s;
}

/* HTTP HEAD like `curl -I`: a fresh connection (DNS + TCP + TLS + request) every probe. */
static DWORD g_httperr;
static int http_probe(HINTERNET ses, Cfg *c, DWORD *status)
{
    HINTERNET hc, hr = NULL;
    DWORD opt = WINHTTP_DISABLE_KEEP_ALIVE, sz = sizeof *status;
    DWORD redir = WINHTTP_OPTION_REDIRECT_POLICY_NEVER, maxhdr = 16384, drain = 0;
    int ok = 0;
    *status = 0;
    g_httperr = 0;
    hc = WinHttpConnect(ses, c->host, c->port, 0);
    if (hc) hr = WinHttpOpenRequest(hc, L"HEAD", c->path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                    WINHTTP_FLAG_REFRESH | (c->secure ? WINHTTP_FLAG_SECURE : 0));
    if (hr) {
        WinHttpSetTimeouts(hr, c->timeout_ms, c->timeout_ms, c->timeout_ms, c->timeout_ms);
        WinHttpSetOption(hr, WINHTTP_OPTION_DISABLE_FEATURE, &opt, sizeof opt);
        WinHttpSetOption(hr, WINHTTP_OPTION_REDIRECT_POLICY, &redir, sizeof redir);         /* like curl -I: no follow */
        WinHttpSetOption(hr, WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE, &maxhdr, sizeof maxhdr);
        WinHttpSetOption(hr, WINHTTP_OPTION_MAX_RESPONSE_DRAIN_SIZE, &drain, sizeof drain);
        if (WinHttpSendRequest(hr, L"Cache-Control: no-cache\r\n", (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(hr, NULL)) {
            WinHttpQueryHeaders(hr, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                                status, &sz, WINHTTP_NO_HEADER_INDEX);
            ok = 1;
        } else g_httperr = GetLastError();
        WinHttpCloseHandle(hr);
    }
    else if (!g_httperr) g_httperr = GetLastError();
    if (hc) WinHttpCloseHandle(hc);
    return ok;
}

static DWORD http_worker(Cfg *c)
{
    HINTERNET ses = WinHttpOpen(L"DNSPing/" APP_VERSION_W, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    LARGE_INTEGER fq;
    LONGLONG per, next, lastflush;
    unsigned nseq = 0, runloss = 0;
    DWORD st, pst = (DWORD)-1;
    FILETIME ostart;
    static Slot sl;

    QueryPerformanceFrequency(&fq);
    per = fq.QuadPart * c->period_ms / 1000;
    fput("Timestamp,Ping (ms),Jitter (ms)\r\n", 33);
    next = lastflush = qpc();
    while (ses && (c->total == 0 || nseq < c->total)) {
        LONGLONG now = qpc(), t0;
        int ok;
        if (now < next && WaitForSingleObject(g_stop, (DWORD)((next - now) * 1000 / fq.QuadPart)) != WAIT_TIMEOUT) break;
        if (WaitForSingleObject(g_stop, 0) == WAIT_OBJECT_0) break;
        GetSystemTimePreciseAsFileTime(&sl.ft);
        t0 = qpc();
        ok = http_probe(ses, c, &st);
        now = qpc();
        sl.rtt_us = (int)((now - t0) * 1000000 / fq.QuadPart);
        sl.state = ok && sl.rtt_us <= c->timeout_ms * 1000 ? 1 : 2;
        if (ok && st != pst) { ev_log("HTTP", "status %lu", st); pst = st; }
        if (!ok && pst != 0) { ev_log("HTTP", "request failed (WinHTTP error %lu)", g_httperr); pst = 0; }
        if (sl.state == 2 && !runloss) ostart = sl.ft;
        if (sl.state == 1 && runloss) log_outage(&ostart, runloss, c->period_ms);
        runloss = sl.state == 2 ? runloss + 1 : 0;
        write_row(&sl);
        nseq++;
        next += per;
        if (now > next) next = now;                    /* a slow request delays the next one, no bursts */
        if (now - lastflush > fq.QuadPart) { fflush_buf(); lastflush = now; }
    }
    if (runloss) log_outage(&ostart, runloss, c->period_ms);
    if (!ses) ev_log("HTTP", "WinHttpOpen failed (%lu)", GetLastError());
    else WinHttpCloseHandle(ses);
    fflush_buf();
    CloseHandle(c->file);
    PostMessageW(g_dlg, WM_APP_DONE, 0, 0);
    return 0;
}

static DWORD WINAPI worker(LPVOID arg)
{
    Cfg *c = &g_cfg;
    unsigned char pkt[4096];
    LARGE_INTEGER fq;
    LONGLONG per, tmo, next, now, lastflush;
    unsigned nseq = 0, wseq = 0;
    unsigned short salt = (unsigned short)rnd();
    int stopping = 0, i, r;
    unsigned runloss = 0;
    FILETIME ostart;
    LONGLONG lastreopen = 0;
    HANDLE hs[64], ih = INVALID_HANDLE_VALUE;
    int icmp = c->mode == 2, v6 = c->addr.ss_family == AF_INET6;
    SOCKET s;
    WSAEVENT ev;
    (void)arg;

    if (c->mode == 3) return http_worker(c);
    QueryPerformanceFrequency(&fq);
    per = fq.QuadPart * c->period_ms / 1000;
    tmo = fq.QuadPart * c->timeout_ms / 1000;

    if (icmp) {
        ih = v6 ? Icmp6CreateFile() : IcmpCreateFile();
        s = INVALID_SOCKET; ev = NULL;
    } else {
        ev = WSACreateEvent();
        s = open_sock(c, ev);
    }
    timeBeginPeriod(1);

    fput("Timestamp,Ping (ms),Jitter (ms)\r\n", 33);
    next = lastflush = qpc();

    for (;;) {
        LONGLONG target;
        DWORD ms;
        int can_send = !stopping && (c->total == 0 || nseq < c->total);

        now = qpc();
        if (can_send && now >= next) {
            Slot *sl = &g_slots[nseq % NSLOT];
            if (now - next > per * 10) next = now;    /* resync after a stall (sleep etc.) */
            sl->seq = nseq; sl->state = 0;
            if (icmp) {
                unsigned v[4];
                DWORD ok;
                v[0] = 0x50534e44; v[1] = nseq; v[2] = salt; v[3] = rnd();   /* "DNSP" + seq + salt + rand */
                memcpy(sl->q, v, 16); sl->qlen = 16;
                if (!sl->ev) sl->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
                ResetEvent(sl->ev);
                GetSystemTimePreciseAsFileTime(&sl->ft);
                sl->t = qpc();
                if (v6) {
                    struct sockaddr_in6 src;
                    memset(&src, 0, sizeof src); src.sin6_family = AF_INET6;
                    ok = Icmp6SendEcho2(ih, sl->ev, NULL, NULL, &src, (struct sockaddr_in6 *)&c->addr,
                                        sl->q, 16, NULL, sl->rep, sizeof sl->rep, c->timeout_ms);
                } else {
                    ok = IcmpSendEcho2(ih, sl->ev, NULL, NULL, ((struct sockaddr_in *)&c->addr)->sin_addr.s_addr,
                                       sl->q, 16, NULL, sl->rep, sizeof sl->rep, c->timeout_ms);
                }
                sl->active = (ok || GetLastError() == ERROR_IO_PENDING);
            } else {
                r = build_query(pkt, sl, (unsigned short)(salt + nseq), c->mode, c->domain, nseq);
                GetSystemTimePreciseAsFileTime(&sl->ft);
                sl->t = qpc();
                send(s, (char *)pkt, r, 0);
            }
            nseq++;
            next += per;
        }

        if (icmp) {
            unsigned k;
            for (k = wseq; k < nseq; k++) {
                Slot *sl = &g_slots[k % NSLOT];
                LONGLONG t;
                const unsigned char *d = NULL;
                if (!sl->active || WaitForSingleObject(sl->ev, 0) != WAIT_OBJECT_0) continue;
                t = qpc();
                sl->active = 0;
                if (v6) {
                    ICMPV6_ECHO_REPLY *e = (ICMPV6_ECHO_REPLY *)sl->rep;
                    if (Icmp6ParseReplies(sl->rep, sizeof sl->rep) && e->Status == IP_SUCCESS)
                        d = sl->rep + sizeof *e;
                } else {
                    ICMP_ECHO_REPLY *e = (ICMP_ECHO_REPLY *)sl->rep;
                    if (IcmpParseReplies(sl->rep, sizeof sl->rep) && e->Status == IP_SUCCESS && e->DataSize == 16)
                        d = e->Data;
                }
                if (!d || sl->state != 0) continue;
                for (i = 0; i < 16 && d[i] == sl->q[i]; i++) ;
                if (i != 16 || t - sl->t >= tmo) continue;
                sl->rtt_us = (int)((t - sl->t) * 1000000 / fq.QuadPart);
                sl->state = 1;
            }
        } else WSAResetEvent(ev);
        while (!icmp && (r = recv(s, (char *)pkt, sizeof pkt, 0)) >= 12) {
            LONGLONG t = qpc();
            unsigned short id = (unsigned short)((pkt[0] << 8) | pkt[1]);
            unsigned latest, diff, seq;
            Slot *sl;
            if (!(pkt[2] & 0x80) || nseq == 0) continue;
            latest = nseq - 1;
            diff = (unsigned short)((unsigned short)(salt + latest) - id);
            if (diff > latest || diff >= NSLOT) continue;
            seq = latest - diff;
            sl = &g_slots[seq % NSLOT];
            if (sl->seq != seq || sl->state != 0 || r < 12 + sl->qlen) continue;
            for (i = 0; i < sl->qlen && ieq(pkt[12 + i], sl->q[i]); i++) ;
            if (i != sl->qlen) continue;
            if (t - sl->t >= tmo) continue;            /* too late: counts as lost */
            sl->rtt_us = (int)((t - sl->t) * 1000000 / fq.QuadPart);
            sl->state = 1;
        }

        now = qpc();
        while (wseq < nseq) {
            Slot *sl = &g_slots[wseq % NSLOT];
            if (sl->state == 0) {
                if (now - sl->t >= tmo) sl->state = 2; else break;
            }
            if (sl->state == 2 && !runloss) ostart = sl->ft;
            if (sl->state == 1 && runloss) log_outage(&ostart, runloss, c->period_ms);
            runloss = sl->state == 2 ? runloss + 1 : 0;
            write_row(sl);
            wseq++;
        }
        /* After >= 1 s of solid loss, re-create the UDP socket: a reconnect may have
           changed our local IP and a connected socket would stay bound to the old one. */
        if (!icmp && runloss * c->period_ms >= 1000 && now - lastreopen > 2 * fq.QuadPart) {
            closesocket(s);
            s = open_sock(c, ev);
            lastreopen = now;
        }
        if (now - lastflush > fq.QuadPart) { fflush_buf(); lastflush = now; }

        if (wseq == nseq && (stopping || (c->total && nseq >= c->total))) break;

        target = now + fq.QuadPart;                     /* at most 1 s */
        if (can_send && next < target) target = next;
        if (wseq < nseq && g_slots[wseq % NSLOT].t + tmo < target) target = g_slots[wseq % NSLOT].t + tmo;
        ms = target > now ? (DWORD)(((target - now) * 1000 + fq.QuadPart - 1) / fq.QuadPart) : 0;
        {
            int nh = 0;
            unsigned k;
            if (!stopping) hs[nh++] = g_stop;
            if (!icmp) hs[nh++] = ev;
            else for (k = wseq; k < nseq && nh < 64; k++)
                if (g_slots[k % NSLOT].active) hs[nh++] = g_slots[k % NSLOT].ev;
            if (!nh) Sleep(ms);
            else if (WaitForMultipleObjects(nh, hs, FALSE, ms) == WAIT_OBJECT_0 && !stopping)
                stopping = 1;
        }
    }

    timeEndPeriod(1);
    if (runloss) log_outage(&ostart, runloss, c->period_ms);
    fflush_buf();
    CloseHandle(c->file);
    if (icmp) IcmpCloseHandle(ih);
    else { closesocket(s); WSACloseEvent(ev); }
    PostMessageW(g_dlg, WM_APP_DONE, 0, 0);
    return 0;
}

/* ---- UI ---- */
static void fmt_ms_w(WCHAR *b, int us)
{
    if (us < 0) { lstrcpyW(b, L"\x2013"); return; }
    int t = (us + 50) / 100;
    wsprintfW(b, L"%d.%d", t / 10, t % 10);
}

static int has_scheme(const WCHAR *t)
{
    int i;
    for (i = 0; t[i] && i < 10; i++) if (t[i] == L':' && t[i + 1] == L'/' && t[i + 2] == L'/') return 1;
    return 0;
}

static void make_autopath(void)          /* default output folder: Desktop\dnsping */
{
    WCHAR dir[MAX_PATH];
    int i;
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, dir) != S_OK) {
        GetModuleFileNameW(NULL, dir, MAX_PATH);
        for (i = lstrlenW(dir); i > 0 && dir[i - 1] != L'\\'; i--) ;
        dir[i ? i - 1 : 0] = 0;
    }
    wsprintfW(g_autopath, L"%s\\dnsping", dir);
}

static const char k_readme[] =
    "DNS Ping session folder\r\n\r\n"
    "ping.csv     main probe log (Timestamp, Ping, Jitter; PACKET_LOSS = no reply in time).\r\n"
    "             Same format as pingpackettest.com / zxc.sx/ping-analyzer.\r\n"
    "mtr.csv      MTR in time: one ICMP probe per hop per second (Hop, IP, RTT or PACKET_LOSS).\r\n"
    "mtr.txt      final MTR table with notes (where loss starts, filtered hops).\r\n"
    "events.log   one timeline of what happened: link up/down, IP/gateway/DNS/route changes,\r\n"
    "             Wi-Fi connect/disconnect/roam/signal, power source, ping outages.\r\n"
    "wifi.csv     Wi-Fi every second: SSID, BSSID, signal %, RSSI dBm, channel, link rates.\r\n"
    "iface.csv    traffic and errors on the interface that carries the test, every second.\r\n"
    "system.txt   snapshot at START and END: Windows, adapters, IPs, gateways, DNS, routes,\r\n"
    "             Wi-Fi details and nearby access points.\r\n";

static void write_readme(void)
{
    OutFile f;
    if (of_open(&f, L"readme.txt", NULL)) { of_put(&f, k_readme, sizeof k_readme - 1); of_close(&f); }
}

static void set_status(const WCHAR *s) { SendDlgItemMessageW(g_dlg, IDC_STATUS, SB_SETTEXTW, 0, (LPARAM)s); }

static void sync_mode(void)
{
    int m = (int)SendDlgItemMessageW(g_dlg, IDC_MODE, CB_GETCURSEL, 0, 0);
    EnableWindow(GetDlgItem(g_dlg, IDC_DOMAIN), m < 2);
}

static void mode_changed(void)            /* keep the target field sensible for the new mode */
{
    int m = (int)SendDlgItemMessageW(g_dlg, IDC_MODE, CB_GETCURSEL, 0, 0), i, j;
    WCHAR t[512], o[600];
    GetDlgItemTextW(g_dlg, IDC_SERVER, t, 512);
    if (m == 3 && !has_scheme(t)) {
        wsprintfW(o, L"https://%s/", t[0] ? t : L"www.google.com");
        SetDlgItemTextW(g_dlg, IDC_SERVER, o);
    } else if (m != 3 && has_scheme(t)) {
        for (i = 0; t[i] && !(t[i] == L':' && t[i + 1] == L'/' && t[i + 2] == L'/'); i++) ;
        i += 3;
        for (j = 0; t[i] && t[i] != L'/' && t[i] != L':' && j < 511; ) o[j++] = t[i++];
        o[j] = 0;
        SetDlgItemTextW(g_dlg, IDC_SERVER, o);
    }
    sync_mode();
}

static void enable_inputs(BOOL on)
{
    static const int ids[] = { IDC_SERVER, IDC_MODE, IDC_DOMAIN, IDC_RATE, IDC_DUR, IDC_TMO, IDC_PATH, IDC_BROWSE, IDC_PACK };
    int i;
    for (i = 0; i < (int)(sizeof ids / sizeof ids[0]); i++) EnableWindow(GetDlgItem(g_dlg, ids[i]), on);
    if (on) sync_mode();
}

static void refresh(void)
{
    Stats st;
    WCHAR b[256], a[16], v[16], mi[16], ma[16], jt[16];
    unsigned el, pct;
    EnterCriticalSection(&g_cs);
    st = g_st;
    LeaveCriticalSection(&g_cs);
    fmt_ms_w(a, st.last_us);
    fmt_ms_w(v, st.written > st.lost ? (int)(st.sum_us / (st.written - st.lost)) : -1);
    fmt_ms_w(mi, st.min_us);
    fmt_ms_w(ma, st.written > st.lost ? st.max_us : -1);
    fmt_ms_w(jt, st.jn ? (int)(st.jsum_us / st.jn) : -1);
    wsprintfW(b, L"Ping:  now %s   avg %s   min %s   max %s  ms", a, v, mi, ma);
    SetDlgItemTextW(g_dlg, IDC_STATS1, b);
    pct = st.written ? (unsigned)((ULONGLONG)st.lost * 10000 / st.written) : 0;
    el = (unsigned)((ULONGLONG)st.written * g_cfg.period_ms / 1000);
    wsprintfW(b, L"Probes %u   Lost %u (%u.%02u%%)   Jitter %s ms   %02u:%02u:%02u",
              st.written, st.lost, pct / 100, pct % 100, jt, el / 3600, el / 60 % 60, el % 60);
    SetDlgItemTextW(g_dlg, IDC_STATS2, b);
    if (g_cfg.total)
        SendDlgItemMessageW(g_dlg, IDC_PROG, PBM_SETPOS, (WPARAM)((ULONGLONG)st.written * 1000 / g_cfg.total), 0);
    InvalidateRect(GetDlgItem(g_dlg, IDC_GRAPH), NULL, FALSE);
}

static void draw_graph(DRAWITEMSTRUCT *di)
{
    RECT rc = di->rcItem;
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    HDC dc = CreateCompatibleDC(di->hDC);
    HBITMAP bm = CreateCompatibleBitmap(di->hDC, w, h), obm = SelectObject(dc, bm);
    HPEN grid = CreatePen(PS_SOLID, 1, RGB(225, 228, 235));
    HPEN line = CreatePen(PS_SOLID, 2, RGB(30, 111, 217));
    HPEN red = CreatePen(PS_SOLID, 1, RGB(220, 50, 50));
    HPEN op;
    HBRUSH bg = CreateSolidBrush(RGB(250, 251, 253));
    int vals[GN], n, i, maxv = 0, scale, prevx = 0, prevy = 0, have = 0;
    unsigned pos;
    WCHAR lbl[24];

    EnterCriticalSection(&g_cs);
    pos = g_gpos;
    n = pos < GN ? (int)pos : GN;
    for (i = 0; i < n; i++) vals[i] = g_graph[(pos - n + i) % GN];
    LeaveCriticalSection(&g_cs);

    FillRect(dc, &(RECT){0, 0, w, h}, bg);
    for (i = 0; i < n; i++) if (vals[i] > maxv) maxv = vals[i];
    scale = 10000;                                         /* us, nice steps */
    while (scale < maxv * 5 / 4) scale = scale < 50000 ? scale * 2 : scale + 50000;
    if (scale == 40000) scale = 50000;

    op = SelectObject(dc, grid);
    for (i = 1; i < 4; i++) { MoveToEx(dc, 0, h * i / 4, NULL); LineTo(dc, w, h * i / 4); }

    for (i = 0; i < n; i++) {
        int x = (w - 1) - (n - 1 - i) * (w - 1) / (GN - 1);
        if (vals[i] < 0) {
            SelectObject(dc, red); MoveToEx(dc, x, 0, NULL); LineTo(dc, x, h);
            have = 0;
        } else {
            int y = h - 2 - (int)((LONGLONG)vals[i] * (h - 4) / scale);
            if (y < 1) y = 1;
            SelectObject(dc, line);
            if (have) { MoveToEx(dc, prevx, prevy, NULL); LineTo(dc, x, y); }
            else SetPixel(dc, x, y, RGB(30, 111, 217));
            prevx = x; prevy = y; have = 1;
        }
    }
    SelectObject(dc, op);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(120, 128, 140));
    SelectObject(dc, (HFONT)SendMessageW(g_dlg, WM_GETFONT, 0, 0));
    wsprintfW(lbl, L"%d ms", scale / 1000);
    TextOutW(dc, 4, 2, lbl, lstrlenW(lbl));
    wsprintfW(lbl, L"last %d s", GN * (g_cfg.period_ms ? g_cfg.period_ms : 100) / 1000);
    SetTextAlign(dc, TA_RIGHT);
    TextOutW(dc, w - 4, h - 16, lbl, lstrlenW(lbl));

    BitBlt(di->hDC, rc.left, rc.top, w, h, dc, 0, 0, SRCCOPY);
    SelectObject(dc, obm);
    DeleteObject(bm); DeleteObject(grid); DeleteObject(line); DeleteObject(red); DeleteObject(bg);
    DeleteDC(dc);
}

static void start(void)
{
    char host[128], dom[72];
    struct addrinfo hints, *ai = NULL;
    WCHAR b[MAX_PATH + 64], domw[72];
    int i, sel;

    {
        int mode = (int)SendDlgItemMessageW(g_dlg, IDC_MODE, CB_GETCURSEL, 0, 0);
        WCHAR raw[512], hw[256];
        URL_COMPONENTS uc;
        GetDlgItemTextW(g_dlg, IDC_SERVER, raw, 512);
        for (i = 0; raw[i] == L' '; i++) ;
        memset(&g_cfg, 0, sizeof g_cfg);
        if (mode == 3 && !has_scheme(raw + i)) wsprintfW(g_cfg.url, L"https://%s", raw + i);
        else lstrcpynW(g_cfg.url, raw + i, 512);
        memset(&uc, 0, sizeof uc);
        uc.dwStructSize = sizeof uc;
        uc.lpszHostName = g_cfg.host; uc.dwHostNameLength = 256;
        uc.lpszUrlPath = g_cfg.path; uc.dwUrlPathLength = 512;
        if (has_scheme(g_cfg.url)) {
            if (!WinHttpCrackUrl(g_cfg.url, 0, 0, &uc) || !g_cfg.host[0]) {
                MessageBoxW(g_dlg, L"Cannot parse the URL. Example: https://www.google.com/", L"DNS Ping", MB_ICONERROR);
                return;
            }
            g_cfg.port = uc.nPort; g_cfg.secure = uc.nScheme == INTERNET_SCHEME_HTTPS;
            if (!g_cfg.path[0]) lstrcpyW(g_cfg.path, L"/");
            lstrcpynW(hw, g_cfg.host, 256);
        } else lstrcpynW(hw, g_cfg.url, 256);
        for (i = lstrlenW(hw); i > 0 && hw[i - 1] == L' '; i--) hw[i - 1] = 0;
        lstrcpynW(g_server, mode == 3 ? g_cfg.url : hw, 128);
        WideCharToMultiByte(CP_ACP, 0, hw, -1, host, sizeof host, NULL, NULL);
        i = 0;
    }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM; hints.ai_protocol = IPPROTO_UDP;
    if (getaddrinfo(host + i, "53", &hints, &ai) != 0 || !ai) {
        MessageBoxW(g_dlg, L"Cannot resolve the target address.", L"DNS Ping", MB_ICONERROR);
        return;
    }
    memcpy(&g_cfg.addr, ai->ai_addr, ai->ai_addrlen);
    g_cfg.addrlen = (int)ai->ai_addrlen;
    freeaddrinfo(ai);

    GetDlgItemTextW(g_dlg, IDC_DOMAIN, domw, 64);
    WideCharToMultiByte(CP_ACP, 0, domw, -1, dom, 64, NULL, NULL);
    for (i = 0; dom[i]; i++) ;
    while (i > 0 && (dom[i - 1] == '.' || dom[i - 1] == ' ')) dom[--i] = 0;
    if (!dom[0] && SendDlgItemMessageW(g_dlg, IDC_MODE, CB_GETCURSEL, 0, 0) < 2) { MessageBoxW(g_dlg, L"Enter a domain to query.", L"DNS Ping", MB_ICONERROR); return; }
    lstrcpyA(g_cfg.domain, dom);

    g_cfg.mode = (int)SendDlgItemMessageW(g_dlg, IDC_MODE, CB_GETCURSEL, 0, 0);
    g_cfg.period_ms = k_rate_ms[SendDlgItemMessageW(g_dlg, IDC_RATE, CB_GETCURSEL, 0, 0)];
    g_cfg.timeout_ms = k_tmo_ms[SendDlgItemMessageW(g_dlg, IDC_TMO, CB_GETCURSEL, 0, 0)];
    sel = (int)SendDlgItemMessageW(g_dlg, IDC_DUR, CB_GETCURSEL, 0, 0);
    g_cfg.total = (unsigned)(k_dur_s[sel] * 1000 / g_cfg.period_ms);

    {
        WCHAR base[MAX_PATH], srv[64];
        SYSTEMTIME st;
        GetDlgItemTextW(g_dlg, IDC_PATH, base, MAX_PATH);
        if (!base[0]) { make_autopath(); lstrcpyW(base, g_autopath); SetDlgItemTextW(g_dlg, IDC_PATH, base); }
        for (i = lstrlenW(base); i > 0 && (base[i - 1] == L'\\' || base[i - 1] == L' '); i--) base[i - 1] = 0;
        lstrcpynW(srv, g_cfg.mode == 3 ? g_cfg.host : g_server, 64);
        for (i = 0; srv[i]; i++)
            if (srv[i] == L':' || srv[i] == L'/' || srv[i] == L'\\' || srv[i] == L'*' || srv[i] == L'?' || srv[i] == L' ') srv[i] = L'-';
        GetLocalTime(&st);
        wsprintfW(g_sessdir, L"%s\\%s_%s_%04d%02d%02d-%02d%02d%02d", base, g_cfg.mode == 3 ? L"http" : g_cfg.mode == 2 ? L"icmp" : L"dns", srv,
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        SHCreateDirectoryExW(NULL, g_sessdir, NULL);
        wsprintfW(g_path, L"%s\\ping.csv", g_sessdir);
    }
    g_cfg.file = CreateFileW(g_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_cfg.file == INVALID_HANDLE_VALUE) {
        MessageBoxW(g_dlg, L"Cannot create the session folder.", L"DNS Ping", MB_ICONERROR);
        return;
    }

    memset(&g_st, 0, sizeof g_st);
    g_st.min_us = g_st.prev_us = g_st.last_us = -1;
    g_gpos = 0; g_flen = 0;
    ResetEvent(g_stop);

    {
        HWND pb = GetDlgItem(g_dlg, IDC_PROG);
        LONG_PTR style = GetWindowLongPtrW(pb, GWL_STYLE);
        if (g_cfg.total) {
            SetWindowLongPtrW(pb, GWL_STYLE, style & ~PBS_MARQUEE);
            SendMessageW(pb, PBM_SETMARQUEE, FALSE, 0);
            SendMessageW(pb, PBM_SETRANGE32, 0, 1000);
            SendMessageW(pb, PBM_SETPOS, 0, 0);
        } else {
            SetWindowLongPtrW(pb, GWL_STYLE, style | PBS_MARQUEE);
            SendMessageW(pb, PBM_SETMARQUEE, TRUE, 40);
        }
    }

    write_readme();
    of_open(&g_events, L"events.log", NULL);
    {
        char desc[256], ip[64];
        static const char *mn[] = { "DNS query (cached name, 0x20)", "DNS query (random subdomain)", "ICMP ping", "HTTP HEAD (curl -I)" };
        addr_str(&g_cfg.addr, ip, sizeof ip);
        wsprintfA(desc, "%s -> %S (%s), every %d ms, timeout %d ms%s%s", mn[g_cfg.mode], g_server, ip, g_cfg.period_ms, g_cfg.timeout_ms,
                  g_cfg.mode >= 2 ? "" : ", domain ", g_cfg.mode >= 2 ? "" : g_cfg.domain);
        ev_log("START", "%s", desc);
        g_mon = netmon_start(&g_cfg.addr, desc);
        g_mtr = mtr_start(&g_cfg.addr);
    }

    g_running = 1;
    enable_inputs(FALSE);
    SetDlgItemTextW(g_dlg, IDC_START, L"STOP");
    wsprintfW(b, L"%s %s every %d ms...", g_cfg.mode == 3 ? L"HEAD" : g_cfg.mode == 2 ? L"Pinging" : L"Querying", g_server, g_cfg.period_ms);
    set_status(b);
    SetTimer(g_dlg, 1, 100, NULL);
    g_thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
}

static int g_closing;

static DWORD WINAPI finisher(LPVOID a)
{
    HANDLE hs[3];
    (void)a;
    SetEvent(g_stop);                                      /* duration over / stop: MTR + monitor too */
    hs[0] = g_thread; hs[1] = g_mtr; hs[2] = g_mon;
    WaitForMultipleObjects(3, hs, TRUE, INFINITE);         /* each thread is bounded (timeouts) */
    ev_log("STOP", "%u probes, %u lost", g_st.written, g_st.lost);
    of_close(&g_events);
    PostMessageW(g_dlg, WM_APP_FIN, 0, 0);
    return 0;
}

static int g_recorded;

static void pack(void)
{
    WCHAR zp[MAX_PATH + 8], b[MAX_PATH + 96], args[MAX_PATH + 16];
    int n;
    if (!g_sessdir[0]) { MessageBoxW(g_dlg, L"Run a test first: the archive packs the last session folder.", L"DNS Ping", MB_ICONINFORMATION); return; }
    if (g_running) of_flush(&g_events);
    n = zip_dir(g_sessdir, zp);
    if (!n) { MessageBoxW(g_dlg, L"Cannot create the archive.", L"DNS Ping", MB_ICONERROR); return; }
    clipboard_file(g_dlg, zp);
    wsprintfW(args, L"/select,\"%s\"", zp);
    ShellExecuteW(g_dlg, NULL, L"explorer.exe", args, NULL, SW_SHOWNORMAL);
    wsprintfW(b, L"Archive copied to clipboard (Ctrl+V into a chat): %s", zp);
    set_status(b);
}
static void analyze(void) { analyze_open(g_dlg, g_recorded || g_running ? g_path : NULL); }

static INT_PTR CALLBACK DlgProc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    int i;
    switch (m) {
    case WM_INITDIALOG: {
        LOGFONTW lf;
        HICON ic = LoadIconW(g_inst, MAKEINTRESOURCEW(IDI_APP));
        g_dlg = h;
        SendMessageW(h, WM_SETICON, ICON_BIG, (LPARAM)ic);
        SendMessageW(h, WM_SETICON, ICON_SMALL, (LPARAM)ic);
        GetObjectW((HFONT)SendMessageW(h, WM_GETFONT, 0, 0), sizeof lf, &lf);
        lf.lfWeight = FW_BOLD; lf.lfHeight = lf.lfHeight * 5 / 4;
        g_hfont = CreateFontIndirectW(&lf);
        for (i = IDC_H1; i <= IDC_H3; i++) SendDlgItemMessageW(h, i, WM_SETFONT, (WPARAM)g_hfont, 0);

        for (i = 0; i < (int)(sizeof k_servers / sizeof *k_servers); i++)
            SendDlgItemMessageW(h, IDC_SERVER, CB_ADDSTRING, 0, (LPARAM)k_servers[i]);
        SetDlgItemTextW(h, IDC_SERVER, k_servers[0]);
        SendDlgItemMessageW(h, IDC_MODE, CB_ADDSTRING, 0, (LPARAM)L"Cached name (0x20)");
        SendDlgItemMessageW(h, IDC_MODE, CB_ADDSTRING, 0, (LPARAM)L"Random subdomain");
        SendDlgItemMessageW(h, IDC_MODE, CB_ADDSTRING, 0, (LPARAM)L"ICMP ping");
        SendDlgItemMessageW(h, IDC_MODE, CB_ADDSTRING, 0, (LPARAM)L"HTTP HEAD (curl -I)");
        SendDlgItemMessageW(h, IDC_MODE, CB_SETCURSEL, 0, 0);
        SetDlgItemTextW(h, IDC_DOMAIN, L"google.com");
        for (i = 0; i < RATE_N; i++) SendDlgItemMessageW(h, IDC_RATE, CB_ADDSTRING, 0, (LPARAM)k_rate_s[i]);
        SendDlgItemMessageW(h, IDC_RATE, CB_SETCURSEL, RATE_DEF, 0);
        for (i = 0; i < 8; i++) SendDlgItemMessageW(h, IDC_DUR, CB_ADDSTRING, 0, (LPARAM)k_dur_str[i]);
        SendDlgItemMessageW(h, IDC_DUR, CB_SETCURSEL, 3, 0);
        for (i = 0; i < 3; i++) SendDlgItemMessageW(h, IDC_TMO, CB_ADDSTRING, 0, (LPARAM)k_tmo_s[i]);
        SendDlgItemMessageW(h, IDC_TMO, CB_SETCURSEL, 1, 0);
        make_autopath();
        SetDlgItemTextW(h, IDC_PATH, g_autopath);
        g_cfg.period_ms = 100;
        g_st.min_us = g_st.prev_us = g_st.last_us = -1;
        refresh();
        set_status(L"Ready");
        return TRUE;
    }
    case WM_DRAWITEM:
        if (wp == IDC_GRAPH) { draw_graph((DRAWITEMSTRUCT *)lp); return TRUE; }
        break;
    case WM_TIMER:
        if (wp == 2) { EndDialog(h, 0); return TRUE; }
        refresh();
        return TRUE;
    case WM_APP_DONE:                                      /* probe thread ended: finish the rest off the UI thread */
        KillTimer(h, 1);
        refresh();
        EnableWindow(GetDlgItem(h, IDC_START), FALSE);
        set_status(L"Finishing: final MTR table and system snapshot...");
        CloseHandle(CreateThread(NULL, 0, finisher, NULL, 0, NULL));
        return TRUE;
    case WM_APP_FIN: {
        WCHAR b[MAX_PATH + 64];
        CloseHandle(g_thread); CloseHandle(g_mtr); CloseHandle(g_mon);
        g_running = 0;
        if (g_closing) { EndDialog(h, 0); return TRUE; }
        g_recorded = 1;
        refresh();
        SendDlgItemMessageW(h, IDC_PROG, PBM_SETMARQUEE, FALSE, 0);
        enable_inputs(TRUE);
        EnableWindow(GetDlgItem(h, IDC_START), TRUE);
        SetDlgItemTextW(h, IDC_START, L"START");
        wsprintfW(b, L"Saved %u probes to %s", g_st.written, g_sessdir);
        set_status(b);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_START:
            if (g_running) {
                SetEvent(g_stop);
                EnableWindow(GetDlgItem(h, IDC_START), FALSE);
                set_status(L"Stopping (waiting for in-flight replies)...");
            } else start();
            return TRUE;
        case IDC_MODE:
        case IDC_SERVER:
            if (HIWORD(wp) == CBN_SELCHANGE || HIWORD(wp) == CBN_EDITCHANGE) {
                if (LOWORD(wp) == IDC_MODE && HIWORD(wp) == CBN_SELCHANGE) mode_changed();
            }
            return TRUE;
        case IDC_BROWSE: {
            BROWSEINFOW bi;
            WCHAR fn[MAX_PATH];
            LPITEMIDLIST il;
            memset(&bi, 0, sizeof bi);
            bi.hwndOwner = h; bi.pszDisplayName = fn;
            bi.lpszTitle = L"Folder for test sessions (a subfolder is created per test)";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            il = SHBrowseForFolderW(&bi);
            if (il) {
                if (SHGetPathFromIDListW(il, fn)) SetDlgItemTextW(h, IDC_PATH, fn);
                CoTaskMemFree(il);
            }
            return TRUE;
        }
        case IDC_MTR:
            mtr_window(h);
            return TRUE;
        case IDC_PACK:
            pack();
            return TRUE;
        case IDC_ANALYZE:
            analyze();
            return TRUE;
        case IDCANCEL:
            if (!g_running) { EndDialog(h, 0); return TRUE; }
            if (!g_closing) {                              /* let the files finish, then exit */
                g_closing = 1;
                SetEvent(g_stop);
                EnableWindow(GetDlgItem(h, IDC_START), FALSE);
                EnableWindow(GetDlgItem(h, IDCANCEL), FALSE);
                set_status(L"Closing: saving files...");
                SetTimer(h, 2, 20000, NULL);               /* safety net */
            }
            return TRUE;
        }
        break;
    }
    return FALSE;
}

void WINAPI entry(void)
{
    INITCOMMONCONTROLSEX icc = { sizeof icc, ICC_PROGRESS_CLASS | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES };
    WSADATA wsa;
    LARGE_INTEGER t;
    InitCommonControlsEx(&icc);
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitializeCriticalSection(&g_cs);
    QueryPerformanceCounter(&t);
    g_rng = (unsigned)t.QuadPart ^ GetCurrentProcessId() << 16 ^ GetTickCount();
    if (!g_rng) g_rng = 0x9e3779b9;
    g_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_inst = GetModuleHandleW(NULL);
    ExitProcess((UINT)DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_MAIN), NULL, DlgProc, 0));
}

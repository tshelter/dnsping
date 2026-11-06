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
 * Built without the C runtime (see build.sh) to keep the .exe tiny.
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <mmsystem.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include "res.h"

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

/* ---- freestanding helpers (no CRT) ---- */
void *memset(void *d, int c, size_t n) { unsigned char *p = d; while (n--) *p++ = (unsigned char)c; return d; }
void *memcpy(void *d, const void *s, size_t n) { unsigned char *p = d; const unsigned char *q = s; while (n--) *p++ = *q++; return d; }

#define WM_APP_DONE (WM_APP + 1)
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
    int addrlen, mode, /* 0 dns 0x20, 1 dns random, 2 icmp */ period_ms, timeout_ms;
    unsigned total;
    char domain[72];
    HANDLE file;
} Cfg;

static HINSTANCE g_inst;
static HWND g_dlg;
static HANDLE g_thread, g_stop;
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

static const int k_rate_ms[] = { 100, 50, 200, 500, 1000 };
static const WCHAR *k_rate_s[] = { L"10 Hz (100 ms)", L"20 Hz (50 ms)", L"5 Hz (200 ms)", L"2 Hz (500 ms)", L"1 Hz (1 s)" };
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

static DWORD WINAPI worker(LPVOID arg)
{
    Cfg *c = &g_cfg;
    unsigned char pkt[512];
    LARGE_INTEGER fq;
    LONGLONG per, tmo, next, now, lastflush;
    unsigned nseq = 0, wseq = 0;
    unsigned short salt = (unsigned short)rnd();
    int stopping = 0, i, r;
    DWORD br, f = FALSE;
    HANDLE hs[64], ih = INVALID_HANDLE_VALUE;
    int icmp = c->mode == 2, v6 = c->addr.ss_family == AF_INET6;
    SOCKET s;
    WSAEVENT ev;
    (void)arg;

    QueryPerformanceFrequency(&fq);
    per = fq.QuadPart * c->period_ms / 1000;
    tmo = fq.QuadPart * c->timeout_ms / 1000;

    if (icmp) {
        ih = v6 ? Icmp6CreateFile() : IcmpCreateFile();
        s = INVALID_SOCKET; ev = NULL;
    } else {
        s = socket(c->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
        connect(s, (struct sockaddr *)&c->addr, c->addrlen);
        WSAIoctl(s, SIO_UDP_CONNRESET, &f, sizeof f, NULL, 0, &br, NULL, NULL);
        ev = WSACreateEvent();
        WSAEventSelect(s, ev, FD_READ);
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
            write_row(sl);
            wseq++;
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

static void make_autopath(void)
{
    WCHAR dir[MAX_PATH], srv[64];
    SYSTEMTIME st;
    int i;
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, dir) != S_OK) {
        GetModuleFileNameW(NULL, dir, MAX_PATH);
        for (i = lstrlenW(dir); i > 0 && dir[i - 1] != L'\\'; i--) ;
        dir[i ? i - 1 : 0] = 0;
    }
    GetDlgItemTextW(g_dlg, IDC_SERVER, srv, 64);
    for (i = 0; srv[i]; i++)
        if (srv[i] == L':' || srv[i] == L'/' || srv[i] == L'\\' || srv[i] == L'*' || srv[i] == L'?') srv[i] = L'-';
    GetLocalTime(&st);
    wsprintfW(g_autopath, L"%s\\%s_%s_%04d%02d%02d-%02d%02d%02d.csv", dir,
              SendDlgItemMessageW(g_dlg, IDC_MODE, CB_GETCURSEL, 0, 0) == 2 ? L"icmpping" : L"dnsping", srv,
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static void set_status(const WCHAR *s) { SendDlgItemMessageW(g_dlg, IDC_STATUS, SB_SETTEXTW, 0, (LPARAM)s); }

static void sync_mode(void)
{
    int icmp = SendDlgItemMessageW(g_dlg, IDC_MODE, CB_GETCURSEL, 0, 0) == 2;
    EnableWindow(GetDlgItem(g_dlg, IDC_DOMAIN), !icmp);
}

static void enable_inputs(BOOL on)
{
    static const int ids[] = { IDC_SERVER, IDC_MODE, IDC_DOMAIN, IDC_RATE, IDC_DUR, IDC_TMO, IDC_PATH, IDC_BROWSE };
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

    GetDlgItemTextW(g_dlg, IDC_SERVER, g_server, 128);
    WideCharToMultiByte(CP_ACP, 0, g_server, -1, host, sizeof host, NULL, NULL);
    for (i = 0; host[i] == ' '; i++) ;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM; hints.ai_protocol = IPPROTO_UDP;
    if (getaddrinfo(host + i, "53", &hints, &ai) != 0 || !ai) {
        MessageBoxW(g_dlg, L"Cannot resolve the DNS server address.", L"DNS Ping", MB_ICONERROR);
        return;
    }
    memset(&g_cfg, 0, sizeof g_cfg);
    memcpy(&g_cfg.addr, ai->ai_addr, ai->ai_addrlen);
    g_cfg.addrlen = (int)ai->ai_addrlen;
    freeaddrinfo(ai);

    GetDlgItemTextW(g_dlg, IDC_DOMAIN, domw, 64);
    WideCharToMultiByte(CP_ACP, 0, domw, -1, dom, 64, NULL, NULL);
    for (i = 0; dom[i]; i++) ;
    while (i > 0 && (dom[i - 1] == '.' || dom[i - 1] == ' ')) dom[--i] = 0;
    if (!dom[0] && SendDlgItemMessageW(g_dlg, IDC_MODE, CB_GETCURSEL, 0, 0) != 2) { MessageBoxW(g_dlg, L"Enter a domain to query.", L"DNS Ping", MB_ICONERROR); return; }
    lstrcpyA(g_cfg.domain, dom);

    g_cfg.mode = (int)SendDlgItemMessageW(g_dlg, IDC_MODE, CB_GETCURSEL, 0, 0);
    g_cfg.period_ms = k_rate_ms[SendDlgItemMessageW(g_dlg, IDC_RATE, CB_GETCURSEL, 0, 0)];
    g_cfg.timeout_ms = k_tmo_ms[SendDlgItemMessageW(g_dlg, IDC_TMO, CB_GETCURSEL, 0, 0)];
    sel = (int)SendDlgItemMessageW(g_dlg, IDC_DUR, CB_GETCURSEL, 0, 0);
    g_cfg.total = (unsigned)(k_dur_s[sel] * 1000 / g_cfg.period_ms);

    GetDlgItemTextW(g_dlg, IDC_PATH, g_path, MAX_PATH);
    if (!g_path[0] || !lstrcmpW(g_path, g_autopath)) {
        make_autopath();
        lstrcpyW(g_path, g_autopath);
        SetDlgItemTextW(g_dlg, IDC_PATH, g_path);
    }
    g_cfg.file = CreateFileW(g_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_cfg.file == INVALID_HANDLE_VALUE) {
        MessageBoxW(g_dlg, L"Cannot create the output file.", L"DNS Ping", MB_ICONERROR);
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

    g_running = 1;
    enable_inputs(FALSE);
    EnableWindow(GetDlgItem(g_dlg, IDC_ANALYZE), FALSE);
    SetDlgItemTextW(g_dlg, IDC_START, L"STOP");
    wsprintfW(b, L"%s %s every %d ms...", g_cfg.mode == 2 ? L"Pinging" : L"Querying", g_server, g_cfg.period_ms);
    set_status(b);
    SetTimer(g_dlg, 1, 100, NULL);
    g_thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
}

static void stop_and_wait(DWORD ms)
{
    if (!g_running) return;
    SetEvent(g_stop);
    WaitForSingleObject(g_thread, ms);
}

static void analyze(void)
{
    WCHAR args[MAX_PATH + 16];
    wsprintfW(args, L"/select,\"%s\"", g_path);
    ShellExecuteW(g_dlg, NULL, L"explorer.exe", args, NULL, SW_SHOWNORMAL);
    ShellExecuteW(g_dlg, L"open", L"https://zxc.sx/ping-analyzer", NULL, NULL, SW_SHOWNORMAL);
}

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
        SendDlgItemMessageW(h, IDC_MODE, CB_SETCURSEL, 0, 0);
        SetDlgItemTextW(h, IDC_DOMAIN, L"google.com");
        for (i = 0; i < 5; i++) SendDlgItemMessageW(h, IDC_RATE, CB_ADDSTRING, 0, (LPARAM)k_rate_s[i]);
        SendDlgItemMessageW(h, IDC_RATE, CB_SETCURSEL, 0, 0);
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
        refresh();
        return TRUE;
    case WM_APP_DONE: {
        WCHAR b[MAX_PATH + 64];
        KillTimer(h, 1);
        WaitForSingleObject(g_thread, INFINITE);
        CloseHandle(g_thread);
        g_running = 0;
        refresh();
        SendDlgItemMessageW(h, IDC_PROG, PBM_SETMARQUEE, FALSE, 0);
        enable_inputs(TRUE);
        EnableWindow(GetDlgItem(h, IDC_START), TRUE);
        EnableWindow(GetDlgItem(h, IDC_ANALYZE), TRUE);
        SetDlgItemTextW(h, IDC_START, L"START");
        wsprintfW(b, L"Saved %u rows: %s", g_st.written, g_path);
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
                WCHAR cur[MAX_PATH];
                if (LOWORD(wp) == IDC_MODE) sync_mode();
                if (LOWORD(wp) == IDC_SERVER && HIWORD(wp) == CBN_SELCHANGE) return TRUE;  /* text not updated yet */
                GetDlgItemTextW(h, IDC_PATH, cur, MAX_PATH);
                if (!lstrcmpW(cur, g_autopath)) { make_autopath(); SetDlgItemTextW(h, IDC_PATH, g_autopath); }
            }
            return TRUE;
        case IDC_BROWSE: {
            OPENFILENAMEW of;
            WCHAR fn[MAX_PATH];
            GetDlgItemTextW(h, IDC_PATH, fn, MAX_PATH);
            memset(&of, 0, sizeof of);
            of.lStructSize = sizeof of; of.hwndOwner = h;
            of.lpstrFilter = L"CSV files (*.csv)\0*.csv\0All files\0*.*\0";
            of.lpstrFile = fn; of.nMaxFile = MAX_PATH; of.lpstrDefExt = L"csv";
            of.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER;
            if (GetSaveFileNameW(&of)) SetDlgItemTextW(h, IDC_PATH, fn);
            return TRUE;
        }
        case IDC_ANALYZE:
            analyze();
            return TRUE;
        case IDCANCEL:
            stop_and_wait(5000);
            EndDialog(h, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

void WINAPI entry(void)
{
    INITCOMMONCONTROLSEX icc = { sizeof icc, ICC_PROGRESS_CLASS | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES };
    WSADATA wsa;
    LARGE_INTEGER t;
    InitCommonControlsEx(&icc);
    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitializeCriticalSection(&g_cs);
    QueryPerformanceCounter(&t);
    g_rng = (unsigned)t.QuadPart ^ GetCurrentProcessId() << 16 ^ GetTickCount();
    if (!g_rng) g_rng = 0x9e3779b9;
    g_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_inst = GetModuleHandleW(NULL);
    ExitProcess((UINT)DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_MAIN), NULL, DlgProc, 0));
}

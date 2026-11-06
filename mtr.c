/*
 * Minimal MTR: once per second, an ICMP echo with TTL = 1..N to the target
 * (async IcmpSendEcho2 / Icmp6SendEcho2, no admin rights). Per-hop stats,
 * per-probe log (mtr.csv), final table with interpretation (mtr.txt) and a
 * live window. Reverse DNS runs in its own thread.
 */
#include "common.h"
#include <iphlpapi.h>
#include <icmpapi.h>
#include <commctrl.h>
#include "res.h"

#define MAXHOP 30
typedef struct {
    unsigned sent, recv;
    int last, best, worst;                    /* us; last < 0 = lost */
    unsigned long long sum, sum2;
    char ip[48], name[128];
    int named;
} Hop;

static Hop H[MAXHOP + 1];
static int Hdest, Hmax;
static unsigned Hround;
static CRITICAL_SECTION Hcs;
static int Hinit;
static char Htarget[64];
static struct sockaddr_storage Mtarget;
static HWND Mwnd;
static volatile LONG Mgen;                     /* bumps each test: stale resolver threads exit */

void mtr_reset(void)
{
    if (!Hinit) { InitializeCriticalSection(&Hcs); Hinit = 1; }
    EnterCriticalSection(&Hcs);
    memset(H, 0, sizeof H);
    Hdest = Hmax = 0; Hround = 0;
    LeaveCriticalSection(&Hcs);
}

static LONGLONG qpc(void) { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }

static void f_ms(char *b, int us)
{
    int t;
    if (us < 0) { lstrcpyA(b, "-"); return; }
    t = (us + 50) / 100;
    wsprintfA(b, "%d.%d", t / 10, t % 10);
}

static int nhops(void) { return Hdest ? Hdest : (Hmax < MAXHOP ? Hmax + (Hmax ? 1 : 0) : MAXHOP); }
static unsigned loss_pm(const Hop *h) { return h->sent ? (h->sent - h->recv) * 1000 / h->sent : 0; }  /* per mille */

/* Interpretation, in the spirit of pathping's "where does loss start" column. */
static const char *note(int i, int n)
{
    const Hop *h = &H[i];
    unsigned l = loss_pm(h), dl;
    int j, later_ok = 0, persists = 1;
    if (!h->sent) return "";
    for (j = i + 1; j <= n; j++) if (H[j].recv) later_ok = 1;
    if (!h->recv) return later_ok ? "no reply (filtered) - path OK" : (i == n ? "no reply" : "");
    if (l >= 10) {
        for (j = i + 1; j <= n; j++) if (H[j].sent >= 5 && loss_pm(&H[j]) * 2 < l) persists = 0;
        if (!persists) return "ICMP rate-limit, not real loss";
        for (j = 1; j < i; j++) {          /* earlier hop already persisting? */
            unsigned pl = loss_pm(&H[j]);
            int k, p = pl >= 10;
            for (k = j + 1; k <= n && p; k++) if (H[k].sent >= 5 && loss_pm(&H[k]) * 2 < pl) p = 0;
            if (p) return "";
        }
        return "<< LOSS STARTS HERE";
    }
    dl = i == n ? l : 0; (void)dl;
    if (i == 1 && is_private(h->ip)) return "your router / LAN";
    if (is_private(h->ip) && h->ip[0] == '1' && h->ip[1] == '0' && h->ip[2] == '0' && h->ip[3] == '.') return "CGNAT";
    return "";
}

static void row_text(int i, int n, char *host, char *loss, char *last, char *avg, char *best, char *worst, char *sd, const char **nt)
{
    Hop *h = &H[i];
    unsigned l = loss_pm(h);
    if (h->ip[0]) {
        if (h->name[0] && lstrcmpA(h->name, h->ip)) wsprintfA(host, "%s [%s]", h->name, h->ip);
        else lstrcpyA(host, h->ip);
    } else lstrcpyA(host, "*");
    wsprintfA(loss, "%u.%u", l / 10, l % 10);
    f_ms(last, h->recv ? h->last : -1);
    f_ms(avg, h->recv ? (int)(h->sum / h->recv) : -1);
    f_ms(best, h->recv ? h->best : -1);
    f_ms(worst, h->recv ? h->worst : -1);
    if (h->recv > 1) {
        unsigned long long m = h->sum / h->recv, v = h->sum2 / h->recv;
        f_ms(sd, (int)isqrt64(v > m * m ? v - m * m : 0));
    } else lstrcpyA(sd, "-");
    *nt = note(i, n);
}

static int mtr_text(char *b, int cap)
{
    int n, i, k;
    char host[200], loss[16], last[16], avg[16], best[16], worst[16], sd[16], t[32];
    const char *nt;
    EnterCriticalSection(&Hcs);
    n = nhops();
    ts_now(t);
    k = wsprintfA(b, "MTR to %s, %u rounds (1 per second), %s\r\n\r\n%3s  %-52s %6s %5s %7s %7s %7s %7s %7s  %s\r\n",
                  Htarget, Hround, t, "#", "Host", "Loss%", "Sent", "Last", "Avg", "Best", "Worst", "StDev", "Note");
    for (i = 1; i <= n && k < cap - 400; i++) {
        row_text(i, n, host, loss, last, avg, best, worst, sd, &nt);
        k += wsprintfA(b + k, "%3d  %-52s %6s %5u %7s %7s %7s %7s %7s  %s\r\n", i, host, loss, H[i].sent, last, avg, best, worst, sd, nt);
    }
    LeaveCriticalSection(&Hcs);
    if (k < cap - 600)
        k += wsprintfA(b + k, "\r\nHow to read: loss only matters if it continues down to the last hop. A hop with loss\r\n"
                              "(or no reply at all) followed by clean hops is just a router that deprioritises ICMP.\r\n"
                              "Hop 1 is usually your router: loss there = Wi-Fi/LAN problem; loss starting further = ISP or beyond.\r\n");
    return k;
}

static DWORD WINAPI resolver(LPVOID a)
{
    LONG gen = (LONG)(LONG_PTR)a;
    do {
        int i;
        for (i = 1; i <= MAXHOP; i++) {
            char ip[48], nm[NI_MAXHOST];
            struct addrinfo hints, *ai = NULL;
            EnterCriticalSection(&Hcs);
            if (H[i].named || !H[i].ip[0]) { LeaveCriticalSection(&Hcs); continue; }
            lstrcpyA(ip, H[i].ip);
            LeaveCriticalSection(&Hcs);
            nm[0] = 0;
            memset(&hints, 0, sizeof hints); hints.ai_flags = AI_NUMERICHOST;
            if (getaddrinfo(ip, NULL, &hints, &ai) == 0 && ai) {
                if (getnameinfo(ai->ai_addr, (socklen_t)ai->ai_addrlen, nm, sizeof nm, NULL, 0, NI_NAMEREQD)) nm[0] = 0;
                freeaddrinfo(ai);
            }
            if (gen != Mgen) return 0;
            EnterCriticalSection(&Hcs);
            if (!lstrcmpA(H[i].ip, ip)) { lstrcpynA(H[i].name, nm, sizeof H[i].name); H[i].named = 1; }
            LeaveCriticalSection(&Hcs);
        }
    } while (gen == Mgen && WaitForSingleObject(g_stop, 500) == WAIT_TIMEOUT);
    return 0;
}

static DWORD WINAPI mtr_thread(LPVOID a)
{
    static HANDLE evs[2][MAXHOP + 1];                  /* two sets: odd/even rounds, so a late */
    static unsigned char reps[2][MAXHOP + 1][256];    /* completion can't land in the next round */
    unsigned round = 0;
    static unsigned char payload[32] = "DNSPing-MTR-probe-0123456789abc";
    int v6 = Mtarget.ss_family == AF_INET6, i;
    HANDLE ih = v6 ? Icmp6CreateFile() : IcmpCreateFile();
    OutFile csv;
    LARGE_INTEGER fq;
    (void)a;

    QueryPerformanceFrequency(&fq);
    of_open(&csv, L"mtr.csv", "Timestamp,Hop,IP,RTT (ms)\r\n");
    for (i = 1; i <= MAXHOP; i++) {
        if (!evs[0][i]) evs[0][i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!evs[1][i]) evs[1][i] = CreateEventW(NULL, TRUE, FALSE, NULL);
    }
    CloseHandle(CreateThread(NULL, 0, resolver, (LPVOID)(LONG_PTR)Mgen, 0, NULL));

    do {
        HANDLE *ev = evs[round & 1];
        unsigned char (*rep)[256] = reps[round++ & 1];
        LONGLONG start = qpc(), t0[MAXHOP + 1], t1[MAXHOP + 1];
        int pend[MAXHOP + 1], lim = Hdest ? Hdest : MAXHOP, ttl;
        char ts[32];
        DWORD wait;
        ts_now(ts);
        for (ttl = 1; ttl <= lim; ttl++) {
            IP_OPTION_INFORMATION opt;
            DWORD r;
            memset(&opt, 0, sizeof opt);
            opt.Ttl = (UCHAR)ttl;
            ResetEvent(ev[ttl]);
            t0[ttl] = qpc(); t1[ttl] = 0;
            if (v6) {
                struct sockaddr_in6 src;
                memset(&src, 0, sizeof src); src.sin6_family = AF_INET6;
                r = Icmp6SendEcho2(ih, ev[ttl], NULL, NULL, &src, (struct sockaddr_in6 *)&Mtarget, payload, sizeof payload,
                                   &opt, rep[ttl], sizeof rep[ttl], 900);
            } else {
                r = IcmpSendEcho2(ih, ev[ttl], NULL, NULL, ((struct sockaddr_in *)&Mtarget)->sin_addr.s_addr, payload, sizeof payload,
                                  &opt, rep[ttl], sizeof rep[ttl], 900);
            }
            pend[ttl] = r || GetLastError() == ERROR_IO_PENDING;
        }
        for (;;) {                                         /* collect completions with precise timestamps */
            HANDLE hs[MAXHOP];
            int map[MAXHOP], n = 0;
            LONGLONG el = (qpc() - start) * 1000 / fq.QuadPart;
            DWORD r;
            for (ttl = 1; ttl <= lim; ttl++) if (pend[ttl] && !t1[ttl]) { map[n] = ttl; hs[n++] = ev[ttl]; }
            if (!n || el >= 1000) break;
            r = WaitForMultipleObjects(n, hs, FALSE, (DWORD)(1000 - el));
            if (r >= WAIT_OBJECT_0 + (DWORD)n) break;
            t1[map[r - WAIT_OBJECT_0]] = qpc();
        }

        EnterCriticalSection(&Hcs);
        for (ttl = 1; ttl <= lim; ttl++) {
            Hop *h = &H[ttl];
            char ip[48] = "";
            int ok = 0, dest = 0, us = 0;
            if (pend[ttl] && t1[ttl]) {
                if (v6) {
                    ICMPV6_ECHO_REPLY *e = (ICMPV6_ECHO_REPLY *)rep[ttl];
                    if (Icmp6ParseReplies(rep[ttl], sizeof rep[ttl]) && (e->Status == IP_SUCCESS || e->Status == IP_TTL_EXPIRED_TRANSIT)) {
                        struct sockaddr_in6 s6;
                        memset(&s6, 0, sizeof s6); s6.sin6_family = AF_INET6;
                        memcpy(&s6.sin6_addr, e->Address.sin6_addr, 16);
                        addr_str(&s6, ip, sizeof ip);
                        ok = 1; dest = e->Status == IP_SUCCESS;
                    }
                } else {
                    ICMP_ECHO_REPLY *e = (ICMP_ECHO_REPLY *)rep[ttl];
                    if (IcmpParseReplies(rep[ttl], sizeof rep[ttl]) && (e->Status == IP_SUCCESS || e->Status == IP_TTL_EXPIRED_TRANSIT)) {
                        struct sockaddr_in s4;
                        memset(&s4, 0, sizeof s4); s4.sin_family = AF_INET; s4.sin_addr.s_addr = e->Address;
                        addr_str(&s4, ip, sizeof ip);
                        ok = 1; dest = e->Status == IP_SUCCESS;
                    }
                }
            }
            h->sent++;
            if (ok) {
                us = (int)((t1[ttl] - t0[ttl]) * 1000000 / fq.QuadPart);
                h->recv++; h->last = us; h->sum += us; h->sum2 += (unsigned long long)us * us;
                if (h->recv == 1 || us < h->best) h->best = us;
                if (us > h->worst) h->worst = us;
                if (lstrcmpA(h->ip, ip)) { lstrcpyA(h->ip, ip); h->name[0] = 0; h->named = 0; }
                if (ttl > Hmax) Hmax = ttl;
                if (dest && (!Hdest || ttl < Hdest)) Hdest = ttl;
                { char ms[16]; f_ms(ms, us); of_printf(&csv, "%s,%d,%s,%s\r\n", ts, ttl, ip, ms); }
            } else {
                h->last = -1;
                of_printf(&csv, "%s,%d,,PACKET_LOSS\r\n", ts, ttl);
            }
            if (dest) break;                              /* nothing beyond the destination */
        }
        Hround++;
        LeaveCriticalSection(&Hcs);
        of_flush(&csv);

        wait = (DWORD)((qpc() - start) * 1000 / fq.QuadPart);
        wait = wait < 1000 ? 1000 - wait : 0;
        if (WaitForSingleObject(g_stop, wait) != WAIT_TIMEOUT) break;
    } while (1);

    of_close(&csv);
    {
        static char txt[32768];
        OutFile f;
        int n = mtr_text(txt, sizeof txt);
        if (of_open(&f, L"mtr.txt", NULL)) { of_put(&f, txt, n); of_close(&f); }
    }
    Sleep(1000);                                          /* let in-flight requests finish before closing */
    IcmpCloseHandle(ih);
    return 0;
}

HANDLE mtr_start(const struct sockaddr_storage *target)
{
    mtr_reset();
    InterlockedIncrement(&Mgen);
    Mtarget = *target;
    addr_str(target, Htarget, sizeof Htarget);
    return CreateThread(NULL, 0, mtr_thread, NULL, 0, NULL);
}

/* ---------- window ---------- */
static void lv_text(HWND lv, int row, int col, const char *s, int insert)
{
    WCHAR w[256];
    LVITEMW it;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, 256);
    memset(&it, 0, sizeof it);
    it.mask = LVIF_TEXT; it.iItem = row; it.iSubItem = col; it.pszText = w;
    if (insert) SendMessageW(lv, LVM_INSERTITEMW, 0, (LPARAM)&it);
    else SendMessageW(lv, LVM_SETITEMTEXTW, row, (LPARAM)&it);
}

static void mtr_refresh(HWND h)
{
    HWND lv = GetDlgItem(h, IDC_M_LIST);
    int n, i, have;
    char host[200], loss[16], last[16], avg[16], best[16], worst[16], sd[16], num[16];
    const char *nt;
    WCHAR hdr[160];
    if (!Hinit) return;
    EnterCriticalSection(&Hcs);
    n = nhops();
    have = (int)SendMessageW(lv, LVM_GETITEMCOUNT, 0, 0);
    while (have > n) SendMessageW(lv, LVM_DELETEITEM, --have, 0);
    for (i = 1; i <= n; i++) {
        row_text(i, n, host, loss, last, avg, best, worst, sd, &nt);
        wsprintfA(num, "%d", i);
        lv_text(lv, i - 1, 0, num, i > have);
        lv_text(lv, i - 1, 1, host, 0);
        lv_text(lv, i - 1, 2, loss, 0);
        wsprintfA(num, "%u", H[i].sent); lv_text(lv, i - 1, 3, num, 0);
        lv_text(lv, i - 1, 4, last, 0);
        lv_text(lv, i - 1, 5, avg, 0);
        lv_text(lv, i - 1, 6, best, 0);
        lv_text(lv, i - 1, 7, worst, 0);
        lv_text(lv, i - 1, 8, sd, 0);
        lv_text(lv, i - 1, 9, nt, 0);
    }
    wsprintfW(hdr, L"Target: %S    Rounds: %u (1 per second)    %s", Htarget[0] ? Htarget : "-", Hround,
              Hround ? (Hdest ? L"" : L"destination not reached yet") : L"Start a test to run MTR");
    LeaveCriticalSection(&Hcs);
    SetDlgItemTextW(h, IDC_M_HDR, hdr);
}

static INT_PTR CALLBACK MtrProc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (m) {
    case WM_INITDIALOG: {
        HWND lv = GetDlgItem(h, IDC_M_LIST);
        static const WCHAR *cols[] = { L"#", L"Host", L"Loss %", L"Sent", L"Last", L"Avg", L"Best", L"Worst", L"StDev", L"Note" };
        static const int w[] = { 3, 33, 9, 7, 7, 7, 7, 8, 8, 34 }, right[] = { 1, 0, 1, 1, 1, 1, 1, 1, 1, 0 };
        RECT r;
        int i, tot;
        DWORD ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES;
        SendMessageW(h, WM_SETICON, ICON_BIG, (LPARAM)LoadIconW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDI_APP)));
        SendMessageW(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, ex, ex);
        GetClientRect(lv, &r);
        tot = r.right - GetSystemMetrics(SM_CXVSCROLL);
        for (i = 0; i < 10; i++) {
            LVCOLUMNW c;
            memset(&c, 0, sizeof c);
            c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            c.fmt = right[i] ? LVCFMT_RIGHT : LVCFMT_LEFT;
            c.pszText = (WCHAR *)cols[i]; c.cx = tot * w[i] / 125;
            SendMessageW(lv, LVM_INSERTCOLUMNW, i, (LPARAM)&c);
        }
        mtr_refresh(h);
        SetTimer(h, 1, 1000, NULL);
        return TRUE;
    }
    case WM_TIMER:
        mtr_refresh(h);
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_M_COPY && Hinit) {
            static char txt[32768];
            int n = mtr_text(txt, sizeof txt), wn;
            HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, (n + 1) * sizeof(WCHAR));
            WCHAR *w = GlobalLock(g);
            wn = MultiByteToWideChar(CP_UTF8, 0, txt, n, w, n);
            w[wn] = 0;
            GlobalUnlock(g);
            if (OpenClipboard(h)) { EmptyClipboard(); SetClipboardData(CF_UNICODETEXT, g); CloseClipboard(); } else GlobalFree(g);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { ShowWindow(h, SW_HIDE); return TRUE; }
        break;
    }
    return FALSE;
}

void mtr_window(HWND parent)
{
    if (!Mwnd) Mwnd = CreateDialogParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_MTR), parent, MtrProc, 0);
    mtr_refresh(Mwnd);
    ShowWindow(Mwnd, SW_SHOW);
    SetForegroundWindow(Mwnd);
}

/*
 * Built-in CSV analyzer: parses any "Timestamp,Ping (ms),..." log (ours or
 * pingpackettest's), groups consecutive losses into outages, and shows a
 * full-run timeline + summary + outage list using plain Win32 controls.
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include "res.h"

typedef struct { LONGLONG ms; int us; } Sample;      /* ms: file's local time; us < 0 = lost */
typedef struct { unsigned i0, i1; } Outage;           /* first / last lost sample */

static Sample *A;
static unsigned An;
static Outage *E;
static unsigned En;
static int Asel = -1, Asortcol = 0;
static LONGLONG Aiv;                                  /* average interval, ms */
static WCHAR Alast[MAX_PATH], Apath[MAX_PATH];
static HWND Adlg;

/* ---- formatting ---- */
static void f_ms(WCHAR *b, int us)                    /* 12.3 */
{
    int t;
    if (us < 0) { lstrcpyW(b, L"\x2013"); return; }
    t = (us + 50) / 100;
    wsprintfW(b, L"%d.%d", t / 10, t % 10);
}
static void f_dur(WCHAR *b, LONGLONG ms)              /* 4.9 s / 2m 05s / 1h 02m 03s */
{
    unsigned s = (unsigned)(ms / 1000);
    if (ms < 60000) wsprintfW(b, L"%u.%u s", s, (unsigned)(ms % 1000) / 100);
    else if (ms < 3600000) wsprintfW(b, L"%um %02us", s / 60, s % 60);
    else wsprintfW(b, L"%uh %02um %02us", s / 3600, s / 60 % 60, s % 60);
}
static void f_time(WCHAR *b, LONGLONG ms, int date)
{
    FILETIME ft; SYSTEMTIME st;
    ULONGLONG v = (ULONGLONG)ms * 10000;
    ft.dwLowDateTime = (DWORD)v; ft.dwHighDateTime = (DWORD)(v >> 32);
    FileTimeToSystemTime(&ft, &st);
    if (date) wsprintfW(b, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    else wsprintfW(b, L"%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

/* ---- parsing ---- */
static int num(const char **p, const char *e, int maxd, int *out)
{
    int v = 0, n = 0;
    while (*p < e && n < maxd && **p >= '0' && **p <= '9') { v = v * 10 + (**p - '0'); (*p)++; n++; }
    *out = v;
    return n;
}
static int parse_ts(const char *p, const char *e, LONGLONG *out)
{
    SYSTEMTIME st; FILETIME ft;
    int y, mo, d, h, mi, s, f = 0, nd;
    memset(&st, 0, sizeof st);
    if (num(&p, e, 4, &y) != 4 || p >= e || *p++ != '-') return 0;
    if (!num(&p, e, 2, &mo) || p >= e || *p++ != '-') return 0;
    if (!num(&p, e, 2, &d) || p >= e || (*p != ' ' && *p != 'T')) return 0;
    p++;
    if (!num(&p, e, 2, &h) || p >= e || *p++ != ':') return 0;
    if (!num(&p, e, 2, &mi) || p >= e || *p++ != ':') return 0;
    if (!num(&p, e, 2, &s)) return 0;
    if (p < e && *p == '.') {
        p++;
        nd = num(&p, e, 3, &f);
        while (nd++ < 3) f *= 10;
    }
    st.wYear = (WORD)y; st.wMonth = (WORD)mo; st.wDay = (WORD)d;
    st.wHour = (WORD)h; st.wMinute = (WORD)mi; st.wSecond = (WORD)s; st.wMilliseconds = (WORD)f;
    if (!SystemTimeToFileTime(&st, &ft)) return 0;
    *out = (LONGLONG)((((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000);
    return 1;
}
static int parse_ping(const char *p, const char *e)  /* -> us, or -1 when not a plain number */
{
    int ip = 0, fr = 0, nd = 0, n;
    while (p < e && (*p == ' ' || *p == '"')) p++;
    while (e > p && (e[-1] == ' ' || e[-1] == '"')) e--;
    if (p >= e || *p == '-') return -1;
    n = num(&p, e, 7, &ip);
    if (!n) return -1;
    if (p < e && *p == '.') {
        p++;
        nd = num(&p, e, 3, &fr);
        if (!nd) return -1;
        while (p < e && *p >= '0' && *p <= '9') p++;
        while (nd++ < 3) fr *= 10;
    }
    if (p != e) return -1;
    return ip * 1000 + fr;
}
static int has(const char *p, const char *e, const char *w)   /* case-insensitive substring */
{
    int n = lstrlenA(w), i;
    for (; p + n <= e; p++) {
        for (i = 0; i < n; i++) {
            char c = p[i];
            if (c >= 'A' && c <= 'Z') c |= 0x20;
            if (c != w[i]) break;
        }
        if (i == n) return 1;
    }
    return 0;
}

static const WCHAR *load_csv(const WCHAR *path)
{
    HANDLE f, heap = GetProcessHeap();
    LARGE_INTEGER sz;
    DWORD rd;
    char *buf, *p, *end, *le;
    int tcol = -1, pcol = -1, col, k;
    unsigned cap;
    static const char *tw[] = { "timestamp", "time", "date" }, *pw[] = { "ping", "latency", "rtt" };

    An = En = 0; Asel = -1;
    f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return L"Cannot open the file.";
    GetFileSizeEx(f, &sz);
    if (sz.QuadPart > 512LL * 1024 * 1024) { CloseHandle(f); return L"The file is too large (over 512 MB)."; }
    buf = HeapAlloc(heap, 0, (SIZE_T)sz.QuadPart + 1);
    if (!buf) { CloseHandle(f); return L"Not enough memory."; }
    ReadFile(f, buf, (DWORD)sz.QuadPart, &rd, NULL);
    CloseHandle(f);
    end = buf + rd;
    p = buf;
    if (rd >= 3 && (unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) p += 3;

    /* header */
    for (le = p; le < end && *le != '\n'; le++) ;
    for (k = 0; k < 3 && tcol < 0; k++) {
        char *a = p, *b; col = 0;
        for (;; col++) {
            for (b = a; b < le && *b != ','; b++) ;
            if (has(a, b, tw[k])) { tcol = col; break; }
            if (b >= le) break;
            a = b + 1;
        }
    }
    for (k = 0; k < 3 && pcol < 0; k++) {
        char *a = p, *b; col = 0;
        for (;; col++) {
            for (b = a; b < le && *b != ','; b++) ;
            if (has(a, b, pw[k])) { pcol = col; break; }
            if (b >= le) break;
            a = b + 1;
        }
    }
    if (tcol < 0 || pcol < 0) { HeapFree(heap, 0, buf); return L"No Timestamp / Ping columns in this file."; }

    cap = (unsigned)(rd / 24) + 16;
    if (A) HeapFree(heap, 0, A);
    A = HeapAlloc(heap, 0, (SIZE_T)cap * sizeof *A);
    if (!A) { HeapFree(heap, 0, buf); return L"Not enough memory."; }

    for (p = le + 1; p < end; p = le + 1) {
        char *ts0 = NULL, *ts1 = NULL, *pg0 = NULL, *pg1 = NULL, *a = p, *b;
        for (le = p; le < end && *le != '\n'; le++) ;
        for (col = 0; ; col++) {
            for (b = a; b < le && *b != ','; b++) ;
            if (col == tcol) { ts0 = a; ts1 = b; }
            if (col == pcol) { pg0 = a; pg1 = b; }
            if (b >= le) break;
            a = b + 1;
        }
        if (ts1 && ts1 > ts0 && ts1[-1] == '\r') ts1--;
        if (pg1 && pg1 > pg0 && pg1[-1] == '\r') pg1--;
        if (!ts0 || An >= cap) continue;
        while (ts0 < ts1 && (*ts0 == ' ' || *ts0 == '"')) ts0++;
        if (!parse_ts(ts0, ts1, &A[An].ms)) continue;
        A[An].us = pg0 ? parse_ping(pg0, pg1) : -1;
        An++;
    }
    HeapFree(heap, 0, buf);
    if (!An) return L"No rows with a readable timestamp.";

    /* outages */
    {
        unsigned i, n = 0;
        for (i = 0; i < An; i++) if (A[i].us < 0 && (i == 0 || A[i - 1].us >= 0)) n++;
        if (E) HeapFree(heap, 0, E);
        E = HeapAlloc(heap, 0, (SIZE_T)(n + 1) * sizeof *E);
        for (i = 0; i < An; i++) {
            if (A[i].us >= 0) continue;
            E[En].i0 = i;
            while (i + 1 < An && A[i + 1].us < 0) i++;
            E[En++].i1 = i;
        }
    }
    Aiv = An > 1 ? (A[An - 1].ms - A[0].ms) / (An - 1) : 100;
    if (Aiv <= 0) Aiv = 1;
    return NULL;
}

static LONGLONG out_ms(const Outage *o) { return A[o->i1].ms - A[o->i0].ms + Aiv; }

/* ---- list views ---- */
static void lv_col(HWND lv, int i, const WCHAR *t, int w, int right)
{
    LVCOLUMNW c;
    memset(&c, 0, sizeof c);
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    c.fmt = right ? LVCFMT_RIGHT : LVCFMT_LEFT;
    c.pszText = (WCHAR *)t; c.cx = w;
    SendMessageW(lv, LVM_INSERTCOLUMNW, i, (LPARAM)&c);
}
static void lv_set(HWND lv, int row, int col, const WCHAR *t, LPARAM lp)
{
    LVITEMW it;
    memset(&it, 0, sizeof it);
    it.iItem = row; it.iSubItem = col; it.pszText = (WCHAR *)t;
    if (col == 0) { it.mask = LVIF_TEXT | LVIF_PARAM; it.lParam = lp; SendMessageW(lv, LVM_INSERTITEMW, 0, (LPARAM)&it); }
    else { it.mask = LVIF_TEXT; SendMessageW(lv, LVM_SETITEMTEXTW, row, (LPARAM)&it); }
}

static int CALLBACK ev_cmp(LPARAM a, LPARAM b, LPARAM col)
{
    const Outage *x = &E[a], *y = &E[b];
    LONGLONG d;
    if (col == 0) return x->i0 < y->i0 ? -1 : 1;
    d = out_ms(y) - out_ms(x);                        /* longest first */
    if (d) return d > 0 ? 1 : -1;
    return x->i0 < y->i0 ? -1 : 1;
}

static void fill_lists(void)
{
    HWND sl = GetDlgItem(Adlg, IDC_A_SUM), el = GetDlgItem(Adlg, IDC_A_EV);
    HANDLE heap = GetProcessHeap();
    WCHAR a[64], b[96], c[32];
    unsigned i, ok = 0, lost = 0, major = 0, slow = 0, jn = 0, *hist;
    LONGLONG sum = 0, jsum = 0, longest = 0, lostms = 0;
    int mn = -1, mx = -1, prev = -1, row = 0, p50 = -1, p95 = -1, p99 = -1;
    const WCHAR *name;

    SendMessageW(sl, LVM_DELETEALLITEMS, 0, 0);
    SendMessageW(el, LVM_DELETEALLITEMS, 0, 0);
    if (!An) return;

    hist = HeapAlloc(heap, HEAP_ZERO_MEMORY, 100001 * sizeof *hist);    /* 0.1 ms bins up to 10 s */
    for (i = 0; i < An; i++) {
        int us = A[i].us;
        if (us < 0) { lost++; continue; }
        ok++; sum += us;
        if (mn < 0 || us < mn) mn = us;
        if (us > mx) mx = us;
        if (us > 100000) slow++;
        if (prev >= 0) { jsum += us > prev ? us - prev : prev - us; jn++; }
        prev = us;
        if (hist) hist[us / 100 > 100000 ? 100000 : us / 100]++;
    }
    if (hist && ok) {
        unsigned acc = 0, k;
        for (k = 0; k <= 100000; k++) {
            acc += hist[k];
            if (p50 < 0 && acc * 100ULL >= ok * 50ULL) p50 = k * 100;
            if (p95 < 0 && acc * 100ULL >= ok * 95ULL) p95 = k * 100;
            if (p99 < 0 && acc * 100ULL >= ok * 99ULL) { p99 = k * 100; break; }
        }
    }
    if (hist) HeapFree(heap, 0, hist);
    for (i = 0; i < En; i++) {
        LONGLONG d = out_ms(&E[i]);
        lostms += d;
        if (d > longest) longest = d;
        if (d >= 1000) major++;
    }

#define ROW(label, val) do { lv_set(sl, row, 0, label, 0); lv_set(sl, row, 1, val, 0); row++; } while (0)
    for (name = Apath + lstrlenW(Apath); name > Apath && name[-1] != L'\\'; name--) ;
    ROW(L"File", name);
    f_time(b, A[0].ms, 1); ROW(L"Start", b);
    f_dur(b, A[An - 1].ms - A[0].ms + Aiv); ROW(L"Duration", b);
    wsprintfW(b, L"%u  (%u.%u Hz)", An, (unsigned)(10000 / Aiv) / 10, (unsigned)(10000 / Aiv) % 10); ROW(L"Probes", b);
    { unsigned pct = (unsigned)(lost * 10000ULL / An); wsprintfW(b, L"%u  (%u.%02u%%)", lost, pct / 100, pct % 100); }
    ROW(L"Lost", b);
    wsprintfW(b, L"%u", En); ROW(L"Drop events", b);
    wsprintfW(b, L"%u", major); ROW(L"Outages \x2265 1 s", b);
    f_dur(b, longest); ROW(L"Longest outage", En ? b : L"\x2013");
    f_dur(b, lostms); ROW(L"Total time lost", b);
    f_ms(a, ok ? (int)(sum / ok) : -1); wsprintfW(b, L"%s ms", a); ROW(L"Ping avg", b);
    f_ms(a, mn); f_ms(c, ok ? mx : -1); wsprintfW(b, L"%s / %s ms", a, c); ROW(L"Ping min / max", b);
    { WCHAR x[16], y[16], z[16]; f_ms(x, p50); f_ms(y, p95); f_ms(z, p99); wsprintfW(b, L"%s / %s / %s ms", x, y, z); }
    ROW(L"p50 / p95 / p99", b);
    f_ms(a, jn ? (int)(jsum / jn) : -1); wsprintfW(b, L"%s ms", a); ROW(L"Jitter avg", b);
    wsprintfW(b, L"%u", slow); ROW(L"Pings > 100 ms", b);
#undef ROW

    SendMessageW(el, WM_SETREDRAW, FALSE, 0);
    for (i = 0; i < En; i++) {
        f_time(b, A[E[i].i0].ms, 0); lv_set(el, (int)i, 0, b, (LPARAM)i);
        f_time(b, A[E[i].i1].ms + Aiv, 0); lv_set(el, (int)i, 1, b, 0);
        f_dur(b, out_ms(&E[i])); lv_set(el, (int)i, 2, b, 0);
        wsprintfW(b, L"%u", E[i].i1 - E[i].i0 + 1); lv_set(el, (int)i, 3, b, 0);
    }
    SendMessageW(el, LVM_SORTITEMS, (WPARAM)Asortcol, (LPARAM)ev_cmp);
    SendMessageW(el, WM_SETREDRAW, TRUE, 0);
}

/* ---- timeline ---- */
static void draw_timeline(DRAWITEMSTRUCT *di)
{
    RECT rc = di->rcItem, r;
    int w = rc.right - rc.left, h = rc.bottom - rc.top, x;
    int top = 4, bot = h - 18, ph = bot - top;
    HDC dc = CreateCompatibleDC(di->hDC);
    HBITMAP bm = CreateCompatibleBitmap(di->hDC, w, h), obm = SelectObject(dc, bm);
    HBRUSH bg = CreateSolidBrush(RGB(250, 251, 253)), sel = CreateSolidBrush(RGB(255, 236, 160));
    HBRUSH fill = CreateSolidBrush(RGB(205, 223, 247)), red = CreateSolidBrush(RGB(220, 50, 50));
    HPEN grid = CreatePen(PS_SOLID, 1, RGB(225, 228, 235)), line = CreatePen(PS_SOLID, 1, RGB(30, 111, 217)), op;
    WCHAR lbl[48];
    int scale = 10000, i;

    r.left = 0; r.top = 0; r.right = w; r.bottom = h;
    FillRect(dc, &r, bg);
    SetBkMode(dc, TRANSPARENT);
    SelectObject(dc, (HFONT)SendMessageW(Adlg, WM_GETFONT, 0, 0));
    SetTextColor(dc, RGB(120, 128, 140));

    if (An >= 1) {
        LONGLONG t0 = A[0].ms, span = A[An - 1].ms - t0 + Aiv;
        static unsigned cnt[4096];
        static int mxp[4096];
        static unsigned char loss[4096];
        unsigned idx;
        int prevy = -1;
        if (w > 4096) w = 4096;
        if (span <= 0) span = 1;

        /* y scale from p99-ish: max of per-column medians would be costly; use max, clipped to 3x avg */
        {
            LONGLONG s = 0; unsigned n = 0; int mx = 0;
            for (i = 0; i < (int)An; i++) if (A[i].us >= 0) { s += A[i].us; n++; if (A[i].us > mx) mx = A[i].us; }
            if (n) { int cap = (int)(s / n) * 4; if (mx > cap && cap > 0) mx = cap; }
            while (scale < mx * 9 / 8) scale = scale < 50000 ? scale * 2 : scale < 200000 ? scale + 50000 : scale * 2;
            if (scale == 40000) scale = 50000;
        }

        for (x = 0; x < w; x++) { cnt[x] = 0; mxp[x] = -1; loss[x] = 0; }
        for (idx = 0; idx < An; idx++) {
            x = (int)((A[idx].ms - t0) * w / span);
            if (x >= w) x = w - 1;
            cnt[x]++;
            if (A[idx].us < 0) loss[x] = 1; else if (A[idx].us > mxp[x]) mxp[x] = A[idx].us;
        }

        if (Asel >= 0 && Asel < (int)En) {
            r.left = (int)((A[E[Asel].i0].ms - t0) * w / span) - 3;
            r.right = (int)((A[E[Asel].i1].ms + Aiv - t0) * w / span) + 4;
            r.top = 0; r.bottom = bot;
            FillRect(dc, &r, sel);
        }
        op = SelectObject(dc, grid);
        for (i = 1; i < 4; i++) { MoveToEx(dc, 0, top + ph * i / 4, NULL); LineTo(dc, w, top + ph * i / 4); }
        MoveToEx(dc, 0, bot, NULL); LineTo(dc, w, bot);

        for (x = 0; x < w; x++) {
            if (mxp[x] >= 0) {
                int y = bot - (int)((LONGLONG)mxp[x] * ph / scale);
                if (y < top) y = top;
                r.left = x; r.right = x + 1; r.top = y; r.bottom = bot;
                FillRect(dc, &r, fill);
                SelectObject(dc, line);
                if (prevy >= 0) { MoveToEx(dc, x - 1, prevy, NULL); LineTo(dc, x, y); }
                SetPixel(dc, x, y, RGB(30, 111, 217));
                prevy = y;
            } else if (cnt[x] || loss[x]) prevy = -1;
        }
        for (x = 0; x < w; x++)                         /* losses on top of everything */
            if (loss[x]) { r.left = x; r.right = x + 1; r.top = top; r.bottom = bot; FillRect(dc, &r, red); }
        SelectObject(dc, op);

        wsprintfW(lbl, L"%d ms", scale / 1000);
        TextOutW(dc, 4, top, lbl, lstrlenW(lbl));
        f_time(lbl, t0, 0); lbl[8] = 0;
        TextOutW(dc, 2, bot + 2, lbl, 8);
        SetTextAlign(dc, TA_CENTER);
        f_time(lbl, t0 + span / 2, 0); lbl[8] = 0;
        TextOutW(dc, w / 2, bot + 2, lbl, 8);
        SetTextAlign(dc, TA_RIGHT);
        f_time(lbl, t0 + span, 0); lbl[8] = 0;
        TextOutW(dc, w - 2, bot + 2, lbl, 8);
    } else {
        SetTextAlign(dc, TA_CENTER);
        TextOutW(dc, w / 2, h / 2 - 8, L"No data loaded", 14);
    }

    BitBlt(di->hDC, rc.left, rc.top, rc.right - rc.left, h, dc, 0, 0, SRCCOPY);
    SelectObject(dc, obm);
    DeleteObject(bm); DeleteObject(bg); DeleteObject(sel); DeleteObject(fill); DeleteObject(red);
    DeleteObject(grid); DeleteObject(line);
    DeleteDC(dc);
}

/* ---- actions ---- */
static void do_load(const WCHAR *path)
{
    const WCHAR *err;
    WCHAR b[MAX_PATH + 64];
    lstrcpynW(Apath, path, MAX_PATH);
    SetDlgItemTextW(Adlg, IDC_A_PATH, Apath);
    SetCursor(LoadCursorW(NULL, IDC_WAIT));
    err = load_csv(Apath);
    fill_lists();
    InvalidateRect(GetDlgItem(Adlg, IDC_A_GRAPH), NULL, FALSE);
    if (err) { wsprintfW(b, L"%s\n\n%s", err, Apath); MessageBoxW(Adlg, b, L"Analyzer", MB_ICONWARNING); }
}

static void find_latest(void)                          /* newest *ping_*.csv on the Desktop */
{
    WCHAR dir[MAX_PATH], pat[MAX_PATH];
    WIN32_FIND_DATAW fd;
    FILETIME best = { 0, 0 };
    HANDLE h;
    if (Alast[0]) return;
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, dir) != S_OK) return;
    wsprintfW(pat, L"%s\\*ping_*.csv", dir);
    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (CompareFileTime(&fd.ftLastWriteTime, &best) > 0) {
            best = fd.ftLastWriteTime;
            wsprintfW(Alast, L"%s\\%s", dir, fd.cFileName);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void copy_report(void)
{
    HWND sl = GetDlgItem(Adlg, IDC_A_SUM), el = GetDlgItem(Adlg, IDC_A_EV);
    int rows, i, j, n = 0, cap = 64 * 1024;
    HGLOBAL g;
    WCHAR *t, cell[128];
    LVITEMW it;
    if (!An) return;
    g = GlobalAlloc(GMEM_MOVEABLE, cap * sizeof(WCHAR));
    t = GlobalLock(g);
#define PUT(s) do { const WCHAR *q_ = (s); while (*q_ && n < cap - 2) t[n++] = *q_++; } while (0)
    memset(&it, 0, sizeof it);
    it.pszText = cell; it.cchTextMax = 128;
    rows = (int)SendMessageW(sl, LVM_GETITEMCOUNT, 0, 0);
    for (i = 0; i < rows; i++) {
        it.iSubItem = 0; SendMessageW(sl, LVM_GETITEMTEXTW, i, (LPARAM)&it); PUT(cell); PUT(L": ");
        it.iSubItem = 1; SendMessageW(sl, LVM_GETITEMTEXTW, i, (LPARAM)&it); PUT(cell); PUT(L"\r\n");
    }
    rows = (int)SendMessageW(el, LVM_GETITEMCOUNT, 0, 0);
    if (rows) PUT(L"\r\nStart\tEnd\tDuration\tLost\r\n");
    for (i = 0; i < rows; i++) {
        for (j = 0; j < 4; j++) {
            it.iSubItem = j; SendMessageW(el, LVM_GETITEMTEXTW, i, (LPARAM)&it); PUT(cell); PUT(j < 3 ? L"\t" : L"\r\n");
        }
    }
#undef PUT
    t[n] = 0;
    GlobalUnlock(g);
    if (OpenClipboard(Adlg)) { EmptyClipboard(); SetClipboardData(CF_UNICODETEXT, g); CloseClipboard(); }
    else GlobalFree(g);
}

static INT_PTR CALLBACK AnalyzeProc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    switch (m) {
    case WM_INITDIALOG: {
        HWND sl = GetDlgItem(h, IDC_A_SUM), el = GetDlgItem(h, IDC_A_EV);
        RECT r;
        int w;
        DWORD ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES;
        Adlg = h;
        SendMessageW(h, WM_SETICON, ICON_BIG, (LPARAM)LoadIconW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDI_APP)));
        SendMessageW(sl, LVM_SETEXTENDEDLISTVIEWSTYLE, ex, ex);
        SendMessageW(el, LVM_SETEXTENDEDLISTVIEWSTYLE, ex, ex);
        GetClientRect(sl, &r); w = r.right - GetSystemMetrics(SM_CXVSCROLL);
        lv_col(sl, 0, L"Metric", w * 45 / 100, 0);
        lv_col(sl, 1, L"Value", w - w * 45 / 100, 0);
        GetClientRect(el, &r); w = r.right - GetSystemMetrics(SM_CXVSCROLL);
        lv_col(el, 0, L"Start", w * 30 / 100, 0);
        lv_col(el, 1, L"End", w * 30 / 100, 0);
        lv_col(el, 2, L"Duration", w * 22 / 100, 1);
        lv_col(el, 3, L"Lost", w - w * 82 / 100, 1);
        find_latest();
        if (Alast[0]) { CheckRadioButton(h, IDC_A_LAST, IDC_A_FILE, IDC_A_LAST); do_load(Alast); }
        else { EnableWindow(GetDlgItem(h, IDC_A_LAST), FALSE); CheckRadioButton(h, IDC_A_LAST, IDC_A_FILE, IDC_A_FILE); }
        return TRUE;
    }
    case WM_DRAWITEM:
        if (wp == IDC_A_GRAPH) { draw_timeline((DRAWITEMSTRUCT *)lp); return TRUE; }
        break;
    case WM_NOTIFY: {
        NMHDR *nh = (NMHDR *)lp;
        if (nh->idFrom == IDC_A_EV && nh->code == LVN_ITEMCHANGED) {
            NMLISTVIEW *nl = (NMLISTVIEW *)lp;
            if ((nl->uNewState ^ nl->uOldState) & LVIS_SELECTED) {
                Asel = (nl->uNewState & LVIS_SELECTED) ? (int)nl->lParam : -1;
                InvalidateRect(GetDlgItem(h, IDC_A_GRAPH), NULL, FALSE);
            }
        } else if (nh->idFrom == IDC_A_EV && nh->code == LVN_COLUMNCLICK) {
            Asortcol = ((NMLISTVIEW *)lp)->iSubItem;
            SendMessageW(nh->hwndFrom, LVM_SORTITEMS, (WPARAM)Asortcol, (LPARAM)ev_cmp);
        }
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_A_LAST:
            if (Alast[0]) do_load(Alast);
            return TRUE;
        case IDC_A_FILE:
        case IDC_A_BROWSE: {
            OPENFILENAMEW of;
            WCHAR fn[MAX_PATH];
            if (LOWORD(wp) == IDC_A_FILE && HIWORD(wp) != BN_CLICKED) return TRUE;
            lstrcpyW(fn, L"");
            memset(&of, 0, sizeof of);
            of.lStructSize = sizeof of; of.hwndOwner = h;
            of.lpstrFilter = L"CSV files (*.csv)\0*.csv\0All files\0*.*\0";
            of.lpstrFile = fn; of.nMaxFile = MAX_PATH;
            of.Flags = OFN_FILEMUSTEXIST | OFN_EXPLORER;
            if (GetOpenFileNameW(&of)) {
                CheckRadioButton(h, IDC_A_LAST, IDC_A_FILE, IDC_A_FILE);
                do_load(fn);
            } else if (Apath[0] && !lstrcmpW(Apath, Alast)) {
                CheckRadioButton(h, IDC_A_LAST, IDC_A_FILE, IDC_A_LAST);
            }
            return TRUE;
        }
        case IDC_A_COPY:
            copy_report();
            return TRUE;
        case IDC_A_WEB: {
            WCHAR args[MAX_PATH + 16];
            if (Apath[0]) {
                wsprintfW(args, L"/select,\"%s\"", Apath);
                ShellExecuteW(h, NULL, L"explorer.exe", args, NULL, SW_SHOWNORMAL);
            }
            ShellExecuteW(h, L"open", L"https://zxc.sx/ping-analyzer", NULL, NULL, SW_SHOWNORMAL);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(h, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

void analyze_open(HWND parent, const WCHAR *last)
{
    if (last && last[0]) lstrcpynW(Alast, last, MAX_PATH);
    Apath[0] = 0;
    DialogBoxParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_ANALYZE), parent, AnalyzeProc, 0);
}

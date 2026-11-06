/*
 * Network monitor: system/network snapshot (system.txt), per-second Wi-Fi and
 * interface counters (wifi.csv, iface.csv), change events (events.log), plus
 * session helpers (buffered files, timestamps) and the zip packer.
 */
#include "common.h"
#include <iphlpapi.h>
#include <netioapi.h>
#include <wlanapi.h>
#include <shlobj.h>
#include "res.h"

WCHAR g_sessdir[MAX_PATH];
OutFile g_events;

/* ---------- small helpers ---------- */
unsigned isqrt64(unsigned long long v)
{
    unsigned long long x = v, y = (x + 1) / 2;
    if (v < 2) return (unsigned)v;
    while (y < x) { x = y; y = (x + v / x) / 2; }
    return (unsigned)x;
}

void ts_ft(char *b, const FILETIME *ft)
{
    FILETIME l; SYSTEMTIME st;
    FileTimeToLocalFileTime(ft, &l);
    FileTimeToSystemTime(&l, &st);
    wsprintfA(b, "%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}
void ts_now(char *b) { FILETIME ft; GetSystemTimePreciseAsFileTime(&ft); ts_ft(b, &ft); }

int of_open(OutFile *f, const WCHAR *name, const char *header)
{
    WCHAR p[MAX_PATH];
    wsprintfW(p, L"%s\\%s", g_sessdir, name);
    InitializeCriticalSection(&f->cs);
    f->n = 0;
    f->h = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f->h == INVALID_HANDLE_VALUE) return 0;
    if (header) of_put(f, header, lstrlenA(header));
    return 1;
}
static void of_flush_nolock(OutFile *f)
{
    DWORD w;
    if (f->n && f->h != INVALID_HANDLE_VALUE) WriteFile(f->h, f->buf, f->n, &w, NULL);
    f->n = 0;
}
void of_put(OutFile *f, const char *s, int n)
{
    if (!f->h || f->h == INVALID_HANDLE_VALUE) return;
    EnterCriticalSection(&f->cs);
    while (n > 0) {
        int k = (int)sizeof f->buf - (int)f->n;
        if (k > n) k = n;
        memcpy(f->buf + f->n, s, k); f->n += k; s += k; n -= k;
        if (f->n == sizeof f->buf) of_flush_nolock(f);
    }
    LeaveCriticalSection(&f->cs);
}
void of_printf(OutFile *f, const char *fmt, ...)
{
    char b[1100];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = wvsprintfA(b, fmt, ap);
    va_end(ap);
    of_put(f, b, n);
}
void of_flush(OutFile *f)
{
    if (!f->h || f->h == INVALID_HANDLE_VALUE) return;
    EnterCriticalSection(&f->cs); of_flush_nolock(f); LeaveCriticalSection(&f->cs);
}
void of_close(OutFile *f)
{
    if (!f->h || f->h == INVALID_HANDLE_VALUE) return;
    of_flush(f);
    CloseHandle(f->h);
    f->h = INVALID_HANDLE_VALUE;
    DeleteCriticalSection(&f->cs);
}

void ev_log(const char *cat, const char *fmt, ...)
{
    char b[1100], t[32];
    va_list ap;
    int n;
    ts_now(t);
    n = wsprintfA(b, "%s  %-6s ", t, cat);
    va_start(ap, fmt);
    n += wvsprintfA(b + n, fmt, ap);
    va_end(ap);
    b[n++] = '\r'; b[n++] = '\n';
    of_put(&g_events, b, n);
}

int addr_str(const void *sa, char *b, int cap)
{
    const struct sockaddr *s = sa;
    DWORD n = (DWORD)cap;
    int len = s->sa_family == AF_INET6 ? (int)sizeof(struct sockaddr_in6) : (int)sizeof(struct sockaddr_in);
    b[0] = 0;
    if (s->sa_family != AF_INET && s->sa_family != AF_INET6) return 0;
    if (s->sa_family == AF_INET6) {               /* drop scope id / port */
        struct sockaddr_in6 c = *(const struct sockaddr_in6 *)sa;
        c.sin6_port = 0; c.sin6_scope_id = 0;
        if (WSAAddressToStringA((struct sockaddr *)&c, len, NULL, b, &n)) b[0] = 0;
    } else {
        struct sockaddr_in c = *(const struct sockaddr_in *)sa;
        c.sin_port = 0;
        if (WSAAddressToStringA((struct sockaddr *)&c, len, NULL, b, &n)) b[0] = 0;
    }
    return lstrlenA(b);
}

int is_private(const char *ip)
{
    int a = 0, b = 0, i = 0;
    if (ip[0] == 'f' || ip[0] == 'F') return 1;            /* fe80::/fd00:: */
    while (ip[i] >= '0' && ip[i] <= '9') a = a * 10 + ip[i++] - '0';
    if (ip[i] != '.') return 0;
    i++;
    while (ip[i] >= '0' && ip[i] <= '9') b = b * 10 + ip[i++] - '0';
    return a == 10 || a == 127 || (a == 172 && b >= 16 && b < 32) || (a == 192 && b == 168) ||
           (a == 100 && b >= 64 && b < 128) || (a == 169 && b == 254);
}

static void mac_str(char *b, const BYTE *m, unsigned n)
{
    unsigned i;
    b[0] = 0;
    for (i = 0; i < n && i < 8; i++) wsprintfA(b + (i ? i * 3 - 1 : 0), i ? "-%02X" : "%02X", m[i]);
}
static void bssid_str(char *b, const BYTE *m)
{
    wsprintfA(b, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}
static void w2a(char *d, const WCHAR *s, int cap) { WideCharToMultiByte(CP_UTF8, 0, s, -1, d, cap, NULL, NULL); }

/* ---------- Wi-Fi (wlanapi loaded dynamically: absent on some systems) ---------- */
typedef DWORD (WINAPI *pWlanOpenHandle)(DWORD, PVOID, PDWORD, PHANDLE);
typedef DWORD (WINAPI *pWlanCloseHandle)(HANDLE, PVOID);
typedef DWORD (WINAPI *pWlanEnumInterfaces)(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST *);
typedef DWORD (WINAPI *pWlanQueryInterface)(HANDLE, const GUID *, WLAN_INTF_OPCODE, PVOID, PDWORD, PVOID *, PWLAN_OPCODE_VALUE_TYPE);
typedef DWORD (WINAPI *pWlanGetNetworkBssList)(HANDLE, const GUID *, const PDOT11_SSID, DOT11_BSS_TYPE, BOOL, PVOID, PWLAN_BSS_LIST *);
typedef VOID (WINAPI *pWlanFreeMemory)(PVOID);
static pWlanOpenHandle wOpen;
static pWlanCloseHandle wClose;
static pWlanEnumInterfaces wEnum;
static pWlanQueryInterface wQuery;
static pWlanGetNetworkBssList wBss;
static pWlanFreeMemory wFree;
static HANDLE g_wlan;

static int wlan_init(void)
{
    HMODULE m;
    DWORD ver;
    if (g_wlan) return 1;
    m = LoadLibraryW(L"wlanapi.dll");
    if (!m) return 0;
    wOpen = (pWlanOpenHandle)GetProcAddress(m, "WlanOpenHandle");
    wClose = (pWlanCloseHandle)GetProcAddress(m, "WlanCloseHandle");
    wEnum = (pWlanEnumInterfaces)GetProcAddress(m, "WlanEnumInterfaces");
    wQuery = (pWlanQueryInterface)GetProcAddress(m, "WlanQueryInterface");
    wBss = (pWlanGetNetworkBssList)GetProcAddress(m, "WlanGetNetworkBssList");
    wFree = (pWlanFreeMemory)GetProcAddress(m, "WlanFreeMemory");
    if (!wOpen || !wClose || !wEnum || !wQuery || !wFree) return 0;
    if (wOpen(2, NULL, &ver, &g_wlan) != ERROR_SUCCESS) { g_wlan = NULL; return 0; }
    return 1;
}

typedef struct {
    int connected;
    char ssid[40], bssid[20];
    int quality, rssi, channel;
    unsigned rx_mbps, tx_mbps, phy;
    char iface[128];
    unsigned auth, cipher;
} WifiState;

static int wifi_read(WifiState *w)       /* first connected interface; 0 if no Wi-Fi at all */
{
    PWLAN_INTERFACE_INFO_LIST il = NULL;
    unsigned i;
    int found = 0;
    memset(w, 0, sizeof *w);
    if (!wlan_init() || wEnum(g_wlan, NULL, &il) != ERROR_SUCCESS) return 0;
    for (i = 0; i < il->dwNumberOfItems; i++) {
        WLAN_INTERFACE_INFO *ii = &il->InterfaceInfo[i];
        PWLAN_CONNECTION_ATTRIBUTES ca = NULL;
        DWORD sz;
        PVOID v = NULL;
        if (!found) { w2a(w->iface, ii->strInterfaceDescription, sizeof w->iface); found = 1; }
        if (ii->isState != wlan_interface_state_connected) continue;
        if (wQuery(g_wlan, &ii->InterfaceGuid, wlan_intf_opcode_current_connection, NULL, &sz, (PVOID *)&ca, NULL) == ERROR_SUCCESS) {
            DOT11_SSID *s = &ca->wlanAssociationAttributes.dot11Ssid;
            unsigned k = s->uSSIDLength < 32 ? s->uSSIDLength : 32;
            memcpy(w->ssid, s->ucSSID, k); w->ssid[k] = 0;
            for (k = 0; w->ssid[k]; k++) if (w->ssid[k] == ',' || w->ssid[k] < ' ') w->ssid[k] = '_';
            bssid_str(w->bssid, ca->wlanAssociationAttributes.dot11Bssid);
            w->quality = (int)ca->wlanAssociationAttributes.wlanSignalQuality;
            w->rx_mbps = ca->wlanAssociationAttributes.ulRxRate / 1000;
            w->tx_mbps = ca->wlanAssociationAttributes.ulTxRate / 1000;
            w->phy = ca->wlanAssociationAttributes.dot11PhyType;
            w->auth = ca->wlanSecurityAttributes.dot11AuthAlgorithm;
            w->cipher = ca->wlanSecurityAttributes.dot11CipherAlgorithm;
            w2a(w->iface, ii->strInterfaceDescription, sizeof w->iface);
            w->connected = 1;
            wFree(ca);
        }
        w->rssi = 0;
        if (wQuery(g_wlan, &ii->InterfaceGuid, wlan_intf_opcode_rssi, NULL, &sz, &v, NULL) == ERROR_SUCCESS) { w->rssi = *(LONG *)v; wFree(v); }
        else w->rssi = w->quality / 2 - 100;                /* Windows' own mapping */
        if (wQuery(g_wlan, &ii->InterfaceGuid, wlan_intf_opcode_channel_number, NULL, &sz, &v, NULL) == ERROR_SUCCESS) { w->channel = (int)*(ULONG *)v; wFree(v); }
        break;
    }
    wFree(il);
    return found;
}

static const char *phy_name(unsigned p)
{
    switch (p) {
    case 4: return "802.11a"; case 5: return "802.11b"; case 6: return "802.11g";
    case 7: return "802.11n (Wi-Fi 4)"; case 8: return "802.11ac (Wi-Fi 5)";
    case 10: return "802.11ax (Wi-Fi 6/6E)"; case 11: return "802.11be (Wi-Fi 7)";
    }
    return "other";
}
static int freq_ch(unsigned khz)
{
    if (khz >= 2412000 && khz <= 2484000) return khz == 2484000 ? 14 : (int)(khz - 2407000) / 5000;
    if (khz >= 5950000) return (int)(khz - 5950000) / 5000;
    if (khz >= 5000000) return (int)(khz - 5000000) / 5000;
    return 0;
}
static const char *band(unsigned khz) { return khz < 3000000 ? "2.4" : khz < 5925000 ? "5" : "6"; }

/* ---------- adapters ---------- */
static IP_ADAPTER_ADDRESSES *get_adapters(void)
{
    ULONG sz = 32768;
    IP_ADAPTER_ADDRESSES *a;
    int tries;
    for (tries = 0; tries < 3; tries++) {
        a = HeapAlloc(GetProcessHeap(), 0, sz);
        if (!a) return NULL;
        if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                 NULL, a, &sz) == ERROR_SUCCESS) return a;
        HeapFree(GetProcessHeap(), 0, a);
    }
    return NULL;
}
static const char *if_type(DWORD t)
{
    switch (t) {
    case 6: return "Ethernet"; case 71: return "Wi-Fi"; case 24: return "Loopback";
    case 23: return "PPP"; case 131: return "Tunnel"; case 243: case 244: return "Mobile";
    }
    return "Other";
}

typedef struct {
    ULONG idx;
    int up;
    char name[96], ips[400], gws[200], dns[200];
} AdState;
#define MAXAD 24
static AdState g_ad[MAXAD], g_adn[MAXAD];
static int g_nad, g_nadn;

static void cat(char *d, int cap, const char *s)
{
    int n = lstrlenA(d), k = lstrlenA(s);
    if (n + k + 3 >= cap) return;
    if (n) { d[n++] = ','; d[n++] = ' '; }
    memcpy(d + n, s, k + 1);
}

static int collect_adapters(AdState *out, IP_ADAPTER_ADDRESSES *list)
{
    IP_ADAPTER_ADDRESSES *a;
    int n = 0;
    for (a = list; a && n < MAXAD; a = a->Next) {
        IP_ADAPTER_UNICAST_ADDRESS *u;
        IP_ADAPTER_GATEWAY_ADDRESS *g;
        IP_ADAPTER_DNS_SERVER_ADDRESS *d;
        AdState *s = &out[n];
        char ip[64], t[80];
        if (a->IfType == 24) continue;
        memset(s, 0, sizeof *s);
        s->idx = a->IfIndex ? a->IfIndex : a->Ipv6IfIndex;
        s->up = a->OperStatus == IfOperStatusUp;
        w2a(s->name, a->FriendlyName, sizeof s->name);
        for (u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family == AF_INET6 &&
                (u->SuffixOrigin == IpSuffixOriginRandom || ((struct sockaddr_in6 *)u->Address.lpSockaddr)->sin6_addr.s6_addr[0] == 0xfe))
                continue;                                    /* skip rotating temp + link-local v6 */
            addr_str(u->Address.lpSockaddr, ip, sizeof ip);
            wsprintfA(t, "%s/%u", ip, u->OnLinkPrefixLength);
            cat(s->ips, sizeof s->ips, t);
        }
        for (g = a->FirstGatewayAddress; g; g = g->Next) { addr_str(g->Address.lpSockaddr, ip, sizeof ip); cat(s->gws, sizeof s->gws, ip); }
        for (d = a->FirstDnsServerAddress; d; d = d->Next) { addr_str(d->Address.lpSockaddr, ip, sizeof ip); cat(s->dns, sizeof s->dns, ip); }
        n++;
    }
    return n;
}

/* ---------- system.txt snapshot ---------- */
static char g_desc[256];
static struct sockaddr_storage g_target;

typedef struct { char ip[64]; unsigned ms; int ok; } Lookup;
static DWORD WINAPI lookup_thread(LPVOID a)
{
    Lookup *lk = a;
    struct addrinfo hints, *ai = NULL;
    LARGE_INTEGER t0, t1, fq;
    memset(&hints, 0, sizeof hints); hints.ai_socktype = SOCK_STREAM;
    QueryPerformanceFrequency(&fq); QueryPerformanceCounter(&t0);
    if (getaddrinfo("www.google.com", NULL, &hints, &ai) == 0 && ai) {
        addr_str(ai->ai_addr, lk->ip, sizeof lk->ip);
        lk->ok = 1;
        freeaddrinfo(ai);
    }
    QueryPerformanceCounter(&t1);
    lk->ms = (unsigned)((t1.QuadPart - t0.QuadPart) * 1000 / fq.QuadPart);
    return 0;
}

static void snapshot(OutFile *f, const char *title)
{
    char b[512], t[32];
    IP_ADAPTER_ADDRESSES *list = get_adapters(), *a;
    TIME_ZONE_INFORMATION tz;
    SYSTEM_POWER_STATUS ps;
    WifiState w;
    LONGLONG up = (LONGLONG)GetTickCount64() / 1000;
    DWORD best = 0, n;
    WCHAR wn[128];
    char hn[128];

    ts_now(t);
    GetTimeZoneInformation(&tz);
    of_printf(f, "==================== %s  %s (UTC%c%02d:%02d) ====================\r\n", title, t,
              tz.Bias <= 0 ? '+' : '-', (tz.Bias < 0 ? -tz.Bias : tz.Bias) / 60, (tz.Bias < 0 ? -tz.Bias : tz.Bias) % 60);
    of_printf(f, "App:       DNS Ping %s\r\nTest:      %s\r\n", APP_VERSION, g_desc);
    {
        typedef LONG (WINAPI *pRtlGetVersion)(OSVERSIONINFOW *);
        OSVERSIONINFOW ov;
        pRtlGetVersion rg = (pRtlGetVersion)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
        memset(&ov, 0, sizeof ov); ov.dwOSVersionInfoSize = sizeof ov;
        if (rg) rg(&ov);
        n = 128; GetComputerNameExW(ComputerNameDnsHostname, wn, &n); w2a(hn, wn, sizeof hn);
        of_printf(f, "Computer:  %s   Windows %u.%u build %u   Uptime %ud %02u:%02u\r\n", hn,
                  ov.dwMajorVersion, ov.dwMinorVersion, ov.dwBuildNumber,
                  (unsigned)(up / 86400), (unsigned)(up / 3600 % 24), (unsigned)(up / 60 % 60));
    }
    if (GetSystemPowerStatus(&ps))
        of_printf(f, "Power:     %s%s, battery %d%%\r\n", ps.ACLineStatus == 1 ? "AC" : ps.ACLineStatus == 0 ? "battery" : "unknown",
                  ps.SystemStatusFlag ? " (battery saver ON)" : "", ps.BatteryLifePercent == 255 ? -1 : ps.BatteryLifePercent);
    if (GetBestInterfaceEx((struct sockaddr *)&g_target, &best) == NO_ERROR) {
        for (a = list; a; a = a->Next) if (a->IfIndex == best || a->Ipv6IfIndex == best) break;
        if (a) { w2a(b, a->FriendlyName, 200); of_printf(f, "Route to target via: %s (if %lu)\r\n", b, best); }
    }
    {   /* system resolver timing, in a helper thread so a dead DNS can't stall us (> 3 s = timeout) */
        Lookup *lk = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *lk);
        HANDLE th = lk ? CreateThread(NULL, 0, lookup_thread, lk, 0, NULL) : NULL;
        if (th && WaitForSingleObject(th, 3000) == WAIT_OBJECT_0) {
            if (lk->ok) of_printf(f, "System DNS lookup www.google.com: %u ms -> %s\r\n", lk->ms, lk->ip);
            else of_printf(f, "System DNS lookup www.google.com: FAILED (%u ms)\r\n", lk->ms);
            HeapFree(GetProcessHeap(), 0, lk);
        } else of_printf(f, "System DNS lookup www.google.com: no answer in 3 s\r\n");   /* lk leaks on purpose */
        if (th) CloseHandle(th);
    }

    of_printf(f, "\r\n--- Adapters ---\r\n");
    for (a = list; a; a = a->Next) {
        IP_ADAPTER_UNICAST_ADDRESS *u;
        IP_ADAPTER_GATEWAY_ADDRESS *g;
        IP_ADAPTER_DNS_SERVER_ADDRESS *d;
        char nm[128], ds[256], mac[32], ip[64];
        if (a->IfType == 24) continue;
        w2a(nm, a->FriendlyName, sizeof nm); w2a(ds, a->Description, sizeof ds);
        mac_str(mac, a->PhysicalAddress, a->PhysicalAddressLength);
        of_printf(f, "[%s] %s\r\n  Type: %s  Status: %s  If: %lu  MAC: %s  MTU: %lu  Link: %lu/%lu Mbps\r\n", nm, ds,
                  if_type(a->IfType), a->OperStatus == IfOperStatusUp ? "Up" : "Down", a->IfIndex, mac[0] ? mac : "-",
                  a->Mtu, (ULONG)(a->TransmitLinkSpeed / 1000000), (ULONG)(a->ReceiveLinkSpeed / 1000000));
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->Flags & IP_ADAPTER_DHCP_ENABLED) {
            addr_str(a->Dhcpv4Server.lpSockaddr ? a->Dhcpv4Server.lpSockaddr : (void *)"", ip, sizeof ip);
            of_printf(f, "  DHCP: on%s%s\r\n", ip[0] ? ", server " : "", ip);
        } else of_printf(f, "  DHCP: off (static)\r\n");
        for (u = a->FirstUnicastAddress; u; u = u->Next) {
            addr_str(u->Address.lpSockaddr, ip, sizeof ip);
            of_printf(f, "  IP: %s/%u%s\r\n", ip, u->OnLinkPrefixLength, u->SuffixOrigin == IpSuffixOriginRandom ? " (temporary)" : "");
        }
        for (g = a->FirstGatewayAddress; g; g = g->Next) { addr_str(g->Address.lpSockaddr, ip, sizeof ip); of_printf(f, "  Gateway: %s\r\n", ip); }
        for (d = a->FirstDnsServerAddress; d; d = d->Next) { addr_str(d->Address.lpSockaddr, ip, sizeof ip); of_printf(f, "  DNS: %s\r\n", ip); }
        if (a->DnsSuffix && a->DnsSuffix[0]) { w2a(ip, a->DnsSuffix, sizeof ip); of_printf(f, "  DNS suffix: %s\r\n", ip); }
    }

    of_printf(f, "\r\n--- Routes (IPv4 + IPv6) ---\r\n%-44s %-28s %5s %6s\r\n", "Destination", "Next hop", "If", "Metric");
    {
        PMIB_IPFORWARD_TABLE2 rt = NULL;
        ULONG i;
        if (GetIpForwardTable2(AF_UNSPEC, &rt) == NO_ERROR) {
            for (i = 0; i < rt->NumEntries; i++) {
                MIB_IPFORWARD_ROW2 *r = &rt->Table[i];
                char dst[80], nh[64];
                SOCKADDR_INET dp = r->DestinationPrefix.Prefix;
                addr_str(&dp, nh, sizeof nh);
                if (dp.si_family == AF_INET6 && (dp.Ipv6.sin6_addr.s6_addr[0] == 0xff ||
                    (dp.Ipv6.sin6_addr.s6_addr[0] == 0xfe && r->DestinationPrefix.PrefixLength >= 64))) continue;
                if (dp.si_family == AF_INET && (dp.Ipv4.sin_addr.s_net >= 224 || r->DestinationPrefix.PrefixLength == 32)) continue;
                wsprintfA(dst, "%s/%u", nh, r->DestinationPrefix.PrefixLength);
                addr_str(&r->NextHop, nh, sizeof nh);
                if (!lstrcmpA(nh, "0.0.0.0") || !lstrcmpA(nh, "::")) lstrcpyA(nh, "on-link");
                of_printf(f, "%-44s %-28s %5lu %6lu\r\n", dst, nh, r->InterfaceIndex, r->Metric);
            }
            FreeMibTable(rt);
        }
    }

    of_printf(f, "\r\n--- Wi-Fi ---\r\n");
    if (!wifi_read(&w)) of_printf(f, "No Wi-Fi adapter.\r\n");
    else if (!w.connected) of_printf(f, "%s: not connected\r\n", w.iface);
    else {
        of_printf(f, "Adapter: %s\r\nSSID: %s   BSSID: %s   %s   Channel %d\r\nSignal: %d%% (%d dBm)   Rate Rx/Tx: %u/%u Mbps   Auth %u / cipher %u\r\n",
                  w.iface, w.ssid, w.bssid, phy_name(w.phy), w.channel, w.quality, w.rssi, w.rx_mbps, w.tx_mbps, w.auth, w.cipher);
        if (wBss) {
            PWLAN_INTERFACE_INFO_LIST il = NULL;
            if (wEnum(g_wlan, NULL, &il) == ERROR_SUCCESS) {
                unsigned i, j;
                for (i = 0; i < il->dwNumberOfItems; i++) {
                    PWLAN_BSS_LIST bl = NULL;
                    if (il->InterfaceInfo[i].isState != wlan_interface_state_connected) continue;
                    if (wBss(g_wlan, &il->InterfaceInfo[i].InterfaceGuid, NULL, dot11_BSS_type_any, FALSE, NULL, &bl) != ERROR_SUCCESS) continue;
                    of_printf(f, "\r\nVisible access points (cached scan, %lu):\r\n%-32s %-17s %4s %4s %5s\r\n", bl->dwNumberOfItems,
                              "SSID", "BSSID", "GHz", "Ch", "dBm");
                    for (j = 0; j < bl->dwNumberOfItems; j++) {
                        WLAN_BSS_ENTRY *e = &bl->wlanBssEntries[j];
                        char ss[40], bs[20];
                        unsigned k = e->dot11Ssid.uSSIDLength < 32 ? e->dot11Ssid.uSSIDLength : 32;
                        memcpy(ss, e->dot11Ssid.ucSSID, k); ss[k] = 0;
                        if (!k) lstrcpyA(ss, "(hidden)");
                        bssid_str(bs, e->dot11Bssid);
                        of_printf(f, "%-32s %-17s %4s %4d %5ld%s\r\n", ss, bs, band(e->ulChCenterFrequency), freq_ch(e->ulChCenterFrequency),
                                  e->lRssi, !lstrcmpA(bs, w.bssid) ? "  <- connected" : "");
                    }
                    wFree(bl);
                    break;
                }
                wFree(il);
            }
        }
    }
    of_printf(f, "\r\n");
    if (list) HeapFree(GetProcessHeap(), 0, list);
}

/* ---------- monitor thread ---------- */
static DWORD WINAPI monitor(LPVOID arg)
{
    OutFile sys, wf, inf;
    WifiState w, pw;
    SYSTEM_POWER_STATUS ps;
    int have_wifi, prev_ac = -1, rssi_band = -1, i, j;
    DWORD best = 0, pbest = (DWORD)-1;
    ULONG64 pin = 0, pout = 0, pie = 0, pid = 0, poe = 0, pod = 0;
    LONGLONG pt = 0;
    char t[32];
    (void)arg;

    of_open(&sys, L"system.txt", NULL);
    snapshot(&sys, "START");
    of_flush(&sys);

    have_wifi = wifi_read(&pw);
    if (have_wifi) {
        of_open(&wf, L"wifi.csv", "Timestamp,SSID,BSSID,Signal (%),RSSI (dBm),Channel,Rx (Mbps),Tx (Mbps)\r\n");
        if (pw.connected) ev_log("WIFI", "connected to \"%s\" BSSID %s ch %d, %d dBm", pw.ssid, pw.bssid, pw.channel, pw.rssi);
        else ev_log("WIFI", "adapter present, not connected");
    }
    of_open(&inf, L"iface.csv", "Timestamp,Interface,Rx (kbit/s),Tx (kbit/s),In errors,In discards,Out errors,Out discards\r\n");
    {
        IP_ADAPTER_ADDRESSES *l = get_adapters();
        g_nad = collect_adapters(g_ad, l);
        if (l) HeapFree(GetProcessHeap(), 0, l);
        for (i = 0; i < g_nad; i++)
            if (g_ad[i].up) ev_log("LINK", "%s up: %s; gw %s; dns %s", g_ad[i].name, g_ad[i].ips, g_ad[i].gws[0] ? g_ad[i].gws : "-", g_ad[i].dns[0] ? g_ad[i].dns : "-");
    }

    do {
        LARGE_INTEGER now, fq;
        ts_now(t);
        QueryPerformanceCounter(&now); QueryPerformanceFrequency(&fq);

        /* Wi-Fi */
        if (have_wifi) {
            wifi_read(&w);
            if (w.connected) {
                int bnd = w.rssi >= -67 ? 0 : w.rssi >= -75 ? 1 : 2;
                of_printf(&wf, "%s,%s,%s,%d,%d,%d,%u,%u\r\n", t, w.ssid, w.bssid, w.quality, w.rssi, w.channel, w.rx_mbps, w.tx_mbps);
                if (!pw.connected) ev_log("WIFI", "connected to \"%s\" BSSID %s ch %d, %d dBm", w.ssid, w.bssid, w.channel, w.rssi);
                else if (lstrcmpA(w.ssid, pw.ssid)) ev_log("WIFI", "switched network \"%s\" -> \"%s\"", pw.ssid, w.ssid);
                else if (lstrcmpA(w.bssid, pw.bssid)) ev_log("WIFI", "roamed BSSID %s -> %s (ch %d -> %d, %d dBm)", pw.bssid, w.bssid, pw.channel, w.channel, w.rssi);
                else if (w.channel != pw.channel) ev_log("WIFI", "channel %d -> %d", pw.channel, w.channel);
                if (rssi_band < 0) rssi_band = bnd;
                else if (bnd > rssi_band || (bnd < rssi_band && w.rssi >= (bnd == 0 ? -67 : -75) + 3)) {   /* 3 dB hysteresis */
                    ev_log("WIFI", "signal %s: %d dBm (%d%%)", bnd == 0 ? "good" : bnd == 1 ? "fair" : "POOR", w.rssi, w.quality);
                    rssi_band = bnd;
                }
            } else {
                of_printf(&wf, "%s,,,,,,,\r\n", t);
                if (pw.connected) ev_log("WIFI", "DISCONNECTED from \"%s\"", pw.ssid);
            }
            pw = w;
        }

        /* adapters: link / IP / gateway / DNS changes */
        {
            IP_ADAPTER_ADDRESSES *l = get_adapters();
            if (l) {
                g_nadn = collect_adapters(g_adn, l);
                HeapFree(GetProcessHeap(), 0, l);
                for (i = 0; i < g_nadn; i++) {
                    AdState *c = &g_adn[i], *p = NULL;
                    for (j = 0; j < g_nad; j++) if (g_ad[j].idx == c->idx) { p = &g_ad[j]; break; }
                    if (!p) { ev_log("LINK", "adapter appeared: %s (%s)", c->name, c->up ? "up" : "down"); continue; }
                    if (c->up != p->up) ev_log("LINK", "%s %s", c->name, c->up ? "UP" : "DOWN");
                    if (lstrcmpA(c->ips, p->ips)) ev_log("IP", "%s: [%s] -> [%s]", c->name, p->ips, c->ips);
                    if (lstrcmpA(c->gws, p->gws)) ev_log("GW", "%s: [%s] -> [%s]", c->name, p->gws, c->gws);
                    if (lstrcmpA(c->dns, p->dns)) ev_log("DNS", "%s: [%s] -> [%s]", c->name, p->dns, c->dns);
                }
                for (j = 0; j < g_nad; j++) {
                    for (i = 0; i < g_nadn; i++) if (g_adn[i].idx == g_ad[j].idx) break;
                    if (i == g_nadn) ev_log("LINK", "adapter removed: %s", g_ad[j].name);
                }
                memcpy(g_ad, g_adn, sizeof g_ad); g_nad = g_nadn;
            }
        }

        /* best route + interface counters */
        if (GetBestInterfaceEx((struct sockaddr *)&g_target, &best) != NO_ERROR) best = 0;
        if (best != pbest) {
            char nm[96] = "none";
            for (i = 0; i < g_nad; i++) if (g_ad[i].idx == best) lstrcpyA(nm, g_ad[i].name);
            ev_log("ROUTE", "path to target now via %s (if %lu)", nm, best);
            pbest = best; pt = 0;
        }
        if (best) {
            MIB_IF_ROW2 r;
            memset(&r, 0, sizeof r);
            r.InterfaceIndex = best;
            if (GetIfEntry2(&r) == NO_ERROR) {
                if (pt) {
                    LONGLONG dt = (now.QuadPart - pt) * 1000 / fq.QuadPart;
                    char nm[160];
                    if (dt <= 0) dt = 1;
                    w2a(nm, r.Alias, sizeof nm);
                    for (i = 0; nm[i]; i++) if (nm[i] == ',') nm[i] = ' ';
                    of_printf(&inf, "%s,%s,%lu,%lu,%lu,%lu,%lu,%lu\r\n", t, nm,
                              (ULONG)((r.InOctets - pin) * 8 / dt), (ULONG)((r.OutOctets - pout) * 8 / dt),
                              (ULONG)(r.InErrors - pie), (ULONG)(r.InDiscards - pid), (ULONG)(r.OutErrors - poe), (ULONG)(r.OutDiscards - pod));
                }
                pin = r.InOctets; pout = r.OutOctets; pie = r.InErrors; pid = r.InDiscards; poe = r.OutErrors; pod = r.OutDiscards;
                pt = now.QuadPart;
            }
        }

        if (GetSystemPowerStatus(&ps) && ps.ACLineStatus <= 1) {
            if (prev_ac >= 0 && ps.ACLineStatus != prev_ac) ev_log("POWER", "%s", ps.ACLineStatus ? "on AC power" : "on BATTERY");
            prev_ac = ps.ACLineStatus;
        }
        of_flush(&g_events);
        if (have_wifi) of_flush(&wf);
        of_flush(&inf);
    } while (WaitForSingleObject(g_stop, 1000) == WAIT_TIMEOUT);

    snapshot(&sys, "END");
    of_close(&sys);
    if (have_wifi) of_close(&wf);
    of_close(&inf);
    return 0;
}

HANDLE netmon_start(const struct sockaddr_storage *target, const char *desc)
{
    g_target = *target;
    lstrcpynA(g_desc, desc, sizeof g_desc);
    return CreateThread(NULL, 0, monitor, NULL, 0, NULL);
}

/* ---------- zip (stored) ---------- */
static unsigned g_crc[256];
static unsigned crc32(unsigned c, const unsigned char *p, unsigned n)
{
    unsigned i, k;
    if (!g_crc[1]) for (i = 0; i < 256; i++) { unsigned v = i; for (k = 0; k < 8; k++) v = v & 1 ? 0xEDB88320u ^ (v >> 1) : v >> 1; g_crc[i] = v; }
    c = ~c;
    while (n--) c = g_crc[(c ^ *p++) & 0xff] ^ (c >> 8);
    return ~c;
}
static void w16(unsigned char *p, unsigned v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); }
static void w32(unsigned char *p, unsigned v) { w16(p, v & 0xffff); w16(p + 2, v >> 16); }

int zip_dir(const WCHAR *dir, WCHAR *zippath)
{
    WCHAR pat[MAX_PATH], fp[MAX_PATH];
    const WCHAR *base;
    WIN32_FIND_DATAW fd;
    HANDLE fh, out, heap = GetProcessHeap();
    unsigned char *cd, hdr[46];
    unsigned cdn = 0, cdcap = 65536, off = 0, files = 0;
    char bname[MAX_PATH * 3];
    DWORD w;

    for (base = dir + lstrlenW(dir); base > dir && base[-1] != L'\\'; base--) ;
    wsprintfW(zippath, L"%s.zip", dir);
    out = CreateFileW(zippath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) return 0;
    cd = HeapAlloc(heap, 0, cdcap);
    WideCharToMultiByte(CP_UTF8, 0, base, -1, bname, sizeof bname, NULL, NULL);
    wsprintfW(pat, L"%s\\*", dir);
    fh = FindFirstFileW(pat, &fd);
    if (fh != INVALID_HANDLE_VALUE) do {
        HANDLE in;
        unsigned char *data;
        unsigned sz, crc, nl;
        char name[MAX_PATH * 3];
        WORD dd, dt;
        FILETIME lft;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        wsprintfW(fp, L"%s\\%s", dir, fd.cFileName);
        in = CreateFileW(fp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (in == INVALID_HANDLE_VALUE) continue;
        sz = GetFileSize(in, NULL);
        data = HeapAlloc(heap, 0, sz + 1);
        if (!data) { CloseHandle(in); continue; }
        ReadFile(in, data, sz, &w, NULL); sz = w;
        CloseHandle(in);
        crc = crc32(0, data, sz);
        lstrcpyA(name, bname); lstrcatA(name, "/");
        WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, name + lstrlenA(name), MAX_PATH * 2, NULL, NULL);
        nl = lstrlenA(name);
        FileTimeToLocalFileTime(&fd.ftLastWriteTime, &lft);
        FileTimeToDosDateTime(&lft, &dd, &dt);

        memset(hdr, 0, 30);
        w32(hdr, 0x04034b50); w16(hdr + 4, 20); w16(hdr + 6, 0x0800); w16(hdr + 8, 0);
        w16(hdr + 10, dt); w16(hdr + 12, dd); w32(hdr + 14, crc); w32(hdr + 18, sz); w32(hdr + 22, sz); w16(hdr + 26, nl);
        WriteFile(out, hdr, 30, &w, NULL); WriteFile(out, name, nl, &w, NULL); WriteFile(out, data, sz, &w, NULL);
        HeapFree(heap, 0, data);

        if (cdn + 46 + nl > cdcap) { cdcap *= 2; cd = HeapReAlloc(heap, 0, cd, cdcap); }
        memset(cd + cdn, 0, 46);
        w32(cd + cdn, 0x02014b50); w16(cd + cdn + 4, 20); w16(cd + cdn + 6, 20); w16(cd + cdn + 8, 0x0800);
        w16(cd + cdn + 12, dt); w16(cd + cdn + 14, dd); w32(cd + cdn + 16, crc); w32(cd + cdn + 20, sz); w32(cd + cdn + 24, sz);
        w16(cd + cdn + 28, nl); w32(cd + cdn + 42, off);
        memcpy(cd + cdn + 46, name, nl);
        cdn += 46 + nl;
        off += 30 + nl + sz;
        files++;
    } while (FindNextFileW(fh, &fd));
    if (fh != INVALID_HANDLE_VALUE) FindClose(fh);
    WriteFile(out, cd, cdn, &w, NULL);
    memset(hdr, 0, 22);
    w32(hdr, 0x06054b50); w16(hdr + 8, files); w16(hdr + 10, files); w32(hdr + 12, cdn); w32(hdr + 16, off);
    WriteFile(out, hdr, 22, &w, NULL);
    CloseHandle(out);
    HeapFree(heap, 0, cd);
    return (int)files;
}

void clipboard_file(HWND h, const WCHAR *path)
{
    int n = lstrlenW(path);
    HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, sizeof(DROPFILES) + (n + 2) * sizeof(WCHAR));
    DROPFILES *df;
    if (!g) return;
    df = GlobalLock(g);
    df->pFiles = sizeof(DROPFILES);
    df->fWide = TRUE;
    memcpy((char *)df + sizeof(DROPFILES), path, n * sizeof(WCHAR));
    GlobalUnlock(g);
    if (OpenClipboard(h)) { EmptyClipboard(); SetClipboardData(CF_HDROP, g); CloseClipboard(); }
    else GlobalFree(g);
}

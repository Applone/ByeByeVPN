#include "port_scan.h"
#include "../core/utils.h"
#include <mutex>
#include <thread>
#include <atomic>
#include <algorithm>
#include <chrono>

#ifdef _WIN32
#include <conio.h>
#else
inline bool _kbhit() { return false; }
inline int _getch() { return 0; }
#endif

static const std::vector<int> TCP_FAST_PORTS = {
    22, 80, 81, 443,
    1080, 1081,
    3128, 4433, 4443,
    6443, 7443,
    8000, 8080, 8081, 8088,
    8443, 8843, 8888,
    9000, 9001, 9050, 9051,
    9443,
    10000, 10443, 10808, 10809, 10810,
    11443, 14443,
    20443, 21443, 22443,
    41641, 44443, 46443,
    50443, 51443,
    51820,
    55443,
    62078
};

std::vector<int> build_tcp_ports() {
    std::vector<int> p;
    switch (g_port_mode) {
        case PortMode::FAST:
            p = TCP_FAST_PORTS; break;
        case PortMode::RANGE: {
            int lo = std::max(1,  g_range_lo);
            int hi = std::min(65535, g_range_hi);
            if (hi < lo) break;
            p.reserve((size_t)hi - lo + 1);
            for (int i=lo; i<=hi; ++i) p.push_back(i);
        } break;
        case PortMode::LIST:
            p = g_port_list; break;
        case PortMode::FULL:
        default:
            p.reserve(65535);
            for (int i=1; i<=65535; ++i) p.push_back(i);
            break;
    }
    return p;
}

struct PortHint { int port; const char* svc; const char* proto; };
static const std::vector<PortHint> PORT_HINTS = {
    {22,"SSH","tcp"},
    {80,"HTTP","tcp"},
    {443,"HTTPS / VLESS / Reality","tcp"},
    {1080,"SOCKS5","tcp"},
    {3128,"HTTP proxy","tcp"},
    {4433,"XTLS / Reality","tcp"},
    {4443,"XTLS / Reality","tcp"},
    {8080,"HTTP proxy","tcp"},
    {8443,"HTTPS alt / Reality","tcp"},
    {8888,"HTTP alt","tcp"},
    {9050,"Tor SOCKS","tcp"},
    {9051,"Tor control","tcp"},
    {10808,"v2ray/xray SOCKS","tcp"},
    {10809,"v2ray/xray HTTP","tcp"},
    {10810,"v2ray/xray alt","tcp"},
    {41641,"WireGuard alt","udp"},
    {51820,"WireGuard","udp"},
    {55555,"AmneziaWG","udp"},
};

const char* port_hint(int p) {
    for (auto& h: PORT_HINTS) if (h.port == p) return h.svc;
    if (p == 6443 || p == 8443 || p == 4443) return "HTTPS alt / possible VPN over TLS";
    if (p >= 10800 && p <= 10820) return "v2ray/xray local-like range";
    return "";
}

static TcpOpen probe_tcp(const std::string& host, int port, int to_ms) {
    TcpOpen o; o.port = port; o.connect_ms = -1;
    auto t0 = std::chrono::steady_clock::now();
    std::string err; SOCKET s = tcp_connect(host, port, to_ms, err);
    if (s == INVALID_SOCKET) { o.err = err; return o; }
    o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - t0).count();
    char buf[512]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 600);
    if (n > 0) {
        buf[n]=0;
        o.banner.assign(buf, n);
        while (!o.banner.empty() && (o.banner.back()=='\r'||o.banner.back()=='\n'||o.banner.back()==0))
            o.banner.pop_back();
    }
    closesocket(s);
    return o;
}

std::vector<TcpOpen> scan_tcp(const std::string& host, const std::vector<int>& ports,
                                int threads, int to_ms, ScanStats* stats) {
    std::vector<TcpOpen> open;
    std::mutex mx;
    std::atomic<size_t> idx{0};
    std::atomic<int>    done{0};
    std::atomic<size_t> tmo{0}, refused{0}, other{0};
    std::atomic<bool>   abort_scan{false};

    while (_kbhit()) _getch();
    fprintf(stderr, "  (press 'q' to skip this phase)\n");

    std::thread kb([&]{
        while (!abort_scan.load()) {
            if (_kbhit()) {
                int c = _getch();
                if (c == 'q' || c == 'Q' || c == 27) {
                    abort_scan = true;
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });

    auto worker = [&]{
        while (true) {
            if (abort_scan.load()) break;
            size_t i = idx.fetch_add(1);
            if (i >= ports.size()) break;
            TcpOpen o = probe_tcp(host, ports[i], to_ms);
            int d = ++done;
            size_t cur = 0;
            if (o.connect_ms < 0) {
                if (o.err == "timeout")      ++tmo;
                else if (o.err == "refused") ++refused;
                else                         ++other;
            }
            {
                std::lock_guard<std::mutex> lk(mx);
                if (o.connect_ms >= 0) open.push_back(std::move(o));
                cur = open.size();
            }
            if (d % 20 == 0 || (size_t)d == ports.size()) {
                fprintf(stderr, "\r  scanning %d/%zu  open=%zu  ", d, ports.size(), cur);
                fflush(stderr);
            }
        }
    };
    threads = std::max(1, std::min(threads, (int)ports.size()));
    std::vector<std::thread> th;
    for (int i=0;i<threads;++i) th.emplace_back(worker);
    for (auto& t: th) t.join();

    abort_scan = true;
    kb.join();

    size_t scanned = std::min(idx.load(), ports.size());
    bool was_skipped = (scanned < ports.size());
    if (was_skipped) {
        fprintf(stderr, "\r  scan SKIPPED at %zu/%zu (open=%zu)        \n",
                scanned, ports.size(), open.size());
    } else {
        fprintf(stderr, "\r  scan done (%zu/%zu, open=%zu)        \n",
                ports.size(), ports.size(), open.size());
    }
    std::sort(open.begin(), open.end(), [](auto&a,auto&b){return a.port<b.port;});
    if (stats) {
        stats->scanned  = scanned;
        stats->timeouts = tmo.load();
        stats->refused  = refused.load();
        stats->other    = other.load();
        stats->skipped  = was_skipped;
    }
    return open;
}
#include "port_scan.h"

#include "../core/utils.h"
#include "tcp_async_scan.h"

#include <algorithm>
#include <string>
#include <vector>

namespace {

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

} // namespace

std::vector<int> build_tcp_ports() {
    std::vector<int> p;
    switch (g_port_mode) {
        case PortMode::FAST:
            p = TCP_FAST_PORTS;
            break;
        case PortMode::RANGE: {
            const int lo = std::max(1, g_range_lo);
            const int hi = std::min(65535, g_range_hi);
            if (hi < lo) break;
            p.reserve(static_cast<size_t>(hi - lo + 1));
            for (int i = lo; i <= hi; ++i) p.push_back(i);
            break;
        }
        case PortMode::LIST:
            p = g_port_list;
            break;
        case PortMode::FULL:
        default:
            p.reserve(65535);
            for (int i = 1; i <= 65535; ++i) p.push_back(i);
            break;
    }
    return p;
}

struct PortHint {
    int port;
    const char* svc;
    const char* proto;
};

static const std::vector<PortHint> PORT_HINTS = {
    {22, "SSH", "tcp"},
    {80, "HTTP", "tcp"},
    {443, "HTTPS / VLESS / Reality", "tcp"},
    {1080, "SOCKS5", "tcp"},
    {3128, "HTTP proxy", "tcp"},
    {4433, "XTLS / Reality", "tcp"},
    {4443, "XTLS / Reality", "tcp"},
    {8080, "HTTP proxy", "tcp"},
    {8443, "HTTPS alt / Reality", "tcp"},
    {8888, "HTTP alt", "tcp"},
    {9050, "Tor SOCKS", "tcp"},
    {9051, "Tor control", "tcp"},
    {10808, "v2ray/xray SOCKS", "tcp"},
    {10809, "v2ray/xray HTTP", "tcp"},
    {10810, "v2ray/xray alt", "tcp"},
    {41641, "WireGuard alt", "udp"},
    {51820, "WireGuard", "udp"},
    {55555, "AmneziaWG", "udp"},
};

const char* port_hint(int p) {
    for (const auto& h : PORT_HINTS) {
        if (h.port == p) return h.svc;
    }
    if (p == 6443 || p == 8443 || p == 4443) return "HTTPS alt / possible VPN over TLS";
    if (p >= 10800 && p <= 10820) return "v2ray/xray local-like range";
    return "";
}

std::vector<TcpOpen> scan_tcp(const std::string& host,
                              const std::vector<int>& ports,
                              int threads,
                              int to_ms,
                              ScanStats* stats) {
    return scan_tcp_async(host, ports, threads, to_ms, stats);
}

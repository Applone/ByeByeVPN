#include "port_scan.h"

#include "../core/utils.h"
#include "tcp_async_scan.h"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <vector>
#include <ranges>

namespace {

// Fast scan ports - commonly used VPN and proxy ports
inline constexpr std::array kTcpFastPorts{
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

// Port to service mapping
struct PortHint {
    int port;
    const char* svc;
};

inline constexpr std::array kPortHints{
    PortHint{22, "SSH"},
    PortHint{80, "HTTP"},
    PortHint{443, "HTTPS / VLESS / Reality"},
    PortHint{1080, "SOCKS5"},
    PortHint{3128, "HTTP proxy"},
    PortHint{4433, "XTLS / Reality"},
    PortHint{4443, "XTLS / Reality"},
    PortHint{8080, "HTTP proxy"},
    PortHint{8443, "HTTPS alt / Reality"},
    PortHint{8888, "HTTP alt"},
    PortHint{9050, "Tor SOCKS"},
    PortHint{9051, "Tor control"},
    PortHint{10808, "v2ray/xray SOCKS"},
    PortHint{10809, "v2ray/xray HTTP"},
    PortHint{10810, "v2ray/xray alt"},
    PortHint{41641, "WireGuard alt"},
    PortHint{51820, "WireGuard"},
    PortHint{55555, "AmneziaWG"},
};

} // namespace

[[nodiscard]] std::vector<int> build_tcp_ports() {
    std::vector<int> p;

    switch (g_port_mode) {
        case PortMode::FAST:
            p.assign(kTcpFastPorts.begin(), kTcpFastPorts.end());
            break;

        case PortMode::RANGE: {
            const int lo{std::max(kMinPortNumber, g_range_lo)};
            const int hi{std::min(kMaxPortNumber, g_range_hi)};
            if (hi < lo) break;

            p.reserve(static_cast<std::size_t>(hi) - static_cast<std::size_t>(lo) + 1);
            for (int i{lo}; i <= hi; ++i) {
                p.push_back(i);
            }
            break;
        }

        case PortMode::LIST:
            p = g_port_list;
            break;

        case PortMode::FULL:
        default:
            p.reserve(static_cast<std::size_t>(kMaxPortNumber));
            for (int i{kMinPortNumber}; i <= kMaxPortNumber; ++i) {
                p.push_back(i);
            }
            break;
    }

    return p;
}

[[nodiscard]] const char* port_hint(int p) {
    // Search known port hints
    const auto it{std::ranges::find_if(kPortHints, [p](const PortHint& h) {
        return h.port == p;
    })};

    if (it != kPortHints.end()) {
        return it->svc;
    }

    // Check special ranges
    if (p == 6443 || p == 8443 || p == 4443) {
        return "HTTPS alt / possible VPN over TLS";
    }
    if (p >= 10800 && p <= 10820) {
        return "v2ray/xray local-like range";
    }

    return "";
}

[[nodiscard]] std::vector<TcpOpen> scan_tcp(
    std::string_view host,
    const std::vector<int>& ports,
    int threads,
    int to_ms,
    ScanStats* stats
) {
    return scan_tcp_async(std::string{host}, ports, threads, to_ms, stats);
}

#include "port_scan.h"

#include "../core/utils.h"
#include "tcp_scanner.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#else
#include <poll.h>
inline bool _kbhit() { return false; }
inline int _getch() { return 0; }
#endif

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

struct PendingConn {
    SOCKET sock = INVALID_SOCKET;
    int port = 0;
    std::chrono::steady_clock::time_point started{};
};

#ifdef _WIN32
using PollFd = WSAPOLLFD;

int os_poll(PollFd* fds, size_t count, int timeout_ms) {
    return WSAPoll(fds, static_cast<ULONG>(count), timeout_ms);
}
#else
using PollFd = pollfd;

int os_poll(PollFd* fds, size_t count, int timeout_ms) {
    return poll(fds, count, timeout_ms);
}
#endif

bool resolve_scan_target(const std::string& host, sockaddr_storage& out_addr, socklen_t& out_len) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* ai = nullptr;
    if (getaddrinfo(host.c_str(), "1", &hints, &ai) != 0 || !ai) {
        return false;
    }

    addrinfo* chosen = nullptr;
    for (auto* p = ai; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            chosen = p;
            break;
        }
    }
    if (!chosen) {
        for (auto* p = ai; p; p = p->ai_next) {
            if (p->ai_family == AF_INET6) {
                chosen = p;
                break;
            }
        }
    }

    if (!chosen) {
        freeaddrinfo(ai);
        return false;
    }

    std::memset(&out_addr, 0, sizeof(out_addr));
    std::memcpy(&out_addr, chosen->ai_addr, chosen->ai_addrlen);
    out_len = static_cast<socklen_t>(chosen->ai_addrlen);

    freeaddrinfo(ai);
    return true;
}

void set_port(sockaddr_storage& addr, int port) {
    if (addr.ss_family == AF_INET) {
        reinterpret_cast<sockaddr_in*>(&addr)->sin_port = htons(static_cast<uint16_t>(port));
    } else if (addr.ss_family == AF_INET6) {
        reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port = htons(static_cast<uint16_t>(port));
    }
}

void read_banner_quick(SOCKET s, std::string& banner) {
    char buf[512];
    int n = tcp_recv_to(s, buf, static_cast<int>(sizeof(buf)) - 1, 180);
    if (n <= 0) return;
    buf[n] = '\0';
    banner.assign(buf, n);
    while (!banner.empty() && (banner.back() == '\r' || banner.back() == '\n' || banner.back() == '\0')) {
        banner.pop_back();
    }
}

bool is_connect_in_progress_error(int err) {
#ifndef _WIN32
    if (err == EINPROGRESS) err = WSAEWOULDBLOCK;
#endif
    return err == WSAEWOULDBLOCK;
}

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
    std::vector<TcpOpen> open;
    if (stats) *stats = {};
    if (ports.empty()) return open;

    sockaddr_storage base_addr{};
    socklen_t base_len = 0;
    if (!resolve_scan_target(host, base_addr, base_len)) {
        fprintf(stderr, "  scan failed: cannot resolve target for TCP scan\n");
        if (stats) {
            stats->scanned = 0;
            stats->other = ports.size();
            stats->skipped = false;
        }
        return open;
    }

    const int max_inflight = std::clamp(threads, 16, 8192);
    fprintf(stderr, "  async non-blocking scanner: inflight=%d, timeout=%dms\n", max_inflight, to_ms);
    fprintf(stderr, "  (press 'q' to skip this phase)\n");

    while (_kbhit()) _getch();

    std::vector<PendingConn> inflight;
    inflight.reserve(static_cast<size_t>(max_inflight));

    size_t next_port = 0;
    size_t completed = 0;
    size_t timeouts = 0;
    size_t refused = 0;
    size_t other = 0;
    bool aborted = false;

    const auto launch_connect = [&](int port) {
        sockaddr_storage dst = base_addr;
        set_port(dst, port);

        SOCKET s = socket(dst.ss_family, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            ++other;
            ++completed;
            return;
        }

        set_nonblocking(s, true);
        const auto started = std::chrono::steady_clock::now();
        int rc = connect(s, reinterpret_cast<const sockaddr*>(&dst), base_len);
        if (rc == 0) {
            set_nonblocking(s, false);
            TcpOpen o;
            o.port = port;
            o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - started)
                              .count();
            read_banner_quick(s, o.banner);
            closesocket(s);
            open.push_back(std::move(o));
            ++completed;
            return;
        }

        const int werr = WSAGetLastError();
        if (is_connect_in_progress_error(werr)) {
            inflight.push_back(PendingConn{s, port, started});
            return;
        }

        closesocket(s);
        if (werr == WSAECONNREFUSED) {
            ++refused;
        } else {
            ++other;
        }
        ++completed;
    };

    while (next_port < ports.size() || !inflight.empty()) {
        if (_kbhit()) {
            const int c = _getch();
            if (c == 'q' || c == 'Q' || c == 27) {
                aborted = true;
                break;
            }
        }

        while (!aborted && next_port < ports.size() && static_cast<int>(inflight.size()) < max_inflight) {
            launch_connect(ports[next_port]);
            ++next_port;
        }

        if (inflight.empty()) {
            if (completed % 200 == 0 || completed == ports.size()) {
                fprintf(stderr, "\r  scanning %zu/%zu  open=%zu  ", completed, ports.size(), open.size());
                fflush(stderr);
            }
            continue;
        }

        std::vector<PollFd> fds;
        fds.reserve(inflight.size());
        for (const auto& p : inflight) {
            PollFd fd{};
            fd.fd = p.sock;
            fd.events = POLLOUT | POLLERR | POLLHUP;
            fd.revents = 0;
            fds.push_back(fd);
        }

        const int prc = os_poll(fds.data(), fds.size(), 25);
        const auto after_poll = std::chrono::steady_clock::now();

        std::vector<PendingConn> next_inflight;
        next_inflight.reserve(inflight.size());

        for (size_t idx = 0; idx < inflight.size(); ++idx) {
            bool remove_now = false;
            bool success = false;

            const bool signaled = prc > 0 && ((fds[idx].revents & (POLLOUT | POLLERR | POLLHUP)) != 0);
            if (signaled) {
                int se = 0;
                socklen_t sl = sizeof(se);
                getsockopt(inflight[idx].sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&se), &sl);
                if (se == 0) {
                    success = true;
                } else if (se == WSAECONNREFUSED) {
                    ++refused;
                } else {
                    ++other;
                }
                remove_now = true;
            } else {
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    after_poll - inflight[idx].started).count();
                if (elapsed >= to_ms) {
                    ++timeouts;
                    remove_now = true;
                }
            }

            if (!remove_now) {
                next_inflight.push_back(inflight[idx]);
                continue;
            }

            if (success) {
                set_nonblocking(inflight[idx].sock, false);
                TcpOpen o;
                o.port = inflight[idx].port;
                o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  after_poll - inflight[idx].started)
                                  .count();
                read_banner_quick(inflight[idx].sock, o.banner);
                open.push_back(std::move(o));
            }

            closesocket(inflight[idx].sock);
            ++completed;
        }

        inflight.swap(next_inflight);

        if (completed % 200 == 0 || completed == ports.size()) {
            fprintf(stderr, "\r  scanning %zu/%zu  open=%zu  ", completed, ports.size(), open.size());
            fflush(stderr);
        }
    }

    if (aborted) {
        for (auto& p : inflight) closesocket(p.sock);
        inflight.clear();
    }

    std::sort(open.begin(), open.end(), [](const TcpOpen& a, const TcpOpen& b) { return a.port < b.port; });

    const size_t scanned = completed;
    const bool was_skipped = aborted || scanned < ports.size();

    if (was_skipped) {
        fprintf(stderr, "\r  scan SKIPPED at %zu/%zu (open=%zu)        \n", scanned, ports.size(), open.size());
    } else {
        fprintf(stderr, "\r  scan done (%zu/%zu, open=%zu)        \n", scanned, ports.size(), open.size());
    }

    if (stats) {
        stats->scanned = scanned;
        stats->timeouts = timeouts;
        stats->refused = refused;
        stats->other = other;
        stats->skipped = was_skipped;
    }

    return open;
}

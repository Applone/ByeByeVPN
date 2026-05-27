#include "tcp_scanner.h"

#include <vector>
#include <memory>
#include <string>
#include <algorithm>
#include <ranges>

namespace {

// Helper to check if error indicates connection in progress
[[nodiscard]] constexpr bool is_would_block_error(int err) noexcept {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK;
#else
    return err == EINPROGRESS || err == WSAEWOULDBLOCK;
#endif
}

// Helper to check if error indicates connection refused
[[nodiscard]] constexpr bool is_refused_error(int err) noexcept {
    return err == WSAECONNREFUSED || err == ECONNREFUSED;
}

} // namespace

[[nodiscard]] SOCKET tcp_connect(std::string_view host, int port, int timeout_ms, std::string& err) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    addrinfo* raw_ai{nullptr};
    const std::string host_str{host};
    const std::string port_str{std::to_string(port)};
    
    if (::getaddrinfo(host_str.c_str(), port_str.c_str(), &hints, &raw_ai) != 0) {
        err = "dns";
        return INVALID_SOCKET;
    }
    
    AddrInfoPtr ai{raw_ai};
    
    // Order addresses: IPv4 first, then IPv6
    std::vector<addrinfo*> ordered;
    for (auto* p{ai.get()}; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            ordered.push_back(p);
        }
    }
    for (auto* p{ai.get()}; p; p = p->ai_next) {
        if (p->ai_family == AF_INET6) {
            ordered.push_back(p);
        }
    }
    
    bool saw_timeout{false};
    bool saw_refused{false};
    
    for (auto* p : ordered) {
        SOCKET s{::socket(p->ai_family, SOCK_STREAM, IPPROTO_TCP)};
        if (s == INVALID_SOCKET) {
            continue;
        }
        
        set_nonblocking(s, true);
        
        const int rc{::connect(s, p->ai_addr, static_cast<int>(p->ai_addrlen))};
        if (rc == 0) {
            // Immediate success
            set_nonblocking(s, false);
            return s;
        }
        
        const int werr{WSAGetLastError()};
        
        if (is_would_block_error(werr)) {
            // Connection in progress - use select to wait
            fd_set wr_set;
            fd_set ex_set;
            FD_ZERO(&wr_set);
            FD_SET(s, &wr_set);
            FD_ZERO(&ex_set);
            FD_SET(s, &ex_set);
            
            timeval tv{};
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            
            const int sr{::select(static_cast<int>(s) + 1, nullptr, &wr_set, &ex_set, &tv)};
            
            if (sr > 0) {
                if (FD_ISSET(s, &ex_set)) {
                    int se{0};
                    socklen_t sl{sizeof(se)};
                    ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&se), &sl);
                    if (is_refused_error(se)) {
                        saw_refused = true;
                    }
                } else if (FD_ISSET(s, &wr_set)) {
                    int se{0};
                    socklen_t sl{sizeof(se)};
                    ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&se), &sl);
                    if (se == 0) {
                        set_nonblocking(s, false);
                        return s;
                    }
                    if (is_refused_error(se)) {
                        saw_refused = true;
                    }
                }
            } else if (sr == 0) {
                saw_timeout = true;
            }
        } else {
            if (is_refused_error(werr)) {
                saw_refused = true;
            }
        }
        
        closesocket(s);
    }
    
    // Set error based on what we observed
    if (saw_refused) {
        err = "refused";
    } else if (saw_timeout) {
        err = "timeout";
    } else {
        err = "other";
    }
    
    return INVALID_SOCKET;
}

[[nodiscard]] int tcp_recv_to(SOCKET s, char* buf, int max, int timeout_ms) {
#ifdef _WIN32
    DWORD to{static_cast<DWORD>(timeout_ms)};
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
#else
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
    return ::recv(s, buf, max, 0);
}

int tcp_send_all(SOCKET s, const void* data, int n) {
    const char* p{static_cast<const char*>(data)};
    int left{n};
    
    while (left > 0) {
        const auto sent = ::send(s, p, static_cast<std::size_t>(left), 0);
        if (sent <= 0) {
            return static_cast<int>(sent);
        }
        p += sent;
        left -= static_cast<int>(sent);
    }
    
    return n;
}

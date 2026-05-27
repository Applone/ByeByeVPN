#include "udp_scanner.h"
#include "../core/utils.h"

#include <chrono>
#include <memory>
#include <algorithm>
#include <array>

#include <openssl/rand.h>

namespace {

// RAII wrapper for addrinfo
struct AddrInfoDeleter {
    void operator()(addrinfo* ai) const noexcept {
        if (ai) ::freeaddrinfo(ai);
    }
};
using AddrInfoPtr = std::unique_ptr<addrinfo, AddrInfoDeleter>;

// Apply jitter delay if configured
void apply_jitter_if_enabled() {
    if (g_udp_jitter) {
        unsigned char jb{0};
        RAND_bytes(&jb, 1);
        Sleep(50 + (jb % 251));
    }
}

// Set socket receive timeout
void set_recv_timeout(SOCKET s, int timeout_ms) {
#ifdef _WIN32
    DWORD to{static_cast<DWORD>(timeout_ms)};
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
#else
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
}

// Check if error indicates timeout/no-reply
[[nodiscard]] bool is_timeout_error(int err) noexcept {
#ifndef _WIN32
    if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR || err == EINVAL) {
        return true;
    }
#endif
    return err == WSAETIMEDOUT || err == 0;
}

// Check if error indicates port unreachable
[[nodiscard]] constexpr bool is_port_unreachable(int err) noexcept {
#ifndef _WIN32
    if (err == ECONNREFUSED) return true;
#endif
    return err == WSAECONNRESET;
}

} // namespace

[[nodiscard]] UdpResult udp_probe(std::string_view host,
                                  int port,
                                  std::span<const unsigned char> payload,
                                  int timeout_ms) {
    UdpResult result;
    
    apply_jitter_if_enabled();
    
    const auto start_time{std::chrono::steady_clock::now()};
    
    // Resolve hostname
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    
    addrinfo* raw_ai{nullptr};
    const std::string host_str{host};
    const std::string port_str{std::to_string(port)};
    
    if (::getaddrinfo(host_str.c_str(), port_str.c_str(), &hints, &raw_ai) != 0) {
        result.err = "dns";
        return result;
    }
    
    AddrInfoPtr ai{raw_ai};
    
    // Find suitable address (prefer IPv4)
    addrinfo* chosen{nullptr};
    for (auto* p{ai.get()}; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            chosen = p;
            break;
        }
    }
    if (!chosen) {
        for (auto* p{ai.get()}; p; p = p->ai_next) {
            if (p->ai_family == AF_INET6) {
                chosen = p;
                break;
            }
        }
    }
    
    if (!chosen) {
        result.err = "dns";
        return result;
    }
    
    // Create UDP socket with RAII
    SocketGuard sock{::socket(chosen->ai_family, SOCK_DGRAM, IPPROTO_UDP)};
    if (!sock) {
        result.err = "socket";
        return result;
    }
    
    set_recv_timeout(sock.get(), timeout_ms);
    
    // Connect (for UDP, this just sets the default destination)
    if (::connect(sock.get(), chosen->ai_addr, static_cast<int>(chosen->ai_addrlen)) != 0) {
        const int saved_err{WSAGetLastError()};
        result.err = "connect " + std::to_string(saved_err);
        return result;
    }
    
    // Send the payload
    const auto sent = ::send(sock.get(), 
                             reinterpret_cast<const char*>(payload.data()), 
                             payload.size(), 
                             0);
    if (sent <= 0) {
        result.err = "send";
        return result;
    }
    
    // Receive response
    std::array<char, 2048> buf{};
    const auto got = ::recv(sock.get(), buf.data(), buf.size(), 0);
    const int saved_err{(got <= 0) ? WSAGetLastError() : 0};
    
    // Calculate elapsed time
    result.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time
    ).count();
    
    // Normalize error code on non-Windows
#ifndef _WIN32
    int werr{saved_err};
    if (werr == EAGAIN || werr == EWOULDBLOCK || werr == EINTR || werr == EINVAL) {
        werr = WSAETIMEDOUT;
    } else if (werr == ECONNREFUSED) {
        werr = WSAECONNRESET;
    }
#else
    const int werr{saved_err};
#endif
    
    if (got > 0) {
        result.responded = true;
        result.bytes = static_cast<int>(got);
        result.reply_hex = hex_s(
            reinterpret_cast<unsigned char*>(buf.data()),
            static_cast<std::size_t>(std::min<ssize_t>(32, got)),
            true
        );
    } else if (is_timeout_error(werr)) {
        result.err = "no-reply / filtered";
    } else if (is_port_unreachable(werr)) {
        result.err = "ICMP port-unreachable (port closed)";
    } else {
        result.err = "wsa " + std::to_string(werr);
    }
    
    return result;
}

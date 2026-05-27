#pragma once

#include "socket_sys.h"

#include <string>
#include <string_view>
#include <span>
#include <concepts>

// Concept for byte-like types
template<typename T>
concept ByteType = std::same_as<T, char> || std::same_as<T, unsigned char> || std::same_as<T, std::byte>;

// TCP connection with timeout
// Returns INVALID_SOCKET on failure, valid socket on success
[[nodiscard]] SOCKET tcp_connect(std::string_view host, int port, int timeout_ms, std::string& err);

// Receive with timeout
// Returns number of bytes received, 0 on timeout/close, -1 on error
[[nodiscard]] int tcp_recv_to(SOCKET s, char* buf, int max, int timeout_ms);

// Send all data reliably
// Returns number of bytes sent (n on success), or <= 0 on error
int tcp_send_all(SOCKET s, const void* data, int n);

// Overload using span for modern C++
inline int tcp_send_all(SOCKET s, std::span<const std::byte> data) {
    return tcp_send_all(s, data.data(), static_cast<int>(data.size()));
}

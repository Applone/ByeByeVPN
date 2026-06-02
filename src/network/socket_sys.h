#pragma once

// Socket abstraction layer for cross-platform compatibility
// Using C++20 features: concepts, constexpr, RAII

#include <concepts>
#include <memory>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

namespace socket_sys {

// RAII wrapper for Winsock initialization - Rule of Zero via unique_ptr-like semantics
class WinsockRuntime {
public:
    WinsockRuntime() noexcept {
        WSADATA ws_data;
        if (WSAStartup(MAKEWORD(2, 2), &ws_data) == 0) {
            handle_.reset(this);
        }
    }
    
    [[nodiscard]] inline bool ready() const noexcept { return handle_ != nullptr; }

private:
    std::unique_ptr<void, decltype([](void*){ WSACleanup(); })> handle_;
};

// Global runtime instance with inline variable (C++17/20)
inline const WinsockRuntime g_winsock_runtime{};

} // namespace socket_sys

// Check if socket runtime is ready
[[nodiscard]] inline bool socket_runtime_ready() noexcept {
    return socket_sys::g_winsock_runtime.ready();
}

#else // POSIX

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>



// Type aliases for POSIX compatibility with Windows API
using SOCKET = int;
inline constexpr SOCKET INVALID_SOCKET{-1};
inline constexpr int SOCKET_ERROR{-1};

// Function compatibility macros
inline int closesocket(SOCKET s) noexcept { return s < 0 ? -1 : ::close(s); }

// Error code compatibility
[[nodiscard]] inline int WSAGetLastError() noexcept { return errno; }

// Windows error code equivalents
inline constexpr int WSAEWOULDBLOCK{EWOULDBLOCK};
inline constexpr int WSAECONNREFUSED{ECONNREFUSED};
inline constexpr int WSAETIMEDOUT{ETIMEDOUT};
inline constexpr int WSAECONNRESET{ECONNRESET};

// Sleep compatibility
inline void Sleep(int ms) noexcept { ::usleep(ms * 1000); }

// Socket runtime is always ready on POSIX
[[nodiscard]] constexpr bool socket_runtime_ready() noexcept { return true; }

#endif // _WIN32

// Concept for socket types
template<typename T>
concept SocketType = std::same_as<T, SOCKET>;

// Set socket non-blocking mode
inline void set_nonblocking(SOCKET s, bool nb) noexcept {
#ifdef _WIN32
    u_long flag{nb ? 1UL : 0UL};
    ::ioctlsocket(s, FIONBIO, &flag);
#else
    int flags{::fcntl(s, F_GETFL, 0)};
    if (flags == -1) return;
    
    if (nb) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    ::fcntl(s, F_SETFL, flags);
#endif
}

// RAII socket guard for automatic cleanup
struct SocketHandle {
    SOCKET s{INVALID_SOCKET};
    SocketHandle() = default;
	// This is false positive due to an old version of cppcheck.
	// cppcheck-suppress noExplicitConstructor
    SocketHandle(std::nullptr_t) noexcept {}
    explicit SocketHandle(SOCKET sock) noexcept : s{sock} {}
    explicit operator bool() const noexcept { return s != INVALID_SOCKET; }
    bool operator==(std::nullptr_t) const noexcept { return s == INVALID_SOCKET; }
    bool operator!=(std::nullptr_t) const noexcept { return s != INVALID_SOCKET; }
    bool operator==(const SocketHandle& o) const noexcept { return s == o.s; }
    bool operator!=(const SocketHandle& o) const noexcept { return s != o.s; }
};

struct SocketDeleter {
    using pointer = SocketHandle;
    void operator()(SocketHandle h) const noexcept {
        if (h.s != INVALID_SOCKET) {
            closesocket(h.s);
        }
    }
};

class SocketGuard {
public:
    explicit SocketGuard(SOCKET s = INVALID_SOCKET) noexcept 
        : socket_{s == INVALID_SOCKET ? nullptr : SocketHandle{s}} {}
    
    [[nodiscard]] SOCKET get() const noexcept { return socket_.get().s; }
    [[nodiscard]] bool valid() const noexcept { return socket_ != nullptr; }
    [[nodiscard]] explicit operator bool() const noexcept { return valid(); }
    
    SOCKET release() noexcept { return socket_.release().s; }
    
    void reset(SOCKET s = INVALID_SOCKET) noexcept {
        socket_.reset(s == INVALID_SOCKET ? nullptr : SocketHandle{s});
    }
    
    void close() noexcept { socket_.reset(); }

private:
    std::unique_ptr<SocketHandle, SocketDeleter> socket_;
};

// RAII wrapper for addrinfo (centralized — used by dns, tcp_scanner, udp_scanner)
struct AddrInfoDeleter {
    void operator()(addrinfo* ai) const noexcept {
        if (ai) ::freeaddrinfo(ai);
    }
};
using AddrInfoPtr = std::unique_ptr<addrinfo, AddrInfoDeleter>;

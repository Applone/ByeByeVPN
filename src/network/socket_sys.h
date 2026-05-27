#pragma once

// Socket abstraction layer for cross-platform compatibility
// Using C++20 features: concepts, constexpr, RAII

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <concepts>

namespace socket_sys {

// RAII wrapper for Winsock initialization - Rule of Zero via unique_ptr-like semantics
class WinsockRuntime {
public:
    WinsockRuntime() noexcept : ready_{WSAStartup(MAKEWORD(2, 2), &ws_data_) == 0} {}
    
    ~WinsockRuntime() {
        if (ready_) {
            WSACleanup();
        }
    }
    
    // Non-copyable, non-movable (singleton semantics)
    WinsockRuntime(const WinsockRuntime&) = delete;
    WinsockRuntime& operator=(const WinsockRuntime&) = delete;
    WinsockRuntime(WinsockRuntime&&) = delete;
    WinsockRuntime& operator=(WinsockRuntime&&) = delete;
    
    [[nodiscard]] constexpr bool ready() const noexcept { return ready_; }

private:
    WSADATA ws_data_{};
    bool ready_{false};
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

#include <concepts>

// Type aliases for POSIX compatibility with Windows API
using SOCKET = int;
inline constexpr SOCKET INVALID_SOCKET{-1};
inline constexpr int SOCKET_ERROR{-1};

// Function compatibility macros
inline int closesocket(SOCKET s) noexcept { return ::close(s); }

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
class SocketGuard {
public:
    explicit SocketGuard(SOCKET s = INVALID_SOCKET) noexcept : socket_{s} {}
    
    ~SocketGuard() {
        close();
    }
    
    // Non-copyable
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;
    
    // Movable
    SocketGuard(SocketGuard&& other) noexcept : socket_{other.release()} {}
    
    SocketGuard& operator=(SocketGuard&& other) noexcept {
        if (this != &other) {
            close();
            socket_ = other.release();
        }
        return *this;
    }
    
    [[nodiscard]] SOCKET get() const noexcept { return socket_; }
    [[nodiscard]] bool valid() const noexcept { return socket_ != INVALID_SOCKET; }
    [[nodiscard]] explicit operator bool() const noexcept { return valid(); }
    
    SOCKET release() noexcept {
        SOCKET s{socket_};
        socket_ = INVALID_SOCKET;
        return s;
    }
    
    void reset(SOCKET s = INVALID_SOCKET) noexcept {
        close();
        socket_ = s;
    }
    
    void close() noexcept {
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }

private:
    SOCKET socket_;
};

#ifndef NETWORK_SOCKET_SYS_H
#define NETWORK_SOCKET_SYS_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

namespace socket_sys_detail {

class WinsockRuntime {
public:
    WinsockRuntime() noexcept : rc_(WSAStartup(MAKEWORD(2, 2), &ws_)) {}

    ~WinsockRuntime() {
        if (rc_ == 0) WSACleanup();
    }

    bool ready() const noexcept { return rc_ == 0; }

private:
    WSADATA ws_{};
    int rc_ = 0;
};

[[maybe_unused]] inline const WinsockRuntime g_winsock_runtime{};

} // namespace socket_sys_detail

inline bool socket_runtime_ready() noexcept {
    return socket_sys_detail::g_winsock_runtime.ready();
}
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket close

inline int WSAGetLastError() { return errno; }
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAECONNREFUSED ECONNREFUSED
#define WSAETIMEDOUT ETIMEDOUT
#define WSAECONNRESET ECONNRESET

inline void Sleep(int ms) { usleep(ms * 1000); }

inline bool socket_runtime_ready() noexcept { return true; }
#endif

inline void set_nonblocking(SOCKET s, bool nb) {
#ifdef _WIN32
    u_long bl = nb ? 1 : 0;
    ioctlsocket(s, FIONBIO, &bl);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (nb) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    fcntl(s, F_SETFL, flags);
#endif
}

#endif // NETWORK_SOCKET_SYS_H
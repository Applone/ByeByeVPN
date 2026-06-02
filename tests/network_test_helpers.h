#ifndef TESTS_NETWORK_TEST_HELPERS_H
#define TESTS_NETWORK_TEST_HELPERS_H

#include "network/socket_sys.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace testnet {

inline int reserve_unused_tcp_port() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) throw std::runtime_error("socket");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(s);
        throw std::runtime_error("bind");
    }

    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&bound), &len) != 0) {
        closesocket(s);
        throw std::runtime_error("getsockname");
    }

    const int port = ntohs(bound.sin_port);
    closesocket(s);
    return port;
}

inline int reserve_unused_udp_port() {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) throw std::runtime_error("socket");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(s);
        throw std::runtime_error("bind");
    }

    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&bound), &len) != 0) {
        closesocket(s);
        throw std::runtime_error("getsockname");
    }

    const int port = ntohs(bound.sin_port);
    closesocket(s);
    return port;
}

inline int send_all(SOCKET s, const std::string& data) {
    const char* p = data.data();
    int left = static_cast<int>(data.size());
    while (left > 0) {
        const int n = send(s, p, left, 0);
        if (n <= 0) return n;
        p += n;
        left -= n;
    }
    return static_cast<int>(data.size());
}

// Rule of Zero: the listening socket is owned by a SocketGuard and the worker
// by a std::jthread (which joins on destruction). No user-declared destructor
// or copy/move members are needed. thread_ is declared last so it is joined
// before the socket and handler it borrows are torn down.
class TcpOneShotServer {
public:
    using Handler = std::function<void(SOCKET)>;

    explicit TcpOneShotServer(Handler handler) : handler_(std::move(handler)) {
        listen_sock_.reset(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!listen_sock_) throw std::runtime_error("socket");

        int opt = 1;
        setsockopt(listen_sock_.get(), SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&opt), sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if (bind(listen_sock_.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0)
            throw std::runtime_error("bind");        // SocketGuard closes on throw
        if (listen(listen_sock_.get(), 1) != 0)
            throw std::runtime_error("listen");

        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        if (getsockname(listen_sock_.get(), reinterpret_cast<sockaddr*>(&bound), &len) != 0)
            throw std::runtime_error("getsockname");
        port_ = ntohs(bound.sin_port);

        set_nonblocking(listen_sock_.get(), true);

        thread_ = std::jthread([this](std::stop_token st) {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (!st.stop_requested() && std::chrono::steady_clock::now() < deadline) {
                SOCKET client = accept(listen_sock_.get(), nullptr, nullptr);
                if (client != INVALID_SOCKET) {
                    SocketGuard cg{client};          // RAII close after handler
                    set_nonblocking(client, false);
                    handler_(client);
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }

    [[nodiscard]] int port() const noexcept { return port_; }

private:
    int port_ = 0;
    Handler handler_;
    SocketGuard listen_sock_;
    std::jthread thread_;  // declared last → joined first
};

// Rule of Zero: SocketGuard owns the socket, std::jthread owns the worker.
class UdpOneShotServer {
public:
    using Handler = std::function<void(SOCKET, const sockaddr_in&, const std::vector<unsigned char>&)>;

    explicit UdpOneShotServer(Handler handler) : handler_(std::move(handler)) {
        sock_.reset(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
        if (!sock_) throw std::runtime_error("socket");

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if (bind(sock_.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0)
            throw std::runtime_error("bind");
        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        if (getsockname(sock_.get(), reinterpret_cast<sockaddr*>(&bound), &len) != 0)
            throw std::runtime_error("getsockname");
        port_ = ntohs(bound.sin_port);

#ifdef _WIN32
        DWORD to = 2000;
        setsockopt(sock_.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
#else
        timeval tv{};
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock_.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif

        thread_ = std::jthread([this] {
            unsigned char buf[2048] = {0};
            sockaddr_in peer{};
            socklen_t plen = sizeof(peer);
            const int n = recvfrom(sock_.get(), reinterpret_cast<char*>(buf), sizeof(buf), 0,
                                   reinterpret_cast<sockaddr*>(&peer), &plen);
            if (n > 0) {
                handler_(sock_.get(), peer, std::vector<unsigned char>(buf, buf + n));
            }
        });
    }

    [[nodiscard]] int port() const noexcept { return port_; }

private:
    int port_ = 0;
    Handler handler_;
    SocketGuard sock_;
    std::jthread thread_;  // declared last → joined first
};

class TcpMultiShotServer {
public:
    using Handler = std::function<void(SOCKET, int)>;

    TcpMultiShotServer(int max_clients,
                       Handler handler,
                       std::chrono::milliseconds accept_window = std::chrono::milliseconds(2500))
        : max_clients_(max_clients), handler_(std::move(handler)), accept_window_(accept_window) {
        if (max_clients_ <= 0) {
            throw std::invalid_argument("max_clients must be positive");
        }

        listen_sock_.reset(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!listen_sock_) throw std::runtime_error("socket");

        int opt = 1;
        setsockopt(listen_sock_.get(), SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&opt), sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if (bind(listen_sock_.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0)
            throw std::runtime_error("bind");
        if (listen(listen_sock_.get(), max_clients_) != 0)
            throw std::runtime_error("listen");

        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        if (getsockname(listen_sock_.get(), reinterpret_cast<sockaddr*>(&bound), &len) != 0)
            throw std::runtime_error("getsockname");
        port_ = ntohs(bound.sin_port);

        set_nonblocking(listen_sock_.get(), true);

        thread_ = std::jthread([this](std::stop_token st) {
            const auto deadline = std::chrono::steady_clock::now() + accept_window_;
            int handled = 0;
            while (!st.stop_requested() && handled < max_clients_ &&
                   std::chrono::steady_clock::now() < deadline) {
                SOCKET client = accept(listen_sock_.get(), nullptr, nullptr);
                if (client != INVALID_SOCKET) {
                    SocketGuard cg{client};          // RAII close after handler
                    set_nonblocking(client, false);
                    handler_(client, handled);
                    ++handled;
                    handled_clients_.store(handled, std::memory_order_relaxed);
                    continue;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }

    [[nodiscard]] int port() const noexcept { return port_; }
    [[nodiscard]] int handled_clients() const noexcept {
        return handled_clients_.load(std::memory_order_relaxed);
    }

private:
    int max_clients_ = 0;
    int port_ = 0;
    Handler handler_;
    std::chrono::milliseconds accept_window_{};
    std::atomic<int> handled_clients_{0};
    SocketGuard listen_sock_;
    std::jthread thread_;  // declared last → joined first
};

} // namespace testnet

#endif

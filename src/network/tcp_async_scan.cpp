#include "tcp_async_scan.h"

#include "../core/utils.h"
#include "tcp_scanner.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <stop_token>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#include <mswsock.h>
#else
#include <arpa/inet.h>
#include <csignal>
#include <cerrno>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/epoll.h>
#include <unistd.h>
inline bool kbhit_stub() { return false; }
inline int getch_stub() { return 0; }
#endif

namespace {

using Clock = std::chrono::steady_clock;

struct WorkerResult {
    std::vector<TcpOpen> open;
    size_t scanned = 0;
    size_t timeouts = 0;
    size_t refused = 0;
    size_t other = 0;
    bool aborted = false;
};

struct PendingConnect {
    SocketGuard sock;
    int port = 0;
    Clock::time_point started{};
};

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

#ifndef _WIN32
bool is_connect_in_progress_error(int err) {
    return err == EINPROGRESS || err == EALREADY || err == EWOULDBLOCK;
}
#endif

bool is_refused_error(int err) {
#ifdef _WIN32
    return err == WSAECONNREFUSED;
#else
    return err == ECONNREFUSED;
#endif
}

class ThreadPool {
public:
    explicit ThreadPool(size_t worker_count) {
        workers_.reserve(worker_count);
        for (size_t i = 0; i < worker_count; ++i) {
            workers_.emplace_back([this](const std::stop_token& stoken) {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(mu_);
                        if (!cv_.wait(lock, stoken, [this] { return !tasks_.empty(); })) {
                            return;
                        }
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    task();
                }
            });
        }
    }

    template <typename Fn>
    auto enqueue(Fn&& fn) -> std::future<std::invoke_result_t<Fn>> {
        using Ret = std::invoke_result_t<Fn>;

        auto task = std::make_shared<std::packaged_task<Ret()>>(std::forward<Fn>(fn));
        std::future<Ret> fut = task->get_future();

        {
            std::scoped_lock lock(mu_);
            tasks_.emplace([task] { (*task)(); });
        }
        cv_.notify_one();

        return fut;
    }

private:
    std::queue<std::function<void()>> tasks_;
    std::mutex mu_;
    std::condition_variable_any cv_;
    std::vector<std::jthread> workers_;
};

#ifndef _WIN32
// Active sockets managed strictly via RAII SocketGuard in PendingConnect
#endif

#ifndef _WIN32
WorkerResult scan_connect_worker_epoll(const sockaddr_storage& base_addr,
                                       socklen_t base_len,
                                       const std::vector<int>& ports,
                                       int timeout_ms,
                                       int max_inflight,
                                       std::atomic<bool>& stop_flag,
                                       std::atomic<size_t>* global_scanned,
                                       std::atomic<size_t>* global_open) {
    WorkerResult out;
    if (ports.empty()) return out;

    SocketGuard epfd_guard{epoll_create1(0)};
    const int epfd = epfd_guard.get();
    if (epfd < 0) {
        out.scanned = ports.size();
        out.other = ports.size();
        if (global_scanned) global_scanned->fetch_add(ports.size(), std::memory_order_relaxed);
        return out;
    }

    std::unordered_map<SOCKET, PendingConnect> active;
    active.reserve(static_cast<size_t>(max_inflight) * 2 + 16);

    size_t next_idx = 0;

    auto mark_done = [&out, global_scanned]() {
        ++out.scanned;
        if (global_scanned) global_scanned->fetch_add(1, std::memory_order_relaxed);
    };

    auto launch_connect = [&](int port) {
        sockaddr_storage dst = base_addr;
        set_port(dst, port);

        SocketGuard s_guard{socket(dst.ss_family, SOCK_STREAM, IPPROTO_TCP)};
        SOCKET s = s_guard.get();
        if (s == INVALID_SOCKET) {
            ++out.other;
            mark_done();
            return;
        }

        set_nonblocking(s, true);
        const auto started = Clock::now();

        int rc = connect(s, reinterpret_cast<const sockaddr*>(&dst), base_len);
        if (rc == 0) {
            set_nonblocking(s, false);
            TcpOpen o;
            o.port = port;
            o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
            // s_guard closes socket automatically
            out.open.push_back(std::move(o));
            if (global_open) global_open->fetch_add(1, std::memory_order_relaxed);
            mark_done();
            return;
        }

        const int err = WSAGetLastError();
        if (!is_connect_in_progress_error(err)) {
            // s_guard closes socket automatically
            if (is_refused_error(err)) ++out.refused;
            else ++out.other;
            mark_done();
            return;
        }

        epoll_event ev{};
        ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
        ev.data.fd = s;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, s, &ev) != 0) {
            // s_guard closes socket automatically
            ++out.other;
            mark_done();
            return;
        }

        active.emplace(s, PendingConnect{.sock=std::move(s_guard), .port=port, .started=started});
    };

    while ((next_idx < ports.size() || !active.empty()) && !stop_flag.load(std::memory_order_relaxed)) {
        while (next_idx < ports.size() && std::cmp_less(active.size(), max_inflight) &&
               !stop_flag.load(std::memory_order_relaxed)) {
            launch_connect(ports.at(next_idx));
            ++next_idx;
        }

        if (active.empty()) continue;

        epoll_event events[256];
        const int n = epoll_wait(epfd, events, static_cast<int>(std::size(events)), 20);
        const auto now = Clock::now();

        if (n > 0) {
            for (int i = 0; i < n; ++i) {
                const SOCKET s = events[i].data.fd;
                auto it = active.find(s);
                if (it == active.end()) continue;

                int se = 0;
                socklen_t sl = sizeof(se);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&se), &sl) != 0) {
                    se = WSAGetLastError();
                }

                epoll_ctl(epfd, EPOLL_CTL_DEL, s, nullptr);

                if (se == 0) {
                    set_nonblocking(s, false);
                    TcpOpen o;
                    o.port = it->second.port;
                    o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.started).count();
                    out.open.push_back(std::move(o));
                    if (global_open) global_open->fetch_add(1, std::memory_order_relaxed);
                } else if (is_refused_error(se)) {
                    ++out.refused;
                } else {
                    ++out.other;
                }

                // Socket is closed automatically upon erasure from active map
                active.erase(it);
                mark_done();
            }
        }

        for (auto it = active.begin(); it != active.end();) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.started).count();
            if (elapsed >= timeout_ms) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, it->first, nullptr);
                // Socket is closed automatically upon erasure from active map
                ++out.timeouts;
                mark_done();
                it = active.erase(it);
            } else {
                ++it;
            }
        }
    }

    if (stop_flag.load(std::memory_order_relaxed)) {
        out.aborted = true;
    }

    active.clear();
    // epfd is automatically closed by epfd_guard
    return out;
}
#endif

#ifdef _WIN32
struct IocpConn {
    OVERLAPPED ov{};
    SOCKET sock = INVALID_SOCKET;
    int port = 0;
    Clock::time_point started{};
};

bool bind_connectex_socket(SOCKET s, int family) {
    if (family == AF_INET) {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = 0;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        return bind(s, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == 0;
    }

    if (family == AF_INET6) {
        sockaddr_in6 local{};
        local.sin6_family = AF_INET6;
        local.sin6_port = 0;
        local.sin6_addr = in6addr_any;
        return bind(s, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == 0;
    }

    return false;
}

LPFN_CONNECTEX load_connectex_ptr(int family) {
    SOCKET tmp = WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (tmp == INVALID_SOCKET) return nullptr;

    GUID guid = WSAID_CONNECTEX;
    LPFN_CONNECTEX fn = nullptr;
    DWORD bytes = 0;

    const int rc = WSAIoctl(tmp,
                            SIO_GET_EXTENSION_FUNCTION_POINTER,
                            &guid,
                            sizeof(guid),
                            &fn,
                            sizeof(fn),
                            &bytes,
                            nullptr,
                            nullptr);
    closesocket(tmp);
    if (rc != 0) return nullptr;
    return fn;
}

WorkerResult scan_connect_worker_iocp(const sockaddr_storage& base_addr,
                                      socklen_t base_len,
                                      const std::vector<int>& ports,
                                      int timeout_ms,
                                      int max_inflight,
                                      std::atomic<bool>& stop_flag,
                                      std::atomic<size_t>* global_scanned,
                                      std::atomic<size_t>* global_open) {
    WorkerResult out;
    if (ports.empty()) return out;

    LPFN_CONNECTEX connect_ex = load_connectex_ptr(base_addr.ss_family);
    if (!connect_ex) {
        out.scanned = ports.size();
        out.other = ports.size();
        if (global_scanned) global_scanned->fetch_add(ports.size(), std::memory_order_relaxed);
        return out;
    }

    HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (!iocp) {
        out.scanned = ports.size();
        out.other = ports.size();
        if (global_scanned) global_scanned->fetch_add(ports.size(), std::memory_order_relaxed);
        return out;
    }

    std::unordered_map<OVERLAPPED*, std::unique_ptr<IocpConn>> active;
    std::unordered_map<OVERLAPPED*, std::unique_ptr<IocpConn>> retired;
    active.reserve(static_cast<size_t>(max_inflight) * 2 + 16);
    retired.reserve(static_cast<size_t>(max_inflight) * 2 + 16);

    auto mark_done = [&out, global_scanned]() {
        ++out.scanned;
        if (global_scanned) global_scanned->fetch_add(1, std::memory_order_relaxed);
    };

    size_t next_idx = 0;

    auto classify_error = [&](int err) {
        if (is_refused_error(err)) ++out.refused;
        else ++out.other;
        mark_done();
    };

    auto launch_connect = [&](int port) {
        sockaddr_storage dst = base_addr;
        set_port(dst, port);

        auto conn = std::make_unique<IocpConn>();
        conn->sock = WSASocketW(dst.ss_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        conn->port = port;
        conn->started = Clock::now();

        if (conn->sock == INVALID_SOCKET) {
            ++out.other;
            mark_done();
            return;
        }

        if (!CreateIoCompletionPort(reinterpret_cast<HANDLE>(conn->sock), iocp, 0, 0)) {
            closesocket(conn->sock);
            ++out.other;
            mark_done();
            return;
        }

        if (!bind_connectex_socket(conn->sock, dst.ss_family)) {
            closesocket(conn->sock);
            ++out.other;
            mark_done();
            return;
        }

        OVERLAPPED* ov = &conn->ov;
        active.emplace(ov, std::move(conn));

        DWORD bytes_sent = 0;
        BOOL ok = connect_ex(active[ov]->sock,
                             reinterpret_cast<const sockaddr*>(&dst),
                             static_cast<int>(base_len),
                             nullptr,
                             0,
                             &bytes_sent,
                             ov);
        if (ok) {
            auto done = std::move(active[ov]);
            active.erase(ov);

            setsockopt(done->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0);
            set_nonblocking(done->sock, false);
            TcpOpen o;
            o.port = done->port;
            o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - done->started).count();
            closesocket(done->sock);

            out.open.push_back(std::move(o));
            if (global_open) global_open->fetch_add(1, std::memory_order_relaxed);
            mark_done();
            return;
        }

        const int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING) {
            auto done = std::move(active[ov]);
            active.erase(ov);
            closesocket(done->sock);
            classify_error(err);
            return;
        }
    };

    while ((next_idx < ports.size() || !active.empty()) && !stop_flag.load(std::memory_order_relaxed)) {
        while (next_idx < ports.size() && static_cast<int>(active.size()) < max_inflight &&
               !stop_flag.load(std::memory_order_relaxed)) {
            launch_connect(ports.at(next_idx));
            ++next_idx;
        }

        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* ov = nullptr;
        BOOL ok = GetQueuedCompletionStatus(iocp, &bytes, &key, &ov, 20);

        if (ov != nullptr) {
            auto it = active.find(ov);
            if (it != active.end()) {
                auto done = std::move(it->second);
                active.erase(it);

                int se = 0;
                int sl = sizeof(se);
                if (getsockopt(done->sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&se), &sl) != 0) {
                    se = WSAGetLastError();
                }

                if (ok && se == 0) {
                    setsockopt(done->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0);
                    set_nonblocking(done->sock, false);
                    TcpOpen o;
                    o.port = done->port;
                    o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - done->started).count();
                    out.open.push_back(std::move(o));
                    if (global_open) global_open->fetch_add(1, std::memory_order_relaxed);
                } else if (is_refused_error(se)) {
                    ++out.refused;
                } else {
                    ++out.other;
                }

                closesocket(done->sock);
                mark_done();
            } else {
                auto rit = retired.find(ov);
                if (rit != retired.end()) {
                    retired.erase(rit);
                }
            }
        }

        const auto now = Clock::now();
        for (auto it = active.begin(); it != active.end();) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second->started).count();
            if (elapsed >= timeout_ms) {
                auto done = std::move(it->second);
                it = active.erase(it);

                CancelIoEx(reinterpret_cast<HANDLE>(done->sock), &done->ov);
                closesocket(done->sock);
                done->sock = INVALID_SOCKET;
                retired.emplace(&done->ov, std::move(done));

                ++out.timeouts;
                mark_done();
            } else {
                ++it;
            }
        }
    }

    if (stop_flag.load(std::memory_order_relaxed)) {
        out.aborted = true;
        for (auto it = active.begin(); it != active.end();) {
            auto conn = std::move(it->second);
            it = active.erase(it);
            if (conn->sock != INVALID_SOCKET) {
                CancelIoEx(reinterpret_cast<HANDLE>(conn->sock), &conn->ov);
                closesocket(conn->sock);
                conn->sock = INVALID_SOCKET;
            }
            retired.emplace(&conn->ov, std::move(conn));
        }
    }

    constexpr int kRetiredDrainTimeoutMs = 1000;
    const auto drain_deadline = Clock::now() + std::chrono::milliseconds(kRetiredDrainTimeoutMs);
    while (!retired.empty() && Clock::now() < drain_deadline) {
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* ov = nullptr;
        const BOOL got = GetQueuedCompletionStatus(iocp, &bytes, &key, &ov, 20);
        if (ov != nullptr) {
            auto rit = retired.find(ov);
            if (rit != retired.end()) {
                retired.erase(rit);
            }
        }
        if (!got && ov == nullptr && GetLastError() == WAIT_TIMEOUT) {
            break;
        }
    }

    retired.clear();

    CloseHandle(iocp);
    return out;
}
#endif

#ifndef _WIN32
uint16_t checksum16(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += static_cast<uint16_t>((data[0] << 8U) | data[1]);
        data += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += static_cast<uint16_t>(data[0] << 8U);
    }
    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<uint16_t>(~sum);
}

struct PseudoHeader {
    uint32_t src = 0;
    uint32_t dst = 0;
    uint8_t zero = 0;
    uint8_t proto = IPPROTO_TCP;
    uint16_t tcp_len = htons(sizeof(tcphdr));
};

struct SynFrame {
    iphdr ip{};
    tcphdr tcp{};
};

struct SynPending {
    int port = 0;
    uint16_t src_port = 0;
    Clock::time_point sent{};
};

volatile sig_atomic_t g_syn_abort = 0;

void syn_abort_signal_handler(int) {
    g_syn_abort = 1;
}

std::mutex g_syn_scan_mutex;

struct SigactionTuple {
    struct sigaction old_int{};
    struct sigaction old_term{};
    bool installed{false};
    
    SigactionTuple() = default;
	// This is false positive due to an old version of cppcheck. 
	// cppcheck-suppress noExplicitConstructor
    SigactionTuple(std::nullptr_t) noexcept {}
    
    explicit operator bool() const noexcept { return installed; }
    bool operator==(std::nullptr_t) const noexcept { return !installed; }
    bool operator!=(std::nullptr_t) const noexcept { return installed; }
    bool operator==(const SigactionTuple& o) const noexcept { return installed == o.installed; }
    bool operator!=(const SigactionTuple& o) const noexcept { return installed != o.installed; }
};

struct SigactionDeleter {
    using pointer = SigactionTuple;
    void operator()(SigactionTuple h) const noexcept {
        if (h.installed) {
            sigaction(SIGINT, &h.old_int, nullptr);
            sigaction(SIGTERM, &h.old_term, nullptr);
        }
    }
};

class SynAbortSignalGuard {
public:
    explicit SynAbortSignalGuard() : lock_(g_syn_scan_mutex) {
        g_syn_abort = 0;

        struct sigaction new_action{};
        std::memset(&new_action, 0, sizeof(new_action));
        new_action.sa_handler = syn_abort_signal_handler;
        sigemptyset(&new_action.sa_mask);
        new_action.sa_flags = 0;

        SigactionTuple tuple;
        if (sigaction(SIGINT, &new_action, &tuple.old_int) == 0 &&
            sigaction(SIGTERM, &new_action, &tuple.old_term) == 0) {
            tuple.installed = true;
            guard_.reset(tuple);
        }
    }

private:
    std::unique_lock<std::mutex> lock_;
    std::unique_ptr<SigactionTuple, SigactionDeleter> guard_;
};

bool resolve_ipv4_target(const std::string& host, sockaddr_in& out) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* ai = nullptr;
    if (getaddrinfo(host.c_str(), "1", &hints, &ai) != 0 || !ai) return false;

    bool ok = false;
    for (const auto* p = ai; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            std::memcpy(&out, p->ai_addr, sizeof(sockaddr_in));
            ok = true;
            break;
        }
    }

    freeaddrinfo(ai);
    return ok;
}

bool resolve_source_ipv4(const sockaddr_in& dst, in_addr& out_src) {
    SOCKET u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u == INVALID_SOCKET) return false;

    bool ok = false;
    if (connect(u, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst)) == 0) {
        sockaddr_in local{};
        socklen_t sl = sizeof(local);
        if (getsockname(u, reinterpret_cast<sockaddr*>(&local), &sl) == 0) {
            out_src = local.sin_addr;
            ok = true;
        }
    }

    closesocket(u);
    return ok;
}

bool send_syn_packet(SOCKET raw_send,
                     const in_addr& src,
                     const sockaddr_in& dst,
                     uint16_t src_port,
                     uint16_t dst_port,
                     uint32_t seq_no) {
    SynFrame frame{};

    frame.ip.ihl = 5;
    frame.ip.version = 4;
    frame.ip.tos = 0;
    frame.ip.tot_len = htons(sizeof(SynFrame));
    frame.ip.id = htons(static_cast<uint16_t>(seq_no & 0xFFFFU));
    frame.ip.frag_off = 0;
    frame.ip.ttl = 64;
    frame.ip.protocol = IPPROTO_TCP;
    frame.ip.saddr = src.s_addr;
    frame.ip.daddr = dst.sin_addr.s_addr;
    frame.ip.check = 0;
    frame.ip.check = checksum16(reinterpret_cast<const uint8_t*>(&frame.ip), sizeof(iphdr));

    frame.tcp.source = htons(src_port);
    frame.tcp.dest = htons(dst_port);
    frame.tcp.seq = htonl(seq_no);
    frame.tcp.ack_seq = 0;
    frame.tcp.doff = sizeof(tcphdr) / 4;
    frame.tcp.syn = 1;
    frame.tcp.window = htons(64240);
    frame.tcp.check = 0;

    PseudoHeader pseudo{};
    pseudo.src = src.s_addr;
    pseudo.dst = dst.sin_addr.s_addr;

    uint8_t cbuf[sizeof(PseudoHeader) + sizeof(tcphdr)] = {0};
    std::memcpy(cbuf, &pseudo, sizeof(pseudo));
    std::memcpy(cbuf + sizeof(pseudo), &frame.tcp, sizeof(tcphdr));
    frame.tcp.check = checksum16(cbuf, sizeof(cbuf));

    const int sent = sendto(raw_send,
                            reinterpret_cast<const char*>(&frame),
                            sizeof(frame),
                            0,
                            reinterpret_cast<const sockaddr*>(&dst),
                            sizeof(dst));
    return std::cmp_equal(sent ,sizeof(frame));
}

std::optional<WorkerResult> scan_syn_half_open_linux(const std::string& host,
                                                      const std::vector<int>& ports,
                                                      int timeout_ms,
                                                      int max_inflight,
                                                      std::atomic<size_t>* global_scanned,
                                                      std::atomic<size_t>* global_open) {
    if (ports.empty()) return WorkerResult{};

    if (geteuid() != 0) {
        fprintf(stderr, "  syn-scan requires root privileges; falling back to connect scan\n");
        return std::nullopt;
    }

    sockaddr_in dst{};
    if (!resolve_ipv4_target(host, dst)) {
        fprintf(stderr, "  syn-scan supports IPv4 targets only; falling back to connect scan\n");
        return std::nullopt;
    }

    in_addr src{};
    if (!resolve_source_ipv4(dst, src)) {
        fprintf(stderr, "  syn-scan could not resolve source address; falling back to connect scan\n");
        return std::nullopt;
    }

    SOCKET send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_fd == INVALID_SOCKET) {
        fprintf(stderr, "  syn-scan raw send socket failed; falling back to connect scan\n");
        return std::nullopt;
    }

    int hdrincl = 1;
    if (setsockopt(send_fd, IPPROTO_IP, IP_HDRINCL, reinterpret_cast<const char*>(&hdrincl), sizeof(hdrincl)) != 0) {
        closesocket(send_fd);
        fprintf(stderr, "  syn-scan IP_HDRINCL setup failed; falling back to connect scan\n");
        return std::nullopt;
    }

    SOCKET recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_fd == INVALID_SOCKET) {
        closesocket(send_fd);
        fprintf(stderr, "  syn-scan raw receive socket failed; falling back to connect scan\n");
        return std::nullopt;
    }

    set_nonblocking(recv_fd, true);

    WorkerResult out;
    std::unordered_map<uint16_t, SynPending> pending;
    pending.reserve(static_cast<size_t>(max_inflight) * 2 + 16);

    uint16_t src_port_cursor = 40000;
    std::mt19937 rng{std::random_device{}()};
    SynAbortSignalGuard abort_guard;

    auto mark_done = [&out, global_scanned]() {
        ++out.scanned;
        if (global_scanned) global_scanned->fetch_add(1, std::memory_order_relaxed);
    };

    auto alloc_src_port = [&]() -> uint16_t {
        for (int i = 0; i < 20000; ++i) {
            const auto p = static_cast<uint16_t>(40000 + ((src_port_cursor++ - 40000) % 20000));
            if (pending.find(p) == pending.end()) return p;
        }
        return 0;
    };

    size_t next_idx = 0;

    while (next_idx < ports.size() || !pending.empty()) {
        if (g_syn_abort) {
            out.aborted = true;
            break;
        }

        while (next_idx < ports.size() && std::cmp_less(pending.size(), max_inflight)) {
            const int port = ports.at(next_idx++);
            const uint16_t src_port = alloc_src_port();
            if (src_port == 0) {
                ++out.other;
                mark_done();
                continue;
            }

            const uint32_t seq = rng();
            if (!send_syn_packet(send_fd, src, dst, src_port, static_cast<uint16_t>(port), seq)) {
                ++out.other;
                mark_done();
                continue;
            }

            pending.emplace(src_port, SynPending{.port=port, .src_port=src_port, .sent=Clock::now()});
        }

        pollfd pfd{};
        pfd.fd = recv_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        poll(&pfd, 1, 6);

        if ((pfd.revents & POLLIN) != 0) {
            for (;;) {
                uint8_t buf[2048] = {0};
                sockaddr_in from{};
                socklen_t from_len = sizeof(from);
                const int n = recvfrom(recv_fd,
                                       reinterpret_cast<char*>(buf),
                                       sizeof(buf),
                                       0,
                                       reinterpret_cast<sockaddr*>(&from),
                                       &from_len);
                if (n <= 0) break;

                if (std::cmp_less(n ,sizeof(iphdr) + sizeof(tcphdr))) continue;

                const auto* iph = reinterpret_cast<const iphdr*>(buf);
                if (iph->protocol != IPPROTO_TCP) continue;

                const int ip_hlen = iph->ihl * 4;
                if (std::cmp_less(ip_hlen ,sizeof(iphdr)) || n < ip_hlen + static_cast<int>(sizeof(tcphdr))) continue;

                if (iph->saddr != dst.sin_addr.s_addr || iph->daddr != src.s_addr) continue;

                const auto* tcp = reinterpret_cast<const tcphdr*>(buf + ip_hlen);
                const uint16_t dst_src_port = ntohs(tcp->dest);

                auto it = pending.find(dst_src_port);
                if (it == pending.end()) continue;

                if (tcp->syn && tcp->ack) {
                    TcpOpen o;
                    o.port = it->second.port;
                    o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - it->second.sent).count();
                    out.open.push_back(std::move(o));
                    if (global_open) global_open->fetch_add(1, std::memory_order_relaxed);
                } else if (tcp->rst) {
                    ++out.refused;
                } else {
                    ++out.other;
                }

                pending.erase(it);
                mark_done();
            }
        }

        const auto now = Clock::now();
        for (auto it = pending.begin(); it != pending.end();) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.sent).count();
            if (elapsed >= timeout_ms) {
                ++out.timeouts;
                mark_done();
                it = pending.erase(it);
            } else {
                ++it;
            }
        }

        if (out.scanned % 200 == 0 || out.scanned == ports.size()) {
            fprintf(stderr, "\r  scanning %zu/%zu  open=%zu  ", out.scanned, ports.size(), out.open.size());
            fflush(stderr);
        }
    }

    closesocket(recv_fd);
    closesocket(send_fd);

    return out;
}
#endif

WorkerResult run_connect_scan_with_pool(const sockaddr_storage& base_addr,
                                        socklen_t base_len,
                                        const std::vector<int>& ports,
                                        int threads,
                                        int timeout_ms) {
    WorkerResult total;
    if (ports.empty()) return total;

    const int inflight_total = std::clamp(threads, 64, 16384);

    auto hw = static_cast<size_t>(std::thread::hardware_concurrency());
    if (hw == 0) hw = 4;

    size_t workers = std::clamp<size_t>(static_cast<size_t>(inflight_total / 256), 1, hw * 2);
    if (ports.size() >= 2048) workers = std::max<size_t>(2, workers);
    workers = std::min(workers, ports.size());

    const int inflight_per_worker = std::max(64, inflight_total / static_cast<int>(workers));

    std::vector<std::vector<int>> shards(workers);
    for (size_t i = 0; i < ports.size(); ++i) {
        shards.at(i % workers).push_back(ports.at(i));
    }

    fprintf(stderr,
            "  async scanner: workers=%zu inflight=%d (%d/worker) timeout=%dms\n",
            workers,
            inflight_total,
            inflight_per_worker,
            timeout_ms);
#ifdef _WIN32
    fprintf(stderr, "  (press 'q' to skip this phase)\n");
#endif

    std::atomic<bool> stop_flag{false};
    std::atomic<size_t> progress_scanned{0};
    std::atomic<size_t> progress_open{0};

#ifdef _WIN32
    while (_kbhit()) _getch();
#endif

    ThreadPool pool(workers);
    std::vector<std::future<WorkerResult>> futures;
    futures.reserve(workers);

    for (size_t i = 0; i < workers; ++i) {
        auto task = [&, i]() -> WorkerResult {
#ifdef _WIN32
            return scan_connect_worker_iocp(base_addr,
                                            base_len,
                                            shards.at(i),
                                            timeout_ms,
                                            inflight_per_worker,
                                            stop_flag,
                                            &progress_scanned,
                                            &progress_open);
#else
            return scan_connect_worker_epoll(base_addr,
                                             base_len,
                                             shards.at(i),
                                             timeout_ms,
                                             inflight_per_worker,
                                             stop_flag,
                                             &progress_scanned,
                                             &progress_open);
#endif
        };
        futures.push_back(pool.enqueue(std::move(task)));
    }

    std::vector<bool> taken(futures.size(), false);
    size_t done = 0;
    size_t last_scanned = 0;
    auto last_progress = Clock::now();
    const long long stall_limit_ms = std::max<long long>(8000, static_cast<long long>(timeout_ms) * 6LL);
    bool watchdog_triggered = false;

    while (done < futures.size()) {
#ifdef _WIN32
        if (_kbhit()) {
            const int c = _getch();
            if (c == 'q' || c == 'Q' || c == 27) {
                stop_flag.store(true, std::memory_order_relaxed);
            }
        }
#endif

        for (size_t i = 0; i < futures.size(); ++i) {
            if (taken.at(i)) continue;
            if (futures.at(i).wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                WorkerResult wr = futures.at(i).get();
                taken.at(i) = true;
                ++done;

                total.scanned += wr.scanned;
                total.timeouts += wr.timeouts;
                total.refused += wr.refused;
                total.other += wr.other;
                total.aborted = total.aborted || wr.aborted;
                total.open.insert(total.open.end(),
                                  std::make_move_iterator(wr.open.begin()),
                                  std::make_move_iterator(wr.open.end()));
            }
        }

        fprintf(stderr,
                "\r  scanning %zu/%zu  open=%zu  ",
                progress_scanned.load(std::memory_order_relaxed),
                ports.size(),
                progress_open.load(std::memory_order_relaxed));
        fflush(stderr);

        const size_t now_scanned = progress_scanned.load(std::memory_order_relaxed);
        if (now_scanned != last_scanned) {
            last_scanned = now_scanned;
            last_progress = Clock::now();
            watchdog_triggered = false;
        } else {
            const auto stalled_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - last_progress).count();
            if (stalled_ms > stall_limit_ms) {
                if (!watchdog_triggered) {
                    fprintf(stderr,
                            "\n  watchdog: no scan progress for %lld ms, stopping pending connects\n",
                            static_cast<long long>(stalled_ms));
                    watchdog_triggered = true;
                }
                stop_flag.store(true, std::memory_order_relaxed);
            }
        }

        if (done == futures.size()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    return total;
}

} // namespace

std::vector<TcpOpen> scan_tcp_async(const std::string& host,
                                    const std::vector<int>& ports,
                                    int threads,
                                    int to_ms,
                                    ScanStats* stats) {
    std::vector<TcpOpen> open;
    if (stats) *stats = {};

    if (ports.empty()) return open;

#ifndef _WIN32
    if (g_tcp_syn_scan) {
        const int syn_inflight = std::clamp(threads, 64, 4000);
        fprintf(stderr, "  syn half-open scanner: inflight=%d timeout=%dms\n", syn_inflight, to_ms);

        std::atomic<size_t> syn_scanned{0};
        std::atomic<size_t> syn_open{0};

        auto syn_res = scan_syn_half_open_linux(host, ports, to_ms, syn_inflight, &syn_scanned, &syn_open);
        if (syn_res.has_value()) {
            open = std::move(syn_res->open);
            std::ranges::sort(open, [](const TcpOpen& a, const TcpOpen& b) { return a.port < b.port; });

            const size_t scanned = syn_res->scanned;
            const bool skipped = syn_res->aborted || scanned < ports.size();

            if (skipped) {
                fprintf(stderr, "\r  scan SKIPPED at %zu/%zu (open=%zu)        \n", scanned, ports.size(), open.size());
            } else {
                fprintf(stderr, "\r  scan done (%zu/%zu, open=%zu)        \n", scanned, ports.size(), open.size());
            }

            if (stats) {
                stats->scanned = scanned;
                stats->timeouts = syn_res->timeouts;
                stats->refused = syn_res->refused;
                stats->other = syn_res->other;
                stats->skipped = skipped;
            }

            return open;
        }
    }
#else
    if (g_tcp_syn_scan) {
        fprintf(stderr, "  --syn is Linux-only; using IOCP connect scan\n");
    }
#endif

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

    WorkerResult total = run_connect_scan_with_pool(base_addr, base_len, ports, threads, to_ms);

    open = std::move(total.open);
    std::ranges::sort(open, [](const TcpOpen& a, const TcpOpen& b) { return a.port < b.port; });

    const size_t scanned = total.scanned;
    const bool skipped = total.aborted || scanned < ports.size();

    if (skipped) {
        fprintf(stderr, "\r  scan SKIPPED at %zu/%zu (open=%zu)        \n", scanned, ports.size(), open.size());
    } else {
        fprintf(stderr, "\r  scan done (%zu/%zu, open=%zu)        \n", scanned, ports.size(), open.size());
    }

    if (stats) {
        stats->scanned = scanned;
        stats->timeouts = total.timeouts;
        stats->refused = total.refused;
        stats->other = total.other;
        stats->skipped = skipped;
    }

    return open;
}

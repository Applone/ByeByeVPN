#include "dns.h"

#include <algorithm>
#include <chrono>
#include <memory>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

static std::string sa_ip(const sockaddr* sa) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        auto* s4 = (sockaddr_in*)sa;
        inet_ntop(AF_INET, &s4->sin_addr, buf, sizeof(buf));
    } else {
        auto* s6 = (sockaddr_in6*)sa;
        inet_ntop(AF_INET6, &s6->sin6_addr, buf, sizeof(buf));
    }
    return buf;
}

Resolved resolve_host(const std::string& host) {
    Resolved r; r.host = host;
    auto t0 = std::chrono::steady_clock::now();
    auto elapsed_ms = [&]() -> long long {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - t0).count();
    };

    // Bypass DNS if host is already an IP address
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET, host.c_str(), &(sa4.sin_addr)) == 1) {
        r.ips.push_back(host);
        r.primary_ip = host;
        r.family = "v4";
        r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        return r;
    } else if (inet_pton(AF_INET6, host.c_str(), &(sa6.sin6_addr)) == 1) {
        r.ips.push_back(host);
        r.primary_ip = host;
        r.family = "v6";
        r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        return r;
    }

    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &ai);
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> ai_ptr(ai, freeaddrinfo);
#ifdef _WIN32
    if (rc != 0) { r.ms = elapsed_ms(); r.err = gai_strerrorA(rc); return r; }
#else
    if (rc != 0) { r.ms = elapsed_ms(); r.err = gai_strerror(rc); return r; }
#endif
    
    std::vector<std::string> v4_ips, v6_ips;
    for (auto* p = ai_ptr.get(); p; p = p->ai_next) {
        std::string ip = sa_ip(p->ai_addr);
        if (p->ai_family == AF_INET) {
            if (std::find(v4_ips.begin(), v4_ips.end(), ip) == v4_ips.end())
                v4_ips.push_back(ip);
        } else if (p->ai_family == AF_INET6) {
            if (std::find(v6_ips.begin(), v6_ips.end(), ip) == v6_ips.end())
                v6_ips.push_back(ip);
        }
    }
    for (auto& s: v4_ips) r.ips.push_back(s);
    for (auto& s: v6_ips) r.ips.push_back(s);
    if (!r.ips.empty()) r.primary_ip = r.ips.front();
    bool has4 = !v4_ips.empty(), has6 = !v6_ips.empty();
    r.family = (has4 && has6) ? "mixed(v4-preferred)"
             : has4 ? "v4"
             : has6 ? "v6" : "";
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return r;
}

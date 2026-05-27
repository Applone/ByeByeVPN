#include "dns.h"
#include "socket_sys.h"

#include <algorithm>
#include <chrono>
#include <array>
#include <ranges>

namespace {

// Extract IP string from sockaddr
[[nodiscard]] std::string extract_ip(const sockaddr* sa) {
    std::array<char, INET6_ADDRSTRLEN> buf{};
    
    if (sa->sa_family == AF_INET) {
        const auto* s4{reinterpret_cast<const sockaddr_in*>(sa)};
        inet_ntop(AF_INET, &s4->sin_addr, buf.data(), buf.size());
    } else if (sa->sa_family == AF_INET6) {
        const auto* s6{reinterpret_cast<const sockaddr_in6*>(sa)};
        inet_ntop(AF_INET6, &s6->sin6_addr, buf.data(), buf.size());
    }
    
    return std::string{buf.data()};
}

// Check if string is an IPv4 address
[[nodiscard]] bool is_ipv4(std::string_view s) {
    sockaddr_in sa{};
    return inet_pton(AF_INET, std::string{s}.c_str(), &sa.sin_addr) == 1;
}

// Check if string is an IPv6 address
[[nodiscard]] bool is_ipv6(std::string_view s) {
    sockaddr_in6 sa{};
    return inet_pton(AF_INET6, std::string{s}.c_str(), &sa.sin6_addr) == 1;
}

} // namespace

[[nodiscard]] Resolved resolve_host(std::string_view host) {
    Resolved result;
    result.host = std::string{host};
    
    const auto start_time{std::chrono::steady_clock::now()};
    
    auto elapsed_ms = [&]() -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time
        ).count();
    };
    
    const std::string host_str{host};
    
    // Check if host is already an IP address (bypass DNS)
    if (is_ipv4(host)) {
        result.ips.push_back(host_str);
        result.primary_ip = host_str;
        result.family = "v4";
        result.ms = elapsed_ms();
        return result;
    }
    
    if (is_ipv6(host)) {
        result.ips.push_back(host_str);
        result.primary_ip = host_str;
        result.family = "v6";
        result.ms = elapsed_ms();
        return result;
    }
    
    // Perform DNS resolution
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    addrinfo* raw_ai{nullptr};
    const int rc{::getaddrinfo(host_str.c_str(), nullptr, &hints, &raw_ai)};
    AddrInfoPtr ai{raw_ai};
    
    if (rc != 0) {
        result.ms = elapsed_ms();
#ifdef _WIN32
        const char* err_str{gai_strerrorA(rc)};
#else
        const char* err_str{gai_strerror(rc)};
#endif
        result.err = (err_str && err_str[0]) ? std::string{err_str} : ("error " + std::to_string(rc));
        return result;
    }
    
    // Collect IPv4 and IPv6 addresses separately
    std::vector<std::string> v4_ips;
    std::vector<std::string> v6_ips;
    
    for (const auto* p{ai.get()}; p; p = p->ai_next) {
        std::string ip{extract_ip(p->ai_addr)};
        
        if (p->ai_family == AF_INET) {
            // Use ranges to check for duplicates
            if (std::ranges::find(v4_ips, ip) == v4_ips.end()) {
                v4_ips.push_back(std::move(ip));
            }
        } else if (p->ai_family == AF_INET6) {
            if (std::ranges::find(v6_ips, ip) == v6_ips.end()) {
                v6_ips.push_back(std::move(ip));
            }
        }
    }
    
    // Build result: IPv4 first, then IPv6
    for (auto& ip : v4_ips) {
        result.ips.push_back(std::move(ip));
    }
    for (auto& ip : v6_ips) {
        result.ips.push_back(std::move(ip));
    }
    
    if (!result.ips.empty()) {
        result.primary_ip = result.ips.front();
    }
    
    // Determine address family
    const bool has_v4{!v4_ips.empty()};
    const bool has_v6{!v6_ips.empty()};
    
    if (has_v4 && has_v6) {
        result.family = "mixed(v4-preferred)";
    } else if (has_v4) {
        result.family = "v4";
    } else if (has_v6) {
        result.family = "v6";
    }
    
    result.ms = elapsed_ms();
    return result;
}

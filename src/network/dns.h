#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

// Result of DNS resolution
struct Resolved {
    std::string host;
    std::string primary_ip;
    std::vector<std::string> ips;
    std::string family;
    std::string err;
    std::int64_t ms{0};
    
    // Rule of Zero - compiler generates all special members
    
    // Helper to check if resolution succeeded
    [[nodiscard]] bool ok() const noexcept { return err.empty() && !ips.empty(); }
};

// Resolve hostname to IP addresses
// Returns IPv4 addresses first, then IPv6
[[nodiscard]] Resolved resolve_host(std::string_view host);

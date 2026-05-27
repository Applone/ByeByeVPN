#pragma once

#include <vector>
#include <string>
#include <string_view>
#include <cstddef>
#include <cstdint>

#include "tcp_scanner.h"

// Build list of TCP ports based on global port mode
[[nodiscard]] std::vector<int> build_tcp_ports();

// Get service hint for known ports
[[nodiscard]] const char* port_hint(int p);

// Result of scanning a single TCP port
struct TcpOpen {
    int port{0};
    std::int64_t connect_ms{0};
    std::string banner;
    std::string err;
    
    // Check if connection succeeded
    [[nodiscard]] constexpr bool ok() const noexcept {
        return port > 0 && err.empty();
    }
};

// Statistics from a port scan
struct ScanStats {
    std::size_t scanned{0};
    std::size_t timeouts{0};
    std::size_t refused{0};
    std::size_t other{0};
    bool skipped{false};
    
    // Total failed connections
    [[nodiscard]] constexpr std::size_t failed() const noexcept {
        return timeouts + refused + other;
    }
};

// Scan TCP ports on a host
[[nodiscard]] std::vector<TcpOpen> scan_tcp(
    std::string_view host,
    const std::vector<int>& ports,
    int threads,
    int to_ms,
    ScanStats* stats = nullptr
);

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "port_scan.h"

// Async TCP port scanner using epoll (Linux) or IOCP (Windows)
// Supports both connect-scan and SYN half-open scan (Linux only, requires root)
[[nodiscard]] std::vector<TcpOpen> scan_tcp_async(
    const std::string& host,
    const std::vector<int>& ports,
    int threads,
    int to_ms,
    ScanStats* stats
);

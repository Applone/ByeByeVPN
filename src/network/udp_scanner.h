#pragma once

#include "socket_sys.h"

#include <string>
#include <string_view>
#include <span>
#include <cstdint>

// Result of a UDP probe
struct UdpResult {
    bool responded{false};
    int bytes{0};
    std::string reply_hex;
    std::int64_t ms{0};
    std::string err;
    
    // Rule of Zero - compiler generates all special members
};

// Send a UDP probe and wait for response
[[nodiscard]] UdpResult udp_probe(std::string_view host, 
                                  int port, 
                                  std::span<const unsigned char> payload, 
                                  int timeout_ms);

// Overload for raw pointer (backward compatibility)
[[nodiscard]] inline UdpResult udp_probe(const std::string& host, 
                                         int port, 
                                         const unsigned char* payload, 
                                         int plen, 
                                         int timeout_ms) {
    if (plen < 0 || (plen > 0 && payload == nullptr)) {
        UdpResult r;
        r.err = "invalid argument";
        return r;
    }
    return udp_probe(host, port, std::span<const unsigned char>{payload, static_cast<std::size_t>(plen)}, timeout_ms);
}

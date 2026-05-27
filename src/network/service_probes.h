#pragma once

#include <string>
#include <string_view>
#include <cstddef>

// Fingerprinting result
struct FpResult {
    std::string service;
    std::string details;
    std::string raw_hex;
    bool is_vpn_like{false};
    bool silent{false};
    
    // Check if result indicates a VPN-like service
    [[nodiscard]] constexpr bool vpn_detected() const noexcept {
        return is_vpn_like && !silent;
    }
};

// Get printable prefix of a string
[[nodiscard]] std::string printable_prefix(std::string_view s, std::size_t lim = 80);

// Fingerprint HTTP server
[[nodiscard]] FpResult fp_http_plain(std::string_view host, int port);

// Fingerprint SSH server
[[nodiscard]] FpResult fp_ssh(std::string_view banner_hint, std::string_view host, int port);

// Fingerprint SOCKS5 proxy
[[nodiscard]] FpResult fp_socks5(std::string_view host, int port);

// Fingerprint HTTP CONNECT proxy
[[nodiscard]] FpResult fp_http_connect(std::string_view host, int port);

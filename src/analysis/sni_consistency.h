#pragma once

#include <string>
#include <string_view>
#include <vector>

// SNI consistency check result
struct SniConsistency {
    std::string base_sni;
    std::string base_sha;
    std::string base_subject;
    std::vector<std::string> base_san;
    
    // Entry for each test SNI
    struct Entry {
        std::string sni;
        bool ok{false};
        std::string sha;
        std::string subject;
    };
    
    std::vector<Entry> entries;
    bool same_cert_always{false};
    bool reality_like{false};
    bool default_cert_only{false};
    std::string matched_foreign_sni;
    std::string brand_claimed;
    bool cert_impersonation{false};
    bool passthrough_mode{false};
    int distinct_certs{0};
    
    // Check if result indicates VPN-like behavior
    [[nodiscard]] constexpr bool vpn_like() const noexcept {
        return reality_like || cert_impersonation || passthrough_mode;
    }
};

// Check SNI consistency for TLS server
[[nodiscard]] SniConsistency sni_consistency(
    std::string_view ip,
    int port,
    std::string_view base_sni
);

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

// TLS probe result
struct TlsProbe {
    bool ok{false};
    std::string err;
    std::string version;
    std::string cipher;
    std::string alpn;
    std::string group;
    std::string cert_subject;
    std::string cert_issuer;
    std::string cert_sha256;
    std::vector<std::string> san;
    std::int64_t handshake_ms{0};
    std::string subject_cn;
    std::string issuer_cn;
    int age_days{0};
    int days_left{0};
    int total_validity_days{0};
    bool self_signed{false};
    bool is_letsencrypt{false};
    bool is_wildcard{false};
    int san_count{0};
    
    bool has_certificate{false};
    
    // Check if certificate is expiring soon (less than 7 days)
    [[nodiscard]] constexpr bool expiring_soon() const noexcept {
        return has_certificate && days_left >= 0 && days_left < 7;
    }
    
    // Check if certificate is expired
    [[nodiscard]] constexpr bool expired() const noexcept {
        return days_left < 0;
    }
    
    // Check if certificate uses short validity (typical of ACME)
    [[nodiscard]] constexpr bool short_validity() const noexcept {
        return total_validity_days > 0 && total_validity_days <= 90;
    }
};

// Probe TLS endpoint and retrieve certificate info
[[nodiscard]] TlsProbe tls_probe(
    std::string_view ip,
    int port,
    std::string_view sni,
    std::string_view alpn = "h2,http/1.1",
    int to_ms = 5000
);

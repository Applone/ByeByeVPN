#include "sni_consistency.h"

#include "brand_cert.h"
#include "../network/tls_probe.h"
#include "../core/utils.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

// ASCII case-insensitive equality on string_views, with no heap allocation
// (the previous implementation materialised two std::strings per comparison
// just to reach _stricmp's const char* API).
[[nodiscard]] constexpr bool iequals_ascii(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i{0}; i < a.size(); ++i) {
        const auto ca{static_cast<unsigned char>(a.at(i))};
        const auto cb{static_cast<unsigned char>(b.at(i))};
        const bool a_alpha{ca >= 'A' && ca <= 'Z'};
        const bool b_alpha{cb >= 'A' && cb <= 'Z'};
        const unsigned char fa{a_alpha ? static_cast<unsigned char>(ca | 0x20) : ca};
        const unsigned char fb{b_alpha ? static_cast<unsigned char>(cb | 0x20) : cb};
        if (fa != fb) return false;
    }
    return true;
}

// Check if name matches pattern (supports wildcards)
[[nodiscard]] bool dns_name_match(std::string_view name, std::string_view pat) noexcept {
    if (name.empty() || pat.empty()) return false;

    // Wildcard pattern
    if (pat.starts_with("*.")) {
        const std::string_view suffix{pat.substr(1)};
        if (name.size() <= suffix.size()) return false;

        const std::size_t off{name.size() - suffix.size()};
        // Check suffix matches and only one label before wildcard
        return iequals_ascii(name.substr(off), suffix) &&
               name.find('.') == off;
    }

    return iequals_ascii(name, pat);
}

// Check if certificate covers the given name
[[nodiscard]] bool cert_covers_name(
    std::string_view sni,
    std::string_view subject_cn,
    const std::vector<std::string>& san
) {
    if (dns_name_match(sni, subject_cn)) return true;
    
    return std::ranges::any_of(san, [&](const std::string& s) {
        return dns_name_match(sni, s);
    });
}

// Alternative SNIs to test
inline constexpr std::array kAltSnis{
    "www.microsoft.com",
    "www.apple.com",
    "www.amazon.com",
    "www.google.com",
    "www.cloudflare.com",
    "www.bing.com",
    "addons.mozilla.org",
    "www.yandex.ru",
    "www.github.com",
    "random-domain-that-does-not-exist.invalid"
};

} // namespace

[[nodiscard]] SniConsistency sni_consistency(
    std::string_view ip,
    int port,
    std::string_view base_sni
) {
    SniConsistency c;
    c.base_sni = std::string{base_sni};
    
    // Probe with base SNI
    const std::string ip_str{ip};
    const std::string base_sni_str{base_sni};
    const TlsProbe base{tls_probe(ip_str, port, base_sni_str)};
    
    if (!base.ok) return c;
    
    c.base_sha = base.cert_sha256;
    c.base_subject = base.cert_subject;
    c.base_san = base.san;
    
    // Track statistics
    int same{0};
    int total{0};
    std::set<std::string> distinct;
    
    if (!base.cert_sha256.empty()) {
        distinct.insert(base.cert_sha256);
    }
    
    // Test alternative SNIs
    for (const auto& s : kAltSnis) {
        const TlsProbe p{tls_probe(ip_str, port, s)};
        
        SniConsistency::Entry e;
        e.sni = s;
        e.ok = p.ok;
        e.sha = p.cert_sha256;
        e.subject = p.cert_subject;
        
        if (p.ok) {
            ++total;
            if (p.cert_sha256 == base.cert_sha256) {
                ++same;
            }
            if (!p.cert_sha256.empty()) {
                distinct.insert(p.cert_sha256);
            }
        }
        
        c.entries.push_back(std::move(e));
    }
    
    c.distinct_certs = static_cast<int>(distinct.size());
    c.brand_claimed = cert_claims_brand(base.subject_cn, base.san);

    // Analyze results
    if (total >= 3 && same == total) {
        c.same_cert_always = true;
        const bool cert_covers_base{cert_covers_name(base_sni, base.subject_cn, base.san)};
        
        if (!cert_covers_base) {
            for (const auto& s : kAltSnis) {
                if (iequals_ascii(s, base_sni_str)) continue;
                
                if (cert_covers_name(s, base.subject_cn, base.san)) {
                    c.reality_like = true;
                    c.matched_foreign_sni = s;
                    break;
                }
            }
        }
        
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            if (!c.reality_like && !cert_covers_base) {
                c.reality_like = true;
                c.matched_foreign_sni = c.brand_claimed;
            }
        }
        
        if (!c.reality_like) {
            c.default_cert_only = true;
        }
    } else if (total >= 3 && ((same == 0 && c.distinct_certs >= 3) ||
                               (same > 0 && same < total))) {
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            c.reality_like = true;
            c.matched_foreign_sni = c.brand_claimed;
            c.passthrough_mode = true;
        }
    }
    
    return c;
}

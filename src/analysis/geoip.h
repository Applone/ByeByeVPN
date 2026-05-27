#pragma once

#include <string>
#include <string_view>

// GeoIP information for an IP address
struct GeoInfo {
    std::string ip;
    std::string country;
    std::string country_code;
    std::string city;
    std::string asn;
    std::string asn_org;
    bool is_hosting{false};
    bool is_vpn{false};
    bool is_proxy{false};
    bool is_tor{false};
    bool is_abuser{false};
    std::string source;
    std::string err;
    
    // Check if query succeeded
    [[nodiscard]] bool ok() const noexcept {
        return !ip.empty() && err.empty();
    }
    
    // Check if IP is suspicious (VPN, proxy, tor, or hosting)
    [[nodiscard]] constexpr bool suspicious() const noexcept {
        return is_vpn || is_proxy || is_tor || is_hosting;
    }
};

// GeoIP lookups from various providers
[[nodiscard]] GeoInfo geo_ipapi_is(std::string_view ip);
[[nodiscard]] GeoInfo geo_iplocate(std::string_view ip);
[[nodiscard]] GeoInfo geo_ipwho_is(std::string_view ip);
[[nodiscard]] GeoInfo geo_ipinfo_io(std::string_view ip);
[[nodiscard]] GeoInfo geo_freeipapi(std::string_view ip);
[[nodiscard]] GeoInfo geo_2ip_ru(std::string_view ip);
[[nodiscard]] GeoInfo geo_sypex(std::string_view ip);

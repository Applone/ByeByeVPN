#include "geoip.h"

#include "../network/http_client.h"
#include "../core/utils.h"

#include <string>
#include <string_view>

[[nodiscard]] GeoInfo geo_ipapi_is(std::string_view ip) {
    GeoInfo g;
    g.source = "ipapi.is";

    std::string url{"https://api.ipapi.is/"};
    if (!ip.empty()) {
        url += "?q=";
        url += ip;
    }

    const auto r{http_get(url, 7000)};
    if (!r.ok()) {
        g.err = "http " + std::to_string(r.status) + " " + r.err;
        return g;
    }

    g.ip = json_get_str(r.body, "ip");
    g.country = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city = json_get_str(r.body, "city");

    // Extract ASN block
    std::string asn_block;
    const auto ap{r.body.find("\"asn\"")};
    if (ap != std::string::npos) {
        const auto ob{r.body.find('{', ap)};
        const auto ce{ob == std::string::npos ? std::string::npos : r.body.find('}', ob)};
        if (ob != std::string::npos && ce != std::string::npos) {
            asn_block = r.body.substr(ob, ce - ob + 1);
        }
    }

    g.asn = json_get_str(asn_block, "asn");
    g.asn_org = json_get_str(asn_block, "org");
    if (g.asn.empty()) {
        g.asn = json_get_str(r.body, "asn");
    }

    const auto tf{[&](const char* k) { return json_get_str(r.body, k) == "true"; }};
    g.is_hosting = tf("is_datacenter") || tf("is_hosting");
    g.is_vpn = tf("is_vpn");
    g.is_proxy = tf("is_proxy");
    g.is_tor = tf("is_tor");
    g.is_abuser = tf("is_abuser");

    return g;
}

[[nodiscard]] GeoInfo geo_iplocate(std::string_view ip) {
    GeoInfo g;
    g.source = "iplocate.io";

    std::string url{"https://iplocate.io/api/lookup/"};
    if (!ip.empty()) {
        url += ip;
    }

    const auto r{http_get(url, 7000)};
    if (!r.ok()) {
        g.err = "http " + std::to_string(r.status) + " " + r.err;
        return g;
    }

    g.ip = json_get_str(r.body, "ip");
    g.country = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city = json_get_str(r.body, "city");

    // Extract ASN block
    std::string asn_block;
    const auto ap{r.body.find("\"asn\"")};
    if (ap != std::string::npos) {
        const auto ob{r.body.find('{', ap)};
        const auto ce{ob == std::string::npos ? std::string::npos : r.body.find('}', ob)};
        const auto comma{r.body.find(',', ap)};
        if (ob != std::string::npos && ce != std::string::npos &&
            ob < (comma == std::string::npos ? ce + 1 : comma)) {
            asn_block = r.body.substr(ob, ce - ob + 1);
        }
    }

    if (!asn_block.empty()) {
        g.asn = json_get_str(asn_block, "asn");
        g.asn_org = json_get_str(asn_block, "name");
        if (g.asn_org.empty()) {
            g.asn_org = json_get_str(asn_block, "org");
        }
    } else {
        g.asn = json_get_str(r.body, "asn");
        g.asn_org = json_get_str(r.body, "org");
    }

    g.is_hosting = json_get_str(r.body, "is_hosting") == "true";
    g.is_vpn = json_get_str(r.body, "is_vpn") == "true" ||
               json_get_str(r.body, "is_anonymous") == "true";
    g.is_proxy = json_get_str(r.body, "is_proxy") == "true";
    g.is_tor = json_get_str(r.body, "is_tor") == "true";

    return g;
}

[[nodiscard]] GeoInfo geo_ipwho_is(std::string_view ip) {
    GeoInfo g;
    g.source = "ipwho.is";

    std::string url{"https://ipwho.is/"};
    if (!ip.empty()) {
        url += ip;
    }

    const auto r{http_get(url, 7000)};
    if (!r.ok()) {
        g.err = "http " + std::to_string(r.status) + " " + r.err;
        return g;
    }

    g.ip = json_get_str(r.body, "ip");
    g.country = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city = json_get_str(r.body, "city");

    // Extract connection block
    const auto cp{r.body.find("\"connection\"")};
    if (cp != std::string::npos) {
        const auto ob{r.body.find('{', cp)};
        const auto ce{ob == std::string::npos ? std::string::npos : r.body.find('}', ob)};
        if (ob != std::string::npos && ce != std::string::npos) {
            const std::string sb{r.body.substr(ob, ce - ob + 1)};
            g.asn = json_get_str(sb, "asn");
            g.asn_org = json_get_str(sb, "isp");
            if (g.asn_org.empty()) {
                g.asn_org = json_get_str(sb, "org");
            }
        }
    }

    return g;
}

[[nodiscard]] GeoInfo geo_ipinfo_io(std::string_view ip) {
    GeoInfo g;
    g.source = "ipinfo.io";

    std::string url{"https://ipinfo.io/"};
    if (!ip.empty()) {
        url += ip;
    }
    url += "/json";

    const auto r{http_get(url, 7000)};
    if (!r.ok()) {
        g.err = "http " + std::to_string(r.status) + " " + r.err;
        return g;
    }

    g.ip = json_get_str(r.body, "ip");
    g.country_code = json_get_str(r.body, "country");
    g.city = json_get_str(r.body, "city");

    // Parse org field (format: "AS12345 Org Name")
    const std::string orgraw{json_get_str(r.body, "org")};
    if (!orgraw.empty()) {
        if (orgraw.starts_with("AS")) {
            const auto sp{orgraw.find(' ')};
            if (sp != std::string::npos) {
                g.asn = orgraw.substr(0, sp);
                g.asn_org = orgraw.substr(sp + 1);
            } else {
                g.asn = orgraw;
            }
        } else {
            g.asn_org = orgraw;
        }
    }

    return g;
}

[[nodiscard]] GeoInfo geo_freeipapi(std::string_view ip) {
    GeoInfo g;
    g.source = "freeipapi.com";

    std::string url{"https://freeipapi.com/api/json/"};
    if (!ip.empty()) {
        url += ip;
    }

    const auto r{http_get(url, 7000)};
    if (!r.ok()) {
        g.err = "http " + std::to_string(r.status) + " " + r.err;
        return g;
    }

    g.ip = json_get_str(r.body, "ipAddress");
    g.country = json_get_str(r.body, "countryName");
    g.country_code = json_get_str(r.body, "countryCode");
    g.city = json_get_str(r.body, "cityName");

    return g;
}

[[nodiscard]] GeoInfo geo_2ip_ru(std::string_view ip) {
    GeoInfo g;
    g.source = "2ip.me (RU)";

    std::string url{"https://api.2ip.me/geo.json"};
    if (!ip.empty()) {
        url += "?ip=";
        url += url_encode(std::string{ip});
    }

    const auto r{http_get(url, 7000)};
    if (!r.ok()) {
        g.err = "http " + std::to_string(r.status) + " " + r.err;
        return g;
    }

    g.ip = json_get_str(r.body, "ip");
    if (g.ip.empty()) {
        g.ip = std::string{ip};
    }

    g.country = json_get_str(r.body, "country");
    if (g.country.empty()) g.country = json_get_str(r.body, "country_rus");
    if (g.country.empty()) g.country = json_get_str(r.body, "countryName");

    g.country_code = json_get_str(r.body, "country_code");
    if (g.country_code.empty()) g.country_code = json_get_str(r.body, "countryCode");

    g.city = json_get_str(r.body, "city");
    if (g.city.empty()) g.city = json_get_str(r.body, "city_rus");
    if (g.city.empty()) g.city = json_get_str(r.body, "cityName");

    const std::string org{json_get_str(r.body, "org")};
    if (!org.empty()) {
        g.asn_org = org;
    }

    return g;
}

[[nodiscard]] GeoInfo geo_sypex(std::string_view ip) {
    GeoInfo g;
    g.source = "sypexgeo.net (RU)";

    const std::string url{"https://api.sypexgeo.net/json/" + std::string{ip}};
    const auto r{http_get(url, 7000)};
    
    if (!r.ok()) {
        g.err = "http " + std::to_string(r.status) + " " + r.err;
        return g;
    }

    g.ip = std::string{ip};
    g.country_code = json_get_str(r.body, "iso");

    // Extract country block
    {
        const auto cp{r.body.find("\"country\"")};
        if (cp != std::string::npos) {
            const auto ob{r.body.find('{', cp)};
            const auto ce{ob == std::string::npos ? std::string::npos : r.body.find('}', ob)};
            if (ob != std::string::npos && ce != std::string::npos) {
                const std::string sb{r.body.substr(ob, ce - ob + 1)};
                g.country = json_get_str(sb, "name_en");
                if (g.country.empty()) g.country = json_get_str(sb, "name_ru");
                if (g.country_code.empty()) g.country_code = json_get_str(sb, "iso");
            }
        }
    }

    // Extract city block
    {
        const auto cp{r.body.find("\"city\"")};
        if (cp != std::string::npos) {
            const auto ob{r.body.find('{', cp)};
            const auto ce{ob == std::string::npos ? std::string::npos : r.body.find('}', ob)};
            if (ob != std::string::npos && ce != std::string::npos) {
                const std::string sb{r.body.substr(ob, ce - ob + 1)};
                g.city = json_get_str(sb, "name_en");
                if (g.city.empty()) g.city = json_get_str(sb, "name_ru");
            }
        }
    }

    return g;
}

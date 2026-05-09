#include "orchestrator.h"

#include "../analysis/brand_cert.h"
#include "../analysis/ct_check.h"
#include "../analysis/sni_consistency.h"
#include "../core/utils.h"
#include "../network/https_probe.h"
#include "../network/j3_probes.h"
#include "../network/port_scan.h"
#include "../network/tls_probe.h"
#include "../network/vpn_probes.h"

#include <algorithm>
#include <array>
#include <future>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

struct UdpPlan {
    int port;
    const char* label;
    bool use_awg;
};

constexpr std::array<UdpPlan, 3> kUdpPlans{{
    {51820, "WireGuard handshake", false},
    {41641, "WireGuard alt-port handshake", false},
    {55555, "AmneziaWG handshake (Sx=8)", true},
}};

constexpr std::array<int, 22> kTlsPorts{{
    443, 4433, 4443, 8443, 9443, 10443, 14443, 20443, 21443, 22443,
    50443, 51443, 55443, 2083, 2087, 2096, 6443, 7443, 2053,
    8843, 44443, 46443,
}};

constexpr std::array<int, 8> kHttpPorts{{80, 81, 8080, 8081, 8088, 8888, 3128, 8000}};
constexpr std::array<int, 8> kSocksPorts{{1080, 1081, 1082, 9050, 10808, 10809, 10810, 7890}};

template <size_t N>
bool in_ports(const int port, const std::array<int, N>& ports) {
    return std::find(ports.begin(), ports.end(), port) != ports.end();
}

bool is_tls_port(const int port) {
    return in_ports(port, kTlsPorts);
}

bool has_token(const std::string& value, const std::vector<std::string>& needles) {
    const std::string low = tolower_s(value);
    return std::any_of(needles.begin(), needles.end(), [&](const std::string& n) {
        return contains(low, n);
    });
}

bool is_known_cdn_asn(const std::string& asn_org) {
    static const std::vector<std::string> kCdnAsnNeedles = {
        "cloudflare",
        "akamai",
        "fastly",
        "amazon",
        "aws",
        "google",
        "gcp",
        "microsoft",
        "azure",
        "edgecast",
        "edgio",
        "cdn77",
        "cachefly",
        "ddos-guard",
        "verizon media",
        "limelight",
        "stackpath",
        "bunny",
        "cloudfront",
        "netflix"
    };
    return has_token(asn_org, kCdnAsnNeedles);
}

bool looks_like_cdn_lb(const FullReport::PortFp& pf, const std::vector<std::string>& asn_orgs) {
    static const std::vector<std::string> kServerNeedles = {
        "envoy",
        "cloudflare",
        "cloudfront",
        "akamai",
        "fastly",
        "varnish",
        "gws",
        "awselb",
        "elb",
        "edge"
    };

    if (std::any_of(asn_orgs.begin(), asn_orgs.end(), [](const std::string& org) { return is_known_cdn_asn(org); })) {
        return true;
    }

    if (pf.https) {
        if (has_token(pf.https->server_hdr, kServerNeedles)) return true;
        if (pf.https->has_cdn_hdr) return true;
    }

    return false;
}

struct ScoreBook {
    int score = 100;
    std::vector<std::string> strong;
    std::vector<std::string> soft;
    std::vector<std::pair<std::string, std::string>> notes;

    void strong_signal(std::string text, int penalty) {
        strong.push_back(std::move(text));
        score -= penalty;
    }

    void soft_signal(std::string text, int penalty) {
        soft.push_back(std::move(text));
        score -= penalty;
    }

    void note(std::string tag, std::string text) {
        notes.emplace_back(std::move(tag), std::move(text));
    }

    void clamp() {
        score = std::clamp(score, 0, 100);
    }
};

GeoInfo safe_get_geo(std::future<GeoInfo>& f, const char* source) {
    try {
        return f.get();
    } catch (const std::exception& e) {
        GeoInfo g;
        g.source = source;
        g.err = e.what();
        return g;
    } catch (...) {
        GeoInfo g;
        g.source = source;
        g.err = "unknown exception";
        return g;
    }
}

void print_geo_line(const GeoInfo& g) {
    if (!g.err.empty()) {
        tee_printf("  %s%-12s%s %serr: %s%s\n",
                   col(C::CYN), g.source.c_str(), col(C::RST),
                   col(C::RED), g.err.c_str(), col(C::RST));
        return;
    }

    tee_printf("  %s%-12s%s IP %s%-15s%s  %s%s%s  (%s) AS %s %s\n",
               col(C::CYN), g.source.c_str(), col(C::RST),
               col(C::WHT), g.ip.c_str(), col(C::RST),
               col(C::BOLD), g.country_code.empty() ? g.country.c_str() : g.country_code.c_str(), col(C::RST),
               g.city.c_str(), g.asn.c_str(), g.asn_org.c_str());

    std::string flags;
    const auto append_flag = [&](const bool on, const char* name, const char* color) {
        if (!on) return;
        if (!flags.empty()) flags += ' ';
        flags += col(color);
        flags += name;
        flags += col(C::RST);
    };

    append_flag(g.is_hosting, "HOSTING", C::YEL);
    append_flag(g.is_vpn, "VPN", C::RED);
    append_flag(g.is_proxy, "PROXY", C::RED);
    append_flag(g.is_tor, "TOR", C::RED);

    if (!flags.empty()) tee_printf("               flags: %s\n", flags.c_str());
}



} // namespace

FullReport run_full_target(const std::string& target) {
    FullReport R;
    R.target = target;

    tee_printf("\n%s[1/7] DNS resolve%s\n", col(C::BOLD), col(C::RST));
    R.dns = resolve_host(target);
    if (!R.dns.err.empty()) {
        tee_printf("  %sERR%s: %s\n", col(C::RED), col(C::RST), R.dns.err.c_str());
        return R;
    }

    tee_printf("  %s%s%s  ->  ", col(C::WHT), target.c_str(), col(C::RST));
    for (const auto& ip : R.dns.ips) tee_printf("%s ", ip.c_str());
    tee_printf("[%s, %lldms]\n", R.dns.family.c_str(), R.dns.ms);

    if (R.dns.primary_ip != target) {
        tee_printf("  %susing primary IP%s %s%s%s for all probes\n",
                   col(C::DIM), col(C::RST),
                   col(C::BOLD), R.dns.primary_ip.c_str(), col(C::RST));
    }

    if (g_no_geoip) {
        tee_printf("\n%s[2/7] GeoIP%s  SKIPPED (--no-geoip / --stealth)\n",
                   col(C::BOLD), col(C::RST));
    } else {
        tee_printf("\n%s[2/7] GeoIP%s  (7 HTTPS providers in parallel)\n", col(C::BOLD), col(C::RST));

        auto fg_eu1 = std::async(std::launch::async, geo_ipapi_is, R.dns.primary_ip);
        auto fg_eu2 = std::async(std::launch::async, geo_iplocate, R.dns.primary_ip);
        auto fg_eu3 = std::async(std::launch::async, geo_freeipapi, R.dns.primary_ip);
        auto fg_ru1 = std::async(std::launch::async, geo_2ip_ru, R.dns.primary_ip);
        auto fg_ru2 = std::async(std::launch::async, geo_sypex, R.dns.primary_ip);
        auto fg_gl1 = std::async(std::launch::async, geo_ipwho_is, R.dns.primary_ip);
        auto fg_gl2 = std::async(std::launch::async, geo_ipinfo_io, R.dns.primary_ip);

        R.geos.push_back(safe_get_geo(fg_eu1, "ipapi.is"));
        R.geos.push_back(safe_get_geo(fg_eu2, "iplocate.io"));
        R.geos.push_back(safe_get_geo(fg_eu3, "freeipapi.com"));
        R.geos.push_back(safe_get_geo(fg_ru1, "2ip.ru"));
        R.geos.push_back(safe_get_geo(fg_ru2, "sypexgeo.net"));
        R.geos.push_back(safe_get_geo(fg_gl1, "ipwho.is"));
        R.geos.push_back(safe_get_geo(fg_gl2, "ipinfo.io"));

        for (const auto& g : R.geos) print_geo_line(g);
    }

    const auto ports = build_tcp_ports();
    const char* mode_name =
        g_port_mode == PortMode::FULL ? "FULL 1-65535" :
        g_port_mode == PortMode::FAST ? "FAST" :
        g_port_mode == PortMode::RANGE ? "RANGE" : "LIST";

    const char* tcp_method =
#if defined(_WIN32)
        "IOCP connect";
#else
        (g_tcp_syn_scan ? "SYN half-open" : "epoll connect");
#endif

    tee_printf("\n%s[3/7] TCP port scan%s  mode=%s%s%s  method=%s%s%s  (%zu ports, %d inflight, %dms timeout)\n",
               col(C::BOLD), col(C::RST),
               col(C::CYN), mode_name, col(C::RST),
               col(C::CYN), tcp_method, col(C::RST),
               ports.size(), g_threads, g_tcp_to);

    R.open_tcp = scan_tcp(R.dns.primary_ip, ports, g_threads, g_tcp_to, &R.scan_stats);

    if (R.open_tcp.empty()) {
        tee_printf("  %sno open TCP ports found%s\n", col(C::YEL), col(C::RST));
    } else {
        for (const auto& o : R.open_tcp) {
            tee_printf("  %s:%-5d%s  %3lldms  %s%s%s",
                       col(C::GRN), o.port, col(C::RST),
                       o.connect_ms,
                       col(C::DIM), port_hint(o.port), col(C::RST));
            if (!o.banner.empty()) {
                tee_printf("  %sbanner:%s %s", col(C::CYN), col(C::RST), printable_prefix(o.banner, 60).c_str());
            }
            tee_printf("\n");
        }
    }

    tee_printf("\n%s[4/7] UDP active probes%s  (WG / AmneziaWG only)\n", col(C::BOLD), col(C::RST));
    for (const auto& plan : kUdpPlans) {
        UdpResult u = plan.use_awg
            ? amneziawg_probe(R.dns.primary_ip, plan.port)
            : wireguard_probe(R.dns.primary_ip, plan.port);

        R.udp_probes.push_back({plan.port, u});

        tee_printf("  %sUDP:%-5d%s  %-32s  ",
                   u.responded ? col(C::GRN) : col(C::DIM),
                   plan.port,
                   col(C::RST),
                   plan.label);

        if (u.responded) {
            tee_printf("%sRESP %dB%s  %s\n", col(C::GRN), u.bytes, col(C::RST), u.reply_hex.c_str());
        } else {
            tee_printf("%sno answer (%s)%s\n", col(C::DIM), u.err.empty() ? "closed/filtered" : u.err.c_str(), col(C::RST));
        }
    }

    tee_printf("\n%s[5/7] Service and TLS fingerprints%s\n", col(C::BOLD), col(C::RST));

    for (const auto& o : R.open_tcp) {
        FullReport::PortFp pf;
        pf.port = o.port;
        bool printed = false;

        const auto line = [&](const FpResult& f) {
            tee_printf("  %s:%-5d%s  %s%-16s%s  %s",
                       col(C::CYN), o.port, col(C::RST),
                       col(C::BOLD), f.service.c_str(), col(C::RST),
                       f.details.c_str());
            if (f.is_vpn_like) tee_printf("  %s[vpn-like]%s", col(C::YEL), col(C::RST));
            tee_printf("\n");
        };

        if (starts_with(o.banner, "SSH-") || o.port == 22 || o.port == 2222 || o.port == 22222) {
            pf.fp = fp_ssh(o.banner, R.dns.primary_ip, o.port);
            line(pf.fp);
            printed = true;
        }

        if (is_tls_port(o.port)) {
            TlsProbe tp = tls_probe(R.dns.primary_ip, o.port, R.dns.host);
            pf.tls = tp;

            if (tp.ok) {
                FpResult f;
                f.service = "TLS";
                f.details = tp.version + " / " + tp.cipher + " / ALPN=" + (tp.alpn.empty() ? "-" : tp.alpn) +
                            " / " + tp.group + " / " + std::to_string(tp.handshake_ms) + "ms";
                pf.fp = f;
                line(f);

                tee_printf("        cert CN=%s  issuer=%s  age=%dd left=%dd SAN=%d%s%s\n",
                           tp.subject_cn.empty() ? "(none)" : tp.subject_cn.c_str(),
                           tp.issuer_cn.empty() ? "(none)" : tp.issuer_cn.c_str(),
                           tp.age_days,
                           tp.days_left,
                           tp.san_count,
                           tp.is_wildcard ? " wildcard" : "",
                           tp.self_signed ? " self-signed" : "");

                SniConsistency sc = sni_consistency(R.dns.primary_ip, o.port, R.dns.host);
                pf.sni = sc;
                if (sc.reality_like) {
                    tee_printf("        %sSNI steering pattern detected%s (matched foreign SNI: %s)%s\n",
                               col(C::GRN), col(C::RST),
                               sc.matched_foreign_sni.empty() ? "-" : sc.matched_foreign_sni.c_str(),
                               sc.passthrough_mode ? " [passthrough]" : "");
                } else if (sc.default_cert_only || sc.same_cert_always) {
                    tee_printf("        %sSNI behaviour looks like regular non-Reality TLS%s\n", col(C::DIM), col(C::RST));
                } else {
                    tee_printf("        %sSNI cert varies per host (multi-tenant / vhost style)%s\n", col(C::DIM), col(C::RST));
                }

                if (!g_no_ct && !sc.base_sha.empty()) {
                    CtCheck ct = ct_check(sc.base_sha, true);
                    pf.ct = ct;
                    if (ct.queried && !ct.err.empty()) {
                        tee_printf("        %sCT lookup failed:%s %s\n", col(C::DIM), col(C::RST), ct.err.c_str());
                    } else if (ct.queried && ct.found) {
                        tee_printf("        %sCT log:%s found (%d entries)\n", col(C::GRN), col(C::RST), ct.log_entries);
                    } else if (ct.queried && !ct.found) {
                        tee_printf("        %sCT log:%s not found\n", col(C::YEL), col(C::RST));
                    }
                }

                HttpsProbe hp = https_probe(R.dns.primary_ip, o.port, R.dns.host);
                pf.https = hp;
                if (hp.tls_ok && hp.responded) {
                    tee_printf("        HTTP-over-TLS: %s%s%s",
                               hp.version_anomaly ? col(C::RED) : col(C::GRN),
                               printable_prefix(hp.first_line, 72).c_str(),
                               col(C::RST));
                    if (!hp.server_hdr.empty()) tee_printf("  Server: %s", printable_prefix(hp.server_hdr, 40).c_str());
                    tee_printf("\n");
                } else if (hp.tls_ok) {
                    tee_printf("        %sHTTP-over-TLS: no HTTP response after successful handshake%s\n", col(C::YEL), col(C::RST));
                }
            } else {
                FpResult f;
                f.service = "TLS-FAIL";
                f.details = tp.err;
                pf.fp = f;
                line(f);
            }

            printed = true;
        }

        if (in_ports(o.port, kHttpPorts)) {
            const FpResult hp = fp_http_plain(R.dns.primary_ip, o.port);
            if (!hp.details.empty() || hp.silent) {
                pf.fp = hp;
                line(hp);
                printed = true;
            }

            const FpResult proxy = fp_http_connect(R.dns.primary_ip, o.port);
            if (proxy.service == "HTTP-PROXY") {
                pf.fp = proxy;
                line(proxy);
                printed = true;
            }
        }

        if (in_ports(o.port, kSocksPorts)) {
            const FpResult socks = fp_socks5(R.dns.primary_ip, o.port);
            pf.fp = socks;
            line(socks);
            printed = true;
        }

        if (!printed) {
            FpResult unknown;
            unknown.service = "unknown";
            unknown.details = o.banner.empty()
                ? "open but silent on connect"
                : "banner: " + printable_prefix(o.banner, 70);
            pf.fp = unknown;

            if (!o.banner.empty() || R.open_tcp.size() < 20) {
                line(unknown);
            }
        }

        R.fps.push_back(std::move(pf));
    }

    tee_printf("\n%s[6/7] Active junk probing (J3)%s\n", col(C::BOLD), col(C::RST));
    for (auto& pf : R.fps) {
        if (!is_tls_port(pf.port) && pf.port != 80 && pf.port != 8080) continue;

        tee_printf("  %s-> port :%d%s\n", col(C::BOLD), pf.port, col(C::RST));
        auto probes = j3_probes(R.dns.primary_ip, pf.port);

        for (const auto& p : probes) {
            tee_printf("     %s%-7s%s  %-28s  ",
                       p.responded ? col(C::YEL) : col(C::GRN),
                       p.responded ? "RESP" : "SILENT",
                       col(C::RST),
                       p.name.c_str());
            if (p.responded) {
                tee_printf("%dB  %s\n", p.bytes, printable_prefix(p.first_line, 50).c_str());
            } else {
                tee_printf("(dropped)\n");
            }
        }

        pf.j3 = probes;
        pf.j3a = j3_analyze(pf.j3);

        const int silent = pf.j3a->silent;
        const int resp = pf.j3a->resp;
        const char* verdict =
            silent >= 6 ? "strict silent-on-junk" :
            resp >= 6 ? "permissive web-like" : "mixed";

        tee_printf("     %s-> %s%s  (silent=%d / resp=%d)\n",
                   col(C::MAG), verdict, col(C::RST), silent, resp);
    }

    tee_printf("\n%s[7/7] Verdict%s\n", col(C::BOLD), col(C::RST));

    std::set<int> openset;
    for (const auto& o : R.open_tcp) openset.insert(o.port);

    ScoreBook book;

    const auto responded_on = [&](const int port) {
        return std::any_of(R.udp_probes.begin(), R.udp_probes.end(), [port](const auto& x) {
            return x.first == port && x.second.responded;
        });
    };

    const bool wg_default = responded_on(51820);
    const bool wg_alt = responded_on(41641);
    const bool awg_default = responded_on(55555);

    if (wg_default) {
        book.strong_signal("WireGuard handshake accepted on UDP/51820 (default signature)", 22);
    }
    if (wg_alt) {
        book.soft_signal("WireGuard-like handshake accepted on UDP/41641", 4);
    }
    if (awg_default) {
        book.strong_signal("AmneziaWG handshake accepted on UDP/55555 (obfuscated WG profile)", 18);
    }

    const int hosting_hits = static_cast<int>(std::count_if(R.geos.begin(), R.geos.end(), [](const GeoInfo& g) {
        return g.is_hosting;
    }));

    if (hosting_hits > 0) {
        book.note("asn-hosting", "hosting/datacenter ASN is normal for public infrastructure");
    }

    bool any_tls = false;
    bool any_reality = false;
    bool any_impersonation = false;
    bool any_proxy_open = false;
    bool any_j3_canned = false;
    bool any_j3_badver = false;
    bool any_ct_absent_fresh = false;
    bool any_cdn_lb_detected = false;

    std::vector<std::string> asn_orgs;
    for (const auto& g : R.geos) {
        if (!g.asn_org.empty()) asn_orgs.push_back(g.asn_org);
    }

    for (const auto& pf : R.fps) {
        const bool cdn_lb_port = looks_like_cdn_lb(pf, asn_orgs);
        if (cdn_lb_port) {
            any_cdn_lb_detected = true;
            book.note("cdn-lb", "CDN/load-balancer traits on :" + std::to_string(pf.port) + ", suppressing SNI-impersonation penalties");
        }

        if (pf.fp.service == "HTTP-PROXY") {
            any_proxy_open = true;
            book.strong_signal("open HTTP CONNECT proxy exposed on :" + std::to_string(pf.port), 15);
        } else if (pf.fp.service == "SOCKS5") {
            any_proxy_open = true;
            book.strong_signal("open SOCKS5 proxy exposed on :" + std::to_string(pf.port), 15);
        }

        if (pf.tls && pf.tls->ok) {
            any_tls = true;

            if (pf.tls->version != "TLSv1.3") {
                book.soft_signal("TLS < 1.3 on :" + std::to_string(pf.port), 5);
            }
            if (pf.tls->self_signed) {
                book.strong_signal("self-signed certificate on :" + std::to_string(pf.port), 8);
            }
            if (pf.tls->age_days >= 0 && pf.tls->age_days < 14) {
                book.note("cert-fresh", "fresh certificate on :" + std::to_string(pf.port) + " (rotation alone is not a reliable signal)");
            }
        }

        if (pf.sni && pf.sni->reality_like) {
            if (cdn_lb_port) {
                book.note("sni-cdn", "SNI mismatch on :" + std::to_string(pf.port) + " looks CDN/LB-driven, not VPN-specific");
            } else {
                any_reality = true;
                const int penalty = pf.sni->passthrough_mode ? 20 : 16;
                book.strong_signal("Reality/XTLS SNI steering on :" + std::to_string(pf.port), penalty);

                if (pf.sni->cert_impersonation && !pf.sni->brand_claimed.empty()) {
                    const bool owns = asn_owns_brand(pf.sni->brand_claimed, asn_orgs);
                    if (!owns) {
                        any_impersonation = true;
                        book.strong_signal("cert claims brand '" + pf.sni->brand_claimed + "' on non-owning ASN", 18);
                    }
                }
            }
        }

        if (pf.https && pf.https->tls_ok) {
            if (pf.https->responded && pf.https->version_anomaly) {
                book.strong_signal("invalid HTTP version over TLS on :" + std::to_string(pf.port), 14);
            } else if (!pf.https->responded) {
                book.soft_signal("TLS handshake succeeded but no HTTP response on :" + std::to_string(pf.port), 8);
            } else if (pf.https->server_hdr.empty()) {
                book.soft_signal("HTTP response without Server header on :" + std::to_string(pf.port), 4);
            }

            if (pf.https->has_proxy_leak) {
                if (cdn_lb_port) {
                    book.note("proxy-hdr", "forwarding headers on :" + std::to_string(pf.port) + " are expected for CDN/LB edges");
                } else {
                    book.strong_signal("proxy-chain headers leaked by HTTPS origin on :" + std::to_string(pf.port), 10);
                }
            }
        }

        if (pf.ct && pf.ct->queried && !pf.ct->found && pf.ct->err.empty()) {
            if (pf.tls && pf.tls->ok && pf.tls->age_days >= 0 && pf.tls->age_days < 30) {
                any_ct_absent_fresh = true;
                book.strong_signal("fresh cert missing from CT logs on :" + std::to_string(pf.port), 10);
            } else {
                book.note("ct-miss", "certificate not found in CT logs on :" + std::to_string(pf.port));
            }
        }

        if (pf.j3a) {
            if (pf.j3a->canned_identical >= 2) {
                any_j3_canned = true;
                book.strong_signal("canned fallback page under active probing on :" + std::to_string(pf.port), 12);
            }
            if (pf.j3a->http_bad_version >= 1) {
                any_j3_badver = true;
                book.strong_signal("malformed HTTP version under active probing on :" + std::to_string(pf.port), 12);
            }
            if (pf.j3a->raw_non_http >= 2 && pf.j3a->http_real == 0) {
                book.soft_signal("raw non-HTTP replies under active probing on :" + std::to_string(pf.port), 6);
            }
        }
    }

    book.clamp();
    R.score = book.score;

    if (R.score >= 85) R.label = "CLEAN";
    else if (R.score >= 70) R.label = "LOW-SIGNAL";
    else if (R.score >= 50) R.label = "SUSPICIOUS";
    else R.label = "HIGH-CONFIDENCE";

    const char* verdict_color = R.score >= 85 ? C::GRN : R.score >= 50 ? C::YEL : C::RED;

    std::string stack_name;
    if (any_reality && awg_default) {
        stack_name = "VLESS / XTLS-Reality + AmneziaWG";
    } else if (any_reality) {
        stack_name = "VLESS / XTLS-Reality";
    } else if (awg_default) {
        stack_name = "Amnezia WireGuard";
    } else if (wg_default || wg_alt) {
        stack_name = "WireGuard";
    } else if (any_tls && openset.count(443) > 0) {
        stack_name = "generic TLS origin";
    } else {
        stack_name = "no signature-less VPN indicator";
    }

    R.guess_stack.push_back(stack_name);

    tee_printf("\n  %sStack identified:%s  %s%s%s\n",
               col(C::BOLD), col(C::RST),
               col(C::CYN), stack_name.c_str(), col(C::RST));

    tee_printf("\n  %sStrong signals (%zu)%s\n", col(C::BOLD), book.strong.size(), col(C::RST));
    if (book.strong.empty()) {
        tee_printf("    (none)\n");
    } else {
        for (const auto& s : book.strong) {
            tee_printf("    %s[!]%s %s\n", col(C::RED), col(C::RST), s.c_str());
        }
    }

    tee_printf("\n  %sSoft signals (%zu)%s\n", col(C::BOLD), book.soft.size(), col(C::RST));
    if (book.soft.empty()) {
        tee_printf("    (none)\n");
    } else {
        for (const auto& s : book.soft) {
            tee_printf("    %s[-]%s %s\n", col(C::YEL), col(C::RST), s.c_str());
        }
    }

    tee_printf("\n  %sInformational (%zu)%s\n", col(C::BOLD), book.notes.size(), col(C::RST));
    if (book.notes.empty()) {
        tee_printf("    (none)\n");
    } else {
        for (const auto& [tag, text] : book.notes) {
            tee_printf("    %s[i]%s %s%s%s  %s\n", col(C::CYN), col(C::RST), col(C::DIM), tag.c_str(), col(C::RST), text.c_str());
        }
    }

    tee_printf("\n  %sFinal score:%s %s%d/100%s  verdict: %s%s%s\n",
               col(C::BOLD), col(C::RST),
               col(C::BOLD), R.score, col(C::RST),
               col(verdict_color), R.label.c_str(), col(C::RST));

    tee_printf("\n  %sDPI exposure matrix:%s\n", col(C::BOLD), col(C::RST));
    const auto axis = [&](const char* name, const char* level, const std::string& note) {
        const char* c = std::string_view(level) == "HIGH" ? C::RED
                       : std::string_view(level) == "MEDIUM" ? C::YEL
                       : std::string_view(level) == "LOW" ? C::GRN
                       : C::DIM;
        tee_printf("    %-34s %s%-6s%s  %s\n", name, col(c), level, col(C::RST), note.c_str());
    };

    axis("WireGuard handshake", wg_default ? "HIGH" : (wg_alt ? "MEDIUM" : "NONE"),
         wg_default ? "UDP/51820 handshake matched"
                    : wg_alt ? "only alt-port handshake matched"
                             : "no WG handshake reply");

    axis("AmneziaWG handshake", awg_default ? "HIGH" : "NONE",
         awg_default ? "UDP/55555 obfuscated handshake matched" : "no AWG reply");

    axis("Reality cert steering", any_reality ? "HIGH" : "NONE",
         any_reality ? "SNI steering pattern matched" : "no Reality steering pattern");

    axis("Cert impersonation", any_impersonation ? "HIGH" : "NONE",
         any_impersonation ? "brand cert/ASN ownership mismatch" : "no cert/ASN brand mismatch");

    axis("Active probing anomalies", (any_j3_canned || any_j3_badver) ? "HIGH" : "LOW",
         (any_j3_canned || any_j3_badver) ? "canned fallback or malformed HTTP version observed"
                                          : "no hard active-probing anomalies");

    axis("CT freshness mismatch", any_ct_absent_fresh ? "MEDIUM" : "LOW",
         any_ct_absent_fresh ? "fresh cert absent from CT logs" : "no fresh CT mismatch observed");

    axis("Open proxy exposure", any_proxy_open ? "HIGH" : "NONE",
         any_proxy_open ? "HTTP/SOCKS proxy reachable from WAN" : "no open proxy fingerprint");

    axis("CDN/LB environment", any_cdn_lb_detected ? "LOW" : "NONE",
         any_cdn_lb_detected ? "CDN/LB traits detected; SNI mismatch heuristics are down-weighted" : "no CDN/LB traits detected");

    axis("Network-level filtering", "NONE", "timeout-wall heuristic removed from scoring");

    tee_printf("\n  %sHardening suggestions:%s\n", col(C::BOLD), col(C::RST));
    bool any_suggestion = false;

    const auto suggest = [&](const char* tag, const char* text) {
        tee_printf("    %s[%s]%s\n      %s\n", col(C::GRN), tag, col(C::RST), text);
        any_suggestion = true;
    };

    if (wg_default && !awg_default) {
        suggest("wireguard",
                "WG default signature is exposed on UDP/51820. Move to non-default ports and/or"
                " switch to AmneziaWG transport obfuscation for DPI resistance.");
    }

    if (any_reality && any_impersonation) {
        suggest("reality-dest",
                "Reality dest/cert points to a brand outside your ASN footprint. Use a dest that"
                " is ASN-consistent with your infrastructure or terminate with your own domain cert.");
    }

    if (any_j3_canned || any_j3_badver) {
        suggest("fallback-shape",
                "Active probes observe canned or malformed fallback output. Route unknown traffic"
                " to a real web stack so fallback responses match normal HTTP server behaviour.");
    }

    if (any_proxy_open) {
        suggest("open-proxy",
                "Close WAN exposure for SOCKS/HTTP CONNECT listeners. Restrict by source ACL or"
                " bind only to loopback/overlay interfaces.");
    }

    if (awg_default) {
        suggest("amneziawg",
                "Keep AmneziaWG parameters rotated and avoid publishing fixed fingerprints in"
                " public configs. Pair with regular cert/key hygiene on adjacent TLS services.");
    }

    if (!any_suggestion) {
        tee_printf("    (no urgent hardening required)\n");
    }

    tee_printf("\n  %sTSPU classification (emulated):%s\n", col(C::BOLD), col(C::RST));
    {
        struct Rule {
            const char* name;
            bool hit;
            const char* why;
            bool tier_a;
        };

        const std::array<Rule, 6> rules{{
            {"WireGuard signature", wg_default, "UDP/51820 handshake reply", true},
            {"AmneziaWG signature", awg_default, "UDP/55555 obfuscated handshake reply", true},
            {"Open proxy exposure", any_proxy_open, "SOCKS/HTTP CONNECT reachable", true},
            {"Reality cert-steering", any_reality, "SNI steering discriminator", false},
            {"Cert impersonation", any_impersonation, "brand cert/ASN mismatch", false},
            {"Active-probe anomalies", any_j3_canned || any_j3_badver, "canned/malformed HTTP fallback", false},
        }};

        int a_hits = 0;
        int b_hits = 0;
        for (const auto& r : rules) {
            if (!r.hit) continue;
            if (r.tier_a) ++a_hits; else ++b_hits;
        }

        const char* tier_name = "PASS / ALLOW";
        const char* tier_desc = "no actionable signatures matched";
        const char* tier_color = C::GRN;

        if (a_hits > 0) {
            tier_name = "IMMEDIATE BLOCK";
            tier_desc = "A-tier protocol/proxy signatures matched";
            tier_color = C::RED;
        } else if (b_hits >= 2) {
            tier_name = "BLOCK (accumulative)";
            tier_desc = "multiple B-tier anomalies crossed confidence threshold";
            tier_color = C::RED;
        } else if (b_hits == 1) {
            tier_name = "MONITOR / THROTTLE";
            tier_desc = "single B-tier anomaly: monitor and sample further";
            tier_color = C::YEL;
        }

        tee_printf("    %sVerdict:%s %s%s%s — %s\n",
                   col(C::BOLD), col(C::RST),
                   col(tier_color), tier_name, col(C::RST), tier_desc);
        tee_printf("    %sTier hits:%s A=%d / B=%d\n", col(C::DIM), col(C::RST), a_hits, b_hits);

        if (a_hits + b_hits > 0) {
            tee_printf("    %sTriggered rules:%s\n", col(C::DIM), col(C::RST));
            for (const auto& r : rules) {
                if (!r.hit) continue;
                tee_printf("      %s[%c]%s %-30s  %s\n",
                           col(r.tier_a ? C::RED : C::YEL), r.tier_a ? 'A' : 'B', col(C::RST),
                           r.name, r.why);
            }
        }
    }

    tee_printf("\n  %sThreat-model note:%s\n", col(C::BOLD), col(C::RST));
    tee_printf("    This build focuses on remote, signature-less VPN profiling only: VLESS/Reality,\n"
               "    WireGuard and AmneziaWG. Legacy clear-signature protocols and local-host checks\n"
               "    are intentionally removed to keep scoring grounded in high-confidence network\n"
               "    evidence from remote active and passive probes.\n");

    return R;
}

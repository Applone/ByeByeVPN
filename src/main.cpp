#include "analysis/geoip.h"
#include "analysis/sni_consistency.h"
#include "cli/orchestrator.h"
#include "core/utils.h"
#include "network/dns.h"
#include "network/j3_probes.h"
#include "network/openssl_runtime.h"
#include "network/port_scan.h"
#include "network/tls_probe.h"
#include "network/udp_scanner.h"
#include "network/vpn_probes.h"

#include <openssl/ssl.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <future>
#include <limits>
#include <set>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/resource.h>
#endif

#if __cplusplus >= 202002L && __has_include(<format>)
#include <format>
#define BYEBYEVPN_HAS_STD_FORMAT 1
#else
#define BYEBYEVPN_HAS_STD_FORMAT 0
#endif

namespace {

using std::set;
using std::string;
using std::vector;

class Cleanup {
public:
    ~Cleanup() {
        if (g_save_fp) {
            fprintf(g_save_fp, "```\n");
            fclose(g_save_fp);
            g_save_fp = nullptr;
        }
        openssl_runtime_cleanup();
        fflush(stdout);
        fflush(stderr);
    }
};

bool try_parse_int(const string& s, int& out, const int min_v, const int max_v) {
    if (s.empty()) return false;
    char* endptr = nullptr;
    errno = 0;
    const long res = strtol(s.c_str(), &endptr, 10);
    if (errno != 0 || endptr == s.c_str() || *endptr != '\0' || res < min_v || res > max_v) return false;
    out = static_cast<int>(res);
    return true;
}

void clamp_threads_to_nofile_limit() {
#ifndef _WIN32
    constexpr int kNofileReserve = 128;

    rlimit lim{};
    if (getrlimit(RLIMIT_NOFILE, &lim) != 0) return;
    if (lim.rlim_cur == RLIM_INFINITY) return;

    const rlim_t reserve = static_cast<rlim_t>(kNofileReserve);
    if (lim.rlim_cur <= reserve) {
        if (g_threads != 1) {
            g_threads = 1;
            fprintf(stderr,
                    "warn: clamped --threads to %d due to RLIMIT_NOFILE soft=%llu (raise ulimit -n to allow more)\n",
                    g_threads,
                    static_cast<unsigned long long>(lim.rlim_cur));
        }
        return;
    }

    const rlim_t max_threads_rl = lim.rlim_cur - reserve;
    const int max_threads =
        max_threads_rl > static_cast<rlim_t>(std::numeric_limits<int>::max())
            ? std::numeric_limits<int>::max()
            : static_cast<int>(max_threads_rl);

    if (g_threads > max_threads) {
        g_threads = max_threads;
        fprintf(stderr,
                "warn: clamped --threads to %d due to RLIMIT_NOFILE soft=%llu (raise ulimit -n to allow more)\n",
                g_threads,
                static_cast<unsigned long long>(lim.rlim_cur));
    }
#endif
}

int parse_int_fatal(const char* s, const char* name, const int min_v, const int max_v) {
    int out = 0;
    if (!try_parse_int(s, out, min_v, max_v)) {
        fprintf(stderr, "Error: invalid value for %s: '%s' (expected %d-%d)\n", name, s, min_v, max_v);
        std::exit(1);
    }
    return out;
}

string extract_target_arg(const vector<string>& pos) {
    if (pos.empty()) return {};
    static const set<string> cmds = {
        "scan", "full", "ports", "udp", "tls", "j3", "geoip", "help"
    };
    if (pos.size() >= 2 && cmds.count(pos[0])) {
        if (pos[0] == "help") return {};
        return pos[1];
    }
    if (pos[0] == "help") return {};
    return pos[0];
}

string default_save_path_for_target(const string& target) {
    if (target.empty()) return "byebyevpn-scan.md";
    string safe;
    for (const char c : target) {
        if (c == ':' || c == '/' || c == '\\' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
            safe += '_';
        } else {
            safe += c;
        }
    }
    return "byebyevpn-" + safe + ".md";
}

void print_geo(const GeoInfo& g) {
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
    const auto add = [&](const bool v, const char* n, const char* c) {
        if (v) {
            if (!flags.empty()) flags += ' ';
            flags += col(c);
            flags += n;
            flags += col(C::RST);
        }
    };

    add(g.is_hosting, "HOSTING", C::YEL);
    add(g.is_vpn, "VPN", C::RED);
    add(g.is_proxy, "PROXY", C::RED);
    add(g.is_tor, "TOR", C::RED);
    add(g.is_abuser, "ABUSER", C::RED);

    if (!flags.empty()) tee_printf("               flags: %s\n", flags.c_str());
}

GeoInfo safe_get_geo(std::future<GeoInfo>& f, const std::string& source) {
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

void clear_screen() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
    fputs("\x1b[2J\x1b[H", stdout);
    fflush(stdout);
}

void help() {
    tee_printf("ByeByeVPN — remote server profiling for signature-less VPN detection\n\n");
    tee_printf("Usage:\n");
    tee_printf("  byebyevpn                      interactive menu\n");
    tee_printf("  byebyevpn <ip-or-host>         full scan (recommended)\n");
    tee_printf("  byebyevpn scan <ip>            full scan same\n");
    tee_printf("  byebyevpn ports <ip>           TCP port scan only\n");
    tee_printf("  byebyevpn udp <ip>             UDP WG/AWG probes only\n");
    tee_printf("  byebyevpn tls <ip> [port]      TLS + SNI consistency only\n");
    tee_printf("  byebyevpn j3 <ip> [port]       active junk probing only\n");
    tee_printf("  byebyevpn geoip <ip>           GeoIP only\n\n");

    tee_printf("Port-scan modes (default: --full):\n");
    tee_printf("  --full              scan ALL ports 1-65535  (default)\n");
    tee_printf("  --fast              curated port subset\n");
    tee_printf("  --range 1000-2000   scan a port range\n");
    tee_printf("  --ports 80,443,8443 scan explicit port list\n\n");

    tee_printf("Tuning:\n");
    tee_printf("  --threads N     parallel TCP connects   (default 1200)\n");
    tee_printf("  --tcp-to MS     TCP connect timeout      (default 1000)\n");
    tee_printf("  --udp-to MS     UDP recv timeout         (default 900)\n");
    tee_printf("  --syn           Linux-only TCP SYN half-open scan\n");
    tee_printf("  --no-color      disable ANSI colors\n");
    tee_printf("  -v / --verbose  verbose\n\n");

    tee_printf("Stealth / privacy:\n");
    tee_printf("  --stealth       enable --no-geoip + --no-ct + --udp-jitter\n");
    tee_printf("  --no-geoip      skip all 3rd-party GeoIP lookups\n");
    tee_printf("  --no-ct         skip crt.sh CT lookup\n");
    tee_printf("  --udp-jitter    add random delay between UDP probes\n\n");

    tee_printf("Save scan output:\n");
    tee_printf("  --save           write to byebyevpn-<target>.md\n");
    tee_printf("  --save <path>    write to custom path\n");
}

void pause_for_enter() {
    tee_printf("\n%s[Enter] to continue...%s", col(C::DIM), col(C::RST));
    fflush(stdout);
    int c;
    while ((c = getchar()) != EOF && c != '\n') {}
}

string ask(const string& prompt) {
    tee_printf("%s", prompt.c_str());
    fflush(stdout);
    char buf[256] = {0};
    if (!fgets(buf, sizeof(buf), stdin)) return {};
    return trim(buf);
}

void show_udp_wg(const string& ip) {
    const auto show = [&](const char* name, const int port, const UdpResult& u) {
        std::string status;
#if BYEBYEVPN_HAS_STD_FORMAT
        status = u.responded ? std::format("RESP {}B {}", u.bytes, u.reply_hex)
                             : std::format("no answer ({})", u.err);
#else
        if (u.responded) {
            status = "RESP " + std::to_string(u.bytes) + "B " + u.reply_hex;
        } else {
            status = "no answer (" + u.err + ")";
        }
#endif
        tee_printf("  UDP:%-5d  %-30s  %s\n", port, name, status.c_str());
    };

    show("WireGuard handshake", 51820, wireguard_probe(ip, 51820));
    show("WireGuard alt-port", 41641, wireguard_probe(ip, 41641));
    show("AmneziaWG (Sx=8)", 55555, amneziawg_probe(ip, 55555));
}

void interactive() {
    for (;;) {
        clear_screen();
        banner();
        tee_printf("  %s[1]%s  Full scan             — end-to-end remote profile\n", col(C::CYN), col(C::RST));
        tee_printf("  %s[2]%s  TCP port scan         — TCP scan only\n", col(C::CYN), col(C::RST));
        tee_printf("  %s[3]%s  UDP WG/AWG probes     — signature-less VPN probes\n", col(C::CYN), col(C::RST));
        tee_printf("  %s[4]%s  TLS + SNI consistency — Reality discriminator\n", col(C::CYN), col(C::RST));
        tee_printf("  %s[5]%s  J3 active probing     — active junk probes\n", col(C::CYN), col(C::RST));
        tee_printf("  %s[6]%s  GeoIP lookup          — country / ASN aggregation\n", col(C::CYN), col(C::RST));
        tee_printf("  %s[0]%s  Exit\n\n", col(C::CYN), col(C::RST));

        const string s = ask("  > ");
        if (s.empty()) continue;
        const char c = s[0];

        if (c == '0' || c == 'q' || c == 'Q') break;

        if (c == '1') {
            const string t = ask("  target (IP or hostname): ");
            if (!t.empty()) run_full_target(t);
            pause_for_enter();
            continue;
        }

        if (c == '2') {
            const string t = ask("  target IP or host: ");
            if (!t.empty()) {
                const auto rs = resolve_host(t);
                const auto op = scan_tcp(rs.primary_ip.empty() ? t : rs.primary_ip, build_tcp_ports(), g_threads, g_tcp_to);
                for (const auto& o : op) {
                    std::string extra;
                    if (!o.banner.empty()) {
                        extra = " banner=" + printable_prefix(o.banner, 60);
                    }
                    tee_printf("  :%-5d  %lldms  %s%s\n",
                               o.port,
                               o.connect_ms,
                               port_hint(o.port),
                               extra.c_str());
                }
            }
            pause_for_enter();
            continue;
        }

        if (c == '3') {
            const string t = ask("  target IP or host: ");
            if (!t.empty()) {
                const auto rs = resolve_host(t);
                const string ip = rs.primary_ip.empty() ? t : rs.primary_ip;
                show_udp_wg(ip);
            }
            pause_for_enter();
            continue;
        }

        if (c == '4') {
            const string t = ask("  target host (used as SNI): ");
            const string ps = ask("  port (default 443): ");
            int port = 443;
            if (!ps.empty() && !try_parse_int(ps, port, 1, 65535)) {
                tee_printf("  %serror: invalid port '%s', using default 443%s\n", col(C::RED), ps.c_str(), col(C::RST));
            }
            if (!t.empty()) {
                const auto rs = resolve_host(t);
                const string ip = rs.primary_ip.empty() ? t : rs.primary_ip;
                const auto tp = tls_probe(ip, port, t);
                if (!tp.ok) {
                    tee_printf("  TLS fail: %s\n", tp.err.c_str());
                } else {
                    tee_printf("  %s%s%s / %s / ALPN=%s / %s / %lldms\n",
                               col(C::BOLD), tp.version.c_str(), col(C::RST),
                               tp.cipher.c_str(), tp.alpn.c_str(), tp.group.c_str(), tp.handshake_ms);
                    tee_printf("  cert: %s\n", tp.cert_subject.c_str());
                    tee_printf("  issuer: %s\n", tp.cert_issuer.c_str());
                    tee_printf("  sha256: %s\n", tp.cert_sha256.c_str());

                    const auto sc = sni_consistency(ip, port, t);
                    for (const auto& e : sc.entries) {
#if BYEBYEVPN_HAS_STD_FORMAT
                        const std::string sha = e.ok ? std::format("sha:{}", e.sha.substr(0, 16)) : "fail";
#else
                        const std::string sha = e.ok ? ("sha:" + e.sha.substr(0, 16)) : "fail";
#endif
                        tee_printf("    alt SNI %-35s  %s  %s\n",
                                   e.sni.c_str(),
                                   sha.c_str(),
                                   (e.ok && e.sha == sc.base_sha) ? "SAME" : "diff");
                    }

                    if (sc.reality_like) {
                        tee_printf("  %s=> Reality/XTLS pattern (matched foreign SNI '%s')%s\n",
                                   col(C::GRN), sc.matched_foreign_sni.c_str(), col(C::RST));
                    } else if (sc.default_cert_only) {
                        tee_printf("  %s=> plain TLS server with a single default cert (NOT Reality)%s\n",
                                   col(C::CYN), col(C::RST));
                    } else if (sc.same_cert_always) {
                        tee_printf("  %s=> identical cert for all SNIs without foreign coverage (inconclusive)%s\n",
                                   col(C::YEL), col(C::RST));
                    } else {
                        tee_printf("  %s=> cert varies per SNI (multi-tenant TLS, not Reality)%s\n",
                                   col(C::YEL), col(C::RST));
                    }
                }
            }
            pause_for_enter();
            continue;
        }

        if (c == '5') {
            const string t = ask("  target IP or host: ");
            const string ps = ask("  port: ");
            if (!t.empty() && !ps.empty()) {
                int port = 0;
                if (!try_parse_int(ps, port, 1, 65535)) {
                    tee_printf("  %serror: invalid port '%s'%s\n", col(C::RED), ps.c_str(), col(C::RST));
                } else {
                    const auto rs = resolve_host(t);
                    const string ip = rs.primary_ip.empty() ? t : rs.primary_ip;
                    const auto probes = j3_probes(ip, port);
                    for (const auto& p : probes) {
                        tee_printf("  %-30s  %s  %dB %s\n",
                                   p.name.c_str(),
                                   p.responded ? "RESP" : "SILENT",
                                   p.bytes,
                                   p.responded ? printable_prefix(p.first_line, 60).c_str() : "(dropped)");
                    }
                }
            }
            pause_for_enter();
            continue;
        }

        if (c == '6') {
            const string t = ask("  IP (blank = your IP): ");
            auto f1 = std::async(std::launch::async, geo_ipapi_is, t);
            auto f2 = std::async(std::launch::async, geo_iplocate, t);
            auto f3 = std::async(std::launch::async, geo_freeipapi, t);
            auto f4 = std::async(std::launch::async, geo_2ip_ru, t);
            auto f5 = std::async(std::launch::async, geo_sypex, t);
            auto f6 = std::async(std::launch::async, geo_ipwho_is, t);
            auto f7 = std::async(std::launch::async, geo_ipinfo_io, t);

            tee_printf("  %s-- EU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(safe_get_geo(f1, "ipapi.is"));
            print_geo(safe_get_geo(f2, "iplocate.io"));
            print_geo(safe_get_geo(f3, "freeipapi.com"));
            tee_printf("  %s-- RU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(safe_get_geo(f4, "2ip.ru"));
            print_geo(safe_get_geo(f5, "sypexgeo.net"));
            tee_printf("  %s-- global --%s\n", col(C::BOLD), col(C::RST));
            print_geo(safe_get_geo(f6, "ipwho.is"));
            print_geo(safe_get_geo(f7, "ipinfo.io"));

            pause_for_enter();
            continue;
        }
    }
}

} // namespace

int main_impl(int argc, char** argv) {
    enable_vt();

    std::string ossl_err;
    if (!openssl_runtime_init(&ossl_err)) {
        fprintf(stderr, "fatal: OpenSSL initialization failed: %s\n", ossl_err.c_str());
        fflush(stderr);
        return 2;
    }

    if (!socket_runtime_ready()) {
        fprintf(stderr, "fatal: socket runtime initialization failed\n");
        fflush(stderr);
        return 2;
    }

    Cleanup cleanup_guard;

    vector<string> pos;
    for (int i = 1; i < argc; ++i) {
        const string a = argv[i];
        if (a == "--no-color") g_no_color = true;
        else if (a == "--verbose" || a == "-v") g_verbose = true;
        else if (a == "--threads") {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --threads requires a value\n");
                return 1;
            }
            g_threads = parse_int_fatal(argv[++i], "--threads", 1, 10000);
        }
        else if (a == "--tcp-to") {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --tcp-to requires a value\n");
                return 1;
            }
            g_tcp_to = parse_int_fatal(argv[++i], "--tcp-to", 1, 60000);
        }
        else if (a == "--udp-to") {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --udp-to requires a value\n");
                return 1;
            }
            g_udp_to = parse_int_fatal(argv[++i], "--udp-to", 1, 60000);
        }
        else if (a == "--syn") g_tcp_syn_scan = true;
        else if (a == "--stealth") {
            g_stealth = true;
            g_no_geoip = true;
            g_no_ct = true;
            g_udp_jitter = true;
        } else if (a == "--no-geoip") {
            g_no_geoip = true;
        } else if (a == "--no-ct") {
            g_no_ct = true;
        } else if (a == "--use-ip-api") {
            fprintf(stderr, "warn: --use-ip-api is deprecated; only HTTPS GeoIP providers are used now\n");
        } else if (a == "--udp-jitter") {
            g_udp_jitter = true;
        } else if (a == "--save") {
            g_save_requested = true;
            if (i + 1 < argc) {
                const string nxt = argv[i + 1];
                if (!nxt.empty() && nxt[0] != '-') {
                    g_save_path = nxt;
                    ++i;
                }
            }
        } else if (a == "--full") {
            g_port_mode = PortMode::FULL;
        } else if (a == "--fast") {
            g_port_mode = PortMode::FAST;
        } else if (a == "--range") {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --range requires a value in format start-end\n");
                return 1;
            }
            const string v = argv[++i];
            const size_t dash = v.find('-');
            if (dash == string::npos || dash == 0 || dash == v.size() - 1) {
                fprintf(stderr, "Error: invalid --range format '%s' (expected start-end, e.g., 1000-2000)\n", v.c_str());
                return 1;
            }
            g_range_lo = parse_int_fatal(v.substr(0, dash).c_str(), "range start", 1, 65535);
            g_range_hi = parse_int_fatal(v.substr(dash + 1).c_str(), "range end", 1, 65535);
            if (g_range_lo > g_range_hi) {
                fprintf(stderr, "Error: invalid --range '%s' (start must be <= end)\n", v.c_str());
                return 1;
            }
            g_port_mode = PortMode::RANGE;
        } else if (a == "--ports") {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --ports requires a comma-separated list of ports\n");
                return 1;
            }
            ++i;
            const string v = argv[i];
            g_port_list.clear();
            size_t p = 0;
            while (p < v.size()) {
                const size_t c = v.find(',', p);
                const string tok = v.substr(p, c == string::npos ? string::npos : c - p);
                if (!tok.empty()) g_port_list.push_back(parse_int_fatal(tok.c_str(), "port list entry", 1, 65535));
                if (c == string::npos) break;
                p = c + 1;
            }
            if (!g_port_list.empty()) g_port_mode = PortMode::LIST;
        } else if (a == "--help" || a == "-h" || a == "/?") {
            help();
            return 0;
        } else {
            pos.push_back(a);
        }
    }

    clamp_threads_to_nofile_limit();

    if (g_save_requested) {
        const string target = extract_target_arg(pos);
        string path = g_save_path;
        if (path.empty()) path = default_save_path_for_target(target);
        g_save_fp = fopen(path.c_str(), "w");
        if (!g_save_fp) {
            fprintf(stderr, "warn: --save: cannot open '%s' for writing (%s); continuing without save\n",
                    path.c_str(), strerror(errno));
        } else {
            g_save_path = path;
            const time_t now = time(nullptr);
            const struct tm* lt = localtime(&now);
            fprintf(g_save_fp, "# Scan report\n\n");
            if (lt) {
                fprintf(g_save_fp,
                        "**Date:** %04d-%02d-%02d %02d:%02d:%02d  \n",
                        1900 + lt->tm_year, 1 + lt->tm_mon, lt->tm_mday,
                        lt->tm_hour, lt->tm_min, lt->tm_sec);
            }
            if (!target.empty()) fprintf(g_save_fp, "**Target:** `%s`  \n", target.c_str());
            fprintf(g_save_fp, "**Scanner version:** v1.1.1  \n\n");
            fprintf(g_save_fp, "```\n");
        }
    }

    banner();
    int rc = 0;

    if (pos.empty()) {
        interactive();
    } else {
        const string& cmd = pos[0];

        if (cmd == "scan" || cmd == "full") {
            if (pos.size() < 2) {
                tee_printf("need target\n");
                rc = 2;
                goto done;
            }
            run_full_target(pos[1]);
        } else if (cmd == "ports") {
            if (pos.size() < 2) {
                tee_printf("need target\n");
                rc = 2;
                goto done;
            }
            const auto rs = resolve_host(pos[1]);
            const auto op = scan_tcp(rs.primary_ip.empty() ? pos[1] : rs.primary_ip, build_tcp_ports(), g_threads, g_tcp_to);
            for (const auto& o : op) {
                tee_printf("  :%-5d  %lldms  %s\n", o.port, o.connect_ms, port_hint(o.port));
            }
        } else if (cmd == "udp") {
            if (pos.size() < 2) {
                tee_printf("need target\n");
                rc = 2;
                goto done;
            }
            const auto rs = resolve_host(pos[1]);
            const string ip = rs.primary_ip.empty() ? pos[1] : rs.primary_ip;
            show_udp_wg(ip);
        } else if (cmd == "tls") {
            if (pos.size() < 2) {
                tee_printf("need target\n");
                rc = 2;
                goto done;
            }
            int port = 443;
            if (pos.size() >= 3 && !try_parse_int(pos[2], port, 1, 65535)) {
                fprintf(stderr, "Error: invalid port '%s' (expected 1-65535)\n", pos[2].c_str());
                rc = 2;
                goto done;
            }
            const auto rs = resolve_host(pos[1]);
            const string ip = rs.primary_ip.empty() ? pos[1] : rs.primary_ip;
            const auto tp = tls_probe(ip, port, pos[1]);
            if (!tp.ok) {
                tee_printf("TLS fail: %s\n", tp.err.c_str());
                rc = 1;
                goto done;
            }
            tee_printf("  %s / %s / ALPN=%s / %s / %lldms\n",
                       tp.version.c_str(), tp.cipher.c_str(), tp.alpn.c_str(), tp.group.c_str(), tp.handshake_ms);
            tee_printf("  cert:   %s\n", tp.cert_subject.c_str());
            tee_printf("  issuer: %s\n", tp.cert_issuer.c_str());
            tee_printf("  sha256: %s\n", tp.cert_sha256.c_str());

            const auto sc = sni_consistency(ip, port, pos[1]);
            for (const auto& e : sc.entries) {
#if BYEBYEVPN_HAS_STD_FORMAT
                const std::string sha = e.ok ? std::format("sha:{}", e.sha.substr(0, 16)) : "fail";
#else
                const std::string sha = e.ok ? ("sha:" + e.sha.substr(0, 16)) : "fail";
#endif
                tee_printf("    %-35s  %s  %s\n",
                           e.sni.c_str(),
                           sha.c_str(),
                           (e.ok && e.sha == sc.base_sha) ? "SAME" : "diff");
            }

            if (sc.reality_like)
                tee_printf("  => Reality/XTLS pattern (cert covers foreign SNI '%s')\n", sc.matched_foreign_sni.c_str());
            else if (sc.default_cert_only)
                tee_printf("  => plain TLS server with single default cert (NOT Reality)\n");
            else if (sc.same_cert_always)
                tee_printf("  => identical cert across SNIs but covers no foreign SNI (inconclusive)\n");
            else
                tee_printf("  => cert varies per SNI (multi-tenant TLS, NOT Reality)\n");
        } else if (cmd == "j3") {
            if (pos.size() < 2) {
                tee_printf("need target\n");
                rc = 2;
                goto done;
            }
            int port = 443;
            if (pos.size() >= 3 && !try_parse_int(pos[2], port, 1, 65535)) {
                fprintf(stderr, "Error: invalid port '%s' (expected 1-65535)\n", pos[2].c_str());
                rc = 2;
                goto done;
            }
            const auto rs = resolve_host(pos[1]);
            const string ip = rs.primary_ip.empty() ? pos[1] : rs.primary_ip;
            const auto probes = j3_probes(ip, port);
            for (const auto& p : probes) {
                tee_printf("  %-28s  %s  %dB %s\n",
                           p.name.c_str(),
                           p.responded ? "RESP" : "SILENT",
                           p.bytes,
                           p.responded ? printable_prefix(p.first_line, 60).c_str() : "(dropped)");
            }
        } else if (cmd == "geoip") {
            const string ip = pos.size() >= 2 ? pos[1] : "";
            auto f1 = std::async(std::launch::async, geo_ipapi_is, ip);
            auto f2 = std::async(std::launch::async, geo_iplocate, ip);
            auto f3 = std::async(std::launch::async, geo_freeipapi, ip);
            auto f4 = std::async(std::launch::async, geo_2ip_ru, ip);
            auto f5 = std::async(std::launch::async, geo_sypex, ip);
            auto f6 = std::async(std::launch::async, geo_ipwho_is, ip);
            auto f7 = std::async(std::launch::async, geo_ipinfo_io, ip);

            tee_printf("  %s-- EU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(safe_get_geo(f1, "ipapi.is"));
            print_geo(safe_get_geo(f2, "iplocate.io"));
            print_geo(safe_get_geo(f3, "freeipapi.com"));
            tee_printf("  %s-- RU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(safe_get_geo(f4, "2ip.ru"));
            print_geo(safe_get_geo(f5, "sypexgeo.net"));
            tee_printf("  %s-- global --%s\n", col(C::BOLD), col(C::RST));
            print_geo(safe_get_geo(f6, "ipwho.is"));
            print_geo(safe_get_geo(f7, "ipinfo.io"));
        } else if (cmd == "help") {
            help();
        } else {
            run_full_target(cmd);
        }
    }

 done:
    if (g_save_fp) {
        fprintf(stderr, "saved to %s\n", g_save_path.c_str());
    }
    return rc;
}

int main(int argc, char** argv) {
    try {
        return main_impl(argc, argv);
    } catch (const std::exception& e) {
        fprintf(stderr, "fatal: %s\n", e.what());
        return 1;
    } catch (...) {
        fprintf(stderr, "fatal: unknown exception\n");
        return 1;
    }
}

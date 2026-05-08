#include "snitch.h"
#include "../network/tcp_scanner.h"
#include <chrono>
#include <cmath>
#include <algorithm>
#include <cctype>
#include <future>

static double percentile(std::vector<double> v, double pct) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    double idx = pct * (n - 1);
    size_t lo = (size_t)std::floor(idx);
    size_t hi = (size_t)std::ceil(idx);
    if (lo == hi) return v[lo];
    double frac = idx - lo;
    return v[lo] * (1 - frac) + v[hi] * frac;
}

static double tcp_rtt_sample_ms(const std::string& host, int port, int to_ms) {
    auto t0 = std::chrono::steady_clock::now();
    std::string err;
    SOCKET s = tcp_connect(host, port, to_ms, err);
    if (s == INVALID_SOCKET) return -1.0;
    auto t1 = std::chrono::steady_clock::now();
    closesocket(s);
    double us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    return us / 1000.0;
}

static void measure_rtt_series(const std::string& host, int port, int to_ms, int samples, std::vector<double>& out) {
    out.reserve(samples);
    for (int i = 0; i < samples; ++i) {
        double ms = tcp_rtt_sample_ms(host, port, to_ms);
        if (ms > 0) out.push_back(ms);
    }
}

static double country_min_rtt_ms(const std::string& cc) {
    static const struct { const char* cc; double min_ms; double max_ms; } TBL[] = {
        {"RU",     4,    40},
        {"BY",    10,    40},
        {"UA",    10,    50},
        {"KZ",    20,    80},
        {"LT",    15,    45},
        {"LV",    15,    45},
        {"EE",    15,    45},
        {"FI",    10,    45},
        {"SE",    20,    55},
        {"NO",    25,    60},
        {"DE",    25,    60},
        {"NL",    30,    65},
        {"FR",    30,    70},
        {"GB",    35,    75},
        {"IT",    35,    80},
        {"ES",    45,    90},
        {"PL",    25,    60},
        {"CZ",    25,    60},
        {"AT",    30,    65},
        {"CH",    30,    70},
        {"BE",    30,    65},
        {"HU",    30,    65},
        {"RO",    30,    70},
        {"BG",    30,    70},
        {"TR",    45,   100},
        {"IL",    60,   120},
        {"IR",    70,   150},
        {"AE",    80,   150},
        {"SA",    80,   160},
        {"IN",   110,   220},
        {"CN",   130,   290},
        {"HK",   140,   280},
        {"JP",   150,   300},
        {"KR",   150,   300},
        {"SG",   160,   320},
        {"TH",   160,   320},
        {"ID",   180,   350},
        {"AU",   230,   420},
        {"NZ",   260,   460},
        {"US",   100,   200},
        {"CA",   100,   200},
        {"MX",   130,   260},
        {"BR",   180,   340},
        {"AR",   210,   380},
        {"ZA",   160,   320},
        {"EG",   60,    130},
    };
    if (cc.empty()) return 0.0;
    std::string u = cc;
    std::transform(u.begin(), u.end(), u.begin(), [](unsigned char c){ return std::toupper(c); });
    for (auto& e: TBL) if (u == e.cc) return e.min_ms;
    return 0.0;
}

static double country_max_rtt_ms(const std::string& cc) {
    static const struct { const char* cc; double max_ms; } TBL[] = {
        {"RU",40},{"BY",40},{"UA",50},{"KZ",80},{"LT",45},{"LV",45},{"EE",45},
        {"FI",45},{"SE",55},{"NO",60},{"DE",60},{"NL",65},{"FR",70},{"GB",75},
        {"IT",80},{"ES",90},{"PL",60},{"CZ",60},{"AT",65},{"CH",70},{"BE",65},
        {"HU",65},{"RO",70},{"BG",70},{"TR",100},{"IL",120},{"IR",150},{"AE",150},
        {"SA",160},{"IN",220},{"CN",290},{"HK",280},{"JP",300},{"KR",300},{"SG",320},
        {"TH",320},{"ID",350},{"AU",420},{"NZ",460},{"US",200},{"CA",200},{"MX",260},
        {"BR",340},{"AR",380},{"ZA",320},{"EG",130},
    };
    if (cc.empty()) return 0.0;
    std::string u = cc;
    std::transform(u.begin(), u.end(), u.begin(), [](unsigned char c){ return std::toupper(c); });
    for (auto& e: TBL) if (u == e.cc) return e.max_ms;
    return 0.0;
}



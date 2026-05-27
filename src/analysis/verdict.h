#pragma once

#include <optional>
#include <string>
#include <vector>
#include <cstdint>

#include "../network/dns.h"
#include "../network/https_probe.h"
#include "../network/j3_probes.h"
#include "../network/port_scan.h"
#include "../network/service_probes.h"
#include "../network/tls_probe.h"
#include "../network/udp_scanner.h"
#include "ct_check.h"
#include "geoip.h"
#include "sni_consistency.h"

// JA3 fingerprint information
struct Ja3Info {
    std::string version;
    std::string ciphers;
    std::string extensions;
    std::string groups;
    std::string ec_formats;
    std::string ja3_hash;
};

// Advisory information
struct Advice {
    std::string kind;
    std::string text;
};

// Full analysis report
struct FullReport {
    std::string target;
    Resolved dns;
    std::vector<GeoInfo> geos;
    std::vector<TcpOpen> open_tcp;
    std::vector<std::pair<int, UdpResult>> udp_probes;

    // Per-port fingerprinting results
    struct PortFp {
        int port{0};
        FpResult fp;
        std::optional<TlsProbe> tls;
        std::optional<SniConsistency> sni;
        std::vector<J3Result> j3;
        std::optional<J3Analysis> j3a;
        std::optional<HttpsProbe> https;
        std::optional<CtCheck> ct;
    };

    std::vector<PortFp> fps;
    ScanStats scan_stats;
    int score{0};
    std::string label;
    std::vector<Advice> advices;
    std::vector<std::string> guess_stack;
    
    // Check if report indicates VPN-like behavior
    // Score starts at 100 (clean) and decreases as VPN evidence accumulates.
    // A score below 50 corresponds to "HIGH-CONFIDENCE" VPN detection.
    [[nodiscard]] bool vpn_detected() const noexcept {
        return score < 50;
    }
};

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

#include "core/utils.h"
#include "network/port_scan.h"

namespace {

struct PortModeGuard {
    PortMode mode = g_port_mode;
    int lo = g_range_lo;
    int hi = g_range_hi;
    std::vector<int> list = g_port_list;

    ~PortModeGuard() {
        g_port_mode = mode;
        g_range_lo = lo;
        g_range_hi = hi;
        g_port_list = list;
    }
};

} // namespace

TEST_CASE("build_tcp_ports FAST includes common VPN-related ports") {
    PortModeGuard guard;
    g_port_mode = PortMode::FAST;

    const auto ports = build_tcp_ports();
    REQUIRE(!ports.empty());
    REQUIRE(std::find(ports.begin(), ports.end(), 22) != ports.end());
    REQUIRE(std::find(ports.begin(), ports.end(), 443) != ports.end());
    REQUIRE(std::find(ports.begin(), ports.end(), 51820) != ports.end());
}

TEST_CASE("build_tcp_ports RANGE clamps boundaries") {
    PortModeGuard guard;
    g_port_mode = PortMode::RANGE;
    g_range_lo = -5;
    g_range_hi = 3;

    const auto ports = build_tcp_ports();
    REQUIRE(ports.size() == 3);
    REQUIRE(ports[0] == 1);
    REQUIRE(ports[2] == 3);
}

TEST_CASE("build_tcp_ports LIST preserves explicit list") {
    PortModeGuard guard;
    g_port_mode = PortMode::LIST;
    g_port_list = {443, 8443, 1080};

    const auto ports = build_tcp_ports();
    REQUIRE(ports == g_port_list);
}

TEST_CASE("port_hint reports known and unknown ports") {
    REQUIRE(std::string(port_hint(22)) == "SSH");
    REQUIRE(std::string(port_hint(10809)) == "v2ray/xray HTTP");
    REQUIRE(std::string(port_hint(65000)).empty());
}

TEST_CASE("build_tcp_ports FULL generates 65535 ports") {
    PortModeGuard guard;
    g_port_mode = PortMode::FULL;

    const auto ports = build_tcp_ports();
    REQUIRE(ports.size() == 65535);
    REQUIRE(ports.front() == 1);
    REQUIRE(ports.back() == 65535);
}

TEST_CASE("build_tcp_ports RANGE reversed hi < lo yields empty") {
    PortModeGuard guard;
    g_port_mode = PortMode::RANGE;
    g_range_lo = 100;
    g_range_hi = 50;

    const auto ports = build_tcp_ports();
    REQUIRE(ports.empty());
}

TEST_CASE("build_tcp_ports RANGE exact single port") {
    PortModeGuard guard;
    g_port_mode = PortMode::RANGE;
    g_range_lo = 443;
    g_range_hi = 443;

    const auto ports = build_tcp_ports();
    REQUIRE(ports.size() == 1);
    REQUIRE(ports[0] == 443);
}

TEST_CASE("build_tcp_ports RANGE high boundary clamping") {
    PortModeGuard guard;
    g_port_mode = PortMode::RANGE;
    g_range_lo = 65530;
    g_range_hi = 70000;

    const auto ports = build_tcp_ports();
    REQUIRE(ports.size() == 6);
    REQUIRE(ports.back() == 65535);
}

TEST_CASE("port_hint covers additional port ranges") {
    REQUIRE(std::string(port_hint(6443)).find("HTTPS") != std::string::npos);
    REQUIRE(std::string(port_hint(8443)).find("HTTPS") != std::string::npos);
    REQUIRE(std::string(port_hint(4443)).find("XTLS") != std::string::npos);
    REQUIRE(std::string(port_hint(4433)).find("XTLS") != std::string::npos);
    REQUIRE(std::string(port_hint(10810)).find("v2ray") != std::string::npos);
    REQUIRE(std::string(port_hint(10800)).find("v2ray") != std::string::npos);
    REQUIRE(std::string(port_hint(10820)).find("v2ray") != std::string::npos);
    REQUIRE(std::string(port_hint(80)) == "HTTP");
    REQUIRE(std::string(port_hint(443)).find("HTTPS") != std::string::npos);
    REQUIRE(std::string(port_hint(1080)) == "SOCKS5");
    REQUIRE(std::string(port_hint(51820)) == "WireGuard");
    REQUIRE(std::string(port_hint(9050)) == "Tor SOCKS");
    REQUIRE(std::string(port_hint(41641)).find("WireGuard") != std::string::npos);
    REQUIRE(std::string(port_hint(55555)).find("AmneziaWG") != std::string::npos);
}

TEST_CASE("port_hint returns empty for non-hint ports") {
    REQUIRE(std::string(port_hint(1)).empty());
    REQUIRE(std::string(port_hint(12345)).empty());
    REQUIRE(std::string(port_hint(50000)).empty());
}

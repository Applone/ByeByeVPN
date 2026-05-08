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

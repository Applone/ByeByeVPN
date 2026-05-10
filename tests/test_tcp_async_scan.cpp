#include <catch2/catch_test_macros.hpp>

#include "core/utils.h"
#include "network/tcp_async_scan.h"
#include "network_test_helpers.h"

#include <algorithm>
#include <vector>

namespace {

struct TcpSynScanGuard {
    bool value = g_tcp_syn_scan;
    ~TcpSynScanGuard() { g_tcp_syn_scan = value; }
};

} // namespace

TEST_CASE("scan_tcp_async returns empty for empty port list") {
    TcpSynScanGuard guard;
    g_tcp_syn_scan = false;

    ScanStats stats{};
    const auto result = scan_tcp_async("127.0.0.1", {}, 16, 200, &stats);

    REQUIRE(result.empty());
    REQUIRE(stats.scanned == 0);
    REQUIRE(stats.timeouts == 0);
    REQUIRE(stats.refused == 0);
    REQUIRE(stats.other == 0);
    REQUIRE_FALSE(stats.skipped);
}

TEST_CASE("scan_tcp_async reports unresolved target") {
    TcpSynScanGuard guard;
    g_tcp_syn_scan = false;

    ScanStats stats{};
    const std::vector<int> ports = {80, 443};

    const auto result = scan_tcp_async("bad host name with spaces", ports, 16, 200, &stats);

    REQUIRE(result.empty());
    REQUIRE(stats.scanned == 0);
    REQUIRE(stats.other == ports.size());
    REQUIRE_FALSE(stats.skipped);
}

TEST_CASE("scan_tcp_async discovers open loopback port") {
    TcpSynScanGuard guard;
    g_tcp_syn_scan = false;

    testnet::TcpOneShotServer server([](SOCKET client) {
        const char kMsg[] = "banner";
        send(client, kMsg, 6, 0);
    });

    const int closed_port = testnet::reserve_unused_tcp_port();
    const std::vector<int> ports = {closed_port, server.port()};

    ScanStats stats{};
    const auto result = scan_tcp_async("127.0.0.1", ports, 32, 300, &stats);

    REQUIRE(std::any_of(result.begin(), result.end(), [&](const TcpOpen& o) {
        return o.port == server.port();
    }));
    REQUIRE(stats.scanned == ports.size());
    REQUIRE(stats.refused + stats.other + stats.timeouts >= 1);
    REQUIRE_FALSE(stats.skipped);
}

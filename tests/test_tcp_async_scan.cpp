#include <catch2/catch_test_macros.hpp>

#include "core/utils.h"
#include "network/tcp_async_scan.h"
#include "network_test_helpers.h"

#include <algorithm>
#include <iterator>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

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

TEST_CASE("scan_tcp_async handles null stats pointer") {
    TcpSynScanGuard guard;
    g_tcp_syn_scan = false;

    const auto result = scan_tcp_async("127.0.0.1", {}, 16, 200, nullptr);
    REQUIRE(result.empty());
}

TEST_CASE("scan_tcp_async counts all-refused ports") {
    TcpSynScanGuard guard;
    g_tcp_syn_scan = false;

    std::vector<int> closed_ports;
    for (int i = 0; i < 5; ++i) {
        closed_ports.push_back(testnet::reserve_unused_tcp_port());
    }

    ScanStats stats{};
    const auto result = scan_tcp_async("127.0.0.1", closed_ports, 32, 200, &stats);

    REQUIRE(result.empty());
    REQUIRE(stats.scanned == closed_ports.size());
    REQUIRE(stats.refused + stats.other + stats.timeouts == closed_ports.size());
    REQUIRE_FALSE(stats.skipped);
}

TEST_CASE("scan_tcp_async results are sorted by port") {
    TcpSynScanGuard guard;
    g_tcp_syn_scan = false;

    testnet::TcpOneShotServer server([](SOCKET client) {
        const char kMsg[] = "hi";
        send(client, kMsg, 2, 0);
    });

    const std::vector<int> ports = {server.port()};
    ScanStats stats{};
    const auto result = scan_tcp_async("127.0.0.1", ports, 32, 300, &stats);

    for (size_t i = 1; i < result.size(); ++i) {
        REQUIRE(result[i - 1].port <= result[i].port);
    }
}

TEST_CASE("scan_tcp_async with single port") {
    TcpSynScanGuard guard;
    g_tcp_syn_scan = false;

    testnet::TcpOneShotServer server([](SOCKET client) {
        const char kMsg[] = "x";
        send(client, kMsg, 1, 0);
    });

    ScanStats stats{};
    const auto result = scan_tcp_async("127.0.0.1", {server.port()}, 1, 500, &stats);

    REQUIRE(result.size() == 1);
    REQUIRE(result[0].port == server.port());
    REQUIRE(result[0].connect_ms >= 0);
    REQUIRE(stats.scanned == 1);
}

TEST_CASE("scan_tcp_async handles duplicate open ports and keeps sorted output") {
    TcpSynScanGuard guard;
    g_tcp_syn_scan = false;

    testnet::TcpMultiShotServer server(
        2,
        [](SOCKET client, int) {
            const char kMsg[] = "ok";
            send(client, kMsg, 2, 0);
        });

    const int closed = testnet::reserve_unused_tcp_port();
    const std::vector<int> ports = {server.port(), closed, server.port()};

    ScanStats stats{};
    const auto result = scan_tcp_async("127.0.0.1", ports, 1, 180, &stats);

    REQUIRE(stats.scanned == ports.size());
    REQUIRE(std::is_sorted(result.begin(), result.end(), [](const TcpOpen& a, const TcpOpen& b) {
        return a.port < b.port;
    }));

    const auto open_hits = std::count_if(result.begin(), result.end(), [&](const TcpOpen& o) {
        return o.port == server.port();
    });
    REQUIRE(open_hits >= 1);
}

TEST_CASE("scan_tcp_async non-empty scan works with null stats") {
    TcpSynScanGuard guard;
    g_tcp_syn_scan = false;

    testnet::TcpOneShotServer server([](SOCKET client) {
        const char kMsg[] = "banner";
        send(client, kMsg, 6, 0);
    });

    const auto result = scan_tcp_async("127.0.0.1", {server.port()}, 8, 300, nullptr);
    REQUIRE(result.size() == 1);
    REQUIRE(result.front().port == server.port());
}

#ifndef _WIN32
TEST_CASE("scan_tcp_async --syn falls back to connect scan when not root") {
    if (geteuid() == 0) {
        SKIP("Fallback path is specific to non-root execution");
    }

    TcpSynScanGuard guard;
    g_tcp_syn_scan = true;

    testnet::TcpOneShotServer server([](SOCKET client) {
        const char kMsg[] = "hi";
        send(client, kMsg, 2, 0);
    });

    ScanStats stats{};
    const auto result = scan_tcp_async("127.0.0.1", {server.port()}, 64, 300, &stats);

    REQUIRE(result.size() == 1);
    REQUIRE(result.front().port == server.port());
    REQUIRE(stats.scanned == 1);
    REQUIRE_FALSE(stats.skipped);
}
#endif

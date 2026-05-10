#include <catch2/catch_test_macros.hpp>

#include "core/utils.h"
#include "network/udp_scanner.h"
#include "network_test_helpers.h"

#include <array>
#include <string>

namespace {

struct UdpJitterGuard {
    bool jitter = g_udp_jitter;
    ~UdpJitterGuard() { g_udp_jitter = jitter; }
};

} // namespace

TEST_CASE("udp_probe receives response from loopback server") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    testnet::UdpOneShotServer server([](SOCKET sock, const sockaddr_in& peer, const std::vector<unsigned char>& data) {
        const std::string reply = data.empty() ? "empty" : "pong";
        sendto(sock, reply.data(), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    });

    const std::array<unsigned char, 4> payload = {'p', 'i', 'n', 'g'};
    const UdpResult r = udp_probe("127.0.0.1", server.port(), payload.data(), static_cast<int>(payload.size()), 1200);

    REQUIRE(r.responded);
    REQUIRE(r.bytes > 0);
    CHECK(r.err.empty());
    CHECK_FALSE(r.reply_hex.empty());
}

TEST_CASE("udp_probe reports non-response state for unused port") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    const int unused_port = testnet::reserve_unused_udp_port();
    const std::array<unsigned char, 1> payload = {0x01};

    const UdpResult r = udp_probe("127.0.0.1", unused_port, payload.data(), 1, 150);
    REQUIRE_FALSE(r.responded);
    REQUIRE((r.err == "no-reply / filtered" ||
             r.err == "ICMP port-unreachable (port closed)" ||
             r.err.rfind("wsa ", 0) == 0));
}

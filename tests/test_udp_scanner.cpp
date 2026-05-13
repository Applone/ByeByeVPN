#include <catch2/catch_test_macros.hpp>

#include "core/utils.h"
#include "network/udp_scanner.h"
#include "network_test_helpers.h"

#include <array>
#include <chrono>
#include <string>
#include <thread>

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

TEST_CASE("udp_probe response includes timing measurement") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    testnet::UdpOneShotServer server([](SOCKET sock, const sockaddr_in& peer, const std::vector<unsigned char>&) {
        const std::string reply = "pong";
        sendto(sock, reply.data(), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    });

    const std::array<unsigned char, 4> payload = {'p', 'i', 'n', 'g'};
    const UdpResult r = udp_probe("127.0.0.1", server.port(), payload.data(),
                                  static_cast<int>(payload.size()), 1500);

    REQUIRE(r.responded);
    REQUIRE(r.ms >= 0);
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

TEST_CASE("udp_probe returns timeout-shaped result against silent receiver") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    testnet::UdpOneShotServer server([](SOCKET, const sockaddr_in&, const std::vector<unsigned char>&) {
        // absorb the packet but send nothing
    });

    const std::array<unsigned char, 4> payload = {'a', 'b', 'c', 'd'};
    const UdpResult r = udp_probe("127.0.0.1", server.port(), payload.data(),
                                  static_cast<int>(payload.size()), 120);

    REQUIRE_FALSE(r.responded);
    REQUIRE(r.err == "no-reply / filtered");
    REQUIRE(r.ms >= 0);
}

TEST_CASE("udp_probe fails with dns error for unresolvable host") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    const std::array<unsigned char, 1> payload = {0x01};
    const UdpResult r = udp_probe("name with spaces and no resolution", 12345,
                                  payload.data(), 1, 50);

    REQUIRE_FALSE(r.responded);
    REQUIRE(r.err == "dns");
}

TEST_CASE("udp_probe with jitter enabled still completes against responsive server") {
    UdpJitterGuard guard;
    g_udp_jitter = true;

    testnet::UdpOneShotServer server([](SOCKET sock, const sockaddr_in& peer, const std::vector<unsigned char>&) {
        const std::string reply = "j";
        sendto(sock, reply.data(), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    });

    const std::array<unsigned char, 2> payload = {0xAA, 0xBB};
    const UdpResult r = udp_probe("127.0.0.1", server.port(), payload.data(), 2, 2000);

    REQUIRE(r.responded);
    REQUIRE(r.bytes >= 1);
    REQUIRE(r.err.empty());
}

TEST_CASE("udp_probe truncates reply_hex preview to 32 bytes") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    testnet::UdpOneShotServer server([](SOCKET sock, const sockaddr_in& peer, const std::vector<unsigned char>&) {
        std::string reply(64, 'A');
        sendto(sock, reply.data(), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    });

    const std::array<unsigned char, 1> payload = {0x01};
    const UdpResult r = udp_probe("127.0.0.1", server.port(), payload.data(), 1, 1500);

    REQUIRE(r.responded);
    REQUIRE(r.bytes == 64);
    // hex_s with spaces produces 32 bytes * 3 chars - 1 (no trailing space) = 95 chars
    REQUIRE(r.reply_hex.size() <= 32 * 3);
}

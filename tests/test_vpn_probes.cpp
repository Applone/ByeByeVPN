#include <catch2/catch_test_macros.hpp>

#include "core/utils.h"
#include "network/vpn_probes.h"
#include "network_test_helpers.h"

#include <atomic>
#include <string>

namespace {

struct UdpJitterGuard {
    bool jitter = g_udp_jitter;
    ~UdpJitterGuard() { g_udp_jitter = jitter; }
};

} // namespace

TEST_CASE("wireguard_probe sends 148-byte packet with MessageInitiation header") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    std::atomic<std::size_t> observed_size{0};
    std::atomic<unsigned int> observed_first{0};

    testnet::UdpOneShotServer server([&](SOCKET sock, const sockaddr_in& peer, const std::vector<unsigned char>& data) {
        observed_size.store(data.size(), std::memory_order_relaxed);
        observed_first.store(data.empty() ? 0U : static_cast<unsigned int>(data[0]), std::memory_order_relaxed);
        const std::string reply = "wg";
        sendto(sock, reply.data(), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    });

    const auto r = wireguard_probe("127.0.0.1", server.port());
    REQUIRE(r.responded);
    REQUIRE(r.bytes > 0);
    REQUIRE(r.err.empty());
    REQUIRE(observed_size.load(std::memory_order_relaxed) == 148);
    REQUIRE(observed_first.load(std::memory_order_relaxed) == 0x01U);
}

TEST_CASE("wireguard_probe reports udp errors when no listener exists") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    const int unused = testnet::reserve_unused_udp_port();
    const auto r = wireguard_probe("127.0.0.1", unused);
    REQUIRE_FALSE(r.responded);
    REQUIRE_FALSE(r.err.empty());
}

TEST_CASE("amneziawg_probe caps junk prefix at 64 bytes and preserves header") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    std::atomic<std::size_t> observed_size{0};
    std::atomic<unsigned int> observed_marker{0};

    testnet::UdpOneShotServer server([&](SOCKET sock, const sockaddr_in& peer, const std::vector<unsigned char>& data) {
        observed_size.store(data.size(), std::memory_order_relaxed);
        observed_marker.store(data.size() > 64 ? static_cast<unsigned int>(data[64]) : 0U,
                              std::memory_order_relaxed);
        const std::string reply = "awg";
        sendto(sock, reply.data(), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    });

    const auto r = amneziawg_probe("127.0.0.1", server.port(), 99);
    REQUIRE(r.responded);
    REQUIRE(r.err.empty());
    REQUIRE(observed_size.load(std::memory_order_relaxed) == 64 + 148);
    REQUIRE(observed_marker.load(std::memory_order_relaxed) == 0x01U);
}

TEST_CASE("amneziawg_probe with zero junk prefix matches wireguard layout") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    std::atomic<std::size_t> observed_size{0};
    std::atomic<unsigned int> observed_first{0};

    testnet::UdpOneShotServer server([&](SOCKET sock, const sockaddr_in& peer, const std::vector<unsigned char>& data) {
        observed_size.store(data.size(), std::memory_order_relaxed);
        observed_first.store(data.empty() ? 0U : static_cast<unsigned int>(data[0]), std::memory_order_relaxed);
        const std::string reply = "ok";
        sendto(sock, reply.data(), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    });

    const auto r = amneziawg_probe("127.0.0.1", server.port(), 0);
    REQUIRE(r.responded);
    REQUIRE(observed_size.load(std::memory_order_relaxed) == 148);
    REQUIRE(observed_first.load(std::memory_order_relaxed) == 0x01U);
}

TEST_CASE("amneziawg_probe accepts mid-range junk prefix without truncation") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    std::atomic<std::size_t> observed_size{0};
    std::atomic<unsigned int> observed_marker{0};

    testnet::UdpOneShotServer server([&](SOCKET sock, const sockaddr_in& peer, const std::vector<unsigned char>& data) {
        observed_size.store(data.size(), std::memory_order_relaxed);
        observed_marker.store(data.size() > 16 ? static_cast<unsigned int>(data[16]) : 0U,
                              std::memory_order_relaxed);
        const std::string reply = "ok";
        sendto(sock, reply.data(), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    });

    const auto r = amneziawg_probe("127.0.0.1", server.port(), 16);
    REQUIRE(r.responded);
    REQUIRE(observed_size.load(std::memory_order_relaxed) == 16 + 148);
    REQUIRE(observed_marker.load(std::memory_order_relaxed) == 0x01U);
}

TEST_CASE("amneziawg_probe reports udp errors on unused port") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    const int unused = testnet::reserve_unused_udp_port();
    const auto r = amneziawg_probe("127.0.0.1", unused, 8);
    REQUIRE_FALSE(r.responded);
    REQUIRE_FALSE(r.err.empty());
}

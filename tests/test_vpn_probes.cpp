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

TEST_CASE("wireguard_probe sends packet and handles response") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    std::atomic<std::size_t> observed_size{0};
    std::atomic<unsigned int> observed_first{0};

    testnet::UdpOneShotServer validating_server([&](SOCKET sock, const sockaddr_in& peer, const std::vector<unsigned char>& data) {
        observed_size.store(data.size(), std::memory_order_relaxed);
        observed_first.store(data.empty() ? 0U : static_cast<unsigned int>(data[0]), std::memory_order_relaxed);
        const std::string reply = "wg";
        sendto(sock, reply.data(), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    });

    const auto r = wireguard_probe("127.0.0.1", validating_server.port());
    REQUIRE(r.responded);
    REQUIRE(r.bytes > 0);
    REQUIRE(r.err.empty());
    REQUIRE(observed_size.load(std::memory_order_relaxed) == 148);
    REQUIRE(observed_first.load(std::memory_order_relaxed) == 0x01U);
}

TEST_CASE("amneziawg_probe caps junk prefix and handles response") {
    UdpJitterGuard guard;
    g_udp_jitter = false;

    std::atomic<std::size_t> observed_size{0};
    std::atomic<unsigned int> observed_marker{0};

    testnet::UdpOneShotServer validating_server([&](SOCKET sock, const sockaddr_in& peer, const std::vector<unsigned char>& data) {
        observed_size.store(data.size(), std::memory_order_relaxed);
        observed_marker.store(data.size() > 64 ? static_cast<unsigned int>(data[64]) : 0U,
                              std::memory_order_relaxed);
        const std::string reply = "awg";
        sendto(sock, reply.data(), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    });

    const auto r = amneziawg_probe("127.0.0.1", validating_server.port(), 99);
    REQUIRE(r.responded);
    REQUIRE(r.err.empty());
    REQUIRE(observed_size.load(std::memory_order_relaxed) == 64 + 148);
    REQUIRE(observed_marker.load(std::memory_order_relaxed) == 0x01U);
}

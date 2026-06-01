#include "vpn_probes.h"

#include <openssl/rand.h>

#include <array>
#include <limits>
#include <vector>
#include <algorithm>
#include <span>

namespace {

// Constants
inline constexpr std::size_t kWireGuardPacketSize{148};
inline constexpr std::size_t kWireGuardRandomOffset{4};
inline constexpr std::size_t kWireGuardRandomSize{140};
inline constexpr std::size_t kMaxJunkPrefixLen{64};
inline constexpr int kProbeTimeoutMs{1500};

// Create RNG error result
[[nodiscard]] UdpResult make_rng_error() {
    UdpResult result;
    result.err = "rng";
    return result;
}

// Fill buffer with random bytes using OpenSSL
[[nodiscard]] bool fill_random(std::span<unsigned char> data) noexcept {
    if (data.empty()) return false;
    if (data.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) return false;
    return RAND_bytes(data.data(), static_cast<int>(data.size())) == 1;
}

} // namespace

[[nodiscard]] UdpResult wireguard_probe(std::string_view host, int port) {
    std::array<unsigned char, kWireGuardPacketSize> pkt{};
    
    // Set message type: MessageInitiation (0x01)
    pkt.at(0) = 0x01;
    
    // Fill random data starting at offset 4
    if (!fill_random(std::span{pkt.data() + kWireGuardRandomOffset, kWireGuardRandomSize})) {
        return make_rng_error();
    }
    
    return udp_probe(host, port, std::span{pkt}, kProbeTimeoutMs);
}

[[nodiscard]] UdpResult amneziawg_probe(std::string_view host, int port, std::size_t junk_prefix_len) {
    // Clamp junk prefix length
    const std::size_t actual_junk_len{std::min(junk_prefix_len, kMaxJunkPrefixLen)};
    const std::size_t total_size{actual_junk_len + kWireGuardPacketSize};
    
    std::vector<unsigned char> pkt(total_size, 0);
    
    // Fill junk prefix with random data
    if (actual_junk_len > 0) {
        if (!fill_random(std::span{pkt.data(), actual_junk_len})) {
            return make_rng_error();
        }
    }
    
    // Set message type after junk prefix
    pkt.at(actual_junk_len) = 0x01;
    
    // Fill random data for WireGuard payload
    if (!fill_random(std::span{pkt.data() + actual_junk_len + kWireGuardRandomOffset, 
                               kWireGuardRandomSize})) {
        return make_rng_error();
    }
    
    return udp_probe(host, port, std::span{pkt}, kProbeTimeoutMs);
}

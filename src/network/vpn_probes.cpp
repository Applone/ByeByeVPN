#include "vpn_probes.h"

#include <openssl/rand.h>

#include <array>
#include <limits>
#include <vector>

namespace {

UdpResult rng_error() {
    UdpResult r;
    r.err = "rng";
    return r;
}

bool fill_random(unsigned char* data, const std::size_t size) {
    if (!data || size == 0) return false;
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max())) return false;
    return RAND_bytes(data, static_cast<int>(size)) == 1;
}

} // namespace

UdpResult wireguard_probe(const std::string& host, int port) {
    std::array<unsigned char, 148> pkt{};
    pkt[0] = 0x01; // MessageInitiation

    if (!fill_random(pkt.data() + 4, 140)) {
        return rng_error();
    }

    return udp_probe(host, port, pkt.data(), static_cast<int>(pkt.size()), 1500);
}

UdpResult amneziawg_probe(const std::string& host, int port, std::size_t junk_prefix_len) {
    if (junk_prefix_len > 64) junk_prefix_len = 64;

    std::vector<unsigned char> pkt(junk_prefix_len + 148, 0);

    if (junk_prefix_len > 0 && !fill_random(pkt.data(), junk_prefix_len)) {
        return rng_error();
    }

    pkt[junk_prefix_len] = 0x01; // MessageInitiation after junk prefix
    if (!fill_random(pkt.data() + junk_prefix_len + 4, 140)) {
        return rng_error();
    }

    return udp_probe(host, port, pkt.data(), static_cast<int>(pkt.size()), 1500);
}

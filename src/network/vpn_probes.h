#pragma once

#include "udp_scanner.h"

#include <cstddef>
#include <string>
#include <string_view>

// WireGuard handshake probe (standard format)
[[nodiscard]] UdpResult wireguard_probe(std::string_view host, int port);

// AmneziaWG handshake probe (obfuscated format with junk prefix)
[[nodiscard]] UdpResult amneziawg_probe(std::string_view host, int port, std::size_t junk_prefix_len = 8);

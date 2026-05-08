#ifndef NETWORK_VPN_PROBES_H
#define NETWORK_VPN_PROBES_H

#include <cstddef>
#include <string>
#include "udp_scanner.h"

UdpResult wireguard_probe(const std::string& host, int port);
UdpResult amneziawg_probe(const std::string& host, int port, std::size_t junk_prefix_len = 8);

#endif // NETWORK_VPN_PROBES_H

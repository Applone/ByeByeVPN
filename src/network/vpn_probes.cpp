#include "vpn_probes.h"
#include <openssl/rand.h>
#include <cstring>
#include <vector>
#ifndef _WIN32
#include <arpa/inet.h>
#endif

UdpResult quic_probe(const std::string& host, int port) {
    unsigned char pkt[] = {
        0xc0,                        
        0x00,0x00,0x00,0x01,         
        0x08,                        
        0,0,0,0,0,0,0,0,             
        0x00,                        
        0x00,                        
        0x44,0x40,                   
    };
    if (RAND_bytes(pkt + 6, 8) != 1) {
        UdpResult r;
        r.err = "rng";
        return r;
    }
    std::vector<unsigned char> full(1200, 0x00);
    memcpy(full.data(), pkt, sizeof(pkt));
    return udp_probe(host, port, full.data(), (int)full.size(), 1500);
}

UdpResult openvpn_probe(const std::string& host, int port) {
    unsigned char pkt[26] = {0};
    pkt[0] = 0x38; 
    unsigned char rnd_off = 0;
    if (RAND_bytes(pkt+1, 8) != 1 ||
        RAND_bytes(&rnd_off, 1) != 1 ||
        RAND_bytes(pkt+18, 8) != 1) {
        UdpResult r;
        r.err = "rng";
        return r;
    }
    pkt[9] = 0x00;            
    unsigned int pid = htonl(0);
    memcpy(pkt+10, &pid, 4);  
    unsigned int ts = htonl((unsigned int)time(nullptr) - (unsigned int)rnd_off);
    memcpy(pkt+14, &ts, 4);   
    return udp_probe(host, port, pkt, sizeof(pkt), 1200);
}

UdpResult wireguard_probe(const std::string& host, int port) {
    unsigned char pkt[148] = {0};
    pkt[0] = 0x01;   
    if (RAND_bytes(pkt+4, 140) != 1) {
        UdpResult r;
        r.err = "rng";
        return r;
    }
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

UdpResult ike_probe(const std::string& host, int port) {
    unsigned char pkt[28] = {0};
    if (RAND_bytes(pkt, 8) != 1) {
        UdpResult r;
        r.err = "rng";
        return r;
    }
    pkt[16] = 0x21;           
    pkt[17] = 0x20;           
    pkt[18] = 0x22;           
    pkt[19] = 0x08;           
    pkt[24] = 0; pkt[25] = 0; pkt[26] = 0; pkt[27] = 28;
    return udp_probe(host, port, pkt, sizeof(pkt), 1200);
}

UdpResult dns_probe(const std::string& host, int port) {
    unsigned char q[] = {
        0,0,        0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
        0x00,0x01, 0x00,0x01
    };
    if (RAND_bytes(q, 2) != 1) {
        UdpResult r;
        r.err = "rng";
        return r;
    }
    return udp_probe(host, port, q, sizeof(q), 1200);
}

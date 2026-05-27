#include "j3_probes.h"

#include "tcp_scanner.h"
#include "../core/utils.h"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

// Send a probe and collect response
[[nodiscard]] J3Result j3_send(
    std::string_view host,
    int port,
    std::string_view name,
    std::span<const std::byte> data,
    bool close_after_send = false
) {
    J3Result r;
    r.name = std::string{name};
    
    const auto t0{std::chrono::steady_clock::now()};
    
    std::string err;
    SOCKET s{tcp_connect(std::string{host}, port, g_tcp_to, err)};
    if (s == INVALID_SOCKET) return r;
    
    SocketGuard guard{s};
    
    if (!data.empty()) {
        if (tcp_send_all(s, data.data(), static_cast<int>(data.size())) != static_cast<int>(data.size())) {
            return r;
        }
    }
    
    if (close_after_send) return r;
    
    std::array<char, 1024> buf{};
    const int n{tcp_recv_to(s, buf.data(), static_cast<int>(buf.size() - 1), 1200)};
    
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0
    ).count();
    
    if (n > 0) {
        r.responded = true;
        r.bytes = n;
        
        const std::string raw{buf.data(), static_cast<std::size_t>(n)};
        const auto nl{raw.find('\n')};
        r.first_line = trim(raw.substr(0, nl == std::string::npos ? raw.size() : nl));
        r.hex_head = hex_s(
            reinterpret_cast<const unsigned char*>(buf.data()),
            std::min(16, n),
            true
        );
    }
    
    return r;
}

// Overload for char data
[[nodiscard]] J3Result j3_send(
    std::string_view host,
    int port,
    std::string_view name,
    const void* data,
    int dlen,
    bool close_after_send = false
) {
    return j3_send(
        host, port, name,
        std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(data),
            static_cast<std::size_t>(dlen)
        },
        close_after_send
    );
}

// Check if line looks like HTTP response
[[nodiscard]] bool looks_like_http_line(std::string_view first_line, bool* bad_version_out = nullptr) {
    if (first_line.size() < 9) return false;
    if (!first_line.starts_with("HTTP/")) return false;
    
    const char x{first_line[5]};
    const char dot{first_line[6]};
    const char y{first_line[7]};
    
    if (dot != '.') return false;
    
    const bool good_version{(x == '1' && (y == '0' || y == '1')) || (x == '2' && y == '0')};
    if (!good_version && bad_version_out) {
        *bad_version_out = true;
    }
    
    return true;
}

// Check if probe name is a valid HTTP probe
[[nodiscard]] bool is_valid_http_probe(const char* name) noexcept {
    if (!name) return false;
    return std::strstr(name, "HTTP GET /") != nullptr ||
           std::strstr(name, "HTTP abs-URI") != nullptr;
}

} // namespace

[[nodiscard]] std::vector<J3Result> j3_probes(std::string_view host, int port) {
    std::vector<J3Result> out;
    const std::string host_str{host};
    
    // Probe 1: Empty/close - just connect and wait for data
    {
        std::string err;
        SOCKET s{tcp_connect(host_str, port, g_tcp_to, err)};
        J3Result r;
        r.name = "empty/close";
        
        if (s != INVALID_SOCKET) {
            SocketGuard guard{s};
            std::array<char, 128> buf{};
            const int n{tcp_recv_to(s, buf.data(), static_cast<int>(buf.size() - 1), 800)};
            
            if (n > 0) {
                r.responded = true;
                r.bytes = n;
                
                const std::string b{buf.data(), static_cast<std::size_t>(n)};
                std::string printable;
                for (char c : b) {
                    printable += (c >= 32 && c < 127) ? c : '.';
                }
                r.first_line = printable;
                r.hex_head = hex_s(
                    reinterpret_cast<const unsigned char*>(buf.data()),
                    std::min(16, n),
                    true
                );
            }
        }
        out.push_back(std::move(r));
    }
    
    // Probe 2: HTTP GET
    {
        const std::string req{
            "GET / HTTP/1.1\r\n"
            "Host: " + host_str + "\r\n"
            "User-Agent: curl/8.4.0\r\n"
            "Accept: */*\r\n\r\n"
        };
        out.push_back(j3_send(host, port, "HTTP GET /", req.data(), static_cast<int>(req.size())));
    }
    
    // Probe 3: HTTP CONNECT
    {
        const std::string req{"CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n"};
        out.push_back(j3_send(host, port, "HTTP CONNECT", req.data(), static_cast<int>(req.size())));
    }
    
    // Probe 4: SSH banner
    {
        const std::string req{"SSH-2.0-OpenSSH_8.9p1\r\n"};
        out.push_back(j3_send(host, port, "SSH banner", req.data(), static_cast<int>(req.size())));
    }
    
    // Probe 5: Random 512 bytes
    {
        std::array<unsigned char, 512> buf{};
        if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) == 1) {
            out.push_back(j3_send(host, port, "random 512B", buf.data(), static_cast<int>(buf.size())));
        }
    }
    
    // Probe 6: TLS ClientHello with invalid SNI
    {
        constexpr unsigned char kHello[] = {
            0x16, 0x03, 0x01, 0x00, 0x70,  // TLS record
            0x01, 0x00, 0x00, 0x6c,        // Handshake header
            0x03, 0x03,                    // TLS 1.2
            // Random (32 bytes) - will be filled
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00,                          // Session ID length
            0x00, 0x02,                    // Cipher suites length
            0x13, 0x02,                    // TLS_AES_256_GCM_SHA384
            0x01, 0x00,                    // Compression methods
            0x00, 0x41,                    // Extensions length
            // SNI extension with ".invalid"
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b,
            0, 0, 0, '.', 'i', 'n', 'v', 'a', 'l', 'i', 'd',
            // ALPN extension
            0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08,
            'h', 't', 't', 'p', '/', '1', '.', '1',
            // Other extensions
            0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
            0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d,
            0x00, 0x0d, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x01, 0x05, 0x01, 0x08, 0x07, 0x08, 0x08,
            0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
            0x00, 0x33, 0x00, 0x02, 0x00, 0x00
        };
        std::array<unsigned char, sizeof(kHello)> hello{};
        std::copy(std::begin(kHello), std::end(kHello), hello.begin());
        
        // Fill random bytes
        if (RAND_bytes(hello.data() + 11, 32) == 1) {
            // Randomize SNI prefix
            for (std::size_t i{11 + 32}; i + 11 <= hello.size(); ++i) {
                if (hello[i] == '.' && hello[i + 1] == 'i' && hello[i + 2] == 'n' &&
                    hello[i + 3] == 'v' && hello[i + 4] == 'a' && hello[i + 5] == 'l' &&
                    hello[i + 6] == 'i' && hello[i + 7] == 'd') {
                    std::array<unsigned char, 3> r{};
                    if (RAND_bytes(r.data(), 3) == 1) {
                        hello[i - 3] = static_cast<unsigned char>('a' + (r[0] % 26));
                        hello[i - 2] = static_cast<unsigned char>('a' + (r[1] % 26));
                        hello[i - 1] = static_cast<unsigned char>('a' + (r[2] % 26));
                    }
                    break;
                }
            }
            out.push_back(j3_send(host, port, "TLS CH invalid-SNI", hello.data(), static_cast<int>(hello.size())));
        }
    }
    
    // Probe 7: HTTP absolute URI (proxy-style)
    {
        const std::string req{"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"};
        out.push_back(j3_send(host, port, "HTTP abs-URI (proxy-style)", req.data(), static_cast<int>(req.size())));
    }
    
    // Probe 8: Garbage bytes
    {
        std::array<unsigned char, 128> garb;
        garb.fill(0xFF);
        out.push_back(j3_send(host, port, "0xFF x128", garb.data(), static_cast<int>(garb.size())));
    }
    
    return out;
}

[[nodiscard]] J3Analysis j3_analyze(const std::vector<J3Result>& probes) {
    J3Analysis a;
    
    struct KeyEntry {
        std::string line;
        int bytes;
        const char* name;
    };
    std::vector<KeyEntry> keys;
    
    for (const auto& p : probes) {
        if (p.responded) {
            ++a.resp;
            keys.push_back({p.first_line, p.bytes, p.name.c_str()});
            
            bool bad_v{false};
            const bool is_http{looks_like_http_line(p.first_line, &bad_v)};
            
            if (is_http && !bad_v) {
                ++a.http_real;
            } else if (is_http && bad_v) {
                ++a.http_bad_version;
            } else {
                ++a.raw_non_http;
            }
        } else {
            ++a.silent;
        }
    }
    
    // Check for canned responses
    for (std::size_t i{0}; i < keys.size(); ++i) {
        int count{0};
        bool has_valid_http{false};
        
        for (std::size_t j{0}; j < keys.size(); ++j) {
            if (keys[i].line == keys[j].line && keys[i].bytes == keys[j].bytes) {
                ++count;
                if (is_valid_http_probe(keys[j].name)) {
                    has_valid_http = true;
                }
            }
        }
        
        if (count >= 2 && keys[i].line.size() > 3 && has_valid_http) {
            a.canned_identical = count;
            a.canned_line = keys[i].line;
            a.canned_bytes = keys[i].bytes;
            break;
        }
    }
    
    return a;
}

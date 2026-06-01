#include "service_probes.h"

#include "tcp_scanner.h"
#include "../core/utils.h"

#include <array>
#include <cctype>
#include <cstdlib>
#include <string>
#include <string_view>

[[nodiscard]] std::string printable_prefix(std::string_view s, std::size_t lim) {
    std::string out;
    out.reserve(std::min(s.size(), lim));
    
    for (std::size_t i{0}; i < s.size() && out.size() < lim; ++i) {
        const char c{s[i]};
        if (c >= 32 && c < 127) {
            out += c;
        } else if (c == '\r') {
            if (out.size() + 2 <= lim) out += "\\r";
            else out += '.';
        } else if (c == '\n') {
            if (out.size() + 2 <= lim) out += "\\n";
            else out += '.';
        } else {
            out += '.';
        }
    }
    return out;
}

[[nodiscard]] FpResult fp_http_plain(std::string_view host, int port) {
    FpResult f;
    f.service = "HTTP?";
    
    const std::string host_str{host};
    
    std::string err;
    SOCKET s{tcp_connect(host_str, port, g_tcp_to, err)};
    if (s == INVALID_SOCKET) {
        f.silent = true;
        return f;
    }
    SocketGuard guard{s};
    
    const std::string req{
        "GET / HTTP/1.1\r\n"
        "Host: " + host_str + "\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    };
    
    if (tcp_send_all(s, req.data(), static_cast<int>(req.size())) != static_cast<int>(req.size())) {
        f.silent = true;
        return f;
    }
    
    std::array<char, 2048> buf{};
    const int n{tcp_recv_to(s, buf.data(), static_cast<int>(buf.size() - 1), 1500)};
    
    if (n <= 0) {
        f.silent = true;
        return f;
    }
    
    buf[static_cast<std::size_t>(n)] = '\0';
    const std::string resp{buf.data(), static_cast<std::size_t>(n)};
    const std::string first{resp.substr(0, resp.find('\n'))};
    
    // Find Server header
    std::string server;
    const std::string lower_resp{tolower_s(resp)};
    const std::size_t sv{lower_resp.find("server:")};
    if (sv != std::string::npos) {
        auto e{resp.find('\r', sv)};
        if (e == std::string::npos) {
            e = resp.find('\n', sv);
        }
        server = trim(resp.substr(sv + 7, e - (sv + 7)));
    }
    
    f.service = "HTTP";
    f.details = trim(first);
    if (!server.empty()) {
        f.details += "  | Server: " + server;
    }

    // Check for common VPN frontend indicators
    const std::string rl{tolower_s(server)};
    if (contains(rl, "caddy")) {
        f.details += "  %[caddy-fronted - common Xray/Reality fallback]";
    } else if (contains(rl, "nginx")) {
        f.details += "  %[nginx - fallback host?]";
    } else if (contains(rl, "cloudflare")) {
        f.details += "  %[cloudflare]";
    }
    
    return f;
}

[[nodiscard]] FpResult fp_ssh(std::string_view banner_hint, std::string_view host, int port) {
    FpResult f;
    f.service = "SSH?";
    
    std::string b{banner_hint};
    
    // Try to get banner if not provided
    if (b.empty() || !b.starts_with("SSH-")) {
        const std::string host_str{host};
        std::string err;
        SOCKET s{tcp_connect(host_str, port, g_tcp_to, err)};
        
        if (s != INVALID_SOCKET) {
            SocketGuard guard{s};
            std::array<char, 256> buf{};
            const int n{tcp_recv_to(s, buf.data(), static_cast<int>(buf.size() - 1), 1500)};
            if (n > 0) {
                buf[static_cast<std::size_t>(n)] = '\0';
                b.assign(buf.data(), static_cast<std::size_t>(n));
            }
        }
    }
    
    if (b.starts_with("SSH-")) {
        f.service = "SSH";
        // Trim trailing CR/LF
        while (!b.empty() && (b.back() == '\r' || b.back() == '\n')) {
            b.pop_back();
        }
        f.details = b;
    } else {
        f.details = "no SSH banner (but port open)";
    }
    
    return f;
}

[[nodiscard]] FpResult fp_socks5(std::string_view host, int port) {
    FpResult f;
    f.service = "SOCKS?";
    
    const std::string host_str{host};
    std::string err;
    SOCKET s{tcp_connect(host_str, port, g_tcp_to, err)};
    
    if (s == INVALID_SOCKET) {
        f.silent = true;
        return f;
    }
    SocketGuard guard{s};
    
    // SOCKS5 greeting: version 5, 2 methods (no-auth, user/pass)
    constexpr std::array<unsigned char, 4> greet{0x05, 0x02, 0x00, 0x02};
    if (tcp_send_all(s, greet.data(), static_cast<int>(greet.size())) != static_cast<int>(greet.size())) {
        f.silent = true;
        return f;
    }
    
    std::array<unsigned char, 8> reply{};
    const int n{tcp_recv_to(s, reinterpret_cast<char*>(reply.data()), static_cast<int>(reply.size()), 1200)};
    
    if (n <= 0) {
        f.silent = true;
        return f;
    }
    
    if (reply[0] == 0x05 && n >= 2) {
        f.service = "SOCKS5";
        f.details = "methods=0x" + hex_s(reply.data() + 1, 1);
        
        if (reply[1] == 0x00) {
            f.details += " (no-auth)";
        } else if (reply[1] == 0x02) {
            f.details += " (user/pass)";
        } else if (reply[1] == 0xFF) {
            f.details += " (no acceptable)";
        }
        
        f.is_vpn_like = true;
    } else if (reply[0] == 0x05) {
        f.service = "SOCKS5";
        f.details = "short greeting";
        f.is_vpn_like = true;
    } else if (reply[0] == 0x04) {
        f.service = "SOCKS4";
        f.is_vpn_like = true;
    } else {
        f.details = "reply=" + hex_s(reply.data(), std::min(4, n));
    }
    
    return f;
}

[[nodiscard]] FpResult fp_http_connect(std::string_view host, int port) {
    FpResult f;
    f.service = "HTTP-PROXY?";

    const std::string host_str{host};
    std::string err;
    SOCKET s{tcp_connect(host_str, port, g_tcp_to, err)};
    
    if (s == INVALID_SOCKET) {
        f.silent = true;
        return f;
    }
    SocketGuard guard{s};

    const std::string req{
        "CONNECT example.com:443 HTTP/1.1\r\n"
        "Host: example.com:443\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "\r\n"
    };
    
    if (tcp_send_all(s, req.data(), static_cast<int>(req.size())) != static_cast<int>(req.size())) {
        f.silent = true;
        return f;
    }

    std::array<char, 512> buf{};
    const int n{tcp_recv_to(s, buf.data(), static_cast<int>(buf.size() - 1), 1500)};
    
    if (n <= 0) {
        f.silent = true;
        return f;
    }

    buf[static_cast<std::size_t>(n)] = '\0';
    const std::string resp{buf.data(), static_cast<std::size_t>(n)};
    const auto nl{resp.find('\n')};
    const std::string first{trim(resp.substr(0, nl == std::string::npos ? resp.size() : nl))};

    if (!starts_with(first, "HTTP/")) {
        f.details = printable_prefix(first);
        return f;
    }

    // Parse status code
    int status{0};
    const auto p1{first.find(' ')};
    if (p1 != std::string::npos && p1 + 1 < first.size()) {
        const auto p2{first.find(' ', p1 + 1)};
        const std::string code{first.substr(p1 + 1, (p2 == std::string::npos ? first.size() : p2) - (p1 + 1))};
        
        if (code.size() == 3 &&
            std::isdigit(static_cast<unsigned char>(code[0])) &&
            std::isdigit(static_cast<unsigned char>(code[1])) &&
            std::isdigit(static_cast<unsigned char>(code[2]))) {
            status = std::atoi(code.c_str());
        }
    }

    f.details = first;

    const bool connect_ok{status == 200 || status == 201 || status == 202};
    if (connect_ok) {
        f.service = "HTTP-PROXY";
        f.is_vpn_like = true;
    } else {
        f.service = "HTTP-CONNECT-DENY";
        f.is_vpn_like = false;
    }

    return f;
}

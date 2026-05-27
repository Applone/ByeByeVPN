#include "http_client.h"

#include "openssl_runtime.h"
#include "tcp_scanner.h"
#include "../core/utils.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <array>
#include <string>
#include <string_view>
#include <ranges>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

namespace {

// Constants
inline constexpr std::size_t kMaxResponseSize{1024 * 1024};  // 1 MB

// Check if string is an IPv4 literal
[[nodiscard]] bool is_ipv4_literal(std::string_view s) noexcept {
    int dots{0};
    for (char c : s) {
        if (c == '.') {
            ++dots;
        } else if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return dots == 3;
}

// Check if string is an IP literal (IPv4 or IPv6)
[[nodiscard]] bool is_ip_literal(std::string_view host) noexcept {
    if (host.empty()) return false;
    if (host[0] == '[') return false;  // IPv6 in brackets not directly supported
    return is_ipv4_literal(host) || host.find(':') != std::string_view::npos;
}

// Parse port from string
[[nodiscard]] bool parse_http_port(std::string_view text, int& port) {
    if (text.empty()) return false;
    
    // Check all digits
    if (!std::ranges::all_of(text, [](char c) {
        return std::isdigit(static_cast<unsigned char>(c)) != 0;
    })) {
        return false;
    }
    
    char* endptr{nullptr};
    errno = 0;
    const std::string text_str{text};
    const long v{std::strtol(text_str.c_str(), &endptr, 10)};
    
    if (errno != 0 || endptr == text_str.c_str() || *endptr != '\0' || v < 1 || v > 65535) {
        return false;
    }
    
    port = static_cast<int>(v);
    return true;
}

// Set socket timeouts
void set_socket_timeouts(SOCKET s, int timeout_ms) {
#ifdef _WIN32
    DWORD to{static_cast<DWORD>(timeout_ms)};
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
#else
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
}

// Format SSL error message
[[nodiscard]] std::string ssl_error_message(SSL* ssl, int rc, const char* op) {
    const int ssl_err{SSL_get_error(ssl, rc)};
    const unsigned long ossl{ERR_get_error()};
    
    std::array<char, 256> buf{};
    if (ossl) {
        ERR_error_string_n(ossl, buf.data(), buf.size());
    }
    
    std::string msg{op};
    msg += " err=" + std::to_string(ssl_err);
    if (buf[0]) {
        msg += " ";
        msg += buf.data();
    }
    return msg;
}

#ifdef _WIN32
// Load Windows root CAs into X509 store
[[nodiscard]] bool load_windows_root_cas_into_store(X509_STORE* store) {
    if (!store) return false;

    HCERTSTORE cert_store{CertOpenSystemStoreA(0, "ROOT")};
    if (!cert_store) return false;

    bool loaded_any{false};
    PCCERT_CONTEXT cert_ctx{nullptr};

    while ((cert_ctx = CertEnumCertificatesInStore(cert_store, cert_ctx)) != nullptr) {
        const unsigned char* p{cert_ctx->pbCertEncoded};
        X509* x{d2i_X509(nullptr, &p, cert_ctx->cbCertEncoded)};
        if (!x) continue;

        if (X509_STORE_add_cert(store, x) == 1) {
            loaded_any = true;
        } else {
            const unsigned long e{ERR_peek_last_error()};
            if (ERR_GET_REASON(e) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                loaded_any = true;
                ERR_clear_error();
            }
        }

        X509_free(x);
    }

    CertCloseStore(cert_store, 0);
    return loaded_any;
}
#endif

// Configure TLS context with trust store
[[nodiscard]] bool configure_tls_ctx(SSL_CTX* ctx) {
    if (!ctx) return false;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    bool trust_loaded{false};

    // Try common CA bundle locations
    constexpr std::array<const char*, 5> kCaBundleCandidates{{
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
    }};

    for (const char* path : kCaBundleCandidates) {
        if (!path || !*path) continue;
        
        FILE* fp{std::fopen(path, "rb")};
        if (!fp) continue;
        std::fclose(fp);

        ERR_clear_error();
        if (SSL_CTX_load_verify_locations(ctx, path, nullptr) == 1) {
            trust_loaded = true;
            break;
        }
        ERR_clear_error();
    }

    if (!trust_loaded) {
        ERR_clear_error();
        trust_loaded = SSL_CTX_set_default_verify_paths(ctx) == 1;
        if (!trust_loaded) ERR_clear_error();
    }

#ifdef _WIN32
    if (!trust_loaded) ERR_clear_error();
    X509_STORE* store{SSL_CTX_get_cert_store(ctx)};
    if (load_windows_root_cas_into_store(store)) {
        trust_loaded = true;
    }
#endif

    return trust_loaded;
}

// RAII wrapper for SSL_CTX
struct SslCtxDeleter {
    void operator()(SSL_CTX* ctx) const noexcept {
        if (ctx) SSL_CTX_free(ctx);
    }
};
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

// RAII wrapper for SSL
struct SslDeleter {
    void operator()(SSL* ssl) const noexcept {
        if (ssl) SSL_free(ssl);
    }
};
using SslPtr = std::unique_ptr<SSL, SslDeleter>;

} // namespace

[[nodiscard]] HttpResp http_get(std::string_view url, int timeout_ms) {
    HttpResp result;
    const auto start_time{std::chrono::steady_clock::now()};

    // Initialize OpenSSL
    std::string ossl_err;
    if (!openssl_runtime_init(&ossl_err)) {
        result.err = "openssl_init " + ossl_err;
        return result;
    }

    // Parse URL
    std::string host;
    std::string path{"/"};
    int port{80};
    bool is_https{false};

    std::string_view u{url};
    if (u.starts_with("https://")) {
        is_https = true;
        port = 443;
        u = u.substr(8);
    } else if (u.starts_with("http://")) {
        u = u.substr(7);
    } else {
        result.err = "bad url scheme";
        return result;
    }

    // Find path/query separator (fragment is stripped, not sent to server)
    const auto slash_pos{u.find('/')};
    const auto query_pos{u.find('?')};
    const auto frag_pos{u.find('#')};

    auto split_pos{slash_pos};
    if (query_pos != std::string_view::npos && 
        (split_pos == std::string_view::npos || query_pos < split_pos)) {
        split_pos = query_pos;
    }
    // Fragment terminates the URL but is not included in split_pos;
    // instead we use it only to bound the path/query portion.

    if (split_pos != std::string_view::npos) {
        host = std::string{u.substr(0, split_pos)};
        // Take path+query up to fragment (if any), stripping fragment
        if (frag_pos != std::string_view::npos && frag_pos > split_pos) {
            path = std::string{u.substr(split_pos, frag_pos - split_pos)};
        } else {
            path = std::string{u.substr(split_pos)};
        }
        if (path[0] != '/') {
            path = "/" + path;
        }
    } else {
        // No path component — host may still contain a fragment to strip
        if (frag_pos != std::string_view::npos) {
            host = std::string{u.substr(0, frag_pos)};
        } else {
            host = std::string{u};
        }
    }

    if (host.empty()) {
        result.err = "bad host";
        return result;
    }

    // Handle IPv6 addresses in brackets
    if (host[0] == '[') {
        const auto close{host.find(']')};
        if (close == std::string::npos) {
            result.err = "bad host";
            return result;
        }
        if (close + 1 < host.size()) {
            if (host[close + 1] != ':') {
                result.err = "bad host";
                return result;
            }
            if (!parse_http_port(std::string_view{host}.substr(close + 2), port)) {
                result.err = "bad port";
                return result;
            }
        }
        host = host.substr(1, close - 1);
    } else {
        // Parse port from host:port
        const auto first_col{host.find(':')};
        const auto last_col{host.rfind(':')};
        if (first_col != std::string::npos && first_col == last_col) {
            std::string_view ps{std::string_view{host}.substr(last_col + 1)};
            bool all_digits{!ps.empty()};
            for (char c : ps) {
                if (!std::isdigit(static_cast<unsigned char>(c))) {
                    all_digits = false;
                }
            }
            if (all_digits) {
                if (!parse_http_port(ps, port)) {
                    result.err = "bad port";
                    return result;
                }
                host.erase(last_col);
            }
        }
    }

    if (host.empty()) {
        result.err = "bad host";
        return result;
    }

    // Connect to server
    std::string conn_err;
    SOCKET s{tcp_connect(host, port, timeout_ms, conn_err)};
    if (s == INVALID_SOCKET) {
        result.err = "connect " + conn_err;
        return result;
    }
    
    SocketGuard socket_guard{s};
    set_socket_timeouts(s, timeout_ms);

    SslCtxPtr ctx;
    SslPtr ssl;

    if (is_https) {
        SSL_CTX* raw_ctx{SSL_CTX_new(TLS_client_method())};
        if (!raw_ctx) {
            result.err = "ssl_ctx_new";
            return result;
        }
        ctx.reset(raw_ctx);

        if (!configure_tls_ctx(ctx.get())) {
            result.err = "ssl_trust_store";
            return result;
        }

        SSL* raw_ssl{SSL_new(ctx.get())};
        if (!raw_ssl) {
            result.err = "ssl_new";
            return result;
        }
        ssl.reset(raw_ssl);

        if (!ssl_attach_socket(ssl.get(), s, &result.err)) {
            result.err = "ssl_set_fd " + result.err;
            return result;
        }

        const bool is_ip{is_ip_literal(host)};

        if (!is_ip) {
            if (SSL_set_tlsext_host_name(ssl.get(), host.c_str()) != 1) {
                result.err = "ssl_set_sni";
                return result;
            }
        }

        X509_VERIFY_PARAM* param{SSL_get0_param(ssl.get())};
        if (!param) {
            result.err = "ssl_get_param";
            return result;
        }

        if (is_ip) {
            if (X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str()) != 1) {
                result.err = "ssl_set_ip";
                return result;
            }
        } else {
            if (X509_VERIFY_PARAM_set1_host(param, host.c_str(), host.size()) != 1) {
                result.err = "ssl_set_host";
                return result;
            }
        }

        const int conn_rc{SSL_connect(ssl.get())};
        if (conn_rc != 1) {
            result.err = ssl_error_message(ssl.get(), conn_rc, "ssl_connect");
            return result;
        }

        const long verify{SSL_get_verify_result(ssl.get())};
        if (verify != X509_V_OK) {
            result.err = "ssl_verify " + std::to_string(verify);
            return result;
        }
    }

    // Build and send request
    const std::string req{
        "GET " + path + " HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Connection: close\r\n"
        "User-Agent: byebyevpn/3\r\n"
        "Accept: */*\r\n"
        "\r\n"
    };

    if (is_https) {
        const int wrote{SSL_write(ssl.get(), req.data(), static_cast<int>(req.size()))};
        if (wrote <= 0) {
            result.err = ssl_error_message(ssl.get(), wrote, "ssl_write");
            return result;
        }
        if (wrote != static_cast<int>(req.size())) {
            result.err = "ssl_write partial";
            return result;
        }
    } else {
        const int sent{tcp_send_all(s, req.data(), static_cast<int>(req.size()))};
        if (sent != static_cast<int>(req.size())) {
            result.err = "send " + std::to_string(WSAGetLastError());
            return result;
        }
    }

    // Read response
    std::string resp_data;
    std::array<char, 4096> buf{};
    
    while (true) {
        int got{0};
        if (is_https) {
            got = SSL_read(ssl.get(), buf.data(), static_cast<int>(buf.size()));
            if (got <= 0) {
                const int se{SSL_get_error(ssl.get(), got)};
                if (se == SSL_ERROR_ZERO_RETURN) {
                    break;
                }
                if (se == SSL_ERROR_WANT_READ || se == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                result.err = ssl_error_message(ssl.get(), got, "ssl_read");
                return result;
            }
        } else {
            got = tcp_recv_to(s, buf.data(), static_cast<int>(buf.size()), timeout_ms);
            if (got <= 0) break;
        }

        resp_data.append(buf.data(), static_cast<std::size_t>(got));
        if (resp_data.size() > kMaxResponseSize) break;
    }

    // Parse response
    const auto header_end{resp_data.find("\r\n\r\n")};
    if (header_end != std::string::npos) {
        std::string headers{resp_data.substr(0, header_end)};
        result.body = resp_data.substr(header_end + 4);

        // Parse status code
        const auto space1{headers.find(' ')};
        if (space1 != std::string::npos) {
            const auto space2{headers.find(' ', space1 + 1)};
            if (space2 != std::string::npos) {
                std::string_view status_str{
                    std::string_view{headers}.substr(space1 + 1, space2 - space1 - 1)
                };
                const std::string status_str_s{status_str};
                if (status_str.size() == 3 &&
                    std::isdigit(static_cast<unsigned char>(status_str[0])) &&
                    std::isdigit(static_cast<unsigned char>(status_str[1])) &&
                    std::isdigit(static_cast<unsigned char>(status_str[2]))) {
                    char* endptr{nullptr};
                    const long val{std::strtol(status_str_s.c_str(), &endptr, 10)};
                    if (endptr != status_str_s.c_str() && *endptr == '\0') {
                        result.status = static_cast<int>(val);
                    }
                }
            }
        }

        // Handle chunked transfer encoding
        const std::string h_lower{tolower_s(headers)};
        if (h_lower.find("transfer-encoding: chunked") != std::string::npos) {
            std::string decoded;
            std::size_t pos{0};
            while (pos < result.body.size()) {
                const auto nl{result.body.find("\r\n", pos)};
                if (nl == std::string::npos) break;
                
                const std::string hex_len{result.body.substr(pos, nl - pos)};
                char* endptr{nullptr};
                const long len{std::strtol(hex_len.c_str(), &endptr, 16)};
                if (endptr == hex_len.c_str() || len < 0) break;
                if (len == 0) break;
                
                pos = nl + 2;
                if (pos + static_cast<std::size_t>(len) > result.body.size()) break;
                decoded.append(result.body.substr(pos, static_cast<std::size_t>(len)));
                pos += static_cast<std::size_t>(len) + 2;
            }
            result.body = std::move(decoded);
        }
    } else {
        result.err = "no header";
    }

    result.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time
    ).count();
    
    return result;
}

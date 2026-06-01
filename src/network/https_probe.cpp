#include "https_probe.h"

#include "openssl_runtime.h"
#include "tcp_scanner.h"
#include "../core/utils.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace {

// Set socket timeouts
void set_socket_timeouts(SOCKET s, int to_ms) {
#ifdef _WIN32
    const DWORD to{static_cast<DWORD>(to_ms)};
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
#else
    timeval tv{};
    tv.tv_sec = to_ms / 1000;
    tv.tv_usec = (to_ms % 1000) * 1000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
}

// Format SSL error message
[[nodiscard]] std::string ssl_error_message(SSL* ssl, int rc, const char* op) {
    const int ssl_err{SSL_get_error(ssl, rc)};
    const unsigned long ossl{ERR_get_error()};
    
    std::array<char, 256> buf{};
    if (ossl != 0) {
        ERR_error_string_n(ossl, buf.data(), buf.size());
    }
    
    std::string msg{op};
    msg += " err=" + std::to_string(ssl_err);
    if (buf.at(0) != '\0') {
        msg += " ";
        msg += buf.data();
    }
    return msg;
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

// ALPN protocol list for HTTP/1.1
inline constexpr std::array<unsigned char, 9> kAlpnHttp11{
    8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

// Extract header value from response
[[nodiscard]] std::string get_header(
    std::string_view body,
    std::string_view lower_body,
    std::string_view key
) {
    const std::string lkey{tolower_s(std::string{key})};
    const std::string start_key{lkey + ":"};
    const std::string line_key{"\n" + lkey + ":"};
    
    std::size_t p{std::string_view::npos};
    if (lower_body.starts_with(start_key)) {
        p = 0;
    } else {
        p = lower_body.find(line_key);
    }
    
    if (p == std::string_view::npos) return {};
    
    const auto colon{body.find(':', p)};
    if (colon == std::string_view::npos) return {};
    
    const auto eol{body.find('\n', colon + 1)};
    const auto end_pos{eol == std::string_view::npos ? body.size() : eol};
    
    if (colon >= end_pos) return {};
    
    return trim(std::string{body.substr(colon + 1, end_pos - colon - 1)});
}

} // namespace

[[nodiscard]] HttpsProbe https_probe(
    std::string_view ip,
    int port,
    std::string_view host_hdr,
    int to_ms
) {
    HttpsProbe r;
    
    // Initialize OpenSSL
    std::string ossl_err;
    if (!openssl_runtime_init(&ossl_err)) {
        r.err = "openssl_init " + ossl_err;
        return r;
    }

    // Connect TCP
    std::string conn_err;
    SOCKET s{tcp_connect(std::string{ip}, port, to_ms, conn_err)};
    if (s == INVALID_SOCKET) {
        r.err = conn_err;
        return r;
    }
    SocketGuard socket_guard{s};
    set_socket_timeouts(s, to_ms);

    // Create SSL context
    SSL_CTX* raw_ctx{SSL_CTX_new(TLS_client_method())};
    if (!raw_ctx) {
        r.err = "ssl_ctx_new";
        return r;
    }
    SslCtxPtr ctx{raw_ctx};
    
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

    // Create SSL connection
    SSL* raw_ssl{SSL_new(ctx.get())};
    if (!raw_ssl) {
        r.err = "ssl_new";
        return r;
    }
    SslPtr ssl{raw_ssl};
    
    if (!ssl_attach_socket(ssl.get(), s, &r.err)) {
        r.err = "ssl_set_fd " + r.err;
        return r;
    }
    
    // Set SNI
    if (!host_hdr.empty()) {
        const std::string host_str{host_hdr};
        if (SSL_set_tlsext_host_name(ssl.get(), host_str.c_str()) != 1) {
            r.err = "ssl_set_sni";
            return r;
        }
    }
    
    // Set ALPN
    SSL_set_alpn_protos(ssl.get(), kAlpnHttp11.data(), static_cast<unsigned>(kAlpnHttp11.size()));
    
    // Perform handshake
    const int rc{SSL_connect(ssl.get())};
    if (rc != 1) {
        r.err = ssl_error_message(ssl.get(), rc, "ssl_connect");
        return r;
    }
    r.tls_ok = true;
    
    // Send HTTP request
    const std::string host_for_req{host_hdr.empty() ? std::string{ip} : std::string{host_hdr}};
    const std::string req{
        "GET / HTTP/1.1\r\n"
        "Host: " + host_for_req + "\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    };
    
    const int wrote{SSL_write(ssl.get(), req.data(), static_cast<int>(req.size()))};
    if (wrote <= 0) {
        r.err = ssl_error_message(ssl.get(), wrote, "ssl_write");
        return r;
    }
    if (std::cmp_not_equal(wrote ,req.size())) {
        r.err = "ssl_write partial";
        return r;
    }
    
    // Read response
    std::string body;
    std::array<char, 1024> buf{};
    
    for (int i{0}; i < 6; ++i) {
        const int n{SSL_read(ssl.get(), buf.data(), static_cast<int>(buf.size()))};
        if (n <= 0) {
            const int ssl_err{SSL_get_error(ssl.get(), n)};
            if (ssl_err == SSL_ERROR_ZERO_RETURN) break;
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) continue;
            r.err = ssl_error_message(ssl.get(), n, "ssl_read");
            break;
        }
        body.append(buf.data(), static_cast<std::size_t>(n));
        if (body.size() >= 4096) break;
    }
    
    SSL_shutdown(ssl.get());
    
    r.bytes = static_cast<int>(body.size());
    if (body.empty()) return r;
    
    r.responded = true;
    
    // Parse first line
    const auto nl{body.find('\n')};
    r.first_line = trim(body.substr(0, nl == std::string::npos ? body.size() : nl));
    
    // Parse HTTP version and status
    if (starts_with(r.first_line, "HTTP/")) {
        const auto sp{r.first_line.find(' ')};
        r.http_version = r.first_line.substr(0, sp == std::string::npos ? r.first_line.size() : sp);
        
        if (r.http_version.size() >= 8) {
            const char x{r.http_version.at(5)};
            const char y{r.http_version.at(7)};
            if (!(x == '1' || x == '2') || !(y == '0' || y == '1')) {
                r.version_anomaly = true;
            }
            if (x == '0') {
                r.version_anomaly = true;
            }
        } else {
            r.version_anomaly = true;
        }
        
        if (sp != std::string::npos) {
            const auto sp2{r.first_line.find(' ', sp + 1)};
            if (sp2 != std::string::npos) {
                const std::string code{r.first_line.substr(sp + 1, sp2 - sp - 1)};
                r.status_code = std::atoi(code.c_str());
            }
        }
    } else {
        r.version_anomaly = true;
    }
    
    // Parse Server header
    auto sh{body.find("\nServer:")};
    if (sh == std::string::npos) {
        sh = body.find("\nserver:");
    }
    if (sh != std::string::npos) {
        const auto se{body.find('\n', sh + 1)};
        const std::string sv{body.substr(sh + 8, (se == std::string::npos ? body.size() : se) - (sh + 8))};
        r.server_hdr = trim(sv);
    } else {
        r.no_server_hdr = r.status_code > 0;
    }
    
    // Parse other headers
    const std::string lower_body{tolower_s(body)};
    
    r.via_hdr = get_header(body, lower_body, "Via");
    r.forwarded_hdr = get_header(body, lower_body, "Forwarded");
    r.xff_hdr = get_header(body, lower_body, "X-Forwarded-For");
    r.xreal_ip_hdr = get_header(body, lower_body, "X-Real-IP");
    r.x_forwarded_proto = get_header(body, lower_body, "X-Forwarded-Proto");
    r.x_forwarded_host = get_header(body, lower_body, "X-Forwarded-Host");
    r.cf_ray_hdr = get_header(body, lower_body, "CF-Ray");
    r.cf_cache_status = get_header(body, lower_body, "CF-Cache-Status");
    r.x_amz_cf_id = get_header(body, lower_body, "X-Amz-Cf-Id");
    r.x_amz_cf_pop = get_header(body, lower_body, "X-Amz-Cf-Pop");
    r.x_azure_ref = get_header(body, lower_body, "X-Azure-Ref");
    r.x_azure_clientip = get_header(body, lower_body, "X-Azure-ClientIP");
    r.x_cache = get_header(body, lower_body, "X-Cache");
    r.x_served_by = get_header(body, lower_body, "X-Served-By");
    r.alt_svc = get_header(body, lower_body, "Alt-Svc");
    
    // Set flags
    r.has_proxy_leak = !r.via_hdr.empty() ||
                       !r.forwarded_hdr.empty() ||
                       !r.xff_hdr.empty() ||
                       !r.xreal_ip_hdr.empty();
    
    r.has_cdn_hdr = !r.cf_ray_hdr.empty() ||
                    !r.x_amz_cf_id.empty() ||
                    !r.x_azure_ref.empty() ||
                    !r.x_served_by.empty();
    
    return r;
}

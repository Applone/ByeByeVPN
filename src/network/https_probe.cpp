#include "https_probe.h"
#include <memory>
#include "tcp_scanner.h"
#include "../core/utils.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

static void set_socket_timeouts(SOCKET s, int to_ms) {
#ifdef _WIN32
    DWORD to = (DWORD)to_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
#else
    struct timeval tv{};
    tv.tv_sec = to_ms / 1000;
    tv.tv_usec = (to_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif
}

static std::string ssl_error_message(SSL* ssl, int rc, const char* op) {
    int ssl_err = SSL_get_error(ssl, rc);
    unsigned long ossl = ERR_get_error();
    char buf[256] = {0};
    if (ossl) ERR_error_string_n(ossl, buf, sizeof(buf));
    std::string msg = op;
    msg += " err=" + std::to_string(ssl_err);
    if (buf[0]) {
        msg += " ";
        msg += buf;
    }
    return msg;
}

HttpsProbe https_probe(const std::string& ip, int port, const std::string& host_hdr, int to_ms) {
    HttpsProbe r;
    std::string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }
    set_socket_timeouts(s, to_ms);

    SSL_CTX* raw_ctx = SSL_CTX_new(TLS_client_method());
    if (!raw_ctx) { r.err = "ssl_ctx_new"; closesocket(s); return r; }
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(raw_ctx, SSL_CTX_free);
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

    SSL* raw_ssl = SSL_new(ctx.get());
    if (!raw_ssl) { r.err = "ssl_new"; closesocket(s); return r; }
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(raw_ssl, SSL_free);
    if (SSL_set_fd(ssl.get(), (int)s) != 1) {
        r.err = "ssl_set_fd";
        closesocket(s);
        return r;
    }
    if (!host_hdr.empty() && SSL_set_tlsext_host_name(ssl.get(), host_hdr.c_str()) != 1) {
        r.err = "ssl_set_sni";
        closesocket(s);
        return r;
    }
    
    static const unsigned char alpn_h11[] = {8,'h','t','t','p','/','1','.','1'};
    SSL_set_alpn_protos(ssl.get(), alpn_h11, sizeof(alpn_h11));
    int rc = SSL_connect(ssl.get());
    if (rc != 1) {
        r.err = ssl_error_message(ssl.get(), rc, "ssl_connect");
        closesocket(s);
        return r;
    }
    r.tls_ok = true;
    std::string req = "GET / HTTP/1.1\r\nHost: " + (host_hdr.empty() ? ip : host_hdr) + "\r\n"
                 "Accept: */*\r\n"
                 "Connection: close\r\n\r\n";
    int wrote = SSL_write(ssl.get(), req.data(), (int)req.size());
    if (wrote <= 0) {
        r.err = ssl_error_message(ssl.get(), wrote, "ssl_write");
        closesocket(s);
        return r;
    }
    if (wrote != (int)req.size()) {
        r.err = "ssl_write partial";
        closesocket(s);
        return r;
    }
    std::string body;
    char buf[1024];
    for (int i=0; i<6; ++i) {
        int n = SSL_read(ssl.get(), buf, sizeof(buf));
        if (n <= 0) {
            int ssl_err = SSL_get_error(ssl.get(), n);
            if (ssl_err == SSL_ERROR_ZERO_RETURN) break;
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) continue;
            r.err = ssl_error_message(ssl.get(), n, "ssl_read");
            break;
        }
        body.append(buf, n);
        if (body.size() >= 4096) break;
    }
    SSL_shutdown(ssl.get());
    closesocket(s);
    r.bytes = (int)body.size();
    if (body.empty()) return r;
    r.responded = true;
    size_t nl = body.find('\n');
    r.first_line = trim(body.substr(0, nl == std::string::npos ? body.size() : nl));
    if (starts_with(r.first_line, "HTTP/")) {
        size_t sp = r.first_line.find(' ');
        r.http_version = r.first_line.substr(0, sp == std::string::npos ? r.first_line.size() : sp);
        if (r.http_version.size() >= 8) {
            char x = r.http_version[5], y = r.http_version[7];
            if (!(x=='1' || x=='2') || !(y=='0' || y=='1')) r.version_anomaly = true;
            if (x=='0') r.version_anomaly = true;
        } else r.version_anomaly = true;
        if (sp != std::string::npos) {
            size_t sp2 = r.first_line.find(' ', sp+1);
            if (sp2 != std::string::npos) {
                std::string code = r.first_line.substr(sp+1, sp2 - sp - 1);
                r.status_code = atoi(code.c_str());
            }
        }
    } else {
        r.version_anomaly = true;
    }
    size_t sh = body.find("\nServer:");
    if (sh == std::string::npos) sh = body.find("\nserver:");
    if (sh != std::string::npos) {
        size_t se = body.find('\n', sh + 1);
        std::string sv = body.substr(sh + 8, (se == std::string::npos ? body.size() : se) - (sh + 8));
        r.server_hdr = trim(sv);
    } else {
        r.no_server_hdr = (r.status_code > 0);
    }
    std::string lower_body = tolower_s(body);
    auto get_hdr = [&](const char* key) -> std::string {
        std::string lkl = tolower_s(key);
        std::string start_key = lkl + ":";
        std::string line_key = "\n" + lkl + ":";
        size_t p = lower_body.rfind(start_key, 0) == 0 ? 0 : lower_body.find(line_key);
        if (p == std::string::npos) return {};
        size_t colon = body.find(':', p);
        size_t eol = body.find('\n', colon == std::string::npos ? p : colon + 1);
        if (colon == std::string::npos || (eol != std::string::npos && colon > eol)) return {};
        std::string val = body.substr(colon + 1, (eol == std::string::npos ? body.size() : eol) - (colon + 1));
        return trim(val);
    };
    r.via_hdr           = get_hdr("Via");
    r.forwarded_hdr     = get_hdr("Forwarded");
    r.xff_hdr           = get_hdr("X-Forwarded-For");
    r.xreal_ip_hdr      = get_hdr("X-Real-IP");
    r.x_forwarded_proto = get_hdr("X-Forwarded-Proto");
    r.x_forwarded_host  = get_hdr("X-Forwarded-Host");
    r.cf_ray_hdr        = get_hdr("CF-Ray");
    r.cf_cache_status   = get_hdr("CF-Cache-Status");
    r.x_amz_cf_id       = get_hdr("X-Amz-Cf-Id");
    r.x_amz_cf_pop      = get_hdr("X-Amz-Cf-Pop");
    r.x_azure_ref       = get_hdr("X-Azure-Ref");
    r.x_azure_clientip  = get_hdr("X-Azure-ClientIP");
    r.x_cache           = get_hdr("X-Cache");
    r.x_served_by       = get_hdr("X-Served-By");
    r.alt_svc           = get_hdr("Alt-Svc");
    
    r.has_proxy_leak = !r.via_hdr.empty() ||
                       !r.forwarded_hdr.empty() ||
                       !r.xff_hdr.empty() ||
                       !r.xreal_ip_hdr.empty();
    r.has_cdn_hdr    = !r.cf_ray_hdr.empty() ||
                       !r.x_amz_cf_id.empty() ||
                       !r.x_azure_ref.empty() ||
                       !r.x_served_by.empty();
    return r;
}

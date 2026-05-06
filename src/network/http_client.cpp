#include "http_client.h"
#include <memory>
#include "tcp_scanner.h"
#include "../core/utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <chrono>
#include <vector>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <stdexcept>

static bool parse_http_port(const std::string& text, int& port) {
    if (text.empty()) return false;
    for (char c : text) {
        if (!std::isdigit((unsigned char)c)) return false;
    }
    char* end = nullptr;
    errno = 0;
    long v = std::strtol(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0' || v < 1 || v > 65535) return false;
    port = (int)v;
    return true;
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

HttpResp http_get(const std::string& url, int timeout_ms) {
    HttpResp r;
    auto t0 = std::chrono::steady_clock::now();
    
    // Simple URL parser
    std::string host, path = "/";
    int port = 80;
    bool is_https = false;
    
    std::string u = url;
    if (starts_with(u, "https://")) { is_https = true; port = 443; u = u.substr(8); }
    else if (starts_with(u, "http://")) { u = u.substr(7); }
    else { r.err = "bad url scheme"; return r; }
    
    size_t slash = u.find('/');
    if (slash != std::string::npos) {
        host = u.substr(0, slash);
        path = u.substr(slash);
    } else {
        host = u;
    }
    
    if (host.empty()) { r.err = "bad host"; return r; }

    if (!host.empty() && host[0] == '[') {
        size_t close = host.find(']');
        if (close == std::string::npos) { r.err = "bad host"; return r; }
        if (close + 1 < host.size()) {
            if (host[close + 1] != ':') { r.err = "bad host"; return r; }
            if (!parse_http_port(host.substr(close + 2), port)) { r.err = "bad port"; return r; }
        }
        host = host.substr(1, close - 1);
    } else {
        size_t first_col = host.find(':');
        size_t last_col = host.rfind(':');
        if (first_col != std::string::npos && first_col == last_col) {
            std::string ps = host.substr(last_col + 1);
            bool all_digits = !ps.empty();
            for (char c : ps) if (!std::isdigit((unsigned char)c)) all_digits = false;
            if (all_digits) {
                if (!parse_http_port(ps, port)) { r.err = "bad port"; return r; }
                host = host.substr(0, last_col);
            }
        }
    }
    if (host.empty()) { r.err = "bad host"; return r; }

    std::string err;
    SOCKET s = tcp_connect(host, port, timeout_ms, err);
    if (s == INVALID_SOCKET) { r.err = "connect " + err; return r; }

    SSL_CTX* raw_ctx = nullptr;
    SSL* raw_ssl = nullptr;
    if (is_https) {
        raw_ctx = SSL_CTX_new(TLS_client_method());
        if (!raw_ctx) { r.err = "ssl_ctx_new"; closesocket(s); return r; }
        if (SSL_CTX_set_default_verify_paths(raw_ctx) != 1) {
            r.err = "ssl_verify_paths";
            SSL_CTX_free(raw_ctx);
            closesocket(s);
            return r;
        }
        SSL_CTX_set_verify(raw_ctx, SSL_VERIFY_PEER, nullptr);

        raw_ssl = SSL_new(raw_ctx);
        if (!raw_ssl) { r.err = "ssl_new"; SSL_CTX_free(raw_ctx); closesocket(s); return r; }
        if (SSL_set_fd(raw_ssl, (int)s) != 1) {
            r.err = "ssl_set_fd";
            SSL_free(raw_ssl);
            SSL_CTX_free(raw_ctx);
            closesocket(s);
            return r;
        }
        if (SSL_set_tlsext_host_name(raw_ssl, host.c_str()) != 1) {
            r.err = "ssl_set_sni";
            SSL_free(raw_ssl);
            SSL_CTX_free(raw_ctx);
            closesocket(s);
            return r;
        }
        
        X509_VERIFY_PARAM *param = SSL_get0_param(raw_ssl);
        if (!param || X509_VERIFY_PARAM_set1_host(param, host.c_str(), host.size()) != 1) {
            r.err = "ssl_set_host";
            SSL_free(raw_ssl);
            SSL_CTX_free(raw_ctx);
            closesocket(s);
            return r;
        }
        
        // Timeout handling for SSL handshake is complex in non-blocking, so we rely on TCP timeout blocking
        if (SSL_connect(raw_ssl) <= 0) {
            r.err = "ssl_connect";
            SSL_free(raw_ssl);
            SSL_CTX_free(raw_ctx);
            closesocket(s);
            return r;
        }
        if (SSL_get_verify_result(raw_ssl) != X509_V_OK) {
            r.err = "ssl_verify";
            SSL_free(raw_ssl);
            SSL_CTX_free(raw_ctx);
            closesocket(s);
            return r;
        }
    }

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(raw_ctx, SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(raw_ssl, SSL_free);

    std::string req = "GET " + path + " HTTP/1.1\r\n"
                      "Host: " + host + "\r\n"
                      "Connection: close\r\n"
                      "User-Agent: \r\n"
                      "\r\n";

    if (is_https) {
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
    } else {
        int sent = tcp_send_all(s, req.data(), (int)req.size());
        if (sent != (int)req.size()) {
            r.err = "send " + std::to_string(WSAGetLastError());
            closesocket(s);
            return r;
        }
    }

    std::string resp_data;
    char buf[4096];
    while (true) {
        int got = 0;
        if (is_https) {
            got = SSL_read(ssl.get(), buf, sizeof(buf));
        } else {
            got = tcp_recv_to(s, buf, sizeof(buf), timeout_ms);
        }
        if (got <= 0) break;
        resp_data.append(buf, got);
        if (resp_data.size() > 1024 * 1024) break; // 1MB max
    }

    closesocket(s);

    size_t header_end = resp_data.find("\r\n\r\n");
    if (header_end != std::string::npos) {
        std::string headers = resp_data.substr(0, header_end);
        r.body = resp_data.substr(header_end + 4);
        
        size_t space1 = headers.find(' ');
        if (space1 != std::string::npos) {
            size_t space2 = headers.find(' ', space1 + 1);
            if (space2 != std::string::npos) {
                try {
                    r.status = std::stoi(headers.substr(space1 + 1, space2 - space1 - 1));
                } catch (const std::invalid_argument&) {
                    r.status = 0;
                } catch (const std::out_of_range&) {
                    r.status = 0;
                }
            }
        }
        
        // Handle chunked transfer encoding loosely
        std::string h_lower = tolower_s(headers);
        if (h_lower.find("transfer-encoding: chunked") != std::string::npos) {
            std::string decoded;
            size_t pos = 0;
            while (pos < r.body.size()) {
                size_t nl = r.body.find("\r\n", pos);
                if (nl == std::string::npos) break;
                std::string hex_len = r.body.substr(pos, nl - pos);
                int len = 0;
                try { len = std::stoi(hex_len, nullptr, 16); } catch(...) { break; }
                if (len == 0) break;
                pos = nl + 2;
                if (pos + len > r.body.size()) break;
                decoded.append(r.body.substr(pos, len));
                pos += len + 2; // skip \r\n
            }
            r.body = decoded;
        }
    } else {
        r.err = "no header";
    }

    r.ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count());
    return r;
}

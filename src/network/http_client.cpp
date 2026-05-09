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
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

namespace {

bool is_ipv4_literal(const std::string& s) {
    int dots = 0;
    for (char c : s) {
        if (c == '.') {
            ++dots;
        } else if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return dots == 3;
}

bool is_ip_literal(const std::string& host) {
    if (host.empty()) return false;
    if (host[0] == '[') return false;
    return is_ipv4_literal(host) || host.find(':') != std::string::npos;
}

bool parse_http_port(const std::string& text, int& port) {
    if (text.empty()) return false;
    if (!std::all_of(text.begin(), text.end(), [](char c) {
            return std::isdigit(static_cast<unsigned char>(c)) != 0;
        })) return false;

    char* end = nullptr;
    errno = 0;
    long v = std::strtol(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0' || v < 1 || v > 65535) return false;

    port = (int)v;
    return true;
}

void set_socket_timeouts(SOCKET s, int timeout_ms) {
#ifdef _WIN32
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
#else
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
}

std::string ssl_error_message(SSL* ssl, int rc, const char* op) {
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

#ifdef _WIN32
bool load_windows_root_cas_into_store(X509_STORE* store) {
    if (!store) return false;

    HCERTSTORE cert_store = CertOpenSystemStoreA(0, "ROOT");
    if (!cert_store) return false;

    bool loaded_any = false;
    PCCERT_CONTEXT cert_ctx = nullptr;

    while ((cert_ctx = CertEnumCertificatesInStore(cert_store, cert_ctx)) != nullptr) {
        const unsigned char* p = cert_ctx->pbCertEncoded;
        X509* x = d2i_X509(nullptr, &p, cert_ctx->cbCertEncoded);
        if (!x) continue;

        if (X509_STORE_add_cert(store, x) == 1) {
            loaded_any = true;
        } else {
            unsigned long e = ERR_peek_last_error();
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

bool configure_tls_ctx(SSL_CTX* ctx) {
    if (!ctx) return false;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    bool trust_loaded = false;

    static const char* kCaBundleCandidates[] = {
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
    };

    for (const char* path : kCaBundleCandidates) {
        if (!path || !*path) continue;
        FILE* fp = std::fopen(path, "rb");
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
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    if (load_windows_root_cas_into_store(store)) trust_loaded = true;
#endif

    return trust_loaded;
}

} // namespace

HttpResp http_get(const std::string& url, int timeout_ms) {
    HttpResp r;
    auto t0 = std::chrono::steady_clock::now();

    std::string ossl_err;
    if (!openssl_runtime_init(&ossl_err)) {
        r.err = "openssl_init " + ossl_err;
        return r;
    }

    std::string host;
    std::string path = "/";
    int port = 80;
    bool is_https = false;

    std::string u = url;
    if (starts_with(u, "https://")) {
        is_https = true;
        port = 443;
        u = u.substr(8);
    } else if (starts_with(u, "http://")) {
        u = u.substr(7);
    } else {
        r.err = "bad url scheme";
        return r;
    }

    size_t split_pos = std::string::npos;
    const size_t slash_pos = u.find('/');
    const size_t query_pos = u.find('?');
    const size_t frag_pos = u.find('#');

    split_pos = slash_pos;
    if (query_pos != std::string::npos && (split_pos == std::string::npos || query_pos < split_pos)) {
        split_pos = query_pos;
    }
    if (frag_pos != std::string::npos && (split_pos == std::string::npos || frag_pos < split_pos)) {
        split_pos = frag_pos;
    }

    if (split_pos != std::string::npos) {
        host = u.substr(0, split_pos);
        path = u.substr(split_pos);
        if (path[0] != '/') {
            path = "/" + path;
        }
    } else {
        host = u;
    }

    if (host.empty()) {
        r.err = "bad host";
        return r;
    }

    if (host[0] == '[') {
        size_t close = host.find(']');
        if (close == std::string::npos) {
            r.err = "bad host";
            return r;
        }
        if (close + 1 < host.size()) {
            if (host[close + 1] != ':') {
                r.err = "bad host";
                return r;
            }
            if (!parse_http_port(host.substr(close + 2), port)) {
                r.err = "bad port";
                return r;
            }
        }
        host = host.substr(1, close - 1);
    } else {
        size_t first_col = host.find(':');
        size_t last_col = host.rfind(':');
        if (first_col != std::string::npos && first_col == last_col) {
            std::string ps = host.substr(last_col + 1);
            bool all_digits = !ps.empty();
            for (char c : ps) {
                if (!std::isdigit((unsigned char)c)) all_digits = false;
            }
            if (all_digits) {
                if (!parse_http_port(ps, port)) {
                    r.err = "bad port";
                    return r;
                }
                host.erase(last_col);
            }
        }
    }

    if (host.empty()) {
        r.err = "bad host";
        return r;
    }

    SOCKET s = INVALID_SOCKET;
    auto close_socket = [&]() {
        if (s != INVALID_SOCKET) {
            closesocket(s);
            s = INVALID_SOCKET;
        }
    };

    auto connect_socket = [&]() -> bool {
        std::string err;
        s = tcp_connect(host, port, timeout_ms, err);
        if (s == INVALID_SOCKET) {
            r.err = "connect " + err;
            return false;
        }
        set_socket_timeouts(s, timeout_ms);
        return true;
    };

    if (!connect_socket()) {
        return r;
    }

    SSL_CTX* raw_ctx = nullptr;
    SSL* raw_ssl = nullptr;

    if (is_https) {
        raw_ctx = SSL_CTX_new(TLS_client_method());
        if (!raw_ctx) {
            r.err = "ssl_ctx_new";
            close_socket();
            return r;
        }

        if (!configure_tls_ctx(raw_ctx)) {
            SSL_CTX_free(raw_ctx);
            raw_ctx = nullptr;
            r.err = "ssl_trust_store";
            close_socket();
            return r;
        }

        raw_ssl = SSL_new(raw_ctx);
        if (!raw_ssl) {
            r.err = "ssl_new";
            SSL_CTX_free(raw_ctx);
            raw_ctx = nullptr;
            close_socket();
            return r;
        }

        if (!ssl_attach_socket(raw_ssl, s, &r.err)) {
            r.err = "ssl_set_fd " + r.err;
            SSL_free(raw_ssl);
            raw_ssl = nullptr;
            SSL_CTX_free(raw_ctx);
            raw_ctx = nullptr;
            close_socket();
            return r;
        }

        const bool is_ip = is_ip_literal(host);

        if (!is_ip) {
            if (SSL_set_tlsext_host_name(raw_ssl, host.c_str()) != 1) {
                r.err = "ssl_set_sni";
                SSL_free(raw_ssl);
                raw_ssl = nullptr;
                SSL_CTX_free(raw_ctx);
                raw_ctx = nullptr;
                close_socket();
                return r;
            }
        }

        X509_VERIFY_PARAM* param = SSL_get0_param(raw_ssl);
        if (!param) {
            r.err = "ssl_get_param";
            SSL_free(raw_ssl);
            raw_ssl = nullptr;
            SSL_CTX_free(raw_ctx);
            raw_ctx = nullptr;
            close_socket();
            return r;
        }

        if (is_ip) {
            if (X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str()) != 1) {
                r.err = "ssl_set_ip";
                SSL_free(raw_ssl);
                raw_ssl = nullptr;
                SSL_CTX_free(raw_ctx);
                raw_ctx = nullptr;
                close_socket();
                return r;
            }
        } else {
            if (X509_VERIFY_PARAM_set1_host(param, host.c_str(), host.size()) != 1) {
                r.err = "ssl_set_host";
                SSL_free(raw_ssl);
                raw_ssl = nullptr;
                SSL_CTX_free(raw_ctx);
                raw_ctx = nullptr;
                close_socket();
                return r;
            }
        }

        const int conn_rc = SSL_connect(raw_ssl);
        if (conn_rc != 1) {
            r.err = ssl_error_message(raw_ssl, conn_rc, "ssl_connect");
            SSL_free(raw_ssl);
            raw_ssl = nullptr;
            SSL_CTX_free(raw_ctx);
            raw_ctx = nullptr;
            close_socket();
            return r;
        }

        long verify = SSL_get_verify_result(raw_ssl);
        if (verify != X509_V_OK) {
            r.err = "ssl_verify " + std::to_string(verify);
            SSL_free(raw_ssl);
            raw_ssl = nullptr;
            SSL_CTX_free(raw_ctx);
            raw_ctx = nullptr;
            close_socket();
            return r;
        }
    }

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(raw_ctx, SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(raw_ssl, SSL_free);

    const std::string req = "GET " + path + " HTTP/1.1\r\n"
                            "Host: " + host + "\r\n"
                            "Connection: close\r\n"
                            "User-Agent: byebyevpn/3\r\n"
                            "Accept: */*\r\n"
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
            if (got <= 0) {
                int se = SSL_get_error(ssl.get(), got);
                if (se == SSL_ERROR_ZERO_RETURN) {
                    break;
                }
                if (se == SSL_ERROR_WANT_READ || se == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                r.err = ssl_error_message(ssl.get(), got, "ssl_read");
                closesocket(s);
                return r;
            }
        } else {
            got = tcp_recv_to(s, buf, sizeof(buf), timeout_ms);
            if (got <= 0) break;
        }

        resp_data.append(buf, got);
        if (resp_data.size() > 1024 * 1024) break;
    }

    closesocket(s);

    const size_t header_end = resp_data.find("\r\n\r\n");
    if (header_end != std::string::npos) {
        std::string headers = resp_data.substr(0, header_end);
        r.body = resp_data.substr(header_end + 4);

        const size_t space1 = headers.find(' ');
        if (space1 != std::string::npos) {
            const size_t space2 = headers.find(' ', space1 + 1);
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

        std::string h_lower = tolower_s(headers);
        if (h_lower.find("transfer-encoding: chunked") != std::string::npos) {
            std::string decoded;
            size_t pos = 0;
            while (pos < r.body.size()) {
                size_t nl = r.body.find("\r\n", pos);
                if (nl == std::string::npos) break;
                std::string hex_len = r.body.substr(pos, nl - pos);
                int len = 0;
                try {
                    len = std::stoi(hex_len, nullptr, 16);
                } catch (...) {
                    break;
                }
                if (len == 0) break;
                pos = nl + 2;
                if (pos + len > r.body.size()) break;
                decoded.append(r.body.substr(pos, len));
                pos += len + 2;
            }
            r.body = decoded;
        }
    } else {
        r.err = "no header";
    }

    r.ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count());
    return r;
}

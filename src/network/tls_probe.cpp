#include "tls_probe.h"

#include "openssl_runtime.h"
#include "tcp_scanner.h"
#include "../core/utils.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

// Calculate days difference from ASN1_TIME to now
[[nodiscard]] int asn1_time_diff_days_now(const ASN1_TIME* t, bool from_t_to_now) noexcept {
    if (!t) return 0;
    int day{0};
    int sec{0};
    if (from_t_to_now) {
        ASN1_TIME_diff(&day, &sec, t, nullptr);
    } else {
        ASN1_TIME_diff(&day, &sec, nullptr, t);
    }
    return day;
}

// Extract CN from X.509 subject string
[[nodiscard]] std::string extract_cn_from_subject(std::string_view subj) {
    const auto p{subj.find("CN=")};
    if (p == std::string_view::npos) return {};
    
    const auto start{p + 3};
    const auto e{subj.find_first_of("/,", start)};
    return std::string{subj.substr(start, e == std::string_view::npos ? std::string_view::npos : e - start)};
}

// Convert X509_NAME to string
[[nodiscard]] std::string x509_name_one(X509_NAME* n) {
    std::array<char, 512> buf{};
    X509_NAME_oneline(n, buf.data(), static_cast<int>(buf.size()));
    return std::string{buf.data()};
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

// RAII wrapper for X509
struct X509Deleter {
    void operator()(X509* x) const noexcept {
        if (x) X509_free(x);
    }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

// RAII wrapper for GENERAL_NAMES
struct GeneralNamesDeleter {
    void operator()(GENERAL_NAMES* gn) const noexcept {
        if (gn) GENERAL_NAMES_free(gn);
    }
};
using GeneralNamesPtr = std::unique_ptr<GENERAL_NAMES, GeneralNamesDeleter>;

// Check if issuer indicates a free ACME CA
[[nodiscard]] bool is_acme_issuer(std::string_view issuer) noexcept {
    return issuer.find("Let's Encrypt") != std::string_view::npos ||
           issuer.find("R3") != std::string_view::npos ||
           issuer.find("R10") != std::string_view::npos ||
           issuer.find("R11") != std::string_view::npos ||
           issuer.find("E5") != std::string_view::npos ||
           issuer.find("E6") != std::string_view::npos ||
           issuer.find("ZeroSSL") != std::string_view::npos ||
           issuer.find("Buypass") != std::string_view::npos ||
           issuer.find("Google Trust Services") != std::string_view::npos;
}

} // namespace

[[nodiscard]] TlsProbe tls_probe(
    std::string_view ip,
    int port,
    std::string_view sni,
    std::string_view alpn,
    int to_ms
) {
    TlsProbe r;

    // Initialize OpenSSL
    std::string ossl_err;
    if (!openssl_runtime_init(&ossl_err)) {
        r.err = "openssl_init " + ossl_err;
        return r;
    }

    const auto t0{std::chrono::steady_clock::now()};
    
    // Connect TCP
    std::string conn_err;
    SOCKET s{tcp_connect(std::string{ip}, port, to_ms, conn_err)};
    if (s == INVALID_SOCKET) {
        r.err = conn_err;
        return r;
    }
    SocketGuard socket_guard{s};

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
    if (!sni.empty()) {
        const std::string sni_str{sni};
        SSL_set_tlsext_host_name(ssl.get(), sni_str.c_str());
    }
    
    // Set ALPN protocols
    std::vector<unsigned char> wire;
    for (const auto& p : split(alpn, ',')) {
        const std::string v{trim(p)};
        if (v.empty() || v.size() > 255) continue;
        wire.push_back(static_cast<unsigned char>(v.size()));
        std::ranges::transform(v, std::back_inserter(wire), [](char c) {
            return static_cast<unsigned char>(c);
        });
    }
    if (!wire.empty()) {
        SSL_set_alpn_protos(ssl.get(), wire.data(), static_cast<unsigned>(wire.size()));
    }
    
    // Non-blocking handshake with timeout
    set_nonblocking(s, true);
    const auto deadline{t0 + std::chrono::milliseconds{to_ms}};
    int ssl_res{0};
    bool timed_out = false;
    
    while (true) {
        ssl_res = SSL_connect(ssl.get());
        if (ssl_res == 1) break;
        
        const int ssl_err{SSL_get_error(ssl.get(), ssl_res)};
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            const auto now{std::chrono::steady_clock::now()};
            if (now >= deadline) {
                timed_out = true;
                break;
            }
            
            const int remaining{static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count()
            )};
            
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(s, &fds);
            
            timeval tv{};
            tv.tv_sec = remaining / 1000;
            tv.tv_usec = (remaining % 1000) * 1000;
            
            const int sr{select(
                static_cast<int>(s) + 1,
                ssl_err == SSL_ERROR_WANT_READ ? &fds : nullptr,
                ssl_err == SSL_ERROR_WANT_WRITE ? &fds : nullptr,
                nullptr,
                &tv
            )};
            
            if (sr == 0) {
                timed_out = true;
                break;
            } else if (sr < 0) {
                r.err = "select error: " + std::string{strerror(errno)};
                timed_out = false;
                break;
            }
        } else {
            break;
        }
    }
    
    set_nonblocking(s, false);

    // Check handshake result
    if (ssl_res != 1) {
        if (timed_out) {
            r.err = "timeout during tls handshake";
        } else if (r.err.empty()) {
            const int ssl_err_code = SSL_get_error(ssl.get(), ssl_res);
            const unsigned long e{ERR_get_error()};
            std::array<char, 256> buf{};
            ERR_error_string_n(e, buf.data(), buf.size());
            r.err = buf[0] ? std::string{buf.data()} : "tls handshake failed";
            r.err += " (ssl_err=" + std::to_string(ssl_err_code) + ")";
        }
        return r;
    }
    
    r.ok = true;
    r.version = SSL_get_version(ssl.get());
    r.cipher = SSL_get_cipher_name(ssl.get());
    
    // Get ALPN
    const unsigned char* ap{nullptr};
    unsigned apl{0};
    SSL_get0_alpn_selected(ssl.get(), &ap, &apl);
    if (apl > 0) {
        r.alpn.assign(reinterpret_cast<const char*>(ap), apl);
    }
    
    // Get negotiated group
    const int nid{static_cast<int>(SSL_get_negotiated_group(ssl.get()))};
    if (const char* gn{OBJ_nid2sn(nid)}; gn) {
        r.group = gn;
    }
    
    // Parse certificate
    X509Ptr cert{SSL_get_peer_certificate(ssl.get())};
    if (cert) {
        r.has_certificate = true;
        r.cert_subject = x509_name_one(X509_get_subject_name(cert.get()));
        r.cert_issuer = x509_name_one(X509_get_issuer_name(cert.get()));
        r.subject_cn = extract_cn_from_subject(r.cert_subject);
        r.issuer_cn = extract_cn_from_subject(r.cert_issuer);
        r.self_signed = !r.cert_subject.empty() && r.cert_subject == r.cert_issuer;
        r.is_letsencrypt = is_acme_issuer(r.cert_issuer);
        
        // Certificate fingerprint
        std::array<unsigned char, 32> dgst{};
        unsigned dl{0};
        X509_digest(cert.get(), EVP_sha256(), dgst.data(), &dl);
        r.cert_sha256 = hex_s(dgst.data(), dl);
        
        // Validity dates
        const ASN1_TIME* nb{X509_get0_notBefore(cert.get())};
        const ASN1_TIME* na{X509_get0_notAfter(cert.get())};
        r.age_days = asn1_time_diff_days_now(nb, true);
        r.days_left = asn1_time_diff_days_now(na, false);
        
        if (nb && na) {
            int d{0};
            int secs{0};
            ASN1_TIME_diff(&d, &secs, nb, na);
            r.total_validity_days = d;
        }
        
        // Subject Alternative Names
        GeneralNamesPtr gens{
            reinterpret_cast<GENERAL_NAMES*>(
                X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr)
            )
        };
        
        if (gens) {
            const int nn{sk_GENERAL_NAME_num(gens.get())};
            for (int i{0}; i < nn; ++i) {
                GENERAL_NAME* g{sk_GENERAL_NAME_value(gens.get(), i)};
                if (g->type == GEN_DNS) {
                    unsigned char* us{nullptr};
                    const int ul{ASN1_STRING_to_UTF8(&us, g->d.dNSName)};
                    if (ul > 0 && us) {
                        std::string name{reinterpret_cast<char*>(us), static_cast<std::size_t>(ul)};
                        if (name.size() > 2 && name[0] == '*' && name[1] == '.') {
                            r.is_wildcard = true;
                        }
                        r.san.push_back(std::move(name));
                    }
                    if (us) OPENSSL_free(us);
                }
                // IP SANs intentionally ignored - SNI consistency matches DNS names only
            }
        }
        
        r.san_count = static_cast<int>(r.san.size());
        
        // Check wildcard in CN
        if (!r.is_wildcard && r.subject_cn.size() > 2 &&
            r.subject_cn[0] == '*' && r.subject_cn[1] == '.') {
            r.is_wildcard = true;
        }
    }
    
    SSL_shutdown(ssl.get());
    
    r.handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0
    ).count();
    
    return r;
}

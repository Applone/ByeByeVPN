#include "tls_probe.h"
#include <memory>
#include "openssl_runtime.h"
#include "tcp_scanner.h"
#include "../core/utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <chrono>

static int asn1_time_diff_days_now(const ASN1_TIME* t, bool from_t_to_now) {
    if (!t) return 0;
    int day = 0, sec = 0;
    if (from_t_to_now) ASN1_TIME_diff(&day, &sec, t, nullptr);
    else               ASN1_TIME_diff(&day, &sec, nullptr, t);
    return day;
}

static std::string extract_cn_from_subject(const std::string& subj) {
    size_t p = subj.find("CN=");
    if (p == std::string::npos) return {};
    p += 3;
    size_t e = subj.find_first_of("/,", p);
    return subj.substr(p, e == std::string::npos ? std::string::npos : e - p);
}

static std::string x509_name_one(X509_NAME* n) {
    char b[512]={0};
    X509_NAME_oneline(n, b, sizeof(b));
    return b;
}

TlsProbe tls_probe(const std::string& ip, int port, const std::string& sni,
                   const std::string& alpn, int to_ms) {
    TlsProbe r;

    std::string ossl_err;
    if (!openssl_runtime_init(&ossl_err)) {
        r.err = "openssl_init " + ossl_err;
        return r;
    }

    auto t0 = std::chrono::steady_clock::now();
    std::string err; SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }

    SSL_CTX* raw_ctx = SSL_CTX_new(TLS_client_method());
    if (!raw_ctx) { r.err = "ssl_ctx_new"; closesocket(s); return r; }
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(raw_ctx, SSL_CTX_free);
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

    SSL* raw_ssl = SSL_new(ctx.get());
    if (!raw_ssl) { r.err = "ssl_new"; closesocket(s); return r; }
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(raw_ssl, SSL_free);
    if (!ssl_attach_socket(ssl.get(), s, &r.err)) {
        r.err = "ssl_set_fd " + r.err;
        closesocket(s);
        return r;
    }
    if (!sni.empty()) SSL_set_tlsext_host_name(ssl.get(), sni.c_str());
    
    std::vector<unsigned char> wire;
    for (auto& p: split(alpn, ',')) {
        std::string v = trim(p); if (v.empty()) continue;
        wire.push_back((unsigned char)v.size());
        for (char c: v) wire.push_back((unsigned char)c);
    }
    if (!wire.empty()) SSL_set_alpn_protos(ssl.get(), wire.data(), (unsigned)wire.size());
    
    set_nonblocking(s, true);
    auto deadline = t0 + std::chrono::milliseconds(to_ms);
    int ssl_res = 0;
    while (true) {
        ssl_res = SSL_connect(ssl.get());
        if (ssl_res == 1) break;
        
        int ssl_err = SSL_get_error(ssl.get(), ssl_res);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) { ssl_res = -1; break; }
            int remaining = (int)std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            
            fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
            timeval tv{}; tv.tv_sec = remaining / 1000; tv.tv_usec = (remaining % 1000) * 1000;
            int sr = select((int)s + 1, (ssl_err == SSL_ERROR_WANT_READ ? &fds : nullptr),
                                       (ssl_err == SSL_ERROR_WANT_WRITE ? &fds : nullptr),
                                       nullptr, &tv);
            if (sr <= 0) { ssl_res = -1; break; }
        } else {
            break;
        }
    }
    set_nonblocking(s, false);

    if (ssl_res != 1) {
        if (ssl_res == -1) r.err = "timeout during tls handshake";
        else {
            unsigned long e = ERR_get_error();
            char b[256]; ERR_error_string_n(e, b, sizeof(b));
            r.err = b[0] ? std::string(b) : std::string("tls handshake failed");
        }
        closesocket(s);
        return r;
    }
    r.ok = true;
    r.version = SSL_get_version(ssl.get());
    r.cipher  = SSL_get_cipher_name(ssl.get());
    const unsigned char* ap=nullptr; unsigned apl=0;
    SSL_get0_alpn_selected(ssl.get(), &ap, &apl);
    if (apl) r.alpn.assign((const char*)ap, apl);
    int nid = SSL_get_negotiated_group(ssl.get());
    const char* gn = OBJ_nid2sn(nid);
    if (gn) r.group = gn;
    
    std::unique_ptr<X509, decltype(&X509_free)> cert(SSL_get_peer_certificate(ssl.get()), X509_free);
    if (cert) {
        r.cert_subject = x509_name_one(X509_get_subject_name(cert.get()));
        r.cert_issuer  = x509_name_one(X509_get_issuer_name(cert.get()));
        r.subject_cn   = extract_cn_from_subject(r.cert_subject);
        r.issuer_cn    = extract_cn_from_subject(r.cert_issuer);
        r.self_signed  = !r.cert_subject.empty() && r.cert_subject == r.cert_issuer;
        
        {
            const std::string& iss = r.cert_issuer;
            r.is_letsencrypt =
                iss.find("Let's Encrypt") != std::string::npos ||
                iss.find("R3") != std::string::npos || iss.find("R10") != std::string::npos ||
                iss.find("R11") != std::string::npos || iss.find("E5") != std::string::npos ||
                iss.find("E6") != std::string::npos ||
                iss.find("ZeroSSL") != std::string::npos ||
                iss.find("Buypass") != std::string::npos ||
                iss.find("Google Trust Services") != std::string::npos;
        }
        unsigned char dgst[32]; unsigned dl = 0;
        X509_digest(cert.get(), EVP_sha256(), dgst, &dl);
        r.cert_sha256 = hex_s(dgst, dl);
        
        const ASN1_TIME* nb = X509_get0_notBefore(cert.get());
        const ASN1_TIME* na = X509_get0_notAfter(cert.get());
        r.age_days  = asn1_time_diff_days_now(nb, true);
        r.days_left = asn1_time_diff_days_now(na, false);
        if (nb && na) {
            int d = 0, secs = 0; ASN1_TIME_diff(&d, &secs, nb, na); r.total_validity_days = d;
        }
        std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> gens(
            (GENERAL_NAMES*)X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr),
            GENERAL_NAMES_free
        );
        if (gens) {
            int nn = sk_GENERAL_NAME_num(gens.get());
            for (int i=0;i<nn;++i) {
                GENERAL_NAME* g = sk_GENERAL_NAME_value(gens.get(), i);
                if (g->type == GEN_DNS) {
                    unsigned char* us = nullptr;
                    int ul = ASN1_STRING_to_UTF8(&us, g->d.dNSName);
                    if (ul > 0) {
                        std::string name(reinterpret_cast<char*>(us), ul);
                        if (name.size() > 2 && name[0]=='*' && name[1]=='.') r.is_wildcard = true;
                        r.san.push_back(std::move(name));
                    }
                    if (us) OPENSSL_free(us);
                } else if (g->type == GEN_IPADD) {
                    // IP SANs are intentionally ignored here; SNI consistency matches DNS names only.
                }
            }
        }
        r.san_count = (int)r.san.size();
        if (!r.is_wildcard && !r.subject_cn.empty() && r.subject_cn.size() > 2 &&
            r.subject_cn[0] == '*' && r.subject_cn[1] == '.') r.is_wildcard = true;
    }
    SSL_shutdown(ssl.get());
    closesocket(s);
    r.handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();
    return r;
}

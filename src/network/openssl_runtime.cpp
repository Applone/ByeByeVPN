#include "openssl_runtime.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include <mutex>

namespace {

std::once_flag g_ossl_once;
bool g_ossl_ok = false;
std::string g_ossl_err;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
OSSL_PROVIDER* g_provider_default = nullptr;
OSSL_PROVIDER* g_provider_base = nullptr;
OSSL_PROVIDER* g_provider_legacy = nullptr;
#endif

std::string last_ssl_error_text(const char* fallback) {
    const unsigned long e = ERR_get_error();
    if (e == 0) return fallback ? std::string(fallback) : std::string("openssl");
    char buf[256] = {0};
    ERR_error_string_n(e, buf, sizeof(buf));
    return buf[0] ? std::string(buf) : (fallback ? std::string(fallback) : std::string("openssl"));
}

} // namespace

bool openssl_runtime_init(std::string* err) {
    std::call_once(g_ossl_once, [] {
        ERR_clear_error();

        if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr) != 1) {
            g_ossl_err = last_ssl_error_text("OPENSSL_init_ssl failed");
            g_ossl_ok = false;
            return;
        }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nullptr) != 1) {
            g_ossl_err = last_ssl_error_text("OPENSSL_init_crypto failed");
            g_ossl_ok = false;
            return;
        }

        g_provider_default = OSSL_PROVIDER_load(nullptr, "default");
        g_provider_base = OSSL_PROVIDER_load(nullptr, "base");
        if (!g_provider_default || !g_provider_base) {
            g_ossl_err = last_ssl_error_text("OSSL_PROVIDER_load failed");
            g_ossl_ok = false;
            return;
        }

        g_provider_legacy = OSSL_PROVIDER_load(nullptr, "legacy");
        ERR_clear_error();
#endif

        g_ossl_ok = true;
    });

    if (!g_ossl_ok && err) *err = g_ossl_err;
    return g_ossl_ok;
}

void openssl_runtime_cleanup() {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (g_provider_legacy) {
        OSSL_PROVIDER_unload(g_provider_legacy);
        g_provider_legacy = nullptr;
    }
    if (g_provider_base) {
        OSSL_PROVIDER_unload(g_provider_base);
        g_provider_base = nullptr;
    }
    if (g_provider_default) {
        OSSL_PROVIDER_unload(g_provider_default);
        g_provider_default = nullptr;
    }
#else
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
#endif
}

bool ssl_attach_socket(SSL* ssl, SOCKET s, std::string* err) {
    if (!ssl) {
        if (err) *err = "ssl_attach_socket: ssl=null";
        return false;
    }
    if (s == INVALID_SOCKET) {
        if (err) *err = "ssl_attach_socket: invalid socket";
        return false;
    }

#if defined(_WIN32) && defined(_WIN64)
    if (s > static_cast<SOCKET>(0x7fffffffULL)) {
        if (err) {
            *err = "ssl_attach_socket: SOCKET handle exceeds OpenSSL fd range";
        }
        return false;
    }
#endif

    ERR_clear_error();
    if (SSL_set_fd(ssl, static_cast<int>(s)) != 1) {
        if (err) *err = last_ssl_error_text("SSL_set_fd failed");
        return false;
    }

    return true;
}

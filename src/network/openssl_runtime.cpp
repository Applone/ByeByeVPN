#include "openssl_runtime.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include <mutex>
#include <array>

namespace {

// Thread-safe initialization state. A plain mutex + flag is used instead of
// std::call_once so the runtime can be torn down and rebuilt: once a
// std::once_flag has fired it can never run again, which would make
// openssl_runtime_init() a no-op after openssl_runtime_cleanup().
std::mutex g_ossl_mutex;
bool g_ossl_initialized{false};
bool g_ossl_ok{false};
std::string g_ossl_err;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
// OpenSSL 3.0+ provider handles
OSSL_PROVIDER* g_provider_default{nullptr};
OSSL_PROVIDER* g_provider_base{nullptr};
OSSL_PROVIDER* g_provider_legacy{nullptr};
#endif

// Get last SSL error as string
[[nodiscard]] std::string last_ssl_error_text(const char* fallback = "openssl") {
    const unsigned long e{ERR_get_error()};
    if (e == 0) {
        return fallback ? std::string{fallback} : std::string{"openssl"};
    }
    
    std::array<char, 256> buf{};
    ERR_error_string_n(e, buf.data(), buf.size());
    
    return buf.at(0) ? std::string{buf.data()} : 
           (fallback ? std::string{fallback} : std::string{"openssl"});
}

// Perform one-time initialization
void do_init() {
    ERR_clear_error();
    
    // Initialize SSL library
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr) != 1) {
        g_ossl_err = last_ssl_error_text("OPENSSL_init_ssl failed");
        g_ossl_ok = false;
        return;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // Initialize crypto for OpenSSL 3.0+
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nullptr) != 1) {
        g_ossl_err = last_ssl_error_text("OPENSSL_init_crypto failed");
        g_ossl_ok = false;
        return;
    }

    // Load required providers
    g_provider_default = OSSL_PROVIDER_load(nullptr, "default");
    g_provider_base = OSSL_PROVIDER_load(nullptr, "base");
    
    if (!g_provider_default || !g_provider_base) {
        g_ossl_err = last_ssl_error_text("OSSL_PROVIDER_load failed");
        g_ossl_ok = false;
        return;
    }

    // Try to load legacy provider (optional, may not be available)
    g_provider_legacy = OSSL_PROVIDER_load(nullptr, "legacy");
    ERR_clear_error();  // Clear any error from optional legacy load
#endif

    g_ossl_ok = true;
}

} // namespace

[[nodiscard]] bool openssl_runtime_init(std::string* err) {
    std::lock_guard<std::mutex> lock(g_ossl_mutex);

    if (!g_ossl_initialized) {
        do_init();
        g_ossl_initialized = true;
    }

    if (!g_ossl_ok && err) {
        *err = g_ossl_err;
    }
    return g_ossl_ok;
}

void openssl_runtime_cleanup() {
    std::lock_guard<std::mutex> lock(g_ossl_mutex);
    if (!g_ossl_initialized) return;

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

    // Allow a subsequent openssl_runtime_init() to rebuild the runtime.
    g_ossl_initialized = false;
    g_ossl_ok = false;
    g_ossl_err.clear();
}

[[nodiscard]] bool ssl_attach_socket(SSL* ssl, SOCKET s, std::string* err) {
    if (!ssl) {
        if (err) *err = "ssl_attach_socket: ssl=null";
        return false;
    }
    
    if (s == INVALID_SOCKET) {
        if (err) *err = "ssl_attach_socket: invalid socket";
        return false;
    }

#if defined(_WIN32) && defined(_WIN64)
    // On 64-bit Windows, check if socket handle fits in int
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

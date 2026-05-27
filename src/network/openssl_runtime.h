#pragma once

#include "socket_sys.h"

#include <string>
#include <optional>

// Forward declaration for SSL
struct ssl_st;
using SSL = ssl_st;

// Initialize OpenSSL runtime (thread-safe, idempotent)
// Returns true on success, false on failure with error message in err
[[nodiscard]] bool openssl_runtime_init(std::string* err = nullptr);

// Cleanup OpenSSL runtime (should be called at program exit)
void openssl_runtime_cleanup();

// Attach a socket to an SSL connection
// Returns true on success, false on failure with error message in err
[[nodiscard]] bool ssl_attach_socket(SSL* ssl, SOCKET s, std::string* err = nullptr);

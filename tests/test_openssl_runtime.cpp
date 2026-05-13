#include <catch2/catch_test_macros.hpp>

#include "network/openssl_runtime.h"
#include "network/tcp_scanner.h"
#include "network_test_helpers.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <string>

TEST_CASE("openssl runtime initializes successfully") {
    std::string err;
    const bool ok = openssl_runtime_init(&err);
    REQUIRE(ok);
    CHECK(err.empty());
}

TEST_CASE("openssl_runtime_init tolerates a null error pointer") {
    REQUIRE(openssl_runtime_init(nullptr));
    REQUIRE(openssl_runtime_init());
}

TEST_CASE("openssl_runtime_init is safe to call multiple times concurrently") {
    REQUIRE(openssl_runtime_init());
    REQUIRE(openssl_runtime_init());
    REQUIRE(openssl_runtime_init());
}

TEST_CASE("ssl_attach_socket validates input") {
    REQUIRE(openssl_runtime_init());

    std::string err;
    REQUIRE_FALSE(ssl_attach_socket(nullptr, INVALID_SOCKET, &err));
    REQUIRE(err.find("ssl=null") != std::string::npos);

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(ctx != nullptr);
    SSL* ssl = SSL_new(ctx);
    REQUIRE(ssl != nullptr);

    err.clear();
    REQUIRE_FALSE(ssl_attach_socket(ssl, INVALID_SOCKET, &err));
    REQUIRE(err.find("invalid socket") != std::string::npos);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

TEST_CASE("ssl_attach_socket succeeds with valid socket") {
    REQUIRE(openssl_runtime_init());

    testnet::TcpOneShotServer server([](SOCKET client) {
        char buf[8] = {0};
        recv(client, buf, sizeof(buf), 0);
    });

    std::string connect_err;
    const SOCKET s = tcp_connect("127.0.0.1", server.port(), 1000, connect_err);
    REQUIRE(s != INVALID_SOCKET);

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(ctx != nullptr);
    SSL* ssl = SSL_new(ctx);
    REQUIRE(ssl != nullptr);

    std::string attach_err;
    REQUIRE(ssl_attach_socket(ssl, s, &attach_err));
    CHECK(attach_err.empty());

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(s);
}

TEST_CASE("ssl_attach_socket tolerates a null error pointer") {
    REQUIRE(openssl_runtime_init());

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(ctx != nullptr);
    SSL* ssl = SSL_new(ctx);
    REQUIRE(ssl != nullptr);

    REQUIRE_FALSE(ssl_attach_socket(nullptr, INVALID_SOCKET, nullptr));
    REQUIRE_FALSE(ssl_attach_socket(ssl, INVALID_SOCKET, nullptr));

    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

TEST_CASE("ssl_attach_socket reports SSL_set_fd failure on closed socket") {
    REQUIRE(openssl_runtime_init());

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(ctx != nullptr);
    SSL* ssl = SSL_new(ctx);
    REQUIRE(ssl != nullptr);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    closesocket(s);

    std::string err;
    const bool ok = ssl_attach_socket(ssl, s, &err);
    if (!ok) {
        REQUIRE_FALSE(err.empty());
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

TEST_CASE("zzz_openssl_runtime_cleanup is safe and idempotent",
          "[openssl_runtime][cleanup]") {
    REQUIRE(openssl_runtime_init());
    openssl_runtime_cleanup();
    openssl_runtime_cleanup();
    REQUIRE(openssl_runtime_init());
}

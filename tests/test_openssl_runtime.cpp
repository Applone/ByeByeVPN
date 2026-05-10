#include <catch2/catch_test_macros.hpp>

#include "network/openssl_runtime.h"
#include "network/tcp_scanner.h"
#include "network_test_helpers.h"

#include <openssl/ssl.h>

TEST_CASE("openssl runtime initializes and cleans up") {
    std::string err;
    const bool ok = openssl_runtime_init(&err);
    REQUIRE(ok);
    CHECK(err.empty());
}

TEST_CASE("ssl_attach_socket validates input") {
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

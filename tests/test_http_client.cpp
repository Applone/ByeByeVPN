#include <catch2/catch_test_macros.hpp>

#include "network/http_client.h"
#include "network_test_helpers.h"

#include <string>

TEST_CASE("http_get rejects unsupported schemes") {
    const auto r = http_get("ftp://example.com", 200);
    REQUIRE(r.status == 0);
    REQUIRE(r.err == "bad url scheme");
}

TEST_CASE("http_get validates host and port syntax") {
    SECTION("missing host") {
        const auto r = http_get("http:///path", 200);
        REQUIRE(r.err == "bad host");
    }

    SECTION("invalid port") {
        const auto r = http_get("http://127.0.0.1:abc/", 200);
        REQUIRE((r.err == "bad port" || r.err.rfind("connect ", 0) == 0));
    }

    SECTION("invalid bracket host") {
        const auto r = http_get("http://[::1", 200);
        REQUIRE(r.err == "bad host");
    }
}

TEST_CASE("http_get parses status and body from loopback response") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        char req[1024] = {0};
        recv(client, req, sizeof(req), 0);
        const std::string resp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "Connection: close\r\n\r\n"
            "hello";
        testnet::send_all(client, resp);
    });

    const auto r = http_get("http://127.0.0.1:" + std::to_string(server.port()) + "/demo", 1000);
    REQUIRE(r.err.empty());
    REQUIRE(r.status == 200);
    REQUIRE(r.body == "hello");
    REQUIRE(r.ok());
}

TEST_CASE("http_get decodes chunked body") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        char req[1024] = {0};
        recv(client, req, sizeof(req), 0);
        const std::string resp =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n\r\n"
            "4\r\nWiki\r\n"
            "5\r\npedia\r\n"
            "0\r\n\r\n";
        testnet::send_all(client, resp);
    });

    const auto r = http_get("http://127.0.0.1:" + std::to_string(server.port()) + "/", 1000);
    REQUIRE(r.status == 200);
    REQUIRE(r.body == "Wikipedia");
    REQUIRE(r.err.empty());
}

TEST_CASE("http_get reports missing headers") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        char req[1024] = {0};
        recv(client, req, sizeof(req), 0);
        testnet::send_all(client, "raw-body-no-headers");
    });

    const auto r = http_get("http://127.0.0.1:" + std::to_string(server.port()) + "/", 1000);
    REQUIRE(r.status == 0);
    REQUIRE(r.err == "no header");
}

#include <catch2/catch_test_macros.hpp>

#include "network/tcp_scanner.h"
#include "network_test_helpers.h"

#include <string>

TEST_CASE("tcp_connect reaches loopback server") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        const char kMsg[] = "ok";
        send(client, kMsg, 2, 0);
    });

    std::string err;
    const SOCKET s = tcp_connect("127.0.0.1", server.port(), 1000, err);
    REQUIRE(s != INVALID_SOCKET);
    CHECK(err.empty());

    char buf[8] = {0};
    const int n = tcp_recv_to(s, buf, sizeof(buf), 1000);
    REQUIRE(n == 2);
    REQUIRE(std::string(buf, buf + 2) == "ok");
    closesocket(s);
}

TEST_CASE("tcp_connect reports refused for closed loopback port") {
    const int closed_port = testnet::reserve_unused_tcp_port();

    std::string err;
    const SOCKET s = tcp_connect("127.0.0.1", closed_port, 200, err);
    REQUIRE(s == INVALID_SOCKET);
    REQUIRE((err == "refused" || err == "other"));
}

TEST_CASE("tcp_send_all writes full payload") {
    std::string received;
    const std::string payload = "hello-over-tcp";

    {
        testnet::TcpOneShotServer server([&received](SOCKET client) {
            char buf[256] = {0};
            const int n = recv(client, buf, sizeof(buf), 0);
            if (n > 0) {
                received.assign(buf, buf + n);
            }
        });

        std::string err;
        const SOCKET s = tcp_connect("127.0.0.1", server.port(), 1000, err);
        REQUIRE(s != INVALID_SOCKET);

        const int sent = tcp_send_all(s, payload.data(), static_cast<int>(payload.size()));
        REQUIRE(sent == static_cast<int>(payload.size()));
        closesocket(s);
    }

    REQUIRE(received == payload);
}

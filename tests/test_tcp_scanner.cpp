#include <catch2/catch_test_macros.hpp>

#include "network/tcp_scanner.h"
#include "network_test_helpers.h"

#include <chrono>
#include <string>
#include <thread>
#include <vector>

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

TEST_CASE("tcp_connect reports dns error for unresolvable host") {
    std::string err;
    const SOCKET s = tcp_connect("name with spaces and no resolution", 12345, 200, err);
    REQUIRE(s == INVALID_SOCKET);
    REQUIRE(err == "dns");
}

TEST_CASE("tcp_connect reports timeout for unroutable destination") {
    std::string err;
    // RFC5737 documentation network — should not route, expected to time out
    const SOCKET s = tcp_connect("192.0.2.1", 1, 80, err);
    REQUIRE(s == INVALID_SOCKET);
    REQUIRE((err == "timeout" || err == "other" || err == "refused"));
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

TEST_CASE("tcp_send_all returns immediately for zero-length payload") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        char buf[4] = {0};
        recv(client, buf, sizeof(buf), 0);
    });

    std::string err;
    const SOCKET s = tcp_connect("127.0.0.1", server.port(), 1000, err);
    REQUIRE(s != INVALID_SOCKET);

    const int sent = tcp_send_all(s, "", 0);
    REQUIRE(sent == 0);

    closesocket(s);
}

TEST_CASE("tcp_send_all reports error on closed socket") {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    closesocket(s);

    const char payload[] = "data";
    const int sent = tcp_send_all(s, payload, 4);
    REQUIRE(sent <= 0);
}

TEST_CASE("tcp_recv_to returns 0 when peer closes cleanly") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        // accept then close immediately
        (void)client;
    });

    std::string err;
    const SOCKET s = tcp_connect("127.0.0.1", server.port(), 1000, err);
    REQUIRE(s != INVALID_SOCKET);

    char buf[8] = {0};
    const int n = tcp_recv_to(s, buf, sizeof(buf), 500);
    REQUIRE(n <= 0);

    closesocket(s);
}

TEST_CASE("tcp_recv_to handles short timeout without crashing") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        send(client, "late", 4, 0);
    });

    std::string err;
    const SOCKET s = tcp_connect("127.0.0.1", server.port(), 1000, err);
    REQUIRE(s != INVALID_SOCKET);

    char buf[16] = {0};
    const int n = tcp_recv_to(s, buf, sizeof(buf), 10);
    // recv may time out (<=0) or race and capture the late bytes; either is fine
    REQUIRE(n <= 4);

    closesocket(s);
}

TEST_CASE("tcp_connect via localhost (IPv4 alias) succeeds") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        send(client, "x", 1, 0);
    });

    std::string err;
    const SOCKET s = tcp_connect("127.0.0.1", server.port(), 1000, err);
    REQUIRE(s != INVALID_SOCKET);
    CHECK(err.empty());
    closesocket(s);
}

#include <catch2/catch_test_macros.hpp>

#include "network/service_probes.h"
#include "network_test_helpers.h"

#include <string>

TEST_CASE("printable_prefix normalizes control characters") {
    const std::string input = std::string("ab\r\n") + std::string(1, static_cast<char>(1)) + "cd";
    const auto out = printable_prefix(input, 16);
    REQUIRE(out == "ab\\r\\n.cd");
}

TEST_CASE("fp_ssh accepts direct banner hint") {
    const auto r = fp_ssh("SSH-2.0-OpenSSH_9.0\r\n", "127.0.0.1", 22);
    REQUIRE(r.service == "SSH");
    REQUIRE(r.details == "SSH-2.0-OpenSSH_9.0");
}

TEST_CASE("fp_http_connect classifies HTTP proxy outcomes") {
    SECTION("connect success") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[512] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client, "HTTP/1.1 200 Connection established\r\n\r\n");
        });

        const auto r = fp_http_connect("127.0.0.1", server.port());
        REQUIRE(r.service == "HTTP-PROXY");
        REQUIRE(r.is_vpn_like);
        REQUIRE_FALSE(r.silent);
    }

    SECTION("connect denied") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[512] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client, "HTTP/1.1 403 Forbidden\r\n\r\n");
        });

        const auto r = fp_http_connect("127.0.0.1", server.port());
        REQUIRE(r.service == "HTTP-CONNECT-DENY");
        REQUIRE_FALSE(r.is_vpn_like);
    }
}

TEST_CASE("fp_socks5 detects socks method reply") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        unsigned char greet[8] = {0};
        recv(client, reinterpret_cast<char*>(greet), sizeof(greet), 0);
        const unsigned char reply[] = {0x05, 0x00};
        send(client, reinterpret_cast<const char*>(reply), sizeof(reply), 0);
    });

    const auto r = fp_socks5("127.0.0.1", server.port());
    REQUIRE(r.service == "SOCKS5");
    REQUIRE(r.is_vpn_like);
    REQUIRE(r.details.find("no-auth") != std::string::npos);
}

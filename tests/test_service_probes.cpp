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
    SECTION("no-auth method") {
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

    SECTION("user/pass method") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            unsigned char greet[8] = {0};
            recv(client, reinterpret_cast<char*>(greet), sizeof(greet), 0);
            const unsigned char reply[] = {0x05, 0x02};
            send(client, reinterpret_cast<const char*>(reply), sizeof(reply), 0);
        });

        const auto r = fp_socks5("127.0.0.1", server.port());
        REQUIRE(r.service == "SOCKS5");
        REQUIRE(r.is_vpn_like);
        REQUIRE(r.details.find("user/pass") != std::string::npos);
    }

    SECTION("no acceptable methods") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            unsigned char greet[8] = {0};
            recv(client, reinterpret_cast<char*>(greet), sizeof(greet), 0);
            const unsigned char reply[] = {0x05, 0xFF};
            send(client, reinterpret_cast<const char*>(reply), sizeof(reply), 0);
        });

        const auto r = fp_socks5("127.0.0.1", server.port());
        REQUIRE(r.service == "SOCKS5");
        REQUIRE(r.is_vpn_like);
        REQUIRE(r.details.find("no acceptable") != std::string::npos);
    }

    SECTION("SOCKS4 reply") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            unsigned char greet[8] = {0};
            recv(client, reinterpret_cast<char*>(greet), sizeof(greet), 0);
            const unsigned char reply[] = {0x04, 0x5A};
            send(client, reinterpret_cast<const char*>(reply), sizeof(reply), 0);
        });

        const auto r = fp_socks5("127.0.0.1", server.port());
        REQUIRE(r.service == "SOCKS4");
        REQUIRE(r.is_vpn_like);
    }

    SECTION("SOCKS5 short greeting") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            unsigned char greet[8] = {0};
            recv(client, reinterpret_cast<char*>(greet), sizeof(greet), 0);
            const unsigned char reply[] = {0x05};
            send(client, reinterpret_cast<const char*>(reply), sizeof(reply), 0);
        });

        const auto r = fp_socks5("127.0.0.1", server.port());
        REQUIRE(r.service == "SOCKS5");
        REQUIRE(r.is_vpn_like);
        REQUIRE(r.details == "short greeting");
    }

    SECTION("unknown protocol reply") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            unsigned char greet[8] = {0};
            recv(client, reinterpret_cast<char*>(greet), sizeof(greet), 0);
            const unsigned char reply[] = {0x01, 0x02, 0x03, 0x04};
            send(client, reinterpret_cast<const char*>(reply), sizeof(reply), 0);
        });

        const auto r = fp_socks5("127.0.0.1", server.port());
        REQUIRE(r.service == "SOCKS?");
        REQUIRE_FALSE(r.is_vpn_like);
        REQUIRE(r.details.find("reply=") != std::string::npos);
    }

    SECTION("silent server") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            unsigned char greet[8] = {0};
            recv(client, reinterpret_cast<char*>(greet), sizeof(greet), 0);
        });

        const auto r = fp_socks5("127.0.0.1", server.port());
        REQUIRE(r.silent);
    }
}

TEST_CASE("fp_ssh reads banner from connection") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        testnet::send_all(client, "SSH-2.0-TestServer\r\n");
    });

    const auto r = fp_ssh("", "127.0.0.1", server.port());
    REQUIRE(r.service == "SSH");
    REQUIRE(r.details == "SSH-2.0-TestServer");
}

TEST_CASE("fp_ssh no SSH banner from server") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        testnet::send_all(client, "HELLO WORLD\r\n");
    });

    const auto r = fp_ssh("", "127.0.0.1", server.port());
    REQUIRE(r.details == "no SSH banner (but port open)");
}

TEST_CASE("fp_http_plain detects server type annotations") {
    SECTION("nginx server") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[1024] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client,
                "HTTP/1.1 200 OK\r\n"
                "Server: nginx/1.24.0\r\n"
                "Connection: close\r\n\r\n");
        });

        const auto r = fp_http_plain("127.0.0.1", server.port());
        REQUIRE(r.service == "HTTP");
        REQUIRE(r.details.find("nginx") != std::string::npos);
    }

    SECTION("caddy server") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[1024] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client,
                "HTTP/1.1 200 OK\r\n"
                "Server: Caddy\r\n"
                "Connection: close\r\n\r\n");
        });

        const auto r = fp_http_plain("127.0.0.1", server.port());
        REQUIRE(r.service == "HTTP");
        REQUIRE(r.details.find("caddy") != std::string::npos);
    }

    SECTION("cloudflare server") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[1024] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client,
                "HTTP/1.1 200 OK\r\n"
                "Server: cloudflare\r\n"
                "Connection: close\r\n\r\n");
        });

        const auto r = fp_http_plain("127.0.0.1", server.port());
        REQUIRE(r.service == "HTTP");
        REQUIRE(r.details.find("cloudflare") != std::string::npos);
    }
}

TEST_CASE("fp_http_plain silent server") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        char req[1024] = {0};
        recv(client, req, sizeof(req), 0);
    });

    const auto r = fp_http_plain("127.0.0.1", server.port());
    REQUIRE(r.silent);
}

TEST_CASE("fp_http_connect non-HTTP response") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        char req[512] = {0};
        recv(client, req, sizeof(req), 0);
        testnet::send_all(client, "NOT-HTTP garbage\r\n");
    });

    const auto r = fp_http_connect("127.0.0.1", server.port());
    REQUIRE(r.service == "HTTP-PROXY?");
    REQUIRE_FALSE(r.is_vpn_like);
    REQUIRE_FALSE(r.details.empty());
}

TEST_CASE("fp_http_connect status code 201") {
    testnet::TcpOneShotServer server([](SOCKET client) {
        char req[512] = {0};
        recv(client, req, sizeof(req), 0);
        testnet::send_all(client, "HTTP/1.1 201 Created\r\n\r\n");
    });

    const auto r = fp_http_connect("127.0.0.1", server.port());
    REQUIRE(r.service == "HTTP-PROXY");
    REQUIRE(r.is_vpn_like);
}

TEST_CASE("printable_prefix edge cases") {
    REQUIRE(printable_prefix("", 80).empty());
    REQUIRE(printable_prefix("abc", 2) == "ab");
    REQUIRE(printable_prefix(std::string(1, static_cast<char>(0x7F)), 10) == ".");
    REQUIRE(printable_prefix(std::string(1, static_cast<char>(31)), 10) == ".");
}

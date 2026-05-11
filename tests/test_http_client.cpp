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

TEST_CASE("HttpResp::ok() boundary values") {
    REQUIRE(HttpResp{199, "", "", 0}.ok() == false);
    REQUIRE(HttpResp{200, "", "", 0}.ok() == true);
    REQUIRE(HttpResp{399, "", "", 0}.ok() == true);
    REQUIRE(HttpResp{400, "", "", 0}.ok() == false);
    REQUIRE(HttpResp{0, "", "", 0}.ok() == false);
    REQUIRE(HttpResp{500, "", "", 0}.ok() == false);
}

TEST_CASE("http_get handles https scheme detection") {
    const int closed = testnet::reserve_unused_tcp_port();
    const auto r = http_get("https://127.0.0.1:" + std::to_string(closed) + "/", 200);
    REQUIRE(!r.err.empty());
}

TEST_CASE("http_get URL parsing edge cases") {
    SECTION("query before slash") {
        const auto r = http_get("http://127.0.0.1:1?q=1", 100);
        REQUIRE(!r.err.empty());
    }

    SECTION("fragment before slash") {
        const auto r = http_get("http://127.0.0.1:1#frag", 100);
        REQUIRE(!r.err.empty());
    }

    SECTION("no path component") {
        const auto r = http_get("http://127.0.0.1:1", 100);
        REQUIRE(!r.err.empty());
    }

    SECTION("empty host with path") {
        const auto r = http_get("http:///", 200);
        REQUIRE(r.err == "bad host");
    }
}

TEST_CASE("http_get bracket IPv6 host parsing") {
    SECTION("bracket host missing close") {
        const auto r = http_get("http://[::1", 200);
        REQUIRE(r.err == "bad host");
    }

    SECTION("bracket host with bad char after close") {
        const auto r = http_get("http://[::1]a/", 200);
        REQUIRE(r.err == "bad host");
    }

    SECTION("bracket host with invalid port") {
        const auto r = http_get("http://[::1]:abc/", 200);
        REQUIRE(r.err == "bad port");
    }

    SECTION("bracket host with port 0") {
        const auto r = http_get("http://[::1]:0/", 200);
        REQUIRE(r.err == "bad port");
    }

    SECTION("bracket host with port 65536") {
        const auto r = http_get("http://[::1]:65536/", 200);
        REQUIRE(r.err == "bad port");
    }
}

TEST_CASE("http_get port parsing for non-bracket hosts") {
    SECTION("valid explicit port") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[1024] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client, "HTTP/1.1 204 No Content\r\n\r\n");
        });

        const auto r = http_get("http://127.0.0.1:" + std::to_string(server.port()) + "/", 1000);
        REQUIRE(r.status == 204);
    }

    SECTION("invalid port string") {
        const auto r = http_get("http://127.0.0.1:abc/", 200);
        REQUIRE((r.err == "bad port" || r.err.rfind("connect ", 0) == 0));
    }

    SECTION("port 65535 is valid") {
        const auto r = http_get("http://127.0.0.1:65535/", 100);
        REQUIRE(r.err != "bad port");
    }
}

TEST_CASE("http_get status parsing edge cases") {
    SECTION("non-numeric status") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[1024] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client, "HTTP/1.1 XXX Error\r\n\r\n");
        });

        const auto r = http_get("http://127.0.0.1:" + std::to_string(server.port()) + "/", 1000);
        REQUIRE(r.status == 0);
    }

    SECTION("no second space in status line") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[1024] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client, "HTTP/1.1\r\n\r\n");
        });

        const auto r = http_get("http://127.0.0.1:" + std::to_string(server.port()) + "/", 1000);
        REQUIRE(r.status == 0);
    }

    SECTION("no space at all in status line") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[1024] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client, "BADPROTOCOL\r\n\r\nbody");
        });

        const auto r = http_get("http://127.0.0.1:" + std::to_string(server.port()) + "/", 1000);
        REQUIRE(r.status == 0);
    }
}

TEST_CASE("http_get chunked decoding edge cases") {
    SECTION("invalid hex chunk length") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[1024] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client,
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: close\r\n\r\n"
                "gggg\r\ndata\r\n0\r\n\r\n");
        });

        const auto r = http_get("http://127.0.0.1:" + std::to_string(server.port()) + "/", 1000);
        REQUIRE(r.status == 200);
        REQUIRE(r.body.empty());
    }

    SECTION("truncated chunk body") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[1024] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client,
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: close\r\n\r\n"
                "ff\r\nshort");
        });

        const auto r = http_get("http://127.0.0.1:" + std::to_string(server.port()) + "/", 1000);
        REQUIRE(r.status == 200);
        REQUIRE(r.body.empty());
    }

    SECTION("missing CRLF in chunk") {
        testnet::TcpOneShotServer server([](SOCKET client) {
            char req[1024] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client,
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: close\r\n\r\n"
                "nolineending");
        });

        const auto r = http_get("http://127.0.0.1:" + std::to_string(server.port()) + "/", 1000);
        REQUIRE(r.status == 200);
        REQUIRE(r.body.empty());
    }
}

TEST_CASE("http_get connect failure for refused port") {
    const int closed = testnet::reserve_unused_tcp_port();
    const auto r = http_get("http://127.0.0.1:" + std::to_string(closed) + "/", 200);
    REQUIRE(r.status == 0);
    REQUIRE(r.err.rfind("connect ", 0) == 0);
}

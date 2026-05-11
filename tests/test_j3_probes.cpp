#include <catch2/catch_test_macros.hpp>

#include "core/utils.h"
#include "network/j3_probes.h"
#include "network_test_helpers.h"

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

namespace {

J3Result make_silent(const char* name) {
    J3Result r;
    r.name = name;
    r.responded = false;
    return r;
}

J3Result make_resp(const char* name, const std::string& first_line, int bytes) {
    J3Result r;
    r.name = name;
    r.responded = true;
    r.bytes = bytes;
    r.first_line = first_line;
    return r;
}

struct TcpTimeoutGuard {
    int saved = g_tcp_to;
    explicit TcpTimeoutGuard(int value) { g_tcp_to = value; }
    ~TcpTimeoutGuard() { g_tcp_to = saved; }
};

} // namespace

TEST_CASE("j3_analyze all silent probes") {
    std::vector<J3Result> probes = {
        make_silent("empty/close"),
        make_silent("HTTP GET /"),
        make_silent("random 512B"),
    };

    const auto a = j3_analyze(probes);
    REQUIRE(a.silent == 3);
    REQUIRE(a.resp == 0);
    REQUIRE(a.http_real == 0);
    REQUIRE(a.raw_non_http == 0);
    REQUIRE(a.canned_identical == 0);
}

TEST_CASE("j3_analyze all HTTP responses") {
    std::vector<J3Result> probes = {
        make_resp("HTTP GET /", "HTTP/1.1 200 OK", 200),
        make_resp("HTTP abs-URI (proxy-style)", "HTTP/1.1 200 OK", 200),
        make_resp("SSH banner", "SSH-2.0-OpenSSH", 15),
    };

    const auto a = j3_analyze(probes);
    REQUIRE(a.resp == 3);
    REQUIRE(a.http_real == 2);
    REQUIRE(a.raw_non_http == 1);
}

TEST_CASE("j3_analyze bad HTTP version") {
    std::vector<J3Result> probes = {
        make_resp("HTTP GET /", "HTTP/3.1 200 OK", 200),
        make_resp("HTTP abs-URI (proxy-style)", "HTTP/0.9 200 OK", 200),
    };

    const auto a = j3_analyze(probes);
    REQUIRE(a.http_bad_version == 2);
    REQUIRE(a.http_real == 0);
}

TEST_CASE("j3_analyze valid HTTP versions") {
    SECTION("HTTP/1.0") {
        const auto a = j3_analyze({make_resp("HTTP GET /", "HTTP/1.0 200 OK", 100)});
        REQUIRE(a.http_real == 1);
        REQUIRE(a.http_bad_version == 0);
    }

    SECTION("HTTP/1.1") {
        const auto a = j3_analyze({make_resp("HTTP GET /", "HTTP/1.1 200 OK", 100)});
        REQUIRE(a.http_real == 1);
    }

    SECTION("HTTP/2.0") {
        const auto a = j3_analyze({make_resp("HTTP GET /", "HTTP/2.0 200 OK", 100)});
        REQUIRE(a.http_real == 1);
    }
}

TEST_CASE("j3_analyze non-HTTP response classification") {
    std::vector<J3Result> probes = {
        make_resp("HTTP GET /", "SSH-2.0-OpenSSH", 15),
        make_resp("random 512B", "garbage data here", 512),
    };

    const auto a = j3_analyze(probes);
    REQUIRE(a.raw_non_http == 2);
    REQUIRE(a.http_real == 0);
}

TEST_CASE("j3_analyze canned identical response detection") {
    std::vector<J3Result> probes = {
        make_resp("HTTP GET /", "HTTP/1.1 403 Forbidden", 150),
        make_resp("HTTP abs-URI (proxy-style)", "HTTP/1.1 403 Forbidden", 150),
        make_resp("SSH banner", "SSH-2.0-Something", 18),
    };

    const auto a = j3_analyze(probes);
    REQUIRE(a.canned_identical >= 2);
    REQUIRE(a.canned_line == "HTTP/1.1 403 Forbidden");
    REQUIRE(a.canned_bytes == 150);
}

TEST_CASE("j3_analyze no canned if only non-HTTP probes match") {
    std::vector<J3Result> probes = {
        make_resp("empty/close", "SAME", 4),
        make_resp("SSH banner", "SAME", 4),
    };

    const auto a = j3_analyze(probes);
    REQUIRE(a.canned_identical == 0);
}

TEST_CASE("j3_analyze no canned if line too short") {
    std::vector<J3Result> probes = {
        make_resp("HTTP GET /", "OK", 2),
        make_resp("HTTP abs-URI (proxy-style)", "OK", 2),
    };

    const auto a = j3_analyze(probes);
    REQUIRE(a.canned_identical == 0);
}

TEST_CASE("j3_analyze mixed silent and responding") {
    std::vector<J3Result> probes = {
        make_silent("empty/close"),
        make_resp("HTTP GET /", "HTTP/1.1 200 OK", 100),
        make_silent("random 512B"),
        make_resp("HTTP CONNECT", "HTTP/1.1 200 OK", 100),
        make_resp("HTTP abs-URI (proxy-style)", "HTTP/1.1 200 OK", 100),
    };

    const auto a = j3_analyze(probes);
    REQUIRE(a.silent == 2);
    REQUIRE(a.resp == 3);
    REQUIRE(a.canned_identical >= 2);
}

TEST_CASE("j3_analyze empty probes list") {
    const auto a = j3_analyze({});
    REQUIRE(a.silent == 0);
    REQUIRE(a.resp == 0);
    REQUIRE(a.canned_identical == 0);
}

TEST_CASE("j3_analyze response too short for HTTP detection") {
    std::vector<J3Result> probes = {
        make_resp("HTTP GET /", "HTTP/1.", 7),
    };

    const auto a = j3_analyze(probes);
    REQUIRE(a.http_real == 0);
    REQUIRE(a.raw_non_http == 1);
}

TEST_CASE("j3_analyze missing dot in version") {
    const auto a = j3_analyze({make_resp("HTTP GET /", "HTTP/X11 200 OK", 100)});
    REQUIRE(a.http_real == 0);
    REQUIRE(a.raw_non_http == 1);
}

TEST_CASE("j3_analyze skips non-http duplicate group and picks later valid canned signature") {
    const std::vector<J3Result> probes = {
        make_resp("SSH banner", "SAME-LINE", 12),
        make_resp("0xFF x128", "SAME-LINE", 12),
        make_resp("HTTP GET /", "HTTP/1.1 403 Forbidden", 19),
        make_resp("HTTP abs-URI (proxy-style)", "HTTP/1.1 403 Forbidden", 19),
    };

    const auto a = j3_analyze(probes);
    REQUIRE(a.canned_identical == 2);
    REQUIRE(a.canned_line == "HTTP/1.1 403 Forbidden");
    REQUIRE(a.canned_bytes == 19);
}

TEST_CASE("j3_analyze requires canned line longer than three chars") {
    const auto a = j3_analyze({
        make_resp("HTTP GET /", "abc", 3),
        make_resp("HTTP abs-URI (proxy-style)", "abc", 3),
    });

    REQUIRE(a.canned_identical == 0);
    REQUIRE(a.canned_line.empty());
    REQUIRE(a.canned_bytes == 0);
}

TEST_CASE("j3_probes loopback service returns named probe set") {
    TcpTimeoutGuard timeout_guard(400);

    testnet::TcpMultiShotServer server(
        2,
        [](SOCKET client, int index) {
            if (index == 0) {
                const char first_probe[] = "srv\x01\n";
                testnet::send_all(client, std::string(first_probe, sizeof(first_probe) - 1));
                return;
            }

            char req[2048] = {0};
            recv(client, req, sizeof(req), 0);
            testnet::send_all(client, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        });

    const auto results = j3_probes("127.0.0.1", server.port());

    REQUIRE(results.size() >= 6);
    REQUIRE(results.size() <= 8);

    auto has_name = [&](const char* name) {
        return std::any_of(results.begin(), results.end(), [&](const J3Result& r) { return r.name == name; });
    };

    REQUIRE(has_name("empty/close"));
    REQUIRE(has_name("HTTP GET /"));
    REQUIRE(has_name("HTTP CONNECT"));
    REQUIRE(has_name("SSH banner"));
    REQUIRE(has_name("HTTP abs-URI (proxy-style)"));
    REQUIRE(has_name("0xFF x128"));

    const auto empty_it = std::find_if(results.begin(), results.end(), [](const J3Result& r) {
        return r.name == "empty/close";
    });
    REQUIRE(empty_it != results.end());
    REQUIRE(empty_it->responded);
    REQUIRE(empty_it->first_line == "srv..");

    const auto http_it = std::find_if(results.begin(), results.end(), [](const J3Result& r) {
        return r.name == "HTTP GET /";
    });
    REQUIRE(http_it != results.end());
    REQUIRE(http_it->responded);
    REQUIRE(http_it->first_line == "HTTP/1.1 200 OK");

    REQUIRE(server.handled_clients() >= 1);
}

TEST_CASE("j3_probes keeps probe descriptors when target is unreachable") {
    TcpTimeoutGuard timeout_guard(80);
    const int closed = testnet::reserve_unused_tcp_port();
    const auto results = j3_probes("127.0.0.1", closed);

    REQUIRE(results.size() >= 6);
    REQUIRE(results.size() <= 8);
    REQUIRE(std::all_of(results.begin(), results.end(), [](const J3Result& r) {
        return !r.name.empty() && !r.responded;
    }));
}

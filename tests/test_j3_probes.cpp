#include <catch2/catch_test_macros.hpp>

#include "network/j3_probes.h"

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

#include <catch2/catch_test_macros.hpp>

#include "analysis/ct_check.h"
#include "network/http_client.h"

#include <string>

static HttpResp g_stub_http_resp;
HttpResp ct_check_http_get_mock(const std::string&, int);

#define http_get ct_check_http_get_mock
#define ct_check ct_check_testable
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#include "../src/analysis/ct_check.cpp"
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#undef ct_check
#undef http_get

HttpResp ct_check_http_get_mock(const std::string&, int) {
    return g_stub_http_resp;
}

TEST_CASE("ct_check rejects non-hex or invalid-length digests") {
    const CtCheck bad_len = ct_check("1234", false);
    REQUIRE_FALSE(bad_len.queried);
    REQUIRE_FALSE(bad_len.found);
    REQUIRE(bad_len.err == "invalid sha256");

    const CtCheck bad_hex = ct_check(std::string(64, 'z'), false);
    REQUIRE_FALSE(bad_hex.queried);
    REQUIRE_FALSE(bad_hex.found);
    REQUIRE(bad_hex.err == "invalid sha256");
}

TEST_CASE("ct_check reports remote-disabled when not allowed") {
    const std::string valid_sha(64, 'a');
    const CtCheck r = ct_check(valid_sha, false);

    REQUIRE_FALSE(r.queried);
    REQUIRE_FALSE(r.found);
    REQUIRE(r.log_entries == 0);
    REQUIRE(r.err == "remote query disabled");
}

TEST_CASE("ct_check remote path reports HTTP status failure") {
    g_stub_http_resp = HttpResp{503, "", "", 0};

    const CtCheck r = ct_check_testable(std::string(64, 'b'), true);
    REQUIRE(r.queried);
    REQUIRE_FALSE(r.found);
    REQUIRE(r.log_entries == 0);
    REQUIRE(r.err == "http 503");
}

TEST_CASE("ct_check remote path handles JSON parse failures") {
    g_stub_http_resp = HttpResp{200, "[", "", 0};

    const CtCheck r = ct_check_testable(std::string(64, 'c'), true);
    REQUIRE(r.queried);
    REQUIRE_FALSE(r.found);
    REQUIRE(r.log_entries == 0);
    REQUIRE(r.err == "json parse");
}

TEST_CASE("ct_check remote path parses array and caps entry count") {
    SECTION("empty array") {
        g_stub_http_resp = HttpResp{200, "[]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'd'), true);
        REQUIRE(r.queried);
        REQUIRE_FALSE(r.found);
        REQUIRE(r.log_entries == 0);
        REQUIRE(r.err.empty());
    }

    SECTION("single object") {
        g_stub_http_resp = HttpResp{200, "[{\"id\":1,\"ok\":true}]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'e'), true);
        REQUIRE(r.queried);
        REQUIRE(r.found);
        REQUIRE(r.log_entries == 1);
        REQUIRE(r.err.empty());
    }

    SECTION("many objects are capped") {
        std::string body = "[";
        for (int i = 0; i < 55; ++i) {
            if (i > 0) body += ",";
            body += "{\"n\":" + std::to_string(i) + "}";
        }
        body += "]";

        g_stub_http_resp = HttpResp{200, body, "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'f'), true);
        REQUIRE(r.queried);
        REQUIRE(r.found);
        REQUIRE(r.log_entries == 50);
        REQUIRE(r.err.empty());
    }
}

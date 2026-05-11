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

    SECTION("exactly 50 entries") {
        std::string body = "[";
        for (int i = 0; i < 50; ++i) {
            if (i > 0) body += ",";
            body += "{\"n\":" + std::to_string(i) + "}";
        }
        body += "]";

        g_stub_http_resp = HttpResp{200, body, "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
        REQUIRE(r.log_entries == 50);
    }
}

TEST_CASE("ct_check validates sha256 edge cases") {
    SECTION("empty digest") {
        const CtCheck r = ct_check("", false);
        REQUIRE(r.err == "invalid sha256");
    }

    SECTION("63-char hex") {
        const CtCheck r = ct_check(std::string(63, 'a'), false);
        REQUIRE(r.err == "invalid sha256");
    }

    SECTION("65-char hex") {
        const CtCheck r = ct_check(std::string(65, 'a'), false);
        REQUIRE(r.err == "invalid sha256");
    }

    SECTION("uppercase hex is accepted") {
        const CtCheck r = ct_check(std::string(64, 'A'), false);
        REQUIRE(r.err == "remote query disabled");
    }

    SECTION("mixed case hex digits") {
        const std::string sha = "0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD";
        const CtCheck r = ct_check(sha, false);
        REQUIRE(r.err == "remote query disabled");
    }

    SECTION("non-hex char in middle") {
        std::string sha(64, 'a');
        sha[32] = 'g';
        const CtCheck r = ct_check(sha, false);
        REQUIRE(r.err == "invalid sha256");
    }
}

TEST_CASE("ct_check HTTP error code 0 means not ok") {
    g_stub_http_resp = HttpResp{0, "", "connect err", 0};
    const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
    REQUIRE(r.queried);
    REQUIRE(r.err == "http 0");
}

TEST_CASE("ct_check HTTP status 399 is ok") {
    g_stub_http_resp = HttpResp{399, "[]", "", 0};
    const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
    REQUIRE(r.queried);
    REQUIRE_FALSE(r.found);
    REQUIRE(r.err.empty());
}

TEST_CASE("ct_check HTTP status 400 is not ok") {
    g_stub_http_resp = HttpResp{400, "[]", "", 0};
    const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
    REQUIRE(r.queried);
    REQUIRE(r.err == "http 400");
}

TEST_CASE("JSON parser handles string escape sequences") {
    SECTION("standard escapes") {
        g_stub_http_resp = HttpResp{200, R"([{"s":"a\"b\\c\/d"}])", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
        REQUIRE(r.log_entries == 1);
    }

    SECTION("control character escapes") {
        g_stub_http_resp = HttpResp{200, R"([{"s":"\b\f\n\r\t"}])", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("unicode escape") {
        g_stub_http_resp = HttpResp{200, R"([{"s":"\u0041\u0042"}])", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("truncated unicode escape") {
        g_stub_http_resp = HttpResp{200, R"(["\u00"])", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("invalid escape character") {
        g_stub_http_resp = HttpResp{200, R"(["\x"])", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("unterminated string") {
        g_stub_http_resp = HttpResp{200, "[\"hello]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("trailing backslash in string") {
        g_stub_http_resp = HttpResp{200, R"(["ab\)", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("control char below 0x20") {
        std::string body = "[\"ab";
        body += static_cast<char>(0x01);
        body += "\"]";
        g_stub_http_resp = HttpResp{200, body, "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }
}

TEST_CASE("JSON parser handles numbers") {
    SECTION("zero") {
        g_stub_http_resp = HttpResp{200, "[0]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("negative number") {
        g_stub_http_resp = HttpResp{200, "[-42]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("decimal") {
        g_stub_http_resp = HttpResp{200, "[3.14]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("exponent") {
        g_stub_http_resp = HttpResp{200, "[1e10]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("negative exponent") {
        g_stub_http_resp = HttpResp{200, "[2.5E-3]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("positive exponent") {
        g_stub_http_resp = HttpResp{200, "[1e+5]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("missing fraction digits") {
        g_stub_http_resp = HttpResp{200, "[3.]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("missing exponent digits") {
        g_stub_http_resp = HttpResp{200, "[1e]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("leading minus only") {
        g_stub_http_resp = HttpResp{200, "[-]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("non-digit after minus") {
        g_stub_http_resp = HttpResp{200, "[-a]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }
}

TEST_CASE("JSON parser handles literals") {
    SECTION("true value") {
        g_stub_http_resp = HttpResp{200, "[true]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("false value") {
        g_stub_http_resp = HttpResp{200, "[false]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("null value") {
        g_stub_http_resp = HttpResp{200, "[null]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("truncated true") {
        g_stub_http_resp = HttpResp{200, "[tru]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("truncated false") {
        g_stub_http_resp = HttpResp{200, "[fals]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("truncated null") {
        g_stub_http_resp = HttpResp{200, "[nul]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }
}

TEST_CASE("JSON parser handles objects") {
    SECTION("empty object in array") {
        g_stub_http_resp = HttpResp{200, "[{}]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("nested objects") {
        g_stub_http_resp = HttpResp{200, R"([{"a":{"b":{"c":1}}}])", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("multiple keys") {
        g_stub_http_resp = HttpResp{200, R"([{"x":1,"y":"z","w":true}])", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("missing colon in object") {
        g_stub_http_resp = HttpResp{200, R"([{"x" 1}])", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("missing comma between keys") {
        g_stub_http_resp = HttpResp{200, R"([{"x":1 "y":2}])", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("non-string key") {
        g_stub_http_resp = HttpResp{200, "[{1:2}]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }
}

TEST_CASE("JSON parser handles arrays") {
    SECTION("nested arrays") {
        g_stub_http_resp = HttpResp{200, "[[1,2],[3]]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
        REQUIRE(r.log_entries == 2);
    }

    SECTION("missing comma in array") {
        g_stub_http_resp = HttpResp{200, "[1 2]", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("empty input") {
        g_stub_http_resp = HttpResp{200, "", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("trailing data after array") {
        g_stub_http_resp = HttpResp{200, "[]extra", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }

    SECTION("whitespace around array") {
        g_stub_http_resp = HttpResp{200, "  [ { \"a\" : 1 } ]  ", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.found);
    }

    SECTION("not an array at top level") {
        g_stub_http_resp = HttpResp{200, R"({"a":1})", "", 0};
        const CtCheck r = ct_check_testable(std::string(64, 'a'), true);
        REQUIRE(r.err == "json parse");
    }
}

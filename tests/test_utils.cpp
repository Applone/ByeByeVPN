#include <catch2/catch_test_macros.hpp>

#include "core/utils.h"

TEST_CASE("tolower_s lowers ASCII letters") {
    REQUIRE(tolower_s("AbC-123") == "abc-123");
}

TEST_CASE("trim removes surrounding whitespace") {
    REQUIRE(trim("  hello\t\n") == "hello");
    REQUIRE(trim("\r\n") == "");
}

TEST_CASE("split keeps empty tokens") {
    const auto parts = split("a,,b,", ',');
    REQUIRE(parts.size() == 4);
    REQUIRE(parts[0] == "a");
    REQUIRE(parts[1] == "");
    REQUIRE(parts[2] == "b");
    REQUIRE(parts[3] == "");
}

TEST_CASE("hex_s encodes bytes") {
    const unsigned char data[] = {0x00, 0xAB, 0xFF};
    REQUIRE(hex_s(data, 3, false) == "00abff");
    REQUIRE(hex_s(data, 3, true) == "00 ab ff");
}

TEST_CASE("url_encode encodes reserved characters") {
    REQUIRE(url_encode("hello world") == "hello%20world");
    REQUIRE(url_encode("a+b=c") == "a%2Bb%3Dc");
}

TEST_CASE("json_get_str finds nested key values") {
    const std::string body = R"({"outer":{"name":"alice","meta":{"city":"Paris"}},"arr":[{"name":"bob"}]})";
    REQUIRE(json_get_str(body, "name") == "alice");
    REQUIRE(json_get_str(body, "city") == "Paris");
    REQUIRE(json_get_str(body, "missing").empty());
}

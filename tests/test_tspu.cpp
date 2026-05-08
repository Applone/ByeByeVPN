#include <catch2/catch_test_macros.hpp>

#include "analysis/tspu.h"

TEST_CASE("looks_like_tspu_redirect detects known host marker") {
    const char* marker = looks_like_tspu_redirect("https://warning.rt.ru/block");
    REQUIRE(marker != nullptr);
    REQUIRE(std::string(marker) == "warning.rt.ru");
}

TEST_CASE("looks_like_tspu_redirect handles host:port and case") {
    const char* marker = looks_like_tspu_redirect("HTTP://RKN.GOV.RU:443/path");
    REQUIRE(marker != nullptr);
    REQUIRE(std::string(marker) == "rkn.gov.ru");
}

TEST_CASE("looks_like_tspu_redirect returns null for non-matching URL") {
    REQUIRE(looks_like_tspu_redirect("https://example.com/ok") == nullptr);
    REQUIRE(looks_like_tspu_redirect("") == nullptr);
}

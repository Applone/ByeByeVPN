#include <catch2/catch_test_macros.hpp>

#include "analysis/ct_check.h"

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

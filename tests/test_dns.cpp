#include <catch2/catch_test_macros.hpp>

#include "network/dns.h"

TEST_CASE("resolve_host bypasses DNS for IP literals") {
    const auto v4 = resolve_host("127.0.0.1");
    REQUIRE(v4.err.empty());
    REQUIRE(v4.family == "v4");
    REQUIRE(v4.primary_ip == "127.0.0.1");
    REQUIRE(v4.ips.size() == 1);

    const auto v6 = resolve_host("::1");
    REQUIRE(v6.err.empty());
    REQUIRE(v6.family == "v6");
    REQUIRE(v6.primary_ip == "::1");
    REQUIRE(v6.ips.size() == 1);
}

TEST_CASE("resolve_host resolves localhost") {
    const auto r = resolve_host("localhost");
    REQUIRE(r.err.empty());
    REQUIRE_FALSE(r.ips.empty());
    REQUIRE_FALSE(r.primary_ip.empty());
    REQUIRE(r.ms >= 0);
}

TEST_CASE("resolve_host reports invalid host errors") {
    const auto r = resolve_host("bad host name with spaces");
    REQUIRE_FALSE(r.err.empty());
    REQUIRE(r.ips.empty());
    REQUIRE(r.primary_ip.empty());
}

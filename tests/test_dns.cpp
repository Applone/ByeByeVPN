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

TEST_CASE("resolve_host IPv4 literal sets family to v4") {
    const auto r = resolve_host("192.168.1.1");
    REQUIRE(r.err.empty());
    REQUIRE(r.family == "v4");
    REQUIRE(r.primary_ip == "192.168.1.1");
    REQUIRE(r.ips.size() == 1);
    REQUIRE(r.ms >= 0);
}

TEST_CASE("resolve_host IPv6 literal sets family to v6") {
    const auto r = resolve_host("fe80::1");
    REQUIRE(r.err.empty());
    REQUIRE(r.family == "v6");
    REQUIRE(r.primary_ip == "fe80::1");
    REQUIRE(r.ips.size() == 1);
}

TEST_CASE("resolve_host preserves host field") {
    const auto r = resolve_host("127.0.0.1");
    REQUIRE(r.host == "127.0.0.1");
}

TEST_CASE("resolve_host nonexistent domain") {
    const auto r = resolve_host("this-domain-does-not-exist-xyz123.invalid");
    REQUIRE_FALSE(r.err.empty());
    REQUIRE(r.ips.empty());
}

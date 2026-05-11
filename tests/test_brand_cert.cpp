#include <catch2/catch_test_macros.hpp>

#include "analysis/brand_cert.h"

#include <string>
#include <vector>

TEST_CASE("cert_claims_brand exact CN match") {
    REQUIRE(cert_claims_brand("google.com", {}) == "google.com");
    REQUIRE(cert_claims_brand("amazon.com", {}) == "amazon.com");
    REQUIRE(cert_claims_brand("cloudflare.com", {}) == "cloudflare.com");
}

TEST_CASE("cert_claims_brand wildcard CN") {
    REQUIRE(cert_claims_brand("*.google.com", {}) == "google.com");
    REQUIRE(cert_claims_brand("*.amazon.com", {}) == "amazon.com");
}

TEST_CASE("cert_claims_brand case insensitive") {
    REQUIRE(cert_claims_brand("Google.Com", {}) == "google.com");
    REQUIRE(cert_claims_brand("AMAZON.COM", {}) == "amazon.com");
}

TEST_CASE("cert_claims_brand subdomain suffix match") {
    REQUIRE(cert_claims_brand("cdn.google.com", {}) == "google.com");
    REQUIRE(cert_claims_brand("www.cloudflare.com", {}) == "cloudflare.com");
    REQUIRE(cert_claims_brand("api.github.com", {}) == "github.com");
}

TEST_CASE("cert_claims_brand SAN match") {
    REQUIRE(cert_claims_brand("unknown.example", {"apple.com"}) == "apple.com");
    REQUIRE(cert_claims_brand("unknown.example", {"*.microsoft.com"}) == "microsoft.com");
    REQUIRE(cert_claims_brand("unknown.example", {"random.xyz", "facebook.com"}) == "facebook.com");
}

TEST_CASE("cert_claims_brand no match") {
    REQUIRE(cert_claims_brand("example.com", {}).empty());
    REQUIRE(cert_claims_brand("random.xyz", {"also-unknown.test"}).empty());
    REQUIRE(cert_claims_brand("", {}).empty());
    REQUIRE(cert_claims_brand("", {""}).empty());
}

TEST_CASE("cert_claims_brand CN takes priority over SAN") {
    const auto result = cert_claims_brand("google.com", {"apple.com"});
    REQUIRE(result == "google.com");
}

TEST_CASE("cert_claims_brand single-char name") {
    REQUIRE(cert_claims_brand("a", {}).empty());
}

TEST_CASE("cert_claims_brand partial domain mismatch") {
    REQUIRE(cert_claims_brand("notgoogle.com", {}).empty());
    REQUIRE(cert_claims_brand("google.com.evil.net", {}).empty());
}

TEST_CASE("asn_owns_brand matches known brand") {
    REQUIRE(asn_owns_brand("google.com", {"Google LLC"}));
    REQUIRE(asn_owns_brand("amazon.com", {"Amazon Technologies Inc."}));
    REQUIRE(asn_owns_brand("cloudflare.com", {"Cloudflare Inc"}));
}

TEST_CASE("asn_owns_brand case insensitive") {
    REQUIRE(asn_owns_brand("google.com", {"GOOGLE LLC"}));
    REQUIRE(asn_owns_brand("amazon.com", {"AMAZON TECHNOLOGIES"}));
}

TEST_CASE("asn_owns_brand no match for unknown brand") {
    REQUIRE_FALSE(asn_owns_brand("unknown.example", {"Google LLC"}));
}

TEST_CASE("asn_owns_brand no match for wrong ASN") {
    REQUIRE_FALSE(asn_owns_brand("google.com", {"Totally Unrelated Corp"}));
}

TEST_CASE("asn_owns_brand handles empty inputs") {
    REQUIRE_FALSE(asn_owns_brand("", {"Google LLC"}));
    REQUIRE_FALSE(asn_owns_brand("google.com", {}));
    REQUIRE_FALSE(asn_owns_brand("", {}));
}

TEST_CASE("asn_owns_brand with multiple ASN orgs") {
    REQUIRE(asn_owns_brand("microsoft.com", {"Random Corp", "Microsoft Corporation"}));
    REQUIRE_FALSE(asn_owns_brand("google.com", {"Evil Corp", "Also Evil Corp"}));
}

TEST_CASE("asn_owns_brand specific Russian brands") {
    REQUIRE(asn_owns_brand("yandex.ru", {"Yandex LLC"}));
    REQUIRE(asn_owns_brand("vk.com", {"VK LLC"}));
    REQUIRE(asn_owns_brand("sberbank.ru", {"Sberbank of Russia"}));
}

TEST_CASE("asn_owns_brand multi-marker matching") {
    REQUIRE(asn_owns_brand("apple.com", {"Akamai Technologies"}));
    REQUIRE(asn_owns_brand("github.com", {"Fastly Inc"}));
    REQUIRE(asn_owns_brand("netflix.com", {"Akamai Technologies"}));
}

#pragma once

#include <string>
#include <string_view>
#include <vector>

// Check if certificate claims a well-known brand domain
[[nodiscard]] std::string cert_claims_brand(
    std::string_view subject_cn,
    const std::vector<std::string>& san
);

// Check if ASN organization owns the brand
[[nodiscard]] bool asn_owns_brand(
    std::string_view brand_domain,
    const std::vector<std::string>& asn_orgs
);

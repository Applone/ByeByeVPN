#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

// Result from a single J3 probe
struct J3Result {
    std::string name;
    bool responded{false};
    int bytes{0};
    std::string first_line;
    std::string hex_head;
    std::int64_t ms{0};
    
    // Check if probe got a response
    [[nodiscard]] constexpr bool ok() const noexcept {
        return responded && bytes > 0;
    }
};

// Analysis of J3 probe results
struct J3Analysis {
    int silent{0};
    int resp{0};
    int http_real{0};
    int http_bad_version{0};
    int raw_non_http{0};
    int canned_identical{0};
    std::string canned_line;
    int canned_bytes{0};
    
    // Check if server shows suspicious behavior
    [[nodiscard]] constexpr bool suspicious() const noexcept {
        return canned_identical >= 2 || http_bad_version > 0;
    }
};

// Run J3 fingerprinting probes
[[nodiscard]] std::vector<J3Result> j3_probes(std::string_view host, int port);

// Analyze J3 probe results
[[nodiscard]] J3Analysis j3_analyze(const std::vector<J3Result>& probes);

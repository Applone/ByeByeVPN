#pragma once

#include <string>
#include <string_view>
#include <cstdint>

// HTTP response structure
struct HttpResp {
    int status{0};
    std::string body;
    std::string err;
    std::int64_t ms{0};
    
    // Rule of Zero - compiler generates all special members
    
    // Check if response indicates success (2xx or 3xx)
    [[nodiscard]] constexpr bool ok() const noexcept {
        return status >= 200 && status < 400;
    }
    
    // Check if response is a success (2xx only)
    [[nodiscard]] constexpr bool success() const noexcept {
        return status >= 200 && status < 300;
    }
};

// Perform HTTP GET request
// Supports both HTTP and HTTPS with certificate verification
[[nodiscard]] HttpResp http_get(std::string_view url, int timeout_ms = 7000);

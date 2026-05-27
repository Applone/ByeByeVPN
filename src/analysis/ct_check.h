#pragma once

#include <cstddef>
#include <string>
#include <string_view>

inline constexpr std::size_t kCtCheckSha256HexLength{64};
inline constexpr int kCtCheckHttpTimeoutMs{5000};
inline constexpr int kCtCheckMaxLogEntries{50};

// Certificate Transparency check result
struct CtCheck {
    bool queried{false};
    bool found{false};
    int log_entries{0};
    std::string err;

    // Check if CT query succeeded with entries
    [[nodiscard]] constexpr bool ok() const noexcept {
        return queried && found && log_entries > 0;
    }
};

// Check certificate against CT logs (crt.sh)
[[nodiscard]] CtCheck ct_check(std::string_view cert_sha256, bool allow_remote = false);

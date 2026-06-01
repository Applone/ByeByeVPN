#include "ct_check.h"

#include "../network/http_client.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <string_view>

namespace {

// Skip whitespace in JSON
void skip_ws(std::string_view s, std::size_t& i) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s.at(i)))) {
        ++i;
    }
}

// Parse JSON string
[[nodiscard]] bool parse_string(std::string_view s, std::size_t& i) {
    if (i >= s.size() || s.at(i) != '"') return false;
    ++i;

    while (i < s.size()) {
        const unsigned char c{static_cast<unsigned char>(s.at(i++))};
        if (c == '"') return true;

        if (c == '\\') {
            if (i >= s.size()) return false;
            const char esc{s.at(i++)};

            if (esc == 'u') {
                for (int n{0}; n < 4; ++n) {
                    if (i >= s.size() || std::isxdigit(static_cast<unsigned char>(s.at(i))) == 0) {
                        return false;
                    }
                    ++i;
                }
            } else if (!(esc == '"' || esc == '\\' || esc == '/' || esc == 'b' ||
                        esc == 'f' || esc == 'n' || esc == 'r' || esc == 't')) {
                return false;
            }
        } else if (c < 0x20) {
            return false;
        }
    }
    return false;
}

// Forward declaration
[[nodiscard]] bool parse_value(std::string_view s, std::size_t& i);

// Parse JSON object
[[nodiscard]] bool parse_object(std::string_view s, std::size_t& i) {
    if (i >= s.size() || s.at(i) != '{') return false;
    ++i;
    skip_ws(s, i);

    if (i < s.size() && s.at(i) == '}') {
        ++i;
        return true;
    }

    while (i < s.size()) {
        if (!parse_string(s, i)) return false;
        skip_ws(s, i);
        if (i >= s.size() || s.at(i) != ':') return false;
        ++i;
        if (!parse_value(s, i)) return false;
        skip_ws(s, i);
        if (i >= s.size()) return false;

        if (s.at(i) == '}') {
            ++i;
            return true;
        }
        if (s.at(i) != ',') return false;
        ++i;
        skip_ws(s, i);
    }
    return false;
}

// Parse JSON array
[[nodiscard]] bool parse_array(std::string_view s, std::size_t& i, std::size_t* count = nullptr) {
    if (i >= s.size() || s.at(i) != '[') return false;
    ++i;
    skip_ws(s, i);

    if (i < s.size() && s.at(i) == ']') {
        ++i;
        if (count) *count = 0;
        return true;
    }

    std::size_t items{0};
    while (i < s.size()) {
        if (!parse_value(s, i)) return false;
        ++items;
        skip_ws(s, i);
        if (i >= s.size()) return false;

        if (s.at(i) == ']') {
            ++i;
            if (count) *count = items;
            return true;
        }
        if (s.at(i) != ',') return false;
        ++i;
        skip_ws(s, i);
    }
    return false;
}

// Parse JSON number
[[nodiscard]] bool parse_number(std::string_view s, std::size_t& i) {
    const std::size_t start{i};

    if (i < s.size() && s.at(i) == '-') ++i;
    if (i >= s.size()) return false;

    if (s.at(i) == '0') {
        ++i;
    } else if (std::isdigit(static_cast<unsigned char>(s.at(i)))) {
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s.at(i)))) ++i;
    } else {
        return false;
    }

    // Fractional part
    if (i < s.size() && s.at(i) == '.') {
        ++i;
        const std::size_t frac{i};
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s.at(i)))) ++i;
        if (frac == i) return false;
    }

    // Exponent
    if (i < s.size() && (s.at(i) == 'e' || s.at(i) == 'E')) {
        ++i;
        if (i < s.size() && (s.at(i) == '+' || s.at(i) == '-')) ++i;
        const std::size_t exp{i};
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s.at(i)))) ++i;
        if (exp == i) return false;
    }

    return i > start;
}

// Parse JSON literal
[[nodiscard]] bool parse_literal(std::string_view s, std::size_t& i, std::string_view lit) {
    if (s.size() - i < lit.size()) return false;
    if (s.substr(i, lit.size()) != lit) return false;
    i += lit.size();
    return true;
}

// Parse any JSON value
[[nodiscard]] bool parse_value(std::string_view s, std::size_t& i) {
    skip_ws(s, i);
    if (i >= s.size()) return false;

    switch (s.at(i)) {
        case '"': return parse_string(s, i);
        case '{': return parse_object(s, i);
        case '[': return parse_array(s, i, nullptr);
        case 't': return parse_literal(s, i, "true");
        case 'f': return parse_literal(s, i, "false");
        case 'n': return parse_literal(s, i, "null");
        default:  return parse_number(s, i);
    }
}

// Parse top-level array and get size
[[nodiscard]] bool parse_top_level_array_size(std::string_view s, std::size_t& count) {
    std::size_t i{0};
    skip_ws(s, i);
    if (!parse_array(s, i, &count)) return false;
    skip_ws(s, i);
    return i == s.size();
}

} // namespace

[[nodiscard]] CtCheck ct_check(std::string_view cert_sha256, bool allow_remote) {
    CtCheck r;

    // Validate SHA256 hash
    if (cert_sha256.length() != kCtCheckSha256HexLength) {
        r.err = "invalid sha256";
        return r;
    }

    if (!std::ranges::all_of(cert_sha256, [](char c) {
        return std::isxdigit(static_cast<unsigned char>(c)) != 0;
    })) {
        r.err = "invalid sha256";
        return r;
    }

    if (!allow_remote) {
        r.err = "remote query disabled";
        return r;
    }

    r.queried = true;

    const std::string url{"https://crt.sh/?q=" + std::string{cert_sha256} + "&output=json"};
    const auto h{http_get(url, kCtCheckHttpTimeoutMs)};

    if (!h.ok()) {
        r.err = "http " + std::to_string(h.status);
        return r;
    }

    std::size_t count{0};
    if (!parse_top_level_array_size(h.body, count)) {
        r.err = "json parse";
        r.found = false;
        r.log_entries = 0;
        return r;
    }

    r.found = count > 0;
    r.log_entries = r.found ? static_cast<int>(std::min<std::size_t>(count, kCtCheckMaxLogEntries)) : 0;

    return r;
}

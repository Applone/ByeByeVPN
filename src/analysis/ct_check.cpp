#include "ct_check.h"
#include "../network/http_client.h"
#include <algorithm>
#include <cctype>
#include <cstring>

namespace {
void skip_ws(const std::string& s, size_t& i) {
    while (i < s.size() && std::isspace((unsigned char)s[i])) ++i;
}

bool parse_string(const std::string& s, size_t& i) {
    if (i >= s.size() || s[i] != '"') return false;
    ++i;
    while (i < s.size()) {
        unsigned char c = (unsigned char)s[i++];
        if (c == '"') return true;
        if (c == '\\') {
            if (i >= s.size()) return false;
            char esc = s[i++];
            if (esc == 'u') {
                for (int n = 0; n < 4; ++n) {
                    if (i >= s.size() || !std::isxdigit((unsigned char)s[i])) return false;
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

bool parse_value(const std::string& s, size_t& i);

bool parse_object(const std::string& s, size_t& i) {
    if (i >= s.size() || s[i] != '{') return false;
    ++i;
    skip_ws(s, i);
    if (i < s.size() && s[i] == '}') {
        ++i;
        return true;
    }
    while (i < s.size()) {
        if (!parse_string(s, i)) return false;
        skip_ws(s, i);
        if (i >= s.size() || s[i] != ':') return false;
        ++i;
        if (!parse_value(s, i)) return false;
        skip_ws(s, i);
        if (i >= s.size()) return false;
        if (s[i] == '}') {
            ++i;
            return true;
        }
        if (s[i] != ',') return false;
        ++i;
        skip_ws(s, i);
    }
    return false;
}

bool parse_array(const std::string& s, size_t& i, size_t* count = nullptr) {
    if (i >= s.size() || s[i] != '[') return false;
    ++i;
    skip_ws(s, i);
    if (i < s.size() && s[i] == ']') {
        ++i;
        if (count) *count = 0;
        return true;
    }
    size_t items = 0;
    while (i < s.size()) {
        if (!parse_value(s, i)) return false;
        ++items;
        skip_ws(s, i);
        if (i >= s.size()) return false;
        if (s[i] == ']') {
            ++i;
            if (count) *count = items;
            return true;
        }
        if (s[i] != ',') return false;
        ++i;
        skip_ws(s, i);
    }
    return false;
}

bool parse_number(const std::string& s, size_t& i) {
    size_t start = i;
    if (i < s.size() && s[i] == '-') ++i;
    if (i >= s.size()) return false;
    if (s[i] == '0') {
        ++i;
    } else if (std::isdigit((unsigned char)s[i])) {
        while (i < s.size() && std::isdigit((unsigned char)s[i])) ++i;
    } else {
        return false;
    }
    if (i < s.size() && s[i] == '.') {
        ++i;
        size_t frac = i;
        while (i < s.size() && std::isdigit((unsigned char)s[i])) ++i;
        if (frac == i) return false;
    }
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        ++i;
        if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
        size_t exp = i;
        while (i < s.size() && std::isdigit((unsigned char)s[i])) ++i;
        if (exp == i) return false;
    }
    return i > start;
}

bool parse_literal(const std::string& s, size_t& i, const char* lit) {
    size_t n = std::strlen(lit);
    if (s.compare(i, n, lit) != 0) return false;
    i += n;
    return true;
}

bool parse_value(const std::string& s, size_t& i) {
    skip_ws(s, i);
    if (i >= s.size()) return false;
    switch (s[i]) {
        case '"': return parse_string(s, i);
        case '{': return parse_object(s, i);
        case '[': return parse_array(s, i, nullptr);
        case 't': return parse_literal(s, i, "true");
        case 'f': return parse_literal(s, i, "false");
        case 'n': return parse_literal(s, i, "null");
        default:  return parse_number(s, i);
    }
}

bool parse_top_level_array_size(const std::string& s, size_t& count) {
    size_t i = 0;
    skip_ws(s, i);
    if (!parse_array(s, i, &count)) return false;
    skip_ws(s, i);
    return i == s.size();
}
}

CtCheck ct_check(const std::string& cert_sha256, bool allow_remote) {
    CtCheck r;
    if (cert_sha256.length() != 64) { r.err = "invalid sha256"; return r; }
    for (char c : cert_sha256) {
        if (!isxdigit((unsigned char)c)) { r.err = "invalid sha256"; return r; }
    }
    if (!allow_remote) { r.err = "remote query disabled"; return r; }
    r.queried = true;
    std::string url = "https://crt.sh/?q=" + cert_sha256 + "&output=json";
    auto h = http_get(url, 5000);
    if (!h.ok()) { r.err = "http " + std::to_string(h.status); return r; }
    size_t count = 0;
    if (!parse_top_level_array_size(h.body, count)) {
        r.err = "json parse";
        r.found = false;
        r.log_entries = 0;
        return r;
    }
    r.found = (count > 0);
    r.log_entries = r.found ? (int)std::min<size_t>(count, 50) : 0;
    return r;
}

#include "utils.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <ranges>

#ifdef _WIN32
#include <windows.h>
#endif

// Strip ANSI escape sequences when writing to save file
void save_write_stripped(const char* s, std::size_t n) {
    if (!g_save_fp || !s || n == 0) return;
    
    for (std::size_t i{0}; i < n; ) {
        if (s[i] == '\x1b' && i + 1 < n && s[i + 1] == '[') {
            i += 2;
            while (i < n && !(s[i] >= '@' && s[i] <= '~')) ++i;
            if (i < n) ++i;
        } else {
            std::fputc(static_cast<unsigned char>(s[i]), g_save_fp);
            ++i;
        }
    }
}

int tee_printf(const char* fmt, ...) {
    if (!fmt) return 0;

    va_list ap;
    va_start(ap, fmt);

    std::array<char, 2048> buf_small{};
    const int needed{std::vsnprintf(buf_small.data(), buf_small.size(), fmt, ap)};
    va_end(ap);

    if (needed < 0) {
        return needed;
    }

    if (needed == 0) {
        return 0;
    }

    if (static_cast<std::size_t>(needed) < buf_small.size()) {
        std::fwrite(buf_small.data(), 1, static_cast<std::size_t>(needed), stdout);
        if (g_save_fp) {
            save_write_stripped(buf_small.data(), static_cast<std::size_t>(needed));
        }
    } else {
        std::vector<char> buf_big(static_cast<std::size_t>(needed) + 1);
        va_list ap2;
        va_start(ap2, fmt);
        const int ret2{std::vsnprintf(buf_big.data(), buf_big.size(), fmt, ap2)};
        va_end(ap2);
        
        if (ret2 < 0) {
            return ret2;
        }

        if (ret2 > 0) {
            std::fwrite(buf_big.data(), 1, static_cast<std::size_t>(ret2), stdout);
            if (g_save_fp) {
                save_write_stripped(buf_big.data(), static_cast<std::size_t>(ret2));
            }
        }
    }
    return needed;
}

int tee_puts(const char* s) {
    if (!s) return 0;
    std::fputs(s, stdout);
    std::fputc('\n', stdout);
    if (g_save_fp) {
        save_write_stripped(s, std::strlen(s));
        std::fputc('\n', g_save_fp);
    }
    return 0;
}

void enable_vt() {
#ifdef _WIN32
    HANDLE h{GetStdHandle(STD_OUTPUT_HANDLE)};
    DWORD mode{0};
    if (GetConsoleMode(h, &mode)) {
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    SetConsoleOutputCP(CP_UTF8);
#endif
}

void banner() {
    tee_printf("%s%s", col(C::BOLD), col(C::MAG));
    tee_puts(" ____             ____           __     ______  _   _ ");
    tee_puts(R"(| __ ) _   _  ___| __ ) _   _  __\ \   / /  _ \| \ | |)");
    tee_puts(R"(|  _ \| | | |/ _ \  _ \| | | |/ _ \ \ / /| |_) |  \| |)");
    tee_puts("| |_) | |_| |  __/ |_) | |_| |  __/\\ V / |  __/| |\\  |");
    tee_puts(R"(|____/ \__, |\___|____/ \__, |\___| \_/  |_|   |_| \_|)");
    tee_puts("       |___/            |___/                          ");
    tee_printf("%s", col(C::RST));
    tee_printf("%s  VPN detectability scanner  v1.1.1%s\n\n",
           col(C::DIM), col(C::RST));
}

[[nodiscard]] std::string tolower_s(std::string s) {
    // Using C++20 ranges
    std::ranges::transform(s, s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

[[nodiscard]] bool contains(std::string_view haystack, std::string_view needle) noexcept {
    return haystack.find(needle) != std::string_view::npos;
}

[[nodiscard]] bool starts_with(std::string_view s, std::string_view prefix) noexcept {
    // C++20 starts_with
    return s.starts_with(prefix);
}

[[nodiscard]] std::string trim(std::string_view s) {
    auto first{s.begin()};
    auto last{s.end()};
    
    while (first != last && std::isspace(static_cast<unsigned char>(*first))) {
        ++first;
    }
    while (last != first && std::isspace(static_cast<unsigned char>(*(last - 1)))) {
        --last;
    }
    
    return std::string{first, last};
}

[[nodiscard]] std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> result;
    std::string current;
    
    for (char c : s) {
        if (c == sep) {
            result.push_back(std::move(current));
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    result.push_back(std::move(current));
    
    return result;
}

[[nodiscard]] std::string hex_s(std::span<const unsigned char> data, bool spaces) {
    constexpr std::array<char, 16> hex_chars{'0', '1', '2', '3', '4', '5', '6', '7',
                                              '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    
    std::string result;
    result.reserve(data.size() * (spaces ? 3 : 2));
    
    for (std::size_t i{0}; i < data.size(); ++i) {
        result += hex_chars.at((data.data()[i] >> 4) & 0xF);
        result += hex_chars.at(data.data()[i] & 0xF);
        if (spaces && i + 1 < data.size()) {
            result += ' ';
        }
    }
    
    return result;
}

[[nodiscard]] std::string hex_s(const unsigned char* d, std::size_t n, bool spaces) {
    return hex_s(std::span<const unsigned char>{d, n}, spaces);
}

[[nodiscard]] std::string url_encode(std::string_view s) {
    constexpr std::array<char, 16> hex_chars{'0', '1', '2', '3', '4', '5', '6', '7',
                                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    std::string out;
    out.reserve(s.size() * 3);
    
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex_chars.at((c >> 4) & 0x0F));
            out.push_back(hex_chars.at(c & 0x0F));
        }
    }
    
    return out;
}

namespace JSON {

struct Value {
    std::string s;
    std::map<std::string, Value> o;
    std::vector<std::string> order;
    std::vector<Value> a;
    bool is_obj{false};
    bool is_arr{false};
};

[[nodiscard]] std::string unescape(std::string_view s) {
    std::string result;
    result.reserve(s.size());

    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };

    auto parse_u16 = [&](std::size_t pos) -> int {
        // pos points to the first hex digit (4 chars needed)
        if (pos + 4 > s.size()) return -1;
        int val = 0;
        for (int k = 0; k < 4; ++k) {
            const int d = hex_val(s.at(pos + k));
            if (d < 0) return -1;
            val = (val << 4) | d;
        }
        return val;
    };

    auto append_utf8 = [&](uint32_t cp) {
        if (cp <= 0x7F) {
            result += static_cast<char>(cp);
        } else if (cp <= 0x7FF) {
            result += static_cast<char>(0xC0 | (cp >> 6));
            result += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp <= 0xFFFF) {
            result += static_cast<char>(0xE0 | (cp >> 12));
            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp <= 0x10FFFF) {
            result += static_cast<char>(0xF0 | (cp >> 18));
            result += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            result += "\xEF\xBF\xBD"; // U+FFFD replacement character
        }
    };
    
    for (std::size_t i{0}; i < s.size(); ++i) {
        if (s.at(i) == '\\' && i + 1 < s.size()) {
            char c{s.at(++i)};
            switch (c) {
                case 'b': result += '\b'; break;
                case 'f': result += '\f'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case 'u': {
                    const int u1 = parse_u16(i + 1);
                    if (u1 < 0) {
                        result += '?';
                        break;
                    }
                    i += 4;
                    // Check for UTF-16 surrogate pair
                    if (u1 >= 0xD800 && u1 <= 0xDBFF &&
                        i + 2 < s.size() && s.at(i + 1) == '\\' && s.at(i + 2) == 'u') {
                        const int u2 = parse_u16(i + 3);
                        if (u2 >= 0xDC00 && u2 <= 0xDFFF) {
                            const uint32_t cp = 0x10000 +
                                ((static_cast<uint32_t>(u1 - 0xD800) << 10) |
                                 static_cast<uint32_t>(u2 - 0xDC00));
                            append_utf8(cp);
                            i += 6; // skip \uXXXX of the low surrogate
                            break;
                        }
                    }
                    // Lone/unpaired surrogate is not a valid scalar value:
                    // emit U+FFFD instead of producing invalid UTF-8.
                    if (u1 >= 0xD800 && u1 <= 0xDFFF) {
                        append_utf8(0xFFFD);
                    } else {
                        append_utf8(static_cast<uint32_t>(u1));
                    }
                    break;
                }
                default:
                    result += c;
                    break;
            }
        } else {
            result += s.at(i);
        }
    }
    return result;
}

Value parse(std::string_view b, std::size_t& i) {
    while (i < b.size() && std::isspace(static_cast<unsigned char>(b.at(i)))) ++i;
    
    Value v;
    if (i >= b.size()) return v;
    
    if (b.at(i) == '"') {
        std::size_t start{++i};
        bool escaped{false};
        while (i < b.size()) {
            if (escaped) {
                escaped = false;
            } else if (b.at(i) == '\\') {
                escaped = true;
            } else if (b.at(i) == '"') {
                break;
            }
            ++i;
        }
        v.s = unescape(b.substr(start, i - start));
        if (i < b.size()) ++i;
    } else if (b.at(i) == '{') {
        v.is_obj = true;
        ++i;
        while (i < b.size() && b.at(i) != '}') {
            Value key{parse(b, i)};
            while (i < b.size() && (std::isspace(static_cast<unsigned char>(b.at(i))) || b.at(i) == ':')) ++i;
            if (v.o.find(key.s) == v.o.end()) {
                v.order.push_back(key.s);
            }
            v.o[key.s] = parse(b, i);
            while (i < b.size() && (std::isspace(static_cast<unsigned char>(b.at(i))) || b.at(i) == ',')) ++i;
        }
        if (i < b.size()) ++i;
    } else if (b.at(i) == '[') {
        v.is_arr = true;
        ++i;
        while (i < b.size() && b.at(i) != ']') {
            v.a.push_back(parse(b, i));
            while (i < b.size() && (std::isspace(static_cast<unsigned char>(b.at(i))) || b.at(i) == ',')) ++i;
        }
        if (i < b.size()) ++i;
    } else {
        std::size_t start{i};
        while (i < b.size() && b.at(i) != ',' && b.at(i) != '}' && b.at(i) != ']' &&
               !std::isspace(static_cast<unsigned char>(b.at(i)))) {
            ++i;
        }
        v.s = std::string{b.substr(start, i - start)};
    }
    
    return v;
}

[[nodiscard]] std::string find_key(const Value& v, std::string_view key) {
    if (v.is_obj) {
        // Using C++20 ranges::find_if
        auto it = std::ranges::find_if(v.o, [&](const auto& kv) {
            return kv.first == key;
        });
        if (it != v.o.end()) {
            return it->second.s;
        }
        for (const auto& child_key : v.order) {
            auto child_it{v.o.find(child_key)};
            if (child_it == v.o.end()) continue;
            std::string result{find_key(child_it->second, key)};
            if (!result.empty()) return result;
        }
    }
    if (v.is_arr) {
        for (const auto& child : v.a) {
            std::string result{find_key(child, key)};
            if (!result.empty()) return result;
        }
    }
    return "";
}

} // namespace JSON

[[nodiscard]] std::string json_get_str(std::string_view body, std::string_view key) {
    std::size_t i{0};
    return JSON::find_key(JSON::parse(body, i), key);
}

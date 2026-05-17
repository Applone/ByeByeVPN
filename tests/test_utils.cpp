#include <catch2/catch_test_macros.hpp>

#include "core/utils.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
static FILE* test_tmpfile() {
    return std::fopen("test_tmpfile.txt", "w+b");
}
#else
static FILE* test_tmpfile() {
    return std::tmpfile();
}
#endif

void save_write_stripped(const char* s, size_t n);

namespace {

struct SaveFpGuard {
    FILE* prev = g_save_fp;
    ~SaveFpGuard() { g_save_fp = prev; }
};

struct NoColorGuard {
    bool prev = g_no_color;
    ~NoColorGuard() { g_no_color = prev; }
};

std::string read_tmpfile(FILE* fp) {
    std::string out;
    if (!fp) return out;
    std::fflush(fp);
    std::rewind(fp);
    char buf[512];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), fp)) > 0) {
        out.append(buf, buf + n);
    }
    return out;
}

} // namespace

TEST_CASE("tolower_s lowers ASCII letters") {
    REQUIRE(tolower_s("AbC-123") == "abc-123");
}

TEST_CASE("trim removes surrounding whitespace") {
    REQUIRE(trim("  hello\t\n") == "hello");
    REQUIRE(trim("\r\n") == "");
}

TEST_CASE("split keeps empty tokens") {
    const auto parts = split("a,,b,", ',');
    REQUIRE(parts.size() == 4);
    REQUIRE(parts[0] == "a");
    REQUIRE(parts[1] == "");
    REQUIRE(parts[2] == "b");
    REQUIRE(parts[3] == "");
}

TEST_CASE("contains and starts_with match expected substrings") {
    REQUIRE(contains("hello world", "lo wo"));
    REQUIRE_FALSE(contains("hello world", "LO WO"));

    REQUIRE(starts_with("vpn://probe", "vpn://"));
    REQUIRE_FALSE(starts_with("vpn://probe", "probe"));
    REQUIRE(starts_with("same", "same"));
}

TEST_CASE("hex_s encodes bytes") {
    const unsigned char data[] = {0x00, 0xAB, 0xFF};
    REQUIRE(hex_s(data, 3, false) == "00abff");
    REQUIRE(hex_s(data, 3, true) == "00 ab ff");
}

TEST_CASE("url_encode encodes reserved characters") {
    REQUIRE(url_encode("hello world") == "hello%20world");
    REQUIRE(url_encode("a+b=c") == "a%2Bb%3Dc");
}

TEST_CASE("json_get_str finds nested key values") {
    const std::string body = R"({"outer":{"name":"alice","meta":{"city":"Paris"}},"arr":[{"name":"bob"}]})";
    REQUIRE(json_get_str(body, "name") == "alice");
    REQUIRE(json_get_str(body, "city") == "Paris");
    REQUIRE(json_get_str(body, "missing").empty());
}

TEST_CASE("json_get_str keeps insertion-order traversal for duplicate keys") {
    const std::string body = R"({"z":{"name":"first"},"a":{"name":"second"}})";
    REQUIRE(json_get_str(body, "name") == "first");
}

TEST_CASE("json_get_str returns scalar token text for non-string values") {
    const std::string body = R"({"ok":true,"count":42,"nil":null,"nested":{"ok":false}})";
    REQUIRE(json_get_str(body, "ok") == "true");
    REQUIRE(json_get_str(body, "count") == "42");
    REQUIRE(json_get_str(body, "nil") == "null");
    REQUIRE(json_get_str(body, "nested") == "");
}

TEST_CASE("json_get_str handles empty and missing input") {
    REQUIRE(json_get_str("", "name").empty());
    REQUIRE(json_get_str("{}", "name").empty());
    REQUIRE(json_get_str("[]", "name").empty());
}

TEST_CASE("json_get_str searches through arrays and deep nesting") {
    const std::string body =
        R"({"root":[{"skip":1},{"layer":{"items":[{"id":"x"},{"target":"hit"}]}}]})";
    REQUIRE(json_get_str(body, "target") == "hit");
    REQUIRE(json_get_str(body, "id") == "x");
}

TEST_CASE("json_get_str unescapes common escaped characters") {
    const std::string body = R"({"s":"line1\nline2\t\"q\""})";
    REQUIRE(json_get_str(body, "s") == "line1\nline2\t\"q\"");
}

TEST_CASE("json_get_str tolerates malformed input") {
    REQUIRE(json_get_str("{", "name").empty());
    REQUIRE(json_get_str("{\"name\":\"alice\"", "name") == "alice");
}

TEST_CASE("json_get_str unicode escape") {
    REQUIRE(json_get_str(R"({"a":"\u0041B"})", "a") == "?B");
}

TEST_CASE("col returns empty string when no_color is true") {
    NoColorGuard color_guard;
    g_no_color = true;
    REQUIRE(std::string(col(C::RED)).empty());
    REQUIRE(std::string(col(C::BOLD)).empty());
    g_no_color = false;
    REQUIRE_FALSE(std::string(col(C::RED)).empty());
}

TEST_CASE("hex_s edge cases") {
    REQUIRE(hex_s(nullptr, 0, false).empty());
    const unsigned char single = 0x42;
    REQUIRE(hex_s(&single, 1, true) == "42");
    REQUIRE(hex_s(&single, 1, false) == "42");
}

TEST_CASE("url_encode preserves unreserved characters") {
    REQUIRE(url_encode("abc123") == "abc123");
    REQUIRE(url_encode("a-b_c.d~e") == "a-b_c.d~e");
    REQUIRE(url_encode("") == "");
}

TEST_CASE("url_encode encodes more special characters") {
    REQUIRE(url_encode("/") == "%2F");
    REQUIRE(url_encode("?") == "%3F");
    REQUIRE(url_encode("#") == "%23");
    REQUIRE(url_encode("@") == "%40");
}

TEST_CASE("split more edge cases") {
    const auto empty = split("", ',');
    REQUIRE(empty.size() == 1);
    REQUIRE(empty[0].empty());

    const auto leading = split(",a", ',');
    REQUIRE(leading.size() == 2);
    REQUIRE(leading[0].empty());
    REQUIRE(leading[1] == "a");

    const auto single = split("only", ',');
    REQUIRE(single.size() == 1);
    REQUIRE(single[0] == "only");
}

TEST_CASE("trim various whitespace types") {
    REQUIRE(trim("") == "");
    REQUIRE(trim("   ") == "");
    REQUIRE(trim("nopad") == "nopad");
    REQUIRE(trim("\t\n\r hello \t\n\r") == "hello");
}

TEST_CASE("starts_with edge cases") {
    REQUIRE(starts_with("", ""));
    REQUIRE(starts_with("abc", ""));
    REQUIRE_FALSE(starts_with("", "a"));
    REQUIRE_FALSE(starts_with("ab", "abc"));
}

TEST_CASE("contains edge cases") {
    REQUIRE(contains("", ""));
    REQUIRE(contains("abc", ""));
    REQUIRE_FALSE(contains("", "a"));
}

TEST_CASE("tolower_s with mixed and empty input") {
    REQUIRE(tolower_s("ABC") == "abc");
    REQUIRE(tolower_s("123") == "123");
    REQUIRE(tolower_s("") == "");
    REQUIRE(tolower_s("MiXeD") == "mixed");
}

TEST_CASE("tee_printf returns 0 for null format") {
    SaveFpGuard guard;
    g_save_fp = nullptr;
    REQUIRE(tee_printf(nullptr) == 0);
}

TEST_CASE("tee_printf returns 0 for empty format string") {
    SaveFpGuard guard;
    g_save_fp = nullptr;
    REQUIRE(tee_printf("%s", "") == 0);
}

TEST_CASE("tee_printf writes formatted output to save file") {
    SaveFpGuard guard;
    FILE* fp = test_tmpfile();
    REQUIRE(fp != nullptr);
    g_save_fp = fp;

    const int n = tee_printf("v=%d %s", 42, "x");
    REQUIRE(n == 6);

    const std::string captured = read_tmpfile(fp);
    REQUIRE(captured == "v=42 x");
    std::fclose(fp);
}

TEST_CASE("tee_printf strips ANSI escapes when saving") {
    SaveFpGuard guard;
    FILE* fp = test_tmpfile();
    REQUIRE(fp != nullptr);
    g_save_fp = fp;

    tee_printf("\x1b[31mred\x1b[0m text");

    const std::string captured = read_tmpfile(fp);
    REQUIRE(captured == "red text");
    std::fclose(fp);
}

TEST_CASE("tee_printf handles output larger than internal buffer") {
    SaveFpGuard guard;
    FILE* fp = test_tmpfile();
    REQUIRE(fp != nullptr);
    g_save_fp = fp;

    const std::string big(4096, 'X');
    const int n = tee_printf("%s", big.c_str());
    REQUIRE(n == static_cast<int>(big.size()));

    const std::string captured = read_tmpfile(fp);
    REQUIRE(captured == big);
    std::fclose(fp);
}

TEST_CASE("tee_puts returns 0 for null input") {
    SaveFpGuard guard;
    g_save_fp = nullptr;
    REQUIRE(tee_puts(nullptr) == 0);
}

TEST_CASE("tee_puts writes string and newline to save file") {
    SaveFpGuard guard;
    FILE* fp = test_tmpfile();
    REQUIRE(fp != nullptr);
    g_save_fp = fp;

    tee_puts("hello");

    const std::string captured = read_tmpfile(fp);
    REQUIRE(captured == "hello\n");
    std::fclose(fp);
}

TEST_CASE("tee_puts strips ANSI escapes when saving") {
    SaveFpGuard guard;
    FILE* fp = test_tmpfile();
    REQUIRE(fp != nullptr);
    g_save_fp = fp;

    tee_puts("\x1b[1mbold\x1b[0m");

    const std::string captured = read_tmpfile(fp);
    REQUIRE(captured == "bold\n");
    std::fclose(fp);
}

TEST_CASE("save_write_stripped is a noop when save_fp is null") {
    SaveFpGuard guard;
    g_save_fp = nullptr;
    save_write_stripped("ignored", 7);
    SUCCEED("did not crash");
}

TEST_CASE("save_write_stripped is a noop for null buffer or zero length") {
    SaveFpGuard guard;
    FILE* fp = test_tmpfile();
    REQUIRE(fp != nullptr);
    g_save_fp = fp;

    save_write_stripped(nullptr, 5);
    save_write_stripped("data", 0);

    const std::string captured = read_tmpfile(fp);
    REQUIRE(captured.empty());
    std::fclose(fp);
}

TEST_CASE("save_write_stripped removes incomplete trailing escape") {
    SaveFpGuard guard;
    FILE* fp = test_tmpfile();
    REQUIRE(fp != nullptr);
    g_save_fp = fp;

    const char input[] = "abc\x1b[31";
    save_write_stripped(input, sizeof(input) - 1);

    const std::string captured = read_tmpfile(fp);
    REQUIRE(captured == "abc");
    std::fclose(fp);
}

TEST_CASE("banner writes content to save file") {
    SaveFpGuard guard;
    FILE* fp = test_tmpfile();
    REQUIRE(fp != nullptr);
    g_save_fp = fp;

    NoColorGuard color_guard;
    g_no_color = true;
    banner();

    const std::string captured = read_tmpfile(fp);
    REQUIRE(captured.find("VPN detectability scanner") != std::string::npos);
    std::fclose(fp);
}

TEST_CASE("enable_vt is callable on this platform") {
    enable_vt();
    SUCCEED("did not crash");
}

TEST_CASE("col returns original pointer when color is enabled") {
    NoColorGuard color_guard;
    g_no_color = false;
    REQUIRE(col(C::RED) == C::RED);
    REQUIRE(col(C::RST) == C::RST);
}

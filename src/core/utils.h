#pragma once

// C++20 Standard Library modules where supported
#if defined(__cpp_modules) && __cpp_modules >= 201907L
import <string>;
import <string_view>;
import <vector>;
import <optional>;
import <set>;
import <map>;
import <chrono>;
import <span>;
import <concepts>;
#else
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <set>
#include <map>
#include <chrono>
#include <span>
#include <concepts>
#include <cstdio>
#endif

// Configuration - global state using inline variables (C++17/20)
namespace config {
    inline constexpr int kDefaultThreadCount{1200};
    inline constexpr int kDefaultTcpTimeoutMs{1000};
    inline constexpr int kDefaultUdpTimeoutMs{900};
    inline constexpr int kMinThreadCount{1};
    inline constexpr int kMaxThreadCount{10000};
    inline constexpr int kMinTimeoutMs{1};
    inline constexpr int kMaxTimeoutMs{60000};
    inline constexpr int kMinPortNumber{1};
    inline constexpr int kMaxPortNumber{65535};

    inline bool g_no_color{false};
    inline bool g_verbose{false};
    inline int  g_threads{kDefaultThreadCount};
    inline int  g_tcp_to{kDefaultTcpTimeoutMs};
    inline int  g_udp_to{kDefaultUdpTimeoutMs};

    inline bool g_stealth{false};
    inline bool g_no_geoip{false};
    inline bool g_no_ct{false};
    inline bool g_udp_jitter{false};
    inline bool g_tcp_syn_scan{false};

    inline bool        g_save_requested{false};
    inline FILE*       g_save_fp{nullptr};
    inline std::string g_save_path{};
    inline std::string g_observer_cc{};

    enum class PortMode { FULL, FAST, RANGE, LIST };
    inline PortMode         g_port_mode{PortMode::FULL};
    inline int              g_range_lo{kMinPortNumber};
    inline int              g_range_hi{kMaxPortNumber};
    inline std::vector<int> g_port_list{};
}

// Re-export for backwards compatibility
using config::kDefaultThreadCount;
using config::kDefaultTcpTimeoutMs;
using config::kDefaultUdpTimeoutMs;
using config::kMinThreadCount;
using config::kMaxThreadCount;
using config::kMinTimeoutMs;
using config::kMaxTimeoutMs;
using config::kMinPortNumber;
using config::kMaxPortNumber;
using config::g_no_color;
using config::g_verbose;
using config::g_threads;
using config::g_tcp_to;
using config::g_udp_to;
using config::g_stealth;
using config::g_no_geoip;
using config::g_no_ct;
using config::g_udp_jitter;
using config::g_tcp_syn_scan;
using config::g_save_requested;
using config::g_save_fp;
using config::g_save_path;
using config::g_observer_cc;
using config::PortMode;
using config::g_port_mode;
using config::g_range_lo;
using config::g_range_hi;
using config::g_port_list;

// ANSI color codes - constexpr for compile-time evaluation
namespace C {
    inline constexpr const char* RST  = "\x1b[0m";
    inline constexpr const char* BOLD = "\x1b[1m";
    inline constexpr const char* DIM  = "\x1b[2m";
    inline constexpr const char* RED  = "\x1b[31m";
    inline constexpr const char* GRN  = "\x1b[32m";
    inline constexpr const char* YEL  = "\x1b[33m";
    inline constexpr const char* BLU  = "\x1b[34m";
    inline constexpr const char* MAG  = "\x1b[35m";
    inline constexpr const char* CYN  = "\x1b[36m";
    inline constexpr const char* WHT  = "\x1b[97m";
}

// Concepts for type constraints
template<typename T>
concept StringLike = std::convertible_to<T, std::string_view>;

template<typename T>
concept Container = requires(T t) {
    std::begin(t);
    std::end(t);
    typename T::value_type;
};

// Color helper - returns appropriate color or empty string based on no-color mode
[[nodiscard]] inline const char* col(const char* c) noexcept {
    return g_no_color ? "" : c;
}

// Output functions
int tee_printf(const char* fmt, ...);
int tee_puts(const char* s);
void save_write_stripped(const char* s, std::size_t n);

// Platform initialization
void enable_vt();
void banner();

// String utilities with C++20 features
[[nodiscard]] std::string tolower_s(std::string s);
[[nodiscard]] bool contains(std::string_view haystack, std::string_view needle) noexcept;
[[nodiscard]] bool starts_with(std::string_view s, std::string_view prefix) noexcept;
[[nodiscard]] std::string trim(std::string_view s);
[[nodiscard]] std::vector<std::string> split(std::string_view s, char sep);
[[nodiscard]] std::string hex_s(std::span<const unsigned char> data, bool spaces = false);
[[nodiscard]] std::string hex_s(const unsigned char* d, std::size_t n, bool spaces = false);
[[nodiscard]] std::string url_encode(std::string_view s);

// JSON utilities
[[nodiscard]] std::string json_get_str(std::string_view body, std::string_view key);

// Platform compatibility
#ifndef _WIN32
#include <strings.h>
#define _stricmp strcasecmp
#endif

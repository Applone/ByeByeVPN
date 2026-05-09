#include "utils.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cctype>

#ifdef _WIN32
#include <windows.h>
#endif

using std::string;
using std::vector;

bool g_no_color = false;
bool g_verbose  = false;
int  g_threads  = 1200;
int  g_tcp_to   = 500;
int  g_udp_to   = 900;
bool g_stealth    = false;
bool g_no_geoip   = false;
bool g_no_ct      = false;
bool g_udp_jitter = false;
bool g_tcp_syn_scan = false;

bool   g_save_requested = false;
FILE*  g_save_fp = nullptr;
string g_save_path;
string g_observer_cc;

PortMode    g_port_mode = PortMode::FULL;
int         g_range_lo  = 1;
int         g_range_hi  = 65535;
std::vector<int> g_port_list;

namespace C {
    const char* RST  = "\x1b[0m";
    const char* BOLD = "\x1b[1m";
    const char* DIM  = "\x1b[2m";
    const char* RED  = "\x1b[31m";
    const char* GRN  = "\x1b[32m";
    const char* YEL  = "\x1b[33m";
    const char* BLU  = "\x1b[34m";
    const char* MAG  = "\x1b[35m";
    const char* CYN  = "\x1b[36m";
    const char* WHT  = "\x1b[97m";
}
const char* col(const char* c) { return g_no_color ? "" : c; }

void save_write_stripped(const char* s, size_t n) {
    if (!g_save_fp || !s || !n) return;
    for (size_t i = 0; i < n; ) {
        if (s[i] == '\x1b' && i + 1 < n && s[i+1] == '[') {
            i += 2;
            while (i < n && !(s[i] >= '@' && s[i] <= '~')) ++i;
            if (i < n) ++i;
        } else {
            fputc((unsigned char)s[i], g_save_fp);
            ++i;
        }
    }
}

int tee_printf(const char* fmt, ...) {
    if (!fmt) return 0;

    va_list ap;
    va_start(ap, fmt);

    va_list ap2;
    va_copy(ap2, ap);

    char buf_small[2048];
    int needed = vsnprintf(buf_small, sizeof(buf_small), fmt, ap);
    va_end(ap);

    if (needed > 0) {
        if (needed < (int)sizeof(buf_small)) {
            fwrite(buf_small, 1, needed, stdout);
            if (g_save_fp) save_write_stripped(buf_small, (size_t)needed);
        } else {
            std::vector<char> buf_big((size_t)needed + 1);
            vsnprintf(buf_big.data(), buf_big.size(), fmt, ap2);
            fwrite(buf_big.data(), 1, needed, stdout);
            if (g_save_fp) save_write_stripped(buf_big.data(), (size_t)needed);
        }
    }

    va_end(ap2);
    return needed;
}

int tee_puts(const char* s) {
    if (!s) return 0;
    fputs(s, stdout);
    fputc('\n', stdout);
    if (g_save_fp) {
        save_write_stripped(s, strlen(s));
        fputc('\n', g_save_fp);
    }
    return 0;
}

void enable_vt() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
#endif
}

void banner() {
    tee_printf("%s%s", col(C::BOLD), col(C::MAG));
    tee_puts(" ____             ____           __     ______  _   _ ");
    tee_puts("| __ ) _   _  ___| __ ) _   _  __\\ \\   / /  _ \\| \\ | |");
    tee_puts("|  _ \\| | | |/ _ \\  _ \\| | | |/ _ \\ \\ / /| |_) |  \\| |");
    tee_puts("| |_) | |_| |  __/ |_) | |_| |  __/\\ V / |  __/| |\\  |");
    tee_puts("|____/ \\__, |\\___|____/ \\__, |\\___| \\_/  |_|   |_| \\_|");
    tee_puts("       |___/            |___/                          ");
    tee_printf("%s", col(C::RST));
    tee_printf("%s  Full TSPU/DPI/VPN detectability scanner  v2.5.7%s\n\n",
           col(C::DIM), col(C::RST));
}

string tolower_s(string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}
bool contains(const string& h, const string& n) { return h.find(n) != string::npos; }
bool starts_with(const string& s, const string& p) {
    return s.size() >= p.size() && std::memcmp(s.data(), p.data(), p.size()) == 0;
}
string trim(const string& s) {
    size_t a=0,b=s.size();
    while(a<b && isspace((unsigned char)s[a])) ++a;
    while(b>a && isspace((unsigned char)s[b-1])) --b;
    return s.substr(a,b-a);
}
vector<string> split(const string& s, char sep) {
    vector<string> r; string cur;
    for (char c: s) {
        if (c == sep) { r.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    r.push_back(cur);
    return r;
}
string hex_s(const unsigned char* d, size_t n, bool spaces) {
    static const char* hex = "0123456789abcdef";
    string s; s.reserve(n*(spaces?3:2));
    for (size_t i=0;i<n;++i) {
        s += hex[(d[i]>>4)&0xF]; s += hex[d[i]&0xF];
        if (spaces && i+1<n) s += ' ';
    }
    return s;
}

string url_encode(const string& s) {
    static const char* hex = "0123456789ABCDEF";
    string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back((char)c);
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0x0F]);
            out.push_back(hex[c & 0x0F]);
        }
    }
    return out;
}

namespace JSON {
    struct Value {
        std::string s;
        std::map<std::string, Value> o;
        std::vector<Value> a;
        bool is_obj = false, is_arr = false;
    };

    static std::string unescape(const std::string& s) {
        std::string r;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '\\' && i + 1 < s.size()) {
                char c = s[++i];
                if (c == 'n') r += '\n'; else if (c == 'r') r += '\r'; else if (c == 't') r += '\t';
                else if (c == '"') r += '"'; else if (c == '\\') r += '\\';
                else if (c == 'u' && i + 4 < s.size()) { i += 4; r += '?'; }
                else r += c;
            } else r += s[i];
        }
        return r;
    }

    static Value parse(const std::string& b, size_t& i) {
        while (i < b.size() && isspace((unsigned char)b[i])) i++;
        Value v;
        if (i >= b.size()) return v;
        if (b[i] == '"') {
            size_t start = ++i;
            bool escaped = false;
            while (i < b.size()) {
                if (escaped) escaped = false;
                else if (b[i] == '\\') escaped = true;
                else if (b[i] == '"') break;
                i++;
            }
            v.s = unescape(b.substr(start, i - start));
            if (i < b.size()) i++;
        } else if (b[i] == '{') {
            v.is_obj = true; i++;
            while (i < b.size() && b[i] != '}') {
                Value key = parse(b, i);
                while (i < b.size() && (isspace((unsigned char)b[i]) || b[i] == ':')) i++;
                v.o[key.s] = parse(b, i);
                while (i < b.size() && (isspace((unsigned char)b[i]) || b[i] == ',')) i++;
            }
            if (i < b.size()) i++;
        } else if (b[i] == '[') {
            v.is_arr = true; i++;
            while (i < b.size() && b[i] != ']') {
                v.a.push_back(parse(b, i));
                while (i < b.size() && (isspace((unsigned char)b[i]) || b[i] == ',')) i++;
            }
            if (i < b.size()) i++;
        } else {
            size_t start = i;
            while (i < b.size() && b[i] != ',' && b[i] != '}' && b[i] != ']' && !isspace((unsigned char)b[i])) i++;
            v.s = b.substr(start, i - start);
        }
        return v;
    }

    static std::string find_key(const Value& v, const std::string& key) {
        if (v.is_obj) {
            auto it = v.o.find(key);
            if (it != v.o.end()) return it->second.s;
            for (const auto& pair : v.o) {
                std::string r = find_key(pair.second, key);
                if (!r.empty()) return r;
            }
        }
        if (v.is_arr) {
            for (const auto& child : v.a) {
                std::string r = find_key(child, key);
                if (!r.empty()) return r;
            }
        }
        return "";
    }
}

string json_get_str(const string& body, const string& key) {
    size_t i = 0;
    return JSON::find_key(JSON::parse(body, i), key);
}

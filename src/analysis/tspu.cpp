#include "tspu.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cctype>



static const char* TSPU_REDIRECT_MARKERS[] = {
    "rkn.gov.ru",
    "warning.rt.ru",
    "nt.rtk.ru",
    "blocked.rt.ru",
    "blocked.ruvds.com",
    "blocked.tattelecom.ru",
    "blocked.yota.ru",
    "zapret.gov.ru",
    "eais.rkn.gov.ru",
    "185.76.180.75",
    "185.76.180.76",
    "185.76.180.77",
    nullptr
};

const char* looks_like_tspu_redirect(const std::string& location) {
    if (location.empty() || location.size() > 512) return nullptr;
    
    std::string host = location;
    size_t scheme = host.find("://");
    if (scheme != std::string::npos) host = host.substr(scheme + 3);
    
    size_t slash = host.find('/');
    if (slash != std::string::npos) host = host.substr(0, slash);
    
    if (host.empty()) return nullptr;
    if (host[0] == '[') {
        size_t close = host.find(']');
        if (close != std::string::npos) host = host.substr(1, close - 1);
    } else {
        size_t colon = host.find(':');
        if (colon != std::string::npos) host = host.substr(0, colon);
    }

    std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c){ return std::tolower(c); });

    for (const char** p = TSPU_REDIRECT_MARKERS; *p; ++p) {
        if (host.find(*p) != std::string::npos) return *p;
    }
    return nullptr;
}
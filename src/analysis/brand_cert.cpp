#include "brand_cert.h"

#include "../core/utils.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <string_view>
#include <ranges>

namespace {

// Brand to ASN marker mapping
struct BrandMarker {
    const char* brand;
    const char* asn_markers;
};

inline constexpr std::array kBrandTable{
    BrandMarker{"amazon.com",     "amazon,aws,a100 row,amazon technologies"},
    BrandMarker{"aws.amazon.com", "amazon,aws"},
    BrandMarker{"microsoft.com",  "microsoft,msn,msft,akamai,edgecast"},
    BrandMarker{"apple.com",      "apple,akamai"},
    BrandMarker{"icloud.com",     "apple"},
    BrandMarker{"google.com",     "google,gts,gcp,youtube"},
    BrandMarker{"googleusercontent.com", "google,gcp"},
    BrandMarker{"googleapis.com", "google,gcp"},
    BrandMarker{"youtube.com",    "google,youtube"},
    BrandMarker{"cloudflare.com", "cloudflare,cloudflare inc"},
    BrandMarker{"github.com",     "github,microsoft,fastly"},
    BrandMarker{"gitlab.com",     "gitlab,cloudflare"},
    BrandMarker{"bitbucket.org",  "atlassian,amazon"},
    BrandMarker{"yahoo.com",      "yahoo,oath,verizon"},
    BrandMarker{"netflix.com",    "netflix,akamai"},
    BrandMarker{"cdn.jsdelivr.net","fastly,cloudflare"},
    BrandMarker{"bing.com",       "microsoft"},
    BrandMarker{"gstatic.com",    "google"},
    BrandMarker{"wikipedia.org",  "wikimedia"},
    BrandMarker{"wikimedia.org",  "wikimedia"},
    BrandMarker{"linkedin.com",   "linkedin,microsoft"},
    BrandMarker{"office.com",     "microsoft"},
    BrandMarker{"office365.com",  "microsoft"},
    BrandMarker{"outlook.com",    "microsoft"},
    BrandMarker{"live.com",       "microsoft"},
    BrandMarker{"azure.com",      "microsoft"},
    BrandMarker{"onedrive.com",   "microsoft"},
    BrandMarker{"facebook.com",   "facebook,meta"},
    BrandMarker{"instagram.com",  "facebook,meta"},
    BrandMarker{"whatsapp.com",   "facebook,meta"},
    BrandMarker{"whatsapp.net",   "facebook,meta"},
    BrandMarker{"messenger.com",  "facebook,meta"},
    BrandMarker{"threads.net",    "facebook,meta"},
    BrandMarker{"twitter.com",    "twitter,x corp,x holdings"},
    BrandMarker{"x.com",          "twitter,x corp,x holdings"},
    BrandMarker{"tiktok.com",     "tiktok,bytedance,akamai"},
    BrandMarker{"telegram.org",   "telegram,telegram messenger"},
    BrandMarker{"t.me",           "telegram,telegram messenger"},
    BrandMarker{"telegram.me",    "telegram,telegram messenger"},
    BrandMarker{"discord.com",    "discord,cloudflare,google"},
    BrandMarker{"discordapp.com", "discord,cloudflare,google"},
    BrandMarker{"slack.com",      "slack,amazon,aws"},
    BrandMarker{"zoom.us",        "zoom"},
    BrandMarker{"signal.org",     "signal,amazon,aws"},
    BrandMarker{"yandex.ru",      "yandex"},
    BrandMarker{"yandex.net",     "yandex"},
    BrandMarker{"yandex.com",     "yandex"},
    BrandMarker{"ya.ru",          "yandex"},
    BrandMarker{"mail.ru",        "mail.ru,vk,v kontakte"},
    BrandMarker{"vk.com",         "vk,v kontakte,mail.ru"},
    BrandMarker{"vk.ru",          "vk,v kontakte,mail.ru"},
    BrandMarker{"vkontakte.ru",   "vk,v kontakte,mail.ru"},
    BrandMarker{"ok.ru",          "vk,v kontakte,mail.ru"},
    BrandMarker{"avito.ru",       "avito,kiev internet"},
    BrandMarker{"ozon.ru",        "ozon"},
    BrandMarker{"wildberries.ru", "wildberries"},
    BrandMarker{"kinopoisk.ru",   "yandex"},
    BrandMarker{"rutube.ru",      "rutube,rbc,gpmd"},
    BrandMarker{"dzen.ru",        "yandex,vk"},
    BrandMarker{"habr.com",       "habr,habrahabr"},
    BrandMarker{"rambler.ru",     "rambler,rambler internet"},
    BrandMarker{"sberbank.ru",    "sberbank,sber"},
    BrandMarker{"sber.ru",        "sberbank,sber"},
    BrandMarker{"sberbank.com",   "sberbank,sber"},
    BrandMarker{"tinkoff.ru",     "tinkoff,t-bank,tcs"},
    BrandMarker{"tbank.ru",       "tinkoff,t-bank,tcs"},
    BrandMarker{"vtb.ru",         "vtb,vtb bank"},
    BrandMarker{"alfabank.ru",    "alfabank,alfa bank"},
    BrandMarker{"gazprombank.ru", "gazprombank,gazprom"},
    BrandMarker{"rosbank.ru",     "rosbank,societe"},
    BrandMarker{"gosuslugi.ru",   "rostelecom,rt,rt-labs"},
    BrandMarker{"mos.ru",         "dit,moscow,mgts"},
    BrandMarker{"rt.ru",          "rostelecom,rt"},
    BrandMarker{"nalog.gov.ru",   "rostelecom,rt"},
    BrandMarker{"mts.ru",         "mts"},
    BrandMarker{"megafon.ru",     "megafon"},
    BrandMarker{"beeline.ru",     "beeline,vimpelcom,pjsc vimpelcom"},
    BrandMarker{"rostelecom.ru",  "rostelecom,rt"},
    BrandMarker{"tele2.ru",       "tele2,rostelecom"},
    BrandMarker{"stripe.com",     "stripe,amazon,aws"},
    BrandMarker{"paypal.com",     "paypal,akamai"},
    BrandMarker{"shopify.com",    "shopify,fastly,cloudflare"},
    BrandMarker{"adobe.com",      "adobe"},
    BrandMarker{"salesforce.com", "salesforce"},
    BrandMarker{"dropbox.com",    "dropbox,amazon,aws"},
    BrandMarker{"spotify.com",    "spotify,amazon,aws"},
    BrandMarker{"twitch.tv",      "twitch,amazon,aws"},
    BrandMarker{"vimeo.com",      "vimeo,akamai,amazon"},
    BrandMarker{"reddit.com",     "reddit,fastly"},
    BrandMarker{"steampowered.com","valve,akamai"},
    BrandMarker{"steamcommunity.com","valve,akamai"},
    BrandMarker{"playstation.com","sony,akamai"},
    BrandMarker{"xbox.com",       "microsoft"},
    BrandMarker{"nintendo.com",   "nintendo,amazon,aws,akamai"},
    BrandMarker{"epicgames.com",  "epic games,cloudflare,amazon"},
    BrandMarker{"battle.net",     "blizzard,akamai"},
};

// Check if name is a known brand
[[nodiscard]] const char* is_brand(std::string_view name) {
    if (name.empty()) return nullptr;
    
    std::string ln{name};
    std::ranges::transform(ln, ln.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    
    // Strip wildcard prefix
    if (ln.size() > 2 && ln[0] == '*' && ln[1] == '.') {
        ln = ln.substr(2);
    }
    
    // Exact match
    const auto exact = std::ranges::find_if(kBrandTable, [&](const auto& entry) {
        return ln == entry.brand;
    });
    if (exact != kBrandTable.end()) {
        return exact->brand;
    }
    
    // Suffix match (e.g., www.google.com matches google.com)
    for (const auto& entry : kBrandTable) {
        const std::string_view b{entry.brand};
        if (ln.size() > b.size() + 1 &&
            ln.compare(ln.size() - b.size(), b.size(), b) == 0 &&
            ln[ln.size() - b.size() - 1] == '.') {
            return entry.brand;
        }
    }
    
    return nullptr;
}

} // namespace

[[nodiscard]] std::string cert_claims_brand(
    std::string_view subject_cn,
    const std::vector<std::string>& san
) {
    // Check subject CN
    if (const char* hit{is_brand(subject_cn)}; hit) {
        return hit;
    }
    
    // Check SANs
    for (const auto& s : san) {
        if (const char* hit{is_brand(s)}; hit) {
            return hit;
        }
    }
    
    return {};
}

[[nodiscard]] bool asn_owns_brand(
    std::string_view brand_domain,
    const std::vector<std::string>& asn_orgs
) {
    if (brand_domain.empty() || asn_orgs.empty()) return false;
    
    const char* canonical{is_brand(brand_domain)};
    if (!canonical) return false;
    
    // Find markers for brand
    const auto it = std::ranges::find_if(kBrandTable, [&](const auto& entry) {
        return std::string_view(canonical) == entry.brand;
    });
    if (it == kBrandTable.end()) return false;
    
    const char* markers{it->asn_markers};
    
    // Convert markers to lowercase
    std::string ms{markers};
    std::ranges::transform(ms, ms.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    
    const std::vector<std::string> parts{split(ms, ',')};
    
    // Check if any ASN org contains any marker
    for (const auto& org : asn_orgs) {
        std::string lo{org};
        std::ranges::transform(lo, lo.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        
        if (std::ranges::any_of(parts, [&](const std::string& m) {
            const std::string mm{trim(m)};
            return !mm.empty() && lo.find(mm) != std::string::npos;
        })) {
            return true;
        }
    }
    
    return false;
}

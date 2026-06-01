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
    BrandMarker{.brand = "amazon.com", .asn_markers = "amazon,aws,a100 row,amazon technologies"},
    BrandMarker{.brand = "aws.amazon.com", .asn_markers = "amazon,aws"},
    BrandMarker{.brand = "microsoft.com", .asn_markers = "microsoft,msn,msft,akamai,edgecast"},
    BrandMarker{.brand = "apple.com", .asn_markers = "apple,akamai"},
    BrandMarker{.brand = "icloud.com", .asn_markers = "apple"},
    BrandMarker{.brand = "google.com", .asn_markers = "google,gts,gcp,youtube"},
    BrandMarker{.brand = "googleusercontent.com", .asn_markers = "google,gcp"},
    BrandMarker{.brand = "googleapis.com", .asn_markers = "google,gcp"},
    BrandMarker{.brand = "youtube.com", .asn_markers = "google,youtube"},
    BrandMarker{.brand = "cloudflare.com", .asn_markers = "cloudflare,cloudflare inc"},
    BrandMarker{.brand = "github.com", .asn_markers = "github,microsoft,fastly"},
    BrandMarker{.brand = "gitlab.com", .asn_markers = "gitlab,cloudflare"},
    BrandMarker{.brand = "bitbucket.org", .asn_markers = "atlassian,amazon"},
    BrandMarker{.brand = "yahoo.com", .asn_markers = "yahoo,oath,verizon"},
    BrandMarker{.brand = "netflix.com", .asn_markers = "netflix,akamai"},
    BrandMarker{.brand = "cdn.jsdelivr.net", .asn_markers = "fastly,cloudflare"},
    BrandMarker{.brand = "bing.com", .asn_markers = "microsoft"},
    BrandMarker{.brand = "gstatic.com", .asn_markers = "google"},
    BrandMarker{.brand = "wikipedia.org", .asn_markers = "wikimedia"},
    BrandMarker{.brand = "wikimedia.org", .asn_markers = "wikimedia"},
    BrandMarker{.brand = "linkedin.com", .asn_markers = "linkedin,microsoft"},
    BrandMarker{.brand = "office.com", .asn_markers = "microsoft"},
    BrandMarker{.brand = "office365.com", .asn_markers = "microsoft"},
    BrandMarker{.brand = "outlook.com", .asn_markers = "microsoft"},
    BrandMarker{.brand = "live.com", .asn_markers = "microsoft"},
    BrandMarker{.brand = "azure.com", .asn_markers = "microsoft"},
    BrandMarker{.brand = "onedrive.com", .asn_markers = "microsoft"},
    BrandMarker{.brand = "facebook.com", .asn_markers = "facebook,meta"},
    BrandMarker{.brand = "instagram.com", .asn_markers = "facebook,meta"},
    BrandMarker{.brand = "whatsapp.com", .asn_markers = "facebook,meta"},
    BrandMarker{.brand = "whatsapp.net", .asn_markers = "facebook,meta"},
    BrandMarker{.brand = "messenger.com", .asn_markers = "facebook,meta"},
    BrandMarker{.brand = "threads.net", .asn_markers = "facebook,meta"},
    BrandMarker{.brand = "twitter.com", .asn_markers = "twitter,x corp,x holdings"},
    BrandMarker{.brand = "x.com", .asn_markers = "twitter,x corp,x holdings"},
    BrandMarker{.brand = "tiktok.com", .asn_markers = "tiktok,bytedance,akamai"},
    BrandMarker{.brand = "telegram.org", .asn_markers = "telegram,telegram messenger"},
    BrandMarker{.brand = "t.me", .asn_markers = "telegram,telegram messenger"},
    BrandMarker{.brand = "telegram.me", .asn_markers = "telegram,telegram messenger"},
    BrandMarker{.brand = "discord.com", .asn_markers = "discord,cloudflare,google"},
    BrandMarker{.brand = "discordapp.com", .asn_markers = "discord,cloudflare,google"},
    BrandMarker{.brand = "slack.com", .asn_markers = "slack,amazon,aws"},
    BrandMarker{.brand = "zoom.us", .asn_markers = "zoom"},
    BrandMarker{.brand = "signal.org", .asn_markers = "signal,amazon,aws"},
    BrandMarker{.brand = "yandex.ru", .asn_markers = "yandex"},
    BrandMarker{.brand = "yandex.net", .asn_markers = "yandex"},
    BrandMarker{.brand = "yandex.com", .asn_markers = "yandex"},
    BrandMarker{.brand = "ya.ru", .asn_markers = "yandex"},
    BrandMarker{.brand = "mail.ru", .asn_markers = "mail.ru,vk,v kontakte"},
    BrandMarker{.brand = "vk.com", .asn_markers = "vk,v kontakte,mail.ru"},
    BrandMarker{.brand = "vk.ru", .asn_markers = "vk,v kontakte,mail.ru"},
    BrandMarker{.brand = "vkontakte.ru", .asn_markers = "vk,v kontakte,mail.ru"},
    BrandMarker{.brand = "ok.ru", .asn_markers = "vk,v kontakte,mail.ru"},
    BrandMarker{.brand = "avito.ru", .asn_markers = "avito,kiev internet"},
    BrandMarker{.brand = "ozon.ru", .asn_markers = "ozon"},
    BrandMarker{.brand = "wildberries.ru", .asn_markers = "wildberries"},
    BrandMarker{.brand = "kinopoisk.ru", .asn_markers = "yandex"},
    BrandMarker{.brand = "rutube.ru", .asn_markers = "rutube,rbc,gpmd"},
    BrandMarker{.brand = "dzen.ru", .asn_markers = "yandex,vk"},
    BrandMarker{.brand = "habr.com", .asn_markers = "habr,habrahabr"},
    BrandMarker{.brand = "rambler.ru", .asn_markers = "rambler,rambler internet"},
    BrandMarker{.brand = "sberbank.ru", .asn_markers = "sberbank,sber"},
    BrandMarker{.brand = "sber.ru", .asn_markers = "sberbank,sber"},
    BrandMarker{.brand = "sberbank.com", .asn_markers = "sberbank,sber"},
    BrandMarker{.brand = "tinkoff.ru", .asn_markers = "tinkoff,t-bank,tcs"},
    BrandMarker{.brand = "tbank.ru", .asn_markers = "tinkoff,t-bank,tcs"},
    BrandMarker{.brand = "vtb.ru", .asn_markers = "vtb,vtb bank"},
    BrandMarker{.brand = "alfabank.ru", .asn_markers = "alfabank,alfa bank"},
    BrandMarker{.brand = "gazprombank.ru", .asn_markers = "gazprombank,gazprom"},
    BrandMarker{.brand = "rosbank.ru", .asn_markers = "rosbank,societe"},
    BrandMarker{.brand = "gosuslugi.ru", .asn_markers = "rostelecom,rt,rt-labs"},
    BrandMarker{.brand = "mos.ru", .asn_markers = "dit,moscow,mgts"},
    BrandMarker{.brand = "rt.ru", .asn_markers = "rostelecom,rt"},
    BrandMarker{.brand = "nalog.gov.ru", .asn_markers = "rostelecom,rt"},
    BrandMarker{.brand = "mts.ru", .asn_markers = "mts"},
    BrandMarker{.brand = "megafon.ru", .asn_markers = "megafon"},
    BrandMarker{.brand = "beeline.ru", .asn_markers = "beeline,vimpelcom,pjsc vimpelcom"},
    BrandMarker{.brand = "rostelecom.ru", .asn_markers = "rostelecom,rt"},
    BrandMarker{.brand = "tele2.ru", .asn_markers = "tele2,rostelecom"},
    BrandMarker{.brand = "stripe.com", .asn_markers = "stripe,amazon,aws"},
    BrandMarker{.brand = "paypal.com", .asn_markers = "paypal,akamai"},
    BrandMarker{.brand = "shopify.com", .asn_markers = "shopify,fastly,cloudflare"},
    BrandMarker{.brand = "adobe.com", .asn_markers = "adobe"},
    BrandMarker{.brand = "salesforce.com", .asn_markers = "salesforce"},
    BrandMarker{.brand = "dropbox.com", .asn_markers = "dropbox,amazon,aws"},
    BrandMarker{.brand = "spotify.com", .asn_markers = "spotify,amazon,aws"},
    BrandMarker{.brand = "twitch.tv", .asn_markers = "twitch,amazon,aws"},
    BrandMarker{.brand = "vimeo.com", .asn_markers = "vimeo,akamai,amazon"},
    BrandMarker{.brand = "reddit.com", .asn_markers = "reddit,fastly"},
    BrandMarker{.brand = "steampowered.com", .asn_markers = "valve,akamai"},
    BrandMarker{.brand = "steamcommunity.com", .asn_markers = "valve,akamai"},
    BrandMarker{.brand = "playstation.com", .asn_markers = "sony,akamai"},
    BrandMarker{.brand = "xbox.com", .asn_markers = "microsoft"},
    BrandMarker{.brand = "nintendo.com", .asn_markers = "nintendo,amazon,aws,akamai"},
    BrandMarker{.brand = "epicgames.com", .asn_markers = "epic games,cloudflare,amazon"},
    BrandMarker{.brand = "battle.net", .asn_markers = "blizzard,akamai"},
};

// Check if name is a known brand
[[nodiscard]] const char* is_brand(std::string_view name) {
    if (name.empty()) return nullptr;
    
    // Strip wildcard prefix
    if (name.starts_with("*.")) {
        name = name.substr(2);
    }
    
    auto iequals = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        return std::ranges::equal(a, b, [](unsigned char c1, unsigned char c2) {
            return std::tolower(c1) == std::tolower(c2);
        });
    };
    
    auto iends_with_dot = [](std::string_view s, std::string_view suffix) {
        if (s.size() <= suffix.size() + 1) return false;
        if (s.at(s.size() - suffix.size() - 1) != '.') return false;
        return std::ranges::equal(s.substr(s.size() - suffix.size()), suffix, [](unsigned char c1, unsigned char c2) {
            return std::tolower(c1) == std::tolower(c2);
        });
    };
    
    // Exact match
    const auto exact = std::ranges::find_if(kBrandTable, [&](const auto& entry) {
        return iequals(name, entry.brand);
    });
    if (exact != kBrandTable.end()) {
        return exact->brand;
    }
    
    // Suffix match (e.g., www.google.com matches google.com)
    for (const auto& entry : kBrandTable) {
        if (iends_with_dot(name, entry.brand)) {
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

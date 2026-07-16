//! Pure routing-policy classification for the version 1 routing contract.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteClass {
    DirectPassthrough,
    DirectFirst,
    LocalBypass,
    GeoExit,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceGroup {
    Discord,
    YoutubeVideo,
    Openai,
    Anthropic,
    Telegram,
    SteamStore,
    Github,
    Google,
    Spotify,
    Generic,
}

impl ServiceGroup {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discord => "discord",
            Self::YoutubeVideo => "youtube_video",
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
            Self::Telegram => "telegram",
            Self::SteamStore => "steam_store",
            Self::Github => "github",
            Self::Google => "google",
            Self::Spotify => "spotify",
            Self::Generic => "generic",
        }
    }

    pub const fn is_protected_local_bypass(self) -> bool {
        matches!(self, Self::Discord | Self::YoutubeVideo)
    }
}

impl fmt::Display for ServiceGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategySet {
    Direct,
    DirectFirst,
    FakeOnly,
    Geph,
    General,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaticRoutePolicy {
    pub domains: Vec<String>,
    pub route_class: RouteClass,
    pub service_group: ServiceGroup,
    pub strategy_set: StrategySet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeoExitRoutePolicy {
    pub domains: Vec<String>,
    pub service_group: ServiceGroup,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutingPolicyTables {
    pub static_routes: Vec<StaticRoutePolicy>,
    pub geo_exit_routes: Vec<GeoExitRoutePolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutePolicyResult {
    pub host: String,
    pub route_class: RouteClass,
    pub service_group: ServiceGroup,
    pub strategy_set: StrategySet,
}

const RU_TLDS: &[&str] = &[
    ".ru",
    ".su",
    ".xn--p1ai",
    ".moscow",
    ".tatar",
    ".xn--80adxhks",
];

const RU_HOSTS: &[&str] = &[
    "vk.com",
    "vk.cc",
    "vkvideo.ru",
    "userapi.com",
    "vk-cdn.net",
    "vkuser.net",
    "yandex.com",
    "yandex.net",
    "yastatic.net",
    "yandexcloud.net",
    "ya.ru",
    "mail.ru",
    "mycdn.me",
    "imgsmail.ru",
    "sberbank.com",
    "sber.ru",
    "sberdevices.ru",
    "ozon.com",
    "ozon.ru",
    "wildberries.ru",
    "wb.ru",
    "avito.ru",
    "gosuslugi.ru",
    "nalog.ru",
    "gov.ru",
    "tinkoff.ru",
    "tbank.ru",
    "gazprombank.ru",
    "vtb.ru",
    "alfabank.ru",
    "rutube.ru",
    "ok.ru",
    "dzen.ru",
    "kinopoisk.ru",
    "2gis.com",
    "2gis.ru",
    "kaspersky.com",
    "kaspersky.ru",
    "aliexpress.ru",
];

const TELEGRAM_HOSTS: &[&str] = &[
    "telegram.org",
    "telegram.me",
    "telegram.dog",
    "t.me",
    "telegra.ph",
];

const GITHUB_HOSTS: &[&str] = &[
    "github.com",
    "githubassets.com",
    "githubusercontent.com",
    "github.io",
    "github.githubassets.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
];

const GOOGLE_DIRECT_FIRST_HOSTS: &[&str] = &["google.com"];
const SPOTIFY_DIRECT_FIRST_HOSTS: &[&str] = &["spotify.com", "spotifycdn.com", "scdn.co"];

const DISCORD_HOSTS: &[&str] = &[
    "discord.com",
    "discord.gg",
    "discord.media",
    "discordapp.com",
    "discordapp.net",
    "discordcdn.com",
    "discord.app",
    "discord.co",
    "discord.dev",
    "discord.design",
    "discord.gift",
    "discord.gifts",
    "discord.new",
    "discord.store",
    "discord.status",
    "discord-activities.com",
    "discordactivities.com",
    "discordmerch.com",
    "discordpartygames.com",
    "discordsays.com",
    "discordsez.com",
    "discordstatus.com",
    "dis.gd",
];

const YOUTUBE_VIDEO_HOSTS: &[&str] = &[
    "googlevideo.com",
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "ggpht.com",
    "gvt1.com",
    "gvt2.com",
];

const OPENAI_HOSTS: &[&str] = &[
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "billing.openai.com",
];

const ANTHROPIC_HOSTS: &[&str] = &["anthropic.com", "claude.ai", "claudeusercontent.com"];

const STEAM_STORE_HOSTS: &[&str] = &[
    "steampowered.com",
    "steamcommunity.com",
    "steamstatic.com",
    "steamusercontent.com",
    "steamcdn-a.akamaihd.net",
    "steamcommunity-a.akamaihd.net",
];

const GEPH_MISC_HOSTS: &[&str] = &["intercomcdn.com"];

fn domains(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn static_route(
    values: &[&str],
    route_class: RouteClass,
    service_group: ServiceGroup,
    strategy_set: StrategySet,
) -> StaticRoutePolicy {
    StaticRoutePolicy {
        domains: domains(values),
        route_class,
        service_group,
        strategy_set,
    }
}

fn geo_exit_route(values: &[&str], service_group: ServiceGroup) -> GeoExitRoutePolicy {
    GeoExitRoutePolicy {
        domains: domains(values),
        service_group,
    }
}

pub fn bundled_policy_v1() -> RoutingPolicyTables {
    RoutingPolicyTables {
        static_routes: vec![
            static_route(
                TELEGRAM_HOSTS,
                RouteClass::DirectPassthrough,
                ServiceGroup::Telegram,
                StrategySet::Direct,
            ),
            static_route(
                GITHUB_HOSTS,
                RouteClass::DirectPassthrough,
                ServiceGroup::Github,
                StrategySet::Direct,
            ),
            static_route(
                GOOGLE_DIRECT_FIRST_HOSTS,
                RouteClass::DirectFirst,
                ServiceGroup::Google,
                StrategySet::DirectFirst,
            ),
            static_route(
                SPOTIFY_DIRECT_FIRST_HOSTS,
                RouteClass::DirectFirst,
                ServiceGroup::Spotify,
                StrategySet::DirectFirst,
            ),
            static_route(
                DISCORD_HOSTS,
                RouteClass::LocalBypass,
                ServiceGroup::Discord,
                StrategySet::FakeOnly,
            ),
            static_route(
                YOUTUBE_VIDEO_HOSTS,
                RouteClass::LocalBypass,
                ServiceGroup::YoutubeVideo,
                StrategySet::FakeOnly,
            ),
        ],
        geo_exit_routes: vec![
            geo_exit_route(OPENAI_HOSTS, ServiceGroup::Openai),
            geo_exit_route(ANTHROPIC_HOSTS, ServiceGroup::Anthropic),
            geo_exit_route(STEAM_STORE_HOSTS, ServiceGroup::SteamStore),
            geo_exit_route(GEPH_MISC_HOSTS, ServiceGroup::Generic),
        ],
    }
}

pub fn normalize_host(host: &str) -> String {
    host.to_lowercase().trim_end_matches('.').to_owned()
}

pub fn host_matches(host: &str, domains: &[String]) -> bool {
    if host.is_empty() {
        return false;
    }
    let normalized = normalize_host(host);
    domains.iter().any(|domain| {
        normalized == *domain
            || normalized
                .strip_suffix(domain)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

pub fn is_russian(host: &str) -> bool {
    let normalized = normalize_host(host);
    if normalized.is_empty() {
        return false;
    }
    RU_TLDS.iter().any(|tld| normalized.ends_with(tld))
        || RU_HOSTS.iter().any(|domain| {
            normalized == *domain
                || normalized
                    .strip_suffix(domain)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
}

pub fn classify_route_policy(host: &str, tables: &RoutingPolicyTables) -> RoutePolicyResult {
    let normalized = normalize_host(host);
    if normalized.is_empty() {
        return RoutePolicyResult {
            host: String::new(),
            route_class: RouteClass::Unknown,
            service_group: ServiceGroup::Generic,
            strategy_set: StrategySet::General,
        };
    }

    if let Some(policy) = tables
        .static_routes
        .iter()
        .find(|policy| host_matches(&normalized, &policy.domains))
    {
        return RoutePolicyResult {
            host: normalized,
            route_class: policy.route_class,
            service_group: policy.service_group,
            strategy_set: policy.strategy_set,
        };
    }

    if is_russian(&normalized) {
        return RoutePolicyResult {
            host: normalized,
            route_class: RouteClass::DirectPassthrough,
            service_group: ServiceGroup::Generic,
            strategy_set: StrategySet::Direct,
        };
    }

    if let Some(policy) = tables
        .geo_exit_routes
        .iter()
        .find(|policy| host_matches(&normalized, &policy.domains))
    {
        return RoutePolicyResult {
            host: normalized,
            route_class: RouteClass::GeoExit,
            service_group: policy.service_group,
            strategy_set: StrategySet::Geph,
        };
    }

    RoutePolicyResult {
        host: normalized,
        route_class: RouteClass::Unknown,
        service_group: ServiceGroup::Generic,
        strategy_set: StrategySet::General,
    }
}

"""Pure routing-policy classification shared by runtime adapters."""

from routing_recovery import (
    ROUTE_GEO_EXIT,
    ROUTE_LOCAL_BYPASS,
    ROUTE_UNKNOWN,
    SERVICE_DISCORD,
    SERVICE_YOUTUBE,
)


ROUTE_DIRECT = "direct_passthrough"
ROUTE_DIRECT_FIRST = "direct_first"

SERVICE_OPENAI = "openai"
SERVICE_ANTHROPIC = "anthropic"
SERVICE_TELEGRAM = "telegram"
SERVICE_STEAM_STORE = "steam_store"
SERVICE_GITHUB = "github"
SERVICE_GOOGLE = "google"
SERVICE_SPOTIFY = "spotify"
SERVICE_GENERIC = "generic"

STRATEGY_FAKE_ONLY = "fake_only"
STRATEGY_GEPH = "geph"
STRATEGY_DIRECT = "direct"
STRATEGY_DIRECT_FIRST = "direct_first"
STRATEGY_GENERAL = "general"

# Russian services stay on the user's direct route. The national TLDs cover the
# general case; the explicit domains cover large services hosted on other TLDs.
RU_TLDS = (".ru", ".su", ".xn--p1ai", ".moscow", ".tatar", ".xn--80adxhks")
RU_HOSTS = (
    "vk.com", "vk.cc", "vkvideo.ru", "userapi.com", "vk-cdn.net", "vkuser.net",
    "yandex.com", "yandex.net", "yastatic.net", "yandexcloud.net", "ya.ru",
    "mail.ru", "mycdn.me", "imgsmail.ru",
    "sberbank.com", "sber.ru", "sberdevices.ru",
    "ozon.com", "ozon.ru", "wildberries.ru", "wb.ru", "avito.ru",
    "gosuslugi.ru", "nalog.ru", "gov.ru",
    "tinkoff.ru", "tbank.ru", "gazprombank.ru", "vtb.ru", "alfabank.ru",
    "rutube.ru", "ok.ru", "dzen.ru", "kinopoisk.ru", "2gis.com", "2gis.ru",
    "kaspersky.com", "kaspersky.ru", "aliexpress.ru",
)


def normalize_host(host):
    return host.lower().rstrip(".") if host else ""


def host_matches(host, domains):
    if not host:
        return False
    normalized = normalize_host(host)
    return any(
        normalized == domain or normalized.endswith("." + domain)
        for domain in domains
    )


def match_policy(host, policies):
    for policy in policies:
        if host_matches(host, policy["domains"]):
            return policy
    return None


def is_russian(host):
    """Return whether a host must stay on the direct Russian route."""
    normalized = normalize_host(host)
    if not normalized:
        return False
    if normalized.endswith(RU_TLDS):
        return True
    return host_matches(normalized, RU_HOSTS)


def _policy_result(host, route_class, service_group, strategy_set):
    return {
        "host": host,
        "route_class": route_class,
        "service_group": service_group,
        "strategy_set": strategy_set,
    }


def classify_route_policy(host, static_routes, geo_exit_routes):
    """Classify one host using already validated policy tables."""
    normalized = normalize_host(host)
    if not normalized:
        return _policy_result(
            "", ROUTE_UNKNOWN, SERVICE_GENERIC, STRATEGY_GENERAL
        )

    policy = match_policy(normalized, static_routes)
    if policy:
        return _policy_result(
            normalized,
            policy["route_class"],
            policy["service_group"],
            policy["strategy_set"],
        )

    if is_russian(normalized):
        return _policy_result(
            normalized, ROUTE_DIRECT, SERVICE_GENERIC, STRATEGY_DIRECT
        )

    geo_policy = match_policy(normalized, geo_exit_routes)
    if geo_policy:
        return _policy_result(
            normalized,
            ROUTE_GEO_EXIT,
            geo_policy.get("service_group", SERVICE_GENERIC),
            STRATEGY_GEPH,
        )

    return _policy_result(
        normalized, ROUTE_UNKNOWN, SERVICE_GENERIC, STRATEGY_GENERAL
    )

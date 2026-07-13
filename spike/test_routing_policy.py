import ast
from pathlib import Path

import routing_policy
import tproxy


STATIC_ROUTES = (
    {
        "domains": ("direct.example",),
        "route_class": routing_policy.ROUTE_DIRECT,
        "service_group": routing_policy.SERVICE_GENERIC,
        "strategy_set": routing_policy.STRATEGY_DIRECT,
    },
    {
        "domains": ("video.example",),
        "route_class": routing_policy.ROUTE_LOCAL_BYPASS,
        "service_group": routing_policy.SERVICE_YOUTUBE,
        "strategy_set": routing_policy.STRATEGY_FAKE_ONLY,
    },
)
GEO_EXIT_ROUTES = (
    {
        "domains": ("geo.example",),
        "service_group": routing_policy.SERVICE_OPENAI,
    },
)


def test_classifier_is_pure_and_normalizes_suffix_matches():
    assert routing_policy.classify_route_policy(
        "Sub.Video.Example.", STATIC_ROUTES, GEO_EXIT_ROUTES
    ) == {
        "host": "sub.video.example",
        "route_class": "local_bypass",
        "service_group": "youtube_video",
        "strategy_set": "fake_only",
    }


def test_classifier_keeps_russian_hosts_direct_before_geo_exit():
    geo_exit_routes = (
        {
            "domains": ("yandex.com",),
            "service_group": routing_policy.SERVICE_GENERIC,
        },
    )

    assert routing_policy.classify_route_policy(
        "yandex.com", (), geo_exit_routes
    )["route_class"] == routing_policy.ROUTE_DIRECT


def test_classifier_returns_unknown_for_unmatched_host():
    assert routing_policy.classify_route_policy(
        "unlisted.example", STATIC_ROUTES, GEO_EXIT_ROUTES
    ) == {
        "host": "unlisted.example",
        "route_class": "unknown",
        "service_group": "generic",
        "strategy_set": "general",
    }


def test_tproxy_reexports_policy_vocabulary_and_classifier():
    assert tproxy.classify_route_policy is routing_policy.classify_route_policy
    assert tproxy.normalize_host is routing_policy.normalize_host
    assert tproxy.is_russian is routing_policy.is_russian
    assert tproxy.ROUTE_LOCAL_BYPASS == routing_policy.ROUTE_LOCAL_BYPASS
    assert tproxy.ROUTE_GEO_EXIT == routing_policy.ROUTE_GEO_EXIT


def test_policy_module_has_no_os_or_network_adapter_imports():
    tree = ast.parse(Path(routing_policy.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])

    assert imported.isdisjoint(
        {"asyncio", "fcntl", "os", "socket", "ssl", "subprocess", "urllib"}
    )

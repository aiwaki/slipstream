"""Pure version 1 route-policy manifest parsing and validation."""

import ipaddress
import re

from routing_policy import (
    ROUTE_DIRECT,
    ROUTE_DIRECT_FIRST,
    ROUTE_GEO_EXIT,
    ROUTE_LOCAL_BYPASS,
    SERVICE_ANTHROPIC,
    SERVICE_DISCORD,
    SERVICE_GENERIC,
    SERVICE_GITHUB,
    SERVICE_GOOGLE,
    SERVICE_OPENAI,
    SERVICE_SPOTIFY,
    SERVICE_STEAM_STORE,
    SERVICE_TELEGRAM,
    SERVICE_YOUTUBE,
    STRATEGY_DIRECT,
    STRATEGY_DIRECT_FIRST,
    STRATEGY_FAKE_ONLY,
    STRATEGY_GEPH,
    classify_route_policy,
    host_matches,
)


CONTRACT_VERSION = 1
MAX_SOURCE_BYTES = 128
MAX_ROUTES_PER_TABLE = 128
MAX_DOMAINS_PER_ROUTE = 256
MAX_TOTAL_DOMAINS = 4096
MAX_HOST_BYTES = 253
MAX_LABEL_BYTES = 63
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

PROTECTED_LOCAL_BYPASS_GROUPS = frozenset((SERVICE_DISCORD, SERVICE_YOUTUBE))
ALLOWED_SERVICE_GROUPS = frozenset((
    SERVICE_DISCORD,
    SERVICE_YOUTUBE,
    SERVICE_OPENAI,
    SERVICE_ANTHROPIC,
    SERVICE_TELEGRAM,
    SERVICE_STEAM_STORE,
    SERVICE_GITHUB,
    SERVICE_GOOGLE,
    SERVICE_SPOTIFY,
    SERVICE_GENERIC,
))
ALLOWED_STRATEGY_BY_ROUTE = {
    ROUTE_DIRECT: frozenset((STRATEGY_DIRECT,)),
    ROUTE_DIRECT_FIRST: frozenset((STRATEGY_DIRECT_FIRST,)),
    ROUTE_LOCAL_BYPASS: frozenset((STRATEGY_FAKE_ONLY,)),
    ROUTE_GEO_EXIT: frozenset((STRATEGY_GEPH,)),
}


class RoutePolicyManifestError(ValueError):
    """Stable policy-manifest validation failure shared by contract vectors."""

    def __init__(self, code, path, message):
        super().__init__(message)
        self.code = code
        self.path = path


def _error(code, path, message):
    raise RoutePolicyManifestError(code, path, message)


def _short_path(path):
    return path[2:] if path.startswith("$.") else path


def _required(manifest, field, path):
    if field not in manifest:
        _error("missing_field", path, f"{field} is required")
    return manifest[field]


def _require_int(value, path, *, min_value, max_value):
    name = path.rsplit(".", 1)[-1]
    if not isinstance(value, int) or isinstance(value, bool):
        _error("invalid_type", path, f"{name} must be an integer")
    if value < min_value or value > max_value:
        _error("out_of_range", path, f"{name} out of range")
    return value


def _normalize_hostname(domain, path, route_path):
    prefix = f"{_short_path(route_path)}.domains contains invalid host {domain!r}: "
    if domain != domain.strip():
        _error("invalid_hostname", path, prefix + "surrounding whitespace is not allowed")
    if not domain.isascii():
        _error("invalid_hostname", path, prefix + "host must be ASCII")
    host = domain[:-1] if domain.endswith(".") else domain
    if host.endswith("."):
        _error("invalid_hostname", path, prefix + "only one trailing root dot is allowed")
    host = host.lower()
    if not host or len(host.encode("ascii")) > MAX_HOST_BYTES:
        _error("invalid_hostname", path, prefix + "host length is invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        _error("invalid_hostname", path, prefix + "IP literals are not policy hostnames")
    labels = host.split(".")
    if len(labels) < 2:
        _error("invalid_hostname", path, prefix + "host must contain at least two labels")
    for label in labels:
        if not label or len(label) > MAX_LABEL_BYTES or HOST_LABEL.fullmatch(label) is None:
            _error("invalid_hostname", path, prefix + "DNS label syntax is invalid")
    return host


def _normalize_domains(domains, path):
    name = _short_path(path)
    if domains is None:
        _error("missing_field", f"{path}.domains", f"{name}.domains is required")
    if not isinstance(domains, (list, tuple)):
        _error(
            "invalid_type",
            f"{path}.domains",
            f"{name}.domains must be a non-empty list",
        )
    if not domains:
        _error(
            "empty_value",
            f"{path}.domains",
            f"{name}.domains must be a non-empty list",
        )
    if len(domains) > MAX_DOMAINS_PER_ROUTE:
        _error(
            "limit_exceeded",
            f"{path}.domains",
            f"route exceeds {MAX_DOMAINS_PER_ROUTE} domains",
        )

    normalized = []
    seen = set()
    for index, domain in enumerate(domains):
        domain_path = f"{path}.domains[{index}]"
        if not isinstance(domain, str):
            _error(
                "invalid_type",
                domain_path,
                f"{name}.domains entries must be strings",
            )
        host = _normalize_hostname(domain, domain_path, path)
        if host not in seen:
            normalized.append(host)
            seen.add(host)
    return normalized


def _normalize_entry(
    entry,
    path,
    *,
    default_route_class=None,
    default_strategy_set=None,
    static_table=False,
    geo_exit_table=False,
):
    name = _short_path(path)
    if not isinstance(entry, dict):
        _error("invalid_type", path, f"{name} must be an object")

    if "service_group" not in entry:
        _error("missing_field", f"{path}.service_group", "service_group is required")
    group = entry["service_group"]
    if not isinstance(group, str):
        _error(
            "invalid_type",
            f"{path}.service_group",
            "service_group must be a string",
        )
    if group not in ALLOWED_SERVICE_GROUPS:
        _error(
            "unsupported_service_group",
            f"{path}.service_group",
            f"{name}.service_group is not supported",
        )

    if "route_class" in entry:
        route_class = entry["route_class"]
    elif default_route_class is not None:
        route_class = default_route_class
    else:
        _error("missing_field", f"{path}.route_class", "route_class is required")
    if not isinstance(route_class, str):
        _error(
            "invalid_type",
            f"{path}.route_class",
            "route_class must be a string",
        )
    if route_class not in ALLOWED_STRATEGY_BY_ROUTE:
        _error(
            "unsupported_route_class",
            f"{path}.route_class",
            f"{name}.route_class is not supported",
        )
    if geo_exit_table and route_class != ROUTE_GEO_EXIT:
        _error(
            "geo_exit_route_mismatch",
            f"{path}.route_class",
            f"{name} must be geo_exit",
        )

    if "strategy_set" in entry:
        strategy_set = entry["strategy_set"]
    elif default_strategy_set is not None:
        strategy_set = default_strategy_set
    else:
        _error("missing_field", f"{path}.strategy_set", "strategy_set is required")
    if not isinstance(strategy_set, str):
        _error(
            "invalid_type",
            f"{path}.strategy_set",
            "strategy_set must be a string",
        )
    if strategy_set not in ALLOWED_STRATEGY_BY_ROUTE[route_class]:
        _error(
            "strategy_mismatch",
            f"{path}.strategy_set",
            f"{name}.strategy_set does not match route_class",
        )

    if group in PROTECTED_LOCAL_BYPASS_GROUPS and (
        route_class != ROUTE_LOCAL_BYPASS or strategy_set != STRATEGY_FAKE_ONLY
    ):
        _error(
            "protected_local_bypass",
            path,
            f"{group} must stay local_bypass/fake_only",
        )
    if static_table and route_class == ROUTE_GEO_EXIT:
        _error(
            "static_geo_exit_forbidden",
            f"{path}.route_class",
            "geo_exit routes belong in geo_exit_routes, not static_routes",
        )

    return {
        "domains": _normalize_domains(entry.get("domains"), path),
        "route_class": route_class,
        "service_group": group,
        "strategy_set": strategy_set,
    }


def _protected_expectations(bundled_static_routes):
    return tuple(
        (domain, policy)
        for policy in bundled_static_routes
        if (
            policy["service_group"] in PROTECTED_LOCAL_BYPASS_GROUPS
            or policy["route_class"] == ROUTE_DIRECT_FIRST
        )
        for domain in policy["domains"]
    )


def _patterns_overlap(left, right):
    return host_matches(left, (right,)) or host_matches(right, (left,))


def _validate_protected_routes(normalized, bundled_static_routes):
    expectations = _protected_expectations(bundled_static_routes)
    for route_index, policy in enumerate(normalized["geo_exit_routes"]):
        for domain_index, domain in enumerate(policy["domains"]):
            protected = next((
                candidate
                for candidate, _expected in expectations
                if _patterns_overlap(domain, candidate)
            ), None)
            if protected is not None:
                _error(
                    "protected_geo_exit_overlap",
                    f"$.geo_exit_routes[{route_index}].domains[{domain_index}]",
                    f"geo_exit domain {domain!r} overlaps protected domain {protected!r}",
                )

    for domain, expected in expectations:
        candidates = [domain]
        seen = {domain}
        for policy in normalized["static_routes"]:
            for candidate in policy["domains"]:
                if host_matches(candidate, (domain,)) and candidate not in seen:
                    candidates.append(candidate)
                    seen.add(candidate)

        for candidate in candidates:
            actual = classify_route_policy(
                candidate,
                normalized["static_routes"],
                normalized["geo_exit_routes"],
            )
            if (
                actual["route_class"] == expected["route_class"]
                and actual["service_group"] == expected["service_group"]
                and actual["strategy_set"] == expected["strategy_set"]
            ):
                continue
            protected_suffix = (
                "" if candidate == domain else f" under protected suffix {domain}"
            )
            if expected["route_class"] == ROUTE_DIRECT_FIRST:
                _error(
                    "protected_direct_first",
                    "$.static_routes",
                    "protected direct-first domains missing or shadowed: "
                    f"{candidate}{protected_suffix}",
                )
            _error(
                "protected_route_mismatch",
                "$.static_routes",
                "protected local-bypass domain missing or shadowed: "
                f"{candidate}{protected_suffix} must stay local_bypass/fake_only as "
                f"{expected['service_group']}",
            )


def _parse_attempt_limits(manifest):
    attempt_limits = _required(manifest, "attempt_limits", "$.attempt_limits")
    if not isinstance(attempt_limits, dict):
        _error("invalid_type", "$.attempt_limits", "attempt_limits must be an object")

    normalized = {}
    for route_class, value in attempt_limits.items():
        route_path = f"$.attempt_limits.{route_class}"
        if route_class != "default" and route_class not in ALLOWED_STRATEGY_BY_ROUTE:
            _error(
                "unsupported_attempt_route",
                route_path,
                f"attempt_limits has unsupported route {route_class!r}",
            )
        normalized[route_class] = _require_int(
            value,
            route_path,
            min_value=1,
            max_value=8,
        )
    if "default" not in normalized:
        _error(
            "missing_field",
            "$.attempt_limits.default",
            "attempt_limits.default is required",
        )
    return normalized


def validate_route_policy_manifest(manifest, bundled_static_routes):
    if not isinstance(manifest, dict):
        _error("invalid_type", "$", "policy manifest must be an object")

    version = _require_int(
        _required(manifest, "version", "$.version"),
        "$.version",
        min_value=1,
        max_value=1_000_000,
    )
    source = _required(manifest, "source", "$.source")
    if not isinstance(source, str):
        _error("invalid_type", "$.source", "source must be a string")
    if not source.strip():
        _error("empty_value", "$.source", "source must be a non-empty string")
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        _error("limit_exceeded", "$.source", f"source exceeds {MAX_SOURCE_BYTES} bytes")

    static_routes = _required(manifest, "static_routes", "$.static_routes")
    if not isinstance(static_routes, list):
        _error(
            "invalid_type",
            "$.static_routes",
            "static_routes must be a non-empty list",
        )
    if not static_routes:
        _error(
            "empty_value",
            "$.static_routes",
            "static_routes must be a non-empty list",
        )
    if len(static_routes) > MAX_ROUTES_PER_TABLE:
        _error(
            "limit_exceeded",
            "$.static_routes",
            f"route table exceeds {MAX_ROUTES_PER_TABLE} entries",
        )

    geo_exit_routes = _required(manifest, "geo_exit_routes", "$.geo_exit_routes")
    if not isinstance(geo_exit_routes, list):
        _error("invalid_type", "$.geo_exit_routes", "geo_exit_routes must be a list")
    if len(geo_exit_routes) > MAX_ROUTES_PER_TABLE:
        _error(
            "limit_exceeded",
            "$.geo_exit_routes",
            f"route table exceeds {MAX_ROUTES_PER_TABLE} entries",
        )

    normalized = {
        "version": version,
        "source": source,
        "static_routes": [],
        "geo_exit_routes": [],
        "attempt_limits": {},
    }
    total_domains = 0
    for index, entry in enumerate(static_routes):
        item = _normalize_entry(
            entry,
            f"$.static_routes[{index}]",
            static_table=True,
        )
        normalized["static_routes"].append(item)
        total_domains += len(item["domains"])
        if total_domains > MAX_TOTAL_DOMAINS:
            _error(
                "limit_exceeded",
                "$",
                f"policy manifest exceeds {MAX_TOTAL_DOMAINS} domains",
            )

    for index, entry in enumerate(geo_exit_routes):
        item = _normalize_entry(
            entry,
            f"$.geo_exit_routes[{index}]",
            default_route_class=ROUTE_GEO_EXIT,
            default_strategy_set=STRATEGY_GEPH,
            geo_exit_table=True,
        )
        normalized["geo_exit_routes"].append(item)
        total_domains += len(item["domains"])
        if total_domains > MAX_TOTAL_DOMAINS:
            _error(
                "limit_exceeded",
                "$",
                f"policy manifest exceeds {MAX_TOTAL_DOMAINS} domains",
            )

    normalized["attempt_limits"] = _parse_attempt_limits(manifest)
    _validate_protected_routes(normalized, bundled_static_routes)
    return normalized

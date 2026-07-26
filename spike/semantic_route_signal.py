"""Pure browser semantic-signal parsing and reduction with no OS effects."""

from dataclasses import dataclass
import ipaddress
import json
import re


SCHEMA_VERSION = 1
MAX_SIGNAL_BYTES = 2048
MAX_SIGNAL_AGE_MS = 120_000
MAX_FUTURE_SKEW_MS = 5_000
SIGNAL_COOLDOWN_MS = 300_000
MIN_CONFIDENCE_BPS = 9_000

SOURCE_BROWSER_EXTENSION = "browser_extension"
CATEGORY_REGIONAL_ACCESS_DENIED = "regional_access_denied"

ACTION_NONE = "none"
ACTION_CONFIRM_EXACT_HOST_GEO_EXIT = "confirm_exact_host_geo_exit"

REASON_ACCEPTED = "accepted"
REASON_NOT_TOP_LEVEL = "not_top_level"
REASON_LOW_CONFIDENCE = "low_confidence"
REASON_STALE = "stale"
REASON_FUTURE = "future"
REASON_REPLAY = "replay"
REASON_PROTECTED_ROUTE = "protected_route"
REASON_ALREADY_GEO_EXIT = "already_geo_exit"
REASON_BACKEND_UNAVAILABLE = "backend_unavailable"
REASON_RATE_LIMITED = "rate_limited"

ROUTE_DIRECT = "direct_passthrough"
ROUTE_DIRECT_FIRST = "direct_first"
ROUTE_LOCAL_BYPASS = "local_bypass"
ROUTE_GEO_EXIT = "geo_exit"
ROUTE_UNKNOWN = "unknown"

_SIGNAL_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_REQUIRED_FIELDS = frozenset(
    (
        "schema_version",
        "signal_id",
        "source",
        "host",
        "category",
        "confidence_bps",
        "observed_at_unix_ms",
        "top_level",
    )
)


class SemanticSignalError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SemanticRouteSignalV1:
    signal_id: str
    host: str
    confidence_bps: int
    observed_at_unix_ms: int
    top_level: bool
    source: str = SOURCE_BROWSER_EXTENSION
    category: str = CATEGORY_REGIONAL_ACCESS_DENIED
    schema_version: int = SCHEMA_VERSION


@dataclass(frozen=True)
class SemanticRouteSignalContext:
    now_unix_ms: int
    route_class: str
    owned_geph_payload_ready: bool
    last_accepted_at_unix_ms: int | None = None
    signal_id_seen: bool = False


@dataclass(frozen=True)
class SemanticRouteSignalDecision:
    accepted: bool
    action: str
    reason: str
    host: str


def _normalize_hostname(value):
    if not isinstance(value, str):
        raise SemanticSignalError("invalid_host")
    host = value.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253 or host != host.strip():
        raise SemanticSignalError("invalid_host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SemanticSignalError("invalid_host")
    labels = host.split(".")
    if len(labels) < 2 or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise SemanticSignalError("invalid_host")
    return host


def parse_semantic_route_signal_v1(payload):
    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        raw = payload
    else:
        raise SemanticSignalError("invalid_shape")
    if not raw:
        raise SemanticSignalError("empty_input")
    if len(raw) > MAX_SIGNAL_BYTES:
        raise SemanticSignalError("payload_too_large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SemanticSignalError("invalid_json") from error
    if not isinstance(value, dict) or frozenset(value) != _REQUIRED_FIELDS:
        raise SemanticSignalError("invalid_shape")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise SemanticSignalError("unsupported_version")
    signal_id = value["signal_id"]
    if not isinstance(signal_id, str) or not _SIGNAL_ID_RE.fullmatch(signal_id):
        raise SemanticSignalError("invalid_signal_id")
    if value["source"] != SOURCE_BROWSER_EXTENSION:
        raise SemanticSignalError("invalid_source")
    host = _normalize_hostname(value["host"])
    if value["category"] != CATEGORY_REGIONAL_ACCESS_DENIED:
        raise SemanticSignalError("invalid_category")
    confidence = value["confidence_bps"]
    if type(confidence) is not int or not 0 <= confidence <= 10_000:
        raise SemanticSignalError("invalid_confidence")
    observed_at = value["observed_at_unix_ms"]
    if type(observed_at) is not int or observed_at <= 0:
        raise SemanticSignalError("invalid_observed_at")
    if type(value["top_level"]) is not bool:
        raise SemanticSignalError("invalid_top_level")
    return SemanticRouteSignalV1(
        signal_id=signal_id,
        host=host,
        confidence_bps=confidence,
        observed_at_unix_ms=observed_at,
        top_level=value["top_level"],
    )


def _decision(signal, accepted, action, reason):
    return SemanticRouteSignalDecision(
        accepted=accepted,
        action=action,
        reason=reason,
        host=signal.host,
    )


def reduce_semantic_route_signal(signal, context):
    if not signal.top_level:
        return _decision(signal, False, ACTION_NONE, REASON_NOT_TOP_LEVEL)
    if signal.confidence_bps < MIN_CONFIDENCE_BPS:
        return _decision(signal, False, ACTION_NONE, REASON_LOW_CONFIDENCE)
    if signal.observed_at_unix_ms > context.now_unix_ms + MAX_FUTURE_SKEW_MS:
        return _decision(signal, False, ACTION_NONE, REASON_FUTURE)
    if context.now_unix_ms - signal.observed_at_unix_ms > MAX_SIGNAL_AGE_MS:
        return _decision(signal, False, ACTION_NONE, REASON_STALE)
    if context.signal_id_seen:
        return _decision(signal, False, ACTION_NONE, REASON_REPLAY)
    if context.route_class in (ROUTE_DIRECT, ROUTE_DIRECT_FIRST, ROUTE_LOCAL_BYPASS):
        return _decision(signal, False, ACTION_NONE, REASON_PROTECTED_ROUTE)
    if context.route_class == ROUTE_GEO_EXIT:
        return _decision(signal, False, ACTION_NONE, REASON_ALREADY_GEO_EXIT)
    if context.route_class != ROUTE_UNKNOWN:
        return _decision(signal, False, ACTION_NONE, REASON_PROTECTED_ROUTE)
    if not context.owned_geph_payload_ready:
        return _decision(signal, False, ACTION_NONE, REASON_BACKEND_UNAVAILABLE)
    if (
        context.last_accepted_at_unix_ms is not None
        and context.now_unix_ms - context.last_accepted_at_unix_ms
        < SIGNAL_COOLDOWN_MS
    ):
        return _decision(signal, False, ACTION_NONE, REASON_RATE_LIMITED)
    return _decision(
        signal,
        True,
        ACTION_CONFIRM_EXACT_HOST_GEO_EXIT,
        REASON_ACCEPTED,
    )

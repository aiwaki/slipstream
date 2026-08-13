"""Pure, privacy-bounded exact-host route preflight contract."""

from dataclasses import dataclass
import ipaddress
import json
import re


SCHEMA_VERSION = 1
MAX_PAYLOAD_BYTES = 2048
MAX_DEADLINE_MS = 8_000
MAX_CANDIDATE_ROUTES = 4

CANDIDATE_ROUTES = frozenset(("system", "app_doh", "local_strategy", "owned_geph"))
OUTCOMES = frozenset(
    (
        "navigation_pending",
        "regional_access_denied",
        "edge_access_denied",
        "challenge_or_auth",
        "usable",
        "terminal_error",
    )
)

REASON_ACCEPTED = "accepted"
REASON_BINDING_MISMATCH = "binding_mismatch"
REASON_CANDIDATE_NOT_ALLOWED = "candidate_not_allowed"
REASON_OBSERVATION_OUTSIDE_DEADLINE = "observation_outside_deadline"
REASON_EXPIRED = "expired"
REASON_REPLAY = "replay"

_CAPABILITY_RE = re.compile(r"^[0-9a-f]{32}$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_JOB_FIELDS = frozenset(
    (
        "schema_version",
        "capability",
        "host",
        "candidate_routes",
        "issued_at_unix_ms",
        "deadline_unix_ms",
    )
)
_RESULT_FIELDS = frozenset(
    (
        "schema_version",
        "capability",
        "host",
        "candidate_route",
        "outcome",
        "observed_at_unix_ms",
    )
)


class RoutePreflightError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RoutePreflightJobV1:
    capability: str
    host: str
    candidate_routes: tuple[str, ...]
    issued_at_unix_ms: int
    deadline_unix_ms: int
    schema_version: int = SCHEMA_VERSION


@dataclass(frozen=True)
class RoutePreflightResultV1:
    capability: str
    host: str
    candidate_route: str
    outcome: str
    observed_at_unix_ms: int
    schema_version: int = SCHEMA_VERSION


@dataclass(frozen=True)
class RoutePreflightDecision:
    accepted: bool
    reason: str
    host: str
    candidate_route: str
    outcome: str


def _object(payload, fields):
    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        raw = payload
    else:
        raise RoutePreflightError("invalid_shape")
    if not raw:
        raise RoutePreflightError("empty_input")
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise RoutePreflightError("payload_too_large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RoutePreflightError("invalid_json") from error
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise RoutePreflightError("invalid_shape")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise RoutePreflightError("unsupported_version")
    return value


def _capability(value):
    if not isinstance(value, str) or not _CAPABILITY_RE.fullmatch(value):
        raise RoutePreflightError("invalid_capability")
    return value


def _host(value):
    if not isinstance(value, str) or not value.isascii() or value != value.strip():
        raise RoutePreflightError("invalid_host")
    host = value.lower()
    if host.endswith("."):
        host = host[:-1]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise RoutePreflightError("invalid_host")
    labels = host.split(".")
    if (
        not host
        or len(host) > 253
        or len(labels) < 2
        or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels)
    ):
        raise RoutePreflightError("invalid_host")
    return host


def parse_route_preflight_job_v1(payload):
    value = _object(payload, _JOB_FIELDS)
    capability = _capability(value["capability"])
    host = _host(value["host"])
    routes = value["candidate_routes"]
    if (
        not isinstance(routes, list)
        or not routes
        or len(routes) > MAX_CANDIDATE_ROUTES
        or len(set(routes)) != len(routes)
        or any(type(route) is not str or route not in CANDIDATE_ROUTES for route in routes)
    ):
        raise RoutePreflightError("invalid_candidate_routes")
    issued_at = value["issued_at_unix_ms"]
    if type(issued_at) is not int or issued_at <= 0:
        raise RoutePreflightError("invalid_issued_at")
    deadline = value["deadline_unix_ms"]
    if (
        type(deadline) is not int
        or deadline <= issued_at
        or deadline - issued_at > MAX_DEADLINE_MS
    ):
        raise RoutePreflightError("invalid_deadline")
    return RoutePreflightJobV1(
        capability=capability,
        host=host,
        candidate_routes=tuple(routes),
        issued_at_unix_ms=issued_at,
        deadline_unix_ms=deadline,
    )


def parse_route_preflight_result_v1(payload):
    value = _object(payload, _RESULT_FIELDS)
    capability = _capability(value["capability"])
    host = _host(value["host"])
    route = value["candidate_route"]
    if type(route) is not str or route not in CANDIDATE_ROUTES:
        raise RoutePreflightError("invalid_candidate_route")
    outcome = value["outcome"]
    if type(outcome) is not str or outcome not in OUTCOMES:
        raise RoutePreflightError("invalid_outcome")
    observed_at = value["observed_at_unix_ms"]
    if type(observed_at) is not int or observed_at <= 0:
        raise RoutePreflightError("invalid_observed_at")
    return RoutePreflightResultV1(
        capability=capability,
        host=host,
        candidate_route=route,
        outcome=outcome,
        observed_at_unix_ms=observed_at,
    )


def validate_route_preflight_result_v1(
    job, result, *, now_unix_ms, capability_seen=False
):
    if capability_seen:
        reason = REASON_REPLAY
    elif (
        job.schema_version != result.schema_version
        or job.capability != result.capability
        or job.host != result.host
    ):
        reason = REASON_BINDING_MISMATCH
    elif result.candidate_route not in job.candidate_routes:
        reason = REASON_CANDIDATE_NOT_ALLOWED
    elif not job.issued_at_unix_ms <= result.observed_at_unix_ms <= job.deadline_unix_ms:
        reason = REASON_OBSERVATION_OUTSIDE_DEADLINE
    elif now_unix_ms > job.deadline_unix_ms:
        reason = REASON_EXPIRED
    else:
        reason = REASON_ACCEPTED
    return RoutePreflightDecision(
        accepted=reason == REASON_ACCEPTED,
        reason=reason,
        host=result.host,
        candidate_route=result.candidate_route,
        outcome=result.outcome,
    )

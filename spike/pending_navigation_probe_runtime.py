"""Bounded owner-only job/result broker for pending-navigation probes."""

from collections import OrderedDict
from dataclasses import dataclass
import ipaddress
import json
import re
import threading
import time


SCHEMA_VERSION = 1
OPERATION_CLAIM = "claim"
OPERATION_SUBMIT = "submit"
OPERATION_NONE = "none"
REASON_ACCEPTED = "accepted"
REASON_INVALID_REQUEST = "invalid_request"
REASON_JOB_READY = "job_ready"
REASON_NO_JOB = "no_job"
REASON_RESULT_REJECTED = "result_rejected"
REASON_EFFECT_UNAVAILABLE = "effect_unavailable"

CAPABILITY_HEX_CHARS = 32
CAPABILITY_TTL_MS = 30_000
CLAIM_LEASE_SECONDS = 5.0
MAX_LIVE_JOBS = 32
MAX_ENQUEUE_AGE_MS = 5_000
MAX_IPC_BYTES = 2_048
PENDING_NAVIGATION_PROBE_SOCKET_PATH = (
    "/var/run/slipstream-browser-probe.sock"
)

_CAPABILITY_RE = re.compile(
    rf"^[0-9a-f]{{{CAPABILITY_HEX_CHARS}}}$"
)
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_JOB_FIELDS = frozenset((
    "schema_version",
    "capability",
    "host",
    "request_started_at_unix_ms",
    "issued_at_unix_ms",
    "expires_at_unix_ms",
))


class PendingNavigationProbeRuntimeError(ValueError):
    pass


@dataclass(slots=True)
class _QueuedProbeJob:
    job: dict
    expires_at_monotonic: float
    claimed_until_monotonic: float = 0.0


def _response(accepted, operation, reason, job=None):
    return {
        "schema_version": SCHEMA_VERSION,
        "accepted": bool(accepted),
        "operation": operation,
        "reason": reason,
        "job": job,
    }


def _reject_duplicate_keys(pairs):
    payload = {}
    for key, value in pairs:
        if key in payload:
            raise PendingNavigationProbeRuntimeError("duplicate_key")
        payload[key] = value
    return payload


def _parse_request(payload):
    if (
        not isinstance(payload, bytes)
        or not payload
        or len(payload) > MAX_IPC_BYTES
    ):
        raise PendingNavigationProbeRuntimeError("invalid_payload")
    try:
        request = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PendingNavigationProbeRuntimeError("invalid_json") from error
    if not isinstance(request, dict):
        raise PendingNavigationProbeRuntimeError("invalid_shape")
    return request


def _canonical_host(value):
    if not isinstance(value, str) or not value.isascii():
        return None
    if not value or len(value) > 253 or value != value.lower().strip("."):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return None
    labels = value.split(".")
    if len(labels) < 2 or any(
        not _HOST_LABEL_RE.fullmatch(label) for label in labels
    ):
        return None
    return value


def _valid_positive_int(value):
    return type(value) is int and value > 0


def _validate_job(job, now_unix_ms):
    if not isinstance(job, dict) or set(job) != _JOB_FIELDS:
        return None
    if type(job.get("schema_version")) is not int or job["schema_version"] != 1:
        return None
    capability = job.get("capability")
    host = _canonical_host(job.get("host"))
    request_started_at = job.get("request_started_at_unix_ms")
    issued_at = job.get("issued_at_unix_ms")
    expires_at = job.get("expires_at_unix_ms")
    if (
        not isinstance(capability, str)
        or not _CAPABILITY_RE.fullmatch(capability)
        or host is None
        or not _valid_positive_int(request_started_at)
        or not _valid_positive_int(issued_at)
        or not _valid_positive_int(expires_at)
        or request_started_at > issued_at
        or expires_at - issued_at != CAPABILITY_TTL_MS
        or not 0 <= now_unix_ms - issued_at <= MAX_ENQUEUE_AGE_MS
        or expires_at <= now_unix_ms
    ):
        return None
    return dict(job)


class PendingNavigationProbeRuntime:
    """Queue exact capability jobs and submit results through one local effect."""

    def __init__(
        self,
        *,
        submit_result,
        wall_clock_ms=None,
        monotonic_clock=None,
        max_live_jobs=MAX_LIVE_JOBS,
        claim_lease_seconds=CLAIM_LEASE_SECONDS,
    ):
        if (
            not callable(submit_result)
            or type(max_live_jobs) is not int
            or max_live_jobs <= 0
            or not isinstance(claim_lease_seconds, (int, float))
            or isinstance(claim_lease_seconds, bool)
            or claim_lease_seconds <= 0
        ):
            raise ValueError("pending-navigation probe runtime bounds are invalid")
        self._submit_result = submit_result
        self._wall_clock_ms = wall_clock_ms or (lambda: int(time.time() * 1000))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._max_live_jobs = max_live_jobs
        self._claim_lease_seconds = float(claim_lease_seconds)
        self._jobs = OrderedDict()
        self._lock = threading.Lock()

    def _prune_locked(self, now_monotonic):
        for capability, queued in tuple(self._jobs.items()):
            if queued.expires_at_monotonic <= now_monotonic:
                self._jobs.pop(capability, None)
        while len(self._jobs) > self._max_live_jobs:
            self._jobs.popitem(last=False)

    def enqueue(self, job):
        now_unix_ms = self._wall_clock_ms()
        now_monotonic = self._monotonic_clock()
        if type(now_unix_ms) is not int or now_unix_ms <= 0:
            return False
        validated = _validate_job(job, now_unix_ms)
        if validated is None:
            return False
        capability = validated["capability"]
        expires_at_monotonic = now_monotonic + (
            validated["expires_at_unix_ms"] - now_unix_ms
        ) / 1000.0
        with self._lock:
            self._prune_locked(now_monotonic)
            if capability in self._jobs:
                return False
            self._jobs[capability] = _QueuedProbeJob(
                job=validated,
                expires_at_monotonic=expires_at_monotonic,
            )
            self._prune_locked(now_monotonic)
            return capability in self._jobs

    def _claim(self):
        now_monotonic = self._monotonic_clock()
        with self._lock:
            self._prune_locked(now_monotonic)
            for queued in self._jobs.values():
                if queued.claimed_until_monotonic > now_monotonic:
                    continue
                queued.claimed_until_monotonic = min(
                    queued.expires_at_monotonic,
                    now_monotonic + self._claim_lease_seconds,
                )
                return _response(
                    True,
                    OPERATION_CLAIM,
                    REASON_JOB_READY,
                    dict(queued.job),
                )
        return _response(True, OPERATION_CLAIM, REASON_NO_JOB)

    def _submit(self, result):
        if not isinstance(result, dict):
            return _response(
                False,
                OPERATION_SUBMIT,
                REASON_INVALID_REQUEST,
            )
        capability = result.get("capability")
        if isinstance(capability, str) and _CAPABILITY_RE.fullmatch(capability):
            with self._lock:
                self._jobs.pop(capability, None)
        try:
            accepted = self._submit_result(result) is True
        except Exception:
            return _response(
                False,
                OPERATION_SUBMIT,
                REASON_EFFECT_UNAVAILABLE,
            )
        return _response(
            accepted,
            OPERATION_SUBMIT,
            REASON_ACCEPTED if accepted else REASON_RESULT_REJECTED,
        )

    def handle(self, payload):
        try:
            request = _parse_request(payload)
        except PendingNavigationProbeRuntimeError:
            return _response(False, OPERATION_NONE, REASON_INVALID_REQUEST)
        if type(request.get("schema_version")) is not int:
            return _response(False, OPERATION_NONE, REASON_INVALID_REQUEST)
        if request["schema_version"] != SCHEMA_VERSION:
            return _response(False, OPERATION_NONE, REASON_INVALID_REQUEST)
        operation = request.get("operation")
        if operation == OPERATION_CLAIM and set(request) == {
            "schema_version",
            "operation",
        }:
            return self._claim()
        if operation == OPERATION_SUBMIT and set(request) == {
            "schema_version",
            "operation",
            "result",
        }:
            return self._submit(request["result"])
        return _response(False, OPERATION_NONE, REASON_INVALID_REQUEST)

    def state_size(self):
        now_monotonic = self._monotonic_clock()
        with self._lock:
            self._prune_locked(now_monotonic)
            return len(self._jobs)

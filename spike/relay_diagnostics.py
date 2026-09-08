"""Bounded, drop-only observations of actual relay termination, not route proof.

The caller supplies a reason at the action/read branch that caused termination;
cleanup timestamps or cancellation of the other relay task are not evidence of
an upstream EOF. This module has no clocks, sockets, sinks, or routing callbacks.
Counters cover accepted records since process start; history is oldest-first.
Lock contention or diagnostic failure may lose observations but never waits.
"""

from collections import deque
import ipaddress
import re
import threading


RECENT_LIMIT = 64
COUNTER_LIMIT = (1 << 31) - 1
REASONS = (
    "upstream_eof",
    "upstream_read_error",
    "upstream_reset",
    "client_eof",
    "client_read_error",
    "local_partial_record_watchdog",
    "local_half_close_idle",
    "authorized_retry",
    "cancellation",
    "write_error",
    "internal_error",
    "unknown",
)
STAGES = ("system_plain", "xbox_plain", "local_strategy", "geph", "unknown")
RECOVERY = (
    "not_attempted",
    "local_ladder_advanced",
    "local_ladder_unchanged",
    "confirmation_scheduled",
    "confirmation_not_scheduled",
    "route_committed",
    "not_applicable",
)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _safe_host(value):
    """Accept only already-normalized DNS names, never stringify input."""
    if type(value) is not str or not value or len(value) > 253:
        return "invalid"
    labels = value.split(".")
    if len(labels) < 2 or not re.search(r"[a-z]", labels[-1]) or not all(
        _LABEL.fullmatch(label) for label in labels
    ):
        return "invalid"
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    return "invalid"


def _safe_event(host, stage, reason, recovery):
    return (
        _safe_host(host),
        stage if type(stage) is str and stage in STAGES else "unknown",
        reason if type(reason) is str and reason in REASONS else "unknown",
        recovery if type(recovery) is str and recovery in RECOVERY else "not_attempted",
    )


def format_event(*, host, stage, reason, recovery="not_attempted"):
    """Return a bounded log line, or None on diagnostic failure; never emit it."""
    try:
        host, stage, reason, recovery = _safe_event(host, stage, reason, recovery)
        return f"relay-end host={host} stage={stage} reason={reason} recovery={recovery}"
    except Exception:
        return None


def _unavailable_snapshot(include_recent):
    snapshot = {
        "schema_version": 1,
        "available": False,
        "counters": {},
        "counter_saturated": False,
    }
    if include_recent is True:
        snapshot["recent"] = []
    return snapshot


class RelayDiagnostics:
    """Fixed-cardinality counters and a fixed-size recent termination history.

    Call record once per relay, after capturing its causal reason and before
    discarding that local state. Its result is delivery status, never permission
    to close, retry, cache, learn, or select a route. Snapshots are detached copies.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._counters = dict.fromkeys(REASONS, 0)
        self._recent = deque(maxlen=RECENT_LIMIT)

    def record(self, *, host, stage, reason, recovery="not_attempted"):
        """Try to retain an observation without blocking the relay."""
        acquired = False
        try:
            event = _safe_event(host, stage, reason, recovery)
            acquired = self._lock.acquire(blocking=False)
            if not acquired:
                return False
            self._counters[event[2]] = min(
                COUNTER_LIMIT, self._counters[event[2]] + 1
            )
            self._recent.append(event)
            return True
        except Exception:
            return False
        finally:
            if acquired:
                try:
                    self._lock.release()
                except Exception:
                    pass

    def snapshot(self, *, include_recent=False):
        """Public default is counters-only; recent hosts require explicit True.

        Use host-level history only in the existing private diagnostics boundary,
        never the public StatusV2 heartbeat. Unavailable is unknown, not zero.
        """
        acquired = False
        try:
            acquired = self._lock.acquire(blocking=False)
            if not acquired:
                return _unavailable_snapshot(include_recent)
            snapshot = {
                "schema_version": 1,
                "available": True,
                "counters": self._counters.copy(),
                "counter_saturated": any(
                    value == COUNTER_LIMIT for value in self._counters.values()
                ),
            }
            if include_recent is True:
                snapshot["recent"] = [
                    {"host": host, "stage": stage, "reason": reason, "recovery": recovery}
                    for host, stage, reason, recovery in self._recent
                ]
            return snapshot
        except Exception:
            return _unavailable_snapshot(include_recent)
        finally:
            if acquired:
                try:
                    self._lock.release()
                except Exception:
                    pass

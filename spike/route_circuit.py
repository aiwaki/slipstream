"""Pure route-scoped circuit breaker with no timers or network side effects."""

from dataclasses import dataclass
from typing import Optional


PHASE_CLOSED = "closed"
PHASE_OPEN = "open"
PHASE_HALF_OPEN = "half_open"
PHASE_INVALID = "invalid"

EVENT_BEFORE_REQUEST = "before_request"
EVENT_RECORD_SUCCESS = "record_success"
EVENT_RECORD_FAILURE = "record_failure"

DECISION_ALLOW = "allow"
DECISION_REJECT = "reject"
DECISION_RECORD = "record"
DECISION_IGNORE = "ignore"

PROTECTED_LOCAL_BYPASS_GROUPS = frozenset(("discord", "youtube_video"))


@dataclass(frozen=True, order=True)
class RouteCircuitKey:
    service_group: str
    route_class: str
    backend_id: str


@dataclass(frozen=True)
class CircuitConfig:
    failure_threshold: int
    open_duration_ms: int
    half_open_max_in_flight: int
    success_threshold: int


@dataclass(frozen=True)
class CircuitState:
    phase: str = PHASE_CLOSED
    consecutive_failures: int = 0
    opened_at_ms: Optional[int] = None
    half_open_in_flight: int = 0
    half_open_successes: int = 0


@dataclass(frozen=True)
class CircuitEvent:
    kind: str
    key: RouteCircuitKey
    now_ms: int


@dataclass(frozen=True)
class CircuitDecision:
    kind: str
    reason: str
    phase: str


@dataclass(frozen=True)
class CircuitSnapshot:
    key: RouteCircuitKey
    state: CircuitState


def _validate_config(config):
    if config.failure_threshold < 1:
        raise ValueError("failure_threshold must be positive")
    if config.open_duration_ms < 0:
        raise ValueError("open_duration_ms must not be negative")
    if config.half_open_max_in_flight < 1:
        raise ValueError("half_open_max_in_flight must be positive")
    if config.success_threshold < 1:
        raise ValueError("success_threshold must be positive")


def _protected_route_mismatch(key):
    return key.service_group in PROTECTED_LOCAL_BYPASS_GROUPS and (
        key.route_class != "local_bypass" or key.backend_id == "geph"
    )


def _store_state(states, key, state):
    updated = dict(states)
    if state == CircuitState():
        updated.pop(key, None)
    else:
        updated[key] = state
    return updated


def _before_request(states, event, state, config):
    if state.phase == PHASE_CLOSED:
        return dict(states), CircuitDecision(DECISION_ALLOW, "closed", PHASE_CLOSED)

    if state.phase == PHASE_OPEN:
        if state.opened_at_ms is None:
            raise ValueError("open circuit requires opened_at_ms")
        if event.now_ms < state.opened_at_ms + config.open_duration_ms:
            return dict(states), CircuitDecision(DECISION_REJECT, "open", PHASE_OPEN)
        state = CircuitState(phase=PHASE_HALF_OPEN)

    if state.phase != PHASE_HALF_OPEN:
        raise ValueError("unknown circuit phase")
    if state.half_open_in_flight >= config.half_open_max_in_flight:
        return _store_state(states, event.key, state), CircuitDecision(
            DECISION_REJECT, "half_open_limit", PHASE_HALF_OPEN
        )
    state = CircuitState(
        phase=PHASE_HALF_OPEN,
        half_open_in_flight=state.half_open_in_flight + 1,
        half_open_successes=state.half_open_successes,
    )
    return _store_state(states, event.key, state), CircuitDecision(
        DECISION_ALLOW, "half_open_probe", PHASE_HALF_OPEN
    )


def _record_success(states, event, state, config):
    if state.phase == PHASE_OPEN:
        return dict(states), CircuitDecision(
            DECISION_IGNORE, "stale_completion", PHASE_OPEN
        )
    if state.phase != PHASE_HALF_OPEN:
        return _store_state(states, event.key, CircuitState()), CircuitDecision(
            DECISION_RECORD, "success_recorded", PHASE_CLOSED
        )
    if state.half_open_in_flight < 1:
        return dict(states), CircuitDecision(
            DECISION_IGNORE, "stale_completion", PHASE_HALF_OPEN
        )

    successes = state.half_open_successes + 1
    if successes >= config.success_threshold:
        return _store_state(states, event.key, CircuitState()), CircuitDecision(
            DECISION_RECORD, "half_open_recovered", PHASE_CLOSED
        )
    state = CircuitState(
        phase=PHASE_HALF_OPEN,
        half_open_in_flight=state.half_open_in_flight - 1,
        half_open_successes=successes,
    )
    return _store_state(states, event.key, state), CircuitDecision(
        DECISION_RECORD, "success_recorded", PHASE_HALF_OPEN
    )


def _record_failure(states, event, state, config):
    if state.phase == PHASE_OPEN:
        return dict(states), CircuitDecision(
            DECISION_IGNORE, "stale_completion", PHASE_OPEN
        )
    if state.phase == PHASE_HALF_OPEN:
        if state.half_open_in_flight < 1:
            return dict(states), CircuitDecision(
                DECISION_IGNORE, "stale_completion", PHASE_HALF_OPEN
            )
        state = CircuitState(
            phase=PHASE_OPEN,
            consecutive_failures=config.failure_threshold,
            opened_at_ms=event.now_ms,
        )
        return _store_state(states, event.key, state), CircuitDecision(
            DECISION_RECORD, "half_open_failure", PHASE_OPEN
        )

    failures = state.consecutive_failures + 1
    if failures >= config.failure_threshold:
        state = CircuitState(
            phase=PHASE_OPEN,
            consecutive_failures=failures,
            opened_at_ms=event.now_ms,
        )
        return _store_state(states, event.key, state), CircuitDecision(
            DECISION_RECORD, "threshold_reached", PHASE_OPEN
        )
    state = CircuitState(consecutive_failures=failures)
    return _store_state(states, event.key, state), CircuitDecision(
        DECISION_RECORD, "failure_recorded", PHASE_CLOSED
    )


def reduce_route_circuit(states, event, config):
    """Apply one event and return a new key-scoped state map plus its decision."""
    _validate_config(config)
    handlers = {
        EVENT_BEFORE_REQUEST: _before_request,
        EVENT_RECORD_SUCCESS: _record_success,
        EVENT_RECORD_FAILURE: _record_failure,
    }
    handler = handlers.get(event.kind)
    if handler is None:
        raise ValueError("unknown circuit event")

    if _protected_route_mismatch(event.key):
        kind = DECISION_REJECT if event.kind == EVENT_BEFORE_REQUEST else DECISION_IGNORE
        return dict(states), CircuitDecision(
            kind, "protected_route_mismatch", PHASE_INVALID
        )

    return handler(states, event, states.get(event.key, CircuitState()), config)


def circuit_snapshot(states):
    """Return a deterministic serialization order for golden-vector tests."""
    return tuple(
        CircuitSnapshot(key, states[key])
        for key in sorted(states)
    )

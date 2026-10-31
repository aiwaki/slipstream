"""Rejected traffic and stale results must not renew inactive circuits."""

from route_circuit import (
    CircuitConfig,
    CircuitEvent,
    RouteCircuitKey,
    DECISION_ALLOW,
    DECISION_IGNORE,
    DECISION_REJECT,
    EVENT_BEFORE_REQUEST,
    EVENT_RECORD_FAILURE,
    EVENT_RECORD_SUCCESS,
)
from route_circuit_registry import RouteCircuitRegistry, RouteCircuitRegistryConfig


def test_rejected_retries_do_not_extend_abandoned_half_open_permit():
    registry = RouteCircuitRegistry(
        CircuitConfig(2, 1000, 1, 1), RouteCircuitRegistryConfig(8, 5000)
    )
    key = RouteCircuitKey("openai", "geo_exit", "geph")
    for at in (0, 1):
        registry.apply(CircuitEvent(EVENT_RECORD_FAILURE, key, at))
    admitted = registry.apply(CircuitEvent(EVENT_BEFORE_REQUEST, key, 1001))
    assert admitted.kind == DECISION_ALLOW
    assert admitted.reason == "half_open_probe"
    # Cancellation loses the admitted result. Denied retries are not activity.
    for at in range(2000, 6001, 1000):
        assert registry.apply(CircuitEvent(EVENT_BEFORE_REQUEST, key, at)).kind == DECISION_REJECT
    assert registry.snapshot()[0].last_touched_ms == 1001
    recovered = registry.apply(CircuitEvent(EVENT_BEFORE_REQUEST, key, 6001))
    assert recovered.kind == DECISION_ALLOW
    assert recovered.reason == "closed"


def test_ignored_completion_does_not_renew_open_circuit():
    registry = RouteCircuitRegistry(
        CircuitConfig(2, 1000, 1, 1), RouteCircuitRegistryConfig(8, 5000)
    )
    key = RouteCircuitKey("openai", "geo_exit", "geph")
    for at in (0, 1):
        registry.apply(CircuitEvent(EVENT_RECORD_FAILURE, key, at))
    ignored = registry.apply(CircuitEvent(EVENT_RECORD_SUCCESS, key, 100))
    assert ignored.kind == DECISION_IGNORE
    assert ignored.reason == "stale_completion"
    assert registry.snapshot()[0].last_touched_ms == 1
    recovered = registry.apply(CircuitEvent(EVENT_BEFORE_REQUEST, key, 5001))
    assert recovered.kind == DECISION_ALLOW
    assert recovered.reason == "closed"

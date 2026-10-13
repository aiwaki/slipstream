"""Denied traffic cannot keep an abandoned half-open permit alive forever."""

from route_circuit import (
    CircuitConfig,
    CircuitEvent,
    RouteCircuitKey,
    DECISION_ALLOW,
    DECISION_REJECT,
    EVENT_BEFORE_REQUEST,
    EVENT_RECORD_FAILURE,
)
from route_circuit_registry import RouteCircuitRegistry, RouteCircuitRegistryConfig
import pytest


def test_rejected_retries_do_not_extend_abandoned_half_open_permit():
    config = CircuitConfig(2, 1000, 1, 1)
    registry = RouteCircuitRegistry(config, RouteCircuitRegistryConfig(8, 5000))
    key = RouteCircuitKey('openai', 'geo_exit', 'geph')
    for at in (0, 1):
        registry.apply(CircuitEvent(EVENT_RECORD_FAILURE, key, at))
    admitted = registry.apply(CircuitEvent(EVENT_BEFORE_REQUEST, key, 1001))
    assert admitted.kind == DECISION_ALLOW
    assert admitted.reason == 'half_open_probe'
    # The admitted socket was cancelled before result publication. Repeated
    # caller retries do not constitute backend activity or proof of liveness.
    for at in range(2000, 6001, 1000):
        assert registry.apply(CircuitEvent(EVENT_BEFORE_REQUEST, key, at)).kind == DECISION_REJECT
    assert registry.snapshot()[0].last_touched_ms == 1001
    recovered = registry.apply(CircuitEvent(EVENT_BEFORE_REQUEST, key, 6001))
    assert recovered.kind == DECISION_ALLOW
    assert recovered.reason == 'closed'


def owned_registry(*, max_entries=8):
    return RouteCircuitRegistry(CircuitConfig(2, 1000, 2, 2),
                                RouteCircuitRegistryConfig(max_entries, 5000))


def open_circuit(registry, key, at=0):
    for now in (at, at + 1):
        registry.apply(CircuitEvent(EVENT_RECORD_FAILURE, key, now))


def test_owned_half_open_slots_release_independently_without_erasing_successes():
    registry = owned_registry()
    key = RouteCircuitKey('openai', 'geo_exit', 'geph')
    open_circuit(registry, key)
    _, first = registry.before_request_owned(key, 1001)
    _, second = registry.before_request_owned(key, 1002)
    assert registry.before_request_owned(key, 1003)[0].kind == DECISION_REJECT
    registry.complete_owned(first, True, 1004)
    assert registry.snapshot()[0].state.half_open_successes == 1
    assert registry.abandon_owned(second)
    assert registry.snapshot()[0].state.half_open_in_flight == 0
    assert not registry.abandon_owned(second)
    assert registry.complete_owned(second, False, 1005) is None
    _, third = registry.before_request_owned(key, 1006)
    registry.complete_owned(third, True, 1007)
    assert not registry.snapshot()


@pytest.mark.parametrize('ending', ['reopen', 'clear', 'expire', 'evict'])
def test_old_permit_cannot_release_or_complete_successor_epoch(ending):
    registry = owned_registry(max_entries=1)
    key = RouteCircuitKey('openai', 'geo_exit', 'geph')
    open_circuit(registry, key)
    _, old = registry.before_request_owned(key, 1001)
    if ending == 'reopen':
        _, peer = registry.before_request_owned(key, 1002)
        registry.complete_owned(peer, False, 1003)
        next_at = 2003
    elif ending == 'clear':
        registry.clear()
        open_circuit(registry, key, 1002)
        next_at = 2003
    elif ending == 'expire':
        registry.before_request_owned(key, 6001)
        open_circuit(registry, key, 6002)
        next_at = 7003
    else:
        other = RouteCircuitKey('other', 'geo_exit', 'geph')
        open_circuit(registry, other, 1002)
        open_circuit(registry, key, 1004)
        next_at = 2005
    _, successor = registry.before_request_owned(key, next_at)
    assert not registry.abandon_owned(old)
    assert registry.complete_owned(old, True, next_at + 1) is None
    assert registry.snapshot()[0].state.half_open_in_flight == 1
    assert registry.abandon_owned(successor)
    assert registry.snapshot()[0].state.half_open_in_flight == 0


def test_foreign_permit_is_not_consumed_and_closed_epoch_storage_is_bounded():
    registry = owned_registry(max_entries=2)
    foreign = owned_registry()
    key = RouteCircuitKey('openai', 'geo_exit', 'geph')
    _, permit = registry.before_request_owned(key, 0)
    assert not foreign.abandon_owned(permit)
    assert registry.abandon_owned(permit)
    for i in range(10):
        registry.before_request_owned(RouteCircuitKey(str(i), 'geo_exit', 'geph'), i)
    assert len(registry._owned_epochs) == 2


def test_owned_epoch_capacity_eviction_cannot_orphan_half_open_slot():
    registry = RouteCircuitRegistry(
        CircuitConfig(2, 1000, 1, 1), RouteCircuitRegistryConfig(1, 5000))
    key = RouteCircuitKey('openai', 'geo_exit', 'geph')
    other = RouteCircuitKey('other', 'geo_exit', 'geph')
    open_circuit(registry, key)
    _, active = registry.before_request_owned(key, 1001)
    registry.before_request_owned(other, 1002)
    # Either retain the active epoch or forget its whole circuit. Forgetting
    # only the epoch makes this cancellation unable to return its only slot.
    registry.abandon_owned(active)
    assert registry.before_request_owned(key, 1003)[0].kind == DECISION_ALLOW


def test_partial_half_open_success_keeps_peer_permit_releasable_past_old_epoch_ttl():
    registry = owned_registry()
    key = RouteCircuitKey('openai', 'geo_exit', 'geph')
    open_circuit(registry, key)
    _, first = registry.before_request_owned(key, 1001)
    _, second = registry.before_request_owned(key, 1002)
    registry.complete_owned(first, True, 5000)
    assert registry.snapshot()[0].state.half_open_successes == 1
    # State remains live until 10000 because of the accepted success, even
    # though the last admission's independent epoch timestamp expires at 6002.
    registry.complete_owned(second, True, 6500)
    # A valid completion must recover or expiry must forget the whole circuit;
    # neither outcome may leave a slot whose completion authority was erased.
    assert not registry.snapshot()

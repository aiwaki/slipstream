"""Bounded runtime storage for the frozen route-circuit v1 reducer."""

from collections import OrderedDict
from dataclasses import dataclass, field, replace
import threading
from typing import Optional

from route_circuit import (
    DECISION_ALLOW,
    DECISION_IGNORE,
    DECISION_RECORD,
    EVENT_BEFORE_REQUEST,
    EVENT_RECORD_FAILURE,
    EVENT_RECORD_SUCCESS,
    PHASE_HALF_OPEN,
    CircuitEvent,
    CircuitDecision,
    CircuitState,
    RouteCircuitKey,
    reduce_route_circuit,
)


@dataclass(frozen=True)
class RouteCircuitRegistryConfig:
    max_entries: int
    idle_ttl_ms: int


@dataclass(frozen=True)
class RouteCircuitRegistrySnapshot:
    key: RouteCircuitKey
    state: CircuitState
    last_touched_ms: int


@dataclass(eq=False)
class _OwnedCircuitPermit:
    registry: object = field(repr=False)
    key: RouteCircuitKey
    epoch: object = field(repr=False)
    consumed: bool = False


def _validate_registry_config(registry_config, circuit_config):
    if registry_config.max_entries < 1:
        raise ValueError("max_entries must be positive")
    if registry_config.idle_ttl_ms < circuit_config.open_duration_ms:
        raise ValueError("idle_ttl_ms must cover open_duration_ms")


class RouteCircuitRegistry:
    """Thread-safe, deterministic TTL/LRU wrapper around route-circuit v1."""

    def __init__(self, circuit_config, registry_config):
        _validate_registry_config(registry_config, circuit_config)
        self._circuit_config = circuit_config
        self._registry_config = registry_config
        self._states = {}
        self._last_touched = {}
        self._last_event_ms: Optional[int] = None
        self._lock = threading.RLock()
        self._permit_owner = object()
        self._owned_epochs = OrderedDict()

    def _prune_idle(self, now_ms):
        expired = [
            key
            for key, touched_at in self._last_touched.items()
            if touched_at + self._registry_config.idle_ttl_ms <= now_ms
        ]
        for key in sorted(expired):
            self._states.pop(key, None)
            self._last_touched.pop(key, None)
            self._owned_epochs.pop(key, None)

    def _enforce_capacity(self, current_key):
        while len(self._states) > self._registry_config.max_entries:
            candidates = [key for key in self._states if key != current_key]
            if not candidates:
                candidates = list(self._states)
            evicted = min(
                candidates,
                key=lambda key: (self._last_touched[key], key),
            )
            self._states.pop(evicted, None)
            self._last_touched.pop(evicted, None)
            self._owned_epochs.pop(evicted, None)

    def _prune_owned_epochs(self, now_ms):
        for key, (_, touched) in tuple(self._owned_epochs.items()):
            if touched + self._registry_config.idle_ttl_ms <= now_ms:
                self._owned_epochs.pop(key, None)
                self._states.pop(key, None)
                self._last_touched.pop(key, None)
        while len(self._owned_epochs) > self._registry_config.max_entries:
            key, _ = self._owned_epochs.popitem(last=False)
            # Ownership and suppression must be evicted together. Otherwise a
            # live half-open slot loses the only token able to release it.
            self._states.pop(key, None)
            self._last_touched.pop(key, None)

    def _consume_owned_permit(self, permit):
        if (type(permit) is not _OwnedCircuitPermit
                or permit.registry is not self._permit_owner or permit.consumed):
            return False
        permit.consumed = True
        current = self._owned_epochs.get(permit.key)
        return current is not None and current[0] is permit.epoch

    def before_request_owned(self, key, now_ms):
        """Issue one private completion permit, outside the frozen v1 reducer."""
        with self._lock:
            decision = self.apply(CircuitEvent(EVENT_BEFORE_REQUEST, key, now_ms))
            if decision.kind != DECISION_ALLOW:
                return decision, None
            self._prune_owned_epochs(now_ms)
            epoch = self._owned_epochs.get(key, (object(), now_ms))[0]
            self._owned_epochs[key] = (epoch, now_ms)
            self._owned_epochs.move_to_end(key)
            self._prune_owned_epochs(now_ms)
            return decision, _OwnedCircuitPermit(self._permit_owner, key, epoch)

    def complete_owned(self, permit, ok, now_ms):
        """Ignore old/foreign/duplicate completions after a circuit epoch ends."""
        with self._lock:
            if now_ms < 0 or (self._last_event_ms is not None and now_ms < self._last_event_ms):
                raise ValueError('route-circuit registry time moved backwards')
            self._prune_idle(now_ms)
            self._prune_owned_epochs(now_ms)
            if not self._consume_owned_permit(permit):
                return None
            return self.apply(CircuitEvent(
                EVENT_RECORD_SUCCESS if ok else EVENT_RECORD_FAILURE, permit.key, now_ms))

    def abandon_owned(self, permit):
        """Release this caller's probe slot without inventing a backend failure."""
        with self._lock:
            if not self._consume_owned_permit(permit):
                return False
            state = self._states.get(permit.key)
            if state is not None and state.phase == PHASE_HALF_OPEN and state.half_open_in_flight:
                self._states[permit.key] = replace(
                    state, half_open_in_flight=state.half_open_in_flight - 1)
            return True

    def record_unowned(self, event):
        """Unadmitted payload evidence cannot finish an owned half-open probe."""
        if event.kind not in (EVENT_RECORD_SUCCESS, EVENT_RECORD_FAILURE):
            raise ValueError('record_unowned requires a completion event')
        with self._lock:
            if event.now_ms < 0 or (self._last_event_ms is not None
                                   and event.now_ms < self._last_event_ms):
                raise ValueError('route-circuit registry time moved backwards')
            self._prune_idle(event.now_ms)
            self._prune_owned_epochs(event.now_ms)
            state = self._states.get(event.key)
            if state is not None and state.phase == PHASE_HALF_OPEN:
                self._last_event_ms = event.now_ms
                return CircuitDecision(DECISION_IGNORE, 'unowned_completion', PHASE_HALF_OPEN)
            return self.apply(event)

    def apply(self, event):
        with self._lock:
            if event.now_ms < 0:
                raise ValueError("now_ms must not be negative")
            if self._last_event_ms is not None and event.now_ms < self._last_event_ms:
                raise ValueError("route-circuit registry time moved backwards")

            self._prune_idle(event.now_ms)
            previous_phase = self._states.get(event.key, CircuitState()).phase
            self._states, decision = reduce_route_circuit(
                self._states,
                event,
                self._circuit_config,
            )
            if self._states.get(event.key, CircuitState()).phase != previous_phase:
                self._owned_epochs.pop(event.key, None)
            epoch = self._owned_epochs.get(event.key)
            if epoch is not None and decision.kind in (DECISION_ALLOW, DECISION_RECORD):
                # A partial half-open success keeps remaining peer permits
                # alive for exactly as long as their circuit state remains.
                self._owned_epochs[event.key] = (epoch[0], event.now_ms)
                self._owned_epochs.move_to_end(event.key)
            if event.key in self._states:
                # Rejected retries and stale results do not represent backend
                # activity. Otherwise an abandoned half-open permit survives
                # forever as long as callers keep retrying the denied route.
                if decision.kind in (DECISION_ALLOW, DECISION_RECORD):
                    self._last_touched[event.key] = event.now_ms
            else:
                self._last_touched.pop(event.key, None)
            self._enforce_capacity(event.key)
            self._last_event_ms = event.now_ms
            return decision

    def clear(self):
        with self._lock:
            self._states.clear()
            self._last_touched.clear()
            self._last_event_ms = None
            self._owned_epochs.clear()

    def snapshot(self):
        with self._lock:
            return tuple(
                RouteCircuitRegistrySnapshot(
                    key=key,
                    state=self._states[key],
                    last_touched_ms=self._last_touched[key],
                )
                for key in sorted(self._states)
            )

    def __len__(self):
        with self._lock:
            return len(self._states)

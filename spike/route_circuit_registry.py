"""Bounded runtime storage for the frozen route-circuit v1 reducer."""

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
    PHASE_CLOSED,
    PHASE_HALF_OPEN,
    CircuitDecision,
    CircuitEvent,
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
class _AttemptPermit:
    owner: object = field(repr=False)
    key: RouteCircuitKey
    generation: object = field(repr=False)
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
        self._generations = {}

    def _forget(self, key):
        self._states.pop(key, None)
        self._last_touched.pop(key, None)
        self._generations.pop(key, None)

    def _validate_time(self, now_ms):
        if now_ms < 0:
            raise ValueError("now_ms must not be negative")
        if self._last_event_ms is not None and now_ms < self._last_event_ms:
            raise ValueError("route-circuit registry time moved backwards")

    def _prune_idle(self, now_ms):
        expired = {
            key
            for key, touched_at in self._last_touched.items()
            if touched_at + self._registry_config.idle_ttl_ms <= now_ms
        }
        expired.update(
            key for key, (_, touched_at) in self._generations.items()
            if touched_at + self._registry_config.idle_ttl_ms <= now_ms
        )
        for key in sorted(expired):
            self._forget(key)

    def _enforce_capacity(self, current_key):
        while len(self._states) > self._registry_config.max_entries:
            candidates = [key for key in self._states if key != current_key]
            if not candidates:
                candidates = list(self._states)
            evicted = min(
                candidates,
                key=lambda key: (self._last_touched[key], key),
            )
            self._forget(evicted)
        while len(self._generations) > self._registry_config.max_entries:
            candidates = [key for key in self._generations if key != current_key]
            evicted = min(candidates, key=lambda key: (self._generations[key][1], key))
            # Forget ownership and suppression together, never orphan a slot.
            self._forget(evicted)

    def before_request_owned(self, key, now_ms):
        """Bind an admitted attempt to the current generation of this key."""
        with self._lock:
            decision = self.apply(CircuitEvent(EVENT_BEFORE_REQUEST, key, now_ms))
            if decision.kind != DECISION_ALLOW:
                return decision, None
            generation = self._generations.get(key, (object(), now_ms))[0]
            self._generations[key] = (generation, now_ms)
            self._enforce_capacity(key)
            return decision, _AttemptPermit(self._permit_owner, key, generation)

    def begin_closed_observation(self, key, now_ms):
        """Observe an independently authorized replay without taking a probe."""
        with self._lock:
            self._validate_time(now_ms)
            self._prune_idle(now_ms)
            if self._states.get(key, CircuitState()).phase != PHASE_CLOSED:
                self._last_event_ms = now_ms
                return None
            return self.before_request_owned(key, now_ms)[1]

    def _consume_permit(self, permit):
        if (type(permit) is not _AttemptPermit
                or permit.owner is not self._permit_owner or permit.consumed):
            return False
        permit.consumed = True
        generation = self._generations.get(permit.key)
        return generation is not None and generation[0] is permit.generation

    def complete_owned(self, permit, ok, now_ms):
        with self._lock:
            self._validate_time(now_ms)
            self._prune_idle(now_ms)
            if not self._consume_permit(permit):
                self._last_event_ms = now_ms
                return None
            return self.apply(CircuitEvent(
                EVENT_RECORD_SUCCESS if ok else EVENT_RECORD_FAILURE,
                permit.key, now_ms,
            ))

    def abandon_owned(self, permit):
        """Release only this attempt's slot, without a synthetic outcome."""
        with self._lock:
            if not self._consume_permit(permit):
                return False
            state = self._states.get(permit.key)
            if state is not None and state.phase == PHASE_HALF_OPEN and state.half_open_in_flight:
                self._states[permit.key] = replace(
                    state, half_open_in_flight=state.half_open_in_flight - 1,
                )
            return True

    def record_unowned(self, event):
        """Keep independent health evidence from completing another probe."""
        if event.kind not in (EVENT_RECORD_SUCCESS, EVENT_RECORD_FAILURE):
            raise ValueError("record_unowned requires a completion event")
        with self._lock:
            self._validate_time(event.now_ms)
            self._prune_idle(event.now_ms)
            state = self._states.get(event.key)
            if state is not None and state.phase == PHASE_HALF_OPEN:
                self._last_event_ms = event.now_ms
                return CircuitDecision(DECISION_IGNORE, "unowned_completion", PHASE_HALF_OPEN)
            return self.apply(event)

    def apply(self, event):
        with self._lock:
            self._validate_time(event.now_ms)
            self._prune_idle(event.now_ms)
            previous_phase = self._states.get(event.key, CircuitState()).phase
            self._states, decision = reduce_route_circuit(
                self._states,
                event,
                self._circuit_config,
            )
            if self._states.get(event.key, CircuitState()).phase != previous_phase:
                self._generations.pop(event.key, None)
            generation = self._generations.get(event.key)
            if generation is not None and decision.kind in (DECISION_ALLOW, DECISION_RECORD):
                self._generations[event.key] = (generation[0], event.now_ms)
            if event.key in self._states:
                # Denied retries and stale results are not backend activity.
                # They must not keep an abandoned half-open permit alive.
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
            self._generations.clear()

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

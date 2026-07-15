"""Bounded runtime storage for the frozen route-circuit v1 reducer."""

from dataclasses import dataclass
import threading
from typing import Optional

from route_circuit import (
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

    def _prune_idle(self, now_ms):
        expired = [
            key
            for key, touched_at in self._last_touched.items()
            if touched_at + self._registry_config.idle_ttl_ms <= now_ms
        ]
        for key in sorted(expired):
            self._states.pop(key, None)
            self._last_touched.pop(key, None)

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

    def apply(self, event):
        with self._lock:
            if event.now_ms < 0:
                raise ValueError("now_ms must not be negative")
            if self._last_event_ms is not None and event.now_ms < self._last_event_ms:
                raise ValueError("route-circuit registry time moved backwards")

            self._prune_idle(event.now_ms)
            self._states, decision = reduce_route_circuit(
                self._states,
                event,
                self._circuit_config,
            )
            if event.key in self._states:
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

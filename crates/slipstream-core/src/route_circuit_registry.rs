//! Bounded runtime storage for the frozen route-circuit v1 reducer.

use crate::route_circuit::{
    reduce_route_circuit, CircuitConfig, CircuitDecision, CircuitEvent, CircuitState,
    CircuitStates, RouteCircuitKey,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteCircuitRegistryConfig {
    pub max_entries: usize,
    pub idle_ttl_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteCircuitRegistrySnapshot {
    pub key: RouteCircuitKey,
    pub state: CircuitState,
    pub last_touched_ms: u64,
}

#[derive(Clone, Debug)]
pub struct RouteCircuitRegistry {
    circuit_config: CircuitConfig,
    registry_config: RouteCircuitRegistryConfig,
    states: CircuitStates,
    last_touched: BTreeMap<RouteCircuitKey, u64>,
    last_event_ms: Option<u64>,
}

impl RouteCircuitRegistry {
    pub fn new(
        circuit_config: CircuitConfig,
        registry_config: RouteCircuitRegistryConfig,
    ) -> Result<Self, String> {
        if registry_config.max_entries < 1 {
            return Err("max_entries must be positive".into());
        }
        if registry_config.idle_ttl_ms < circuit_config.open_duration_ms {
            return Err("idle_ttl_ms must cover open_duration_ms".into());
        }
        Ok(Self {
            circuit_config,
            registry_config,
            states: CircuitStates::new(),
            last_touched: BTreeMap::new(),
            last_event_ms: None,
        })
    }

    fn prune_idle(&mut self, now_ms: u64) {
        let expired: Vec<RouteCircuitKey> = self
            .last_touched
            .iter()
            .filter(|(_, touched_at)| {
                touched_at.saturating_add(self.registry_config.idle_ttl_ms) <= now_ms
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.states.remove(&key);
            self.last_touched.remove(&key);
        }
    }

    fn enforce_capacity(&mut self, current_key: &RouteCircuitKey) {
        while self.states.len() > self.registry_config.max_entries {
            let mut candidates: Vec<&RouteCircuitKey> = self
                .states
                .keys()
                .filter(|key| *key != current_key)
                .collect();
            if candidates.is_empty() {
                candidates.extend(self.states.keys());
            }
            let evicted = candidates
                .into_iter()
                .min_by_key(|key| (self.last_touched.get(*key).copied().unwrap_or(0), *key))
                .expect("over-capacity registry must contain an entry")
                .clone();
            self.states.remove(&evicted);
            self.last_touched.remove(&evicted);
        }
    }

    pub fn apply(&mut self, event: &CircuitEvent) -> Result<CircuitDecision, String> {
        if self
            .last_event_ms
            .is_some_and(|last_event_ms| event.now_ms < last_event_ms)
        {
            return Err("route-circuit registry time moved backwards".into());
        }

        self.prune_idle(event.now_ms);
        let (states, decision) = reduce_route_circuit(&self.states, event, &self.circuit_config)?;
        self.states = states;
        if self.states.contains_key(&event.key) {
            self.last_touched.insert(event.key.clone(), event.now_ms);
        } else {
            self.last_touched.remove(&event.key);
        }
        self.enforce_capacity(&event.key);
        self.last_event_ms = Some(event.now_ms);
        Ok(decision)
    }

    pub fn clear(&mut self) {
        self.states.clear();
        self.last_touched.clear();
        self.last_event_ms = None;
    }

    pub fn snapshot(&self) -> Vec<RouteCircuitRegistrySnapshot> {
        self.states
            .iter()
            .map(|(key, state)| RouteCircuitRegistrySnapshot {
                key: key.clone(),
                state: state.clone(),
                last_touched_ms: self.last_touched[key],
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

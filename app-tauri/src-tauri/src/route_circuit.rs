//! Pure route-scoped circuit breaker with no timers or network side effects.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RouteCircuitKey {
    pub service_group: String,
    pub route_class: String,
    pub backend_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitConfig {
    pub failure_threshold: u32,
    pub open_duration_ms: u64,
    pub half_open_max_in_flight: u32,
    pub success_threshold: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitPhase {
    Closed,
    Open,
    HalfOpen,
    Invalid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitState {
    pub phase: CircuitPhase,
    pub consecutive_failures: u32,
    pub opened_at_ms: Option<u64>,
    pub half_open_in_flight: u32,
    pub half_open_successes: u32,
}

impl Default for CircuitState {
    fn default() -> Self {
        Self {
            phase: CircuitPhase::Closed,
            consecutive_failures: 0,
            opened_at_ms: None,
            half_open_in_flight: 0,
            half_open_successes: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitEventKind {
    BeforeRequest,
    RecordSuccess,
    RecordFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitEvent {
    pub kind: CircuitEventKind,
    pub key: RouteCircuitKey,
    pub now_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitDecisionKind {
    Allow,
    Reject,
    Record,
    Ignore,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitDecision {
    pub kind: CircuitDecisionKind,
    pub reason: String,
    pub phase: CircuitPhase,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitSnapshot {
    pub key: RouteCircuitKey,
    pub state: CircuitState,
}

pub type CircuitStates = BTreeMap<RouteCircuitKey, CircuitState>;

fn decision(
    kind: CircuitDecisionKind,
    reason: impl Into<String>,
    phase: CircuitPhase,
) -> CircuitDecision {
    CircuitDecision {
        kind,
        reason: reason.into(),
        phase,
    }
}

fn validate_config(config: &CircuitConfig) -> Result<(), String> {
    if config.failure_threshold < 1 {
        return Err("failure_threshold must be positive".into());
    }
    if config.half_open_max_in_flight < 1 {
        return Err("half_open_max_in_flight must be positive".into());
    }
    if config.success_threshold < 1 {
        return Err("success_threshold must be positive".into());
    }
    Ok(())
}

fn protected_route_mismatch(key: &RouteCircuitKey) -> bool {
    matches!(key.service_group.as_str(), "discord" | "youtube_video")
        && (key.route_class != "local_bypass" || key.backend_id == "geph")
}

fn store_state(
    states: &CircuitStates,
    key: &RouteCircuitKey,
    state: CircuitState,
) -> CircuitStates {
    let mut updated = states.clone();
    if state == CircuitState::default() {
        updated.remove(key);
    } else {
        updated.insert(key.clone(), state);
    }
    updated
}

fn before_request(
    states: &CircuitStates,
    event: &CircuitEvent,
    mut state: CircuitState,
    config: &CircuitConfig,
) -> Result<(CircuitStates, CircuitDecision), String> {
    if state.phase == CircuitPhase::Closed {
        return Ok((
            states.clone(),
            decision(CircuitDecisionKind::Allow, "closed", CircuitPhase::Closed),
        ));
    }
    if state.phase == CircuitPhase::Open {
        let opened_at_ms = state
            .opened_at_ms
            .ok_or_else(|| "open circuit requires opened_at_ms".to_string())?;
        if event.now_ms < opened_at_ms.saturating_add(config.open_duration_ms) {
            return Ok((
                states.clone(),
                decision(CircuitDecisionKind::Reject, "open", CircuitPhase::Open),
            ));
        }
        state = CircuitState {
            phase: CircuitPhase::HalfOpen,
            ..CircuitState::default()
        };
    }
    if state.phase != CircuitPhase::HalfOpen {
        return Err("unknown circuit phase".into());
    }
    if state.half_open_in_flight >= config.half_open_max_in_flight {
        return Ok((
            store_state(states, &event.key, state),
            decision(
                CircuitDecisionKind::Reject,
                "half_open_limit",
                CircuitPhase::HalfOpen,
            ),
        ));
    }
    state.half_open_in_flight += 1;
    Ok((
        store_state(states, &event.key, state),
        decision(
            CircuitDecisionKind::Allow,
            "half_open_probe",
            CircuitPhase::HalfOpen,
        ),
    ))
}

fn record_success(
    states: &CircuitStates,
    event: &CircuitEvent,
    mut state: CircuitState,
    config: &CircuitConfig,
) -> Result<(CircuitStates, CircuitDecision), String> {
    if state.phase == CircuitPhase::Open {
        return Ok((
            states.clone(),
            decision(
                CircuitDecisionKind::Ignore,
                "stale_completion",
                CircuitPhase::Open,
            ),
        ));
    }
    if state.phase != CircuitPhase::HalfOpen {
        return Ok((
            store_state(states, &event.key, CircuitState::default()),
            decision(
                CircuitDecisionKind::Record,
                "success_recorded",
                CircuitPhase::Closed,
            ),
        ));
    }
    if state.half_open_in_flight < 1 {
        return Ok((
            states.clone(),
            decision(
                CircuitDecisionKind::Ignore,
                "stale_completion",
                CircuitPhase::HalfOpen,
            ),
        ));
    }

    state.half_open_successes += 1;
    if state.half_open_successes >= config.success_threshold {
        return Ok((
            store_state(states, &event.key, CircuitState::default()),
            decision(
                CircuitDecisionKind::Record,
                "half_open_recovered",
                CircuitPhase::Closed,
            ),
        ));
    }
    state.half_open_in_flight -= 1;
    Ok((
        store_state(states, &event.key, state),
        decision(
            CircuitDecisionKind::Record,
            "success_recorded",
            CircuitPhase::HalfOpen,
        ),
    ))
}

fn record_failure(
    states: &CircuitStates,
    event: &CircuitEvent,
    mut state: CircuitState,
    config: &CircuitConfig,
) -> Result<(CircuitStates, CircuitDecision), String> {
    if state.phase == CircuitPhase::Open {
        return Ok((
            states.clone(),
            decision(
                CircuitDecisionKind::Ignore,
                "stale_completion",
                CircuitPhase::Open,
            ),
        ));
    }
    if state.phase == CircuitPhase::HalfOpen {
        if state.half_open_in_flight < 1 {
            return Ok((
                states.clone(),
                decision(
                    CircuitDecisionKind::Ignore,
                    "stale_completion",
                    CircuitPhase::HalfOpen,
                ),
            ));
        }
        state = CircuitState {
            phase: CircuitPhase::Open,
            consecutive_failures: config.failure_threshold,
            opened_at_ms: Some(event.now_ms),
            half_open_in_flight: 0,
            half_open_successes: 0,
        };
        return Ok((
            store_state(states, &event.key, state),
            decision(
                CircuitDecisionKind::Record,
                "half_open_failure",
                CircuitPhase::Open,
            ),
        ));
    }

    state.consecutive_failures += 1;
    if state.consecutive_failures >= config.failure_threshold {
        state.phase = CircuitPhase::Open;
        state.opened_at_ms = Some(event.now_ms);
        return Ok((
            store_state(states, &event.key, state),
            decision(
                CircuitDecisionKind::Record,
                "threshold_reached",
                CircuitPhase::Open,
            ),
        ));
    }
    Ok((
        store_state(states, &event.key, state),
        decision(
            CircuitDecisionKind::Record,
            "failure_recorded",
            CircuitPhase::Closed,
        ),
    ))
}

pub fn reduce_route_circuit(
    states: &CircuitStates,
    event: &CircuitEvent,
    config: &CircuitConfig,
) -> Result<(CircuitStates, CircuitDecision), String> {
    validate_config(config)?;
    if protected_route_mismatch(&event.key) {
        let kind = if event.kind == CircuitEventKind::BeforeRequest {
            CircuitDecisionKind::Reject
        } else {
            CircuitDecisionKind::Ignore
        };
        return Ok((
            states.clone(),
            decision(kind, "protected_route_mismatch", CircuitPhase::Invalid),
        ));
    }

    let state = states.get(&event.key).cloned().unwrap_or_default();
    match event.kind {
        CircuitEventKind::BeforeRequest => before_request(states, event, state, config),
        CircuitEventKind::RecordSuccess => record_success(states, event, state, config),
        CircuitEventKind::RecordFailure => record_failure(states, event, state, config),
    }
}

pub fn circuit_snapshot(states: &CircuitStates) -> Vec<CircuitSnapshot> {
    states
        .iter()
        .map(|(key, state)| CircuitSnapshot {
            key: key.clone(),
            state: state.clone(),
        })
        .collect()
}

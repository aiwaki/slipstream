//! Pure connection-race orchestration with no DNS, clock, or socket I/O.

use crate::address_attempts::{
    plan_address_attempts, AddressAttempt, AddressAttemptState, AddressCandidate,
    AddressDecisionKind, AddressFamily, AddressPlanContext,
};
use crate::route_circuit::{
    reduce_route_circuit, CircuitConfig, CircuitDecision, CircuitDecisionKind, CircuitEvent,
    CircuitEventKind, CircuitStates, RouteCircuitKey,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionRaceConfig {
    pub timeout_ms: u64,
    pub stagger_ms: u64,
    pub max_concurrent: usize,
    pub preferred_family: AddressFamily,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionRacePhase {
    Resolving,
    Connecting,
    Connected,
    Rejected,
    Failed,
    TimedOut,
    Exhausted,
}

impl ConnectionRacePhase {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Connected | Self::Rejected | Self::Failed | Self::TimedOut | Self::Exhausted
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionRaceState {
    pub key: RouteCircuitKey,
    pub phase: ConnectionRacePhase,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub deadline_at_ms: u64,
    pub candidates: Vec<AddressCandidate>,
    pub attempts: Vec<AddressAttempt>,
    pub winner_candidate_id: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionRaceEventKind {
    Resolved,
    ResolveFailed,
    AttemptSucceeded,
    AttemptFailed,
    Wake,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionRaceEvent {
    pub kind: ConnectionRaceEventKind,
    pub now_ms: u64,
    pub candidate_id: String,
    pub candidates: Vec<AddressCandidate>,
}

impl ConnectionRaceEvent {
    pub fn wake(now_ms: u64) -> Self {
        Self {
            kind: ConnectionRaceEventKind::Wake,
            now_ms,
            candidate_id: String::new(),
            candidates: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionRaceCommandKind {
    Resolve,
    Start,
    Cancel,
    Wake,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionRaceCommand {
    pub kind: ConnectionRaceCommandKind,
    pub candidate_id: String,
    pub at_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionRaceTransition {
    pub state: ConnectionRaceState,
    pub circuit_states: CircuitStates,
    pub commands: Vec<ConnectionRaceCommand>,
    pub circuit_decisions: Vec<CircuitDecision>,
}

fn command(
    kind: ConnectionRaceCommandKind,
    candidate_id: impl Into<String>,
    at_ms: Option<u64>,
) -> ConnectionRaceCommand {
    ConnectionRaceCommand {
        kind,
        candidate_id: candidate_id.into(),
        at_ms,
    }
}

fn validate_config(config: &ConnectionRaceConfig) -> Result<(), String> {
    if config.timeout_ms < 1 {
        return Err("timeout_ms must be positive".into());
    }
    if config.max_concurrent < 1 {
        return Err("max_concurrent must be positive".into());
    }
    Ok(())
}

fn address_context(
    state: &ConnectionRaceState,
    config: &ConnectionRaceConfig,
    now_ms: u64,
) -> AddressPlanContext {
    AddressPlanContext {
        now_ms,
        started_at_ms: state.started_at_ms,
        deadline_at_ms: state.deadline_at_ms,
        stagger_ms: config.stagger_ms,
        max_concurrent: config.max_concurrent,
        preferred_family: config.preferred_family,
    }
}

fn record_terminal(
    circuit_states: &CircuitStates,
    mut state: ConnectionRaceState,
    circuit_config: &CircuitConfig,
    now_ms: u64,
    phase: ConnectionRacePhase,
    reason: &str,
    winner_candidate_id: &str,
) -> Result<(ConnectionRaceState, CircuitStates, CircuitDecision), String> {
    let kind = if phase == ConnectionRacePhase::Connected {
        CircuitEventKind::RecordSuccess
    } else {
        CircuitEventKind::RecordFailure
    };
    let (updated_circuits, decision) = reduce_route_circuit(
        circuit_states,
        &CircuitEvent {
            kind,
            key: state.key.clone(),
            now_ms,
        },
        circuit_config,
    )?;
    state.phase = phase;
    state.updated_at_ms = now_ms;
    state.winner_candidate_id = winner_candidate_id.to_string();
    state.reason = reason.to_string();
    Ok((state, updated_circuits, decision))
}

fn cancel_attempts(state: &mut ConnectionRaceState, candidate_ids: &[String], now_ms: u64) {
    for attempt in &mut state.attempts {
        if candidate_ids.contains(&attempt.candidate_id)
            && attempt.state == AddressAttemptState::Running
        {
            attempt.state = AddressAttemptState::Cancelled;
            attempt.completed_at_ms = Some(now_ms);
        }
    }
}

fn settle(
    circuit_states: &CircuitStates,
    mut state: ConnectionRaceState,
    config: &ConnectionRaceConfig,
    circuit_config: &CircuitConfig,
    now_ms: u64,
) -> Result<ConnectionRaceTransition, String> {
    let mut commands = Vec::new();
    loop {
        let result = plan_address_attempts(
            &state.candidates,
            &state.attempts,
            &address_context(&state, config, now_ms),
        )?;
        match result.decision.kind {
            AddressDecisionKind::Start => {
                let candidate_id = result.decision.candidate_id;
                state.updated_at_ms = now_ms;
                state.attempts.push(AddressAttempt {
                    candidate_id: candidate_id.clone(),
                    state: AddressAttemptState::Running,
                    started_at_ms: now_ms,
                    completed_at_ms: None,
                });
                commands.push(command(
                    ConnectionRaceCommandKind::Start,
                    candidate_id,
                    None,
                ));
            }
            AddressDecisionKind::Wait => {
                commands.push(command(
                    ConnectionRaceCommandKind::Wake,
                    "",
                    result.decision.wake_at_ms,
                ));
                return Ok(ConnectionRaceTransition {
                    state,
                    circuit_states: circuit_states.clone(),
                    commands,
                    circuit_decisions: Vec::new(),
                });
            }
            AddressDecisionKind::Select => {
                cancel_attempts(&mut state, &result.decision.cancel, now_ms);
                commands.extend(result.decision.cancel.iter().map(|candidate_id| {
                    command(
                        ConnectionRaceCommandKind::Cancel,
                        candidate_id.clone(),
                        None,
                    )
                }));
                let (state, circuit_states, decision) = record_terminal(
                    circuit_states,
                    state,
                    circuit_config,
                    now_ms,
                    ConnectionRacePhase::Connected,
                    "connected",
                    &result.decision.candidate_id,
                )?;
                return Ok(ConnectionRaceTransition {
                    state,
                    circuit_states,
                    commands,
                    circuit_decisions: vec![decision],
                });
            }
            AddressDecisionKind::Timeout => {
                cancel_attempts(&mut state, &result.decision.cancel, now_ms);
                commands.extend(result.decision.cancel.iter().map(|candidate_id| {
                    command(
                        ConnectionRaceCommandKind::Cancel,
                        candidate_id.clone(),
                        None,
                    )
                }));
                let (state, circuit_states, decision) = record_terminal(
                    circuit_states,
                    state,
                    circuit_config,
                    now_ms,
                    ConnectionRacePhase::TimedOut,
                    "deadline",
                    "",
                )?;
                return Ok(ConnectionRaceTransition {
                    state,
                    circuit_states,
                    commands,
                    circuit_decisions: vec![decision],
                });
            }
            AddressDecisionKind::Exhausted => {
                let (state, circuit_states, decision) = record_terminal(
                    circuit_states,
                    state,
                    circuit_config,
                    now_ms,
                    ConnectionRacePhase::Exhausted,
                    "all_attempts_failed",
                    "",
                )?;
                return Ok(ConnectionRaceTransition {
                    state,
                    circuit_states,
                    commands,
                    circuit_decisions: vec![decision],
                });
            }
        }
    }
}

pub fn start_connection_race(
    circuit_states: &CircuitStates,
    key: RouteCircuitKey,
    config: &ConnectionRaceConfig,
    circuit_config: &CircuitConfig,
    now_ms: u64,
) -> Result<ConnectionRaceTransition, String> {
    validate_config(config)?;
    let deadline_at_ms = now_ms
        .checked_add(config.timeout_ms)
        .ok_or_else(|| "connection-race deadline overflow".to_string())?;
    let mut state = ConnectionRaceState {
        key: key.clone(),
        phase: ConnectionRacePhase::Resolving,
        started_at_ms: now_ms,
        updated_at_ms: now_ms,
        deadline_at_ms,
        candidates: Vec::new(),
        attempts: Vec::new(),
        winner_candidate_id: String::new(),
        reason: String::new(),
    };
    let (updated_circuits, decision) = reduce_route_circuit(
        circuit_states,
        &CircuitEvent {
            kind: CircuitEventKind::BeforeRequest,
            key,
            now_ms,
        },
        circuit_config,
    )?;
    if decision.kind == CircuitDecisionKind::Reject {
        state.phase = ConnectionRacePhase::Rejected;
        state.reason = decision.reason.clone();
        return Ok(ConnectionRaceTransition {
            state,
            circuit_states: updated_circuits,
            commands: Vec::new(),
            circuit_decisions: vec![decision],
        });
    }
    Ok(ConnectionRaceTransition {
        state,
        circuit_states: updated_circuits,
        commands: vec![
            command(ConnectionRaceCommandKind::Resolve, "", None),
            command(ConnectionRaceCommandKind::Wake, "", Some(deadline_at_ms)),
        ],
        circuit_decisions: vec![decision],
    })
}

fn replace_running_attempt(
    mut state: ConnectionRaceState,
    candidate_id: &str,
    attempt_state: AddressAttemptState,
    now_ms: u64,
) -> Result<ConnectionRaceState, String> {
    let attempt = state
        .attempts
        .iter_mut()
        .find(|attempt| attempt.candidate_id == candidate_id)
        .ok_or_else(|| "attempt completion references an unknown candidate".to_string())?;
    if attempt.state != AddressAttemptState::Running {
        return Err("attempt completion requires a running candidate".into());
    }
    attempt.state = attempt_state;
    attempt.completed_at_ms = Some(now_ms);
    state.updated_at_ms = now_ms;
    Ok(state)
}

fn defer_deadline_tie(
    circuit_states: &CircuitStates,
    mut state: ConnectionRaceState,
    event: &ConnectionRaceEvent,
) -> Option<ConnectionRaceTransition> {
    let has_running_attempt = state
        .attempts
        .iter()
        .any(|attempt| attempt.state == AddressAttemptState::Running);
    if event.kind != ConnectionRaceEventKind::Wake
        || event.now_ms != state.deadline_at_ms
        || !has_running_attempt
    {
        return None;
    }
    let wake_at_ms = event.now_ms.checked_add(1)?;
    state.updated_at_ms = event.now_ms;
    Some(ConnectionRaceTransition {
        state,
        circuit_states: circuit_states.clone(),
        commands: vec![command(
            ConnectionRaceCommandKind::Wake,
            "",
            Some(wake_at_ms),
        )],
        circuit_decisions: Vec::new(),
    })
}

fn advance_resolving(
    circuit_states: &CircuitStates,
    mut state: ConnectionRaceState,
    event: &ConnectionRaceEvent,
    config: &ConnectionRaceConfig,
    circuit_config: &CircuitConfig,
) -> Result<ConnectionRaceTransition, String> {
    match event.kind {
        ConnectionRaceEventKind::Wake if event.now_ms < state.deadline_at_ms => {
            state.updated_at_ms = event.now_ms;
            let deadline_at_ms = state.deadline_at_ms;
            Ok(ConnectionRaceTransition {
                state,
                circuit_states: circuit_states.clone(),
                commands: vec![command(
                    ConnectionRaceCommandKind::Wake,
                    "",
                    Some(deadline_at_ms),
                )],
                circuit_decisions: Vec::new(),
            })
        }
        ConnectionRaceEventKind::Wake => {
            let (state, circuit_states, decision) = record_terminal(
                circuit_states,
                state,
                circuit_config,
                event.now_ms,
                ConnectionRacePhase::TimedOut,
                "resolver_deadline",
                "",
            )?;
            Ok(ConnectionRaceTransition {
                state,
                circuit_states,
                commands: Vec::new(),
                circuit_decisions: vec![decision],
            })
        }
        ConnectionRaceEventKind::ResolveFailed => {
            let (state, circuit_states, decision) = record_terminal(
                circuit_states,
                state,
                circuit_config,
                event.now_ms,
                ConnectionRacePhase::Failed,
                "resolve_failed",
                "",
            )?;
            Ok(ConnectionRaceTransition {
                state,
                circuit_states,
                commands: Vec::new(),
                circuit_decisions: vec![decision],
            })
        }
        ConnectionRaceEventKind::Resolved => {
            state.phase = ConnectionRacePhase::Connecting;
            state.updated_at_ms = event.now_ms;
            state.candidates = event.candidates.clone();
            settle(circuit_states, state, config, circuit_config, event.now_ms)
        }
        _ => Err("resolver phase accepts only resolver events or wake".into()),
    }
}

fn advance_connecting(
    circuit_states: &CircuitStates,
    state: ConnectionRaceState,
    event: &ConnectionRaceEvent,
    config: &ConnectionRaceConfig,
    circuit_config: &CircuitConfig,
) -> Result<ConnectionRaceTransition, String> {
    if let Some(transition) = defer_deadline_tie(circuit_states, state.clone(), event) {
        return Ok(transition);
    }
    if event.kind == ConnectionRaceEventKind::AttemptSucceeded
        && event.now_ms > state.deadline_at_ms
    {
        return settle(circuit_states, state, config, circuit_config, event.now_ms);
    }
    let state = match event.kind {
        ConnectionRaceEventKind::Wake => {
            let mut state = state;
            state.updated_at_ms = event.now_ms;
            state
        }
        ConnectionRaceEventKind::AttemptSucceeded => replace_running_attempt(
            state,
            &event.candidate_id,
            AddressAttemptState::Succeeded,
            event.now_ms,
        )?,
        ConnectionRaceEventKind::AttemptFailed => replace_running_attempt(
            state,
            &event.candidate_id,
            AddressAttemptState::Failed,
            event.now_ms,
        )?,
        _ => return Err("connecting phase accepts only attempt events or wake".into()),
    };
    settle(circuit_states, state, config, circuit_config, event.now_ms)
}

pub fn advance_connection_race(
    circuit_states: &CircuitStates,
    state: ConnectionRaceState,
    event: &ConnectionRaceEvent,
    config: &ConnectionRaceConfig,
    circuit_config: &CircuitConfig,
) -> Result<ConnectionRaceTransition, String> {
    validate_config(config)?;
    if state.phase.is_terminal() {
        return Ok(ConnectionRaceTransition {
            state,
            circuit_states: circuit_states.clone(),
            commands: Vec::new(),
            circuit_decisions: Vec::new(),
        });
    }
    if event.now_ms < state.updated_at_ms {
        return Err("connection-race events must be monotonic".into());
    }
    match state.phase {
        ConnectionRacePhase::Resolving => {
            advance_resolving(circuit_states, state, event, config, circuit_config)
        }
        ConnectionRacePhase::Connecting => {
            advance_connecting(circuit_states, state, event, config, circuit_config)
        }
        _ => Err("unknown connection-race phase".into()),
    }
}

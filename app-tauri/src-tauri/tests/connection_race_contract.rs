use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use slipstream_lib::address_attempts::AddressCandidate;
use slipstream_lib::connection_race::{
    advance_connection_race, start_connection_race, ConnectionRaceCommand,
    ConnectionRaceCommandKind, ConnectionRaceConfig, ConnectionRaceEvent, ConnectionRaceEventKind,
    ConnectionRacePhase, ConnectionRaceTransition,
};
use slipstream_lib::route_circuit::{
    circuit_snapshot, CircuitConfig, CircuitDecision, CircuitStates, RouteCircuitKey,
};
use std::collections::{BTreeMap, BTreeSet};

const CONNECTION_RACE_V1: &str = include_str!("../../../contracts/connection-race-v1.json");

#[derive(Clone, Debug, Deserialize)]
struct Contract {
    schema_version: u64,
    contract: String,
    contract_version: u64,
    race_config: ConnectionRaceConfig,
    circuit_config: CircuitConfig,
    vectors: Vec<Vector>,
}

#[derive(Clone, Debug, Deserialize)]
struct Vector {
    name: String,
    requests: Vec<Request>,
    expected_requests: Value,
    expected_circuit_states: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct Request {
    started_at_ms: u64,
    key: RouteCircuitKey,
    resolver: ResolverScript,
    connector: BTreeMap<String, ConnectorScript>,
}

#[derive(Clone, Debug, Deserialize)]
struct ResolverScript {
    outcome: String,
    delay_ms: u64,
    candidates: Vec<AddressCandidate>,
}

#[derive(Clone, Debug, Deserialize)]
struct ConnectorScript {
    outcome: String,
    delay_ms: u64,
}

struct ScheduledEvent {
    priority: u8,
    serial: u64,
    event: ConnectionRaceEvent,
}

#[derive(Default)]
struct ScriptedConnector {
    starts: Vec<String>,
    cancelled: Vec<String>,
    cancelled_set: BTreeSet<String>,
}

struct ScriptedRuntime<'a> {
    request: &'a Request,
    resolver_calls: u32,
    connector: ScriptedConnector,
    queue: Vec<ScheduledEvent>,
    wake_times: BTreeSet<u64>,
    serial: u64,
}

impl<'a> ScriptedRuntime<'a> {
    fn new(request: &'a Request) -> Self {
        Self {
            request,
            resolver_calls: 0,
            connector: ScriptedConnector::default(),
            queue: Vec::new(),
            wake_times: BTreeSet::new(),
            serial: 0,
        }
    }
}

fn enum_name(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .expect("enum must serialize")
        .as_str()
        .expect("enum must serialize as a string")
        .to_string()
}

fn schedule(
    queue: &mut Vec<ScheduledEvent>,
    serial: &mut u64,
    event: ConnectionRaceEvent,
    priority: u8,
) {
    queue.push(ScheduledEvent {
        priority,
        serial: *serial,
        event,
    });
    *serial += 1;
}

fn apply_commands(
    commands: &[ConnectionRaceCommand],
    now_ms: u64,
    runtime: &mut ScriptedRuntime<'_>,
) -> Result<(), String> {
    for command in commands {
        match command.kind {
            ConnectionRaceCommandKind::Resolve => {
                runtime.resolver_calls += 1;
                let script = &runtime.request.resolver;
                let event_kind = match script.outcome.as_str() {
                    "stall" => continue,
                    "success" => ConnectionRaceEventKind::Resolved,
                    "failure" => ConnectionRaceEventKind::ResolveFailed,
                    other => return Err(format!("unknown resolver outcome {other}")),
                };
                schedule(
                    &mut runtime.queue,
                    &mut runtime.serial,
                    ConnectionRaceEvent {
                        kind: event_kind,
                        now_ms: now_ms + script.delay_ms,
                        candidate_id: String::new(),
                        candidates: script.candidates.clone(),
                    },
                    0,
                );
            }
            ConnectionRaceCommandKind::Start => {
                runtime
                    .connector
                    .starts
                    .push(format!("{}@{now_ms}", command.candidate_id));
                let script = runtime
                    .request
                    .connector
                    .get(&command.candidate_id)
                    .ok_or_else(|| {
                        format!("missing connector script for {}", command.candidate_id)
                    })?;
                let event_kind = match script.outcome.as_str() {
                    "stall" => continue,
                    "success" => ConnectionRaceEventKind::AttemptSucceeded,
                    "failure" | "reset" => ConnectionRaceEventKind::AttemptFailed,
                    other => return Err(format!("unknown connector outcome {other}")),
                };
                schedule(
                    &mut runtime.queue,
                    &mut runtime.serial,
                    ConnectionRaceEvent {
                        kind: event_kind,
                        now_ms: now_ms + script.delay_ms,
                        candidate_id: command.candidate_id.clone(),
                        candidates: Vec::new(),
                    },
                    0,
                );
            }
            ConnectionRaceCommandKind::Cancel => {
                if runtime
                    .connector
                    .cancelled_set
                    .insert(command.candidate_id.clone())
                {
                    runtime
                        .connector
                        .cancelled
                        .push(command.candidate_id.clone());
                }
            }
            ConnectionRaceCommandKind::Wake => {
                let at_ms = command
                    .at_ms
                    .ok_or_else(|| "wake command requires at_ms".to_string())?;
                if runtime.wake_times.insert(at_ms) {
                    schedule(
                        &mut runtime.queue,
                        &mut runtime.serial,
                        ConnectionRaceEvent::wake(at_ms),
                        1,
                    );
                }
            }
        }
    }
    Ok(())
}

fn pop_next(queue: &mut Vec<ScheduledEvent>) -> Option<ScheduledEvent> {
    let index = queue
        .iter()
        .enumerate()
        .min_by_key(|(_, scheduled)| {
            (scheduled.event.now_ms, scheduled.priority, scheduled.serial)
        })?
        .0;
    Some(queue.remove(index))
}

fn request_snapshot(
    transition: &ConnectionRaceTransition,
    resolver_calls: u32,
    connector: &ScriptedConnector,
    circuit_decisions: &[CircuitDecision],
) -> Value {
    let attempts: Vec<String> = transition
        .state
        .attempts
        .iter()
        .map(|attempt| {
            format!(
                "{}:{}:{}:{}",
                attempt.candidate_id,
                enum_name(&attempt.state),
                attempt.started_at_ms,
                attempt
                    .completed_at_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "None".to_string())
            )
        })
        .collect();
    let decisions: Vec<String> = circuit_decisions
        .iter()
        .map(|decision| {
            format!(
                "{}:{}:{}",
                enum_name(&decision.kind),
                decision.reason,
                enum_name(&decision.phase)
            )
        })
        .collect();
    json!({
        "phase": enum_name(&transition.state.phase),
        "reason": transition.state.reason,
        "winner_candidate_id": transition.state.winner_candidate_id,
        "completed_at_ms": transition.state.updated_at_ms,
        "resolver_calls": resolver_calls,
        "starts": connector.starts,
        "cancelled": connector.cancelled,
        "attempts": attempts,
        "circuit_decisions": decisions,
    })
}

fn run_request(
    circuit_states: &CircuitStates,
    request: &Request,
    config: &ConnectionRaceConfig,
    circuit_config: &CircuitConfig,
) -> Result<(CircuitStates, Value), String> {
    let mut runtime = ScriptedRuntime::new(request);
    let mut transition = start_connection_race(
        circuit_states,
        request.key.clone(),
        config,
        circuit_config,
        request.started_at_ms,
    )?;
    let mut circuit_decisions = transition.circuit_decisions.clone();
    apply_commands(&transition.commands, request.started_at_ms, &mut runtime)?;

    for _ in 0..100 {
        if transition.state.phase.is_terminal() {
            break;
        }
        let scheduled = pop_next(&mut runtime.queue)
            .ok_or_else(|| "scripted adapters left an active race without events".to_string())?;
        if scheduled.event.kind == ConnectionRaceEventKind::Wake {
            runtime.wake_times.remove(&scheduled.event.now_ms);
        } else if runtime
            .connector
            .cancelled_set
            .contains(&scheduled.event.candidate_id)
        {
            continue;
        }
        transition = advance_connection_race(
            &transition.circuit_states,
            transition.state,
            &scheduled.event,
            config,
            circuit_config,
        )?;
        circuit_decisions.extend(transition.circuit_decisions.clone());
        apply_commands(&transition.commands, scheduled.event.now_ms, &mut runtime)?;
    }
    if !transition.state.phase.is_terminal() {
        return Err("scripted connection race exceeded the step bound".into());
    }

    let snapshot = request_snapshot(
        &transition,
        runtime.resolver_calls,
        &runtime.connector,
        &circuit_decisions,
    );
    Ok((transition.circuit_states, snapshot))
}

#[test]
fn rust_executes_scripted_connection_race_contract() {
    let contract: Contract = serde_json::from_str(CONNECTION_RACE_V1).expect("contract must parse");
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.contract, "slipstream.connection_race");
    assert_eq!(contract.contract_version, 1);
    let names: BTreeSet<&str> = contract
        .vectors
        .iter()
        .map(|vector| vector.name.as_str())
        .collect();
    assert_eq!(names.len(), contract.vectors.len());

    for vector in &contract.vectors {
        let mut circuit_states = CircuitStates::new();
        let mut requests = Vec::new();
        for request in &vector.requests {
            let (updated, snapshot) = run_request(
                &circuit_states,
                request,
                &contract.race_config,
                &contract.circuit_config,
            )
            .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
            circuit_states = updated;
            requests.push(snapshot);
        }
        assert_eq!(
            Value::Array(requests),
            vector.expected_requests,
            "{} requests",
            vector.name
        );
        assert_eq!(
            serde_json::to_value(circuit_snapshot(&circuit_states)).unwrap(),
            vector.expected_circuit_states,
            "{} circuit states",
            vector.name
        );
    }
}

#[test]
fn terminal_transition_ignores_a_late_connector_event() {
    let contract: Contract = serde_json::from_str(CONNECTION_RACE_V1).unwrap();
    let request = &contract.vectors[1].requests[0];
    let resolved = ConnectionRaceEvent {
        kind: ConnectionRaceEventKind::Resolved,
        now_ms: 0,
        candidate_id: String::new(),
        candidates: request.resolver.candidates.clone(),
    };
    let transition = start_connection_race(
        &CircuitStates::new(),
        request.key.clone(),
        &contract.race_config,
        &contract.circuit_config,
        0,
    )
    .unwrap();
    let transition = advance_connection_race(
        &transition.circuit_states,
        transition.state,
        &resolved,
        &contract.race_config,
        &contract.circuit_config,
    )
    .unwrap();
    let success = ConnectionRaceEvent {
        kind: ConnectionRaceEventKind::AttemptSucceeded,
        now_ms: 100,
        candidate_id: "v6-a".into(),
        candidates: Vec::new(),
    };
    let transition = advance_connection_race(
        &transition.circuit_states,
        transition.state,
        &success,
        &contract.race_config,
        &contract.circuit_config,
    )
    .unwrap();
    assert_eq!(transition.state.phase, ConnectionRacePhase::Connected);

    let late = ConnectionRaceEvent {
        kind: ConnectionRaceEventKind::AttemptSucceeded,
        now_ms: 500,
        candidate_id: "v4-a".into(),
        candidates: Vec::new(),
    };
    let ignored = advance_connection_race(
        &transition.circuit_states,
        transition.state.clone(),
        &late,
        &contract.race_config,
        &contract.circuit_config,
    )
    .unwrap();
    assert_eq!(ignored.state, transition.state);
    assert_eq!(ignored.circuit_states, transition.circuit_states);
    assert!(ignored.commands.is_empty());
    assert!(ignored.circuit_decisions.is_empty());
}

#[test]
fn terminal_attempt_snapshots_never_leave_a_running_candidate() {
    let contract: Contract = serde_json::from_str(CONNECTION_RACE_V1).unwrap();
    for vector in &contract.vectors {
        let mut circuit_states = CircuitStates::new();
        for request in &vector.requests {
            let (updated, snapshot) = run_request(
                &circuit_states,
                request,
                &contract.race_config,
                &contract.circuit_config,
            )
            .unwrap();
            for attempt in snapshot["attempts"].as_array().unwrap() {
                assert!(
                    !attempt.as_str().unwrap().contains(":running:"),
                    "{} left a running attempt",
                    vector.name
                );
            }
            circuit_states = updated;
        }
    }
}

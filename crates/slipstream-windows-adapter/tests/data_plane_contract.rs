use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_core::routing_recovery::ConnectionOutcome;
use slipstream_windows_adapter::data_plane::{
    execute_windows_data_plane_transition, execute_windows_data_plane_transition_from,
    reduce_windows_data_plane, validate_windows_data_plane_request,
    RecordingWindowsDataPlaneEffects, WindowsDataPlaneCommand, WindowsDataPlaneConfig,
    WindowsDataPlaneEvent, WindowsDataPlaneRequest, WindowsDataPlaneRequestErrorCode,
    WindowsDataPlaneState, WINDOWS_DATA_PLANE_CONTRACT_VERSION,
};
use std::collections::BTreeSet;

const DATA_PLANE_V1: &str = include_str!("../../../contracts/windows-data-plane-v1.json");

#[derive(Debug, Deserialize)]
struct Contract {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    config: WindowsDataPlaneConfig,
    vectors: Vec<Vector>,
    effect_recovery_vectors: Vec<EffectRecoveryVector>,
    invalid_requests: Vec<InvalidRequest>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    started_at_ms: u64,
    events: Vec<WindowsDataPlaneEvent>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    worker_phase: String,
    sessions: Vec<String>,
    open_resources: Vec<String>,
    effects: Vec<String>,
    outcomes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct InvalidRequest {
    name: String,
    request: WindowsDataPlaneRequest,
    error: WindowsDataPlaneRequestErrorCode,
}

#[derive(Debug, Deserialize)]
struct EffectRecoveryVector {
    name: String,
    vector: String,
    event_index: usize,
    fail_command: String,
    failed_command_index: usize,
    next_command_index: usize,
}

fn contract() -> Contract {
    serde_json::from_str(DATA_PLANE_V1).expect("Windows data-plane v1 must be valid JSON")
}

fn enum_name(value: impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .expect("enum must serialize")
        .as_str()
        .expect("enum must serialize as a string")
        .to_owned()
}

fn outcome_summary(outcome: &ConnectionOutcome) -> String {
    format!(
        "{}:{}:{}:{}:{:.3}:{}",
        outcome.ok,
        outcome.failure_phase,
        outcome.backend,
        outcome.bytes_received,
        outcome.duration,
        outcome.reason
    )
}

fn effect_summary(command: &WindowsDataPlaneCommand) -> String {
    match command {
        WindowsDataPlaneCommand::ReportWorkerReady => "worker_ready".to_owned(),
        WindowsDataPlaneCommand::ReportWorkerStartupFailed { reason } => {
            format!("worker_startup_failed:{reason}")
        }
        WindowsDataPlaneCommand::StartSession { request, .. } => {
            format!("start:{}:{}", request.request_id, request.backend.as_str())
        }
        WindowsDataPlaneCommand::ScheduleFirstPayloadDeadline {
            request_id, at_ms, ..
        } => {
            format!("first_deadline:{request_id}@{at_ms}")
        }
        WindowsDataPlaneCommand::MarkFirstPayload {
            request_id,
            bytes_received,
            ..
        } => format!("first_payload:{request_id}:{bytes_received}"),
        WindowsDataPlaneCommand::CancelSession { request_id, .. } => {
            format!("cancel:{request_id}")
        }
        WindowsDataPlaneCommand::ScheduleCancellationDeadline {
            request_id, at_ms, ..
        } => {
            format!("cancel_deadline:{request_id}@{at_ms}")
        }
        WindowsDataPlaneCommand::CloseSession { request_id, .. } => {
            format!("close:{request_id}")
        }
        WindowsDataPlaneCommand::RecordOutcome {
            request_id,
            outcome,
            ..
        } => format!("outcome:{request_id}:{}", outcome_summary(outcome)),
        WindowsDataPlaneCommand::RejectRequest { request_id, reason } => {
            format!("reject:{request_id}:{reason}")
        }
        WindowsDataPlaneCommand::ScheduleShutdownDeadline { at_ms } => {
            format!("shutdown_deadline@{at_ms}")
        }
        WindowsDataPlaneCommand::ReportWorkerStopped => "worker_stopped".to_owned(),
    }
}

fn session_summaries(state: &WindowsDataPlaneState) -> Vec<String> {
    state
        .sessions
        .iter()
        .map(|(request_id, session)| {
            format!(
                "{}#{}:{}:{}:{}:{}:{}",
                request_id,
                session.session_id,
                enum_name(session.phase),
                session.bytes_received,
                session.first_payload_observed,
                session.cancel_requested,
                session.resource_owned
            )
        })
        .collect()
}

fn assert_resource_mirror(
    name: &str,
    state: &WindowsDataPlaneState,
    effects: &RecordingWindowsDataPlaneEffects,
) {
    let state_owned: BTreeSet<_> = state
        .sessions
        .iter()
        .filter(|(_, session)| session.resource_owned)
        .map(|(request_id, session)| (session.session_id, request_id.clone()))
        .collect();
    let effect_owned: BTreeSet<_> = effects
        .open_resources()
        .iter()
        .map(|(session_id, request_id)| (*session_id, request_id.clone()))
        .collect();
    assert_eq!(state_owned, effect_owned, "{name} ownership");
}

#[test]
fn windows_data_plane_executes_every_v1_vector_through_fake_effects() {
    let contract = contract();
    let policy_tables = bundled_policy_v1();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.contract, "slipstream.windows_data_plane");
    assert_eq!(
        contract.contract_version,
        WINDOWS_DATA_PLANE_CONTRACT_VERSION
    );

    for vector in contract.vectors {
        let mut state = WindowsDataPlaneState::new(vector.started_at_ms);
        let mut effects = RecordingWindowsDataPlaneEffects::default();
        for event in vector.events {
            let transition =
                reduce_windows_data_plane(&state, &event, &contract.config, &policy_tables)
                    .unwrap_or_else(|error| panic!("{}: {event:?}: {error}", vector.name));
            execute_windows_data_plane_transition(&transition, &mut effects)
                .unwrap_or_else(|error| panic!("{}: {event:?}: {error}", vector.name));
            state = transition.state;
            assert_resource_mirror(&vector.name, &state, &effects);
        }

        assert_eq!(
            enum_name(state.worker_phase),
            vector.expected.worker_phase,
            "{} worker phase",
            vector.name
        );
        assert_eq!(
            session_summaries(&state),
            vector.expected.sessions,
            "{} sessions",
            vector.name
        );
        assert_eq!(
            effects
                .open_resources()
                .iter()
                .map(|(session_id, request_id)| (*session_id, request_id.clone()))
                .collect::<Vec<_>>(),
            vector
                .expected
                .open_resources
                .iter()
                .map(|entry| {
                    let (request_id, session_id) = entry
                        .rsplit_once('#')
                        .expect("open resource must include session id");
                    (
                        session_id.parse::<u64>().expect("valid session id"),
                        request_id.to_owned(),
                    )
                })
                .collect::<Vec<_>>(),
            "{} open resources",
            vector.name
        );
        assert_eq!(
            effects
                .commands()
                .iter()
                .map(effect_summary)
                .collect::<Vec<_>>(),
            vector.expected.effects,
            "{} effects",
            vector.name
        );
        assert_eq!(
            effects
                .outcomes()
                .iter()
                .map(outcome_summary)
                .collect::<Vec<_>>(),
            vector.expected.outcomes,
            "{} outcomes",
            vector.name
        );
    }
}

#[test]
fn windows_data_plane_rejects_every_invalid_v1_request() {
    let policy_tables = bundled_policy_v1();
    for vector in contract().invalid_requests {
        assert_eq!(
            validate_windows_data_plane_request(&vector.request, &policy_tables),
            Err(vector.error),
            "{}",
            vector.name
        );
    }
}

#[test]
fn windows_data_plane_resumes_effect_batches_without_replaying_completed_commands() {
    let contract = contract();
    let policy_tables = bundled_policy_v1();

    for recovery in &contract.effect_recovery_vectors {
        let vector = contract
            .vectors
            .iter()
            .find(|vector| vector.name == recovery.vector)
            .unwrap_or_else(|| panic!("{}: missing source vector", recovery.name));
        let mut state = WindowsDataPlaneState::new(vector.started_at_ms);
        let mut effects = RecordingWindowsDataPlaneEffects::default();

        for event in vector.events.iter().take(recovery.event_index) {
            let transition =
                reduce_windows_data_plane(&state, event, &contract.config, &policy_tables)
                    .unwrap_or_else(|error| panic!("{}: {event:?}: {error}", recovery.name));
            execute_windows_data_plane_transition(&transition, &mut effects)
                .unwrap_or_else(|error| panic!("{}: {event:?}: {error}", recovery.name));
            state = transition.state;
        }

        let event = vector
            .events
            .get(recovery.event_index)
            .unwrap_or_else(|| panic!("{}: missing target event", recovery.name));
        let transition = reduce_windows_data_plane(&state, event, &contract.config, &policy_tables)
            .unwrap_or_else(|error| panic!("{}: {event:?}: {error}", recovery.name));
        let commands_before = effects.commands().len();
        effects.fail_once(&recovery.fail_command, "contract fault");

        let error = execute_windows_data_plane_transition(&transition, &mut effects)
            .expect_err("injected command must fail once");
        assert_eq!(
            error.command, recovery.fail_command,
            "{} command",
            recovery.name
        );
        assert_eq!(
            error.failed_command_index, recovery.failed_command_index,
            "{} failed index",
            recovery.name
        );
        assert_eq!(
            error.next_command_index, recovery.next_command_index,
            "{} resume index",
            recovery.name
        );
        assert_eq!(
            error.completed_commands, recovery.failed_command_index,
            "{} completed commands",
            recovery.name
        );
        assert_eq!(
            &effects.commands()[commands_before..],
            &transition.commands[..recovery.failed_command_index],
            "{} completed prefix",
            recovery.name
        );

        execute_windows_data_plane_transition_from(
            &transition,
            &mut effects,
            error.next_command_index,
        )
        .unwrap_or_else(|error| panic!("{} resume: {error}", recovery.name));
        assert_eq!(
            &effects.commands()[commands_before..],
            transition.commands.as_slice(),
            "{} commands execute exactly once",
            recovery.name
        );

        state = transition.state;
        assert_resource_mirror(&recovery.name, &state, &effects);
    }
}

#[test]
fn windows_data_plane_contract_freezes_safety_invariants() {
    let contract = contract();
    for invariant in ["network_effects", "native_api_effects"] {
        assert_eq!(contract.invariants[invariant], false, "{invariant}");
    }
    for invariant in [
        "external_dns_proxy_pac_vpn_read_only",
        "protected_local_bypass_never_uses_geph",
        "first_payload_deadline_does_not_end_relaying_sessions",
        "partial_payload_failure_is_stream_failure",
        "caller_and_shutdown_cancellation_are_not_backend_failures",
        "resources_close_exactly_once_before_outcome",
        "request_policy_is_reclassified_against_active_tables",
        "effect_batches_expose_recoverable_partial_progress",
        "late_completion_cannot_resurrect_terminal_session",
        "shutdown_is_bounded",
        "terminal_history_is_bounded_and_aba_safe",
    ] {
        assert_eq!(contract.invariants[invariant], true, "{invariant}");
    }
}

#[test]
fn pure_data_plane_source_has_no_native_or_network_surface() {
    let source = include_str!("../src/data_plane/v1.rs");
    for forbidden in [
        "std::net::",
        "windows_sys",
        "TcpStream",
        "UdpSocket",
        "WinHttp",
        "InternetOpen",
        "DnsQuery",
        "Set-DnsClientServerAddress",
        "ProxyEnable",
        "VpnService",
        "CreateProcess",
        "TerminateProcess",
        "Command::new",
    ] {
        assert!(
            !source.contains(forbidden),
            "pure data-plane contract must not contain {forbidden}"
        );
    }
}

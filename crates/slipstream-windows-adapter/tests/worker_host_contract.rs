use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_windows_adapter::data_plane::{
    WindowsDataPlaneCommand, WindowsDataPlaneConfig, WindowsDataPlaneWorkerPhase,
};
use slipstream_windows_adapter::service_host::{WindowsServiceHostPhase, WindowsServiceHostStatus};
use slipstream_windows_adapter::worker_host::{
    execute_windows_worker_host_transition, execute_windows_worker_host_transition_from,
    reduce_windows_worker_host, RecordingWindowsWorkerHostEffects, WindowsWorkerHostCommand,
    WindowsWorkerHostEvent, WindowsWorkerHostState, WINDOWS_WORKER_HOST_CONTRACT_VERSION,
};

const WORKER_HOST_V1: &str = include_str!("../../../contracts/windows-worker-host-v1.json");

#[derive(Debug, Deserialize)]
struct Contract {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    initial_service_status: WindowsServiceHostStatus,
    invariants: Value,
    config: WindowsDataPlaneConfig,
    vectors: Vec<Vector>,
    effect_recovery_vectors: Vec<EffectRecoveryVector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    started_at_ms: u64,
    events: Vec<WindowsWorkerHostEvent>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    service_phase: WindowsServiceHostPhase,
    worker_phase: WindowsDataPlaneWorkerPhase,
    sessions: Vec<String>,
    effects: Vec<String>,
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
    serde_json::from_str(WORKER_HOST_V1).expect("Windows worker-host v1 must be valid JSON")
}

fn effect_summary(command: &WindowsWorkerHostCommand) -> String {
    match command {
        WindowsWorkerHostCommand::ReportServiceStatus {
            status,
            win32_exit_code,
        } => format!(
            "service:{}:{win32_exit_code}",
            serde_json::to_value(status).unwrap().as_str().unwrap()
        ),
        WindowsWorkerHostCommand::DataPlane { command } => match command {
            WindowsDataPlaneCommand::ReportWorkerReady => "worker_ready".to_owned(),
            WindowsDataPlaneCommand::ReportWorkerStartupFailed { reason } => {
                format!("worker_startup_failed:{reason}")
            }
            WindowsDataPlaneCommand::StartSession { request, .. } => {
                format!("start:{}:{}", request.request_id, request.backend.as_str())
            }
            WindowsDataPlaneCommand::ScheduleFirstPayloadDeadline {
                request_id, at_ms, ..
            } => format!("first_deadline:{request_id}@{at_ms}"),
            WindowsDataPlaneCommand::CancelSession { request_id, .. } => {
                format!("cancel:{request_id}")
            }
            WindowsDataPlaneCommand::ScheduleShutdownDeadline { at_ms } => {
                format!("shutdown_deadline@{at_ms}")
            }
            WindowsDataPlaneCommand::CloseSession { request_id, .. } => {
                format!("close:{request_id}")
            }
            WindowsDataPlaneCommand::ReportWorkerStopped => "worker_stopped".to_owned(),
            other => panic!("unexpected worker-host fixture command: {other:?}"),
        },
    }
}

fn session_summaries(state: &WindowsWorkerHostState) -> Vec<String> {
    state
        .data_plane
        .sessions
        .iter()
        .map(|(request_id, session)| {
            format!(
                "{}#{}:{}:{}:{}",
                request_id,
                session.session_id,
                serde_json::to_value(session.phase)
                    .unwrap()
                    .as_str()
                    .unwrap(),
                session.cancel_requested,
                session.resource_owned
            )
        })
        .collect()
}

#[test]
fn windows_worker_host_executes_every_v1_vector_through_fake_effects() {
    let contract = contract();
    let policy_tables = bundled_policy_v1();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.contract, "slipstream.windows_worker_host");
    assert_eq!(
        contract.contract_version,
        WINDOWS_WORKER_HOST_CONTRACT_VERSION
    );

    for vector in contract.vectors {
        let mut state = WindowsWorkerHostState::new(vector.started_at_ms);
        let mut effects = RecordingWindowsWorkerHostEffects::default();
        assert_eq!(
            state.initial_service_status(),
            contract.initial_service_status,
            "{} initial status",
            vector.name
        );
        for event in vector.events {
            let transition =
                reduce_windows_worker_host(&state, &event, &contract.config, &policy_tables)
                    .unwrap_or_else(|error| panic!("{}: {event:?}: {error}", vector.name));
            execute_windows_worker_host_transition(&transition, &mut effects)
                .unwrap_or_else(|error| panic!("{}: {event:?}: {error}", vector.name));
            state = transition.state;
        }

        assert_eq!(
            state.service_host.phase(),
            vector.expected.service_phase,
            "{} service phase",
            vector.name
        );
        assert_eq!(
            state.data_plane.worker_phase, vector.expected.worker_phase,
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
                .commands()
                .iter()
                .map(effect_summary)
                .collect::<Vec<_>>(),
            vector.expected.effects,
            "{} effects",
            vector.name
        );
        assert_eq!(
            state.data_plane.active_session_count(),
            effects.data_plane().open_resources().len(),
            "{} resource ownership",
            vector.name
        );
    }
}

#[test]
fn windows_worker_host_resumes_batches_without_replaying_the_completed_prefix() {
    let contract = contract();
    let policy_tables = bundled_policy_v1();

    for recovery in &contract.effect_recovery_vectors {
        let vector = contract
            .vectors
            .iter()
            .find(|vector| vector.name == recovery.vector)
            .unwrap_or_else(|| panic!("{}: missing source vector", recovery.name));
        let mut state = WindowsWorkerHostState::new(vector.started_at_ms);
        let mut effects = RecordingWindowsWorkerHostEffects::default();

        for event in vector.events.iter().take(recovery.event_index) {
            let transition =
                reduce_windows_worker_host(&state, event, &contract.config, &policy_tables)
                    .unwrap();
            execute_windows_worker_host_transition(&transition, &mut effects).unwrap();
            state = transition.state;
        }

        let event = &vector.events[recovery.event_index];
        let transition =
            reduce_windows_worker_host(&state, event, &contract.config, &policy_tables).unwrap();
        let commands_before = effects.commands().len();
        effects.fail_once(&recovery.fail_command, "contract fault");
        let error = execute_windows_worker_host_transition(&transition, &mut effects)
            .expect_err("injected effect must fail once");
        assert_eq!(error.command, recovery.fail_command, "{}", recovery.name);
        assert_eq!(
            error.failed_command_index, recovery.failed_command_index,
            "{}",
            recovery.name
        );
        assert_eq!(
            error.next_command_index, recovery.next_command_index,
            "{}",
            recovery.name
        );
        assert_eq!(
            &effects.commands()[commands_before..],
            &transition.commands[..recovery.failed_command_index],
            "{} completed prefix",
            recovery.name
        );

        execute_windows_worker_host_transition_from(
            &transition,
            &mut effects,
            error.next_command_index,
        )
        .unwrap_or_else(|error| panic!("{} resume: {error}", recovery.name));
        assert_eq!(
            &effects.commands()[commands_before..],
            transition.commands.as_slice(),
            "{} commands execute once",
            recovery.name
        );
    }
}

#[test]
fn windows_worker_host_contract_freezes_lifecycle_safety_invariants() {
    let contract = contract();
    for invariant in ["network_effects", "native_api_effects"] {
        assert_eq!(contract.invariants[invariant], false, "{invariant}");
    }
    for invariant in [
        "running_requires_worker_readiness",
        "startup_failure_reports_nonzero_stopped",
        "shutdown_is_host_owned",
        "stop_pending_precedes_worker_cancellation",
        "stopped_requires_worker_stopped",
        "inconsistent_composition_is_rejected",
        "forced_shutdown_is_bounded",
        "late_completion_cannot_resurrect_service",
        "effect_batches_expose_recoverable_partial_progress",
    ] {
        assert_eq!(contract.invariants[invariant], true, "{invariant}");
    }
}

#[test]
fn pure_worker_host_composition_has_no_native_or_network_surface() {
    let source = include_str!("../src/worker_host/v1.rs");
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
        "CreateProcess",
        "TerminateProcess",
        "Command::new",
    ] {
        assert!(
            !source.contains(forbidden),
            "pure worker-host contract must not contain {forbidden}"
        );
    }
}

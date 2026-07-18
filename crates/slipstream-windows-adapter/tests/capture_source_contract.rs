use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_windows_adapter::capture_source::{
    execute_windows_capture_source_transition, execute_windows_capture_source_transition_from,
    reduce_windows_capture_source, RecordingWindowsCaptureSourceEffects,
    WindowsCaptureSourceCommand, WindowsCaptureSourceConfig, WindowsCaptureSourceEvent,
    WindowsCaptureSourcePhase, WindowsCaptureSourceState, WINDOWS_CAPTURE_SOURCE_CONTRACT_VERSION,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-capture-source-v1.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    config: WindowsCaptureSourceConfig,
    vectors: Vec<Vector>,
    effect_recovery_vectors: Vec<EffectRecoveryVector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    started_at_ms: u64,
    events: Vec<WindowsCaptureSourceEvent>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    phase: WindowsCaptureSourcePhase,
    next_connection_id: u64,
    connections: Vec<String>,
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

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Windows capture-source v1 must be valid JSON")
}

fn stage_event_resource(
    event: &WindowsCaptureSourceEvent,
    effects: &mut RecordingWindowsCaptureSourceEffects,
) {
    if let WindowsCaptureSourceEvent::ConnectionCaptured { resource_id, .. } = event {
        effects
            .stage_captured_stream(*resource_id)
            .expect("fixture resource must be unique");
    }
}

fn command_summary(command: &WindowsCaptureSourceCommand) -> String {
    match command {
        WindowsCaptureSourceCommand::StartSource => "start_source".to_owned(),
        WindowsCaptureSourceCommand::ReportSourceReady => "report_source_ready".to_owned(),
        WindowsCaptureSourceCommand::OfferConnection {
            connection_id,
            resource_id,
            original_destination,
            observed_at_ms,
            valid_until_ms,
        } => format!(
            "offer:{connection_id}#{resource_id}:{}:{}@{observed_at_ms}..{valid_until_ms}",
            original_destination.address, original_destination.port
        ),
        WindowsCaptureSourceCommand::ScheduleAdmissionDeadline {
            connection_id,
            at_ms,
        } => format!("admission_deadline:{connection_id}@{at_ms}"),
        WindowsCaptureSourceCommand::HandoffIngress {
            connection_id,
            resource_id,
            request,
        } => format!(
            "handoff:{connection_id}#{resource_id}:{}#{}",
            request.connector_request.data_plane_request.request_id,
            request.connector_request.session_id
        ),
        WindowsCaptureSourceCommand::CloseCapturedStream {
            connection_id,
            resource_id,
            reason,
        } => format!(
            "close:{}#{resource_id}:{reason}",
            connection_id.map_or_else(|| "none".to_owned(), |value| value.to_string())
        ),
        WindowsCaptureSourceCommand::StopAccepting => "stop_accepting".to_owned(),
        WindowsCaptureSourceCommand::ScheduleShutdownDeadline { at_ms } => {
            format!("shutdown_deadline@{at_ms}")
        }
        WindowsCaptureSourceCommand::ForceStopSource => "force_stop_source".to_owned(),
        WindowsCaptureSourceCommand::ReportSourceStartupFailed { reason } => {
            format!("report_source_startup_failed:{reason}")
        }
        WindowsCaptureSourceCommand::ReportSourceStopped => "report_source_stopped".to_owned(),
    }
}

fn connection_summaries(state: &WindowsCaptureSourceState) -> Vec<String> {
    state
        .connections
        .values()
        .map(|connection| {
            format!(
                "{}#{}:{}:{}:{}:{}:{}",
                connection.connection_id,
                connection.resource_id,
                serde_json::to_value(connection.phase)
                    .unwrap()
                    .as_str()
                    .unwrap(),
                connection.resource_owned,
                connection.original_destination.address,
                connection.original_destination.port,
                connection.terminal_reason
            )
        })
        .collect()
}

fn run_event(
    state: &mut WindowsCaptureSourceState,
    event: &WindowsCaptureSourceEvent,
    config: &WindowsCaptureSourceConfig,
    effects: &mut RecordingWindowsCaptureSourceEffects,
) {
    stage_event_resource(event, effects);
    let transition = reduce_windows_capture_source(state, event, config, &bundled_policy_v1())
        .unwrap_or_else(|error| panic!("{event:?}: {error}"));
    execute_windows_capture_source_transition(&transition, effects)
        .unwrap_or_else(|error| panic!("{event:?}: {error}"));
    *state = transition.state;
}

#[test]
fn rust_executes_windows_capture_source_v1_contract() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_capture_source");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_CAPTURE_SOURCE_CONTRACT_VERSION
    );
    assert_eq!(fixture.invariants["route_selection"], Value::Bool(false));
    assert_eq!(fixture.invariants["name_resolution"], Value::Bool(false));
    assert_eq!(
        fixture.invariants["backend_is_direct_only"],
        Value::Bool(true)
    );
    assert_eq!(
        fixture.invariants["absolute_connector_deadlines_are_not_rebased"],
        Value::Bool(true)
    );
    assert_eq!(
        fixture.invariants["failed_handoff_retains_source_ownership"],
        Value::Bool(true)
    );
    assert_eq!(
        fixture.invariants["production_service_host_network_effects"],
        Value::Bool(false)
    );

    for vector in fixture.vectors {
        let mut state = WindowsCaptureSourceState::new(vector.started_at_ms);
        let mut effects = RecordingWindowsCaptureSourceEffects::default();
        for event in &vector.events {
            run_event(&mut state, event, &fixture.config, &mut effects);
        }
        assert_eq!(state.phase, vector.expected.phase, "{} phase", vector.name);
        assert_eq!(
            state.next_connection_id, vector.expected.next_connection_id,
            "{} next connection ID",
            vector.name
        );
        assert_eq!(
            connection_summaries(&state),
            vector.expected.connections,
            "{} connections",
            vector.name
        );
        assert_eq!(
            effects
                .commands()
                .iter()
                .map(command_summary)
                .collect::<Vec<_>>(),
            vector.expected.effects,
            "{} effects",
            vector.name
        );
        assert_eq!(
            state.staged_connection_count(),
            effects.open_resources().len(),
            "{} source ownership",
            vector.name
        );
    }
}

#[test]
fn capture_source_resumes_effect_batches_without_replaying_completed_prefix() {
    let fixture = contract();
    for recovery in &fixture.effect_recovery_vectors {
        let vector = fixture
            .vectors
            .iter()
            .find(|vector| vector.name == recovery.vector)
            .unwrap_or_else(|| panic!("{}: missing vector", recovery.name));
        let mut state = WindowsCaptureSourceState::new(vector.started_at_ms);
        let mut effects = RecordingWindowsCaptureSourceEffects::default();

        for event in vector.events.iter().take(recovery.event_index) {
            run_event(&mut state, event, &fixture.config, &mut effects);
        }
        let event = &vector.events[recovery.event_index];
        stage_event_resource(event, &mut effects);
        let transition =
            reduce_windows_capture_source(&state, event, &fixture.config, &bundled_policy_v1())
                .expect("recovery vector must reduce");
        let commands_before = effects.commands().len();
        effects.fail_once(&recovery.fail_command, "contract fault");
        let error = execute_windows_capture_source_transition(&transition, &mut effects)
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

        execute_windows_capture_source_transition_from(
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
fn failed_handoff_can_be_compensated_by_closing_the_exact_owned_stream() {
    let fixture = contract();
    let vector = fixture
        .vectors
        .iter()
        .find(|vector| vector.name == "captured-stream-hands-off-after-external-admission")
        .expect("handoff vector");
    let mut state = WindowsCaptureSourceState::new(vector.started_at_ms);
    let mut effects = RecordingWindowsCaptureSourceEffects::default();
    for event in vector.events.iter().take(3) {
        run_event(&mut state, event, &fixture.config, &mut effects);
    }

    let grant = &vector.events[3];
    let transition =
        reduce_windows_capture_source(&state, grant, &fixture.config, &bundled_policy_v1())
            .expect("grant must reduce");
    effects.fail_once("handoff_ingress", "direct ingress unavailable");
    execute_windows_capture_source_transition(&transition, &mut effects)
        .expect_err("handoff must fail before ownership moves");
    assert!(effects.open_resources().contains(&101));
    assert!(effects.handed_off().is_empty());

    let reject = WindowsCaptureSourceEvent::AdmissionRejected {
        now_ms: 21,
        connection_id: 1,
        reason: "handoff_failed".to_owned(),
    };
    run_event(&mut state, &reject, &fixture.config, &mut effects);
    assert!(effects.open_resources().is_empty());
    assert_eq!(
        effects.closed_resources().get(&101).map(String::as_str),
        Some("admission_rejected:handoff_failed")
    );
}

#[test]
fn startup_effect_failure_is_failure_atomic() {
    let fixture = contract();
    let state = WindowsCaptureSourceState::new(0);
    let transition = reduce_windows_capture_source(
        &state,
        &WindowsCaptureSourceEvent::StartRequested { now_ms: 0 },
        &fixture.config,
        &bundled_policy_v1(),
    )
    .expect("start must reduce");
    let mut effects = RecordingWindowsCaptureSourceEffects::default();
    effects.fail_once("start_source", "native source unavailable");
    let error = execute_windows_capture_source_transition(&transition, &mut effects)
        .expect_err("start must fail once");
    assert_eq!(error.next_command_index, 0);
    assert!(!effects.source_started());
    assert_eq!(state.phase, WindowsCaptureSourcePhase::Stopped);
    execute_windows_capture_source_transition_from(
        &transition,
        &mut effects,
        error.next_command_index,
    )
    .expect("start retry must succeed");
    assert!(effects.source_started());
}

#[test]
fn terminal_capture_history_is_bounded_without_reusing_connection_ids() {
    let mut fixture = contract();
    fixture.config.max_retained_terminal_connections = 2;
    let mut state = WindowsCaptureSourceState::new(0);
    let mut effects = RecordingWindowsCaptureSourceEffects::default();
    run_event(
        &mut state,
        &WindowsCaptureSourceEvent::StartRequested { now_ms: 0 },
        &fixture.config,
        &mut effects,
    );
    run_event(
        &mut state,
        &WindowsCaptureSourceEvent::SourceReady { now_ms: 1 },
        &fixture.config,
        &mut effects,
    );
    for offset in 0..3_u64 {
        run_event(
            &mut state,
            &WindowsCaptureSourceEvent::ConnectionCaptured {
                now_ms: 10 + offset * 2,
                resource_id: 200 + offset,
                original_destination:
                    slipstream_windows_adapter::direct_connector::WindowsDirectConnectorEndpoint {
                        address: "127.0.0.1".to_owned(),
                        port: 443,
                    },
            },
            &fixture.config,
            &mut effects,
        );
        run_event(
            &mut state,
            &WindowsCaptureSourceEvent::AdmissionRejected {
                now_ms: 11 + offset * 2,
                connection_id: 1 + offset,
                reason: "not_direct".to_owned(),
            },
            &fixture.config,
            &mut effects,
        );
    }
    assert_eq!(state.next_connection_id, 4);
    assert_eq!(
        state.connections.keys().copied().collect::<Vec<_>>(),
        [2, 3]
    );
    assert!(effects.open_resources().is_empty());
}

#[test]
fn duplicate_resource_id_does_not_close_or_replace_the_tracked_stream() {
    let fixture = contract();
    let mut state = WindowsCaptureSourceState::new(0);
    let mut effects = RecordingWindowsCaptureSourceEffects::default();
    run_event(
        &mut state,
        &WindowsCaptureSourceEvent::StartRequested { now_ms: 0 },
        &fixture.config,
        &mut effects,
    );
    run_event(
        &mut state,
        &WindowsCaptureSourceEvent::SourceReady { now_ms: 1 },
        &fixture.config,
        &mut effects,
    );
    run_event(
        &mut state,
        &WindowsCaptureSourceEvent::ConnectionCaptured {
            now_ms: 10,
            resource_id: 301,
            original_destination:
                slipstream_windows_adapter::direct_connector::WindowsDirectConnectorEndpoint {
                    address: "127.0.0.1".to_owned(),
                    port: 443,
                },
        },
        &fixture.config,
        &mut effects,
    );

    let duplicate = WindowsCaptureSourceEvent::ConnectionCaptured {
        now_ms: 11,
        resource_id: 301,
        original_destination:
            slipstream_windows_adapter::direct_connector::WindowsDirectConnectorEndpoint {
                address: "127.0.0.1".to_owned(),
                port: 443,
            },
    };
    let error =
        reduce_windows_capture_source(&state, &duplicate, &fixture.config, &bundled_policy_v1())
            .expect_err("duplicate resource token must fail closed");
    assert_eq!(error.to_string(), "duplicate capture resource 301");
    assert!(effects.open_resources().contains(&301));
    assert!(effects.closed_resources().is_empty());
    assert!(state.connections.get(&1).unwrap().resource_owned);
}

#[test]
fn capture_source_has_no_interception_resolver_or_system_mutation_surface() {
    let source = include_str!("../src/capture_source/v1.rs");
    for forbidden in [
        "TcpListener",
        "TcpStream",
        "ToSocketAddrs",
        "lookup_host",
        "UdpSocket",
        "WinDivert",
        "Fwpm",
        "windows_sys",
        "std::process",
        "Command::new",
        "Set-DnsClientServerAddress",
        "netsh",
        "WinHttpSetDefaultProxyConfiguration",
        "Geph",
    ] {
        assert!(
            !source.contains(forbidden),
            "capture source contains {forbidden}"
        );
    }
    let worker_host = include_str!("../src/worker_host/v1.rs");
    let production_host = include_str!("../src/service_host/windows.rs");
    assert!(!worker_host.contains("capture_source"));
    assert!(!production_host.contains("capture_source"));
}

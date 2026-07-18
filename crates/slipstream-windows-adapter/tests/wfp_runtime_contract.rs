use serde::Deserialize;
use serde_json::Value;
use slipstream_windows_adapter::wfp_capture::WindowsWfpCaptureIdentity;
use slipstream_windows_adapter::wfp_runtime::{
    execute_windows_wfp_runtime_transition, execute_windows_wfp_runtime_transition_from,
    reduce_windows_wfp_runtime, RecordingWindowsWfpRuntimeEffects, WindowsWfpRuntimeCommand,
    WindowsWfpRuntimeConfig, WindowsWfpRuntimeEvent, WindowsWfpRuntimePhase,
    WindowsWfpRuntimeState, WindowsWfpShutdownCause, WINDOWS_WFP_RUNTIME_CONTRACT_VERSION,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-wfp-runtime-v1.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    identity: WindowsWfpCaptureIdentity,
    config: WindowsWfpRuntimeConfig,
    vectors: Vec<Vector>,
    effect_recovery_vectors: Vec<EffectRecoveryVector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    started_at_ms: u64,
    events: Vec<WindowsWfpRuntimeEvent>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    phase: WindowsWfpRuntimePhase,
    runtime_generation: u64,
    next_runtime_generation: u64,
    kernel_callouts_registered: bool,
    listeners_ready: bool,
    active_session_generation: Option<u64>,
    last_session_generation: Option<u64>,
    next_session_generation: u64,
    filters_absent: bool,
    filter_inspection_pending: bool,
    filter_recheck_at_ms: Option<u64>,
    active_connections: Vec<u64>,
    drain_deadline_at_ms: Option<u64>,
    stop_requested: bool,
    shutdown_cause: Option<WindowsWfpShutdownCause>,
    terminal_reason: String,
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
    serde_json::from_str(CONTRACT).expect("Windows WFP runtime v1 must be valid JSON")
}

fn command_summary(command: &WindowsWfpRuntimeCommand) -> String {
    match command {
        WindowsWfpRuntimeCommand::RegisterKernelCallouts { .. } => {
            "register_kernel_callouts".to_owned()
        }
        WindowsWfpRuntimeCommand::StartOwnedListeners { .. } => "start_owned_listeners".to_owned(),
        WindowsWfpRuntimeCommand::CommitAtomicDynamicSession {
            session_generation, ..
        } => format!("commit_atomic_dynamic_session:{session_generation}"),
        WindowsWfpRuntimeCommand::ReportRuntimeReady => "report_runtime_ready".to_owned(),
        WindowsWfpRuntimeCommand::CloseDynamicSession {
            session_generation, ..
        } => format!("close_dynamic_session:{session_generation}"),
        WindowsWfpRuntimeCommand::InspectOwnedFilters {
            session_generation, ..
        } => format!(
            "inspect_owned_filters:{}",
            session_generation.map_or_else(|| "none".to_owned(), |value| value.to_string())
        ),
        WindowsWfpRuntimeCommand::ReportFilterRemovalBlocked {
            ipv4_present,
            ipv6_present,
        } => {
            let families = match (*ipv4_present, *ipv6_present) {
                (true, true) => "v4+v6",
                (true, false) => "v4",
                (false, true) => "v6",
                (false, false) => "none",
            };
            format!("report_filter_removal_blocked:{families}")
        }
        WindowsWfpRuntimeCommand::ScheduleFilterAbsenceRecheck { at_ms } => {
            format!("schedule_filter_absence_recheck@{at_ms}")
        }
        WindowsWfpRuntimeCommand::StopOwnedListeners { .. } => "stop_owned_listeners".to_owned(),
        WindowsWfpRuntimeCommand::ScheduleDrainDeadline { at_ms } => {
            format!("schedule_drain_deadline@{at_ms}")
        }
        WindowsWfpRuntimeCommand::RejectAcceptedStream { connection_id, .. } => {
            format!("reject_accepted_stream:{connection_id}")
        }
        WindowsWfpRuntimeCommand::ForceCloseAcceptedStreams { connection_ids } => format!(
            "force_close_accepted_streams:{}",
            connection_ids
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
        WindowsWfpRuntimeCommand::UnregisterKernelCallouts { .. } => {
            "unregister_kernel_callouts".to_owned()
        }
        WindowsWfpRuntimeCommand::ReportRuntimeTerminal {
            phase,
            cause,
            reason,
        } => format!(
            "report_runtime_terminal:{}:{}:{reason}",
            serde_json::to_value(phase).unwrap().as_str().unwrap(),
            cause.map_or_else(
                || "none".to_owned(),
                |value| serde_json::to_value(value)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            )
        ),
    }
}

fn run_event(
    state: &mut WindowsWfpRuntimeState,
    event: &WindowsWfpRuntimeEvent,
    config: &WindowsWfpRuntimeConfig,
    effects: &mut RecordingWindowsWfpRuntimeEffects,
) {
    effects
        .stage_event(event)
        .unwrap_or_else(|error| panic!("{event:?} recording stage: {error}"));
    let transition = reduce_windows_wfp_runtime(state, event, config)
        .unwrap_or_else(|error| panic!("{event:?} reducer: {error}"));
    execute_windows_wfp_runtime_transition(&transition, effects)
        .unwrap_or_else(|error| panic!("{event:?} effects: {error}"));
    *state = transition.state;
}

fn assert_expected(
    name: &str,
    state: &WindowsWfpRuntimeState,
    effects: &RecordingWindowsWfpRuntimeEffects,
    expected: &Expected,
) {
    assert_eq!(state.phase, expected.phase, "{name} phase");
    assert_eq!(
        state.runtime_generation, expected.runtime_generation,
        "{name} runtime generation"
    );
    assert_eq!(
        state.next_runtime_generation, expected.next_runtime_generation,
        "{name} next runtime generation"
    );
    assert_eq!(
        state.kernel_callouts_registered, expected.kernel_callouts_registered,
        "{name} kernel registration"
    );
    assert_eq!(
        state.listeners_ready, expected.listeners_ready,
        "{name} listeners"
    );
    assert_eq!(
        state.active_session_generation, expected.active_session_generation,
        "{name} active session"
    );
    assert_eq!(
        state.last_session_generation, expected.last_session_generation,
        "{name} last session"
    );
    assert_eq!(
        state.next_session_generation, expected.next_session_generation,
        "{name} next session"
    );
    assert_eq!(
        state.filters_absent, expected.filters_absent,
        "{name} filters"
    );
    assert_eq!(
        state.filter_inspection_pending, expected.filter_inspection_pending,
        "{name} inspection"
    );
    assert_eq!(
        state.filter_recheck_at_ms, expected.filter_recheck_at_ms,
        "{name} recheck"
    );
    assert_eq!(
        state.active_connections.iter().copied().collect::<Vec<_>>(),
        expected.active_connections,
        "{name} active connections"
    );
    assert_eq!(
        state.drain_deadline_at_ms, expected.drain_deadline_at_ms,
        "{name} drain deadline"
    );
    assert_eq!(
        state.stop_requested, expected.stop_requested,
        "{name} stop request"
    );
    assert_eq!(
        state.shutdown_cause, expected.shutdown_cause,
        "{name} shutdown cause"
    );
    assert_eq!(
        state.terminal_reason, expected.terminal_reason,
        "{name} reason"
    );
    assert_eq!(
        effects
            .commands()
            .iter()
            .map(command_summary)
            .collect::<Vec<_>>(),
        expected.effects,
        "{name} effects"
    );
    assert_eq!(
        state.kernel_callouts_registered,
        effects.kernel_registered(),
        "{name} recorded callout ownership"
    );
    assert_eq!(
        state.listeners_ready,
        effects.listeners_ready(),
        "{name} recorded listener ownership"
    );
    assert_eq!(
        state.active_session_generation,
        effects.active_session(),
        "{name} recorded session ownership"
    );
    assert_eq!(
        state.filters_absent,
        !effects.filters_present(),
        "{name} recorded filter evidence"
    );
    assert_eq!(
        &state.active_connections,
        effects.active_connections(),
        "{name} recorded stream ownership"
    );
}

#[test]
fn rust_executes_windows_wfp_runtime_v1_contract() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_wfp_runtime");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_WFP_RUNTIME_CONTRACT_VERSION
    );
    assert_eq!(fixture.invariants["native_wfp_effects"], Value::Bool(false));
    assert_eq!(
        fixture.invariants["dynamic_session_close_is_first_stop_effect"],
        Value::Bool(true)
    );
    assert_eq!(
        fixture.invariants["exact_owned_filter_absence_precedes_kernel_unregister"],
        Value::Bool(true)
    );
    assert_eq!(
        fixture.invariants["monotonic_runtime_generations_prevent_completion_aba"],
        Value::Bool(true)
    );
    assert_eq!(
        fixture.invariants["over_capacity_accept_is_closed"],
        Value::Bool(true)
    );
    assert_eq!(
        fixture.invariants["production_service_host_network_effects"],
        Value::Bool(false)
    );

    for vector in &fixture.vectors {
        let mut state = WindowsWfpRuntimeState::new(vector.started_at_ms, fixture.identity.clone())
            .unwrap_or_else(|error| panic!("{} state: {error}", vector.name));
        let mut effects = RecordingWindowsWfpRuntimeEffects::default();
        for event in &vector.events {
            run_event(&mut state, event, &fixture.config, &mut effects);
        }
        assert_expected(&vector.name, &state, &effects, &vector.expected);
    }
}

#[test]
fn runtime_effect_batches_resume_without_replaying_completed_prefix() {
    let fixture = contract();
    for recovery in &fixture.effect_recovery_vectors {
        let vector = fixture
            .vectors
            .iter()
            .find(|vector| vector.name == recovery.vector)
            .unwrap_or_else(|| panic!("{}: missing vector", recovery.name));
        let mut state =
            WindowsWfpRuntimeState::new(vector.started_at_ms, fixture.identity.clone()).unwrap();
        let mut effects = RecordingWindowsWfpRuntimeEffects::default();

        for event in vector.events.iter().take(recovery.event_index) {
            run_event(&mut state, event, &fixture.config, &mut effects);
        }
        let event = &vector.events[recovery.event_index];
        effects.stage_event(event).unwrap();
        let transition = reduce_windows_wfp_runtime(&state, event, &fixture.config).unwrap();
        let commands_before = effects.commands().len();
        effects.fail_once(&recovery.fail_command, "contract fault");
        let error = execute_windows_wfp_runtime_transition(&transition, &mut effects)
            .expect_err("injected effect must fail once");
        assert_eq!(error.command, recovery.fail_command, "{}", recovery.name);
        assert_eq!(
            error.failed_command_index, recovery.failed_command_index,
            "{} failed cursor",
            recovery.name
        );
        assert_eq!(
            error.next_command_index, recovery.next_command_index,
            "{} retry cursor",
            recovery.name
        );
        assert_eq!(
            &effects.commands()[commands_before..],
            &transition.commands[..recovery.failed_command_index],
            "{} completed prefix",
            recovery.name
        );

        execute_windows_wfp_runtime_transition_from(
            &transition,
            &mut effects,
            error.next_command_index,
        )
        .unwrap_or_else(|error| panic!("{} resume: {error}", recovery.name));
        state = transition.state;
        for event in vector.events.iter().skip(recovery.event_index + 1) {
            run_event(&mut state, event, &fixture.config, &mut effects);
        }
        assert_expected(&recovery.name, &state, &effects, &vector.expected);
    }
}

#[test]
fn stop_from_ready_emits_only_session_close_first() {
    let fixture = contract();
    let vector = fixture
        .vectors
        .iter()
        .find(|vector| vector.name == "graceful-stop-closes-session-before-proof-and-drain")
        .unwrap();
    let mut state = WindowsWfpRuntimeState::new(0, fixture.identity).unwrap();
    let mut effects = RecordingWindowsWfpRuntimeEffects::default();
    for event in vector.events.iter().take(5) {
        run_event(&mut state, event, &fixture.config, &mut effects);
    }
    let transition =
        reduce_windows_wfp_runtime(&state, &vector.events[5], &fixture.config).unwrap();
    assert_eq!(transition.commands.len(), 1);
    assert_eq!(transition.commands[0].kind(), "close_dynamic_session");

    let fault = WindowsWfpRuntimeEvent::RuntimeFault {
        now_ms: 5,
        binding: state.binding(),
        reason: "runtime fault".to_owned(),
    };
    let transition = reduce_windows_wfp_runtime(&state, &fault, &fixture.config).unwrap();
    assert_eq!(transition.commands.len(), 1);
    assert_eq!(transition.commands[0].kind(), "close_dynamic_session");
}

#[test]
fn stale_runtime_binding_is_rejected_without_effects() {
    let fixture = contract();
    let mut state = WindowsWfpRuntimeState::new(0, fixture.identity).unwrap();
    let mut effects = RecordingWindowsWfpRuntimeEffects::default();
    let ready = &fixture.vectors[0];
    for event in &ready.events {
        run_event(&mut state, event, &fixture.config, &mut effects);
    }
    let error = reduce_windows_wfp_runtime(
        &state,
        &WindowsWfpRuntimeEvent::RuntimeFault {
            now_ms: 4,
            binding: slipstream_windows_adapter::wfp_runtime::WindowsWfpRuntimeBinding {
                service_generation: state.identity.service.generation,
                capture_instance_id: state.identity.capture_instance_id.clone(),
                runtime_generation: state.runtime_generation + 1,
            },
            reason: "stale controller".to_owned(),
        },
        &fixture.config,
    )
    .expect_err("stale event must fail closed at the control boundary");
    assert_eq!(error.to_string(), "stale WFP runtime binding");
}

#[test]
fn runtime_generation_rejects_delayed_completion_after_restart() {
    let fixture = contract();
    let vector = fixture
        .vectors
        .iter()
        .find(|vector| vector.name == "graceful-stop-closes-session-before-proof-and-drain")
        .unwrap();
    let mut state = WindowsWfpRuntimeState::new(0, fixture.identity).unwrap();
    let mut effects = RecordingWindowsWfpRuntimeEffects::default();
    for event in &vector.events {
        run_event(&mut state, event, &fixture.config, &mut effects);
    }
    assert_eq!(state.phase, WindowsWfpRuntimePhase::Stopped);
    let previous_binding = state.binding();

    let restart = reduce_windows_wfp_runtime(
        &state,
        &WindowsWfpRuntimeEvent::StartRequested { now_ms: 11 },
        &fixture.config,
    )
    .unwrap();
    state = restart.state;
    assert_eq!(
        state.runtime_generation,
        previous_binding.runtime_generation + 1
    );
    assert_eq!(restart.commands.len(), 1);
    assert!(matches!(
        &restart.commands[0],
        WindowsWfpRuntimeCommand::RegisterKernelCallouts { binding }
            if binding == &state.binding()
    ));

    let error = reduce_windows_wfp_runtime(
        &state,
        &WindowsWfpRuntimeEvent::KernelCalloutsRegistered {
            now_ms: 12,
            binding: previous_binding,
        },
        &fixture.config,
    )
    .expect_err("a completion from the previous runtime attempt must be rejected");
    assert_eq!(error.to_string(), "stale WFP runtime binding");

    let accepted = reduce_windows_wfp_runtime(
        &state,
        &WindowsWfpRuntimeEvent::KernelCalloutsRegistered {
            now_ms: 12,
            binding: state.binding(),
        },
        &fixture.config,
    )
    .unwrap();
    assert_eq!(
        accepted.state.phase,
        WindowsWfpRuntimePhase::StartingListeners
    );
}

#[test]
fn production_service_host_does_not_compose_wfp_runtime() {
    for (label, source) in [
        ("service host", include_str!("../src/service_host/v1.rs")),
        ("worker host", include_str!("../src/worker_host/v1.rs")),
        (
            "production binary",
            include_str!("../src/bin/slipstream_windows_service.rs"),
        ),
    ] {
        assert!(
            !source.contains("wfp_runtime"),
            "{label} must remain disconnected from the WFP runtime"
        );
    }
}

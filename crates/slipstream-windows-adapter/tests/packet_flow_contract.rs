use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::{bundled_policy_v1, classify_route_policy};
use slipstream_windows_adapter::data_plane::{
    WindowsDataPlaneBackend, WindowsDataPlaneEvent, WindowsDataPlaneRequest,
};
use slipstream_windows_adapter::packet_adapter::v2::{
    classify_windows_packet_capture, WindowsPacketCaptureAttribution, WindowsPacketCaptureDecision,
    WindowsPacketCaptureObservation, WindowsPacketCaptureTransport,
    WindowsPacketHostnameEvidenceSource,
};
use slipstream_windows_adapter::packet_egress::{
    prepare_windows_packet_egress, WindowsPacketBaselineRouteEvidence,
    WindowsPacketCaptureRouteActivationEvidence, WindowsPacketEgressRequest,
    WindowsPacketInterfaceIdentity, WindowsPacketSocketInterfaceBinding,
};
use slipstream_windows_adapter::packet_flow::{
    prepare_windows_packet_flow, reduce_windows_packet_flow, WindowsPacketFlowAdmission,
    WindowsPacketFlowAdmissionErrorCode, WindowsPacketFlowCommand, WindowsPacketFlowConfig,
    WindowsPacketFlowDirection, WindowsPacketFlowEvent, WindowsPacketFlowPhase,
    WindowsPacketFlowRegistry, WindowsPacketFlowTransport, WINDOWS_PACKET_FLOW_CONTRACT_VERSION,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-packet-flow-v1.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    config: WindowsPacketFlowConfig,
    vectors: Vec<FixtureVector>,
    remaining_native_gates: Value,
}

#[derive(Debug, Deserialize)]
struct FixtureVector {
    name: String,
    capture_generation: u64,
    flow_id: u64,
    host: String,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketFlowTransport,
    events: Vec<FixtureEvent>,
    expected: FixtureExpected,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FixtureEvent {
    BackendReady {
        now_ms: u64,
    },
    Payload {
        now_ms: u64,
        direction: WindowsPacketFlowDirection,
        sequence: u64,
        bytes: usize,
    },
    Forwarded {
        now_ms: u64,
        direction: WindowsPacketFlowDirection,
        through_sequence: u64,
    },
    HalfClosed {
        now_ms: u64,
        direction: WindowsPacketFlowDirection,
    },
    DatagramSideClosed {
        now_ms: u64,
    },
    Reset {
        now_ms: u64,
        direction: WindowsPacketFlowDirection,
        reason: String,
    },
    Cancelled {
        now_ms: u64,
    },
    IdleDeadline {
        now_ms: u64,
    },
    BackpressureDeadline {
        now_ms: u64,
        direction: WindowsPacketFlowDirection,
    },
}

#[derive(Debug, Deserialize)]
struct FixtureExpected {
    phase: WindowsPacketFlowPhase,
    resource_owned: bool,
    client_to_backend_bytes: usize,
    backend_to_client_bytes: usize,
    terminal_reason: String,
    must_emit: Vec<String>,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Windows packet-flow v1 must be valid JSON")
}

fn egress_request() -> WindowsPacketEgressRequest {
    WindowsPacketEgressRequest {
        capture_generation: 7,
        flow_id: 41,
        destination: "104.16.58.5".to_owned(),
        capture_started_at_ms: 1_100,
        now_ms: 1_200,
        current_route_epoch: 10,
        current_capture_interface: WindowsPacketInterfaceIdentity {
            luid: 900,
            index: 90,
        },
        current_egress_interface: WindowsPacketInterfaceIdentity {
            luid: 120,
            index: 12,
        },
        current_source_address: "10.0.0.4".to_owned(),
        capture_route: WindowsPacketCaptureRouteActivationEvidence {
            capture_generation: 7,
            destination: "104.16.58.5".to_owned(),
            route_prefix: "104.16.58.5/32".to_owned(),
            previous_route_epoch: 9,
            active_route_epoch: 10,
            activated_at_ms: 1_050,
            capture_interface: WindowsPacketInterfaceIdentity {
                luid: 900,
                index: 90,
            },
        },
        baseline: WindowsPacketBaselineRouteEvidence {
            capture_generation: 7,
            route_epoch: 9,
            destination: "104.16.58.5".to_owned(),
            observed_at_ms: 1_000,
            expires_at_ms: 5_000,
            capture_interface: WindowsPacketInterfaceIdentity {
                luid: 900,
                index: 90,
            },
            egress_interface: WindowsPacketInterfaceIdentity {
                luid: 120,
                index: 12,
            },
            source_address: "10.0.0.4".to_owned(),
            route_prefix: "0.0.0.0/0".to_owned(),
            route_is_loopback: false,
        },
    }
}

fn egress_request_for(capture_generation: u64, flow_id: u64) -> WindowsPacketEgressRequest {
    let mut request = egress_request();
    request.capture_generation = capture_generation;
    request.flow_id = flow_id;
    request.capture_route.capture_generation = capture_generation;
    request.baseline.capture_generation = capture_generation;
    request
}

fn admission(
    host: &str,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketCaptureTransport,
) -> Result<WindowsPacketFlowAdmission, WindowsPacketFlowAdmissionErrorCode> {
    admission_with_key(host, backend, transport, 7, 41)
}

fn admission_with_key(
    host: &str,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketCaptureTransport,
    capture_generation: u64,
    flow_id: u64,
) -> Result<WindowsPacketFlowAdmission, WindowsPacketFlowAdmissionErrorCode> {
    admission_with_owner(host, backend, transport, capture_generation, flow_id, 9)
}

fn admission_with_owner(
    host: &str,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketCaptureTransport,
    capture_generation: u64,
    flow_id: u64,
    session_id: u64,
) -> Result<WindowsPacketFlowAdmission, WindowsPacketFlowAdmissionErrorCode> {
    let policy_tables = bundled_policy_v1();
    let source = match transport {
        WindowsPacketCaptureTransport::TcpTls => {
            WindowsPacketHostnameEvidenceSource::TlsClientHelloSni
        }
        WindowsPacketCaptureTransport::UdpQuic => {
            WindowsPacketHostnameEvidenceSource::QuicInitialSni
        }
        WindowsPacketCaptureTransport::Other => {
            WindowsPacketHostnameEvidenceSource::TlsClientHelloSni
        }
    };
    let observation = WindowsPacketCaptureObservation {
        capture_generation,
        flow_id,
        transport,
        destination: "104.16.58.5".to_owned(),
        observed_at_ms: 1_100,
        expires_at_ms: 5_000,
        attribution: WindowsPacketCaptureAttribution::Hostname {
            source,
            host: host.to_owned(),
        },
    };
    let classification = match classify_windows_packet_capture(&observation, 1_200, &policy_tables)
    {
        WindowsPacketCaptureDecision::PolicyClassified(classification) => classification,
        other => panic!("{host} should be policy-classified, got {other:?}"),
    };
    let egress = prepare_windows_packet_egress(&egress_request_for(capture_generation, flow_id))
        .expect("valid egress fixture");
    let request = WindowsDataPlaneRequest {
        request_id: format!("packet-{}-{session_id}", observation.flow_id),
        policy: classify_route_policy(host, &policy_tables),
        backend,
        started_at_ms: 1_200,
        first_payload_deadline_at_ms: 4_000,
    };
    prepare_windows_packet_flow(
        &classification,
        &egress,
        session_id,
        &request,
        1_200,
        &policy_tables,
    )
}

fn apply(
    state: &mut WindowsPacketFlowRegistry,
    event: WindowsPacketFlowEvent,
    config: &WindowsPacketFlowConfig,
) -> Vec<WindowsPacketFlowCommand> {
    let transition = reduce_windows_packet_flow(state, &event, config)
        .unwrap_or_else(|error| panic!("{event:?}: {error}"));
    *state = transition.state;
    transition.commands
}

fn fixture_event(
    event: FixtureEvent,
    key: slipstream_windows_adapter::packet_flow::WindowsPacketFlowKey,
) -> WindowsPacketFlowEvent {
    match event {
        FixtureEvent::BackendReady { now_ms } => {
            WindowsPacketFlowEvent::BackendReady { now_ms, key }
        }
        FixtureEvent::Payload {
            now_ms,
            direction,
            sequence,
            bytes,
        } => WindowsPacketFlowEvent::Payload {
            now_ms,
            key,
            direction,
            sequence,
            bytes,
        },
        FixtureEvent::Forwarded {
            now_ms,
            direction,
            through_sequence,
        } => WindowsPacketFlowEvent::Forwarded {
            now_ms,
            key,
            direction,
            through_sequence,
        },
        FixtureEvent::HalfClosed { now_ms, direction } => WindowsPacketFlowEvent::HalfClosed {
            now_ms,
            key,
            direction,
        },
        FixtureEvent::DatagramSideClosed { now_ms } => {
            WindowsPacketFlowEvent::DatagramSideClosed { now_ms, key }
        }
        FixtureEvent::Reset {
            now_ms,
            direction,
            reason,
        } => WindowsPacketFlowEvent::Reset {
            now_ms,
            key,
            direction,
            reason,
        },
        FixtureEvent::Cancelled { now_ms } => WindowsPacketFlowEvent::Cancelled { now_ms, key },
        FixtureEvent::IdleDeadline { now_ms } => {
            WindowsPacketFlowEvent::IdleDeadline { now_ms, key }
        }
        FixtureEvent::BackpressureDeadline { now_ms, direction } => {
            WindowsPacketFlowEvent::BackpressureDeadline {
                now_ms,
                key,
                direction,
            }
        }
    }
}

fn direction_name(direction: WindowsPacketFlowDirection) -> &'static str {
    match direction {
        WindowsPacketFlowDirection::ClientToBackend => "client_to_backend",
        WindowsPacketFlowDirection::BackendToClient => "backend_to_client",
    }
}

fn command_summary(command: &WindowsPacketFlowCommand) -> String {
    match command {
        WindowsPacketFlowCommand::OpenBackend { .. } => "open_backend".to_owned(),
        WindowsPacketFlowCommand::Forward { direction, .. } => {
            format!("forward_{}", direction_name(*direction))
        }
        WindowsPacketFlowCommand::PauseReads { direction, .. } => {
            format!("pause_{}", direction_name(*direction))
        }
        WindowsPacketFlowCommand::ResumeReads { direction, .. } => {
            format!("resume_{}", direction_name(*direction))
        }
        WindowsPacketFlowCommand::HalfCloseWrite { direction, .. } => {
            format!("half_close_{}", direction_name(*direction))
        }
        WindowsPacketFlowCommand::CloseFlow { .. } => "close_flow".to_owned(),
        WindowsPacketFlowCommand::ScheduleIdleDeadline { .. } => "schedule_idle".to_owned(),
        WindowsPacketFlowCommand::ScheduleBackpressureDeadline { .. } => {
            "schedule_backpressure".to_owned()
        }
        WindowsPacketFlowCommand::DataPlane { event } => match event {
            WindowsDataPlaneEvent::BackendConnected { .. } => "backend_connected".to_owned(),
            WindowsDataPlaneEvent::PayloadReceived { .. } => "backend_payload".to_owned(),
            WindowsDataPlaneEvent::BackendReset { .. } => "backend_reset".to_owned(),
            WindowsDataPlaneEvent::BackendClosed { .. } => "backend_closed".to_owned(),
            WindowsDataPlaneEvent::CancelRequested { .. } => "cancel_requested".to_owned(),
            WindowsDataPlaneEvent::SessionCancelled { .. } => "session_cancelled".to_owned(),
            other => panic!("unexpected packet-flow data-plane event: {other:?}"),
        },
        WindowsPacketFlowCommand::RejectFlow { .. } => "reject_flow".to_owned(),
    }
}

fn tcp_admission() -> WindowsPacketFlowAdmission {
    admission(
        "updates.discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::TcpTls,
    )
    .expect("protected local bypass should be admitted locally")
}

fn opened_registry(
    config: &WindowsPacketFlowConfig,
) -> (WindowsPacketFlowRegistry, WindowsPacketFlowAdmission) {
    let admission = tcp_admission();
    let mut state = WindowsPacketFlowRegistry::new(1_200);
    apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_200,
            admission: admission.clone(),
        },
        config,
    );
    (state, admission)
}

#[test]
fn contract_freezes_pure_and_bounded_v1_invariants() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_packet_flow");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_PACKET_FLOW_CONTRACT_VERSION
    );
    for invariant in [
        "pure_forwarding_contract_only",
        "capture_classification_and_egress_plan_bound",
        "open_backend_preserves_full_egress_binding",
        "admission_expires_by_first_payload_deadline",
        "active_policy_revalidated",
        "protected_local_bypass_never_uses_geph",
        "ordered_payload_frames",
        "unissued_frames_cannot_be_acknowledged",
        "payload_bytes_remain_effect_owned_by_flow_key",
        "payload_and_queue_sizes_bounded",
        "frame_count_and_aggregate_budget_bounded",
        "high_low_watermark_backpressure",
        "backpressure_timeout_bounded",
        "idle_timeout_bounded",
        "tcp_half_close_preserved_after_queue_drain",
        "early_client_half_close_survives_backend_open",
        "closed_input_never_resumes_reads",
        "udp_datagram_boundaries_preserved",
        "reset_clears_owned_queues",
        "rejected_open_cancels_unowned_session",
        "capture_flow_identity_remains_owned_until_generation_retirement",
        "capture_generation_retirement_is_monotonic",
        "retired_generation_cannot_reopen",
        "terminal_history_bounded",
    ] {
        assert_eq!(fixture.invariants[invariant], true, "{invariant}");
    }
    for invariant in [
        "native_socket_effect",
        "native_packet_effect",
        "native_adapter_effect",
        "native_route_effect",
        "system_dns_mutation",
        "proxy_pac_vpn_mutation",
        "process_or_service_effect",
        "production_service_host_composition",
    ] {
        assert_eq!(fixture.invariants[invariant], false, "{invariant}");
    }
    assert!(fixture
        .remaining_native_gates
        .as_object()
        .expect("remaining gates must be an object")
        .values()
        .all(|value| value == "required"));
}

#[test]
fn language_neutral_vectors_cover_tcp_udp_backpressure_and_cancellation() {
    let fixture = contract();
    for vector in fixture.vectors {
        let packet_transport = match vector.transport {
            WindowsPacketFlowTransport::Tcp => WindowsPacketCaptureTransport::TcpTls,
            WindowsPacketFlowTransport::Udp => WindowsPacketCaptureTransport::UdpQuic,
        };
        let admission = admission_with_key(
            &vector.host,
            vector.backend,
            packet_transport,
            vector.capture_generation,
            vector.flow_id,
        )
        .unwrap_or_else(|error| panic!("{} admission: {error:?}", vector.name));
        let key = admission.key();
        let mut state = WindowsPacketFlowRegistry::new(1_200);
        let mut emitted = apply(
            &mut state,
            WindowsPacketFlowEvent::FlowOpened {
                now_ms: 1_200,
                admission,
            },
            &fixture.config,
        )
        .iter()
        .map(command_summary)
        .collect::<Vec<_>>();
        for event in vector.events {
            emitted.extend(
                apply(&mut state, fixture_event(event, key), &fixture.config)
                    .iter()
                    .map(command_summary),
            );
        }
        let flow = &state.flows[&key];
        assert_eq!(flow.phase, vector.expected.phase, "{} phase", vector.name);
        assert_eq!(
            flow.resource_owned, vector.expected.resource_owned,
            "{} ownership",
            vector.name
        );
        assert_eq!(
            flow.queued_bytes(WindowsPacketFlowDirection::ClientToBackend),
            vector.expected.client_to_backend_bytes,
            "{} client queue",
            vector.name
        );
        assert_eq!(
            flow.queued_bytes(WindowsPacketFlowDirection::BackendToClient),
            vector.expected.backend_to_client_bytes,
            "{} backend queue",
            vector.name
        );
        assert_eq!(
            flow.terminal_reason, vector.expected.terminal_reason,
            "{} reason",
            vector.name
        );
        for required in vector.expected.must_emit {
            assert!(
                emitted.contains(&required),
                "{} missing {required}; emitted {emitted:?}",
                vector.name
            );
        }
    }
}

#[test]
fn admission_binds_capture_egress_policy_and_protected_routes() {
    let local = tcp_admission();
    assert_eq!(local.key().transport, WindowsPacketFlowTransport::Tcp);
    assert_eq!(local.destination(), "104.16.58.5");
    assert_eq!(local.destination_port(), 443);
    assert_eq!(local.expires_at_ms(), 4_000);
    assert_eq!(local.egress().route_epoch(), 10);
    assert_eq!(local.egress().source_address().to_string(), "10.0.0.4");
    assert_eq!(local.egress().egress_interface().luid, 120);
    assert_eq!(local.egress().egress_interface().index, 12);
    assert_eq!(
        local.egress().socket_binding(),
        WindowsPacketSocketInterfaceBinding::Ipv4NetworkByteOrder(12_u32.to_be())
    );
    assert_eq!(
        local.request().backend,
        WindowsDataPlaneBackend::LocalEngine
    );

    assert_eq!(
        admission(
            "updates.discord.com",
            WindowsDataPlaneBackend::Geph,
            WindowsPacketCaptureTransport::TcpTls,
        ),
        Err(WindowsPacketFlowAdmissionErrorCode::InvalidDataPlaneRequest)
    );
    let geo = admission(
        "chatgpt.com",
        WindowsDataPlaneBackend::Geph,
        WindowsPacketCaptureTransport::TcpTls,
    )
    .expect("geo-exit may use verified Geph");
    assert_eq!(geo.request().backend, WindowsDataPlaneBackend::Geph);

    let mut state = WindowsPacketFlowRegistry::new(1_200);
    let commands = apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_200,
            admission: local.clone(),
        },
        &contract().config,
    );
    assert!(commands.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::OpenBackend {
            egress,
            destination_port: 443,
            ..
        } if egress == local.egress()
    )));

    let mut delayed = WindowsPacketFlowRegistry::new(1_200);
    let rejected = apply(
        &mut delayed,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 4_000,
            admission: local,
        },
        &contract().config,
    );
    assert!(rejected.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::RejectFlow { reason, .. }
            if reason == "admission_expired"
    )));
}

#[test]
fn duplicate_open_is_idempotent_and_flow_limit_cancels_the_unowned_session() {
    let mut config = contract().config;
    config.max_active_flows = 1;
    let first = tcp_admission();
    let mut state = WindowsPacketFlowRegistry::new(1_200);
    apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_200,
            admission: first.clone(),
        },
        &config,
    );
    let duplicate = apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_201,
            admission: first,
        },
        &config,
    );
    assert!(duplicate.is_empty());
    assert_eq!(state.active_flow_count(), 1);

    let second = admission_with_key(
        "updates.discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::TcpTls,
        8,
        42,
    )
    .expect("second protected flow should be valid");
    let second_key = second.key();
    let rejected = apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_202,
            admission: second,
        },
        &config,
    );
    assert!(!state.flows.contains_key(&second_key));
    assert!(rejected.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::RejectFlow { key, reason }
            if *key == second_key && reason == "flow_limit"
    )));
    assert!(rejected.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::DataPlane {
            event: WindowsDataPlaneEvent::SessionCancelled { .. }
        }
    )));
}

#[test]
fn capture_identity_tombstone_blocks_new_session_and_survives_terminal_pruning() {
    let mut config = contract().config;
    config.max_retained_terminal_flows = 1;
    let first = admission_with_owner(
        "updates.discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::TcpTls,
        7,
        41,
        9,
    )
    .expect("first owner should be admitted");
    let first_key = first.key();
    let mut state = WindowsPacketFlowRegistry::new(1_200);
    apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_200,
            admission: first,
        },
        &config,
    );
    assert_eq!(
        reduce_windows_packet_flow(
            &state,
            &WindowsPacketFlowEvent::CaptureGenerationRetired {
                now_ms: 1_205,
                capture_generation: 7,
            },
            &config,
        ),
        Err(slipstream_windows_adapter::packet_flow::WindowsPacketFlowError::ActiveCaptureGenerationRetirement)
    );
    apply(
        &mut state,
        WindowsPacketFlowEvent::Reset {
            now_ms: 1_210,
            key: first_key,
            direction: WindowsPacketFlowDirection::BackendToClient,
            reason: "closed".to_owned(),
        },
        &config,
    );

    let same_capture_new_session = admission_with_owner(
        "updates.discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::TcpTls,
        7,
        41,
        10,
    )
    .expect("second session has independently valid boundary evidence");
    let second_key = same_capture_new_session.key();
    let rejected = apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_220,
            admission: same_capture_new_session,
        },
        &config,
    );
    assert!(!state.flows.contains_key(&second_key));
    assert!(rejected.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::RejectFlow { reason, .. }
            if reason == "capture_flow_already_owned"
    )));

    apply(
        &mut state,
        WindowsPacketFlowEvent::CaptureGenerationRetired {
            now_ms: 1_230,
            capture_generation: 7,
        },
        &config,
    );
    assert!(state.flows.is_empty());
    assert!(state.capture_flow_owners.is_empty());
    assert_eq!(state.retired_capture_generation_high_watermark, 7);

    let retired_replay = admission_with_owner(
        "updates.discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::TcpTls,
        7,
        41,
        11,
    )
    .expect("old evidence remains structurally valid inside its original lifetime");
    let replay = apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_240,
            admission: retired_replay,
        },
        &config,
    );
    assert!(state.flows.is_empty());
    assert!(replay.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::RejectFlow { reason, .. }
            if reason == "capture_generation_retired"
    )));
}

#[test]
fn queued_payload_waits_for_backend_and_backpressure_resumes_at_low_watermark() {
    let config = contract().config;
    let (mut state, admission) = opened_registry(&config);
    let key = admission.key();

    let first = apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_210,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 1,
            bytes: 4,
        },
        &config,
    );
    assert!(!first
        .iter()
        .any(|command| matches!(command, WindowsPacketFlowCommand::Forward { .. })));

    let second = apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_220,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 2,
            bytes: 2,
        },
        &config,
    );
    assert!(second.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::PauseReads {
            direction: WindowsPacketFlowDirection::ClientToBackend,
            ..
        }
    )));
    assert!(state.flows[&key].reads_paused(WindowsPacketFlowDirection::ClientToBackend));

    let ready = apply(
        &mut state,
        WindowsPacketFlowEvent::BackendReady { now_ms: 1_230, key },
        &config,
    );
    assert_eq!(
        ready
            .iter()
            .filter(|command| matches!(command, WindowsPacketFlowCommand::Forward { .. }))
            .count(),
        2
    );

    let drained = apply(
        &mut state,
        WindowsPacketFlowEvent::Forwarded {
            now_ms: 1_240,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            through_sequence: 1,
        },
        &config,
    );
    assert!(drained.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::ResumeReads {
            direction: WindowsPacketFlowDirection::ClientToBackend,
            ..
        }
    )));
    assert_eq!(
        state.flows[&key].queued_bytes(WindowsPacketFlowDirection::ClientToBackend),
        2
    );
}

#[test]
fn acknowledgement_before_backend_readiness_cannot_consume_queued_payload() {
    let config = contract().config;
    let (mut state, admission) = opened_registry(&config);
    let key = admission.key();
    apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_210,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 1,
            bytes: 2,
        },
        &config,
    );

    assert_eq!(
        reduce_windows_packet_flow(
            &state,
            &WindowsPacketFlowEvent::Forwarded {
                now_ms: 1_220,
                key,
                direction: WindowsPacketFlowDirection::ClientToBackend,
                through_sequence: 1,
            },
            &config,
        ),
        Err(slipstream_windows_adapter::packet_flow::WindowsPacketFlowError::InvalidForwardAcknowledgement)
    );
    assert_eq!(
        state.flows[&key].queued_bytes(WindowsPacketFlowDirection::ClientToBackend),
        2
    );
    let ready = apply(
        &mut state,
        WindowsPacketFlowEvent::BackendReady { now_ms: 1_230, key },
        &config,
    );
    assert!(ready.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::Forward {
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 1,
            bytes: 2,
            ..
        }
    )));
}

#[test]
fn tcp_half_closes_are_forwarded_only_after_each_queue_drains() {
    let config = contract().config;
    let (mut state, admission) = opened_registry(&config);
    let key = admission.key();
    apply(
        &mut state,
        WindowsPacketFlowEvent::BackendReady { now_ms: 1_210, key },
        &config,
    );
    apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_220,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 1,
            bytes: 2,
        },
        &config,
    );
    let half = apply(
        &mut state,
        WindowsPacketFlowEvent::HalfClosed {
            now_ms: 1_230,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
        },
        &config,
    );
    assert!(!half
        .iter()
        .any(|command| matches!(command, WindowsPacketFlowCommand::HalfCloseWrite { .. })));
    let drained = apply(
        &mut state,
        WindowsPacketFlowEvent::Forwarded {
            now_ms: 1_240,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            through_sequence: 1,
        },
        &config,
    );
    assert!(drained.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::HalfCloseWrite {
            direction: WindowsPacketFlowDirection::ClientToBackend,
            ..
        }
    )));

    let backend_payload = apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_250,
            key,
            direction: WindowsPacketFlowDirection::BackendToClient,
            sequence: 1,
            bytes: 2,
        },
        &config,
    );
    assert!(!backend_payload.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::DataPlane {
            event: WindowsDataPlaneEvent::PayloadReceived { .. }
        }
    )));
    let client_delivery = apply(
        &mut state,
        WindowsPacketFlowEvent::Forwarded {
            now_ms: 1_260,
            key,
            direction: WindowsPacketFlowDirection::BackendToClient,
            through_sequence: 1,
        },
        &config,
    );
    assert!(client_delivery.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::DataPlane {
            event: WindowsDataPlaneEvent::PayloadReceived { bytes: 2, .. }
        }
    )));
    let terminal = apply(
        &mut state,
        WindowsPacketFlowEvent::HalfClosed {
            now_ms: 1_270,
            key,
            direction: WindowsPacketFlowDirection::BackendToClient,
        },
        &config,
    );
    assert_eq!(state.flows[&key].phase, WindowsPacketFlowPhase::Succeeded);
    assert!(!state.flows[&key].resource_owned);
    assert!(terminal.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::DataPlane {
            event: WindowsDataPlaneEvent::BackendClosed { .. }
        }
    )));
}

#[test]
fn closed_input_clears_backpressure_without_resuming_reads() {
    let config = contract().config;
    let (mut state, admission) = opened_registry(&config);
    let key = admission.key();
    for (now_ms, sequence, bytes) in [(1_210, 1, 4), (1_220, 2, 2)] {
        apply(
            &mut state,
            WindowsPacketFlowEvent::Payload {
                now_ms,
                key,
                direction: WindowsPacketFlowDirection::ClientToBackend,
                sequence,
                bytes,
            },
            &config,
        );
    }
    apply(
        &mut state,
        WindowsPacketFlowEvent::HalfClosed {
            now_ms: 1_230,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
        },
        &config,
    );
    apply(
        &mut state,
        WindowsPacketFlowEvent::BackendReady { now_ms: 1_240, key },
        &config,
    );

    let drained = apply(
        &mut state,
        WindowsPacketFlowEvent::Forwarded {
            now_ms: 1_250,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            through_sequence: 1,
        },
        &config,
    );
    assert!(!state.flows[&key].reads_paused(WindowsPacketFlowDirection::ClientToBackend));
    assert!(!drained.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::ResumeReads {
            direction: WindowsPacketFlowDirection::ClientToBackend,
            ..
        }
    )));
}

#[test]
fn udp_keeps_datagrams_distinct_and_closes_after_both_queues_drain() {
    let config = contract().config;
    let admission = admission(
        "chatgpt.com",
        WindowsDataPlaneBackend::Geph,
        WindowsPacketCaptureTransport::UdpQuic,
    )
    .expect("geo UDP classification should be admitted");
    let key = admission.key();
    let mut state = WindowsPacketFlowRegistry::new(1_200);
    apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_200,
            admission,
        },
        &config,
    );
    apply(
        &mut state,
        WindowsPacketFlowEvent::BackendReady { now_ms: 1_210, key },
        &config,
    );
    let first = apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_220,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 1,
            bytes: 2,
        },
        &config,
    );
    let second = apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_230,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 2,
            bytes: 1,
        },
        &config,
    );
    assert!(first.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::Forward {
            sequence: 1,
            bytes: 2,
            ..
        }
    )));
    assert!(second.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::Forward {
            sequence: 2,
            bytes: 1,
            ..
        }
    )));
    apply(
        &mut state,
        WindowsPacketFlowEvent::DatagramSideClosed { now_ms: 1_240, key },
        &config,
    );
    assert_eq!(state.flows[&key].phase, WindowsPacketFlowPhase::Draining);
    apply(
        &mut state,
        WindowsPacketFlowEvent::Forwarded {
            now_ms: 1_250,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            through_sequence: 2,
        },
        &config,
    );
    assert_eq!(state.flows[&key].phase, WindowsPacketFlowPhase::Succeeded);
}

#[test]
fn udp_close_before_backend_ready_cancels_instead_of_claiming_success() {
    let config = contract().config;
    let admission = admission(
        "chatgpt.com",
        WindowsDataPlaneBackend::Geph,
        WindowsPacketCaptureTransport::UdpQuic,
    )
    .expect("geo UDP classification should be admitted");
    let key = admission.key();
    let mut state = WindowsPacketFlowRegistry::new(1_200);
    apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_200,
            admission,
        },
        &config,
    );
    let commands = apply(
        &mut state,
        WindowsPacketFlowEvent::DatagramSideClosed { now_ms: 1_210, key },
        &config,
    );
    assert_eq!(state.flows[&key].phase, WindowsPacketFlowPhase::Cancelled);
    assert!(commands.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::DataPlane {
            event: WindowsDataPlaneEvent::SessionCancelled { .. }
        }
    )));
    assert!(!commands.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::DataPlane {
            event: WindowsDataPlaneEvent::BackendClosed { .. }
        }
    )));
}

#[test]
fn reset_timeout_and_sequence_errors_are_bounded_and_terminal() {
    let config = contract().config;
    let (mut state, admission) = opened_registry(&config);
    let key = admission.key();
    assert!(reduce_windows_packet_flow(
        &state,
        &WindowsPacketFlowEvent::Payload {
            now_ms: 1_210,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 2,
            bytes: 1,
        },
        &config,
    )
    .is_err());

    let reset = apply(
        &mut state,
        WindowsPacketFlowEvent::Reset {
            now_ms: 1_220,
            key,
            direction: WindowsPacketFlowDirection::BackendToClient,
            reason: "upstream reset".to_owned(),
        },
        &config,
    );
    assert_eq!(state.flows[&key].phase, WindowsPacketFlowPhase::Failed);
    assert!(!state.flows[&key].resource_owned);
    assert!(reset.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::DataPlane {
            event: WindowsDataPlaneEvent::BackendReset { .. }
        }
    )));

    let admission = tcp_admission();
    let timeout_key = admission.key();
    let mut timed = WindowsPacketFlowRegistry::new(1_200);
    apply(
        &mut timed,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_200,
            admission,
        },
        &config,
    );
    apply(
        &mut timed,
        WindowsPacketFlowEvent::IdleDeadline {
            now_ms: 2_200,
            key: timeout_key,
        },
        &config,
    );
    assert_eq!(
        timed.flows[&timeout_key].phase,
        WindowsPacketFlowPhase::Failed
    );
    assert_eq!(
        timed.flows[&timeout_key].terminal_reason,
        "packet_flow_idle_timeout"
    );
}

#[test]
fn sustained_backpressure_closes_only_the_owned_flow() {
    let config = contract().config;
    let (mut state, admission) = opened_registry(&config);
    let key = admission.key();
    apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_210,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 1,
            bytes: 4,
        },
        &config,
    );
    apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_220,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 2,
            bytes: 2,
        },
        &config,
    );
    assert!(state.flows[&key].reads_paused(WindowsPacketFlowDirection::ClientToBackend));
    let commands = apply(
        &mut state,
        WindowsPacketFlowEvent::BackpressureDeadline {
            now_ms: 1_470,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
        },
        &config,
    );
    assert_eq!(state.flows[&key].phase, WindowsPacketFlowPhase::Failed);
    assert_eq!(
        state.flows[&key].queued_bytes(WindowsPacketFlowDirection::ClientToBackend),
        0
    );
    assert_eq!(
        state.flows[&key].terminal_reason,
        "packet_flow_backpressure_timeout"
    );
    assert!(commands.iter().any(|command| matches!(
        command,
        WindowsPacketFlowCommand::CloseFlow { key: closed } if *closed == key
    )));
}

#[test]
fn frame_count_bound_rejects_many_tiny_chunks_before_byte_capacity() {
    let mut config = contract().config;
    config.max_queued_frames_per_direction = 1;
    let (mut state, admission) = opened_registry(&config);
    let key = admission.key();
    apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_210,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 1,
            bytes: 1,
        },
        &config,
    );
    apply(
        &mut state,
        WindowsPacketFlowEvent::Payload {
            now_ms: 1_220,
            key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            sequence: 2,
            bytes: 1,
        },
        &config,
    );
    assert_eq!(state.flows[&key].phase, WindowsPacketFlowPhase::Failed);
    assert_eq!(state.flows[&key].terminal_reason, "packet_flow_frame_limit");
    assert_eq!(
        state.flows[&key].queued_bytes(WindowsPacketFlowDirection::ClientToBackend),
        0
    );
}

#[test]
fn terminal_history_is_pruned_deterministically() {
    let mut config = contract().config;
    config.max_retained_terminal_flows = 1;
    let first = tcp_admission();
    let mut state = WindowsPacketFlowRegistry::new(1_200);
    apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_200,
            admission: first.clone(),
        },
        &config,
    );
    apply(
        &mut state,
        WindowsPacketFlowEvent::Reset {
            now_ms: 1_210,
            key: first.key(),
            direction: WindowsPacketFlowDirection::BackendToClient,
            reason: "first".to_owned(),
        },
        &config,
    );

    let second = admission_with_key(
        "updates.discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::TcpTls,
        8,
        42,
    )
    .expect("second protected flow should be admitted locally");
    let second_key = second.key();
    apply(
        &mut state,
        WindowsPacketFlowEvent::FlowOpened {
            now_ms: 1_220,
            admission: second,
        },
        &config,
    );
    apply(
        &mut state,
        WindowsPacketFlowEvent::Reset {
            now_ms: 1_230,
            key: second_key,
            direction: WindowsPacketFlowDirection::BackendToClient,
            reason: "second".to_owned(),
        },
        &config,
    );
    assert_eq!(state.flows.len(), 1);
    assert!(!state.flows.contains_key(&first.key()));
    assert_eq!(state.flows[&second_key].terminal_reason, "second");
}

#[test]
fn pure_source_and_production_host_remain_uncomposed() {
    let source = include_str!("../src/packet_flow/v1.rs");
    for forbidden in [
        "windows_sys",
        "TcpStream",
        "UdpSocket",
        "Wintun",
        "CreateProcess",
        "TerminateProcess",
        "Command::new",
        "std::fs::",
        "std::net::",
        "std::process::",
        "socket2::",
        "Set-DnsClientServerAddress",
        "ProxyEnable",
        "VpnService",
    ] {
        assert!(
            !source.contains(forbidden),
            "pure contract contains {forbidden}"
        );
    }
    let service_host = include_str!("../src/service_host/v1.rs");
    let worker_host = include_str!("../src/worker_host/v1.rs");
    assert!(!service_host.contains("packet_flow"));
    assert!(!worker_host.contains("packet_flow"));
}

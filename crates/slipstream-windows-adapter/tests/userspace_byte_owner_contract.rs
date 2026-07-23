mod support;

use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_windows_adapter::data_plane::WindowsDataPlaneBackend;
use slipstream_windows_adapter::packet_adapter::v4::WindowsPacketCaptureTransport;
use slipstream_windows_adapter::packet_flow::{
    reduce_windows_packet_flow, WindowsPacketFlowCommand, WindowsPacketFlowConfig,
    WindowsPacketFlowDirection, WindowsPacketFlowEvent, WindowsPacketFlowKey,
    WindowsPacketFlowRegistry,
};
use slipstream_windows_adapter::userspace_stack_bridge::{
    bind_windows_userspace_flow, WindowsUserspaceByteDelivery, WindowsUserspaceByteEffects,
    WindowsUserspaceByteOwner, WindowsUserspaceByteOwnerConfig, WindowsUserspaceByteOwnerErrorCode,
    WINDOWS_USERSPACE_BYTE_OWNER_CONTRACT_VERSION,
};
use support::userspace_fixture::{
    admission, classification, flow_open_event, AdmissionFixture, ClassificationFixture,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-userspace-byte-owner-v1.json");
const STACK_SELECTION: &str =
    include_str!("../../../contracts/windows-userspace-stack-selection-v1.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    selected_stack: SelectedStackFixture,
    config: WindowsUserspaceByteOwnerConfig,
    invariants: Value,
    vectors: Vec<ByteOwnerVector>,
}

#[derive(Debug, Deserialize)]
struct SelectedStackFixture {
    contract: String,
    contract_version: u32,
    #[serde(rename = "crate")]
    crate_name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct ByteOwnerVector {
    name: String,
    action: String,
    backend_ready: bool,
    direction: WindowsPacketFlowDirection,
    sequence: u64,
    declared_bytes: usize,
    payload: Vec<u8>,
    effect: String,
    forward_bytes: Option<usize>,
    expected: ExpectedByteOwner,
}

#[derive(Debug, Deserialize)]
struct ExpectedByteOwner {
    disposition: String,
    error: Option<WindowsUserspaceByteOwnerErrorCode>,
    owned_frames: usize,
    owned_bytes: usize,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Windows userspace byte-owner v1 must be valid JSON")
}

fn packet_flow_config() -> WindowsPacketFlowConfig {
    WindowsPacketFlowConfig {
        max_active_flows: 8,
        max_retained_terminal_flows: 2,
        max_retained_flow_identities: 16,
        max_chunk_bytes: 4,
        max_queued_frames_per_direction: 4,
        high_watermark_bytes: 6,
        low_watermark_bytes: 2,
        max_buffered_bytes: 8,
        idle_timeout_ms: 1_000,
        backpressure_timeout_ms: 250,
    }
}

fn fixture_pair(
    capture_generation: u64,
    flow_id: u64,
) -> (ClassificationFixture, AdmissionFixture) {
    (
        ClassificationFixture {
            capture_generation,
            flow_id,
            transport: WindowsPacketCaptureTransport::TcpTls,
            source_address: "10.254.0.2".parse().expect("fixed client address"),
            source_port: 55_000 + u16::try_from(flow_id % 100).expect("bounded fixture port"),
            destination: "104.16.58.5".to_owned(),
            destination_port: 443,
            host: "discord.com".to_owned(),
            expires_at_ms: 5_000,
        },
        AdmissionFixture {
            capture_generation,
            flow_id,
            transport: WindowsPacketCaptureTransport::TcpTls,
            destination: "104.16.58.5".to_owned(),
            destination_port: 443,
            host: "discord.com".to_owned(),
            backend: WindowsDataPlaneBackend::LocalEngine,
        },
    )
}

fn open_flow(
    owner: &mut WindowsUserspaceByteOwner,
    state: WindowsPacketFlowRegistry,
    capture_generation: u64,
    flow_id: u64,
) -> (WindowsPacketFlowRegistry, WindowsPacketFlowKey) {
    open_flow_at(
        owner,
        state,
        capture_generation,
        flow_id,
        1_300,
        &packet_flow_config(),
    )
}

fn open_flow_at(
    owner: &mut WindowsUserspaceByteOwner,
    state: WindowsPacketFlowRegistry,
    capture_generation: u64,
    flow_id: u64,
    now_ms: u64,
    config: &WindowsPacketFlowConfig,
) -> (WindowsPacketFlowRegistry, WindowsPacketFlowKey) {
    let policy_tables = bundled_policy_v1();
    let (classification_fixture, admission_fixture) = fixture_pair(capture_generation, flow_id);
    let classification = classification(&classification_fixture, &policy_tables);
    let admission = admission(&admission_fixture, &policy_tables);
    let binding = bind_windows_userspace_flow(&classification, &admission, now_ms)
        .expect("exact fixture binding");
    let key = binding.key();
    let event = flow_open_event(admission, now_ms, &policy_tables);
    let transition =
        reduce_windows_packet_flow(state.clone(), &event, config).expect("packet flow open");
    owner
        .open_flow(binding, &event, &state, &transition, config)
        .expect("byte owner open");
    (transition.state, key)
}

fn reduce(
    state: &WindowsPacketFlowRegistry,
    event: &WindowsPacketFlowEvent,
) -> slipstream_windows_adapter::packet_flow::WindowsPacketFlowTransition {
    reduce_windows_packet_flow(state.clone(), event, &packet_flow_config())
        .expect("packet-flow transition")
}

#[derive(Default)]
struct RecordingByteEffect {
    fail: bool,
    deliveries: Vec<(
        WindowsPacketFlowKey,
        WindowsPacketFlowDirection,
        u64,
        Vec<u8>,
    )>,
}

impl WindowsUserspaceByteEffects for RecordingByteEffect {
    type Error = &'static str;

    fn forward(&mut self, delivery: &WindowsUserspaceByteDelivery<'_>) -> Result<(), Self::Error> {
        if self.fail {
            return Err("injected stack effect failed");
        }
        assert_eq!(delivery.binding().key(), delivery.key());
        assert_eq!(delivery.binding().tuple().source.port, 55_041);
        self.deliveries.push((
            delivery.key(),
            delivery.direction(),
            delivery.sequence(),
            delivery.bytes().to_vec(),
        ));
        Ok(())
    }
}

#[derive(Default)]
struct FailSecondDeliveryOnce {
    delivered_sequences: Vec<u64>,
    failed_once: bool,
}

impl WindowsUserspaceByteEffects for FailSecondDeliveryOnce {
    type Error = &'static str;

    fn forward(&mut self, delivery: &WindowsUserspaceByteDelivery<'_>) -> Result<(), Self::Error> {
        if self.delivered_sequences.len() == 1 && !self.failed_once {
            self.failed_once = true;
            return Err("injected second-delivery failure");
        }
        self.delivered_sequences.push(delivery.sequence());
        Ok(())
    }
}

#[test]
fn byte_owner_contract_freezes_selected_stack_and_effect_boundaries() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_userspace_byte_owner");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_USERSPACE_BYTE_OWNER_CONTRACT_VERSION
    );

    let selection: Value = serde_json::from_str(STACK_SELECTION).expect("stack selection JSON");
    assert_eq!(fixture.selected_stack.contract, selection["contract"]);
    assert_eq!(
        fixture.selected_stack.contract_version,
        selection["contract_version"]
    );
    assert_eq!(
        fixture.selected_stack.crate_name,
        selection["selected_stack"]["crate"]
    );
    assert_eq!(
        fixture.selected_stack.version,
        selection["selected_stack"]["version"]
    );
    assert_eq!(
        fixture.config,
        WindowsUserspaceByteOwnerConfig::from_packet_flow(&packet_flow_config())
            .expect("packet-flow bounds must produce byte-owner bounds")
    );
    assert_eq!(fixture.config.max_owned_frames(), Some(64));
    assert_eq!(fixture.config.max_owned_bytes(), Some(128));

    for invariant in [
        "opaque_tuple_binding_required",
        "exact_open_admission_capability_required",
        "exact_backend_open_command_set_required",
        "open_exact_reduction_required",
        "full_admission_preserved_across_payload_and_reconcile",
        "payload_exact_reduction_required",
        "active_reconcile_exact_reduction_required",
        "forwarded_event_requires_effect_path",
        "terminal_history_pruning_preserves_delivery",
        "successful_packet_flow_payload_transition_required",
        "exact_packet_flow_predecessor_required",
        "payload_queue_delta_required",
        "exact_flow_direction_sequence_and_length_owned",
        "payload_bytes_retained_until_atomic_effect_success",
        "forward_requires_retained_transition_authorization",
        "pre_backend_client_forward_rejected",
        "forward_acknowledgement_preflight_required",
        "global_registry_watermark_required",
        "terminal_forward_releases_owner",
        "effect_failure_retains_exact_payload",
        "duplicate_and_out_of_order_payload_rejected",
        "per_flow_directional_memory_bounded",
        "terminal_cleanup_is_event_scoped",
        "destructive_cleanup_exact_transition_required",
        "same_timestamp_stale_terminal_transition_cannot_remove_newer_bytes",
        "generation_retirement_is_bounded_and_stale_safe",
        "selected_stack_effect_is_injected",
    ] {
        assert_eq!(fixture.invariants[invariant], true, "{invariant}");
    }
    for invariant in [
        "frozen_packet_flow_v1_modified",
        "selected_stack_instantiated_in_adapter",
        "native_packet_effect",
        "native_socket_effect",
        "wintun_loading",
        "adapter_or_route_mutation",
        "system_dns_mutation",
        "proxy_pac_vpn_mutation",
        "process_or_service_effect",
        "production_service_host_composition",
    ] {
        assert_eq!(fixture.invariants[invariant], false, "{invariant}");
    }
}

#[test]
fn opening_rejects_same_key_transitions_from_other_admission_capabilities() {
    let policy_tables = bundled_policy_v1();
    let (classification_fixture, admission_fixture) = fixture_pair(7, 41);
    let mut other_request = admission_fixture.clone();
    other_request.host = "youtube.com".to_owned();
    let mut other_destination = admission_fixture.clone();
    other_destination.destination = "104.16.58.6".to_owned();

    for mismatched_fixture in [other_request, other_destination] {
        let classification = classification(&classification_fixture, &policy_tables);
        let binding_admission = admission(&admission_fixture, &policy_tables);
        let binding = bind_windows_userspace_flow(&classification, &binding_admission, 1_300)
            .expect("exact fixture binding");
        let mismatched_admission = admission(&mismatched_fixture, &policy_tables);
        assert_eq!(binding.key(), mismatched_admission.key());
        assert_ne!(binding.admission(), &mismatched_admission);
        let event = flow_open_event(mismatched_admission, 1_300, &policy_tables);
        let previous = WindowsPacketFlowRegistry::new(1_200);
        let transition =
            reduce_windows_packet_flow(previous.clone(), &event, &packet_flow_config())
                .expect("mismatched capability is independently valid");

        let mut owner = WindowsUserspaceByteOwner::new(
            WindowsUserspaceByteOwnerConfig::from_packet_flow(&packet_flow_config())
                .expect("valid owner bounds"),
        )
        .expect("valid byte owner");
        let error = owner
            .open_flow(
                binding,
                &event,
                &previous,
                &transition,
                &packet_flow_config(),
            )
            .expect_err("same key cannot substitute another admission capability");
        assert_eq!(
            error.code,
            WindowsUserspaceByteOwnerErrorCode::TransitionMismatch
        );
        assert_eq!(owner.active_flow_count(), 0);
    }
}

#[test]
fn opening_requires_the_complete_backend_command_set() {
    let policy_tables = bundled_policy_v1();
    let (classification_fixture, admission_fixture) = fixture_pair(7, 41);
    let classification = classification(&classification_fixture, &policy_tables);
    let flow_admission = admission(&admission_fixture, &policy_tables);
    let binding = bind_windows_userspace_flow(&classification, &flow_admission, 1_300)
        .expect("exact fixture binding");
    let event = flow_open_event(flow_admission, 1_300, &policy_tables);
    let previous = WindowsPacketFlowRegistry::new(1_200);
    let transition = reduce_windows_packet_flow(previous.clone(), &event, &packet_flow_config())
        .expect("packet-flow open transition");
    let mut owner = WindowsUserspaceByteOwner::new(
        WindowsUserspaceByteOwnerConfig::from_packet_flow(&packet_flow_config())
            .expect("valid owner bounds"),
    )
    .expect("valid byte owner");

    let mut wrong_destination = transition.clone();
    let destination_port = wrong_destination
        .commands
        .iter_mut()
        .find_map(|command| match command {
            WindowsPacketFlowCommand::OpenBackend {
                destination_port, ..
            } => Some(destination_port),
            _ => None,
        })
        .expect("backend-open command");
    *destination_port = 8_443;
    let error = owner
        .open_flow(
            binding.clone(),
            &event,
            &previous,
            &wrong_destination,
            &packet_flow_config(),
        )
        .expect_err("same-key command cannot open a different destination");
    assert_eq!(
        error.code,
        WindowsUserspaceByteOwnerErrorCode::TransitionMismatch
    );

    let mut duplicate_open = transition.clone();
    duplicate_open
        .commands
        .insert(1, transition.commands[0].clone());
    let error = owner
        .open_flow(
            binding.clone(),
            &event,
            &previous,
            &duplicate_open,
            &packet_flow_config(),
        )
        .expect_err("duplicate backend-open command cannot extend the command set");
    assert_eq!(
        error.code,
        WindowsUserspaceByteOwnerErrorCode::TransitionMismatch
    );

    let mut forged_deadline = transition.clone();
    forged_deadline
        .state
        .flows
        .get_mut(&binding.key())
        .expect("opened flow")
        .idle_deadline_at_ms += 1;
    let deadline = forged_deadline
        .commands
        .iter_mut()
        .find_map(|command| match command {
            WindowsPacketFlowCommand::ScheduleIdleDeadline { at_ms, .. } => Some(at_ms),
            _ => None,
        })
        .expect("idle-deadline command");
    *deadline += 1;
    let error = owner
        .open_flow(
            binding,
            &event,
            &previous,
            &forged_deadline,
            &packet_flow_config(),
        )
        .expect_err("consistent forged state and command still need reducer evidence");
    assert_eq!(
        error.code,
        WindowsUserspaceByteOwnerErrorCode::StaleTransition
    );
    assert_eq!(owner.active_flow_count(), 0);
}

#[test]
fn payload_and_reconcile_preserve_the_complete_bound_admission() {
    let policy_tables = bundled_policy_v1();
    let mut owner = WindowsUserspaceByteOwner::new(
        WindowsUserspaceByteOwnerConfig::from_packet_flow(&packet_flow_config())
            .expect("valid owner bounds"),
    )
    .expect("valid byte owner");
    let (state, key) = open_flow(&mut owner, WindowsPacketFlowRegistry::new(1_200), 7, 41);

    let backend_event = WindowsPacketFlowEvent::BackendReady { now_ms: 1_350, key };
    let backend_ready = reduce(&state, &backend_event);
    owner
        .reconcile(
            &backend_event,
            &state,
            &backend_ready,
            &packet_flow_config(),
        )
        .expect("backend-ready owner reconciliation");
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_400,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 3,
    };
    let payload = reduce(&backend_ready.state, &payload_event);

    let (_, mut substituted_fixture) = fixture_pair(7, 41);
    substituted_fixture.host = "youtube.com".to_owned();
    let substituted_admission = admission(&substituted_fixture, &policy_tables);
    assert_eq!(substituted_admission.key(), key);
    assert_ne!(
        payload
            .state
            .flows
            .get(&key)
            .expect("payload flow")
            .admission,
        substituted_admission
    );

    let mut substituted_payload = payload.clone();
    substituted_payload
        .state
        .flows
        .get_mut(&key)
        .expect("payload flow")
        .admission = substituted_admission.clone();
    let stage_error = owner
        .stage_payload(
            &payload_event,
            &backend_ready.state,
            &substituted_payload,
            &packet_flow_config(),
            vec![7, 8, 9],
        )
        .expect_err("same-key admission cannot substitute during payload staging");
    assert_eq!(
        stage_error.code,
        WindowsUserspaceByteOwnerErrorCode::TransitionDidNotAcceptPayload
    );
    assert_eq!(owner.owned_frame_count(), 0);

    owner
        .stage_payload(
            &payload_event,
            &backend_ready.state,
            &payload,
            &packet_flow_config(),
            vec![7, 8, 9],
        )
        .expect("exact admission payload ownership");
    let refresh_event = WindowsPacketFlowEvent::BackendReady { now_ms: 1_450, key };
    let refresh = reduce(&payload.state, &refresh_event);
    let mut substituted_refresh = refresh.clone();
    substituted_refresh
        .state
        .flows
        .get_mut(&key)
        .expect("refreshed flow")
        .admission = substituted_admission;
    let reconcile_error = owner
        .reconcile(
            &refresh_event,
            &payload.state,
            &substituted_refresh,
            &packet_flow_config(),
        )
        .expect_err("same-key admission cannot substitute during reconciliation");
    assert_eq!(
        reconcile_error.code,
        WindowsUserspaceByteOwnerErrorCode::TransitionMismatch
    );
    assert_eq!(owner.owned_frame_count(), 1);
    assert_eq!(owner.owned_byte_count(), 3);
}

#[test]
fn language_neutral_vectors_keep_exact_bytes_until_effect_success() {
    for vector in contract().vectors {
        let config = packet_flow_config();
        let owner_config =
            WindowsUserspaceByteOwnerConfig::from_packet_flow(&config).expect("valid owner config");
        let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
        let (mut state, key) = open_flow(&mut owner, WindowsPacketFlowRegistry::new(1_200), 7, 41);
        if vector.backend_ready {
            let backend_event = WindowsPacketFlowEvent::BackendReady { now_ms: 1_350, key };
            let backend_transition = reduce(&state, &backend_event);
            owner
                .reconcile(
                    &backend_event,
                    &state,
                    &backend_transition,
                    &packet_flow_config(),
                )
                .expect("backend-ready owner reconciliation");
            state = backend_transition.state;
        }
        let payload_event = WindowsPacketFlowEvent::Payload {
            now_ms: 1_400,
            key,
            direction: vector.direction,
            sequence: vector.sequence,
            bytes: vector.declared_bytes,
        };
        let transition = reduce(&state, &payload_event);
        let first_stage = owner.stage_payload(
            &payload_event,
            &state,
            &transition,
            &config,
            vector.payload.clone(),
        );

        let error = match vector.action.as_str() {
            "stage" => first_stage.err().map(|error| error.code),
            "duplicate_stage" => {
                first_stage.expect("first duplicate vector stage must own bytes");
                let duplicate = reduce(&transition.state, &payload_event);
                owner
                    .stage_payload(
                        &payload_event,
                        &transition.state,
                        &duplicate,
                        &config,
                        vector.payload.clone(),
                    )
                    .expect_err("duplicate payload must fail")
                    .code
                    .into()
            }
            "execute" => {
                first_stage.expect("execute vector stage must own bytes");
                let command = WindowsPacketFlowCommand::Forward {
                    key,
                    direction: vector.direction,
                    sequence: vector.sequence,
                    bytes: vector.forward_bytes.expect("execute vector forward bytes"),
                };
                let mut effects = RecordingByteEffect {
                    fail: vector.effect == "fail",
                    ..RecordingByteEffect::default()
                };
                match owner.execute_forward(
                    &command,
                    &transition.state,
                    &config,
                    &mut effects,
                    1_450,
                ) {
                    Ok(event) => {
                        assert_eq!(vector.expected.disposition, "forwarded", "{}", vector.name);
                        assert!(matches!(
                            event,
                            WindowsPacketFlowEvent::Forwarded {
                                key: event_key,
                                direction: event_direction,
                                through_sequence,
                                ..
                            } if event_key == key
                                && event_direction == vector.direction
                                && through_sequence == vector.sequence
                        ));
                        assert_eq!(effects.deliveries.len(), 1, "{}", vector.name);
                        None
                    }
                    Err(error) => {
                        assert!(effects.deliveries.is_empty(), "{}", vector.name);
                        Some(error.code)
                    }
                }
            }
            other => panic!("unknown vector action {other}"),
        };

        assert_eq!(error, vector.expected.error, "{}", vector.name);
        assert_eq!(
            owner.owned_frame_count(),
            vector.expected.owned_frames,
            "{}",
            vector.name
        );
        assert_eq!(
            owner.owned_byte_count(),
            vector.expected.owned_bytes,
            "{}",
            vector.name
        );
    }
}

#[test]
fn unrelated_idle_refresh_cannot_stage_payload_bytes() {
    let owner_config = WindowsUserspaceByteOwnerConfig::from_packet_flow(&packet_flow_config())
        .expect("valid owner config");
    let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
    let (state, key) = open_flow(&mut owner, WindowsPacketFlowRegistry::new(1_200), 7, 41);
    let half_close_event = WindowsPacketFlowEvent::HalfClosed {
        now_ms: 1_350,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
    };
    let half_closed = reduce(&state, &half_close_event);
    assert!(half_closed.commands.iter().any(|command| {
        matches!(
            command,
            WindowsPacketFlowCommand::ScheduleIdleDeadline {
                key: command_key,
                ..
            } if *command_key == key
        )
    }));
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_350,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 3,
    };
    let error = owner
        .stage_payload(
            &payload_event,
            &state,
            &half_closed,
            &packet_flow_config(),
            vec![1, 2, 3],
        )
        .expect_err("idle refresh alone must not prove payload acceptance");

    assert_eq!(
        error.code,
        WindowsUserspaceByteOwnerErrorCode::TransitionDidNotAcceptPayload
    );
    assert_eq!(owner.owned_frame_count(), 0);
    assert_eq!(owner.owned_byte_count(), 0);
}

#[test]
fn terminal_reconciliation_removes_only_the_closed_flow() {
    let owner_config = WindowsUserspaceByteOwnerConfig::from_packet_flow(&packet_flow_config())
        .expect("valid owner config");
    let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
    let (state, first_key) = open_flow(&mut owner, WindowsPacketFlowRegistry::new(1_200), 7, 41);
    let (state, second_key) = open_flow(&mut owner, state, 8, 42);
    let ready_event = WindowsPacketFlowEvent::BackendReady {
        now_ms: 1_350,
        key: first_key,
    };
    let ready = reduce(&state, &ready_event);
    owner
        .reconcile(&ready_event, &state, &ready, &packet_flow_config())
        .expect("backend-ready owner reconciliation");
    let state = ready.state;
    let stale_cancel_event = WindowsPacketFlowEvent::Cancelled {
        now_ms: 1_400,
        key: first_key,
    };
    let stale_cancelled = reduce(&state, &stale_cancel_event);
    let unrelated_ready_event = WindowsPacketFlowEvent::BackendReady {
        now_ms: 1_500,
        key: second_key,
    };
    let advanced = reduce(&state, &unrelated_ready_event);
    let stale_cleanup = owner
        .reconcile(
            &stale_cancel_event,
            &advanced.state,
            &stale_cancelled,
            &packet_flow_config(),
        )
        .expect_err("unrelated registry progress must invalidate terminal cleanup");
    assert_eq!(
        stale_cleanup.code,
        WindowsUserspaceByteOwnerErrorCode::StaleTransition
    );
    assert_eq!(owner.active_flow_count(), 2);
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_400,
        key: first_key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 3,
    };
    let payload_transition = reduce(&state, &payload_event);
    owner
        .stage_payload(
            &payload_event,
            &state,
            &payload_transition,
            &packet_flow_config(),
            vec![1, 2, 3],
        )
        .expect("payload ownership");
    let stale_cleanup = owner
        .reconcile(
            &stale_cancel_event,
            &state,
            &stale_cancelled,
            &packet_flow_config(),
        )
        .expect_err("stale terminal transition must not remove newer bytes");
    assert_eq!(
        stale_cleanup.code,
        WindowsUserspaceByteOwnerErrorCode::StaleTransition
    );
    assert_eq!(owner.active_flow_count(), 2);
    assert_eq!(owner.owned_byte_count(), 3);
    let cancel_event = WindowsPacketFlowEvent::Cancelled {
        now_ms: 1_500,
        key: first_key,
    };
    let cancelled = reduce(&payload_transition.state, &cancel_event);
    let cleanup = owner
        .reconcile(
            &cancel_event,
            &payload_transition.state,
            &cancelled,
            &packet_flow_config(),
        )
        .expect("current terminal cleanup");
    assert_eq!(cleanup.removed_flows, 1);
    assert_eq!(cleanup.removed_frames, 1);
    assert_eq!(cleanup.removed_bytes, 3);
    assert_eq!(owner.active_flow_count(), 1);
    assert_eq!(owner.owned_frame_count(), 0);
    assert_eq!(owner.owned_byte_count(), 0);
    assert!(cancelled.state.flows.contains_key(&second_key));
}

#[test]
fn stale_generation_retirement_cannot_hide_newer_owned_bytes() {
    let owner_config = WindowsUserspaceByteOwnerConfig::from_packet_flow(&packet_flow_config())
        .expect("valid owner config");
    let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
    let (opening_state, key) = open_flow(&mut owner, WindowsPacketFlowRegistry::new(1_200), 7, 41);
    let ready_event = WindowsPacketFlowEvent::BackendReady { now_ms: 1_350, key };
    let ready = reduce(&opening_state, &ready_event);
    owner
        .reconcile(&ready_event, &opening_state, &ready, &packet_flow_config())
        .expect("backend-ready owner reconciliation");
    let stale_base = ready.state.clone();
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_400,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 3,
    };
    let payload_transition = reduce(&ready.state, &payload_event);
    owner
        .stage_payload(
            &payload_event,
            &ready.state,
            &payload_transition,
            &packet_flow_config(),
            vec![1, 2, 3],
        )
        .expect("payload ownership");

    let foreign_retire_event = WindowsPacketFlowEvent::CaptureGenerationRetired {
        now_ms: 1_500,
        capture_generation: key.capture_generation,
    };
    let foreign_retired = reduce(
        &WindowsPacketFlowRegistry::new(1_400),
        &foreign_retire_event,
    );
    let error = owner
        .reconcile(
            &foreign_retire_event,
            &payload_transition.state,
            &foreign_retired,
            &packet_flow_config(),
        )
        .expect_err("retirement from another registry cannot remove active owned bytes");
    assert_eq!(
        error.code,
        WindowsUserspaceByteOwnerErrorCode::StaleTransition
    );
    assert_eq!(owner.active_flow_count(), 1);
    assert_eq!(owner.owned_frame_count(), 1);
    assert_eq!(owner.owned_byte_count(), 3);

    let stale_cancel_event = WindowsPacketFlowEvent::Cancelled { now_ms: 1_400, key };
    let stale_cancelled = reduce(&stale_base, &stale_cancel_event);
    let stale_retire_event = WindowsPacketFlowEvent::CaptureGenerationRetired {
        now_ms: 1_400,
        capture_generation: key.capture_generation,
    };
    let stale_retired = reduce(&stale_cancelled.state, &stale_retire_event);
    let error = owner
        .reconcile(
            &stale_retire_event,
            &stale_cancelled.state,
            &stale_retired,
            &packet_flow_config(),
        )
        .expect_err("stale retirement must be visible and retain newer bytes");

    assert_eq!(
        error.code,
        WindowsUserspaceByteOwnerErrorCode::StaleTransition
    );
    assert_eq!(owner.active_flow_count(), 1);
    assert_eq!(owner.owned_frame_count(), 1);
    assert_eq!(owner.owned_byte_count(), 3);
}

#[test]
fn payload_owned_before_backend_ready_is_delivered_once_backend_opens() {
    let config = packet_flow_config();
    let owner_config =
        WindowsUserspaceByteOwnerConfig::from_packet_flow(&config).expect("valid owner config");
    let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
    let (state, key) = open_flow(&mut owner, WindowsPacketFlowRegistry::new(1_200), 7, 41);
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_350,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 3,
    };
    let queued = reduce(&state, &payload_event);
    assert!(!queued
        .commands
        .iter()
        .any(|command| { matches!(command, WindowsPacketFlowCommand::Forward { .. }) }));
    let early_forward = WindowsPacketFlowCommand::Forward {
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 3,
    };
    let mut forged_queued = queued.clone();
    forged_queued
        .state
        .flows
        .get_mut(&key)
        .expect("forged queued flow")
        .backend_ready = true;
    forged_queued.commands.push(early_forward.clone());
    let forged_error = owner
        .stage_payload(
            &payload_event,
            &state,
            &forged_queued,
            &config,
            vec![4, 5, 6],
        )
        .expect_err("forged payload transition cannot authorize forwarding");
    assert_eq!(
        forged_error.code,
        WindowsUserspaceByteOwnerErrorCode::StaleTransition
    );
    assert_eq!(owner.owned_frame_count(), 0);

    owner
        .stage_payload(&payload_event, &state, &queued, &config, vec![4, 5, 6])
        .expect("pre-backend payload ownership");
    let backend_event = WindowsPacketFlowEvent::BackendReady { now_ms: 1_400, key };
    let mut forged_backend_ready = queued.clone();
    forged_backend_ready.state.updated_at_ms = 1_400;
    let forged_flow = forged_backend_ready
        .state
        .flows
        .get_mut(&key)
        .expect("forged backend-ready flow");
    forged_flow.updated_at_ms = 1_400;
    forged_flow.backend_ready = true;
    forged_backend_ready.commands.push(early_forward.clone());
    let forged_reconcile_error = owner
        .reconcile(
            &backend_event,
            &queued.state,
            &forged_backend_ready,
            &config,
        )
        .expect_err("forged active transition cannot authorize retained bytes");
    assert_eq!(
        forged_reconcile_error.code,
        WindowsUserspaceByteOwnerErrorCode::StaleTransition
    );
    assert_eq!(owner.owned_frame_count(), 1);
    assert_eq!(owner.owned_byte_count(), 3);

    let mut effects = RecordingByteEffect::default();
    let early_error = owner
        .execute_forward(&early_forward, &queued.state, &config, &mut effects, 1_375)
        .expect_err("retained client payload cannot forward before backend readiness");
    assert_eq!(
        early_error.code,
        WindowsUserspaceByteOwnerErrorCode::ForwardNotAuthorized
    );
    assert!(effects.deliveries.is_empty());
    assert_eq!(owner.owned_frame_count(), 1);
    assert_eq!(owner.owned_byte_count(), 3);

    let backend_ready = reduce(&queued.state, &backend_event);
    let mut missing_authorization = backend_ready.clone();
    missing_authorization
        .commands
        .retain(|command| !matches!(command, WindowsPacketFlowCommand::Forward { .. }));
    let malformed_error = owner
        .reconcile(
            &backend_event,
            &queued.state,
            &missing_authorization,
            &config,
        )
        .expect_err("backend readiness must authorize the exact retained queue");
    assert_eq!(
        malformed_error.code,
        WindowsUserspaceByteOwnerErrorCode::StaleTransition
    );
    assert_eq!(owner.owned_frame_count(), 1);
    assert_eq!(owner.owned_byte_count(), 3);
    owner
        .reconcile(&backend_event, &queued.state, &backend_ready, &config)
        .expect("backend-ready owner reconciliation");
    let forward = backend_ready
        .commands
        .iter()
        .find(|command| matches!(command, WindowsPacketFlowCommand::Forward { .. }))
        .expect("backend readiness must release the retained payload");
    let acknowledgement = owner
        .execute_forward(forward, &backend_ready.state, &config, &mut effects, 1_450)
        .expect("retained payload delivery");
    assert!(matches!(
        acknowledgement,
        WindowsPacketFlowEvent::Forwarded {
            key: event_key,
            direction: WindowsPacketFlowDirection::ClientToBackend,
            through_sequence: 1,
            ..
        } if event_key == key
    ));
    assert_eq!(effects.deliveries[0].3, vec![4, 5, 6]);
    assert_eq!(owner.owned_frame_count(), 0);
    assert_eq!(owner.owned_byte_count(), 0);
}

#[test]
fn unrelated_registry_watermark_rejects_forward_before_effect() {
    let config = packet_flow_config();
    let owner_config =
        WindowsUserspaceByteOwnerConfig::from_packet_flow(&config).expect("valid owner config");
    let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
    let (state, key) = open_flow(&mut owner, WindowsPacketFlowRegistry::new(1_200), 7, 41);

    let backend_event = WindowsPacketFlowEvent::BackendReady { now_ms: 1_350, key };
    let backend_ready = reduce(&state, &backend_event);
    owner
        .reconcile(
            &backend_event,
            &state,
            &backend_ready,
            &packet_flow_config(),
        )
        .expect("backend-ready owner reconciliation");
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_400,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 3,
    };
    let payload = reduce(&backend_ready.state, &payload_event);
    owner
        .stage_payload(
            &payload_event,
            &backend_ready.state,
            &payload,
            &config,
            vec![7, 8, 9],
        )
        .expect("payload ownership");
    let forward = payload
        .commands
        .iter()
        .find(|command| matches!(command, WindowsPacketFlowCommand::Forward { .. }))
        .expect("ready payload must include a forward command");

    let policy_tables = bundled_policy_v1();
    let (_, unrelated_fixture) = fixture_pair(8, 42);
    let unrelated_admission = admission(&unrelated_fixture, &policy_tables);
    let unrelated_event = flow_open_event(unrelated_admission, 1_500, &policy_tables);
    let advanced = reduce(&payload.state, &unrelated_event);
    assert_eq!(advanced.state.updated_at_ms, 1_500);

    let mut effects = RecordingByteEffect::default();
    let error = owner
        .execute_forward(forward, &advanced.state, &config, &mut effects, 1_450)
        .expect_err("global registry watermark must reject a stale acknowledgement");
    assert_eq!(
        error.code,
        WindowsUserspaceByteOwnerErrorCode::ForwardAcknowledgementRejected
    );
    assert!(effects.deliveries.is_empty());
    assert_eq!(owner.owned_frame_count(), 1);
    assert_eq!(owner.owned_byte_count(), 3);

    let acknowledgement = owner
        .execute_forward(forward, &advanced.state, &config, &mut effects, 1_550)
        .expect("current registry watermark permits exact delivery");
    let committed = reduce(&advanced.state, &acknowledgement);
    assert_eq!(
        committed
            .state
            .flows
            .get(&key)
            .expect("flow remains retained")
            .queued_bytes(WindowsPacketFlowDirection::ClientToBackend),
        0
    );
    assert_eq!(effects.deliveries.len(), 1);
    assert_eq!(owner.owned_frame_count(), 0);
    assert_eq!(owner.owned_byte_count(), 0);
}

#[test]
fn final_forward_acknowledgement_releases_the_terminal_owner() {
    let config = packet_flow_config();
    let owner_config =
        WindowsUserspaceByteOwnerConfig::from_packet_flow(&config).expect("valid owner config");
    let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
    let (state, key) = open_flow(&mut owner, WindowsPacketFlowRegistry::new(1_200), 7, 41);

    let backend_event = WindowsPacketFlowEvent::BackendReady { now_ms: 1_350, key };
    let backend_ready = reduce(&state, &backend_event);
    owner
        .reconcile(&backend_event, &state, &backend_ready, &config)
        .expect("backend-ready owner reconciliation");
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_400,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 3,
    };
    let payload = reduce(&backend_ready.state, &payload_event);
    owner
        .stage_payload(
            &payload_event,
            &backend_ready.state,
            &payload,
            &config,
            vec![7, 8, 9],
        )
        .expect("payload ownership");
    let forward = payload
        .commands
        .iter()
        .find(|command| matches!(command, WindowsPacketFlowCommand::Forward { .. }))
        .cloned()
        .expect("ready payload must include a forward command");

    let client_half_event = WindowsPacketFlowEvent::HalfClosed {
        now_ms: 1_410,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
    };
    let client_half = reduce(&payload.state, &client_half_event);
    owner
        .reconcile(&client_half_event, &payload.state, &client_half, &config)
        .expect("client half-close reconciliation");
    let backend_half_event = WindowsPacketFlowEvent::HalfClosed {
        now_ms: 1_420,
        key,
        direction: WindowsPacketFlowDirection::BackendToClient,
    };
    let backend_half = reduce(&client_half.state, &backend_half_event);
    owner
        .reconcile(
            &backend_half_event,
            &client_half.state,
            &backend_half,
            &config,
        )
        .expect("backend half-close reconciliation");
    assert!(!backend_half.state.flows[&key].phase.is_terminal());

    let premature_acknowledgement = WindowsPacketFlowEvent::Forwarded {
        now_ms: 1_430,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        through_sequence: 1,
    };
    let premature_commit = reduce(&backend_half.state, &premature_acknowledgement);
    assert!(premature_commit.state.flows[&key].phase.is_terminal());
    let premature_error = owner
        .reconcile(
            &premature_acknowledgement,
            &backend_half.state,
            &premature_commit,
            &config,
        )
        .expect_err("terminal acknowledgement cannot bypass the byte effect");
    assert_eq!(
        premature_error.code,
        WindowsUserspaceByteOwnerErrorCode::ForwardAcknowledgementRejected
    );
    assert_eq!(owner.active_flow_count(), 1);
    assert_eq!(owner.owned_frame_count(), 1);
    assert_eq!(owner.owned_byte_count(), 3);

    let mut effects = RecordingByteEffect::default();
    let acknowledgement = owner
        .execute_forward(&forward, &backend_half.state, &config, &mut effects, 1_430)
        .expect("last queued payload delivery");
    let committed = reduce(&backend_half.state, &acknowledgement);
    assert!(committed.state.flows[&key].phase.is_terminal());
    assert_eq!(effects.deliveries.len(), 1);
    assert_eq!(owner.active_flow_count(), 0);
    assert_eq!(owner.owned_frame_count(), 0);
    assert_eq!(owner.owned_byte_count(), 0);

    let cleanup = owner
        .reconcile(&acknowledgement, &backend_half.state, &committed, &config)
        .expect("post-commit reconciliation remains idempotent");
    assert_eq!(cleanup, Default::default());
}

#[test]
fn final_forward_survives_terminal_history_pruning() {
    let mut config = packet_flow_config();
    config.max_retained_terminal_flows = 1;
    let owner_config =
        WindowsUserspaceByteOwnerConfig::from_packet_flow(&config).expect("valid owner config");
    let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
    let (state, key) = open_flow_at(
        &mut owner,
        WindowsPacketFlowRegistry::new(1_200),
        7,
        41,
        1_300,
        &config,
    );

    let backend_event = WindowsPacketFlowEvent::BackendReady { now_ms: 1_320, key };
    let backend_ready = reduce_windows_packet_flow(state.clone(), &backend_event, &config)
        .expect("backend-ready transition");
    owner
        .reconcile(&backend_event, &state, &backend_ready, &config)
        .expect("backend-ready owner reconciliation");
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_340,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 3,
    };
    let payload = reduce_windows_packet_flow(backend_ready.state.clone(), &payload_event, &config)
        .expect("payload transition");
    owner
        .stage_payload(
            &payload_event,
            &backend_ready.state,
            &payload,
            &config,
            vec![7, 8, 9],
        )
        .expect("payload ownership");
    let forward = payload
        .commands
        .iter()
        .find(|command| matches!(command, WindowsPacketFlowCommand::Forward { .. }))
        .cloned()
        .expect("ready payload must include a forward command");

    let client_half_event = WindowsPacketFlowEvent::HalfClosed {
        now_ms: 1_350,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
    };
    let client_half =
        reduce_windows_packet_flow(payload.state.clone(), &client_half_event, &config)
            .expect("client half-close transition");
    owner
        .reconcile(&client_half_event, &payload.state, &client_half, &config)
        .expect("client half-close reconciliation");
    let backend_half_event = WindowsPacketFlowEvent::HalfClosed {
        now_ms: 1_360,
        key,
        direction: WindowsPacketFlowDirection::BackendToClient,
    };
    let backend_half =
        reduce_windows_packet_flow(client_half.state.clone(), &backend_half_event, &config)
            .expect("backend half-close transition");
    owner
        .reconcile(
            &backend_half_event,
            &client_half.state,
            &backend_half,
            &config,
        )
        .expect("backend half-close reconciliation");

    let (state, other_key) = open_flow_at(&mut owner, backend_half.state, 8, 42, 1_370, &config);
    assert!(key < other_key);
    let cancel_event = WindowsPacketFlowEvent::Cancelled {
        now_ms: 1_450,
        key: other_key,
    };
    let cancelled = reduce_windows_packet_flow(state.clone(), &cancel_event, &config)
        .expect("other terminal transition");
    owner
        .reconcile(&cancel_event, &state, &cancelled, &config)
        .expect("other owner cleanup");
    assert_eq!(owner.active_flow_count(), 1);

    let expected_acknowledgement = WindowsPacketFlowEvent::Forwarded {
        now_ms: 1_450,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        through_sequence: 1,
    };
    let pruned =
        reduce_windows_packet_flow(cancelled.state.clone(), &expected_acknowledgement, &config)
            .expect("terminal acknowledgement transition");
    assert!(!pruned.state.flows.contains_key(&key));
    assert!(pruned.state.flows.contains_key(&other_key));

    let mut effects = RecordingByteEffect::default();
    let acknowledgement = owner
        .execute_forward(&forward, &cancelled.state, &config, &mut effects, 1_450)
        .expect("pruned terminal acknowledgement still delivers bytes");
    assert_eq!(acknowledgement, expected_acknowledgement);
    assert_eq!(effects.deliveries.len(), 1);
    assert_eq!(effects.deliveries[0].3, vec![7, 8, 9]);
    assert_eq!(owner.active_flow_count(), 0);
    assert_eq!(owner.owned_frame_count(), 0);
    assert_eq!(owner.owned_byte_count(), 0);
}

#[test]
fn ordered_delivery_failure_retains_only_the_uncommitted_suffix() {
    let owner_config = WindowsUserspaceByteOwnerConfig::from_packet_flow(&packet_flow_config())
        .expect("valid owner config");
    let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
    let (state, key) = open_flow(&mut owner, WindowsPacketFlowRegistry::new(1_200), 7, 41);

    let first_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_350,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 2,
    };
    let first = reduce(&state, &first_event);
    owner
        .stage_payload(
            &first_event,
            &state,
            &first,
            &packet_flow_config(),
            vec![1, 2],
        )
        .expect("first payload ownership");
    let second_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_360,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 2,
        bytes: 2,
    };
    let second = reduce(&first.state, &second_event);
    owner
        .stage_payload(
            &second_event,
            &first.state,
            &second,
            &packet_flow_config(),
            vec![3, 4],
        )
        .expect("second payload ownership");

    let ready_event = WindowsPacketFlowEvent::BackendReady { now_ms: 1_400, key };
    let ready = reduce(&second.state, &ready_event);
    owner
        .reconcile(&ready_event, &second.state, &ready, &packet_flow_config())
        .expect("backend-ready owner reconciliation");
    let forwards: Vec<_> = ready
        .commands
        .iter()
        .filter(|command| matches!(command, WindowsPacketFlowCommand::Forward { .. }))
        .collect();
    assert_eq!(forwards.len(), 2);

    let mut effects = FailSecondDeliveryOnce::default();
    let first_acknowledgement = owner
        .execute_forward(
            forwards[0],
            &ready.state,
            &packet_flow_config(),
            &mut effects,
            1_410,
        )
        .expect("first delivery");
    let first_committed = reduce(&ready.state, &first_acknowledgement);
    let failure = owner
        .execute_forward(
            forwards[1],
            &first_committed.state,
            &packet_flow_config(),
            &mut effects,
            1_420,
        )
        .expect_err("second delivery should fail once");
    assert_eq!(
        failure.code,
        WindowsUserspaceByteOwnerErrorCode::EffectFailed
    );
    assert_eq!(owner.owned_frame_count(), 1);
    assert_eq!(owner.owned_byte_count(), 2);
    assert_eq!(effects.delivered_sequences, vec![1]);

    let stale = owner
        .execute_forward(
            forwards[0],
            &first_committed.state,
            &packet_flow_config(),
            &mut effects,
            1_425,
        )
        .expect_err("completed prefix must not replay");
    assert_eq!(
        stale.code,
        WindowsUserspaceByteOwnerErrorCode::ForwardMetadataMismatch
    );
    assert_eq!(effects.delivered_sequences, vec![1]);
    owner
        .execute_forward(
            forwards[1],
            &first_committed.state,
            &packet_flow_config(),
            &mut effects,
            1_430,
        )
        .expect("retained suffix retry");
    assert_eq!(effects.delivered_sequences, vec![1, 2]);
    assert_eq!(owner.owned_frame_count(), 0);
    assert_eq!(owner.owned_byte_count(), 0);
}

#[test]
fn invalid_or_overflowing_owner_bounds_fail_before_allocating_state() {
    for config in [
        WindowsUserspaceByteOwnerConfig {
            max_active_flows: 0,
            max_chunk_bytes: 4,
            max_queued_frames_per_direction: 4,
            max_buffered_bytes_per_direction: 8,
        },
        WindowsUserspaceByteOwnerConfig {
            max_active_flows: usize::MAX,
            max_chunk_bytes: 1,
            max_queued_frames_per_direction: usize::MAX,
            max_buffered_bytes_per_direction: usize::MAX,
        },
        WindowsUserspaceByteOwnerConfig {
            max_active_flows: 1,
            max_chunk_bytes: 9,
            max_queued_frames_per_direction: 1,
            max_buffered_bytes_per_direction: 8,
        },
    ] {
        let error = WindowsUserspaceByteOwner::new(config)
            .err()
            .expect("invalid owner config must fail");
        assert_eq!(
            error.code,
            WindowsUserspaceByteOwnerErrorCode::InvalidConfig
        );
    }
}

#[test]
fn owner_limits_remain_authoritative_over_valid_packet_flow_transitions() {
    let mut frame_owner = WindowsUserspaceByteOwner::new(WindowsUserspaceByteOwnerConfig {
        max_active_flows: 1,
        max_chunk_bytes: 4,
        max_queued_frames_per_direction: 1,
        max_buffered_bytes_per_direction: 8,
    })
    .expect("valid stricter frame owner");
    let (state, key) = open_flow(
        &mut frame_owner,
        WindowsPacketFlowRegistry::new(1_200),
        7,
        41,
    );
    let first_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_350,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 2,
    };
    let first = reduce(&state, &first_event);
    frame_owner
        .stage_payload(
            &first_event,
            &state,
            &first,
            &packet_flow_config(),
            vec![1, 2],
        )
        .expect("first frame fits stricter owner");
    let second_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_360,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 2,
        bytes: 2,
    };
    let second = reduce(&first.state, &second_event);
    let frame_error = frame_owner
        .stage_payload(
            &second_event,
            &first.state,
            &second,
            &packet_flow_config(),
            vec![3, 4],
        )
        .expect_err("owner frame limit must remain authoritative");
    assert_eq!(
        frame_error.code,
        WindowsUserspaceByteOwnerErrorCode::FrameLimit
    );
    assert_eq!(frame_owner.owned_frame_count(), 1);
    assert_eq!(frame_owner.owned_byte_count(), 2);

    let policy_tables = bundled_policy_v1();
    let (classification_fixture, admission_fixture) = fixture_pair(8, 42);
    let second_admission = admission(&admission_fixture, &policy_tables);
    let binding = bind_windows_userspace_flow(
        &classification(&classification_fixture, &policy_tables),
        &second_admission,
        1_300,
    )
    .expect("second exact binding");
    let second_open_event = flow_open_event(second_admission, 1_370, &policy_tables);
    let second_open = reduce(&first.state, &second_open_event);
    let flow_error = frame_owner
        .open_flow(
            binding,
            &second_open_event,
            &first.state,
            &second_open,
            &packet_flow_config(),
        )
        .expect_err("owner flow limit must remain authoritative");
    assert_eq!(
        flow_error.code,
        WindowsUserspaceByteOwnerErrorCode::FlowLimit
    );

    let mut byte_owner = WindowsUserspaceByteOwner::new(WindowsUserspaceByteOwnerConfig {
        max_active_flows: 1,
        max_chunk_bytes: 2,
        max_queued_frames_per_direction: 4,
        max_buffered_bytes_per_direction: 3,
    })
    .expect("valid stricter byte owner");
    let (state, key) = open_flow(
        &mut byte_owner,
        WindowsPacketFlowRegistry::new(1_200),
        9,
        43,
    );
    let first_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_350,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: 2,
    };
    let first = reduce(&state, &first_event);
    byte_owner
        .stage_payload(
            &first_event,
            &state,
            &first,
            &packet_flow_config(),
            vec![5, 6],
        )
        .expect("first bytes fit stricter owner");
    let second_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_360,
        key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 2,
        bytes: 2,
    };
    let second = reduce(&first.state, &second_event);
    let byte_error = byte_owner
        .stage_payload(
            &second_event,
            &first.state,
            &second,
            &packet_flow_config(),
            vec![7, 8],
        )
        .expect_err("owner byte limit must remain authoritative");
    assert_eq!(
        byte_error.code,
        WindowsUserspaceByteOwnerErrorCode::BufferLimit
    );
    assert_eq!(byte_owner.owned_frame_count(), 1);
    assert_eq!(byte_owner.owned_byte_count(), 2);
}

#[test]
fn byte_owner_source_is_effect_injected_and_not_composed() {
    let source = include_str!("../src/userspace_stack_bridge/byte_owner_v1.rs");
    for forbidden in [
        "smoltcp::",
        "windows_sys",
        "TcpStream",
        "UdpSocket",
        "std::process",
        "std::process::Command",
        "unsafe {",
        "LoadLibrary",
    ] {
        assert!(
            !source.contains(forbidden),
            "byte owner contains {forbidden}"
        );
    }
    let frozen_flow = include_str!("../src/packet_flow/v1.rs");
    assert!(!frozen_flow.contains("WindowsUserspaceByteOwner"));
    assert!(!frozen_flow.contains("WindowsUserspaceByteDelivery"));
    let production_host = include_str!("../src/service_host/v1.rs");
    assert!(!production_host.contains("userspace_stack_bridge"));
    assert!(!production_host.contains("WindowsUserspaceByteOwner"));
}

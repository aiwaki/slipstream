use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::{
    bundled_policy_v1, classify_route_policy, RoutingPolicyTables,
};
use slipstream_windows_adapter::data_plane::{
    reduce_windows_data_plane, WindowsDataPlaneBackend, WindowsDataPlaneConfig,
    WindowsDataPlaneEvent, WindowsDataPlaneRequest, WindowsDataPlaneState,
};
use slipstream_windows_adapter::packet_adapter::v4::{
    classify_windows_packet_capture, WindowsPacketCaptureAttribution, WindowsPacketCaptureDecision,
    WindowsPacketCaptureObservation, WindowsPacketCaptureTransport,
    WindowsPacketHostnameEvidenceSource, WindowsPacketPolicyClassification,
};
use slipstream_windows_adapter::packet_egress::{
    prepare_windows_packet_egress, WindowsPacketBaselineRouteEvidence,
    WindowsPacketCaptureRouteActivationEvidence, WindowsPacketEgressRequest,
    WindowsPacketInterfaceIdentity,
};
use slipstream_windows_adapter::packet_flow::{
    bind_windows_packet_flow_session, prepare_windows_packet_flow, WindowsPacketFlowAdmission,
    WindowsPacketFlowTransport,
};
use slipstream_windows_adapter::userspace_stack_bridge::{
    bind_windows_userspace_flow, WindowsUserspaceFlowBindingErrorCode,
    WINDOWS_USERSPACE_FLOW_BINDING_CONTRACT_VERSION,
};
use std::net::IpAddr;

const CONTRACT: &str = include_str!("../../../contracts/windows-userspace-flow-binding-v1.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    vectors: Vec<BindingVector>,
}

#[derive(Debug, Deserialize)]
struct BindingVector {
    name: String,
    now_ms: u64,
    classification: ClassificationFixture,
    admission: AdmissionFixture,
    expected: ExpectedBinding,
}

#[derive(Debug, Deserialize)]
struct ClassificationFixture {
    capture_generation: u64,
    flow_id: u64,
    transport: WindowsPacketCaptureTransport,
    source_address: IpAddr,
    source_port: u16,
    destination: String,
    destination_port: u16,
    host: String,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
struct AdmissionFixture {
    capture_generation: u64,
    flow_id: u64,
    transport: WindowsPacketCaptureTransport,
    destination: String,
    destination_port: u16,
    host: String,
    backend: WindowsDataPlaneBackend,
}

#[derive(Debug, Deserialize)]
struct ExpectedBinding {
    disposition: String,
    transport: Option<WindowsPacketFlowTransport>,
    source_address: Option<IpAddr>,
    source_port: Option<u16>,
    destination_address: Option<IpAddr>,
    destination_port: Option<u16>,
    expires_at_ms: Option<u64>,
    error: Option<WindowsUserspaceFlowBindingErrorCode>,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Windows userspace-flow binding v1 must be valid JSON")
}

fn evidence_source(
    transport: WindowsPacketCaptureTransport,
) -> WindowsPacketHostnameEvidenceSource {
    match transport {
        WindowsPacketCaptureTransport::TcpTls | WindowsPacketCaptureTransport::Other => {
            WindowsPacketHostnameEvidenceSource::TlsClientHelloSni
        }
        WindowsPacketCaptureTransport::UdpQuic => {
            WindowsPacketHostnameEvidenceSource::QuicInitialSni
        }
    }
}

fn classification(
    fixture: &ClassificationFixture,
    policy_tables: &RoutingPolicyTables,
) -> WindowsPacketPolicyClassification {
    let observation = WindowsPacketCaptureObservation {
        capture_generation: fixture.capture_generation,
        flow_id: fixture.flow_id,
        transport: fixture.transport,
        source_address: fixture.source_address,
        source_port: fixture.source_port,
        destination: fixture.destination.clone(),
        destination_port: fixture.destination_port,
        observed_at_ms: 1_100,
        expires_at_ms: fixture.expires_at_ms,
        attribution: WindowsPacketCaptureAttribution::Hostname {
            source: evidence_source(fixture.transport),
            host: fixture.host.clone(),
        },
    };
    match classify_windows_packet_capture(&observation, 1_200, policy_tables) {
        WindowsPacketCaptureDecision::PolicyClassified(classification) => classification,
        other => panic!("{} should classify, got {other:?}", fixture.host),
    }
}

fn egress_request(fixture: &AdmissionFixture) -> WindowsPacketEgressRequest {
    let destination = fixture
        .destination
        .parse::<IpAddr>()
        .expect("fixture destination must be a canonical IP address");
    let (source_address, baseline_prefix, capture_prefix) = match destination {
        IpAddr::V4(_) => (
            "10.0.0.4".to_owned(),
            "0.0.0.0/0".to_owned(),
            format!("{}/32", fixture.destination),
        ),
        IpAddr::V6(_) => (
            "fd00::4".to_owned(),
            "::/0".to_owned(),
            format!("{}/128", fixture.destination),
        ),
    };
    WindowsPacketEgressRequest {
        capture_generation: fixture.capture_generation,
        flow_id: fixture.flow_id,
        destination: fixture.destination.clone(),
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
        current_source_address: source_address.clone(),
        capture_route: WindowsPacketCaptureRouteActivationEvidence {
            capture_generation: fixture.capture_generation,
            destination: fixture.destination.clone(),
            route_prefix: capture_prefix,
            previous_route_epoch: 9,
            active_route_epoch: 10,
            activated_at_ms: 1_050,
            capture_interface: WindowsPacketInterfaceIdentity {
                luid: 900,
                index: 90,
            },
        },
        baseline: WindowsPacketBaselineRouteEvidence {
            capture_generation: fixture.capture_generation,
            route_epoch: 9,
            destination: fixture.destination.clone(),
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
            source_address,
            route_prefix: baseline_prefix,
            route_is_loopback: false,
        },
    }
}

fn accepted_data_plane_state(
    request: &WindowsDataPlaneRequest,
    session_id: u64,
    policy_tables: &RoutingPolicyTables,
) -> WindowsDataPlaneState {
    let config = WindowsDataPlaneConfig {
        max_active_sessions: 8,
        max_retained_terminal_sessions: 8,
        cancel_timeout_ms: 1_000,
        shutdown_timeout_ms: 2_000,
    };
    let ready = reduce_windows_data_plane(
        &WindowsDataPlaneState::new(1_200),
        &WindowsDataPlaneEvent::WorkerReady { now_ms: 1_200 },
        &config,
        policy_tables,
    )
    .expect("worker ready")
    .state;
    let mut ready = ready;
    ready.next_session_id = session_id;
    reduce_windows_data_plane(
        &ready,
        &WindowsDataPlaneEvent::RequestAccepted {
            now_ms: 1_200,
            request: request.clone(),
        },
        &config,
        policy_tables,
    )
    .expect("data-plane acceptance")
    .state
}

fn admission(
    fixture: &AdmissionFixture,
    policy_tables: &RoutingPolicyTables,
) -> WindowsPacketFlowAdmission {
    let source_address = match fixture
        .destination
        .parse::<IpAddr>()
        .expect("fixture destination must be a canonical IP address")
    {
        IpAddr::V4(_) => "10.254.0.2".parse().expect("fixed IPv4 source address"),
        IpAddr::V6(_) => "fd00::2".parse().expect("fixed IPv6 source address"),
    };
    let capture = ClassificationFixture {
        capture_generation: fixture.capture_generation,
        flow_id: fixture.flow_id,
        transport: fixture.transport,
        source_address,
        source_port: 55_000,
        destination: fixture.destination.clone(),
        destination_port: fixture.destination_port,
        host: fixture.host.clone(),
        expires_at_ms: 5_000,
    };
    let classification = classification(&capture, policy_tables);
    let egress = prepare_windows_packet_egress(&egress_request(fixture)).expect("valid egress");
    let request = WindowsDataPlaneRequest {
        request_id: format!(
            "binding-{}-{}-{}",
            fixture.capture_generation, fixture.flow_id, fixture.destination_port
        ),
        policy: classify_route_policy(&fixture.host, policy_tables),
        backend: fixture.backend,
        started_at_ms: 1_200,
        first_payload_deadline_at_ms: 4_000,
    };
    let session_id = fixture.flow_id + 10_000;
    let data_plane = accepted_data_plane_state(&request, session_id, policy_tables);
    let session =
        bind_windows_packet_flow_session(&data_plane, &request.request_id, session_id, 1_200)
            .expect("current session binding");
    prepare_windows_packet_flow(
        classification.v3_classification(),
        &egress,
        &data_plane,
        session,
        1_200,
        policy_tables,
    )
    .expect("packet-flow admission")
}

#[test]
fn binding_contract_freezes_original_tuple_and_effect_boundaries() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.contract,
        "slipstream.windows_userspace_flow_binding"
    );
    assert_eq!(
        fixture.contract_version,
        WINDOWS_USERSPACE_FLOW_BINDING_CONTRACT_VERSION
    );
    for invariant in [
        "pure_binding_only",
        "capture_v4_source_endpoint_required",
        "frozen_packet_flow_v1_admission_required",
        "complete_original_five_tuple_bound",
        "destination_address_and_port_match",
        "active_policy_matches",
    ] {
        assert_eq!(fixture.invariants[invariant], true, "{invariant}");
    }
    for invariant in [
        "payload_ownership",
        "userspace_stack_instantiation",
        "native_connector_effect",
        "wintun_loading",
        "adapter_or_route_mutation",
        "socket_or_dns_effect",
        "system_dns_mutation",
        "proxy_pac_vpn_mutation",
        "process_or_service_effect",
        "production_service_host_composition",
    ] {
        assert_eq!(fixture.invariants[invariant], false, "{invariant}");
    }
}

#[test]
fn language_neutral_vectors_bind_only_an_exact_current_tuple() {
    let policy_tables = bundled_policy_v1();
    for vector in contract().vectors {
        let classification = classification(&vector.classification, &policy_tables);
        let admission = admission(&vector.admission, &policy_tables);
        match bind_windows_userspace_flow(&classification, &admission, vector.now_ms) {
            Ok(binding) => {
                assert_eq!(vector.expected.disposition, "bound", "{}", vector.name);
                assert_eq!(vector.expected.error, None, "{}", vector.name);
                let tuple = binding.tuple();
                assert_eq!(
                    Some(tuple.transport),
                    vector.expected.transport,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(tuple.source.address),
                    vector.expected.source_address,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(tuple.source.port),
                    vector.expected.source_port,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(tuple.destination.address),
                    vector.expected.destination_address,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(tuple.destination.port),
                    vector.expected.destination_port,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(binding.expires_at_ms()),
                    vector.expected.expires_at_ms,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    binding.key().capture_generation,
                    vector.classification.capture_generation,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    binding.key().flow_id,
                    vector.classification.flow_id,
                    "{}",
                    vector.name
                );
            }
            Err(error) => {
                assert_eq!(vector.expected.disposition, "rejected", "{}", vector.name);
                assert_eq!(Some(error), vector.expected.error, "{}", vector.name);
                assert_eq!(vector.expected.transport, None, "{}", vector.name);
                assert_eq!(vector.expected.expires_at_ms, None, "{}", vector.name);
            }
        }
    }
}

#[test]
fn source_binding_is_pure_and_frozen_packet_flow_v1_stays_unmodified() {
    let source = include_str!("../src/userspace_stack_bridge/v1.rs").replace("\r\n", "\n");
    for forbidden in [
        "smoltcp",
        "windows_sys",
        "TcpStream",
        "UdpSocket",
        "std::process",
        "Command::",
        "unsafe {",
        "LoadLibrary",
    ] {
        assert!(!source.contains(forbidden), "binding contains {forbidden}");
    }
    let frozen_flow = include_str!("../src/packet_flow/v1.rs");
    assert!(!frozen_flow.contains("WindowsPacketEndpoint"));
    assert!(!frozen_flow.contains("source_endpoint"));
    let production_host = include_str!("../src/service_host/v1.rs");
    assert!(!production_host.contains("userspace_stack_bridge"));
    assert!(!production_host.contains("WindowsUserspaceFlowBinding"));
}

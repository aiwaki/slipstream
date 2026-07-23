use serde::Deserialize;
use slipstream_core::routing_policy::{classify_route_policy, RoutingPolicyTables};
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
    bind_windows_packet_flow_session, prepare_windows_packet_flow,
    prepare_windows_packet_flow_open, WindowsPacketFlowAdmission, WindowsPacketFlowEvent,
};
use std::net::IpAddr;

#[derive(Clone, Debug, Deserialize)]
pub struct ClassificationFixture {
    pub capture_generation: u64,
    pub flow_id: u64,
    pub transport: WindowsPacketCaptureTransport,
    pub source_address: IpAddr,
    pub source_port: u16,
    pub destination: String,
    pub destination_port: u16,
    pub host: String,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AdmissionFixture {
    pub capture_generation: u64,
    pub flow_id: u64,
    pub transport: WindowsPacketCaptureTransport,
    pub destination: String,
    pub destination_port: u16,
    pub host: String,
    pub backend: WindowsDataPlaneBackend,
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

pub fn classification(
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

pub fn admission(
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

#[allow(dead_code)]
pub fn flow_open_event(
    admission: WindowsPacketFlowAdmission,
    now_ms: u64,
    policy_tables: &RoutingPolicyTables,
) -> WindowsPacketFlowEvent {
    let data_plane =
        accepted_data_plane_state(admission.request(), admission.session_id(), policy_tables);
    prepare_windows_packet_flow_open(admission, &data_plane, now_ms)
        .expect("open event should revalidate the accepted session")
}

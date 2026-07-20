use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::{bundled_policy_v1, RouteClass, ServiceGroup};
use slipstream_windows_adapter::packet_adapter::v2::{
    classify_windows_packet_capture, WindowsPacketCaptureDecision, WindowsPacketCaptureObservation,
    WindowsPacketCapturePassthroughReason, WindowsPacketOpaqueReason,
    MAX_PACKET_CAPTURE_EVIDENCE_LIFETIME_MS, WINDOWS_PACKET_CAPTURE_CONTRACT_VERSION,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-packet-capture-v2.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    native_effect_gates: Value,
    vectors: Vec<CaptureVector>,
}

#[derive(Debug, Deserialize)]
struct CaptureVector {
    name: String,
    now_ms: u64,
    observation: WindowsPacketCaptureObservation,
    expected: ExpectedDecision,
}

#[derive(Debug, Deserialize)]
struct ExpectedDecision {
    disposition: String,
    route_class: Option<RouteClass>,
    service_group: Option<ServiceGroup>,
    normalized_host: Option<String>,
    reason: Option<WindowsPacketCapturePassthroughReason>,
    opaque_reason: Option<WindowsPacketOpaqueReason>,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Windows packet-capture v2 must be valid JSON")
}

#[test]
fn contract_keeps_native_effects_and_backend_authorization_closed() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_packet_capture");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_PACKET_CAPTURE_CONTRACT_VERSION
    );
    assert_eq!(fixture.invariants["capture_only"], true);
    assert_eq!(fixture.invariants["backend_authorization"], false);
    assert_eq!(fixture.invariants["native_dll_loading"], false);
    assert_eq!(fixture.invariants["native_adapter_creation"], false);
    assert_eq!(fixture.invariants["native_route_effect"], false);
    assert_eq!(fixture.invariants["default_route_mutation"], false);
    assert_eq!(fixture.invariants["system_dns_mutation"], false);
    assert_eq!(fixture.invariants["proxy_pac_vpn_mutation"], false);
    assert_eq!(
        fixture.invariants["production_service_host_composition"],
        false
    );
    assert_eq!(
        fixture.invariants["maximum_evidence_lifetime_ms"],
        MAX_PACKET_CAPTURE_EVIDENCE_LIFETIME_MS
    );
    assert!(fixture
        .native_effect_gates
        .as_object()
        .expect("native gates must be an object")
        .values()
        .all(|value| value == "required"));
}

#[test]
fn language_neutral_vectors_reclassify_or_passthrough_without_errors() {
    let tables = bundled_policy_v1();
    for vector in contract().vectors {
        let decision = classify_windows_packet_capture(&vector.observation, vector.now_ms, &tables);
        match decision {
            WindowsPacketCaptureDecision::DirectPassthrough {
                reason,
                opaque_reason,
            } => {
                assert_eq!(
                    vector.expected.disposition, "direct_passthrough",
                    "{}",
                    vector.name
                );
                assert_eq!(Some(reason), vector.expected.reason, "{}", vector.name);
                assert_eq!(
                    opaque_reason, vector.expected.opaque_reason,
                    "{}",
                    vector.name
                );
                assert_eq!(vector.expected.route_class, None, "{}", vector.name);
                assert_eq!(vector.expected.service_group, None, "{}", vector.name);
                assert_eq!(vector.expected.normalized_host, None, "{}", vector.name);
            }
            WindowsPacketCaptureDecision::PolicyClassified(classification) => {
                assert_eq!(
                    vector.expected.disposition, "policy_classified",
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(classification.policy().route_class),
                    vector.expected.route_class,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(classification.policy().service_group),
                    vector.expected.service_group,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(classification.policy().host.clone()),
                    vector.expected.normalized_host,
                    "{}",
                    vector.name
                );
                assert_eq!(vector.expected.reason, None, "{}", vector.name);
                assert_eq!(vector.expected.opaque_reason, None, "{}", vector.name);
                assert_eq!(
                    classification.capture_generation(),
                    vector.observation.capture_generation,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    classification.flow_id(),
                    vector.observation.flow_id,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    classification.expires_at_ms(),
                    vector.observation.expires_at_ms,
                    "{}",
                    vector.name
                );
            }
        }
    }
}

#[test]
fn every_passthrough_reason_has_a_stable_machine_code() {
    let reasons = [
        WindowsPacketCapturePassthroughReason::InvalidCaptureGeneration,
        WindowsPacketCapturePassthroughReason::InvalidFlowId,
        WindowsPacketCapturePassthroughReason::DestinationNotCanonical,
        WindowsPacketCapturePassthroughReason::UnsafeDestination,
        WindowsPacketCapturePassthroughReason::InvalidEvidenceWindow,
        WindowsPacketCapturePassthroughReason::EvidenceExpired,
        WindowsPacketCapturePassthroughReason::OpaqueHostname,
        WindowsPacketCapturePassthroughReason::InvalidHostname,
        WindowsPacketCapturePassthroughReason::EvidenceTransportMismatch,
        WindowsPacketCapturePassthroughReason::DirectPolicy,
        WindowsPacketCapturePassthroughReason::UnknownPolicy,
    ];
    assert!(reasons.iter().all(|reason| !reason.as_str().is_empty()));
    assert_eq!(MAX_PACKET_CAPTURE_EVIDENCE_LIFETIME_MS, 5_000);
}

#[test]
fn v2_is_pure_and_not_composed_into_the_production_host() {
    let source = include_str!("../src/packet_adapter/v2.rs").replace("\r\n", "\n");
    for forbidden in [
        "windows_sys",
        "TcpStream",
        "UdpSocket",
        "std::process",
        "Command::",
        "unsafe {",
        "LoadLibrary",
        "CreateUnicastIpAddressEntry",
    ] {
        assert!(!source.contains(forbidden), "v2 contains {forbidden}");
    }

    let production_host = include_str!("../src/service_host/v1.rs");
    assert!(!production_host.contains("packet_adapter::v2"));
    assert!(!production_host.contains("classify_windows_packet_capture"));
}

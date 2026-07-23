use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::{bundled_policy_v1, RouteClass, ServiceGroup};
use slipstream_windows_adapter::packet_adapter::v3::{
    classify_windows_packet_capture, WindowsPacketCaptureDecision, WindowsPacketCaptureObservation,
    WindowsPacketCapturePassthroughReason, WINDOWS_PACKET_CAPTURE_CONTRACT_VERSION,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-packet-capture-v3.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    extends_contract_version: u32,
    invariants: Value,
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
    destination_port: Option<u16>,
    reason: Option<WindowsPacketCapturePassthroughReason>,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Windows packet-capture v3 must be valid JSON")
}

#[test]
fn v3_extends_frozen_v2_only_with_original_destination_port() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_packet_capture");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_PACKET_CAPTURE_CONTRACT_VERSION
    );
    assert_eq!(fixture.extends_contract_version, 2);
    assert_eq!(fixture.invariants["capture_only"], true);
    assert_eq!(
        fixture.invariants["v2_classification_semantics_preserved"],
        true
    );
    assert_eq!(
        fixture.invariants["original_destination_port_required"],
        true
    );
    assert_eq!(fixture.invariants["backend_authorization"], false);
}

#[test]
fn language_neutral_vectors_preserve_or_reject_the_original_port() {
    let tables = bundled_policy_v1();
    for vector in contract().vectors {
        match classify_windows_packet_capture(&vector.observation, vector.now_ms, &tables) {
            WindowsPacketCaptureDecision::DirectPassthrough { reason, .. } => {
                assert_eq!(
                    vector.expected.disposition, "direct_passthrough",
                    "{}",
                    vector.name
                );
                assert_eq!(Some(reason), vector.expected.reason, "{}", vector.name);
                assert_eq!(vector.expected.destination_port, None, "{}", vector.name);
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
                assert_eq!(
                    Some(classification.destination_port()),
                    vector.expected.destination_port,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    classification.destination_port(),
                    vector.observation.destination_port,
                    "{}",
                    vector.name
                );
                assert_eq!(vector.expected.reason, None, "{}", vector.name);
            }
        }
    }
}

#[test]
fn v3_is_pure_and_not_composed_into_the_production_host() {
    let source = include_str!("../src/packet_adapter/v3.rs").replace("\r\n", "\n");
    for forbidden in [
        "windows_sys",
        "TcpStream",
        "UdpSocket",
        "std::process",
        "Command::",
        "unsafe {",
        "LoadLibrary",
    ] {
        assert!(!source.contains(forbidden), "v3 contains {forbidden}");
    }
    let production_host = include_str!("../src/service_host/v1.rs");
    assert!(!production_host.contains("packet_adapter::v3"));
    assert!(!production_host.contains("classify_windows_packet_capture"));
}

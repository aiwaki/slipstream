mod support;

use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_windows_adapter::packet_flow::WindowsPacketFlowTransport;
use slipstream_windows_adapter::userspace_stack_bridge::{
    bind_windows_userspace_flow, WindowsUserspaceFlowBindingErrorCode,
    WINDOWS_USERSPACE_FLOW_BINDING_CONTRACT_VERSION,
};
use std::net::IpAddr;
use support::userspace_fixture::{
    admission, classification, AdmissionFixture, ClassificationFixture,
};

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

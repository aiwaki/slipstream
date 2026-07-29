use serde::Deserialize;
use serde_json::Value;
use slipstream_userspace_stack_effect_evaluation::native_connector_v1::{
    CONTRACT_VERSION, DEFAULT_MAX_FRAME_BYTES, DEFAULT_MAX_QUEUED_BYTES, DEFAULT_MAX_QUEUED_FRAMES,
};

const CONTRACT: &str =
    include_str!("../../../contracts/windows-userspace-native-connector-effect-v1.json");
const PACKET_FLOW: &str = include_str!("../../../contracts/windows-packet-flow-v1.json");
const FLOW_BINDING: &str =
    include_str!("../../../contracts/windows-userspace-flow-binding-v1.json");
const BYTE_OWNER: &str = include_str!("../../../contracts/windows-userspace-byte-owner-v1.json");
const CONNECTOR_SOURCE: &str = include_str!("../src/native_connector_v1.rs");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    scope: String,
    predecessors: Predecessors,
    bounds: Value,
    qualified_properties: Value,
    invariants: Value,
    remaining_gates: Value,
}

#[derive(Debug, Deserialize)]
struct Predecessors {
    packet_flow: Predecessor,
    flow_binding: Predecessor,
    byte_owner: Predecessor,
}

#[derive(Debug, Deserialize)]
struct Predecessor {
    contract: String,
    contract_version: u32,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("native connector effect v1 must be valid JSON")
}

fn predecessor(source: &str) -> Value {
    serde_json::from_str(source).expect("predecessor contract must be valid JSON")
}

fn assert_predecessor(actual: &Predecessor, source: &str) {
    let expected = predecessor(source);
    assert_eq!(actual.contract, expected["contract"]);
    assert_eq!(actual.contract_version, expected["contract_version"]);
}

#[test]
fn native_connector_contract_freezes_its_predecessors_and_bounds() {
    let fixture = contract();

    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.contract,
        "slipstream.windows_userspace_native_connector_effect"
    );
    assert_eq!(fixture.contract_version, CONTRACT_VERSION);
    assert_eq!(fixture.scope, "test_only_numeric_loopback");
    assert_predecessor(&fixture.predecessors.packet_flow, PACKET_FLOW);
    assert_predecessor(&fixture.predecessors.flow_binding, FLOW_BINDING);
    assert_predecessor(&fixture.predecessors.byte_owner, BYTE_OWNER);
    assert_eq!(
        fixture.bounds["max_queued_frames"],
        DEFAULT_MAX_QUEUED_FRAMES
    );
    assert_eq!(fixture.bounds["max_queued_bytes"], DEFAULT_MAX_QUEUED_BYTES);
    assert_eq!(fixture.bounds["max_frame_bytes"], DEFAULT_MAX_FRAME_BYTES);
}

#[test]
fn native_connector_contract_is_bounded_and_non_production() {
    let fixture = contract();

    for property in [
        "byte_owner_handoff_is_atomic",
        "connector_queue_owns_exact_bytes_after_handoff",
        "tcp_partial_progress_retains_exact_suffix",
        "failed_write_before_progress_retains_complete_frame",
        "udp_datagram_progress_is_exact",
        "backend_identity_is_rechecked_before_native_write",
        "transport_identity_is_rechecked_before_native_write",
        "local_bypass_rejects_geph",
        "discord_and_youtube_reject_geph",
        "udp_rejects_geph",
    ] {
        assert_eq!(fixture.qualified_properties[property], true, "{property}");
    }

    for invariant in [
        "test_dependency_only",
        "numeric_loopback_only",
        "frozen_packet_flow_modified",
        "frozen_flow_binding_modified",
        "frozen_byte_owner_modified",
    ] {
        let expected = !invariant.starts_with("frozen_");
        assert_eq!(fixture.invariants[invariant], expected, "{invariant}");
    }
    for invariant in [
        "production_service_host_composition",
        "wintun_loading",
        "adapter_or_route_mutation",
        "system_dns_mutation",
        "proxy_pac_vpn_mutation",
        "process_or_service_effect",
        "default_route_mutation",
        "external_endpoint",
    ] {
        assert_eq!(fixture.invariants[invariant], false, "{invariant}");
    }
    for gate in [
        "selected_stack_to_connector_composition",
        "backend_read_to_selected_stack_composition",
        "disposable_amd64_packet_flow",
        "disposable_arm64_packet_flow",
        "production_service_host_composition",
    ] {
        assert_eq!(fixture.remaining_gates[gate], "required", "{gate}");
    }

    for forbidden in [
        "Wintun",
        "Command::new",
        "launchctl",
        "pfctl",
        "SetIpForwardEntry",
        "DnsServer",
    ] {
        assert!(
            !CONNECTOR_SOURCE.contains(forbidden),
            "unexpected system mutation token: {forbidden}"
        );
    }
}

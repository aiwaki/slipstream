use serde::Deserialize;
use serde_json::Value;
use slipstream_userspace_stack_effect_evaluation::stack_connector_composition_v1::{
    CONTRACT_VERSION, DEFAULT_MAX_FRAME_BYTES, DEFAULT_MAX_QUEUED_BYTES, DEFAULT_MAX_QUEUED_FRAMES,
    INITIAL_BACKEND_SEQUENCE,
};
use slipstream_userspace_stack_effect_evaluation::v1::MAX_EFFECT_PAYLOAD_BYTES;

const CONTRACT: &str =
    include_str!("../../../contracts/windows-userspace-stack-connector-composition-v1.json");
const STACK_EFFECT: &str =
    include_str!("../../../contracts/windows-userspace-stack-effect-v1.json");
const CONNECTOR_EFFECT: &str =
    include_str!("../../../contracts/windows-userspace-native-connector-effect-v1.json");
const FLOW_BINDING: &str =
    include_str!("../../../contracts/windows-userspace-flow-binding-v1.json");
const COMPOSITION_SOURCE: &str = include_str!("../src/stack_connector_composition_v1.rs");
const TRAY_MANIFEST: &str = include_str!("../../../app-tauri/src-tauri/Cargo.toml");
const WINDOWS_ADAPTER_MANIFEST: &str = include_str!("../../slipstream-windows-adapter/Cargo.toml");

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
    selected_stack_effect: Predecessor,
    native_connector_effect: Predecessor,
    flow_binding: Predecessor,
}

#[derive(Debug, Deserialize)]
struct Predecessor {
    contract: String,
    contract_version: u32,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("stack-connector composition v1 must be valid JSON")
}

fn assert_predecessor(actual: &Predecessor, source: &str) {
    let expected: Value = serde_json::from_str(source).expect("predecessor contract JSON");
    assert_eq!(actual.contract, expected["contract"]);
    assert_eq!(actual.contract_version, expected["contract_version"]);
}

#[test]
fn composition_contract_freezes_predecessors_and_bounds() {
    let fixture = contract();

    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.contract,
        "slipstream.windows_userspace_stack_connector_composition"
    );
    assert_eq!(fixture.contract_version, CONTRACT_VERSION);
    assert_eq!(fixture.scope, "test_only_in_memory_and_numeric_loopback");
    assert_predecessor(&fixture.predecessors.selected_stack_effect, STACK_EFFECT);
    assert_predecessor(
        &fixture.predecessors.native_connector_effect,
        CONNECTOR_EFFECT,
    );
    assert_predecessor(&fixture.predecessors.flow_binding, FLOW_BINDING);
    assert_eq!(
        fixture.bounds["max_effect_payload_bytes"],
        MAX_EFFECT_PAYLOAD_BYTES
    );
    assert_eq!(
        fixture.bounds["initial_backend_sequence"],
        INITIAL_BACKEND_SEQUENCE
    );
    assert_eq!(
        fixture.bounds["max_backend_read_frames"],
        DEFAULT_MAX_QUEUED_FRAMES
    );
    assert_eq!(
        fixture.bounds["max_backend_read_bytes"],
        DEFAULT_MAX_QUEUED_BYTES
    );
    assert_eq!(
        fixture.bounds["max_backend_read_frame_bytes"],
        DEFAULT_MAX_FRAME_BYTES
    );
}

#[test]
fn composition_contract_is_bounded_and_non_production() {
    let fixture = contract();

    for property in [
        "selected_stack_output_reaches_connector_queue",
        "connector_queue_receives_exact_payload_once",
        "connector_backpressure_rejects_before_stack_mutation",
        "backend_read_is_retained_before_stack_delivery",
        "backend_read_failure_before_progress_retains_no_frame",
        "backend_read_sequence_is_reducer_issued_and_contiguous",
        "oversized_udp_datagram_is_rejected_without_sequence_advance",
        "selected_stack_failure_retains_complete_backend_frame",
        "backend_read_retry_commits_once",
        "flow_identity_is_rechecked_in_both_directions",
        "backend_identity_is_rechecked_in_both_directions",
        "transport_identity_is_rechecked_in_both_directions",
        "tcp_and_udp_are_bounded",
        "local_bypass_rejects_geph",
        "discord_and_youtube_reject_geph",
        "udp_rejects_geph",
    ] {
        assert_eq!(fixture.qualified_properties[property], true, "{property}");
    }
    assert_eq!(fixture.invariants["test_dependency_only"], true);
    assert_eq!(fixture.invariants["numeric_loopback_only"], true);
    for invariant in [
        "frozen_stack_effect_modified",
        "frozen_native_connector_effect_modified",
        "frozen_flow_binding_modified",
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
        "disposable_amd64_packet_flow",
        "disposable_arm64_packet_flow",
        "production_service_host_composition",
    ] {
        assert_eq!(fixture.remaining_gates[gate], "required", "{gate}");
    }

    assert!(!TRAY_MANIFEST.contains("slipstream-userspace-stack-effect-evaluation"));
    assert!(!WINDOWS_ADAPTER_MANIFEST.contains("slipstream-userspace-stack-effect-evaluation"));
    for forbidden in [
        "Wintun",
        "Command::new",
        "launchctl",
        "pfctl",
        "SetIpForwardEntry",
        "DnsServer",
    ] {
        assert!(
            !COMPOSITION_SOURCE.contains(forbidden),
            "unexpected system mutation token: {forbidden}"
        );
    }
}

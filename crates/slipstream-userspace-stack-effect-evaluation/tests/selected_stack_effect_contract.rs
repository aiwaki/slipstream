use serde::Deserialize;
use serde_json::Value;
use slipstream_userspace_stack_effect_evaluation::v1::{
    BYTE_OWNER_CONTRACT_VERSION, CONTRACT_VERSION, MAX_EFFECT_PAYLOAD_BYTES, MAX_POLL_STEPS,
    STACK_NAME, STACK_SELECTION_CONTRACT_VERSION, STACK_VERSION,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-userspace-stack-effect-v1.json");
const STACK_SELECTION: &str =
    include_str!("../../../contracts/windows-userspace-stack-selection-v1.json");
const BYTE_OWNER: &str = include_str!("../../../contracts/windows-userspace-byte-owner-v1.json");
const MANIFEST: &str = include_str!("../Cargo.toml");
const EFFECT_TEST: &str = include_str!("selected_stack_effect_v1.rs");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    scope: String,
    selected_stack: StackFixture,
    byte_owner: ByteOwnerFixture,
    bounds: Value,
    qualified_properties: Value,
    invariants: Value,
    remaining_gates: Value,
}

#[derive(Debug, Deserialize)]
struct StackFixture {
    contract: String,
    contract_version: u32,
    #[serde(rename = "crate")]
    crate_name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct ByteOwnerFixture {
    contract: String,
    contract_version: u32,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("selected-stack effect v1 must be valid JSON")
}

#[test]
fn effect_contract_freezes_both_predecessors_without_modifying_them() {
    let fixture = contract();
    let selection: Value = serde_json::from_str(STACK_SELECTION).expect("stack selection JSON");
    let byte_owner: Value = serde_json::from_str(BYTE_OWNER).expect("byte-owner JSON");

    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.contract,
        "slipstream.windows_userspace_stack_effect"
    );
    assert_eq!(fixture.contract_version, CONTRACT_VERSION);
    assert_eq!(fixture.scope, "test_only_in_memory");
    assert_eq!(fixture.selected_stack.contract, selection["contract"]);
    assert_eq!(
        fixture.selected_stack.contract_version,
        STACK_SELECTION_CONTRACT_VERSION
    );
    assert_eq!(
        fixture.selected_stack.contract_version,
        selection["contract_version"]
    );
    assert_eq!(fixture.selected_stack.crate_name, STACK_NAME);
    assert_eq!(
        fixture.selected_stack.crate_name,
        selection["selected_stack"]["crate"]
    );
    assert_eq!(fixture.selected_stack.version, STACK_VERSION);
    assert_eq!(
        fixture.selected_stack.version,
        selection["selected_stack"]["version"]
    );
    assert_eq!(fixture.byte_owner.contract, byte_owner["contract"]);
    assert_eq!(
        fixture.byte_owner.contract_version,
        BYTE_OWNER_CONTRACT_VERSION
    );
    assert_eq!(
        fixture.byte_owner.contract_version,
        byte_owner["contract_version"]
    );
}

#[test]
fn effect_contract_is_bounded_and_test_only() {
    let fixture = contract();
    assert_eq!(
        fixture.bounds["max_effect_payload_bytes"],
        MAX_EFFECT_PAYLOAD_BYTES
    );
    assert_eq!(fixture.bounds["max_poll_steps"], MAX_POLL_STEPS);

    for property in [
        "ipv4_tcp_bidirectional_delivery",
        "ipv6_tcp_bidirectional_delivery",
        "ipv4_udp_bidirectional_delivery",
        "ipv6_udp_bidirectional_delivery",
        "exact_flow_identity_used",
        "exact_original_tuple_used",
        "exact_payload_preserved",
        "effect_failure_precedes_stack_mutation",
        "effect_failure_retains_byte_owner_payload",
        "retry_commits_once",
    ] {
        assert_eq!(fixture.qualified_properties[property], true, "{property}");
    }

    assert_eq!(fixture.invariants["test_dependency_only"], true);
    for invariant in [
        "frozen_stack_selection_modified",
        "frozen_byte_owner_modified",
        "production_service_host_composition",
        "native_packet_effect",
        "native_socket_effect",
        "wintun_loading",
        "adapter_or_route_mutation",
        "system_dns_mutation",
        "proxy_pac_vpn_mutation",
        "process_or_service_effect",
        "default_route_mutation",
        "discord_or_youtube_geo_exit",
    ] {
        assert_eq!(fixture.invariants[invariant], false, "{invariant}");
    }

    assert!(!MANIFEST.contains("\n[dependencies]\n"));
    assert!(MANIFEST.contains("\n[dev-dependencies]\n"));
    for forbidden in [
        "TcpStream",
        "UdpSocket",
        "windows_sys",
        "Wintun",
        "Command::new",
        "launchctl",
        "pfctl",
    ] {
        assert!(
            !EFFECT_TEST.contains(forbidden),
            "unexpected native/system effect token: {forbidden}"
        );
    }
    for gate in [
        "ipv6_fragment_reassembly_qualification",
        "native_connector_effects",
        "disposable_amd64_packet_flow",
        "disposable_arm64_packet_flow",
        "production_service_host_composition",
    ] {
        assert_eq!(fixture.remaining_gates[gate], "required", "{gate}");
    }
}

use serde::Deserialize;
use serde_json::Value;
use slipstream_userspace_stack_effect_evaluation::capture_fragment_v1::{
    CAPTURE_CONTRACT_VERSION, CONTRACT_VERSION, FRAGMENT_INPUT_CONTRACT_VERSION,
    MAX_CAPTURE_BOUND_ASSEMBLIES, MAX_CAPTURE_EVIDENCE_LIFETIME_MS, MAX_FRAGMENTS_PER_ASSEMBLY,
    MAX_REASSEMBLED_PAYLOAD_BYTES, REASSEMBLY_TIMEOUT_MS,
};
use slipstream_userspace_stack_evaluation::ipv6_fragment_input_v1::{
    MAX_ACTIVE_ASSEMBLIES as FRAGMENT_MAX_ACTIVE_ASSEMBLIES,
    MAX_FRAGMENTS_PER_ASSEMBLY as FRAGMENT_MAX_FRAGMENTS_PER_ASSEMBLY,
    REASSEMBLY_TIMEOUT_MS as FRAGMENT_REASSEMBLY_TIMEOUT_MS,
};
use slipstream_userspace_stack_evaluation::v1::REASSEMBLY_BUFFER_BYTES;
use slipstream_windows_adapter::packet_adapter::v2::MAX_PACKET_CAPTURE_EVIDENCE_LIFETIME_MS;

const CONTRACT: &str = include_str!("../../../contracts/windows-capture-fragment-effect-v1.json");
const CAPTURE: &str = include_str!("../../../contracts/windows-packet-capture-v4.json");
const FRAGMENT_INPUT: &str =
    include_str!("../../../contracts/windows-userspace-stack-ipv6-fragment-input-v1.json");
const MANIFEST: &str = include_str!("../Cargo.toml");
const EFFECT_TEST: &str = include_str!("capture_fragment_effect_v1.rs");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    scope: String,
    depends_on: DependenciesFixture,
    bounds: Value,
    qualified_properties: Value,
    invariants: Value,
    remaining_gates: Value,
}

#[derive(Debug, Deserialize)]
struct DependenciesFixture {
    packet_capture: DependencyFixture,
    fragment_input: DependencyFixture,
}

#[derive(Debug, Deserialize)]
struct DependencyFixture {
    contract: String,
    contract_version: u32,
    path: String,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("capture-fragment effect v1 must be valid JSON")
}

fn manifest_has_section(manifest: &str, section: &str) -> bool {
    manifest.lines().any(|line| line.trim() == section)
}

#[test]
fn additive_contract_freezes_both_predecessors() {
    let fixture = contract();
    let capture: Value = serde_json::from_str(CAPTURE).expect("packet capture v4 JSON");
    let fragment: Value = serde_json::from_str(FRAGMENT_INPUT).expect("fragment input v1 JSON");

    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.contract,
        "slipstream.windows_capture_fragment_effect"
    );
    assert_eq!(fixture.contract_version, CONTRACT_VERSION);
    assert_eq!(fixture.scope, "test_only_in_memory");
    assert_eq!(
        fixture.depends_on.packet_capture.contract,
        capture["contract"]
    );
    assert_eq!(
        fixture.depends_on.packet_capture.contract_version,
        CAPTURE_CONTRACT_VERSION
    );
    assert_eq!(
        fixture.depends_on.packet_capture.contract_version,
        capture["contract_version"]
    );
    assert_eq!(
        fixture.depends_on.packet_capture.path,
        "contracts/windows-packet-capture-v4.json"
    );
    assert_eq!(
        fixture.depends_on.fragment_input.contract,
        fragment["contract"]
    );
    assert_eq!(
        fixture.depends_on.fragment_input.contract_version,
        FRAGMENT_INPUT_CONTRACT_VERSION
    );
    assert_eq!(
        fixture.depends_on.fragment_input.contract_version,
        fragment["contract_version"]
    );
    assert_eq!(
        fixture.depends_on.fragment_input.path,
        "contracts/windows-userspace-stack-ipv6-fragment-input-v1.json"
    );
}

#[test]
fn composition_contract_is_bounded_and_effect_free() {
    let fixture = contract();
    assert_eq!(MAX_CAPTURE_BOUND_ASSEMBLIES, FRAGMENT_MAX_ACTIVE_ASSEMBLIES);
    assert_eq!(MAX_REASSEMBLED_PAYLOAD_BYTES, REASSEMBLY_BUFFER_BYTES);
    assert_eq!(
        MAX_FRAGMENTS_PER_ASSEMBLY,
        FRAGMENT_MAX_FRAGMENTS_PER_ASSEMBLY
    );
    assert_eq!(REASSEMBLY_TIMEOUT_MS, FRAGMENT_REASSEMBLY_TIMEOUT_MS);
    assert_eq!(
        MAX_CAPTURE_EVIDENCE_LIFETIME_MS,
        MAX_PACKET_CAPTURE_EVIDENCE_LIFETIME_MS
    );
    assert_eq!(
        fixture.bounds["max_capture_bound_assemblies"],
        MAX_CAPTURE_BOUND_ASSEMBLIES
    );
    assert_eq!(
        fixture.bounds["max_reassembled_payload_bytes"],
        MAX_REASSEMBLED_PAYLOAD_BYTES
    );
    assert_eq!(
        fixture.bounds["max_fragments_per_assembly"],
        MAX_FRAGMENTS_PER_ASSEMBLY
    );
    assert_eq!(
        fixture.bounds["max_capture_evidence_lifetime_ms"],
        MAX_CAPTURE_EVIDENCE_LIFETIME_MS
    );
    assert_eq!(
        fixture.bounds["fragment_reassembly_timeout_ms"],
        REASSEMBLY_TIMEOUT_MS
    );
    assert_eq!(
        fixture.bounds["effective_assembly_deadline"],
        "earliest_capture_expiry_or_fragment_timeout"
    );

    for property in [
        "policy_classification_precedes_fragment_state",
        "direct_passthrough_preserves_packet_and_state",
        "exact_capture_generation_and_flow_bound",
        "exact_source_destination_and_protocol_bound_before_allocation",
        "first_fragment_ports_match_classification",
        "completed_transport_ports_match_classification",
        "in_order_normalization",
        "out_of_order_normalization",
        "rfc6946_atomic_fragment_state_bypass",
        "same_identification_cross_flow_rejected_without_eviction",
        "malformed_or_mismatched_input_does_not_allocate",
        "normalization_error_releases_only_exact_assembly",
        "timeout_releases_only_expired_assembly",
        "assembly_never_outlives_capture_evidence",
        "discord_route_remains_local_bypass",
    ] {
        assert_eq!(fixture.qualified_properties[property], true, "{property}");
    }

    for invariant in [
        "additive_contract_preserves_packet_capture_v4",
        "additive_contract_preserves_fragment_input_v1",
        "test_dependency_only",
    ] {
        assert_eq!(fixture.invariants[invariant], true, "{invariant}");
    }
    for invariant in [
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

    assert!(!manifest_has_section(MANIFEST, "[dependencies]"));
    assert!(manifest_has_section(MANIFEST, "[dev-dependencies]"));
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
        "native_connector_effects",
        "disposable_amd64_packet_flow",
        "disposable_arm64_packet_flow",
        "production_service_host_composition",
    ] {
        assert_eq!(fixture.remaining_gates[gate], "required", "{gate}");
    }
}

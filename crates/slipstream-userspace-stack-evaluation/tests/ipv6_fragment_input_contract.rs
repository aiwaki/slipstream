use serde::Deserialize;
use serde_json::Value;
use slipstream_userspace_stack_evaluation::ipv6_fragment_input_v1::{
    CONTRACT_VERSION, MAX_ACTIVE_ASSEMBLIES, MAX_FRAGMENTS_PER_ASSEMBLY, REASSEMBLY_TIMEOUT_MS,
};
use slipstream_userspace_stack_evaluation::v1::{
    REASSEMBLY_BUFFER_BYTES, STACK_NAME, STACK_VERSION,
};

const CONTRACT: &str =
    include_str!("../../../contracts/windows-userspace-stack-ipv6-fragment-input-v1.json");
const SELECTION: &str =
    include_str!("../../../contracts/windows-userspace-stack-selection-v1.json");
const SOURCE: &str = include_str!("../src/ipv6_fragment_input_v1.rs");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    qualification_status: String,
    depends_on: Value,
    bounds: Value,
    qualified_properties: Value,
    known_limits: Value,
    invariants: Value,
    remaining_gates: Value,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("IPv6 fragment-input v1 must be valid JSON")
}

#[test]
fn additive_contract_keeps_the_selected_stack_identity_and_frozen_limit_explicit() {
    let fixture = contract();
    let selection: Value =
        serde_json::from_str(SELECTION).expect("stack selection v1 must be valid JSON");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.contract,
        "slipstream.windows_userspace_stack_ipv6_fragment_input"
    );
    assert_eq!(fixture.contract_version, CONTRACT_VERSION);
    assert_eq!(
        fixture.qualification_status,
        "bounded_pre_stack_reassembly_qualified"
    );
    assert_eq!(
        fixture.depends_on["contract"],
        "slipstream.windows_userspace_stack_selection"
    );
    assert_eq!(fixture.depends_on["contract_version"], 1);
    assert_eq!(fixture.depends_on["selected_stack"], STACK_NAME);
    assert_eq!(fixture.depends_on["selected_stack_version"], STACK_VERSION);
    assert_eq!(
        selection["known_limits"]["ipv6_fragment_reassembly"],
        "not_yet_qualified"
    );
    assert_eq!(
        fixture.invariants["additive_contract_preserves_selection_v1"],
        true
    );
}

#[test]
fn contract_bounds_equal_the_reassembler_constants() {
    let fixture = contract();
    assert_eq!(
        fixture.bounds["accepted_ipv6_extension_shape"],
        "fragment_header_immediately_after_base_header"
    );
    assert_eq!(fixture.bounds["accepted_transport_protocols"][0], "tcp");
    assert_eq!(fixture.bounds["accepted_transport_protocols"][1], "udp");
    assert_eq!(
        fixture.bounds["max_active_assemblies"],
        MAX_ACTIVE_ASSEMBLIES
    );
    assert_eq!(
        fixture.bounds["max_fragments_per_assembly"],
        MAX_FRAGMENTS_PER_ASSEMBLY
    );
    assert_eq!(
        fixture.bounds["max_reassembled_payload_bytes"],
        REASSEMBLY_BUFFER_BYTES
    );
    assert_eq!(
        fixture.bounds["reassembly_timeout_ms"],
        REASSEMBLY_TIMEOUT_MS
    );
    assert_eq!(fixture.bounds["fragment_offset_alignment_bytes"], 8);
}

#[test]
fn contract_records_positive_and_fail_closed_boundaries() {
    let fixture = contract();
    for property in [
        "pre_stack_exact_packet_reconstruction",
        "pre_stack_in_order_reassembly",
        "pre_stack_out_of_order_reassembly",
        "original_udp_source_endpoint_delivery",
        "identification_isolation",
        "overlap_rejection",
        "conflicting_header_rejection",
        "conflicting_total_size_rejection",
        "non_final_alignment_validation",
        "reserved_bits_validation",
        "bounded_assembly_capacity",
        "bounded_fragment_count",
        "bounded_payload_memory",
        "bounded_timeout_cleanup",
    ] {
        assert_eq!(fixture.qualified_properties[property], true, "{property}");
    }
    assert_eq!(
        fixture.qualified_properties["selected_stack_native_ipv6_fragment_delivery"],
        false
    );
    assert_eq!(
        fixture.known_limits["extension_headers_before_fragment"],
        "unsupported_fail_closed"
    );
    assert_eq!(
        fixture.known_limits["ipv6_jumbograms"],
        "unsupported_fail_closed"
    );
    assert_eq!(
        fixture.known_limits["production_backend_bridge"],
        "not_implemented"
    );
    assert_eq!(
        fixture.invariants["effect_free_byte_normalization_only"],
        true
    );
    for invariant in [
        "production_service_host_composition",
        "native_connector_effect",
        "wintun_loading",
        "adapter_or_route_mutation",
        "socket_or_dns_effect",
        "system_dns_mutation",
        "proxy_pac_vpn_mutation",
        "process_or_service_effect",
        "default_route_mutation",
        "discord_or_youtube_geo_exit",
    ] {
        assert_eq!(fixture.invariants[invariant], false, "{invariant}");
    }
    for gate in [
        "windows_capture_composition",
        "native_connector_effects",
        "production_service_host_composition",
        "disposable_amd64_packet_flow",
        "disposable_arm64_packet_flow",
    ] {
        assert_eq!(fixture.remaining_gates[gate], "required", "{gate}");
    }
}

#[test]
fn reassembler_source_has_no_native_or_host_effect_surface() {
    for forbidden in [
        "std::net",
        "std::process",
        "Command::",
        "windows_sys",
        "Wintun",
        "CreateProcess",
        "launchctl",
        "pfctl",
        "networksetup",
    ] {
        assert!(!SOURCE.contains(forbidden), "{forbidden}");
    }
}

use serde::Deserialize;
use serde_json::Value;
use slipstream_userspace_stack_evaluation::v1::{
    CONTRACT_VERSION, FRAGMENTATION_BUFFER_BYTES, L3_MTU, MAX_BURST_FRAMES,
    MAX_LINK_FRAMES_PER_DIRECTION, MAX_SOCKETS_PER_STACK, REASSEMBLY_BUFFER_BYTES,
    REASSEMBLY_BUFFER_COUNT, REQUIRED_RUST_VERSION, STACK_CRATE_SHA256, STACK_NAME, STACK_VERSION,
    TCP_BYTES_PER_DIRECTION, UDP_BYTES_PER_DIRECTION, UDP_PACKET_SLOTS_PER_DIRECTION,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-userspace-stack-selection-v1.json");
const MANIFEST: &str = include_str!("../Cargo.toml");
const LOCK: &str = include_str!("../Cargo.lock");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    selection_status: String,
    selected_stack: StackFixture,
    bounds: Value,
    qualified_properties: Value,
    known_limits: Value,
    invariants: Value,
    remaining_gates: Value,
}

#[derive(Debug, Deserialize)]
struct StackFixture {
    #[serde(rename = "crate")]
    crate_name: String,
    version: String,
    crate_sha256: String,
    source: String,
    repository: String,
    license: String,
    rust_version: String,
    default_features: bool,
    features: Vec<String>,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("userspace stack selection v1 must be valid JSON")
}

#[test]
fn contract_and_lock_freeze_the_exact_evaluation_dependency() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.contract,
        "slipstream.windows_userspace_stack_selection"
    );
    assert_eq!(fixture.contract_version, CONTRACT_VERSION);
    assert_eq!(fixture.selection_status, "selected_for_bounded_evaluation");
    assert_eq!(fixture.selected_stack.crate_name, STACK_NAME);
    assert_eq!(fixture.selected_stack.version, STACK_VERSION);
    assert_eq!(fixture.selected_stack.crate_sha256, STACK_CRATE_SHA256);
    assert_eq!(
        fixture.selected_stack.source,
        "registry+https://github.com/rust-lang/crates.io-index"
    );
    assert_eq!(
        fixture.selected_stack.repository,
        "https://github.com/smoltcp-rs/smoltcp"
    );
    assert_eq!(fixture.selected_stack.license, "0BSD");
    assert_eq!(fixture.selected_stack.rust_version, REQUIRED_RUST_VERSION);
    assert!(!fixture.selected_stack.default_features);
    assert_eq!(env!("CARGO_PKG_RUST_VERSION"), REQUIRED_RUST_VERSION);

    let expected_features = [
        "fragmentation-buffer-size-4096",
        "medium-ip",
        "proto-ipv4",
        "proto-ipv4-fragmentation",
        "proto-ipv6",
        "proto-ipv6-fragmentation",
        "reassembly-buffer-count-2",
        "reassembly-buffer-size-4096",
        "socket-tcp",
        "socket-udp",
        "std",
    ];
    assert_eq!(fixture.selected_stack.features, expected_features);
    assert!(MANIFEST.contains("version = \"=0.13.1\""));
    assert!(MANIFEST.contains("default-features = false"));
    for feature in expected_features {
        assert!(MANIFEST.contains(&format!("\"{feature}\"")));
    }

    let lock_record = format!(
        "name = \"{STACK_NAME}\"\nversion = \"{STACK_VERSION}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{STACK_CRATE_SHA256}\""
    );
    let normalized_lock = LOCK.lines().collect::<Vec<_>>().join("\n");
    assert!(normalized_lock.contains(&lock_record));
}

#[test]
fn contract_freezes_the_same_bounds_as_the_test_harness() {
    let fixture = contract();
    assert_eq!(fixture.bounds["medium"], "layer_3");
    assert_eq!(fixture.bounds["mtu"], L3_MTU);
    assert_eq!(
        fixture.bounds["max_link_frames_per_direction"],
        MAX_LINK_FRAMES_PER_DIRECTION
    );
    assert_eq!(fixture.bounds["max_burst_frames"], MAX_BURST_FRAMES);
    assert_eq!(
        fixture.bounds["max_sockets_per_stack"],
        MAX_SOCKETS_PER_STACK
    );
    assert_eq!(
        fixture.bounds["udp_packet_slots_per_direction"],
        UDP_PACKET_SLOTS_PER_DIRECTION
    );
    assert_eq!(
        fixture.bounds["udp_bytes_per_direction"],
        UDP_BYTES_PER_DIRECTION
    );
    assert_eq!(
        fixture.bounds["tcp_bytes_per_direction"],
        TCP_BYTES_PER_DIRECTION
    );
    assert_eq!(
        fixture.bounds["fragmentation_buffer_bytes"],
        FRAGMENTATION_BUFFER_BYTES
    );
    assert_eq!(
        fixture.bounds["reassembly_buffer_bytes"],
        REASSEMBLY_BUFFER_BYTES
    );
    assert_eq!(
        fixture.bounds["reassembly_buffer_count"],
        REASSEMBLY_BUFFER_COUNT
    );
    assert_eq!(fixture.bounds["random_seed_source"], "explicit_test_vector");
}

#[test]
fn evaluation_contract_keeps_every_native_and_system_effect_closed() {
    let fixture = contract();
    for key in [
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
        assert_eq!(fixture.invariants[key], false, "{key}");
    }
    assert_eq!(fixture.invariants["evaluation_dependency_only"], true);
    assert_eq!(
        fixture.known_limits["ipv6_outbound_fragmentation"],
        "unimplemented_drop_without_frame"
    );
    assert_eq!(
        fixture.known_limits["source_endpoint_binding"],
        "not_present_in_windows_packet_flow_v1"
    );
    assert_eq!(
        fixture.remaining_gates["versioned_source_endpoint_binding"],
        "required"
    );
    assert_eq!(
        fixture.remaining_gates["production_service_host_composition"],
        "required"
    );

    for key in [
        "ipv4_tcp_round_trip",
        "ipv6_tcp_round_trip",
        "ipv4_udp_round_trip",
        "ipv6_udp_below_mtu_round_trip",
        "ipv4_outbound_fragmentation_and_inbound_reassembly",
        "ipv4_udp_checksum_rejection",
        "ipv6_udp_checksum_rejection",
        "fixed_link_queue_bound",
        "fixed_socket_buffer_bound",
    ] {
        assert_eq!(fixture.qualified_properties[key], true, "{key}");
    }

    for forbidden in ["windows-sys", "wintun", "socket2", "tokio"] {
        assert!(
            !MANIFEST.contains(forbidden),
            "unexpected effect dependency: {forbidden}"
        );
        assert!(!LOCK.contains(&format!("name = \"{forbidden}\"")));
    }
}

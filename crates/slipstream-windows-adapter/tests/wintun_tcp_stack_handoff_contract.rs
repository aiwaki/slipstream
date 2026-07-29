use serde::Deserialize;
use serde_json::Value;

const CONTRACT: &str = include_str!("../../../contracts/windows-wintun-tcp-stack-handoff-v1.json");
const ADAPTER_MANIFEST: &str = include_str!("../Cargo.toml");
const TCP_STACK_MODULE: &str =
    include_str!("../../slipstream-userspace-stack-evaluation/src/raw_packet_tcp_v1.rs");
const IPV4_UDP_STACK_MODULE: &str =
    include_str!("../../slipstream-userspace-stack-evaluation/src/raw_packet_udp_v1.rs");
const IPV6_UDP_STACK_MODULE: &str =
    include_str!("../../slipstream-userspace-stack-evaluation/src/raw_packet_udp_ipv6_v1.rs");
const WINTUN_FIXTURE: &str = include_str!("wintun_exact_route_windows.rs");
const WORKFLOW: &str =
    include_str!("../../../.github/workflows/windows-packet-adapter-qualification.yml");
const PRODUCTION_LIB: &str = include_str!("../src/lib.rs");
const PRODUCTION_BIN: &str = include_str!("../src/bin/slipstream_windows_service.rs");
const PRODUCTION_HOST: &str = include_str!("../src/service_host/v1.rs");
const PRODUCTION_HOST_WINDOWS: &str = include_str!("../src/service_host/windows.rs");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    scope: Value,
    bounds: Value,
    qualified_evidence: Value,
    invariants: Value,
    frozen_predecessors: Value,
    remaining_gates: Value,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Wintun TCP-to-stack handoff v1 must be valid JSON")
}

#[test]
fn contract_freezes_the_disposable_native_tcp_handoff() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.contract,
        "slipstream.windows_wintun_tcp_stack_handoff"
    );
    assert_eq!(fixture.contract_version, 1);
    assert_eq!(fixture.scope["transport"], "ipv4_tcp");
    assert_eq!(fixture.scope["capture_adapter"], "wintun_0.14.1");
    assert_eq!(fixture.scope["selected_stack"], "smoltcp_0.13.1");
    assert_eq!(
        fixture.scope["native_architectures"],
        serde_json::json!(["amd64", "arm64"])
    );
    assert_eq!(
        fixture.scope["qualification_test"],
        "native_wintun_ipv4_tcp_round_trip_crosses_the_selected_stack"
    );

    assert_eq!(fixture.bounds["medium"], "layer_3");
    assert_eq!(fixture.bounds["mtu"], 1280);
    assert_eq!(fixture.bounds["max_poll_steps_per_phase"], 64);
    assert_eq!(fixture.bounds["max_link_frames_per_direction"], 8);
    assert_eq!(fixture.bounds["max_burst_frames"], 1);
    assert_eq!(fixture.bounds["one_syn_packet"], true);
    assert_eq!(fixture.bounds["one_handshake_ack_packet"], true);
    assert_eq!(fixture.bounds["one_request_payload_packet"], true);
    assert_eq!(fixture.bounds["max_response_packets"], 8);
    assert_eq!(fixture.bounds["fixed_deadline_seconds"], 3);

    for key in [
        "real_os_tcp_syn",
        "owned_exact_host_route",
        "wintun_captured_syn_packet",
        "selected_stack_emitted_syn_ack",
        "wintun_injected_stack_syn_ack",
        "real_os_tcp_handshake_ack",
        "selected_stack_established_session",
        "wintun_captured_request_packet",
        "selected_stack_received_request_payload",
        "selected_stack_emitted_response_packet",
        "wintun_injected_stack_response",
        "real_os_tcp_response",
        "owned_route_removed",
        "owned_address_removed",
        "owned_adapter_and_session_removed",
    ] {
        assert_eq!(fixture.qualified_evidence[key], true, "{key}");
    }
}

#[test]
fn tcp_boundary_is_bounded_and_keeps_udp_v1_modules_frozen() {
    for required in [
        "pub const CONTRACT_VERSION: u32 = 1;",
        "pub const MAX_POLL_STEPS: usize = 64;",
        "pub struct RawPacketTcpStackV1",
        "pub fn accept_syn_ipv4(",
        "pub fn accept_ack_ipv4(",
        "pub fn exchange_payload_ipv4(",
        "RawPacketTcpPhase::ResponseEmitted",
        "MAX_LINK_FRAMES_PER_DIRECTION",
        "MAX_RESPONSE_PAYLOAD_BYTES",
        "RawPacketTcpErrorCode::SegmentRejected",
        "RawPacketTcpErrorCode::StackOutputExceededBounds",
    ] {
        assert!(
            TCP_STACK_MODULE.contains(required),
            "missing TCP selected-stack boundary {required}"
        );
    }
    assert!(
        IPV4_UDP_STACK_MODULE.contains("pub const CONTRACT_VERSION: u32 = 1;"),
        "frozen IPv4 UDP module must retain contract version 1"
    );
    assert!(
        IPV6_UDP_STACK_MODULE.contains("pub const CONTRACT_VERSION: u32 = 1;"),
        "frozen IPv6 UDP module must retain contract version 1"
    );
    let fixture = contract();
    assert_eq!(
        fixture.frozen_predecessors["raw_packet_udp_v1_changed"],
        false
    );
    assert_eq!(
        fixture.frozen_predecessors["raw_packet_udp_ipv6_v1_changed"],
        false
    );

    let dev_dependencies = ADAPTER_MANIFEST
        .split_once("[dev-dependencies]")
        .expect("adapter manifest must retain dev dependencies")
        .1;
    assert!(dev_dependencies.contains(
        "slipstream-userspace-stack-evaluation = { path = \"../slipstream-userspace-stack-evaluation\" }"
    ));
    let normal_dependencies = ADAPTER_MANIFEST
        .split_once("[dev-dependencies]")
        .expect("adapter manifest must retain dev dependencies")
        .0;
    assert!(!normal_dependencies.contains("slipstream-userspace-stack-evaluation"));
}

#[test]
fn native_tcp_fixture_uses_stack_output_without_manual_packets() {
    let start = WINTUN_FIXTURE
        .find("fn prove_ipv4_tcp_stack_round_trip(")
        .expect("missing IPv4 TCP Wintun stack proof");
    let end = WINTUN_FIXTURE[start..]
        .find("fn prove_ipv6_packet_round_trip(")
        .map(|offset| start + offset)
        .expect("missing end of IPv4 TCP Wintun stack proof");
    let proof = &WINTUN_FIXTURE[start..end];
    for required in [
        "RawPacketTcpStackV1::new_ipv4",
        ".accept_syn_ipv4(&syn_packet)",
        ".accept_ack_ipv4(&acknowledgment_packet)",
        ".exchange_payload_ipv4(&request_packet, TCP_STACK_RESPONSE_PAYLOAD)",
        "exchange.request_payload != TCP_STACK_REQUEST_PAYLOAD",
        "adapter.inject_packet(response_packet)",
    ] {
        assert!(
            proof.contains(required),
            "missing IPv4 TCP Wintun handoff {required}"
        );
    }
    assert!(
        !proof.contains("build_ipv4_tcp_packet("),
        "the TCP selected-stack handoff cannot synthesize handshake or response packets manually"
    );
}

#[test]
fn production_host_remains_closed_and_native_workflow_executes_tcp_exactly() {
    let fixture = contract();
    assert_eq!(fixture.invariants["qualification_dependency_only"], true);
    for key in [
        "production_service_host_composition",
        "manual_handshake_or_response_packet_builder",
        "default_route_mutation",
        "system_dns_mutation",
        "external_proxy_pac_vpn_mutation",
        "external_adapter_or_route_mutation",
        "discord_or_youtube_geo_exit",
    ] {
        assert_eq!(fixture.invariants[key], false, "{key}");
    }
    assert_eq!(
        fixture.remaining_gates["production_service_host_composition"],
        "required"
    );

    for production_source in [
        PRODUCTION_LIB,
        PRODUCTION_BIN,
        PRODUCTION_HOST,
        PRODUCTION_HOST_WINDOWS,
    ] {
        assert!(!production_source.contains("slipstream_userspace_stack_evaluation"));
        assert!(!production_source.contains("RawPacketTcpStackV1"));
    }
    assert_eq!(
        WORKFLOW
            .matches("contracts/windows-wintun-tcp-stack-handoff-v1.json")
            .count(),
        2
    );
    assert_eq!(
        WORKFLOW
            .matches("Qualify Wintun-to-selected-stack IPv4 TCP handoff")
            .count(),
        1
    );
    assert_eq!(
        WORKFLOW
            .matches("-TestName native_wintun_ipv4_tcp_round_trip_crosses_the_selected_stack")
            .count(),
        1
    );
}

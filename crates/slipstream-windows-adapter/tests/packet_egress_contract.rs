use serde::Deserialize;
use serde_json::Value;
use slipstream_windows_adapter::packet_egress::{
    prepare_windows_packet_egress, WindowsPacketEgressErrorCode, WindowsPacketEgressRequest,
    WindowsPacketSocketInterfaceBinding, MAX_PACKET_EGRESS_EVIDENCE_LIFETIME_MS,
    WINDOWS_PACKET_EGRESS_CONTRACT_VERSION,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-packet-egress-v1.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    remaining_native_gates: Value,
    vectors: Vec<EgressVector>,
}

#[derive(Debug, Deserialize)]
struct EgressVector {
    name: String,
    request: WindowsPacketEgressRequest,
    expected: ExpectedEgress,
}

#[derive(Debug, Deserialize)]
struct ExpectedEgress {
    result: String,
    destination: Option<String>,
    source_address: Option<String>,
    egress_luid: Option<u64>,
    egress_index: Option<u32>,
    binding_kind: Option<String>,
    binding_value: Option<u32>,
    error: Option<WindowsPacketEgressErrorCode>,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Windows packet-egress v1 must be valid JSON")
}

#[test]
fn contract_keeps_native_socket_route_and_adapter_effects_closed() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_packet_egress");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_PACKET_EGRESS_CONTRACT_VERSION
    );
    assert_eq!(fixture.invariants["pure_admission_only"], true);
    assert_eq!(
        fixture.invariants["pre_capture_route_evidence_required"],
        true
    );
    assert_eq!(fixture.invariants["capture_generation_bound"], true);
    assert_eq!(
        fixture.invariants["owned_capture_route_transition_bound"],
        true
    );
    assert_eq!(fixture.invariants["route_epoch_bound"], true);
    assert_eq!(fixture.invariants["luid_and_live_index_bound"], true);
    assert_eq!(
        fixture.invariants["source_address_revalidation_bound"],
        true
    );
    assert_eq!(fixture.invariants["capture_interface_rejected"], true);
    assert_eq!(
        fixture.invariants["ipv6_global_unicast_registry_snapshot"],
        "2025-10-10"
    );
    assert_eq!(
        fixture.invariants["ipv6_special_purpose_registry_snapshot"],
        "2025-10-09"
    );
    assert_eq!(fixture.invariants["backend_selection"], false);
    assert_eq!(fixture.invariants["native_route_query"], false);
    assert_eq!(fixture.invariants["native_socket_effect"], false);
    assert_eq!(fixture.invariants["native_adapter_effect"], false);
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
        MAX_PACKET_EGRESS_EVIDENCE_LIFETIME_MS
    );
    assert!(fixture
        .remaining_native_gates
        .as_object()
        .expect("native gates must be an object")
        .values()
        .all(|value| value == "required"));
    assert_eq!(
        fixture.remaining_native_gates["trusted_owned_route_transition_issuer"],
        "required"
    );
}

#[test]
fn language_neutral_vectors_admit_only_fresh_non_capture_egress() {
    for vector in contract().vectors {
        match prepare_windows_packet_egress(&vector.request) {
            Ok(plan) => {
                assert_eq!(vector.expected.result, "plan", "{}", vector.name);
                assert_eq!(
                    Some(plan.destination().to_string()),
                    vector.expected.destination,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(plan.source_address().to_string()),
                    vector.expected.source_address,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(plan.egress_interface().luid),
                    vector.expected.egress_luid,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(plan.egress_interface().index),
                    vector.expected.egress_index,
                    "{}",
                    vector.name
                );
                let (kind, value) = match plan.socket_binding() {
                    WindowsPacketSocketInterfaceBinding::Ipv4NetworkByteOrder(value) => {
                        ("ipv4_network_byte_order", value)
                    }
                    WindowsPacketSocketInterfaceBinding::Ipv6HostByteOrder(value) => {
                        ("ipv6_host_byte_order", value)
                    }
                };
                assert_eq!(
                    Some(kind.to_owned()),
                    vector.expected.binding_kind,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    Some(value),
                    vector.expected.binding_value,
                    "{}",
                    vector.name
                );
                assert_eq!(vector.expected.error, None, "{}", vector.name);
                assert_eq!(
                    plan.capture_generation(),
                    vector.request.capture_generation,
                    "{}",
                    vector.name
                );
                assert_eq!(plan.flow_id(), vector.request.flow_id, "{}", vector.name);
                assert_eq!(
                    plan.route_epoch(),
                    vector.request.current_route_epoch,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    plan.expires_at_ms(),
                    vector.request.baseline.expires_at_ms,
                    "{}",
                    vector.name
                );
            }
            Err(error) => {
                assert_eq!(vector.expected.result, "error", "{}", vector.name);
                assert_eq!(Some(error.code()), vector.expected.error, "{}", vector.name);
                assert_eq!(vector.expected.destination, None, "{}", vector.name);
                assert_eq!(vector.expected.source_address, None, "{}", vector.name);
                assert_eq!(vector.expected.egress_luid, None, "{}", vector.name);
                assert_eq!(vector.expected.egress_index, None, "{}", vector.name);
                assert_eq!(vector.expected.binding_kind, None, "{}", vector.name);
                assert_eq!(vector.expected.binding_value, None, "{}", vector.name);
            }
        }
    }
}

#[test]
fn owned_capture_route_transition_is_exact_and_later_changes_invalidate_it() {
    let mut request = contract()
        .vectors
        .into_iter()
        .find(|vector| vector.name == "ipv4-system-egress-is-generation-and-route-bound")
        .expect("IPv4 admission vector must exist")
        .request;

    assert!(prepare_windows_packet_egress(&request).is_ok());

    request.capture_route.previous_route_epoch = request.baseline.route_epoch + 1;
    assert_eq!(
        prepare_windows_packet_egress(&request)
            .expect_err("owned transition must begin at the baseline epoch")
            .code(),
        WindowsPacketEgressErrorCode::CaptureRoutePreviousEpochMismatch
    );

    request.capture_route.previous_route_epoch = request.baseline.route_epoch;
    request.capture_route.active_route_epoch = request.baseline.route_epoch;
    assert_eq!(
        prepare_windows_packet_egress(&request)
            .expect_err("owned transition must advance the route epoch")
            .code(),
        WindowsPacketEgressErrorCode::InvalidCaptureRouteEpochTransition
    );

    request.capture_route.active_route_epoch = request.current_route_epoch;
    request.current_route_epoch += 1;
    assert_eq!(
        prepare_windows_packet_egress(&request)
            .expect_err("a later route change must invalidate the admission")
            .code(),
        WindowsPacketEgressErrorCode::RouteEpochMismatch
    );
}

#[test]
fn every_egress_failure_has_a_stable_machine_code() {
    let codes = [
        WindowsPacketEgressErrorCode::InvalidCaptureGeneration,
        WindowsPacketEgressErrorCode::InvalidFlowId,
        WindowsPacketEgressErrorCode::InvalidRouteEpoch,
        WindowsPacketEgressErrorCode::CaptureGenerationMismatch,
        WindowsPacketEgressErrorCode::CaptureRouteGenerationMismatch,
        WindowsPacketEgressErrorCode::CaptureRoutePreviousEpochMismatch,
        WindowsPacketEgressErrorCode::InvalidCaptureRouteEpochTransition,
        WindowsPacketEgressErrorCode::RouteEpochMismatch,
        WindowsPacketEgressErrorCode::InvalidActivationWindow,
        WindowsPacketEgressErrorCode::RouteObservedAfterCapture,
        WindowsPacketEgressErrorCode::InvalidCaptureRouteActivationWindow,
        WindowsPacketEgressErrorCode::InvalidEvidenceWindow,
        WindowsPacketEgressErrorCode::EvidenceExpired,
        WindowsPacketEgressErrorCode::DestinationNotCanonical,
        WindowsPacketEgressErrorCode::BaselineDestinationNotCanonical,
        WindowsPacketEgressErrorCode::UnsafeDestination,
        WindowsPacketEgressErrorCode::DestinationMismatch,
        WindowsPacketEgressErrorCode::CaptureRouteDestinationMismatch,
        WindowsPacketEgressErrorCode::CaptureRoutePrefixMismatch,
        WindowsPacketEgressErrorCode::InvalidInterfaceIdentity,
        WindowsPacketEgressErrorCode::CaptureInterfaceIdentityChanged,
        WindowsPacketEgressErrorCode::CaptureRouteInterfaceMismatch,
        WindowsPacketEgressErrorCode::EgressInterfaceIdentityChanged,
        WindowsPacketEgressErrorCode::CaptureInterfaceSelected,
        WindowsPacketEgressErrorCode::SourceAddressNotCanonical,
        WindowsPacketEgressErrorCode::CurrentSourceAddressNotCanonical,
        WindowsPacketEgressErrorCode::SourceAddressChanged,
        WindowsPacketEgressErrorCode::SourceAddressFamilyMismatch,
        WindowsPacketEgressErrorCode::UnsafeSourceAddress,
        WindowsPacketEgressErrorCode::InvalidRoutePrefix,
        WindowsPacketEgressErrorCode::RoutePrefixFamilyMismatch,
        WindowsPacketEgressErrorCode::DestinationOutsideRoutePrefix,
        WindowsPacketEgressErrorCode::LoopbackRoute,
    ];
    assert!(codes.iter().all(|code| !code.as_str().is_empty()));
    assert_eq!(MAX_PACKET_EGRESS_EVIDENCE_LIFETIME_MS, 5_000);
}

#[test]
fn egress_v1_is_pure_and_not_composed_into_the_production_host() {
    let source = include_str!("../src/packet_egress/v1.rs").replace("\r\n", "\n");
    for forbidden in [
        "windows_sys",
        "TcpStream",
        "UdpSocket",
        "socket2",
        "setsockopt",
        "GetBestRoute2",
        "NotifyRouteChange2",
        "ConvertInterfaceLuidToIndex",
        "CreateIpForwardEntry2",
        "DeleteIpForwardEntry2",
        "Wintun",
        "unsafe {",
    ] {
        assert!(
            !source.contains(forbidden),
            "egress v1 contains {forbidden}"
        );
    }

    let production_host = include_str!("../src/service_host/v1.rs");
    assert!(!production_host.contains("packet_egress"));
    assert!(!production_host.contains("prepare_windows_packet_egress"));
}

#[test]
fn native_route_observer_is_read_only_and_not_composed() {
    let source = include_str!("../src/packet_egress/windows.rs").replace("\r\n", "\n");
    for required in [
        "GetBestRoute2",
        "ConvertInterfaceLuidToIndex",
        "ConvertInterfaceIndexToLuid",
        "observe_windows_packet_route_on_interface",
        "&interface_luid",
        "&source_address_storage",
        "EgressInterfaceMismatch",
        "SourceAddressMismatch",
    ] {
        assert!(source.contains(required), "observer is missing {required}");
    }
    for forbidden in [
        "CreateIpForwardEntry2",
        "SetIpForwardEntry2",
        "DeleteIpForwardEntry2",
        "NotifyRouteChange2",
        "TcpStream",
        "UdpSocket",
        "socket2",
        "setsockopt",
        "Wintun",
        "Command::new",
        "is_usable_source_address",
    ] {
        assert!(!source.contains(forbidden), "observer contains {forbidden}");
    }

    let production_host = include_str!("../src/service_host/v1.rs");
    assert!(!production_host.contains("observe_windows_packet_route"));
    assert!(!production_host.contains("WindowsPacketRouteObservation"));
}

#[test]
fn owned_route_transition_issuer_is_opaque_pure_and_not_composed() {
    let source = include_str!("../src/packet_egress/transition_v1.rs").replace("\r\n", "\n");
    for required in [
        "Arc::ptr_eq",
        "begin_exact_host_activation",
        "attest_exact_host_route_created",
        "record_route_change",
        "require_current_activation",
    ] {
        assert!(source.contains(required), "issuer is missing {required}");
    }
    for forbidden in [
        "CreateIpForwardEntry2",
        "SetIpForwardEntry2",
        "DeleteIpForwardEntry2",
        "NotifyRouteChange2",
        "GetBestRoute2",
        "TcpStream",
        "UdpSocket",
        "socket2",
        "setsockopt",
        "Wintun",
        "Command::new",
        "Deserialize",
        "Serialize",
    ] {
        assert!(!source.contains(forbidden), "issuer contains {forbidden}");
    }

    let production_host = include_str!("../src/service_host/v1.rs");
    assert!(!production_host.contains("WindowsOwnedRouteTransitionIssuer"));
    assert!(!production_host.contains("WindowsOwnedCaptureRouteActivation"));
}

#[test]
fn disposable_exact_route_owner_is_feature_gated_exact_and_not_composed() {
    let owner =
        include_str!("../src/packet_egress/disposable_route_owner_v1.rs").replace("\r\n", "\n");
    for required in [
        "SLIPSTREAM_WINDOWS_DISPOSABLE_CI",
        "SLIPSTREAM_WINDOWS_WINTUN_EXACT_ROUTE_CI",
        "SLIPSTREAM_WINDOWS_WINTUN_SOCKET_BINDING_CI",
        "CreateIpForwardEntry2",
        "GetIpForwardEntry2",
        "DeleteIpForwardEntry2",
        "InitializeIpForwardEntry",
        "MIB_IPPROTO_NETMGMT",
        "attest_exact_host_route_created",
        "require_current_activation",
        "record_route_change",
        "cleanup_after",
        "secondary_after",
        "qualify_disposable_exact_host_route_with_active_probe",
        "WindowsDisposableExactRouteActiveProbe",
        "observe_windows_packet_route_on_interface",
        "BaselineEgressRevalidationFailed",
        "BaselineEgressInterfaceChanged",
        "BaselineSourceAddressChanged",
        "BaselineRoutePrefixChanged",
        "BaselineLoopbackStateChanged",
        "require_same_baseline_egress",
        "ActiveProbeGateClosed",
        "ActiveProbeFailed",
        "require_active_probe_gate()?;",
        "recovery_error_after",
        "recovery_failure_is_primary_and_retains_the_probe_failure",
        "error.win32_code()",
        "prior failure: {prior}; cleanup failure: {cleanup}",
        "ROUTE_REMOVAL_TIMEOUT",
        "self.row",
        "PrefixLength = prefix_length",
    ] {
        assert!(
            owner.contains(required),
            "route owner is missing {required}"
        );
    }
    for forbidden in [
        "SetIpForwardEntry2",
        "NotifyRouteChange2",
        "CreateUnicastIpAddressEntry",
        "SetUnicastIpAddressEntry",
        "DeleteUnicastIpAddressEntry",
        "GetIpForwardTable2",
        "WintunDeleteDriver",
        "TcpStream",
        "UdpSocket",
        "DnsQuery",
        "Set-DnsClientServerAddress",
        "WinHttp",
        "Command::new",
    ] {
        assert!(
            !owner.contains(forbidden),
            "route owner contains {forbidden}"
        );
    }
    let recovery_observation = owner
        .find("let recovered = match observe_windows_packet_route(destination)")
        .expect("route owner must always perform the recovery observation");
    let pending_error_return = owner
        .find("if let Some(error) = pending_error")
        .expect("route owner must retain a pending active-probe failure");
    assert!(
        recovery_observation < pending_error_return,
        "route owner must prove baseline recovery before returning an active-probe failure"
    );
    let probe_free_start = owner
        .find("pub fn qualify_disposable_exact_host_route(")
        .expect("route owner must retain the probe-free wrapper");
    let active_probe_start = owner
        .find("pub fn qualify_disposable_exact_host_route_with_active_probe")
        .expect("route owner must expose the gated active-probe entrypoint");
    let implementation_start = owner
        .find("fn qualify_disposable_exact_host_route_impl")
        .expect("both public entrypoints must share one exact-route implementation");
    let probe_free_wrapper = &owner[probe_free_start..active_probe_start];
    let active_probe_wrapper = &owner[active_probe_start..implementation_start];
    assert!(probe_free_wrapper.contains("qualify_disposable_exact_host_route_impl"));
    assert!(!probe_free_wrapper.contains("require_active_probe_gate"));
    assert!(active_probe_wrapper.contains("require_active_probe_gate()?;"));
    let baseline_revalidation = owner
        .find("let revalidated_baseline = observe_windows_packet_route_on_interface")
        .expect("route owner must revalidate baseline egress under the active exact route");
    let active_probe_call = owner
        .find("active_probe(&WindowsDisposableExactRouteActiveProbe")
        .expect("route owner must invoke the disposable probe");
    assert!(
        baseline_revalidation < active_probe_call,
        "baseline source and interface must be revalidated before the probe can run"
    );

    let module = include_str!("../src/packet_egress/mod.rs").replace("\r\n", "\n");
    assert!(module.contains(
        "#[cfg(all(windows, feature = \"disposable-windows-packet-fixture\"))]\n#[allow(unsafe_code)]\nmod disposable_route_owner_v1;"
    ));

    let fixture = include_str!("wintun_exact_route_windows.rs");
    for required in [
        "disposable-windows-packet-fixture",
        "SLIPSTREAM_WINDOWS_DISPOSABLE_CI",
        "SLIPSTREAM_WINDOWS_WINTUN_EXACT_ROUTE_CI",
        "SLIPSTREAM_WINDOWS_WINTUN_SOCKET_BINDING_CI",
        "SLIPSTREAM_WINDOWS_WINTUN_PACKET_DELIVERY_CI",
        "SLIPSTREAM_WINDOWS_WINTUN_PREEXISTING_FLOW_CI",
        "WintunGetAdapterLUID",
        "ConvertInterfaceLuidToIndex",
        "ConvertInterfaceIndexToLuid",
        "InitializeUnicastIpAddressEntry",
        "CreateUnicastIpAddressEntry",
        "GetUnicastIpAddressEntry",
        "DeleteUnicastIpAddressEntry",
        "OwnedUnicastAddress",
        "ADDRESS_READY_TIMEOUT",
        "ADDRESS_REMOVAL_TIMEOUT",
        "wait_until_preferred",
        "IpDadStatePreferred",
        "observed.OnLinkPrefixLength != self.row.OnLinkPrefixLength",
        "SkipAsSource",
        "readiness failed after verified cleanup",
        "exact cleanup failed",
        "remove_and_verify",
        "qualify_disposable_exact_host_route",
        "qualify_disposable_exact_host_route_with_active_probe",
        "native_wintun_ipv4_socket_binding_avoids_the_competing_exact_route",
        "native_wintun_ipv6_socket_binding_avoids_the_competing_exact_route",
        "native_wintun_ipv4_packet_round_trip_is_captured_and_injected",
        "native_wintun_ipv4_preexisting_flow_is_preserved_or_safely_recovered",
        "native_wintun_ipv6_packet_round_trip_is_captured_and_injected",
        "injected active-probe failure must be returned after recovery proof",
        "IP_UNICAST_IF",
        "interface_index.to_be()",
        "IPV6_UNICAST_IF",
        "set_and_verify_ipv6_unicast_interface",
        "OwnedFixtureBaselineRoute",
        "CreateIpForwardEntry2",
        "GetIpForwardEntry2",
        "DeleteIpForwardEntry2",
        "fixture baseline route must remain the fixed IPv4 /24 or IPv6 /64",
        "const IPV4_BASELINE_PREFIX_LENGTH: u8 = 24;",
        "const IPV4_HOST_PREFIX_LENGTH: u8 = 32;",
        "const IPV6_BASELINE_PREFIX_LENGTH: u8 = 64;",
        "const IPV6_HOST_PREFIX_LENGTH: u8 = 128;",
        "BASELINE_ROUTE_REMOVAL_TIMEOUT",
        "getsockopt",
        "setsockopt",
        "Socket::new",
        ".local_addr()",
        ".peer_addr()",
        "connect no-payload IPv4 UDP socket",
        "connect no-payload IPv6 UDP socket",
        "WintunReceivePacket",
        "WintunReleaseReceivePacket",
        "WintunAllocateSendPacket",
        "WintunSendPacket",
        "receive_matching_ipv4_udp_request",
        "receive_ipv4_udp_request_from_either_adapter",
        "try_receive_packet",
        "receive_matching_ipv6_udp_request",
        "build_ipv4_udp_packet",
        "build_ipv6_udp_packet",
        "PACKET_DELIVERY_TIMEOUT",
        "Wintun packet receive exceeded its bounded deadline",
        "Wintun packet round trip exceeded its bounded deadline",
        "Wintun IPv6 packet round trip exceeded its bounded deadline",
        "PREEXISTING_WARMUP_REQUEST",
        "PREEXISTING_CAPTURE_ROLLBACK",
        "require_adapter_absent",
    ] {
        assert!(
            fixture.contains(required),
            "route fixture is missing {required}"
        );
    }
    for forbidden in [
        "SetUnicastIpAddressEntry",
        "GetUnicastIpAddressTable",
        "Set-DnsClientServerAddress",
        "WintunDeleteDriver",
        ".send_to(",
        ".recv_from(",
        "TcpStream",
    ] {
        assert!(
            !fixture.contains(forbidden),
            "route fixture contains {forbidden}"
        );
    }

    let preexisting_start = fixture
        .find("fn native_wintun_ipv4_preexisting_flow_is_preserved_or_safely_recovered()")
        .expect("fixture must contain the IPv4 pre-existing-flow gate");
    let preexisting_end = fixture[preexisting_start..]
        .find("fn native_wintun_ipv6_packet_round_trip_is_captured_and_injected()")
        .map(|offset| preexisting_start + offset)
        .expect("pre-existing-flow gate must end before the IPv6 packet gate");
    let preexisting = &fixture[preexisting_start..preexisting_end];
    assert!(preexisting.contains("PREEXISTING_CAPTURE_ROLLBACK"));
    let warmup = preexisting
        .find("PREEXISTING_WARMUP_REQUEST")
        .expect("pre-existing-flow gate must prove a warm-up exchange");
    let activation = preexisting
        .find("qualify_disposable_exact_host_route_with_active_probe")
        .expect("pre-existing-flow gate must use the owned exact-route activation");
    let retry = preexisting
        .find("PREEXISTING_RETRY_REQUEST")
        .expect("pre-existing-flow gate must retain a post-rollback retry");
    let cleanup = preexisting
        .find("let baseline_route_cleanup = match baseline_route.as_mut()")
        .expect("pre-existing-flow gate must explicitly clean its baseline route");
    let accept_flow_result = preexisting
        .find("flow_result?;")
        .expect("pre-existing-flow gate must defer its result until after cleanup");
    assert!(warmup < activation && activation < retry);
    assert!(cleanup < accept_flow_result);

    for (start_marker, end_marker) in [
        (
            "fn native_wintun_ipv4_socket_binding_avoids_the_competing_exact_route()",
            "fn native_wintun_ipv6_socket_binding_avoids_the_competing_exact_route()",
        ),
        (
            "fn native_wintun_ipv6_socket_binding_avoids_the_competing_exact_route()",
            "fn native_wintun_ipv4_packet_round_trip_is_captured_and_injected()",
        ),
        (
            "fn prove_ipv4_socket_binding(",
            "fn prove_ipv6_socket_binding(",
        ),
        (
            "fn prove_ipv6_socket_binding(",
            "fn set_and_verify_ipv4_unicast_interface(",
        ),
    ] {
        let start = fixture
            .find(start_marker)
            .unwrap_or_else(|| panic!("missing no-payload region start {start_marker}"));
        let end = fixture[start..]
            .find(end_marker)
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("missing no-payload region end {end_marker}"));
        let region = &fixture[start..end];
        for forbidden in [".send(", ".send_to(", ".recv(", ".recv_from("] {
            assert!(
                !region.contains(forbidden),
                "no-payload region {start_marker} contains {forbidden}"
            );
        }
    }

    let workflow =
        include_str!("../../../.github/workflows/windows-packet-adapter-qualification.yml");
    assert!(workflow
        .contains("Qualify exact-route transition, pinned egress revalidation, and cleanup"));
    assert!(workflow.contains("-TestTarget wintun_exact_route_windows"));
    assert!(workflow.contains("-TimeoutSeconds 120"));
    assert!(workflow.contains("Qualify no-payload IPv4 socket selection under exact route"));
    assert!(workflow
        .contains("-TestName native_wintun_ipv4_socket_binding_avoids_the_competing_exact_route"));
    assert!(workflow.contains("Qualify no-payload IPv6 socket selection under exact route"));
    assert!(workflow
        .contains("-TestName native_wintun_ipv6_socket_binding_avoids_the_competing_exact_route"));
    assert!(workflow.contains("Qualify closed IPv4 packet capture and injection round trip"));
    assert!(workflow
        .contains("-TestName native_wintun_ipv4_packet_round_trip_is_captured_and_injected"));
    assert!(workflow.contains("Qualify pre-existing IPv4 UDP flow activation safety"));
    assert!(workflow.contains(
        "-TestName native_wintun_ipv4_preexisting_flow_is_preserved_or_safely_recovered"
    ));
    assert!(workflow.contains("SLIPSTREAM_WINDOWS_WINTUN_PREEXISTING_FLOW_CI: \"1\""));
    assert!(workflow.contains("Qualify closed IPv6 packet capture and injection round trip"));
    assert!(workflow
        .contains("-TestName native_wintun_ipv6_packet_round_trip_is_captured_and_injected"));
    assert!(workflow.contains("SLIPSTREAM_WINDOWS_WINTUN_PACKET_DELIVERY_CI: \"1\""));

    let production_host = include_str!("../src/service_host/windows.rs");
    assert!(!production_host.contains("disposable_route_owner_v1"));
    assert!(!production_host.contains("qualify_disposable_exact_host_route"));
    assert!(!production_host.contains("WintunReceivePacket"));
    assert!(!production_host.contains("WintunSendPacket"));
}

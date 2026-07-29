use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../contracts/windows-route-change-observer-v1.json"
    ))
    .expect("parse Windows route-change observer contract")
}

#[test]
fn route_change_observer_contract_is_frozen_and_bounded() {
    let contract = contract();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract"],
        "slipstream.windows_route_change_observer"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["invariants"]["read_only_subscription"], true);
    assert_eq!(contract["invariants"]["bounded_event_history"], 64);
    assert_eq!(
        contract["invariants"]["cleanup_failure_is_structured"],
        true
    );
    assert_eq!(
        contract["invariants"]["production_service_host_composition"],
        false
    );
    assert_eq!(
        contract["disposable_native_qualification"]["architectures"],
        serde_json::json!(["amd64", "arm64"])
    );
    assert_eq!(
        contract["disposable_native_qualification"]["active_token_invalidated"],
        true
    );
}

#[test]
fn native_observer_is_read_only_bounded_and_not_composed() {
    let source = include_str!("../src/packet_egress/route_change_observer_windows_v1.rs")
        .replace("\r\n", "\n");
    for required in [
        "NotifyRouteChange2",
        "CancelMibChangeNotify2",
        "MAX_RETAINED_EVENTS: usize = 64",
        "VecDeque",
        "wait_for_route_after",
        "EventHistoryOverflow",
        "SequenceExhausted",
        "context.changed.notify_all()",
        "Windows reported a successful registration",
        "The kernel may still call this context",
    ] {
        assert!(source.contains(required), "observer is missing {required}");
    }
    for forbidden in [
        "CreateIpForwardEntry2",
        "SetIpForwardEntry2",
        "DeleteIpForwardEntry2",
        "GetBestRoute2",
        "TcpStream",
        "UdpSocket",
        "socket2",
        "Command::new",
        "CreateProcess",
        "StartService",
        "Wintun",
    ] {
        assert!(!source.contains(forbidden), "observer contains {forbidden}");
    }

    let production_host = include_str!("../src/service_host/windows.rs");
    assert!(!production_host.contains("WindowsRouteChangeObserverV1"));
    assert!(!production_host.contains("qualify_disposable_windows_route_churn"));
}

#[test]
fn disposable_route_churn_gate_is_exact_and_feature_only() {
    let source =
        include_str!("../src/packet_egress/disposable_route_churn_v1.rs").replace("\r\n", "\n");
    for required in [
        "SLIPSTREAM_WINDOWS_DISPOSABLE_CI",
        "SLIPSTREAM_WINDOWS_WINTUN_EXACT_ROUTE_CI",
        "SLIPSTREAM_WINDOWS_WINTUN_ROUTE_CHURN_CI",
        "windows_disposable_route_churn_gate_is_open",
        "qualify_disposable_windows_route_churn",
        "attest_exact_host_route_created",
        "require_current_activation",
        "record_route_change",
        "CreateIpForwardEntry2",
        "GetIpForwardEntry2",
        "DeleteIpForwardEntry2",
        "observe_windows_packet_route",
        "baseline route identity changed after cleanup",
        "active token survived a later native route change",
        "route_lookup_failure_after_cleanup",
        "CleanupFailed",
    ] {
        assert!(
            source.contains(required),
            "route-churn qualification is missing {required}"
        );
    }
    for forbidden in [
        "SetIpForwardEntry2",
        "TcpStream",
        "UdpSocket",
        "socket2",
        "Command::new",
        "CreateProcess",
        "StartService",
        "SetInterfaceDnsSettings",
        "WinHttpSetDefaultProxyConfiguration",
        "InternetSetOption",
        "RasDial",
    ] {
        assert!(
            !source.contains(forbidden),
            "route-churn qualification contains {forbidden}"
        );
    }

    let module = include_str!("../src/packet_egress/mod.rs");
    assert!(
        module.contains("#[cfg(all(windows, feature = \"disposable-windows-packet-fixture\"))]")
    );
    let production_host = include_str!("../src/service_host/windows.rs");
    assert!(!production_host.contains("disposable_route_churn_v1"));
    assert!(!production_host.contains("WindowsRouteChangeObserverV1"));
}

#![cfg(windows)]

use slipstream_windows_adapter::packet_egress::{
    observe_windows_packet_route, observe_windows_packet_route_on_interface,
    WindowsOwnedRouteTransitionIssuer, WindowsOwnedRouteTransitionState,
    WindowsPacketInterfaceIdentity, WindowsPacketRouteObserverErrorCode,
};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn native_packet_route_observer_is_read_only_and_consistent() {
    let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let observation = observe_windows_packet_route(destination)
        .expect("the native runner must expose a route to a public IPv4 destination");

    assert_eq!(observation.destination(), destination);
    assert_ne!(observation.egress_interface().luid, 0);
    assert_ne!(observation.egress_interface().index, 0);
    assert!(matches!(observation.source_address(), IpAddr::V4(_)));
    assert!(!observation.route_prefix().is_empty());
    assert!(!observation.route_is_loopback());

    let egress = observation.egress_interface();
    let source = observation.source_address();
    let constrained = observe_windows_packet_route_on_interface(destination, egress, source)
        .expect("the native runner must revalidate its selected interface and source");
    assert_eq!(constrained.destination(), destination);
    assert_eq!(constrained.egress_interface(), egress);
    assert_eq!(constrained.source_address(), source);
    assert_eq!(constrained.route_prefix(), observation.route_prefix());
    assert_eq!(
        constrained.route_is_loopback(),
        observation.route_is_loopback()
    );

    let capture = WindowsPacketInterfaceIdentity {
        luid: if egress.luid == 1 { 2 } else { 1 },
        index: if egress.index == 1 { 2 } else { 1 },
    };
    let mut issuer = WindowsOwnedRouteTransitionIssuer::new(1, capture, 1)
        .expect("a distinct non-zero capture identity must be accepted");
    let intent = issuer
        .begin_exact_host_activation(observation)
        .expect("the collector-owned timestamp must stage immediately");
    assert_eq!(intent.baseline().egress_interface, egress);
    issuer
        .cancel_before_effect(intent)
        .expect("staging without a route effect must remain reversible");
    assert_eq!(issuer.state(), WindowsOwnedRouteTransitionState::Ready);

    let error = observe_windows_packet_route(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .expect_err("special-purpose destinations must fail before route observation");
    assert_eq!(
        error.code(),
        WindowsPacketRouteObserverErrorCode::UnsafeDestination
    );
    assert_eq!(error.win32_code(), None);

    let error = observe_windows_packet_route_on_interface(
        destination,
        egress,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    )
    .expect_err("unsafe source constraints must fail before route observation");
    assert_eq!(
        error.code(),
        WindowsPacketRouteObserverErrorCode::UnsafeSourceAddress
    );
    assert_eq!(error.win32_code(), None);
}

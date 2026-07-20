#![cfg(windows)]

use slipstream_windows_adapter::packet_egress::{
    observe_windows_packet_route, WindowsPacketRouteObserverErrorCode,
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

    let error = observe_windows_packet_route(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .expect_err("special-purpose destinations must fail before route observation");
    assert_eq!(
        error.code(),
        WindowsPacketRouteObserverErrorCode::UnsafeDestination
    );
    assert_eq!(error.win32_code(), None);
}

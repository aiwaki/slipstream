#![cfg(all(windows, feature = "disposable-windows-packet-fixture"))]

use slipstream_windows_adapter::packet_adapter::{
    collect_windows_packet_adapter_artifact, WindowsCollectedPacketAdapterAdmission,
    WindowsPacketAdapterArchitecture,
};
use slipstream_windows_adapter::packet_egress::{
    qualify_disposable_exact_host_route, qualify_disposable_exact_host_route_with_active_probe,
    WindowsDisposableExactRouteActiveProbe, WindowsDisposableExactRouteErrorCode,
    WindowsOwnedRouteTransitionIssuer, WindowsPacketInterfaceIdentity,
    WINDOWS_DISPOSABLE_EXACT_ROUTE_OWNER_VERSION,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawSocket;
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    FreeLibrary, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS, HMODULE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
    CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry,
    GetIpForwardEntry2, GetUnicastIpAddressEntry, InitializeIpForwardEntry,
    InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    getsockopt, setsockopt, IpDadStatePreferred, WSAGetLastError, AF_INET, AF_INET6, IN6_ADDR,
    IN6_ADDR_0, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
    IP_UNICAST_IF, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
    SOCKET,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

const DISPOSABLE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_DISPOSABLE_CI";
const EXACT_ROUTE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_EXACT_ROUTE_CI";
const SOCKET_BINDING_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_SOCKET_BINDING_CI";
const PACKET_DELIVERY_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_PACKET_DELIVERY_CI";
const WINTUN_MIN_RING_CAPACITY: u32 = 0x2_0000;
const WINTUN_MAX_IP_PACKET_SIZE: usize = 0xffff;
const ADDRESS_READY_TIMEOUT: Duration = Duration::from_secs(5);
const ADDRESS_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);
const ADDRESS_PROBE_INTERVAL: Duration = Duration::from_millis(25);
const BASELINE_ROUTE_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);
const PACKET_DELIVERY_TIMEOUT: Duration = Duration::from_secs(3);
const PACKET_DELIVERY_PROBE_INTERVAL: Duration = Duration::from_millis(5);
const PACKET_DELIVERY_PORT: u16 = 41_723;
const PACKET_REQUEST_PAYLOAD: &[u8] = b"slipstream-wintun-request-v1";
const PACKET_RESPONSE_PAYLOAD: &[u8] = b"slipstream-wintun-response-v1";
const IPV4_MIN_HEADER_LENGTH: usize = 20;
const UDP_HEADER_LENGTH: usize = 8;
const IPV4_VERSION_AND_MIN_HEADER_LENGTH: u8 = 0x45;
const IPV4_PACKET_IDENTIFICATION: u16 = 0x534c;
const IPV4_DEFAULT_TTL: u8 = 64;
const IPV4_UDP_PROTOCOL: u8 = 17;
const IPV6_BASELINE_NETWORK: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0);
const IPV6_BASELINE_SOURCE: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 2);
const IPV6_CAPTURE_SOURCE: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 3);
const IPV6_DESTINATION: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
const IPV6_BASELINE_PREFIX_LENGTH: u8 = 64;
const IPV6_HOST_PREFIX_LENGTH: u8 = 128;

type WintunAdapterHandle = *mut c_void;
type WintunSessionHandle = *mut c_void;
type WintunCreateAdapter = unsafe extern "system" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const GUID,
) -> WintunAdapterHandle;
type WintunOpenAdapter = unsafe extern "system" fn(name: *const u16) -> WintunAdapterHandle;
type WintunCloseAdapter = unsafe extern "system" fn(adapter: WintunAdapterHandle);
type WintunGetAdapterLuid =
    unsafe extern "system" fn(adapter: WintunAdapterHandle, luid: *mut NET_LUID_LH);
type WintunGetRunningDriverVersion = unsafe extern "system" fn() -> u32;
type WintunStartSession =
    unsafe extern "system" fn(adapter: WintunAdapterHandle, capacity: u32) -> WintunSessionHandle;
type WintunEndSession = unsafe extern "system" fn(session: WintunSessionHandle);
type WintunReceivePacket =
    unsafe extern "system" fn(session: WintunSessionHandle, packet_size: *mut u32) -> *mut u8;
type WintunReleaseReceivePacket =
    unsafe extern "system" fn(session: WintunSessionHandle, packet: *const u8);
type WintunAllocateSendPacket =
    unsafe extern "system" fn(session: WintunSessionHandle, packet_size: u32) -> *mut u8;
type WintunSendPacket = unsafe extern "system" fn(session: WintunSessionHandle, packet: *const u8);

#[test]
fn native_wintun_exact_route_transition_is_owned_and_removed() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let adapter_name = wide(&unique_adapter_name("Route"));
    let tunnel_type = wide("Slipstream CI Route");
    api.require_adapter_absent(&adapter_name, "before exact-route fixture")
        .unwrap_or_else(|error| panic!("Wintun exact-route preflight: {error}"));

    let qualification_result = (|| {
        let mut adapter = OwnedWintunAdapter::create(&api, &adapter_name, &tunnel_type)?;
        adapter.start_session()?;
        let capture_interface = adapter.interface_identity()?;
        let mut issuer = WindowsOwnedRouteTransitionIssuer::new(1, capture_interface, 1)
            .map_err(|error| format!("construct exact-route issuer: {error}"))?;
        let mut address = OwnedUnicastAddress::create(
            capture_interface,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            32,
        )?;
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let route_result = qualify_disposable_exact_host_route(&mut issuer, destination)
            .map_err(|error| format!("qualify exact-route owner: {error}"));
        let address_cleanup = address.remove_and_verify();
        if let Err(cleanup_error) = address_cleanup {
            return Err(format!(
                "owned Wintun address cleanup failed: {cleanup_error}; route result: {route_result:?}"
            ));
        }
        let qualification = route_result?;

        if WINDOWS_DISPOSABLE_EXACT_ROUTE_OWNER_VERSION != 1
            || qualification.destination() != destination
            || qualification.exact_route_prefix() != "1.1.1.1/32"
            || qualification.capture_interface() != capture_interface
            || qualification.baseline_egress_interface() == capture_interface
            || qualification.recovered_egress_interface()
                != qualification.baseline_egress_interface()
            || qualification.route_epoch_after_removal() != 3
        {
            return Err("exact-route qualification returned inconsistent evidence".to_owned());
        }

        adapter.end_session();
        adapter.close_adapter();
        Ok::<(), String>(())
    })();

    let cleanup_result = api.require_adapter_absent(&adapter_name, "after exact-route fixture");
    if let Err(cleanup_error) = cleanup_result {
        panic!(
            "Wintun exact-route cleanup proof failed: {cleanup_error}; qualification result: {qualification_result:?}"
        );
    }
    if let Err(qualification_error) = qualification_result {
        panic!("disposable exact-route qualification failed after adapter cleanup: {qualification_error}");
    }

    drop(api);
    assert_eq!(
        admission
            .retained_dll_length()
            .expect("revalidate retained admitted Wintun DLL"),
        admission.evidence().dll_length
    );
}

#[test]
fn native_wintun_ipv4_socket_binding_avoids_the_competing_exact_route() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(SOCKET_BINDING_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let adapter_name = wide(&unique_adapter_name("Socket"));
    let tunnel_type = wide("Slipstream CI Socket");
    api.require_adapter_absent(&adapter_name, "before socket-binding fixture")
        .unwrap_or_else(|error| panic!("Wintun socket-binding preflight: {error}"));

    let qualification_result = (|| {
        let mut adapter = OwnedWintunAdapter::create(&api, &adapter_name, &tunnel_type)?;
        adapter.start_session()?;
        let capture_interface = adapter.interface_identity()?;
        let capture_source = Ipv4Addr::new(192, 0, 2, 2);
        let mut address =
            OwnedUnicastAddress::create(capture_interface, IpAddr::V4(capture_source), 32)?;
        let destination = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let mut failure_issuer = WindowsOwnedRouteTransitionIssuer::new(2, capture_interface, 1)
            .map_err(|error| format!("construct probe-failure issuer: {error}"))?;
        let injected_error = qualify_disposable_exact_host_route_with_active_probe(
            &mut failure_issuer,
            destination,
            |active| {
                if active.capture_source_address() != IpAddr::V4(capture_source) {
                    return Err("unexpected capture source before injected failure".to_owned());
                }
                Err("injected active-probe failure".to_owned())
            },
        )
        .expect_err("injected active-probe failure must be returned after recovery proof");
        if injected_error.code() != WindowsDisposableExactRouteErrorCode::ActiveProbeFailed
            || !injected_error
                .to_string()
                .contains("injected active-probe failure")
        {
            return Err(format!(
                "probe-failure recovery returned unexpected evidence: {injected_error}"
            ));
        }

        let mut issuer = WindowsOwnedRouteTransitionIssuer::new(3, capture_interface, 1)
            .map_err(|error| format!("construct socket-binding issuer: {error}"))?;
        let route_result = qualify_disposable_exact_host_route_with_active_probe(
            &mut issuer,
            destination,
            |active| prove_ipv4_socket_binding(active, capture_source),
        )
        .map_err(|error| format!("qualify IPv4 socket binding: {error}"));
        let address_cleanup = address.remove_and_verify();
        if let Err(cleanup_error) = address_cleanup {
            return Err(format!(
                "owned Wintun address cleanup failed: {cleanup_error}; socket result: {route_result:?}"
            ));
        }
        let qualification = route_result?;

        if qualification.destination() != destination
            || qualification.exact_route_prefix() != "1.0.0.1/32"
            || qualification.capture_interface() != capture_interface
            || qualification.baseline_egress_interface() == capture_interface
            || qualification.recovered_egress_interface()
                != qualification.baseline_egress_interface()
            || qualification.route_epoch_after_removal() != 3
        {
            return Err("socket-binding qualification returned inconsistent evidence".to_owned());
        }

        adapter.end_session();
        adapter.close_adapter();
        Ok::<(), String>(())
    })();

    let cleanup_result = api.require_adapter_absent(&adapter_name, "after socket-binding fixture");
    if let Err(cleanup_error) = cleanup_result {
        panic!(
            "Wintun socket-binding cleanup proof failed: {cleanup_error}; qualification result: {qualification_result:?}"
        );
    }
    if let Err(qualification_error) = qualification_result {
        panic!(
            "disposable socket-binding qualification failed after adapter cleanup: {qualification_error}"
        );
    }

    drop(api);
    assert_eq!(
        admission
            .retained_dll_length()
            .expect("revalidate retained admitted Wintun DLL"),
        admission.evidence().dll_length
    );
}

#[test]
fn native_wintun_ipv6_socket_binding_avoids_the_competing_exact_route() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(SOCKET_BINDING_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let baseline_name = wide(&unique_adapter_name("Socket6Baseline"));
    let capture_name = wide(&unique_adapter_name("Socket6Capture"));
    let baseline_tunnel_type = wide("Slipstream CI IPv6 Baseline");
    let capture_tunnel_type = wide("Slipstream CI IPv6 Capture");
    api.require_adapter_absent(&baseline_name, "before IPv6 baseline fixture")
        .unwrap_or_else(|error| panic!("Wintun IPv6 baseline preflight: {error}"));
    api.require_adapter_absent(&capture_name, "before IPv6 capture fixture")
        .unwrap_or_else(|error| panic!("Wintun IPv6 capture preflight: {error}"));

    let qualification_result = (|| {
        let mut baseline_adapter =
            OwnedWintunAdapter::create(&api, &baseline_name, &baseline_tunnel_type)?;
        baseline_adapter.start_session()?;
        let baseline_interface = baseline_adapter.interface_identity()?;
        let mut capture_adapter =
            OwnedWintunAdapter::create(&api, &capture_name, &capture_tunnel_type)?;
        capture_adapter.start_session()?;
        let capture_interface = capture_adapter.interface_identity()?;
        if capture_interface == baseline_interface {
            return Err("IPv6 fixture adapters resolved to the same interface".to_owned());
        }

        let baseline_source = IPV6_BASELINE_SOURCE;
        let capture_source = IPV6_CAPTURE_SOURCE;
        let destination = IpAddr::V6(IPV6_DESTINATION);
        let mut baseline_address = OwnedUnicastAddress::create(
            baseline_interface,
            IpAddr::V6(baseline_source),
            IPV6_HOST_PREFIX_LENGTH,
        )?;
        let mut capture_address = OwnedUnicastAddress::create(
            capture_interface,
            IpAddr::V6(capture_source),
            IPV6_HOST_PREFIX_LENGTH,
        )?;
        let mut issuer = WindowsOwnedRouteTransitionIssuer::new(4, capture_interface, 1)
            .map_err(|error| format!("construct IPv6 socket-binding issuer: {error}"))?;
        let mut baseline_route = OwnedFixtureBaselineRoute::create(
            baseline_interface,
            IPV6_BASELINE_NETWORK,
            IPV6_BASELINE_PREFIX_LENGTH,
        )?;

        let route_result = qualify_disposable_exact_host_route_with_active_probe(
            &mut issuer,
            destination,
            |active| {
                prove_ipv6_socket_binding(
                    active,
                    capture_source,
                    baseline_interface,
                    baseline_source,
                )
            },
        )
        .map_err(|error| format!("qualify IPv6 socket binding: {error}"));

        let baseline_route_cleanup = baseline_route.remove_and_verify();
        let capture_address_cleanup = capture_address.remove_and_verify();
        let baseline_address_cleanup = baseline_address.remove_and_verify();
        let mut cleanup_errors = Vec::new();
        if let Err(error) = baseline_route_cleanup {
            cleanup_errors.push(format!("baseline route: {error}"));
        }
        if let Err(error) = capture_address_cleanup {
            cleanup_errors.push(format!("capture address: {error}"));
        }
        if let Err(error) = baseline_address_cleanup {
            cleanup_errors.push(format!("baseline address: {error}"));
        }
        if !cleanup_errors.is_empty() {
            return Err(format!(
                "IPv6 fixture cleanup failed: {}; socket result: {route_result:?}",
                cleanup_errors.join("; ")
            ));
        }
        let qualification = route_result?;

        if qualification.destination() != destination
            || qualification.exact_route_prefix() != "2606:4700:4700::1111/128"
            || qualification.capture_interface() != capture_interface
            || qualification.baseline_egress_interface() != baseline_interface
            || qualification.recovered_egress_interface() != baseline_interface
            || qualification.route_epoch_after_removal() != 3
        {
            return Err(
                "IPv6 socket-binding qualification returned inconsistent evidence".to_owned(),
            );
        }

        capture_adapter.end_session();
        capture_adapter.close_adapter();
        baseline_adapter.end_session();
        baseline_adapter.close_adapter();
        Ok::<(), String>(())
    })();

    let baseline_cleanup =
        api.require_adapter_absent(&baseline_name, "after IPv6 baseline fixture");
    let capture_cleanup = api.require_adapter_absent(&capture_name, "after IPv6 capture fixture");
    if baseline_cleanup.is_err() || capture_cleanup.is_err() {
        panic!(
            "Wintun IPv6 adapter cleanup proof failed: baseline={baseline_cleanup:?}, capture={capture_cleanup:?}; qualification result: {qualification_result:?}"
        );
    }
    if let Err(qualification_error) = qualification_result {
        panic!(
            "disposable IPv6 socket-binding qualification failed after adapter cleanup: {qualification_error}"
        );
    }

    drop(api);
    assert_eq!(
        admission
            .retained_dll_length()
            .expect("revalidate retained admitted Wintun DLL"),
        admission.evidence().dll_length
    );
}

#[test]
fn native_wintun_ipv4_packet_round_trip_is_captured_and_injected() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(SOCKET_BINDING_CI_ENV).as_deref() != Ok("1")
        || std::env::var(PACKET_DELIVERY_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let adapter_name = wide(&unique_adapter_name("Packet4"));
    let tunnel_type = wide("Slipstream CI IPv4 Packet Delivery");
    api.require_adapter_absent(&adapter_name, "before IPv4 packet-delivery fixture")
        .unwrap_or_else(|error| panic!("Wintun IPv4 packet-delivery preflight: {error}"));

    let qualification_result = (|| {
        let mut adapter = OwnedWintunAdapter::create(&api, &adapter_name, &tunnel_type)?;
        adapter.start_session()?;
        let capture_interface = adapter.interface_identity()?;
        let capture_source = Ipv4Addr::new(192, 0, 2, 20);
        let destination = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
        let mut address =
            OwnedUnicastAddress::create(capture_interface, IpAddr::V4(capture_source), 32)?;
        let mut issuer = WindowsOwnedRouteTransitionIssuer::new(5, capture_interface, 1)
            .map_err(|error| format!("construct IPv4 packet-delivery issuer: {error}"))?;

        let route_result = qualify_disposable_exact_host_route_with_active_probe(
            &mut issuer,
            destination,
            |active| prove_ipv4_packet_round_trip(active, &adapter, capture_source),
        )
        .map_err(|error| format!("qualify IPv4 packet delivery: {error}"));

        let address_cleanup = address.remove_and_verify();
        if let Err(cleanup_error) = address_cleanup {
            return Err(format!(
                "owned IPv4 packet-delivery address cleanup failed: {cleanup_error}; route result: {route_result:?}"
            ));
        }
        let qualification = route_result?;
        if qualification.destination() != destination
            || qualification.exact_route_prefix() != "1.0.0.2/32"
            || qualification.capture_interface() != capture_interface
            || qualification.baseline_egress_interface() == capture_interface
            || qualification.recovered_egress_interface()
                != qualification.baseline_egress_interface()
            || qualification.route_epoch_after_removal() != 3
        {
            return Err(
                "IPv4 packet-delivery qualification returned inconsistent evidence".to_owned(),
            );
        }

        adapter.end_session();
        adapter.close_adapter();
        Ok::<(), String>(())
    })();

    let cleanup_result =
        api.require_adapter_absent(&adapter_name, "after IPv4 packet-delivery fixture");
    if let Err(cleanup_error) = cleanup_result {
        panic!(
            "Wintun IPv4 packet-delivery cleanup proof failed: {cleanup_error}; qualification result: {qualification_result:?}"
        );
    }
    if let Err(qualification_error) = qualification_result {
        panic!(
            "disposable IPv4 packet-delivery qualification failed after adapter cleanup: {qualification_error}"
        );
    }

    drop(api);
    assert_eq!(
        admission
            .retained_dll_length()
            .expect("revalidate retained admitted Wintun DLL"),
        admission.evidence().dll_length
    );
}

fn prove_ipv4_packet_round_trip(
    active: &WindowsDisposableExactRouteActiveProbe<'_>,
    adapter: &OwnedWintunAdapter<'_>,
    expected_capture_source: Ipv4Addr,
) -> Result<(), String> {
    let destination = match active.destination() {
        IpAddr::V4(destination) => destination,
        IpAddr::V6(_) => {
            return Err("IPv4 packet-delivery probe received an IPv6 destination".to_owned())
        }
    };
    if active.exact_route_prefix() != format!("{destination}/32")
        || active.capture_interface() == active.baseline_egress_interface()
        || active.capture_source_address() != IpAddr::V4(expected_capture_source)
        || active.baseline_source_address() == IpAddr::V4(expected_capture_source)
    {
        return Err("active route facts do not prove the owned capture path".to_owned());
    }

    let peer = SocketAddrV4::new(destination, PACKET_DELIVERY_PORT);
    let socket = UdpSocket::bind(SocketAddrV4::new(expected_capture_source, 0))
        .map_err(|error| format!("bind IPv4 packet-delivery socket: {error}"))?;
    socket
        .connect(peer)
        .map_err(|error| format!("connect IPv4 packet-delivery socket: {error}"))?;
    let local = match socket
        .local_addr()
        .map_err(|error| format!("read IPv4 packet-delivery local address: {error}"))?
    {
        SocketAddr::V4(local) => local,
        SocketAddr::V6(_) => {
            return Err("IPv4 packet-delivery socket retained an IPv6 local address".to_owned())
        }
    };
    if *local.ip() != expected_capture_source || local.port() == 0 {
        return Err(format!(
            "IPv4 packet-delivery source mismatch: local={local}, expected={expected_capture_source}"
        ));
    }

    let deadline = Instant::now() + PACKET_DELIVERY_TIMEOUT;
    let sent = socket
        .send(PACKET_REQUEST_PAYLOAD)
        .map_err(|error| format!("send IPv4 packet-delivery request: {error}"))?;
    if sent != PACKET_REQUEST_PAYLOAD.len() {
        return Err(format!(
            "IPv4 packet-delivery request was partial: sent={sent}, expected={}",
            PACKET_REQUEST_PAYLOAD.len()
        ));
    }

    let request = adapter.receive_matching_ipv4_udp_request(
        expected_capture_source,
        destination,
        local.port(),
        PACKET_DELIVERY_PORT,
        PACKET_REQUEST_PAYLOAD,
        deadline,
    )?;
    let response = build_ipv4_udp_packet(
        destination,
        expected_capture_source,
        request.destination_port,
        request.source_port,
        PACKET_RESPONSE_PAYLOAD,
    )?;
    adapter.inject_packet(&response)?;

    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| "Wintun packet round trip exceeded its bounded deadline".to_owned())?;
    socket
        .set_read_timeout(Some(remaining))
        .map_err(|error| format!("bound IPv4 packet-delivery receive timeout: {error}"))?;
    let mut received = vec![0u8; PACKET_RESPONSE_PAYLOAD.len() + 1];
    let received_length = socket
        .recv(&mut received)
        .map_err(|error| format!("receive injected IPv4 packet-delivery response: {error}"))?;
    if Instant::now() > deadline {
        return Err("Wintun packet round trip exceeded its bounded deadline".to_owned());
    }
    if &received[..received_length] != PACKET_RESPONSE_PAYLOAD {
        return Err(format!(
            "injected IPv4 response payload mismatch: length={received_length}"
        ));
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct CapturedIpv4UdpRequest {
    source_port: u16,
    destination_port: u16,
}

fn parse_ipv4_udp_request(
    packet: &[u8],
    expected_source: Ipv4Addr,
    expected_destination: Ipv4Addr,
    expected_source_port: u16,
    expected_destination_port: u16,
    expected_payload: &[u8],
) -> Result<Option<CapturedIpv4UdpRequest>, String> {
    if packet.len() < IPV4_MIN_HEADER_LENGTH || packet[0] >> 4 != 4 {
        return Ok(None);
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if source != expected_source
        || destination != expected_destination
        || packet[9] != IPV4_UDP_PROTOCOL
    {
        return Ok(None);
    }

    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < IPV4_MIN_HEADER_LENGTH || header_length > packet.len() {
        return Err("captured IPv4 packet has an invalid header length".to_owned());
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length != packet.len() || total_length < header_length + UDP_HEADER_LENGTH {
        return Err(format!(
            "captured IPv4 packet length mismatch: packet={}, header={header_length}, total={total_length}",
            packet.len()
        ));
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return Err("captured IPv4 UDP request was fragmented".to_owned());
    }

    let udp = &packet[header_length..];
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if source_port != expected_source_port
        || destination_port != expected_destination_port
        || udp_length != udp.len()
        || udp_length != UDP_HEADER_LENGTH + expected_payload.len()
        || &udp[UDP_HEADER_LENGTH..] != expected_payload
    {
        return Err(format!(
            "captured IPv4 UDP request mismatch: source_port={source_port}, destination_port={destination_port}, udp_length={udp_length}, packet_udp_length={} ",
            udp.len()
        ));
    }
    Ok(Some(CapturedIpv4UdpRequest {
        source_port,
        destination_port,
    }))
}

fn build_ipv4_udp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let udp_length = UDP_HEADER_LENGTH
        .checked_add(payload.len())
        .ok_or_else(|| "IPv4 UDP payload length overflow".to_owned())?;
    let total_length = IPV4_MIN_HEADER_LENGTH
        .checked_add(udp_length)
        .ok_or_else(|| "IPv4 packet length overflow".to_owned())?;
    let total_length_u16 = u16::try_from(total_length)
        .map_err(|_| "IPv4 packet exceeds the 65535-byte limit".to_owned())?;
    let udp_length_u16 = u16::try_from(udp_length)
        .map_err(|_| "IPv4 UDP packet exceeds the 65535-byte limit".to_owned())?;

    let mut packet = vec![0u8; total_length];
    packet[0] = IPV4_VERSION_AND_MIN_HEADER_LENGTH;
    packet[2..4].copy_from_slice(&total_length_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&IPV4_PACKET_IDENTIFICATION.to_be_bytes());
    packet[8] = IPV4_DEFAULT_TTL;
    packet[9] = IPV4_UDP_PROTOCOL;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());

    packet[IPV4_MIN_HEADER_LENGTH..IPV4_MIN_HEADER_LENGTH + 2]
        .copy_from_slice(&source_port.to_be_bytes());
    packet[IPV4_MIN_HEADER_LENGTH + 2..IPV4_MIN_HEADER_LENGTH + 4]
        .copy_from_slice(&destination_port.to_be_bytes());
    packet[IPV4_MIN_HEADER_LENGTH + 4..IPV4_MIN_HEADER_LENGTH + 6]
        .copy_from_slice(&udp_length_u16.to_be_bytes());
    packet[IPV4_MIN_HEADER_LENGTH + UDP_HEADER_LENGTH..].copy_from_slice(payload);

    let ipv4_checksum = internet_checksum(&packet[..IPV4_MIN_HEADER_LENGTH]);
    packet[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

    let mut pseudo_header = Vec::with_capacity(12 + udp_length);
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.push(0);
    pseudo_header.push(IPV4_UDP_PROTOCOL);
    pseudo_header.extend_from_slice(&udp_length_u16.to_be_bytes());
    pseudo_header.extend_from_slice(&packet[IPV4_MIN_HEADER_LENGTH..]);
    let udp_checksum = internet_checksum(&pseudo_header);
    packet[26..28].copy_from_slice(
        &(if udp_checksum == 0 {
            0xffff
        } else {
            udp_checksum
        })
        .to_be_bytes(),
    );
    Ok(packet)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn prove_ipv4_socket_binding(
    active: &WindowsDisposableExactRouteActiveProbe<'_>,
    expected_capture_source: Ipv4Addr,
) -> Result<(), String> {
    let destination = match active.destination() {
        IpAddr::V4(destination) => destination,
        IpAddr::V6(_) => return Err("IPv4 socket probe received an IPv6 destination".to_owned()),
    };
    let baseline_source = match active.baseline_source_address() {
        IpAddr::V4(source) => source,
        IpAddr::V6(_) => return Err("IPv4 socket probe received an IPv6 source".to_owned()),
    };
    if active.exact_route_prefix() != format!("{destination}/32")
        || active.capture_interface() == active.baseline_egress_interface()
        || active.capture_source_address() != IpAddr::V4(expected_capture_source)
        || baseline_source == expected_capture_source
    {
        return Err("active route facts do not prove a competing capture route".to_owned());
    }

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|error| format!("create IPv4 UDP socket: {error}"))?;
    let interface_index = active.baseline_egress_interface().index;
    set_and_verify_ipv4_unicast_interface(&socket, interface_index)?;
    socket
        .bind(&SockAddr::from(SocketAddrV4::new(baseline_source, 0)))
        .map_err(|error| format!("bind baseline source {baseline_source}: {error}"))?;
    let peer = SocketAddrV4::new(destination, 9);
    socket
        .connect(&SockAddr::from(peer))
        .map_err(|error| format!("connect no-payload IPv4 UDP socket: {error}"))?;

    let local = socket
        .local_addr()
        .map_err(|error| format!("read bound local address: {error}"))?
        .as_socket_ipv4()
        .ok_or_else(|| "bound socket did not retain an IPv4 local address".to_owned())?;
    let observed_peer = socket
        .peer_addr()
        .map_err(|error| format!("read connected peer address: {error}"))?
        .as_socket_ipv4()
        .ok_or_else(|| "connected socket did not retain an IPv4 peer".to_owned())?;
    if *local.ip() != baseline_source || local.port() == 0 || observed_peer != peer {
        return Err(format!(
            "socket binding mismatch: local={local}, peer={observed_peer}, expected_source={baseline_source}, expected_peer={peer}"
        ));
    }
    Ok(())
}

fn prove_ipv6_socket_binding(
    active: &WindowsDisposableExactRouteActiveProbe<'_>,
    expected_capture_source: Ipv6Addr,
    expected_baseline_interface: WindowsPacketInterfaceIdentity,
    expected_baseline_source: Ipv6Addr,
) -> Result<(), String> {
    let destination = match active.destination() {
        IpAddr::V6(destination) => destination,
        IpAddr::V4(_) => return Err("IPv6 socket probe received an IPv4 destination".to_owned()),
    };
    let baseline_source = match active.baseline_source_address() {
        IpAddr::V6(source) => source,
        IpAddr::V4(_) => return Err("IPv6 socket probe received an IPv4 source".to_owned()),
    };
    if active.exact_route_prefix() != format!("{destination}/128")
        || active.capture_interface() == active.baseline_egress_interface()
        || active.baseline_egress_interface() != expected_baseline_interface
        || active.capture_source_address() != IpAddr::V6(expected_capture_source)
        || baseline_source != expected_baseline_source
        || baseline_source == expected_capture_source
    {
        return Err(
            "active IPv6 route facts do not prove the controlled competing route".to_owned(),
        );
    }

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|error| format!("create IPv6 UDP socket: {error}"))?;
    let interface_index = active.baseline_egress_interface().index;
    set_and_verify_ipv6_unicast_interface(&socket, interface_index)?;
    socket
        .bind(&SockAddr::from(SocketAddrV6::new(baseline_source, 0, 0, 0)))
        .map_err(|error| format!("bind IPv6 baseline source {baseline_source}: {error}"))?;
    let peer = SocketAddrV6::new(destination, 9, 0, 0);
    socket
        .connect(&SockAddr::from(peer))
        .map_err(|error| format!("connect no-payload IPv6 UDP socket: {error}"))?;

    let local = socket
        .local_addr()
        .map_err(|error| format!("read bound IPv6 local address: {error}"))?
        .as_socket_ipv6()
        .ok_or_else(|| "bound socket did not retain an IPv6 local address".to_owned())?;
    let observed_peer = socket
        .peer_addr()
        .map_err(|error| format!("read connected IPv6 peer address: {error}"))?
        .as_socket_ipv6()
        .ok_or_else(|| "connected socket did not retain an IPv6 peer".to_owned())?;
    if *local.ip() != baseline_source || local.port() == 0 || observed_peer != peer {
        return Err(format!(
            "IPv6 socket binding mismatch: local={local}, peer={observed_peer}, expected_source={baseline_source}, expected_peer={peer}"
        ));
    }
    Ok(())
}

fn set_and_verify_ipv4_unicast_interface(
    socket: &Socket,
    interface_index: u32,
) -> Result<(), String> {
    let raw_socket = socket.as_raw_socket() as SOCKET;
    let network_order_index = interface_index.to_be();
    let set_result = unsafe {
        setsockopt(
            raw_socket,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &network_order_index as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if set_result != 0 {
        return Err(format!(
            "set IP_UNICAST_IF to interface {interface_index}: Winsock error {}",
            unsafe { WSAGetLastError() }
        ));
    }

    let mut observed_index = 0u32;
    let mut observed_length = std::mem::size_of::<u32>() as i32;
    let get_result = unsafe {
        getsockopt(
            raw_socket,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &mut observed_index as *mut u32 as *mut u8,
            &mut observed_length,
        )
    };
    if get_result != 0 {
        return Err(format!(
            "read IP_UNICAST_IF for interface {interface_index}: Winsock error {}",
            unsafe { WSAGetLastError() }
        ));
    }
    if observed_length != std::mem::size_of::<u32>() as i32 || observed_index != interface_index {
        return Err(format!(
            "IP_UNICAST_IF round-trip mismatch: value={observed_index}, length={observed_length}, expected={interface_index}"
        ));
    }
    Ok(())
}

fn set_and_verify_ipv6_unicast_interface(
    socket: &Socket,
    interface_index: u32,
) -> Result<(), String> {
    let raw_socket = socket.as_raw_socket() as SOCKET;
    let set_result = unsafe {
        setsockopt(
            raw_socket,
            IPPROTO_IPV6,
            IPV6_UNICAST_IF,
            &interface_index as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if set_result != 0 {
        return Err(format!(
            "set IPV6_UNICAST_IF to interface {interface_index}: Winsock error {}",
            unsafe { WSAGetLastError() }
        ));
    }

    let mut observed_index = 0u32;
    let mut observed_length = std::mem::size_of::<u32>() as i32;
    let get_result = unsafe {
        getsockopt(
            raw_socket,
            IPPROTO_IPV6,
            IPV6_UNICAST_IF,
            &mut observed_index as *mut u32 as *mut u8,
            &mut observed_length,
        )
    };
    if get_result != 0 {
        return Err(format!(
            "read IPV6_UNICAST_IF for interface {interface_index}: Winsock error {}",
            unsafe { WSAGetLastError() }
        ));
    }
    if observed_length != std::mem::size_of::<u32>() as i32 || observed_index != interface_index {
        return Err(format!(
            "IPV6_UNICAST_IF host-order round-trip mismatch: value={observed_index}, length={observed_length}, expected={interface_index}"
        ));
    }
    Ok(())
}

fn load_admitted_wintun() -> Result<(WindowsCollectedPacketAdapterAdmission, LoadedWintun), String>
{
    let architecture = current_architecture();
    let archive = required_path("SLIPSTREAM_WINTUN_ARCHIVE");
    let license = required_path("SLIPSTREAM_WINTUN_LICENSE");
    let dll = required_path("SLIPSTREAM_WINTUN_DLL");
    let collected = collect_windows_packet_adapter_artifact(architecture, &archive, &license, &dll)
        .map_err(|error| format!("collect pinned {} Wintun: {error:?}", architecture.as_str()))?;
    let admission = collected
        .admit()
        .map_err(|error| format!("admit pinned {} Wintun: {error:?}", architecture.as_str()))?;
    let api = LoadedWintun::load(admission.dll_path())
        .map_err(|error| format!("load admitted Wintun DLL: {error}"))?;
    Ok((admission, api))
}

fn current_architecture() -> WindowsPacketAdapterArchitecture {
    #[cfg(target_arch = "x86_64")]
    {
        WindowsPacketAdapterArchitecture::Amd64
    }
    #[cfg(target_arch = "aarch64")]
    {
        WindowsPacketAdapterArchitecture::Arm64
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("the disposable Wintun exact-route gate supports only AMD64 and ARM64");
}

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} must point to the pinned Wintun fixture"))
}

fn unique_adapter_name(purpose: &str) -> String {
    let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_owned());
    let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".to_owned());
    format!(
        "SlipstreamCI-{purpose}-{run_id}-{attempt}-{}",
        std::process::id()
    )
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct LoadedWintun {
    module: HMODULE,
    create_adapter: WintunCreateAdapter,
    open_adapter: WintunOpenAdapter,
    close_adapter: WintunCloseAdapter,
    get_adapter_luid: WintunGetAdapterLuid,
    get_running_driver_version: WintunGetRunningDriverVersion,
    start_session: WintunStartSession,
    end_session: WintunEndSession,
    receive_packet: WintunReceivePacket,
    release_receive_packet: WintunReleaseReceivePacket,
    allocate_send_packet: WintunAllocateSendPacket,
    send_packet: WintunSendPacket,
}

impl LoadedWintun {
    fn load(path: &Path) -> Result<Self, String> {
        let path_wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let module = unsafe {
            LoadLibraryExW(
                path_wide.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(format!("LoadLibraryExW failed with {}", last_error()));
        }

        let resolved = unsafe {
            (|| {
                Ok(Self {
                    module,
                    create_adapter: resolve(module, c"WintunCreateAdapter")?,
                    open_adapter: resolve(module, c"WintunOpenAdapter")?,
                    close_adapter: resolve(module, c"WintunCloseAdapter")?,
                    get_adapter_luid: resolve(module, c"WintunGetAdapterLUID")?,
                    get_running_driver_version: resolve(module, c"WintunGetRunningDriverVersion")?,
                    start_session: resolve(module, c"WintunStartSession")?,
                    end_session: resolve(module, c"WintunEndSession")?,
                    receive_packet: resolve(module, c"WintunReceivePacket")?,
                    release_receive_packet: resolve(module, c"WintunReleaseReceivePacket")?,
                    allocate_send_packet: resolve(module, c"WintunAllocateSendPacket")?,
                    send_packet: resolve(module, c"WintunSendPacket")?,
                })
            })()
        };
        if resolved.is_err() {
            unsafe {
                FreeLibrary(module);
            }
        }
        resolved
    }

    fn adapter_presence(&self, name: &[u16]) -> Result<bool, String> {
        let adapter = unsafe { (self.open_adapter)(name.as_ptr()) };
        if adapter.is_null() {
            let error = last_error();
            return if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND) {
                Ok(false)
            } else {
                Err(format!(
                    "adapter presence could not be proven: WintunOpenAdapter failed with {error}"
                ))
            };
        }
        unsafe {
            (self.close_adapter)(adapter);
        }
        Ok(true)
    }

    fn require_adapter_absent(&self, name: &[u16], phase: &str) -> Result<(), String> {
        if self.adapter_presence(name)? {
            return Err(format!("test adapter still exists {phase}"));
        }
        Ok(())
    }
}

impl Drop for LoadedWintun {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

struct OwnedWintunAdapter<'a> {
    api: &'a LoadedWintun,
    adapter: WintunAdapterHandle,
    session: WintunSessionHandle,
}

impl<'a> OwnedWintunAdapter<'a> {
    fn create(api: &'a LoadedWintun, name: &[u16], tunnel_type: &[u16]) -> Result<Self, String> {
        let adapter =
            unsafe { (api.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), ptr::null()) };
        if adapter.is_null() {
            return Err(format!("WintunCreateAdapter failed with {}", last_error()));
        }
        let version = unsafe { (api.get_running_driver_version)() };
        if version == 0 {
            let error = last_error();
            unsafe {
                (api.close_adapter)(adapter);
            }
            return Err(format!("WintunGetRunningDriverVersion failed with {error}"));
        }
        Ok(Self {
            api,
            adapter,
            session: ptr::null_mut(),
        })
    }

    fn start_session(&mut self) -> Result<(), String> {
        let session = unsafe { (self.api.start_session)(self.adapter, WINTUN_MIN_RING_CAPACITY) };
        if session.is_null() {
            return Err(format!("WintunStartSession failed with {}", last_error()));
        }
        self.session = session;
        Ok(())
    }

    fn interface_identity(&self) -> Result<WindowsPacketInterfaceIdentity, String> {
        let mut luid = NET_LUID_LH::default();
        unsafe {
            (self.api.get_adapter_luid)(self.adapter, &mut luid);
        }
        let luid_value = unsafe { luid.Value };
        if luid_value == 0 {
            return Err("WintunGetAdapterLUID returned a zero LUID".to_owned());
        }
        let mut index = 0;
        let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        if result != 0 || index == 0 {
            return Err(format!("ConvertInterfaceLuidToIndex failed with {result}"));
        }
        let mut round_trip = NET_LUID_LH::default();
        let result = unsafe { ConvertInterfaceIndexToLuid(index, &mut round_trip) };
        if result != 0 || unsafe { round_trip.Value } != luid_value {
            return Err(format!(
                "Wintun interface identity round trip failed with {result}"
            ));
        }
        Ok(WindowsPacketInterfaceIdentity {
            luid: luid_value,
            index,
        })
    }

    fn receive_matching_ipv4_udp_request(
        &self,
        expected_source: Ipv4Addr,
        expected_destination: Ipv4Addr,
        expected_source_port: u16,
        expected_destination_port: u16,
        expected_payload: &[u8],
        deadline: Instant,
    ) -> Result<CapturedIpv4UdpRequest, String> {
        loop {
            let packet = self.receive_packet_until(deadline)?;
            if let Some(request) = parse_ipv4_udp_request(
                &packet,
                expected_source,
                expected_destination,
                expected_source_port,
                expected_destination_port,
                expected_payload,
            )? {
                return Ok(request);
            }
        }
    }

    fn receive_packet_until(&self, deadline: Instant) -> Result<Vec<u8>, String> {
        if self.session.is_null() {
            return Err("Wintun packet receive requires an active owned session".to_owned());
        }
        loop {
            if Instant::now() >= deadline {
                return Err("Wintun packet receive exceeded its bounded deadline".to_owned());
            }
            let mut packet_size = 0u32;
            let packet = unsafe { (self.api.receive_packet)(self.session, &mut packet_size) };
            if !packet.is_null() {
                if packet_size == 0 || packet_size as usize > WINTUN_MAX_IP_PACKET_SIZE {
                    unsafe {
                        (self.api.release_receive_packet)(self.session, packet);
                    }
                    return Err(format!(
                        "Wintun returned an invalid packet length {packet_size}"
                    ));
                }
                let packet_copy =
                    unsafe { std::slice::from_raw_parts(packet, packet_size as usize).to_vec() };
                unsafe {
                    (self.api.release_receive_packet)(self.session, packet);
                }
                return Ok(packet_copy);
            }

            let error = last_error();
            if error != ERROR_NO_MORE_ITEMS {
                return Err(format!("WintunReceivePacket failed with {error}"));
            }
            if Instant::now() >= deadline {
                return Err("Wintun packet receive exceeded its bounded deadline".to_owned());
            }
            thread::sleep(PACKET_DELIVERY_PROBE_INTERVAL);
        }
    }

    fn inject_packet(&self, packet: &[u8]) -> Result<(), String> {
        if self.session.is_null() {
            return Err("Wintun packet injection requires an active owned session".to_owned());
        }
        if packet.is_empty() || packet.len() > WINTUN_MAX_IP_PACKET_SIZE {
            return Err(format!(
                "Wintun packet injection length {} is outside the valid range",
                packet.len()
            ));
        }
        let packet_size = u32::try_from(packet.len())
            .map_err(|_| "Wintun packet injection length overflow".to_owned())?;
        let destination = unsafe { (self.api.allocate_send_packet)(self.session, packet_size) };
        if destination.is_null() {
            return Err(format!(
                "WintunAllocateSendPacket failed with {}",
                last_error()
            ));
        }
        unsafe {
            ptr::copy_nonoverlapping(packet.as_ptr(), destination, packet.len());
            (self.api.send_packet)(self.session, destination);
        }
        Ok(())
    }

    fn end_session(&mut self) {
        if self.session.is_null() {
            return;
        }
        unsafe {
            (self.api.end_session)(self.session);
        }
        self.session = ptr::null_mut();
    }

    fn close_adapter(&mut self) {
        if self.adapter.is_null() {
            return;
        }
        unsafe {
            (self.api.close_adapter)(self.adapter);
        }
        self.adapter = ptr::null_mut();
    }
}

impl Drop for OwnedWintunAdapter<'_> {
    fn drop(&mut self) {
        self.end_session();
        self.close_adapter();
    }
}

struct OwnedFixtureBaselineRoute {
    row: MIB_IPFORWARD_ROW2,
    present: bool,
}

impl OwnedFixtureBaselineRoute {
    fn create(
        interface: WindowsPacketInterfaceIdentity,
        network: Ipv6Addr,
        prefix_length: u8,
    ) -> Result<Self, String> {
        if prefix_length != IPV6_BASELINE_PREFIX_LENGTH || network != IPV6_BASELINE_NETWORK {
            return Err("fixture baseline route must remain the fixed IPv6 /64".to_owned());
        }

        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe {
            InitializeIpForwardEntry(&mut row);
        }
        row.InterfaceLuid = NET_LUID_LH {
            Value: interface.luid,
        };
        row.InterfaceIndex = interface.index;
        row.DestinationPrefix.Prefix = sockaddr_from_ip(IpAddr::V6(network));
        row.DestinationPrefix.PrefixLength = prefix_length;
        row.NextHop = sockaddr_from_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        row.SitePrefixLength = prefix_length;
        row.Metric = 5;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.Loopback = false;
        row.AutoconfigureAddress = false;
        row.Publish = false;
        row.Immortal = false;

        if lookup_fixture_baseline_route(row)?.is_some() {
            return Err("fixture IPv6 baseline route already exists before creation".to_owned());
        }
        let result = unsafe { CreateIpForwardEntry2(&row) };
        if result != 0 {
            return Err(format!(
                "CreateIpForwardEntry2 baseline failed with {result}"
            ));
        }
        let mut owned = Self { row, present: true };
        let verification_error = match lookup_fixture_baseline_route(row) {
            Ok(Some(observed)) if same_fixture_baseline_route_key(observed, row) => {
                return Ok(owned);
            }
            Ok(Some(_)) => "created route identity changed during verification".to_owned(),
            Ok(None) => "created route was absent during verification".to_owned(),
            Err(error) => format!("created route lookup failed: {error}"),
        };
        let cleanup_result = owned.remove_and_verify();
        Err(format!(
            "fixture IPv6 baseline route verification failed: {verification_error}; cleanup={cleanup_result:?}"
        ))
    }

    fn remove_and_verify(&mut self) -> Result<(), String> {
        let result = unsafe { DeleteIpForwardEntry2(&self.row) };
        if result != 0 && !matches!(result, ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND) {
            return Err(format!(
                "DeleteIpForwardEntry2 baseline failed with {result}"
            ));
        }

        let deadline = Instant::now() + BASELINE_ROUTE_REMOVAL_TIMEOUT;
        loop {
            if lookup_fixture_baseline_route(self.row)?.is_none() {
                self.present = false;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(
                    "fixture IPv6 baseline route remained after bounded deletion".to_owned(),
                );
            }
            thread::sleep(ADDRESS_PROBE_INTERVAL);
        }
    }
}

impl Drop for OwnedFixtureBaselineRoute {
    fn drop(&mut self) {
        if self.present {
            unsafe {
                DeleteIpForwardEntry2(&self.row);
            }
        }
    }
}

fn lookup_fixture_baseline_route(
    row: MIB_IPFORWARD_ROW2,
) -> Result<Option<MIB_IPFORWARD_ROW2>, String> {
    let mut observed = row;
    let result = unsafe { GetIpForwardEntry2(&mut observed) };
    match result {
        0 => Ok(Some(observed)),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Ok(None),
        error => Err(format!("GetIpForwardEntry2 baseline failed with {error}")),
    }
}

fn same_fixture_baseline_route_key(left: MIB_IPFORWARD_ROW2, right: MIB_IPFORWARD_ROW2) -> bool {
    (unsafe { left.InterfaceLuid.Value }) == (unsafe { right.InterfaceLuid.Value })
        && left.InterfaceIndex == right.InterfaceIndex
        && left.DestinationPrefix.PrefixLength == right.DestinationPrefix.PrefixLength
        && ip_from_sockaddr(left.DestinationPrefix.Prefix)
            == ip_from_sockaddr(right.DestinationPrefix.Prefix)
        && ip_from_sockaddr(left.NextHop) == ip_from_sockaddr(right.NextHop)
}

struct OwnedUnicastAddress {
    row: MIB_UNICASTIPADDRESS_ROW,
    present: bool,
}

impl OwnedUnicastAddress {
    fn create(
        interface: WindowsPacketInterfaceIdentity,
        address: IpAddr,
        prefix_length: u8,
    ) -> Result<Self, String> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe {
            InitializeUnicastIpAddressEntry(&mut row);
        }
        row.InterfaceLuid = NET_LUID_LH {
            Value: interface.luid,
        };
        row.InterfaceIndex = interface.index;
        row.Address = sockaddr_from_ip(address);
        row.OnLinkPrefixLength = prefix_length;
        row.SkipAsSource = false;
        row.DadState = IpDadStatePreferred;

        if lookup_unicast_address(row)?.is_some() {
            return Err("owned Wintun address already exists before creation".to_owned());
        }
        let result = unsafe { CreateUnicastIpAddressEntry(&row) };
        if result != 0 {
            return Err(format!("CreateUnicastIpAddressEntry failed with {result}"));
        }
        let mut owned = Self { row, present: true };
        if let Err(readiness_error) = owned.wait_until_preferred() {
            let cleanup_result = owned.remove_and_verify();
            return match cleanup_result {
                Ok(()) => Err(format!(
                    "owned Wintun address readiness failed after verified cleanup: {readiness_error}"
                )),
                Err(cleanup_error) => Err(format!(
                    "owned Wintun address readiness failed: {readiness_error}; exact cleanup failed: {cleanup_error}"
                )),
            };
        }
        Ok(owned)
    }

    fn wait_until_preferred(&self) -> Result<(), String> {
        let deadline = Instant::now() + ADDRESS_READY_TIMEOUT;
        loop {
            let Some(observed) = lookup_unicast_address(self.row)? else {
                return Err("owned Wintun address disappeared before becoming ready".to_owned());
            };
            if !same_unicast_address_key(observed, self.row)
                || observed.OnLinkPrefixLength != self.row.OnLinkPrefixLength
            {
                return Err(format!(
                    "owned Wintun address identity or /{} prefix changed",
                    self.row.OnLinkPrefixLength
                ));
            }
            if observed.DadState == IpDadStatePreferred && !observed.SkipAsSource {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "owned Wintun address did not become preferred within the bounded wait (dad_state={}, skip_as_source={})",
                    observed.DadState, observed.SkipAsSource
                ));
            }
            thread::sleep(ADDRESS_PROBE_INTERVAL);
        }
    }

    fn remove_and_verify(&mut self) -> Result<(), String> {
        let result = unsafe { DeleteUnicastIpAddressEntry(&self.row) };
        if result != 0 && !matches!(result, ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND) {
            return Err(format!("DeleteUnicastIpAddressEntry failed with {result}"));
        }

        let deadline = Instant::now() + ADDRESS_REMOVAL_TIMEOUT;
        loop {
            if lookup_unicast_address(self.row)?.is_none() {
                self.present = false;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("owned Wintun address remained after bounded deletion".to_owned());
            }
            thread::sleep(ADDRESS_PROBE_INTERVAL);
        }
    }
}

impl Drop for OwnedUnicastAddress {
    fn drop(&mut self) {
        if self.present {
            unsafe {
                DeleteUnicastIpAddressEntry(&self.row);
            }
        }
    }
}

fn lookup_unicast_address(
    row: MIB_UNICASTIPADDRESS_ROW,
) -> Result<Option<MIB_UNICASTIPADDRESS_ROW>, String> {
    let mut observed = row;
    let result = unsafe { GetUnicastIpAddressEntry(&mut observed) };
    match result {
        0 => Ok(Some(observed)),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Ok(None),
        error => Err(format!("GetUnicastIpAddressEntry failed with {error}")),
    }
}

fn same_unicast_address_key(
    left: MIB_UNICASTIPADDRESS_ROW,
    right: MIB_UNICASTIPADDRESS_ROW,
) -> bool {
    (unsafe { left.InterfaceLuid.Value }) == (unsafe { right.InterfaceLuid.Value })
        && left.InterfaceIndex == right.InterfaceIndex
        && ip_from_sockaddr(left.Address) == ip_from_sockaddr(right.Address)
}

fn ip_from_sockaddr(address: SOCKADDR_INET) -> Option<IpAddr> {
    match unsafe { address.si_family } {
        AF_INET => {
            let octets = unsafe { address.Ipv4.sin_addr.S_un.S_un_b };
            Some(IpAddr::V4(Ipv4Addr::new(
                octets.s_b1,
                octets.s_b2,
                octets.s_b3,
                octets.s_b4,
            )))
        }
        AF_INET6 => {
            let octets = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn sockaddr_from_ip(address: IpAddr) -> SOCKADDR_INET {
    match address {
        IpAddr::V4(address) => {
            let [s_b1, s_b2, s_b3, s_b4] = address.octets();
            SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_un_b: IN_ADDR_0_0 {
                                s_b1,
                                s_b2,
                                s_b3,
                                s_b4,
                            },
                        },
                    },
                    sin_zero: [0; 8],
                },
            }
        }
        IpAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
        },
    }
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

unsafe fn resolve<T: Copy>(module: HMODULE, name: &std::ffi::CStr) -> Result<T, String> {
    let function = GetProcAddress(module, name.as_ptr().cast())
        .ok_or_else(|| format!("{} is missing ({})", name.to_string_lossy(), last_error()))?;
    Ok(std::mem::transmute_copy::<
        unsafe extern "system" fn() -> isize,
        T,
    >(&function))
}

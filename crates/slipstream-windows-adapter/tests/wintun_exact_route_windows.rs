#![cfg(all(windows, feature = "disposable-windows-packet-fixture"))]

use slipstream_windows_adapter::packet_adapter::{
    collect_windows_packet_adapter_artifact, WindowsCollectedPacketAdapterAdmission,
    WindowsPacketAdapterArchitecture,
};
use slipstream_windows_adapter::packet_egress::{
    observe_windows_packet_route, qualify_disposable_exact_host_route,
    qualify_disposable_exact_host_route_with_active_probe, WindowsDisposableExactRouteActiveProbe,
    WindowsDisposableExactRouteErrorCode, WindowsOwnedRouteTransitionIssuer,
    WindowsPacketInterfaceIdentity, WINDOWS_DISPOSABLE_EXACT_ROUTE_OWNER_VERSION,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, UdpSocket,
};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
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
const PREEXISTING_FLOW_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_PREEXISTING_FLOW_CI";
const PREEXISTING_TCP_FLOW_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_PREEXISTING_TCP_FLOW_CI";
const CRASH_REMOVAL_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_CRASH_REMOVAL_CI";
const CRASH_REMOVAL_CHILD_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_CRASH_REMOVAL_CHILD";
const CRASH_REMOVAL_ADAPTER_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_CRASH_REMOVAL_ADAPTER";
const CRASH_REMOVAL_READY_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_CRASH_REMOVAL_READY";
const INDEPENDENT_ROUTE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_INDEPENDENT_ROUTE_CI";
const INDEPENDENT_ROUTE_CHILD_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_INDEPENDENT_ROUTE_CHILD";
const INDEPENDENT_ROUTE_ADAPTER_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_INDEPENDENT_ROUTE_ADAPTER";
const INDEPENDENT_ROUTE_READY_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_INDEPENDENT_ROUTE_READY";
const INDEPENDENT_ROUTE_RELEASE_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_INDEPENDENT_ROUTE_RELEASE";
const WINTUN_MIN_RING_CAPACITY: u32 = 0x2_0000;
const WINTUN_MAX_IP_PACKET_SIZE: usize = 0xffff;
const ADDRESS_READY_TIMEOUT: Duration = Duration::from_secs(5);
const ADDRESS_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);
const ADDRESS_PROBE_INTERVAL: Duration = Duration::from_millis(25);
const BASELINE_ROUTE_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);
const CRASH_CHILD_READY_TIMEOUT: Duration = Duration::from_secs(45);
const CRASH_CHILD_FAILSAFE_LIFETIME: Duration = Duration::from_secs(90);
const CRASH_CHILD_TERMINATION_TIMEOUT: Duration = Duration::from_secs(15);
const CRASH_CAPTURE_REMOVAL_TIMEOUT: Duration = Duration::from_secs(30);
const CRASH_PROBE_INTERVAL: Duration = Duration::from_millis(100);
const INDEPENDENT_CHILD_READY_TIMEOUT: Duration = Duration::from_secs(45);
const INDEPENDENT_CHILD_FAILSAFE_LIFETIME: Duration = Duration::from_secs(90);
const INDEPENDENT_CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(60);
const INDEPENDENT_PROBE_INTERVAL: Duration = Duration::from_millis(100);
const PACKET_DELIVERY_TIMEOUT: Duration = Duration::from_secs(3);
const PACKET_DELIVERY_PROBE_INTERVAL: Duration = Duration::from_millis(5);
const PACKET_DELIVERY_PORT: u16 = 41_723;
const TCP_PACKET_DELIVERY_PORT: u16 = 41_724;
const PACKET_REQUEST_PAYLOAD: &[u8] = b"slipstream-wintun-request-v1";
const PACKET_RESPONSE_PAYLOAD: &[u8] = b"slipstream-wintun-response-v1";
const PREEXISTING_WARMUP_REQUEST: &[u8] = b"slipstream-preexisting-warmup-v1";
const PREEXISTING_WARMUP_RESPONSE: &[u8] = b"slipstream-preexisting-warmup-response-v1";
const PREEXISTING_ACTIVE_REQUEST: &[u8] = b"slipstream-preexisting-active-v1";
const PREEXISTING_ACTIVE_RESPONSE: &[u8] = b"slipstream-preexisting-active-response-v1";
const PREEXISTING_RETRY_REQUEST: &[u8] = b"slipstream-preexisting-retry-v1";
const PREEXISTING_RETRY_RESPONSE: &[u8] = b"slipstream-preexisting-retry-response-v1";
const PREEXISTING_CAPTURE_ROLLBACK: &str = "preexisting_flow_reached_capture_with_baseline_source";
const PREEXISTING_TCP_WARMUP_REQUEST: &[u8] = b"slipstream-tcp-warmup-v1";
const PREEXISTING_TCP_WARMUP_RESPONSE: &[u8] = b"slipstream-tcp-warmup-response-v1";
const PREEXISTING_TCP_ACTIVE_REQUEST: &[u8] = b"slipstream-tcp-active-v1";
const PREEXISTING_TCP_ACTIVE_RESPONSE: &[u8] = b"slipstream-tcp-active-response-v1";
const PREEXISTING_TCP_RETRY_REQUEST: &[u8] = b"slipstream-tcp-retry-v1";
const PREEXISTING_TCP_RETRY_RESPONSE: &[u8] = b"slipstream-tcp-retry-response-v1";
const PREEXISTING_TCP_CAPTURE_ROLLBACK: &str =
    "preexisting_tcp_flow_reached_capture_with_baseline_source";
const IPV4_MIN_HEADER_LENGTH: usize = 20;
const IPV6_HEADER_LENGTH: usize = 40;
const IPV6_PAYLOAD_LENGTH_OFFSET: usize = 4;
const IPV6_NEXT_HEADER_OFFSET: usize = 6;
const IPV6_HOP_LIMIT_OFFSET: usize = 7;
const IPV6_SOURCE_OFFSET: usize = 8;
const IPV6_DESTINATION_OFFSET: usize = 24;
const UDP_HEADER_LENGTH: usize = 8;
const UDP_SOURCE_PORT_OFFSET: usize = 0;
const UDP_DESTINATION_PORT_OFFSET: usize = 2;
const UDP_LENGTH_OFFSET: usize = 4;
const UDP_CHECKSUM_OFFSET: usize = 6;
const TCP_MIN_HEADER_LENGTH: usize = 20;
const TCP_SOURCE_PORT_OFFSET: usize = 0;
const TCP_DESTINATION_PORT_OFFSET: usize = 2;
const TCP_SEQUENCE_OFFSET: usize = 4;
const TCP_ACKNOWLEDGMENT_OFFSET: usize = 8;
const TCP_DATA_OFFSET: usize = 12;
const TCP_FLAGS_OFFSET: usize = 13;
const TCP_WINDOW_OFFSET: usize = 14;
const TCP_CHECKSUM_OFFSET: usize = 16;
const IPV4_VERSION_AND_MIN_HEADER_LENGTH: u8 = 0x45;
const IPV6_VERSION: u8 = 0x60;
const IPV4_PACKET_IDENTIFICATION: u16 = 0x534c;
const IPV4_DEFAULT_TTL: u8 = 64;
const IPV6_DEFAULT_HOP_LIMIT: u8 = 64;
const UDP_PROTOCOL_NUMBER: u8 = 17;
const TCP_PROTOCOL_NUMBER: u8 = 6;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_SERVER_INITIAL_SEQUENCE: u32 = 0x534c_1000;
const IPV4_BASELINE_NETWORK: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 0);
const IPV4_BASELINE_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 255, 254, 2);
const IPV4_CAPTURE_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 255, 254, 3);
const IPV4_PREEXISTING_DESTINATION: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 3);
const IPV4_CRASH_REMOVAL_DESTINATION: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 4);
const IPV4_INDEPENDENT_ROUTE_DESTINATION: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 5);
const IPV4_INDEPENDENT_ROUTE_SOURCE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
const IPV4_BASELINE_PREFIX_LENGTH: u8 = 24;
const IPV4_HOST_PREFIX_LENGTH: u8 = 32;
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
fn native_wintun_child_termination_removes_active_capture_route() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(SOCKET_BINDING_CI_ENV).as_deref() != Ok("1")
        || std::env::var(CRASH_REMOVAL_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let baseline_name = wide(&unique_adapter_name("CrashRouteBaseline"));
    let capture_name_string = unique_adapter_name("CrashRouteCapture");
    let capture_name = wide(&capture_name_string);
    let baseline_tunnel_type = wide("Slipstream CI Crash Baseline");
    api.require_adapter_absent(&baseline_name, "before crash-route baseline fixture")
        .unwrap_or_else(|error| panic!("Wintun crash-route baseline preflight: {error}"));
    api.require_adapter_absent(&capture_name, "before crash-route capture fixture")
        .unwrap_or_else(|error| panic!("Wintun crash-route capture preflight: {error}"));

    let qualification_result = (|| {
        let mut baseline_adapter =
            OwnedWintunAdapter::create(&api, &baseline_name, &baseline_tunnel_type)?;
        baseline_adapter.start_session()?;
        let baseline_interface = baseline_adapter.interface_identity()?;
        let mut baseline_address = None;
        let mut baseline_route = None;
        let crash_result = (|| {
            baseline_address = Some(OwnedUnicastAddress::create(
                baseline_interface,
                IpAddr::V4(IPV4_BASELINE_SOURCE),
                IPV4_HOST_PREFIX_LENGTH,
            )?);
            baseline_route = Some(OwnedFixtureBaselineRoute::create(
                baseline_interface,
                IpAddr::V4(IPV4_BASELINE_NETWORK),
                IPV4_BASELINE_PREFIX_LENGTH,
            )?);

            let fixture_dir = OwnedCrashFixtureDirectory::create()?;
            let current_exe = std::env::current_exe()
                .map_err(|error| format!("resolve exact integration-test executable: {error}"))?;
            let child = Command::new(current_exe)
                .args([
                    "--exact",
                    "native_wintun_crash_child_holds_active_capture_route",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CRASH_REMOVAL_CHILD_ENV, "1")
                .env(CRASH_REMOVAL_ADAPTER_ENV, &capture_name_string)
                .env(CRASH_REMOVAL_READY_ENV, fixture_dir.marker_path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| format!("spawn exact crash-route child: {error}"))?;
            let mut child = ExactCrashChild::new(child);
            let expected_marker = format!("{capture_name_string}\n{}\n", child.id());
            let mut evidence = None;
            let active_result = (|| {
                wait_for_crash_child_ready(
                    &mut child,
                    fixture_dir.marker_path(),
                    &expected_marker,
                )?;
                let capture_interface =
                    api.adapter_interface_identity(&capture_name)?
                        .ok_or_else(|| {
                            "crash-route capture adapter disappeared after readiness".to_owned()
                        })?;
                if capture_interface == baseline_interface {
                    return Err(
                        "crash-route capture adapter reused the baseline identity".to_owned()
                    );
                }
                let route_row = fixture_route_row(
                    capture_interface,
                    IpAddr::V4(IPV4_CRASH_REMOVAL_DESTINATION),
                    IPV4_HOST_PREFIX_LENGTH,
                    0,
                );
                let address_row = fixture_unicast_address_row(
                    capture_interface,
                    IpAddr::V4(IPV4_CAPTURE_SOURCE),
                    IPV4_HOST_PREFIX_LENGTH,
                );
                let observed_route = lookup_fixture_route(route_row)?
                    .ok_or_else(|| "active crash-route /32 was not observable".to_owned())?;
                if !same_fixture_route_key(observed_route, route_row) {
                    return Err("active crash-route /32 identity changed".to_owned());
                }
                let observed_address = lookup_unicast_address(address_row)?
                    .ok_or_else(|| "active crash-route address was not observable".to_owned())?;
                if !same_unicast_address_key(observed_address, address_row) {
                    return Err("active crash-route address identity changed".to_owned());
                }
                let active =
                    observe_windows_packet_route(IpAddr::V4(IPV4_CRASH_REMOVAL_DESTINATION))
                        .map_err(|error| format!("observe active crash route: {error}"))?;
                if active.egress_interface() != capture_interface
                    || active.source_address() != IpAddr::V4(IPV4_CAPTURE_SOURCE)
                    || active.route_prefix() != "1.0.0.4/32"
                {
                    return Err(format!(
                        "active crash route selected unexpected evidence: interface={:?}, source={}, prefix={}",
                        active.egress_interface(),
                        active.source_address(),
                        active.route_prefix()
                    ));
                }
                evidence = Some(CrashCaptureEvidence {
                    capture_interface,
                    route_row,
                    address_row,
                });
                Ok::<(), String>(())
            })();

            let termination_result = child.terminate_and_wait();
            let removal_result = (|| {
                let deadline = Instant::now() + CRASH_CAPTURE_REMOVAL_TIMEOUT;
                api.wait_for_adapter_absent_until(&capture_name, deadline)?;
                if let Some(evidence) = evidence {
                    wait_for_fixture_route_absent_until(evidence.route_row, deadline)?;
                    wait_for_unicast_address_absent_until(evidence.address_row, deadline)?;
                    let recovered =
                        observe_windows_packet_route(IpAddr::V4(IPV4_CRASH_REMOVAL_DESTINATION))
                            .map_err(|error| {
                                format!("observe post-crash baseline route: {error}")
                            })?;
                    if recovered.egress_interface() != baseline_interface
                        || recovered.source_address() != IpAddr::V4(IPV4_BASELINE_SOURCE)
                        || recovered.route_prefix() != "1.0.0.0/24"
                        || evidence.capture_interface == recovered.egress_interface()
                    {
                        return Err(format!(
                            "post-crash route did not recover the exact baseline: interface={:?}, source={}, prefix={}",
                            recovered.egress_interface(),
                            recovered.source_address(),
                            recovered.route_prefix()
                        ));
                    }
                }
                Ok::<(), String>(())
            })();

            let mut errors = Vec::new();
            if let Err(error) = active_result {
                errors.push(format!("active evidence: {error}"));
            }
            match termination_result {
                Ok(status) if !status.success() => {}
                Ok(status) => errors.push(format!("crash child exited successfully: {status}")),
                Err(error) => errors.push(format!("child termination: {error}")),
            }
            if let Err(error) = removal_result {
                errors.push(format!("bounded capture removal: {error}"));
            }
            if !errors.is_empty() {
                return Err(errors.join("; "));
            }
            Ok::<(), String>(())
        })();

        let baseline_route_cleanup = match baseline_route.as_mut() {
            Some(route) => route.remove_and_verify(),
            None => Ok(()),
        };
        let baseline_address_cleanup = match baseline_address.as_mut() {
            Some(address) => address.remove_and_verify(),
            None => Ok(()),
        };
        baseline_adapter.end_session();
        baseline_adapter.close_adapter();
        let mut cleanup_errors = Vec::new();
        if let Err(error) = baseline_route_cleanup {
            cleanup_errors.push(format!("baseline route: {error}"));
        }
        if let Err(error) = baseline_address_cleanup {
            cleanup_errors.push(format!("baseline address: {error}"));
        }
        if !cleanup_errors.is_empty() {
            return Err(format!(
                "crash-route baseline cleanup failed: {}; crash result: {crash_result:?}",
                cleanup_errors.join("; ")
            ));
        }
        crash_result?;
        Ok::<(), String>(())
    })();

    let baseline_cleanup =
        api.require_adapter_absent(&baseline_name, "after crash-route baseline fixture");
    let capture_cleanup =
        api.require_adapter_absent(&capture_name, "after crash-route capture fixture");
    if baseline_cleanup.is_err() || capture_cleanup.is_err() {
        panic!(
            "Wintun crash-route adapter cleanup proof failed: baseline={baseline_cleanup:?}, capture={capture_cleanup:?}; qualification result: {qualification_result:?}"
        );
    }
    if let Err(qualification_error) = qualification_result {
        panic!(
            "disposable crash-route qualification failed after adapter cleanup: {qualification_error}"
        );
    }

    drop(api);
    assert_eq!(
        admission
            .retained_dll_length()
            .expect("revalidate retained admitted Wintun DLL after crash-route removal"),
        admission.evidence().dll_length
    );
}

#[test]
fn native_wintun_crash_child_holds_active_capture_route() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(SOCKET_BINDING_CI_ENV).as_deref() != Ok("1")
        || std::env::var(CRASH_REMOVAL_CI_ENV).as_deref() != Ok("1")
        || std::env::var(CRASH_REMOVAL_CHILD_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let adapter_name_string = std::env::var(CRASH_REMOVAL_ADAPTER_ENV)
        .expect("crash-route child requires its exact adapter name");
    assert!(
        adapter_name_string.starts_with("SlipstreamCI-CrashRouteCapture-"),
        "crash-route child rejected an unowned adapter name"
    );
    let ready_path = required_path(CRASH_REMOVAL_READY_ENV);
    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted child Wintun DLL: {error}"));
    let adapter_name = wide(&adapter_name_string);
    let tunnel_type = wide("Slipstream CI Crash Capture");
    api.require_adapter_absent(&adapter_name, "inside crash-route child before creation")
        .unwrap_or_else(|error| panic!("Wintun crash-route child preflight: {error}"));

    let mut adapter = OwnedWintunAdapter::create(&api, &adapter_name, &tunnel_type)
        .unwrap_or_else(|error| panic!("create crash-route child adapter: {error}"));
    adapter
        .start_session()
        .unwrap_or_else(|error| panic!("start crash-route child session: {error}"));
    let capture_interface = adapter
        .interface_identity()
        .unwrap_or_else(|error| panic!("read crash-route child interface: {error}"));
    let mut address = OwnedUnicastAddress::create(
        capture_interface,
        IpAddr::V4(IPV4_CAPTURE_SOURCE),
        IPV4_HOST_PREFIX_LENGTH,
    )
    .unwrap_or_else(|error| panic!("create crash-route child address: {error}"));
    let mut issuer = WindowsOwnedRouteTransitionIssuer::new(9, capture_interface, 1)
        .unwrap_or_else(|error| panic!("construct crash-route child issuer: {error}"));

    let route_result = qualify_disposable_exact_host_route_with_active_probe(
        &mut issuer,
        IpAddr::V4(IPV4_CRASH_REMOVAL_DESTINATION),
        |active| {
            if active.capture_interface() != capture_interface
                || active.capture_source_address() != IpAddr::V4(IPV4_CAPTURE_SOURCE)
                || active.exact_route_prefix() != "1.0.0.4/32"
            {
                return Err("crash-route child received inconsistent active evidence".to_owned());
            }
            write_crash_ready_marker(
                &ready_path,
                &format!("{adapter_name_string}\n{}\n", std::process::id()),
            )?;
            std::hint::black_box((&admission, &api, &adapter, &address, active));
            thread::sleep(CRASH_CHILD_FAILSAFE_LIFETIME);
            Err("crash-route child exceeded its failsafe lifetime".to_owned())
        },
    );
    let address_cleanup = address.remove_and_verify();
    adapter.end_session();
    adapter.close_adapter();
    panic!(
        "crash-route child returned instead of being terminated: route={route_result:?}, address_cleanup={address_cleanup:?}"
    );
}

#[test]
fn native_wintun_independent_route_owner_is_preserved_during_capture() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(SOCKET_BINDING_CI_ENV).as_deref() != Ok("1")
        || std::env::var(INDEPENDENT_ROUTE_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let independent_name_string = unique_adapter_name("IndependentRouteOwner");
    let independent_name = wide(&independent_name_string);
    let capture_name = wide(&unique_adapter_name("IndependentRouteCapture"));
    let capture_tunnel_type = wide("Slipstream CI Independent Capture");
    api.require_adapter_absent(&independent_name, "before independent route-owner fixture")
        .unwrap_or_else(|error| panic!("independent route-owner preflight: {error}"));
    api.require_adapter_absent(&capture_name, "before independent capture fixture")
        .unwrap_or_else(|error| panic!("independent capture preflight: {error}"));

    let qualification_result = (|| {
        let fixture_dir = OwnedIndependentRouteFixtureDirectory::create()?;
        let current_exe = std::env::current_exe()
            .map_err(|error| format!("resolve exact integration-test executable: {error}"))?;
        let child = Command::new(current_exe)
            .args([
                "--exact",
                "native_wintun_independent_route_child_holds_baseline",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(INDEPENDENT_ROUTE_CHILD_ENV, "1")
            .env(INDEPENDENT_ROUTE_ADAPTER_ENV, &independent_name_string)
            .env(INDEPENDENT_ROUTE_READY_ENV, fixture_dir.ready_path())
            .env(INDEPENDENT_ROUTE_RELEASE_ENV, fixture_dir.release_path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("spawn independent route-owner child: {error}"))?;
        let mut child = IndependentRouteChild::new(child);
        let expected_marker = format!("{independent_name_string}\n{}\n", child.id());
        let mut independent_evidence = None;

        let coexistence_result = (|| {
            wait_for_independent_route_child_ready(
                &mut child,
                fixture_dir.ready_path(),
                &expected_marker,
            )?;
            child.require_running("after readiness")?;
            let independent_interface = api
                .adapter_interface_identity(&independent_name)?
                .ok_or_else(|| {
                    "independent route-owner adapter disappeared after readiness".to_owned()
                })?;
            let route_lookup = fixture_route_row(
                independent_interface,
                IpAddr::V4(IPV4_BASELINE_NETWORK),
                IPV4_BASELINE_PREFIX_LENGTH,
                0,
            );
            let route_row = lookup_fixture_route(route_lookup)?
                .ok_or_else(|| "independent route-owner /24 was not observable".to_owned())?;
            let address_lookup = fixture_unicast_address_row(
                independent_interface,
                IpAddr::V4(IPV4_INDEPENDENT_ROUTE_SOURCE),
                IPV4_HOST_PREFIX_LENGTH,
            );
            let address_row = lookup_unicast_address(address_lookup)?
                .ok_or_else(|| "independent route-owner address was not observable".to_owned())?;
            independent_evidence = Some(IndependentRouteEvidence {
                route_row,
                address_row,
            });
            require_independent_route_resources_unchanged(
                &api,
                &independent_name,
                independent_interface,
                route_row,
                address_row,
            )?;
            require_independent_route_selected(independent_interface)?;

            let mut capture_adapter =
                OwnedWintunAdapter::create(&api, &capture_name, &capture_tunnel_type)?;
            let mut capture_address = None;
            let capture_result = (|| {
                capture_adapter.start_session()?;
                let capture_interface = capture_adapter.interface_identity()?;
                if capture_interface == independent_interface {
                    return Err("capture adapter reused the independent owner identity".to_owned());
                }
                capture_address = Some(OwnedUnicastAddress::create(
                    capture_interface,
                    IpAddr::V4(IPV4_CAPTURE_SOURCE),
                    IPV4_HOST_PREFIX_LENGTH,
                )?);
                let mut issuer =
                    WindowsOwnedRouteTransitionIssuer::new(11, capture_interface, 1)
                        .map_err(|error| format!("construct independent-route issuer: {error}"))?;
                let qualification = qualify_disposable_exact_host_route_with_active_probe(
                    &mut issuer,
                    IpAddr::V4(IPV4_INDEPENDENT_ROUTE_DESTINATION),
                    |active| {
                        child.require_running("while the capture route is active")?;
                        require_independent_route_resources_unchanged(
                            &api,
                            &independent_name,
                            independent_interface,
                            route_row,
                            address_row,
                        )?;
                        if active.baseline_egress_interface() != independent_interface
                            || active.baseline_source_address()
                                != IpAddr::V4(IPV4_INDEPENDENT_ROUTE_SOURCE)
                            || active.capture_interface() != capture_interface
                            || active.capture_source_address() != IpAddr::V4(IPV4_CAPTURE_SOURCE)
                            || active.exact_route_prefix() != "1.0.0.5/32"
                        {
                            return Err(
                                "active capture did not retain the independent baseline evidence"
                                    .to_owned(),
                            );
                        }
                        Ok(())
                    },
                )
                .map_err(|error| format!("qualify independent route coexistence: {error}"))?;
                if qualification.destination() != IpAddr::V4(IPV4_INDEPENDENT_ROUTE_DESTINATION)
                    || qualification.capture_interface() != capture_interface
                    || qualification.baseline_egress_interface() != independent_interface
                    || qualification.recovered_egress_interface() != independent_interface
                {
                    return Err(
                        "independent route coexistence returned inconsistent evidence".to_owned(),
                    );
                }
                child.require_running("after capture-route removal")?;
                require_independent_route_resources_unchanged(
                    &api,
                    &independent_name,
                    independent_interface,
                    route_row,
                    address_row,
                )?;
                require_independent_route_selected(independent_interface)?;
                Ok::<(), String>(())
            })();

            let capture_address_cleanup = match capture_address.as_mut() {
                Some(address) => address.remove_and_verify(),
                None => Ok(()),
            };
            capture_adapter.end_session();
            capture_adapter.close_adapter();
            let capture_adapter_cleanup =
                api.require_adapter_absent(&capture_name, "after independent capture fixture");
            let independent_after_cleanup = (|| {
                child.require_running("after Slipstream capture cleanup")?;
                require_independent_route_resources_unchanged(
                    &api,
                    &independent_name,
                    independent_interface,
                    route_row,
                    address_row,
                )?;
                require_independent_route_selected(independent_interface)
            })();
            let mut errors = Vec::new();
            if let Err(error) = capture_result {
                errors.push(format!("capture transaction: {error}"));
            }
            if let Err(error) = capture_address_cleanup {
                errors.push(format!("capture address cleanup: {error}"));
            }
            if let Err(error) = capture_adapter_cleanup {
                errors.push(format!("capture adapter cleanup: {error}"));
            }
            if let Err(error) = independent_after_cleanup {
                errors.push(format!("independent owner after capture cleanup: {error}"));
            }
            if !errors.is_empty() {
                return Err(errors.join("; "));
            }
            Ok::<(), String>(())
        })();

        let child_exit_result = child.release_and_wait(fixture_dir.release_path());
        let independent_cleanup_result = (|| {
            let deadline = Instant::now() + INDEPENDENT_CHILD_EXIT_TIMEOUT;
            api.wait_for_adapter_absent_until(&independent_name, deadline)?;
            if let Some(evidence) = independent_evidence {
                wait_for_fixture_route_absent_until(evidence.route_row, deadline)?;
                wait_for_unicast_address_absent_until(evidence.address_row, deadline)?;
            }
            Ok::<(), String>(())
        })();

        let mut errors = Vec::new();
        if let Err(error) = coexistence_result {
            errors.push(format!("coexistence: {error}"));
        }
        match child_exit_result {
            Ok(status) if status.success() => {}
            Ok(status) => errors.push(format!("independent child exited unsuccessfully: {status}")),
            Err(error) => errors.push(format!("independent child release: {error}")),
        }
        if let Err(error) = independent_cleanup_result {
            errors.push(format!("independent owner cleanup: {error}"));
        }
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        Ok::<(), String>(())
    })();

    let independent_cleanup =
        api.require_adapter_absent(&independent_name, "after independent route-owner fixture");
    let capture_cleanup =
        api.require_adapter_absent(&capture_name, "after independent capture fixture");
    if independent_cleanup.is_err() || capture_cleanup.is_err() {
        panic!(
            "independent-route cleanup proof failed: owner={independent_cleanup:?}, capture={capture_cleanup:?}; qualification result: {qualification_result:?}"
        );
    }
    if let Err(qualification_error) = qualification_result {
        panic!(
            "disposable independent-route coexistence failed after cleanup: {qualification_error}"
        );
    }

    drop(api);
    assert_eq!(
        admission
            .retained_dll_length()
            .expect("revalidate retained admitted Wintun DLL after independent-route coexistence"),
        admission.evidence().dll_length
    );
}

#[test]
fn native_wintun_independent_route_child_holds_baseline() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(SOCKET_BINDING_CI_ENV).as_deref() != Ok("1")
        || std::env::var(INDEPENDENT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(INDEPENDENT_ROUTE_CHILD_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let adapter_name_string = std::env::var(INDEPENDENT_ROUTE_ADAPTER_ENV)
        .expect("independent route child requires its exact adapter name");
    assert!(
        adapter_name_string.starts_with("SlipstreamCI-IndependentRouteOwner-"),
        "independent route child rejected an unowned adapter name"
    );
    let ready_path = required_path(INDEPENDENT_ROUTE_READY_ENV);
    let release_path = required_path(INDEPENDENT_ROUTE_RELEASE_ENV);
    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted child Wintun DLL: {error}"));
    let adapter_name = wide(&adapter_name_string);
    let tunnel_type = wide("Independent CI Route Owner");
    api.require_adapter_absent(&adapter_name, "inside independent child before creation")
        .unwrap_or_else(|error| panic!("independent route child preflight: {error}"));

    let mut adapter = OwnedWintunAdapter::create(&api, &adapter_name, &tunnel_type)
        .unwrap_or_else(|error| panic!("create independent route child adapter: {error}"));
    adapter
        .start_session()
        .unwrap_or_else(|error| panic!("start independent route child session: {error}"));
    let independent_interface = adapter
        .interface_identity()
        .unwrap_or_else(|error| panic!("read independent route child interface: {error}"));
    let mut address = OwnedUnicastAddress::create(
        independent_interface,
        IpAddr::V4(IPV4_INDEPENDENT_ROUTE_SOURCE),
        IPV4_HOST_PREFIX_LENGTH,
    )
    .unwrap_or_else(|error| panic!("create independent route child address: {error}"));
    let mut route = OwnedFixtureBaselineRoute::create(
        independent_interface,
        IpAddr::V4(IPV4_BASELINE_NETWORK),
        IPV4_BASELINE_PREFIX_LENGTH,
    )
    .unwrap_or_else(|error| panic!("create independent route child baseline: {error}"));
    write_independent_ready_marker(
        &ready_path,
        &format!("{adapter_name_string}\n{}\n", std::process::id()),
    )
    .unwrap_or_else(|error| panic!("publish independent route child readiness: {error}"));
    wait_for_independent_release(&release_path, &admission, &api, &adapter, &address, &route)
        .unwrap_or_else(|error| panic!("wait for independent route child release: {error}"));

    let route_cleanup = route.remove_and_verify();
    let address_cleanup = address.remove_and_verify();
    adapter.end_session();
    adapter.close_adapter();
    let adapter_cleanup =
        api.require_adapter_absent(&adapter_name, "after independent route child release");
    if route_cleanup.is_err() || address_cleanup.is_err() || adapter_cleanup.is_err() {
        panic!(
            "independent route child cleanup failed: route={route_cleanup:?}, address={address_cleanup:?}, adapter={adapter_cleanup:?}"
        );
    }
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
            IpAddr::V6(IPV6_BASELINE_NETWORK),
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

#[test]
fn native_wintun_ipv4_preexisting_flow_is_preserved_or_safely_recovered() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(SOCKET_BINDING_CI_ENV).as_deref() != Ok("1")
        || std::env::var(PACKET_DELIVERY_CI_ENV).as_deref() != Ok("1")
        || std::env::var(PREEXISTING_FLOW_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let baseline_name = wide(&unique_adapter_name("PreFlow4Baseline"));
    let capture_name = wide(&unique_adapter_name("PreFlow4Capture"));
    let baseline_tunnel_type = wide("Slipstream CI IPv4 Existing Baseline");
    let capture_tunnel_type = wide("Slipstream CI IPv4 Existing Capture");
    api.require_adapter_absent(&baseline_name, "before IPv4 existing-flow baseline fixture")
        .unwrap_or_else(|error| panic!("Wintun IPv4 existing-flow baseline preflight: {error}"));
    api.require_adapter_absent(&capture_name, "before IPv4 existing-flow capture fixture")
        .unwrap_or_else(|error| panic!("Wintun IPv4 existing-flow capture preflight: {error}"));

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
            return Err("IPv4 existing-flow adapters resolved to the same interface".to_owned());
        }

        let mut baseline_address = None;
        let mut capture_address = None;
        let mut baseline_route = None;
        let flow_result = (|| {
            baseline_address = Some(OwnedUnicastAddress::create(
                baseline_interface,
                IpAddr::V4(IPV4_BASELINE_SOURCE),
                IPV4_HOST_PREFIX_LENGTH,
            )?);
            capture_address = Some(OwnedUnicastAddress::create(
                capture_interface,
                IpAddr::V4(IPV4_CAPTURE_SOURCE),
                IPV4_HOST_PREFIX_LENGTH,
            )?);
            baseline_route = Some(OwnedFixtureBaselineRoute::create(
                baseline_interface,
                IpAddr::V4(IPV4_BASELINE_NETWORK),
                IPV4_BASELINE_PREFIX_LENGTH,
            )?);
            let socket = connected_ipv4_udp_socket(
                IPV4_BASELINE_SOURCE,
                IPV4_PREEXISTING_DESTINATION,
                PACKET_DELIVERY_PORT,
            )?;
            prove_ipv4_udp_round_trip_on_adapter(
                &socket,
                &baseline_adapter,
                IPV4_BASELINE_SOURCE,
                IPV4_PREEXISTING_DESTINATION,
                PREEXISTING_WARMUP_REQUEST,
                PREEXISTING_WARMUP_RESPONSE,
                "pre-existing warm-up",
            )?;

            let mut active_path = None;
            let mut issuer = WindowsOwnedRouteTransitionIssuer::new(7, capture_interface, 1)
                .map_err(|error| format!("construct IPv4 existing-flow issuer: {error}"))?;
            let route_result = qualify_disposable_exact_host_route_with_active_probe(
                &mut issuer,
                IpAddr::V4(IPV4_PREEXISTING_DESTINATION),
                |active| {
                    let path = prove_ipv4_preexisting_flow_during_activation(
                        active,
                        &socket,
                        &baseline_adapter,
                        &capture_adapter,
                    )?;
                    active_path = Some(path);
                    match path {
                        PreexistingFlowPath::Baseline => Ok(()),
                        PreexistingFlowPath::Capture => {
                            Err(PREEXISTING_CAPTURE_ROLLBACK.to_owned())
                        }
                    }
                },
            );

            let qualification = match (route_result, active_path) {
                (Ok(qualification), Some(PreexistingFlowPath::Baseline)) => Some(qualification),
                (Err(error), Some(PreexistingFlowPath::Capture))
                    if error.code() == WindowsDisposableExactRouteErrorCode::ActiveProbeFailed
                        && error.detail_message() == Some(PREEXISTING_CAPTURE_ROLLBACK) =>
                {
                    prove_ipv4_udp_round_trip_on_adapter(
                        &socket,
                        &baseline_adapter,
                        IPV4_BASELINE_SOURCE,
                        IPV4_PREEXISTING_DESTINATION,
                        PREEXISTING_RETRY_REQUEST,
                        PREEXISTING_RETRY_RESPONSE,
                        "post-rollback retry",
                    )?;
                    None
                }
                (Ok(_), path) => {
                    return Err(format!(
                        "existing-flow qualification succeeded without baseline continuity: {path:?}"
                    ))
                }
                (Err(error), path) => {
                    return Err(format!(
                        "existing-flow qualification returned unexpected evidence: error={error}, path={path:?}"
                    ))
                }
            };

            if let Some(qualification) = qualification.as_ref() {
                if qualification.destination() != IpAddr::V4(IPV4_PREEXISTING_DESTINATION)
                    || qualification.exact_route_prefix() != "1.0.0.3/32"
                    || qualification.capture_interface() != capture_interface
                    || qualification.baseline_egress_interface() != baseline_interface
                    || qualification.recovered_egress_interface() != baseline_interface
                    || qualification.route_epoch_after_removal() != 3
                {
                    return Err(
                        "IPv4 existing-flow qualification returned inconsistent evidence"
                            .to_owned(),
                    );
                }
            }
            Ok::<_, String>(qualification)
        })();

        let baseline_route_cleanup = match baseline_route.as_mut() {
            Some(route) => route.remove_and_verify(),
            None => Ok(()),
        };
        let capture_address_cleanup = match capture_address.as_mut() {
            Some(address) => address.remove_and_verify(),
            None => Ok(()),
        };
        let baseline_address_cleanup = match baseline_address.as_mut() {
            Some(address) => address.remove_and_verify(),
            None => Ok(()),
        };
        capture_adapter.end_session();
        capture_adapter.close_adapter();
        baseline_adapter.end_session();
        baseline_adapter.close_adapter();
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
                "IPv4 existing-flow fixture cleanup failed: {}; flow result: {flow_result:?}",
                cleanup_errors.join("; "),
            ));
        }
        flow_result?;
        Ok::<(), String>(())
    })();

    let baseline_cleanup =
        api.require_adapter_absent(&baseline_name, "after IPv4 existing-flow baseline fixture");
    let capture_cleanup =
        api.require_adapter_absent(&capture_name, "after IPv4 existing-flow capture fixture");
    if baseline_cleanup.is_err() || capture_cleanup.is_err() {
        panic!(
            "Wintun IPv4 existing-flow adapter cleanup proof failed: baseline={baseline_cleanup:?}, capture={capture_cleanup:?}; qualification result: {qualification_result:?}"
        );
    }
    if let Err(qualification_error) = qualification_result {
        panic!(
            "disposable IPv4 existing-flow qualification failed after adapter cleanup: {qualification_error}"
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
fn native_wintun_ipv4_tcp_preexisting_flow_is_preserved_or_safely_recovered() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(SOCKET_BINDING_CI_ENV).as_deref() != Ok("1")
        || std::env::var(PACKET_DELIVERY_CI_ENV).as_deref() != Ok("1")
        || std::env::var(PREEXISTING_TCP_FLOW_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    assert_ipv4_tcp_segment_parser_contract();
    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let baseline_name = wide(&unique_adapter_name("TcpFlow4Baseline"));
    let capture_name = wide(&unique_adapter_name("TcpFlow4Capture"));
    let baseline_tunnel_type = wide("Slipstream CI IPv4 TCP Baseline");
    let capture_tunnel_type = wide("Slipstream CI IPv4 TCP Capture");
    api.require_adapter_absent(&baseline_name, "before IPv4 TCP-flow baseline fixture")
        .unwrap_or_else(|error| panic!("Wintun IPv4 TCP-flow baseline preflight: {error}"));
    api.require_adapter_absent(&capture_name, "before IPv4 TCP-flow capture fixture")
        .unwrap_or_else(|error| panic!("Wintun IPv4 TCP-flow capture preflight: {error}"));

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
            return Err("IPv4 TCP-flow adapters resolved to the same interface".to_owned());
        }

        let mut baseline_address = None;
        let mut capture_address = None;
        let mut baseline_route = None;
        let flow_result = (|| {
            baseline_address = Some(OwnedUnicastAddress::create(
                baseline_interface,
                IpAddr::V4(IPV4_BASELINE_SOURCE),
                IPV4_HOST_PREFIX_LENGTH,
            )?);
            capture_address = Some(OwnedUnicastAddress::create(
                capture_interface,
                IpAddr::V4(IPV4_CAPTURE_SOURCE),
                IPV4_HOST_PREFIX_LENGTH,
            )?);
            baseline_route = Some(OwnedFixtureBaselineRoute::create(
                baseline_interface,
                IpAddr::V4(IPV4_BASELINE_NETWORK),
                IPV4_BASELINE_PREFIX_LENGTH,
            )?);
            let mut stream = connected_ipv4_tcp_stream(
                IPV4_BASELINE_SOURCE,
                IPV4_PREEXISTING_DESTINATION,
                TCP_PACKET_DELIVERY_PORT,
                &baseline_adapter,
            )?;
            prove_ipv4_tcp_round_trip_on_adapter(
                &mut stream,
                &baseline_adapter,
                IPV4_BASELINE_SOURCE,
                IPV4_PREEXISTING_DESTINATION,
                PREEXISTING_TCP_WARMUP_REQUEST,
                PREEXISTING_TCP_WARMUP_RESPONSE,
                "TCP pre-existing warm-up",
            )?;

            let mut active_path = None;
            let mut issuer = WindowsOwnedRouteTransitionIssuer::new(8, capture_interface, 1)
                .map_err(|error| format!("construct IPv4 TCP-flow issuer: {error}"))?;
            let route_result = qualify_disposable_exact_host_route_with_active_probe(
                &mut issuer,
                IpAddr::V4(IPV4_PREEXISTING_DESTINATION),
                |active| {
                    let path = prove_ipv4_tcp_preexisting_flow_during_activation(
                        active,
                        &mut stream,
                        &baseline_adapter,
                        &capture_adapter,
                    )?;
                    active_path = Some(path);
                    match path {
                        PreexistingFlowPath::Baseline => Ok(()),
                        PreexistingFlowPath::Capture => {
                            Err(PREEXISTING_TCP_CAPTURE_ROLLBACK.to_owned())
                        }
                    }
                },
            );

            let qualification = match (route_result, active_path) {
                (Ok(qualification), Some(PreexistingFlowPath::Baseline)) => Some(qualification),
                (Err(error), Some(PreexistingFlowPath::Capture))
                    if error.code() == WindowsDisposableExactRouteErrorCode::ActiveProbeFailed
                        && error.detail_message() == Some(PREEXISTING_TCP_CAPTURE_ROLLBACK) =>
                {
                    complete_ipv4_tcp_round_trip_on_adapter(
                        &mut stream,
                        &baseline_adapter,
                        IPV4_BASELINE_SOURCE,
                        IPV4_PREEXISTING_DESTINATION,
                        PREEXISTING_TCP_ACTIVE_REQUEST,
                        PREEXISTING_TCP_ACTIVE_RESPONSE,
                        "post-rollback TCP active retransmission",
                    )?;
                    None
                }
                (Ok(_), path) => {
                    return Err(format!(
                        "TCP-flow qualification succeeded without baseline continuity: {path:?}"
                    ))
                }
                (Err(error), path) => {
                    return Err(format!(
                        "TCP-flow qualification returned unexpected evidence: error={error}, path={path:?}"
                    ))
                }
            };
            prove_ipv4_tcp_round_trip_on_adapter(
                &mut stream,
                &baseline_adapter,
                IPV4_BASELINE_SOURCE,
                IPV4_PREEXISTING_DESTINATION,
                PREEXISTING_TCP_RETRY_REQUEST,
                PREEXISTING_TCP_RETRY_RESPONSE,
                "post-removal TCP retry",
            )?;

            if let Some(qualification) = qualification.as_ref() {
                if qualification.destination() != IpAddr::V4(IPV4_PREEXISTING_DESTINATION)
                    || qualification.exact_route_prefix() != "1.0.0.3/32"
                    || qualification.capture_interface() != capture_interface
                    || qualification.baseline_egress_interface() != baseline_interface
                    || qualification.recovered_egress_interface() != baseline_interface
                    || qualification.route_epoch_after_removal() != 3
                {
                    return Err(
                        "IPv4 TCP-flow qualification returned inconsistent evidence".to_owned()
                    );
                }
            }
            drop(stream);
            Ok::<_, String>(qualification)
        })();

        let baseline_route_cleanup = match baseline_route.as_mut() {
            Some(route) => route.remove_and_verify(),
            None => Ok(()),
        };
        let capture_address_cleanup = match capture_address.as_mut() {
            Some(address) => address.remove_and_verify(),
            None => Ok(()),
        };
        let baseline_address_cleanup = match baseline_address.as_mut() {
            Some(address) => address.remove_and_verify(),
            None => Ok(()),
        };
        capture_adapter.end_session();
        capture_adapter.close_adapter();
        baseline_adapter.end_session();
        baseline_adapter.close_adapter();
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
                "IPv4 TCP-flow fixture cleanup failed: {}; flow result: {flow_result:?}",
                cleanup_errors.join("; "),
            ));
        }
        flow_result?;
        Ok::<(), String>(())
    })();

    let baseline_cleanup =
        api.require_adapter_absent(&baseline_name, "after IPv4 TCP-flow baseline fixture");
    let capture_cleanup =
        api.require_adapter_absent(&capture_name, "after IPv4 TCP-flow capture fixture");
    if baseline_cleanup.is_err() || capture_cleanup.is_err() {
        panic!(
            "Wintun IPv4 TCP-flow adapter cleanup proof failed: baseline={baseline_cleanup:?}, capture={capture_cleanup:?}; qualification result: {qualification_result:?}"
        );
    }
    if let Err(qualification_error) = qualification_result {
        panic!(
            "disposable IPv4 TCP-flow qualification failed after adapter cleanup: {qualification_error}"
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
fn native_wintun_ipv6_packet_round_trip_is_captured_and_injected() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(SOCKET_BINDING_CI_ENV).as_deref() != Ok("1")
        || std::env::var(PACKET_DELIVERY_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let baseline_name = wide(&unique_adapter_name("Packet6Baseline"));
    let capture_name = wide(&unique_adapter_name("Packet6Capture"));
    let baseline_tunnel_type = wide("Slipstream CI IPv6 Packet Baseline");
    let capture_tunnel_type = wide("Slipstream CI IPv6 Packet Capture");
    api.require_adapter_absent(&baseline_name, "before IPv6 packet baseline fixture")
        .unwrap_or_else(|error| panic!("Wintun IPv6 packet baseline preflight: {error}"));
    api.require_adapter_absent(&capture_name, "before IPv6 packet capture fixture")
        .unwrap_or_else(|error| panic!("Wintun IPv6 packet capture preflight: {error}"));

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
            return Err("IPv6 packet fixture adapters resolved to the same interface".to_owned());
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
        let mut issuer = WindowsOwnedRouteTransitionIssuer::new(6, capture_interface, 1)
            .map_err(|error| format!("construct IPv6 packet-delivery issuer: {error}"))?;
        let mut baseline_route = OwnedFixtureBaselineRoute::create(
            baseline_interface,
            IpAddr::V6(IPV6_BASELINE_NETWORK),
            IPV6_BASELINE_PREFIX_LENGTH,
        )?;

        let route_result = qualify_disposable_exact_host_route_with_active_probe(
            &mut issuer,
            destination,
            |active| {
                prove_ipv6_packet_round_trip(
                    active,
                    &capture_adapter,
                    capture_source,
                    baseline_interface,
                    baseline_source,
                )
            },
        )
        .map_err(|error| format!("qualify IPv6 packet delivery: {error}"));

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
                "IPv6 packet fixture cleanup failed: {}; route result: {route_result:?}",
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
                "IPv6 packet-delivery qualification returned inconsistent evidence".to_owned(),
            );
        }

        capture_adapter.end_session();
        capture_adapter.close_adapter();
        baseline_adapter.end_session();
        baseline_adapter.close_adapter();
        Ok::<(), String>(())
    })();

    let baseline_cleanup =
        api.require_adapter_absent(&baseline_name, "after IPv6 packet baseline fixture");
    let capture_cleanup =
        api.require_adapter_absent(&capture_name, "after IPv6 packet capture fixture");
    if baseline_cleanup.is_err() || capture_cleanup.is_err() {
        panic!(
            "Wintun IPv6 packet adapter cleanup proof failed: baseline={baseline_cleanup:?}, capture={capture_cleanup:?}; qualification result: {qualification_result:?}"
        );
    }
    if let Err(qualification_error) = qualification_result {
        panic!(
            "disposable IPv6 packet-delivery qualification failed after adapter cleanup: {qualification_error}"
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

fn connected_ipv4_udp_socket(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    destination_port: u16,
) -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind(SocketAddrV4::new(source, 0))
        .map_err(|error| format!("bind pre-existing IPv4 UDP socket: {error}"))?;
    let peer = SocketAddrV4::new(destination, destination_port);
    socket
        .connect(peer)
        .map_err(|error| format!("connect pre-existing IPv4 UDP socket: {error}"))?;
    let local = match socket
        .local_addr()
        .map_err(|error| format!("read pre-existing IPv4 UDP local address: {error}"))?
    {
        SocketAddr::V4(local) => local,
        SocketAddr::V6(_) => {
            return Err("pre-existing IPv4 UDP socket retained an IPv6 local address".to_owned())
        }
    };
    let observed_peer = match socket
        .peer_addr()
        .map_err(|error| format!("read pre-existing IPv4 UDP peer address: {error}"))?
    {
        SocketAddr::V4(peer) => peer,
        SocketAddr::V6(_) => {
            return Err("pre-existing IPv4 UDP socket retained an IPv6 peer".to_owned())
        }
    };
    if *local.ip() != source || local.port() == 0 || observed_peer != peer {
        return Err(format!(
            "pre-existing IPv4 UDP binding mismatch: local={local}, peer={observed_peer}, expected_source={source}, expected_peer={peer}"
        ));
    }
    Ok(socket)
}

fn prove_ipv4_udp_round_trip_on_adapter(
    socket: &UdpSocket,
    adapter: &OwnedWintunAdapter<'_>,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    request_payload: &[u8],
    response_payload: &[u8],
    phase: &str,
) -> Result<(), String> {
    let local = match socket
        .local_addr()
        .map_err(|error| format!("read {phase} local address: {error}"))?
    {
        SocketAddr::V4(local) => local,
        SocketAddr::V6(_) => return Err(format!("{phase} socket retained an IPv6 local address")),
    };
    if *local.ip() != source || local.port() == 0 {
        return Err(format!(
            "{phase} source mismatch: local={local}, expected={source}"
        ));
    }

    let deadline = Instant::now() + PACKET_DELIVERY_TIMEOUT;
    let sent = socket
        .send(request_payload)
        .map_err(|error| format!("send {phase} request: {error}"))?;
    if sent != request_payload.len() {
        return Err(format!(
            "{phase} request was partial: sent={sent}, expected={}",
            request_payload.len()
        ));
    }
    let request = adapter.receive_matching_ipv4_udp_request(
        source,
        destination,
        local.port(),
        PACKET_DELIVERY_PORT,
        request_payload,
        deadline,
    )?;
    inject_and_receive_ipv4_udp_response(
        socket,
        adapter,
        request,
        destination,
        source,
        response_payload,
        deadline,
        phase,
    )
}

fn prove_ipv4_preexisting_flow_during_activation(
    active: &WindowsDisposableExactRouteActiveProbe<'_>,
    socket: &UdpSocket,
    baseline_adapter: &OwnedWintunAdapter<'_>,
    capture_adapter: &OwnedWintunAdapter<'_>,
) -> Result<PreexistingFlowPath, String> {
    if active.destination() != IpAddr::V4(IPV4_PREEXISTING_DESTINATION)
        || active.exact_route_prefix() != "1.0.0.3/32"
        || active.capture_interface() == active.baseline_egress_interface()
        || active.baseline_source_address() != IpAddr::V4(IPV4_BASELINE_SOURCE)
        || active.capture_source_address() != IpAddr::V4(IPV4_CAPTURE_SOURCE)
    {
        return Err(
            "active route facts do not prove the controlled existing-flow paths".to_owned(),
        );
    }
    let local = match socket
        .local_addr()
        .map_err(|error| format!("read active existing-flow local address: {error}"))?
    {
        SocketAddr::V4(local) => local,
        SocketAddr::V6(_) => {
            return Err("active existing-flow socket retained an IPv6 local address".to_owned())
        }
    };
    if *local.ip() != IPV4_BASELINE_SOURCE || local.port() == 0 {
        return Err(format!(
            "active existing-flow source changed before send: {local}"
        ));
    }

    let deadline = Instant::now() + PACKET_DELIVERY_TIMEOUT;
    let sent = socket
        .send(PREEXISTING_ACTIVE_REQUEST)
        .map_err(|error| format!("send active existing-flow request: {error}"))?;
    if sent != PREEXISTING_ACTIVE_REQUEST.len() {
        return Err(format!(
            "active existing-flow request was partial: sent={sent}, expected={}",
            PREEXISTING_ACTIVE_REQUEST.len()
        ));
    }
    let (path, request) = receive_ipv4_udp_request_from_either_adapter(
        baseline_adapter,
        capture_adapter,
        IPV4_BASELINE_SOURCE,
        IPV4_PREEXISTING_DESTINATION,
        local.port(),
        PACKET_DELIVERY_PORT,
        PREEXISTING_ACTIVE_REQUEST,
        deadline,
    )?;
    if path == PreexistingFlowPath::Capture {
        return Ok(path);
    }
    inject_and_receive_ipv4_udp_response(
        socket,
        baseline_adapter,
        request,
        IPV4_PREEXISTING_DESTINATION,
        IPV4_BASELINE_SOURCE,
        PREEXISTING_ACTIVE_RESPONSE,
        deadline,
        "active baseline continuity",
    )?;
    Ok(path)
}

fn connected_ipv4_tcp_stream(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    destination_port: u16,
    adapter: &OwnedWintunAdapter<'_>,
) -> Result<TcpStream, String> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|error| format!("create IPv4 TCP socket: {error}"))?;
    socket
        .bind(&SockAddr::from(SocketAddrV4::new(source, 0)))
        .map_err(|error| format!("bind IPv4 TCP baseline source {source}: {error}"))?;
    let local = match socket
        .local_addr()
        .map_err(|error| format!("read bound IPv4 TCP address: {error}"))?
        .as_socket()
    {
        Some(SocketAddr::V4(local)) if *local.ip() == source && local.port() != 0 => local,
        other => return Err(format!("unexpected bound IPv4 TCP address: {other:?}")),
    };
    socket
        .set_nonblocking(true)
        .map_err(|error| format!("make IPv4 TCP connect nonblocking: {error}"))?;
    let peer = SocketAddrV4::new(destination, destination_port);
    match socket.connect(&SockAddr::from(peer)) {
        Ok(()) => {
            return Err(
                "disposable IPv4 TCP socket connected without the synthetic handshake".to_owned(),
            )
        }
        Err(error)
            if error.kind() == ErrorKind::WouldBlock
                || matches!(error.raw_os_error(), Some(10035..=10037)) => {}
        Err(error) => return Err(format!("start nonblocking IPv4 TCP connect: {error}")),
    }

    let deadline = Instant::now() + PACKET_DELIVERY_TIMEOUT;
    let syn = adapter.receive_matching_ipv4_tcp_segment(
        source,
        destination,
        Some(local.port()),
        destination_port,
        &[],
        TCP_FLAG_SYN,
        TCP_FLAG_ACK,
        deadline,
    )?;
    let syn_ack = build_ipv4_tcp_packet(
        destination,
        source,
        destination_port,
        local.port(),
        TCP_SERVER_INITIAL_SEQUENCE,
        syn.sequence_number.wrapping_add(1),
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        &[],
    )?;
    adapter.inject_packet(&syn_ack)?;
    let handshake_ack = adapter.receive_matching_ipv4_tcp_segment(
        source,
        destination,
        Some(local.port()),
        destination_port,
        &[],
        TCP_FLAG_ACK,
        TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN,
        deadline,
    )?;
    if handshake_ack.sequence_number != syn.sequence_number.wrapping_add(1)
        || handshake_ack.acknowledgment_number != TCP_SERVER_INITIAL_SEQUENCE.wrapping_add(1)
    {
        return Err(format!(
            "synthetic IPv4 TCP handshake ACK mismatch: sequence={}, acknowledgment={}",
            handshake_ack.sequence_number, handshake_ack.acknowledgment_number
        ));
    }

    loop {
        if let Some(error) = socket
            .take_error()
            .map_err(|error| format!("read IPv4 TCP connect error: {error}"))?
        {
            return Err(format!("synthetic IPv4 TCP connect failed: {error}"));
        }
        match socket.peer_addr() {
            Ok(observed) if observed.as_socket() == Some(SocketAddr::V4(peer)) => break,
            Ok(observed) => {
                return Err(format!(
                    "synthetic IPv4 TCP connect selected unexpected peer {observed:?}"
                ))
            }
            Err(error)
                if error.kind() == ErrorKind::NotConnected
                    || matches!(error.raw_os_error(), Some(10035 | 10057)) => {}
            Err(error) => return Err(format!("observe synthetic IPv4 TCP connect: {error}")),
        }
        if Instant::now() >= deadline {
            return Err("synthetic IPv4 TCP handshake exceeded its bounded deadline".to_owned());
        }
        thread::sleep(PACKET_DELIVERY_PROBE_INTERVAL);
    }
    socket
        .set_nonblocking(false)
        .map_err(|error| format!("restore blocking IPv4 TCP socket: {error}"))?;
    let stream: TcpStream = socket.into();
    stream
        .set_nodelay(true)
        .map_err(|error| format!("disable Nagle for IPv4 TCP fixture: {error}"))?;
    stream
        .set_read_timeout(Some(PACKET_DELIVERY_TIMEOUT))
        .map_err(|error| format!("bound IPv4 TCP read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(PACKET_DELIVERY_TIMEOUT))
        .map_err(|error| format!("bound IPv4 TCP write timeout: {error}"))?;
    Ok(stream)
}

#[allow(clippy::too_many_arguments)]
fn prove_ipv4_tcp_round_trip_on_adapter(
    stream: &mut TcpStream,
    adapter: &OwnedWintunAdapter<'_>,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    request_payload: &[u8],
    response_payload: &[u8],
    phase: &str,
) -> Result<(), String> {
    stream
        .write_all(request_payload)
        .map_err(|error| format!("write {phase} request: {error}"))?;
    complete_ipv4_tcp_round_trip_on_adapter(
        stream,
        adapter,
        source,
        destination,
        request_payload,
        response_payload,
        phase,
    )
}

#[allow(clippy::too_many_arguments)]
fn complete_ipv4_tcp_round_trip_on_adapter(
    stream: &mut TcpStream,
    adapter: &OwnedWintunAdapter<'_>,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    request_payload: &[u8],
    response_payload: &[u8],
    phase: &str,
) -> Result<(), String> {
    let local = match stream
        .local_addr()
        .map_err(|error| format!("read {phase} local address: {error}"))?
    {
        SocketAddr::V4(local) => local,
        SocketAddr::V6(_) => return Err(format!("{phase} retained an IPv6 local address")),
    };
    let deadline = Instant::now() + PACKET_DELIVERY_TIMEOUT;
    let request = adapter.receive_matching_ipv4_tcp_segment(
        source,
        destination,
        Some(local.port()),
        TCP_PACKET_DELIVERY_PORT,
        request_payload,
        TCP_FLAG_ACK,
        TCP_FLAG_SYN | TCP_FLAG_FIN,
        deadline,
    )?;
    inject_and_receive_ipv4_tcp_response(
        stream,
        adapter,
        request,
        destination,
        source,
        response_payload,
        deadline,
        phase,
    )
}

fn prove_ipv4_tcp_preexisting_flow_during_activation(
    active: &WindowsDisposableExactRouteActiveProbe<'_>,
    stream: &mut TcpStream,
    baseline_adapter: &OwnedWintunAdapter<'_>,
    capture_adapter: &OwnedWintunAdapter<'_>,
) -> Result<PreexistingFlowPath, String> {
    if active.destination() != IpAddr::V4(IPV4_PREEXISTING_DESTINATION)
        || active.exact_route_prefix() != "1.0.0.3/32"
        || active.capture_interface() == active.baseline_egress_interface()
        || active.baseline_source_address() != IpAddr::V4(IPV4_BASELINE_SOURCE)
        || active.capture_source_address() != IpAddr::V4(IPV4_CAPTURE_SOURCE)
    {
        return Err("active route facts do not prove controlled TCP-flow paths".to_owned());
    }
    let local = match stream
        .local_addr()
        .map_err(|error| format!("read active TCP-flow local address: {error}"))?
    {
        SocketAddr::V4(local) => local,
        SocketAddr::V6(_) => return Err("active TCP-flow retained an IPv6 source".to_owned()),
    };
    let peer = match stream
        .peer_addr()
        .map_err(|error| format!("read active TCP-flow peer address: {error}"))?
    {
        SocketAddr::V4(peer) => peer,
        SocketAddr::V6(_) => return Err("active TCP-flow retained an IPv6 peer".to_owned()),
    };
    if *local.ip() != IPV4_BASELINE_SOURCE
        || local.port() == 0
        || *peer.ip() != IPV4_PREEXISTING_DESTINATION
        || peer.port() != TCP_PACKET_DELIVERY_PORT
    {
        return Err(format!(
            "active TCP-flow endpoints changed before send: local={local}, peer={peer}"
        ));
    }

    stream
        .write_all(PREEXISTING_TCP_ACTIVE_REQUEST)
        .map_err(|error| format!("write active TCP-flow request: {error}"))?;
    let deadline = Instant::now() + PACKET_DELIVERY_TIMEOUT;
    let (path, request) = receive_ipv4_tcp_segment_from_either_adapter(
        baseline_adapter,
        capture_adapter,
        IPV4_BASELINE_SOURCE,
        IPV4_PREEXISTING_DESTINATION,
        local.port(),
        TCP_PACKET_DELIVERY_PORT,
        PREEXISTING_TCP_ACTIVE_REQUEST,
        deadline,
    )?;
    if path == PreexistingFlowPath::Capture {
        return Ok(path);
    }
    inject_and_receive_ipv4_tcp_response(
        stream,
        baseline_adapter,
        request,
        IPV4_PREEXISTING_DESTINATION,
        IPV4_BASELINE_SOURCE,
        PREEXISTING_TCP_ACTIVE_RESPONSE,
        deadline,
        "active TCP baseline continuity",
    )?;
    Ok(path)
}

#[allow(clippy::too_many_arguments)]
fn receive_ipv4_tcp_segment_from_either_adapter(
    baseline_adapter: &OwnedWintunAdapter<'_>,
    capture_adapter: &OwnedWintunAdapter<'_>,
    expected_source: Ipv4Addr,
    expected_destination: Ipv4Addr,
    expected_source_port: u16,
    expected_destination_port: u16,
    expected_payload: &[u8],
    deadline: Instant,
) -> Result<(PreexistingFlowPath, CapturedTcpSegment), String> {
    loop {
        if let Some(packet) = baseline_adapter.try_receive_packet()? {
            if let Some(segment) = parse_ipv4_tcp_segment(
                &packet,
                expected_source,
                expected_destination,
                Some(expected_source_port),
                expected_destination_port,
                expected_payload,
                TCP_FLAG_ACK,
                TCP_FLAG_SYN | TCP_FLAG_FIN,
            )? {
                return Ok((PreexistingFlowPath::Baseline, segment));
            }
        }
        if let Some(packet) = capture_adapter.try_receive_packet()? {
            if let Some(segment) = parse_ipv4_tcp_segment(
                &packet,
                expected_source,
                expected_destination,
                Some(expected_source_port),
                expected_destination_port,
                expected_payload,
                TCP_FLAG_ACK,
                TCP_FLAG_SYN | TCP_FLAG_FIN,
            )? {
                return Ok((PreexistingFlowPath::Capture, segment));
            }
        }
        if Instant::now() >= deadline {
            return Err(
                "pre-existing IPv4 TCP request reached neither owned adapter before deadline"
                    .to_owned(),
            );
        }
        thread::sleep(PACKET_DELIVERY_PROBE_INTERVAL);
    }
}

#[allow(clippy::too_many_arguments)]
fn inject_and_receive_ipv4_tcp_response(
    stream: &mut TcpStream,
    adapter: &OwnedWintunAdapter<'_>,
    request: CapturedTcpSegment,
    response_source: Ipv4Addr,
    response_destination: Ipv4Addr,
    response_payload: &[u8],
    deadline: Instant,
    phase: &str,
) -> Result<(), String> {
    let payload_length = u32::try_from(request.payload_length)
        .map_err(|_| format!("{phase} TCP payload length exceeds u32"))?;
    let acknowledged = request.sequence_number.wrapping_add(payload_length);
    let response = build_ipv4_tcp_packet(
        response_source,
        response_destination,
        request.destination_port,
        request.source_port,
        request.acknowledgment_number,
        acknowledged,
        TCP_FLAG_PSH | TCP_FLAG_ACK,
        response_payload,
    )?;
    adapter.inject_packet(&response)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| format!("{phase} exceeded its bounded deadline"))?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|error| format!("bound {phase} receive timeout: {error}"))?;
    let mut received = vec![0u8; response_payload.len()];
    stream
        .read_exact(&mut received)
        .map_err(|error| format!("read {phase} response: {error}"))?;
    if Instant::now() > deadline || received != response_payload {
        return Err(format!(
            "{phase} response exceeded its deadline or mismatched"
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn receive_ipv4_udp_request_from_either_adapter(
    baseline_adapter: &OwnedWintunAdapter<'_>,
    capture_adapter: &OwnedWintunAdapter<'_>,
    expected_source: Ipv4Addr,
    expected_destination: Ipv4Addr,
    expected_source_port: u16,
    expected_destination_port: u16,
    expected_payload: &[u8],
    deadline: Instant,
) -> Result<(PreexistingFlowPath, CapturedUdpRequest), String> {
    loop {
        if let Some(packet) = baseline_adapter.try_receive_packet()? {
            if let Some(request) = parse_ipv4_udp_request(
                &packet,
                expected_source,
                expected_destination,
                expected_source_port,
                expected_destination_port,
                expected_payload,
            )? {
                return Ok((PreexistingFlowPath::Baseline, request));
            }
        }
        if let Some(packet) = capture_adapter.try_receive_packet()? {
            if let Some(request) = parse_ipv4_udp_request(
                &packet,
                expected_source,
                expected_destination,
                expected_source_port,
                expected_destination_port,
                expected_payload,
            )? {
                return Ok((PreexistingFlowPath::Capture, request));
            }
        }
        if Instant::now() >= deadline {
            return Err(
                "pre-existing IPv4 request reached neither owned adapter before deadline"
                    .to_owned(),
            );
        }
        thread::sleep(PACKET_DELIVERY_PROBE_INTERVAL);
    }
}

#[allow(clippy::too_many_arguments)]
fn inject_and_receive_ipv4_udp_response(
    socket: &UdpSocket,
    adapter: &OwnedWintunAdapter<'_>,
    request: CapturedUdpRequest,
    response_source: Ipv4Addr,
    response_destination: Ipv4Addr,
    response_payload: &[u8],
    deadline: Instant,
    phase: &str,
) -> Result<(), String> {
    let response = build_ipv4_udp_packet(
        response_source,
        response_destination,
        request.destination_port,
        request.source_port,
        response_payload,
    )?;
    adapter.inject_packet(&response)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| format!("{phase} exceeded its bounded deadline"))?;
    socket
        .set_read_timeout(Some(remaining))
        .map_err(|error| format!("bound {phase} receive timeout: {error}"))?;
    let mut received = vec![0u8; response_payload.len() + 1];
    let received_length = socket
        .recv(&mut received)
        .map_err(|error| format!("receive {phase} response: {error}"))?;
    if Instant::now() > deadline {
        return Err(format!("{phase} exceeded its bounded deadline"));
    }
    if &received[..received_length] != response_payload {
        return Err(format!(
            "{phase} response payload mismatch: length={received_length}"
        ));
    }
    Ok(())
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

fn prove_ipv6_packet_round_trip(
    active: &WindowsDisposableExactRouteActiveProbe<'_>,
    adapter: &OwnedWintunAdapter<'_>,
    expected_capture_source: Ipv6Addr,
    expected_baseline_interface: WindowsPacketInterfaceIdentity,
    expected_baseline_source: Ipv6Addr,
) -> Result<(), String> {
    let destination = match active.destination() {
        IpAddr::V6(destination) => destination,
        IpAddr::V4(_) => {
            return Err("IPv6 packet-delivery probe received an IPv4 destination".to_owned())
        }
    };
    if active.exact_route_prefix() != format!("{destination}/128")
        || active.capture_interface() == active.baseline_egress_interface()
        || active.baseline_egress_interface() != expected_baseline_interface
        || active.capture_source_address() != IpAddr::V6(expected_capture_source)
        || active.baseline_source_address() != IpAddr::V6(expected_baseline_source)
    {
        return Err("active route facts do not prove the owned IPv6 capture path".to_owned());
    }

    let peer = SocketAddrV6::new(destination, PACKET_DELIVERY_PORT, 0, 0);
    let socket = UdpSocket::bind(SocketAddrV6::new(expected_capture_source, 0, 0, 0))
        .map_err(|error| format!("bind IPv6 packet-delivery socket: {error}"))?;
    socket
        .connect(peer)
        .map_err(|error| format!("connect IPv6 packet-delivery socket: {error}"))?;
    let local = match socket
        .local_addr()
        .map_err(|error| format!("read IPv6 packet-delivery local address: {error}"))?
    {
        SocketAddr::V6(local) => local,
        SocketAddr::V4(_) => {
            return Err("IPv6 packet-delivery socket retained an IPv4 local address".to_owned())
        }
    };
    if *local.ip() != expected_capture_source || local.port() == 0 {
        return Err(format!(
            "IPv6 packet-delivery source mismatch: local={local}, expected={expected_capture_source}"
        ));
    }

    let deadline = Instant::now() + PACKET_DELIVERY_TIMEOUT;
    let sent = socket
        .send(PACKET_REQUEST_PAYLOAD)
        .map_err(|error| format!("send IPv6 packet-delivery request: {error}"))?;
    if sent != PACKET_REQUEST_PAYLOAD.len() {
        return Err(format!(
            "IPv6 packet-delivery request was partial: sent={sent}, expected={}",
            PACKET_REQUEST_PAYLOAD.len()
        ));
    }

    let request = adapter.receive_matching_ipv6_udp_request(
        expected_capture_source,
        destination,
        local.port(),
        PACKET_DELIVERY_PORT,
        PACKET_REQUEST_PAYLOAD,
        deadline,
    )?;
    let response = build_ipv6_udp_packet(
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
        .ok_or_else(|| "Wintun IPv6 packet round trip exceeded its bounded deadline".to_owned())?;
    socket
        .set_read_timeout(Some(remaining))
        .map_err(|error| format!("bound IPv6 packet-delivery receive timeout: {error}"))?;
    let mut received = vec![0u8; PACKET_RESPONSE_PAYLOAD.len() + 1];
    let received_length = socket
        .recv(&mut received)
        .map_err(|error| format!("receive injected IPv6 packet-delivery response: {error}"))?;
    if Instant::now() > deadline {
        return Err("Wintun IPv6 packet round trip exceeded its bounded deadline".to_owned());
    }
    if &received[..received_length] != PACKET_RESPONSE_PAYLOAD {
        return Err(format!(
            "injected IPv6 response payload mismatch: length={received_length}"
        ));
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct CapturedUdpRequest {
    source_port: u16,
    destination_port: u16,
}

#[derive(Debug, Eq, PartialEq)]
struct CapturedTcpSegment {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: u8,
    payload_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreexistingFlowPath {
    Baseline,
    Capture,
}

#[allow(clippy::too_many_arguments)]
fn parse_ipv4_tcp_segment(
    packet: &[u8],
    expected_source: Ipv4Addr,
    expected_destination: Ipv4Addr,
    expected_source_port: Option<u16>,
    expected_destination_port: u16,
    expected_payload: &[u8],
    required_flags: u8,
    forbidden_flags: u8,
) -> Result<Option<CapturedTcpSegment>, String> {
    if packet.len() < IPV4_MIN_HEADER_LENGTH || packet[0] >> 4 != 4 {
        return Ok(None);
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if source != expected_source
        || destination != expected_destination
        || packet[9] != TCP_PROTOCOL_NUMBER
    {
        return Ok(None);
    }

    let ip_header_length = usize::from(packet[0] & 0x0f) * 4;
    if ip_header_length < IPV4_MIN_HEADER_LENGTH || ip_header_length > packet.len() {
        return Err("captured IPv4 TCP packet has an invalid IP header length".to_owned());
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length != packet.len() || total_length < ip_header_length + TCP_MIN_HEADER_LENGTH {
        return Err(format!(
            "captured IPv4 TCP packet length mismatch: packet={}, header={ip_header_length}, total={total_length}",
            packet.len()
        ));
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return Err("captured IPv4 TCP segment was fragmented".to_owned());
    }
    if internet_checksum(&packet[..ip_header_length]) != 0 {
        return Err("captured IPv4 TCP packet has an invalid IP header checksum".to_owned());
    }

    let tcp = &packet[ip_header_length..];
    let tcp_header_length = usize::from(tcp[TCP_DATA_OFFSET] >> 4) * 4;
    if tcp_header_length < TCP_MIN_HEADER_LENGTH || tcp_header_length > tcp.len() {
        return Err("captured IPv4 TCP segment has an invalid TCP header length".to_owned());
    }
    let source_port =
        u16::from_be_bytes([tcp[TCP_SOURCE_PORT_OFFSET], tcp[TCP_SOURCE_PORT_OFFSET + 1]]);
    let destination_port = u16::from_be_bytes([
        tcp[TCP_DESTINATION_PORT_OFFSET],
        tcp[TCP_DESTINATION_PORT_OFFSET + 1],
    ]);
    if expected_source_port.is_some_and(|port| source_port != port)
        || destination_port != expected_destination_port
    {
        return Ok(None);
    }
    let flags = tcp[TCP_FLAGS_OFFSET];
    if flags & required_flags != required_flags || flags & forbidden_flags != 0 {
        return Ok(None);
    }

    let tcp_length = tcp.len();
    let mut pseudo_header = Vec::with_capacity(12 + tcp_length);
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.push(0);
    pseudo_header.push(TCP_PROTOCOL_NUMBER);
    pseudo_header.extend_from_slice(
        &u16::try_from(tcp_length)
            .map_err(|_| "captured IPv4 TCP segment exceeds 65535 bytes".to_owned())?
            .to_be_bytes(),
    );
    pseudo_header.extend_from_slice(tcp);
    if internet_checksum(&pseudo_header) != 0 {
        return Err("captured IPv4 TCP segment has an invalid checksum".to_owned());
    }

    let payload = &tcp[tcp_header_length..];
    if payload.is_empty() && !expected_payload.is_empty() {
        return Ok(None);
    }
    if payload != expected_payload {
        return Err(format!(
            "captured IPv4 TCP payload mismatch: observed={}, expected={}",
            payload.len(),
            expected_payload.len()
        ));
    }
    Ok(Some(CapturedTcpSegment {
        source_port,
        destination_port,
        sequence_number: u32::from_be_bytes([
            tcp[TCP_SEQUENCE_OFFSET],
            tcp[TCP_SEQUENCE_OFFSET + 1],
            tcp[TCP_SEQUENCE_OFFSET + 2],
            tcp[TCP_SEQUENCE_OFFSET + 3],
        ]),
        acknowledgment_number: u32::from_be_bytes([
            tcp[TCP_ACKNOWLEDGMENT_OFFSET],
            tcp[TCP_ACKNOWLEDGMENT_OFFSET + 1],
            tcp[TCP_ACKNOWLEDGMENT_OFFSET + 2],
            tcp[TCP_ACKNOWLEDGMENT_OFFSET + 3],
        ]),
        flags,
        payload_length: payload.len(),
    }))
}

fn assert_ipv4_tcp_segment_parser_contract() {
    let source_port = 40_002;
    let packet = build_ipv4_tcp_packet(
        IPV4_BASELINE_SOURCE,
        IPV4_PREEXISTING_DESTINATION,
        source_port,
        TCP_PACKET_DELIVERY_PORT,
        100,
        200,
        TCP_FLAG_PSH | TCP_FLAG_ACK,
        PREEXISTING_TCP_WARMUP_REQUEST,
    )
    .expect("build checksum-valid IPv4 TCP segment");
    let parse = |packet: &[u8]| {
        parse_ipv4_tcp_segment(
            packet,
            IPV4_BASELINE_SOURCE,
            IPV4_PREEXISTING_DESTINATION,
            Some(source_port),
            TCP_PACKET_DELIVERY_PORT,
            PREEXISTING_TCP_WARMUP_REQUEST,
            TCP_FLAG_ACK,
            TCP_FLAG_SYN | TCP_FLAG_FIN,
        )
    };
    assert_eq!(
        parse(&packet).expect("parse checksum-valid IPv4 TCP segment"),
        Some(CapturedTcpSegment {
            source_port,
            destination_port: TCP_PACKET_DELIVERY_PORT,
            sequence_number: 100,
            acknowledgment_number: 200,
            flags: TCP_FLAG_PSH | TCP_FLAG_ACK,
            payload_length: PREEXISTING_TCP_WARMUP_REQUEST.len(),
        })
    );

    let mut invalid_header = packet.clone();
    invalid_header[8] ^= 1;
    assert!(parse(&invalid_header)
        .expect_err("reject an invalid IPv4 TCP IP-header checksum")
        .contains("invalid IP header checksum"));

    let mut invalid_tcp = packet;
    invalid_tcp[IPV4_MIN_HEADER_LENGTH + TCP_MIN_HEADER_LENGTH] ^= 1;
    assert!(parse(&invalid_tcp)
        .expect_err("reject an invalid IPv4 TCP checksum")
        .contains("invalid checksum"));
}

#[test]
fn ipv4_tcp_segment_parser_requires_valid_checksums() {
    assert_ipv4_tcp_segment_parser_contract();
}

fn parse_ipv4_udp_request(
    packet: &[u8],
    expected_source: Ipv4Addr,
    expected_destination: Ipv4Addr,
    expected_source_port: u16,
    expected_destination_port: u16,
    expected_payload: &[u8],
) -> Result<Option<CapturedUdpRequest>, String> {
    if packet.len() < IPV4_MIN_HEADER_LENGTH || packet[0] >> 4 != 4 {
        return Ok(None);
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if source != expected_source
        || destination != expected_destination
        || packet[9] != UDP_PROTOCOL_NUMBER
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
    if internet_checksum(&packet[..header_length]) != 0 {
        return Err("captured IPv4 packet has an invalid header checksum".to_owned());
    }

    let udp = &packet[header_length..];
    let source_port =
        u16::from_be_bytes([udp[UDP_SOURCE_PORT_OFFSET], udp[UDP_SOURCE_PORT_OFFSET + 1]]);
    let destination_port = u16::from_be_bytes([
        udp[UDP_DESTINATION_PORT_OFFSET],
        udp[UDP_DESTINATION_PORT_OFFSET + 1],
    ]);
    let udp_length = usize::from(u16::from_be_bytes([
        udp[UDP_LENGTH_OFFSET],
        udp[UDP_LENGTH_OFFSET + 1],
    ]));
    if source_port != expected_source_port
        || destination_port != expected_destination_port
        || udp_length != udp.len()
        || udp_length != UDP_HEADER_LENGTH + expected_payload.len()
    {
        return Err(format!(
            "captured IPv4 UDP request mismatch: source_port={source_port}, destination_port={destination_port}, udp_length={udp_length}, packet_udp_length={} ",
            udp.len()
        ));
    }
    let udp_checksum = u16::from_be_bytes([udp[UDP_CHECKSUM_OFFSET], udp[UDP_CHECKSUM_OFFSET + 1]]);
    if udp_checksum != 0 {
        let mut pseudo_header = Vec::with_capacity(12 + udp_length);
        pseudo_header.extend_from_slice(&source.octets());
        pseudo_header.extend_from_slice(&destination.octets());
        pseudo_header.push(0);
        pseudo_header.push(UDP_PROTOCOL_NUMBER);
        pseudo_header.extend_from_slice(&(udp_length as u16).to_be_bytes());
        pseudo_header.extend_from_slice(udp);
        if internet_checksum(&pseudo_header) != 0 {
            return Err("captured IPv4 UDP request has an invalid checksum".to_owned());
        }
    }
    if &udp[UDP_HEADER_LENGTH..] != expected_payload {
        return Err("captured IPv4 UDP request payload mismatch".to_owned());
    }
    Ok(Some(CapturedUdpRequest {
        source_port,
        destination_port,
    }))
}

#[test]
fn ipv4_udp_request_parser_requires_valid_checksums() {
    let source_port = 40_001;
    let packet = build_ipv4_udp_packet(
        IPV4_BASELINE_SOURCE,
        IPV4_PREEXISTING_DESTINATION,
        source_port,
        PACKET_DELIVERY_PORT,
        PREEXISTING_WARMUP_REQUEST,
    )
    .expect("build checksum-valid IPv4 UDP request");
    let parse = |packet: &[u8]| {
        parse_ipv4_udp_request(
            packet,
            IPV4_BASELINE_SOURCE,
            IPV4_PREEXISTING_DESTINATION,
            source_port,
            PACKET_DELIVERY_PORT,
            PREEXISTING_WARMUP_REQUEST,
        )
    };

    assert_eq!(
        parse(&packet).expect("parse checksum-valid IPv4 UDP request"),
        Some(CapturedUdpRequest {
            source_port,
            destination_port: PACKET_DELIVERY_PORT,
        })
    );

    let mut invalid_header = packet.clone();
    invalid_header[8] ^= 1;
    assert!(parse(&invalid_header)
        .expect_err("reject an invalid IPv4 header checksum")
        .contains("invalid header checksum"));

    let mut invalid_udp = packet.clone();
    invalid_udp[IPV4_MIN_HEADER_LENGTH + UDP_HEADER_LENGTH] ^= 1;
    assert!(parse(&invalid_udp)
        .expect_err("reject an invalid IPv4 UDP checksum")
        .contains("invalid checksum"));

    let mut zero_udp_checksum = packet;
    zero_udp_checksum
        [IPV4_MIN_HEADER_LENGTH + UDP_CHECKSUM_OFFSET..IPV4_MIN_HEADER_LENGTH + UDP_HEADER_LENGTH]
        .fill(0);
    assert!(parse(&zero_udp_checksum)
        .expect("IPv4 permits a zero UDP checksum")
        .is_some());
}

fn parse_ipv6_udp_request(
    packet: &[u8],
    expected_source: Ipv6Addr,
    expected_destination: Ipv6Addr,
    expected_source_port: u16,
    expected_destination_port: u16,
    expected_payload: &[u8],
) -> Result<Option<CapturedUdpRequest>, String> {
    if packet.len() < IPV6_HEADER_LENGTH || packet[0] >> 4 != 6 {
        return Ok(None);
    }
    let mut source_octets = [0u8; 16];
    source_octets.copy_from_slice(&packet[IPV6_SOURCE_OFFSET..IPV6_DESTINATION_OFFSET]);
    let mut destination_octets = [0u8; 16];
    destination_octets.copy_from_slice(&packet[IPV6_DESTINATION_OFFSET..IPV6_HEADER_LENGTH]);
    let source = Ipv6Addr::from(source_octets);
    let destination = Ipv6Addr::from(destination_octets);
    if source != expected_source
        || destination != expected_destination
        || packet[IPV6_NEXT_HEADER_OFFSET] != UDP_PROTOCOL_NUMBER
    {
        return Ok(None);
    }

    let payload_length = usize::from(u16::from_be_bytes([
        packet[IPV6_PAYLOAD_LENGTH_OFFSET],
        packet[IPV6_PAYLOAD_LENGTH_OFFSET + 1],
    ]));
    if payload_length != packet.len() - IPV6_HEADER_LENGTH || payload_length < UDP_HEADER_LENGTH {
        return Err(format!(
            "captured IPv6 packet length mismatch: packet={}, payload={payload_length}",
            packet.len()
        ));
    }
    let udp = &packet[IPV6_HEADER_LENGTH..];
    let source_port =
        u16::from_be_bytes([udp[UDP_SOURCE_PORT_OFFSET], udp[UDP_SOURCE_PORT_OFFSET + 1]]);
    let destination_port = u16::from_be_bytes([
        udp[UDP_DESTINATION_PORT_OFFSET],
        udp[UDP_DESTINATION_PORT_OFFSET + 1],
    ]);
    let udp_length = usize::from(u16::from_be_bytes([
        udp[UDP_LENGTH_OFFSET],
        udp[UDP_LENGTH_OFFSET + 1],
    ]));
    if source_port != expected_source_port
        || destination_port != expected_destination_port
        || udp_length != udp.len()
        || udp_length != UDP_HEADER_LENGTH + expected_payload.len()
        || &udp[UDP_HEADER_LENGTH..] != expected_payload
    {
        return Err(format!(
            "captured IPv6 UDP request mismatch: source_port={source_port}, destination_port={destination_port}, udp_length={udp_length}, packet_udp_length={}",
            udp.len()
        ));
    }
    Ok(Some(CapturedUdpRequest {
        source_port,
        destination_port,
    }))
}

#[allow(clippy::too_many_arguments)]
fn build_ipv4_tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let tcp_length = TCP_MIN_HEADER_LENGTH
        .checked_add(payload.len())
        .ok_or_else(|| "IPv4 TCP payload length overflow".to_owned())?;
    let total_length = IPV4_MIN_HEADER_LENGTH
        .checked_add(tcp_length)
        .ok_or_else(|| "IPv4 TCP packet length overflow".to_owned())?;
    let total_length_u16 = u16::try_from(total_length)
        .map_err(|_| "IPv4 TCP packet exceeds the 65535-byte limit".to_owned())?;
    let tcp_length_u16 = u16::try_from(tcp_length)
        .map_err(|_| "IPv4 TCP segment exceeds the 65535-byte limit".to_owned())?;

    let mut packet = vec![0u8; total_length];
    packet[0] = IPV4_VERSION_AND_MIN_HEADER_LENGTH;
    packet[2..4].copy_from_slice(&total_length_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&IPV4_PACKET_IDENTIFICATION.to_be_bytes());
    packet[8] = IPV4_DEFAULT_TTL;
    packet[9] = TCP_PROTOCOL_NUMBER;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());

    let tcp = &mut packet[IPV4_MIN_HEADER_LENGTH..];
    tcp[TCP_SOURCE_PORT_OFFSET..TCP_SOURCE_PORT_OFFSET + 2]
        .copy_from_slice(&source_port.to_be_bytes());
    tcp[TCP_DESTINATION_PORT_OFFSET..TCP_DESTINATION_PORT_OFFSET + 2]
        .copy_from_slice(&destination_port.to_be_bytes());
    tcp[TCP_SEQUENCE_OFFSET..TCP_SEQUENCE_OFFSET + 4]
        .copy_from_slice(&sequence_number.to_be_bytes());
    tcp[TCP_ACKNOWLEDGMENT_OFFSET..TCP_ACKNOWLEDGMENT_OFFSET + 4]
        .copy_from_slice(&acknowledgment_number.to_be_bytes());
    tcp[TCP_DATA_OFFSET] = 5 << 4;
    tcp[TCP_FLAGS_OFFSET] = flags;
    tcp[TCP_WINDOW_OFFSET..TCP_WINDOW_OFFSET + 2].copy_from_slice(&u16::MAX.to_be_bytes());
    tcp[TCP_MIN_HEADER_LENGTH..].copy_from_slice(payload);

    let ipv4_checksum = internet_checksum(&packet[..IPV4_MIN_HEADER_LENGTH]);
    packet[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

    let mut pseudo_header = Vec::with_capacity(12 + tcp_length);
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.push(0);
    pseudo_header.push(TCP_PROTOCOL_NUMBER);
    pseudo_header.extend_from_slice(&tcp_length_u16.to_be_bytes());
    pseudo_header.extend_from_slice(&packet[IPV4_MIN_HEADER_LENGTH..]);
    let tcp_checksum = internet_checksum(&pseudo_header);
    let checksum_offset = IPV4_MIN_HEADER_LENGTH + TCP_CHECKSUM_OFFSET;
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(
        &(if tcp_checksum == 0 {
            0xffff
        } else {
            tcp_checksum
        })
        .to_be_bytes(),
    );
    Ok(packet)
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
    packet[9] = UDP_PROTOCOL_NUMBER;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());

    packet[IPV4_MIN_HEADER_LENGTH + UDP_SOURCE_PORT_OFFSET
        ..IPV4_MIN_HEADER_LENGTH + UDP_SOURCE_PORT_OFFSET + 2]
        .copy_from_slice(&source_port.to_be_bytes());
    packet[IPV4_MIN_HEADER_LENGTH + UDP_DESTINATION_PORT_OFFSET
        ..IPV4_MIN_HEADER_LENGTH + UDP_DESTINATION_PORT_OFFSET + 2]
        .copy_from_slice(&destination_port.to_be_bytes());
    packet[IPV4_MIN_HEADER_LENGTH + UDP_LENGTH_OFFSET
        ..IPV4_MIN_HEADER_LENGTH + UDP_LENGTH_OFFSET + 2]
        .copy_from_slice(&udp_length_u16.to_be_bytes());
    packet[IPV4_MIN_HEADER_LENGTH + UDP_HEADER_LENGTH..].copy_from_slice(payload);

    let ipv4_checksum = internet_checksum(&packet[..IPV4_MIN_HEADER_LENGTH]);
    packet[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

    let mut pseudo_header = Vec::with_capacity(12 + udp_length);
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.push(0);
    pseudo_header.push(UDP_PROTOCOL_NUMBER);
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

fn build_ipv6_udp_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let udp_length = UDP_HEADER_LENGTH
        .checked_add(payload.len())
        .ok_or_else(|| "IPv6 UDP payload length overflow".to_owned())?;
    let udp_length_u16 = u16::try_from(udp_length)
        .map_err(|_| "IPv6 UDP packet exceeds the 65535-byte limit".to_owned())?;
    let total_length = IPV6_HEADER_LENGTH
        .checked_add(udp_length)
        .ok_or_else(|| "IPv6 packet length overflow".to_owned())?;
    if total_length > WINTUN_MAX_IP_PACKET_SIZE {
        return Err("IPv6 packet exceeds the Wintun packet-size limit".to_owned());
    }

    let mut packet = vec![0u8; total_length];
    packet[0] = IPV6_VERSION;
    packet[IPV6_PAYLOAD_LENGTH_OFFSET..IPV6_PAYLOAD_LENGTH_OFFSET + 2]
        .copy_from_slice(&udp_length_u16.to_be_bytes());
    packet[IPV6_NEXT_HEADER_OFFSET] = UDP_PROTOCOL_NUMBER;
    packet[IPV6_HOP_LIMIT_OFFSET] = IPV6_DEFAULT_HOP_LIMIT;
    packet[IPV6_SOURCE_OFFSET..IPV6_DESTINATION_OFFSET].copy_from_slice(&source.octets());
    packet[IPV6_DESTINATION_OFFSET..IPV6_HEADER_LENGTH].copy_from_slice(&destination.octets());

    packet[IPV6_HEADER_LENGTH + UDP_SOURCE_PORT_OFFSET
        ..IPV6_HEADER_LENGTH + UDP_SOURCE_PORT_OFFSET + 2]
        .copy_from_slice(&source_port.to_be_bytes());
    packet[IPV6_HEADER_LENGTH + UDP_DESTINATION_PORT_OFFSET
        ..IPV6_HEADER_LENGTH + UDP_DESTINATION_PORT_OFFSET + 2]
        .copy_from_slice(&destination_port.to_be_bytes());
    packet[IPV6_HEADER_LENGTH + UDP_LENGTH_OFFSET..IPV6_HEADER_LENGTH + UDP_LENGTH_OFFSET + 2]
        .copy_from_slice(&udp_length_u16.to_be_bytes());
    packet[IPV6_HEADER_LENGTH + UDP_HEADER_LENGTH..].copy_from_slice(payload);

    let mut pseudo_header = Vec::with_capacity(40 + udp_length);
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.extend_from_slice(&(udp_length as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, UDP_PROTOCOL_NUMBER]);
    pseudo_header.extend_from_slice(&packet[IPV6_HEADER_LENGTH..]);
    let udp_checksum = internet_checksum(&pseudo_header);
    let checksum_offset = IPV6_HEADER_LENGTH + UDP_CHECKSUM_OFFSET;
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(
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

struct CrashCaptureEvidence {
    capture_interface: WindowsPacketInterfaceIdentity,
    route_row: MIB_IPFORWARD_ROW2,
    address_row: MIB_UNICASTIPADDRESS_ROW,
}

struct IndependentRouteEvidence {
    route_row: MIB_IPFORWARD_ROW2,
    address_row: MIB_UNICASTIPADDRESS_ROW,
}

struct IndependentRouteChild {
    child: Option<Child>,
}

impl IndependentRouteChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("child handle is present").id()
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child handle is present")
    }

    fn require_running(&mut self, context: &str) -> Result<(), String> {
        let Some(child) = self.child.as_mut() else {
            return Err(format!(
                "independent route child has no retained handle {context}"
            ));
        };
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("inspect independent route child {context}: {error}"))?
        {
            self.child = None;
            return Err(format!(
                "independent route child exited {context}: {status}"
            ));
        }
        Ok(())
    }

    fn release_and_wait(&mut self, release_path: &Path) -> Result<ExitStatus, String> {
        self.require_running("before explicit release")?;
        if let Err(release_error) = write_independent_ready_marker(release_path, "release\n") {
            let fallback = self.terminate_and_wait("after release-marker failure");
            return Err(format!(
                "publish independent child release: {release_error}; exact-handle fallback: {fallback:?}"
            ));
        }
        match self.wait_for_exit(INDEPENDENT_CHILD_EXIT_TIMEOUT) {
            Ok(status) => Ok(status),
            Err(wait_error) => {
                let fallback = self.terminate_and_wait("after graceful-release timeout");
                Err(format!("{wait_error}; exact-handle fallback: {fallback:?}"))
            }
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> Result<ExitStatus, String> {
        let pid = self.id();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self
                .child_mut()
                .try_wait()
                .map_err(|error| format!("inspect released independent child {pid}: {error}"))?
            {
                self.child = None;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "released independent child {pid} did not exit within {} ms",
                    timeout.as_millis()
                ));
            }
            thread::sleep(INDEPENDENT_PROBE_INTERVAL);
        }
    }

    fn terminate_and_wait(&mut self, context: &str) -> Result<ExitStatus, String> {
        self.require_running(context)?;
        self.child_mut()
            .kill()
            .map_err(|error| format!("terminate exact independent child {context}: {error}"))?;
        self.wait_for_exit(CRASH_CHILD_TERMINATION_TIMEOUT)
    }
}

impl Drop for IndependentRouteChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let _ = thread::Builder::new()
            .name("wintun-independent-route-child-reaper".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
    }
}

struct OwnedIndependentRouteFixtureDirectory {
    directory: PathBuf,
    ready: PathBuf,
    release: PathBuf,
}

impl OwnedIndependentRouteFixtureDirectory {
    fn create() -> Result<Self, String> {
        let base = std::env::var_os("RUNNER_TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_owned());
        let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".to_owned());
        let directory = base.join(format!(
            "slipstream-wintun-independent-route-{run_id}-{attempt}-{}",
            std::process::id()
        ));
        fs::create_dir(&directory)
            .map_err(|error| format!("create {}: {error}", directory.display()))?;
        let ready = directory.join("ready.txt");
        let release = directory.join("release.txt");
        Ok(Self {
            directory,
            ready,
            release,
        })
    }

    fn ready_path(&self) -> &Path {
        &self.ready
    }

    fn release_path(&self) -> &Path {
        &self.release
    }
}

impl Drop for OwnedIndependentRouteFixtureDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.ready);
        let _ = fs::remove_file(self.ready.with_extension("pending"));
        let _ = fs::remove_file(&self.release);
        let _ = fs::remove_file(self.release.with_extension("pending"));
        let _ = fs::remove_dir(&self.directory);
    }
}

struct ExactCrashChild {
    child: Option<Child>,
}

impl ExactCrashChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("child handle is present").id()
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child handle is present")
    }

    fn terminate_and_wait(&mut self) -> Result<ExitStatus, String> {
        if let Some(status) = self
            .child_mut()
            .try_wait()
            .map_err(|error| format!("inspect crash-route child before termination: {error}"))?
        {
            self.child = None;
            return Err(format!(
                "crash-route child exited before exact termination: {status}"
            ));
        }
        self.child_mut()
            .kill()
            .map_err(|error| format!("terminate exact crash-route child handle: {error}"))?;
        self.wait_for_exit(CRASH_CHILD_TERMINATION_TIMEOUT)
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> Result<ExitStatus, String> {
        let pid = self.id();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self
                .child_mut()
                .try_wait()
                .map_err(|error| format!("inspect terminated crash-route child {pid}: {error}"))?
            {
                self.child = None;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "terminated crash-route child {pid} did not exit within {} ms",
                    timeout.as_millis()
                ));
            }
            thread::sleep(CRASH_PROBE_INTERVAL);
        }
    }
}

impl Drop for ExactCrashChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let _ = thread::Builder::new()
            .name("wintun-crash-route-child-reaper".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
    }
}

struct OwnedCrashFixtureDirectory {
    directory: PathBuf,
    marker: PathBuf,
}

impl OwnedCrashFixtureDirectory {
    fn create() -> Result<Self, String> {
        let base = std::env::var_os("RUNNER_TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_owned());
        let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".to_owned());
        let directory = base.join(format!(
            "slipstream-wintun-crash-route-{run_id}-{attempt}-{}",
            std::process::id()
        ));
        fs::create_dir(&directory)
            .map_err(|error| format!("create {}: {error}", directory.display()))?;
        let marker = directory.join("ready.txt");
        Ok(Self { directory, marker })
    }

    fn marker_path(&self) -> &Path {
        &self.marker
    }
}

impl Drop for OwnedCrashFixtureDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.marker);
        let _ = fs::remove_dir(&self.directory);
    }
}

fn wait_for_crash_child_ready(
    child: &mut ExactCrashChild,
    marker: &Path,
    expected: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + CRASH_CHILD_READY_TIMEOUT;
    loop {
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .map_err(|error| format!("inspect crash-route child readiness: {error}"))?
        {
            return Err(format!(
                "crash-route child exited before readiness: {status}"
            ));
        }
        match fs::read_to_string(marker) {
            Ok(contents) if contents == expected => return Ok(()),
            Ok(contents) => {
                return Err(format!(
                    "crash-route child published unexpected marker {contents:?}"
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound && Instant::now() < deadline => {
                thread::sleep(CRASH_PROBE_INTERVAL);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(format!(
                    "crash-route child did not publish readiness within {} ms",
                    CRASH_CHILD_READY_TIMEOUT.as_millis()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "read crash-route child marker {}: {error}",
                    marker.display()
                ));
            }
        }
    }
}

fn write_crash_ready_marker(path: &Path, contents: &str) -> Result<(), String> {
    let temporary = path.with_extension("pending");
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        file.write_all(contents.as_bytes())
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", temporary.display()))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "publish {} as {}: {error}",
                temporary.display(),
                path.display()
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn wait_for_independent_route_child_ready(
    child: &mut IndependentRouteChild,
    marker: &Path,
    expected: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + INDEPENDENT_CHILD_READY_TIMEOUT;
    loop {
        child.require_running("before readiness")?;
        match fs::read_to_string(marker) {
            Ok(contents) if contents == expected => return Ok(()),
            Ok(contents) => {
                return Err(format!(
                    "independent route child published unexpected marker {contents:?}"
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound && Instant::now() < deadline => {
                thread::sleep(INDEPENDENT_PROBE_INTERVAL);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(format!(
                    "independent route child did not publish readiness within {} ms",
                    INDEPENDENT_CHILD_READY_TIMEOUT.as_millis()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "read independent route child marker {}: {error}",
                    marker.display()
                ));
            }
        }
    }
}

fn write_independent_ready_marker(path: &Path, contents: &str) -> Result<(), String> {
    let temporary = path.with_extension("pending");
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        file.write_all(contents.as_bytes())
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", temporary.display()))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "publish {} as {}: {error}",
                temporary.display(),
                path.display()
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn wait_for_independent_release(
    release_path: &Path,
    admission: &WindowsCollectedPacketAdapterAdmission,
    api: &LoadedWintun,
    adapter: &OwnedWintunAdapter<'_>,
    address: &OwnedUnicastAddress,
    route: &OwnedFixtureBaselineRoute,
) -> Result<(), String> {
    let deadline = Instant::now() + INDEPENDENT_CHILD_FAILSAFE_LIFETIME;
    loop {
        match fs::read_to_string(release_path) {
            Ok(contents) if contents == "release\n" => return Ok(()),
            Ok(contents) => {
                return Err(format!(
                    "independent route child received unexpected release marker {contents:?}"
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound && Instant::now() < deadline => {
                std::hint::black_box((admission, api, adapter, address, route));
                thread::sleep(INDEPENDENT_PROBE_INTERVAL);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(format!(
                    "independent route child exceeded its {} ms failsafe lifetime",
                    INDEPENDENT_CHILD_FAILSAFE_LIFETIME.as_millis()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "read independent route release marker {}: {error}",
                    release_path.display()
                ));
            }
        }
    }
}

fn require_independent_route_resources_unchanged(
    api: &LoadedWintun,
    adapter_name: &[u16],
    expected_interface: WindowsPacketInterfaceIdentity,
    route_row: MIB_IPFORWARD_ROW2,
    address_row: MIB_UNICASTIPADDRESS_ROW,
) -> Result<(), String> {
    let observed_interface = api
        .adapter_interface_identity(adapter_name)?
        .ok_or_else(|| "independent route-owner adapter disappeared".to_owned())?;
    if observed_interface != expected_interface {
        return Err("independent route-owner adapter identity changed".to_owned());
    }
    let observed_route = lookup_fixture_route(route_row)?
        .ok_or_else(|| "independent route-owner /24 disappeared".to_owned())?;
    if !same_independent_route_state(observed_route, route_row) {
        return Err("independent route-owner /24 attributes changed".to_owned());
    }
    let observed_address = lookup_unicast_address(address_row)?
        .ok_or_else(|| "independent route-owner address disappeared".to_owned())?;
    if !same_independent_address_state(observed_address, address_row) {
        return Err("independent route-owner address attributes changed".to_owned());
    }
    Ok(())
}

fn same_independent_route_state(
    observed: MIB_IPFORWARD_ROW2,
    expected: MIB_IPFORWARD_ROW2,
) -> bool {
    same_fixture_route_key(observed, expected)
        && observed.SitePrefixLength == expected.SitePrefixLength
        && observed.Metric == expected.Metric
        && observed.Protocol == expected.Protocol
        && observed.Loopback == expected.Loopback
        && observed.AutoconfigureAddress == expected.AutoconfigureAddress
        && observed.Publish == expected.Publish
        && observed.Immortal == expected.Immortal
        && observed.Origin == expected.Origin
}

fn same_independent_address_state(
    observed: MIB_UNICASTIPADDRESS_ROW,
    expected: MIB_UNICASTIPADDRESS_ROW,
) -> bool {
    same_unicast_address_key(observed, expected)
        && expected.DadState == IpDadStatePreferred
        && !expected.SkipAsSource
        && observed.PrefixOrigin == expected.PrefixOrigin
        && observed.SuffixOrigin == expected.SuffixOrigin
        && observed.OnLinkPrefixLength == expected.OnLinkPrefixLength
        && observed.SkipAsSource == expected.SkipAsSource
        && observed.DadState == expected.DadState
        && (unsafe { observed.ScopeId.Anonymous.Value })
            == (unsafe { expected.ScopeId.Anonymous.Value })
}

fn require_independent_route_selected(
    expected_interface: WindowsPacketInterfaceIdentity,
) -> Result<(), String> {
    let selected = observe_windows_packet_route(IpAddr::V4(IPV4_INDEPENDENT_ROUTE_DESTINATION))
        .map_err(|error| format!("observe independent route selection: {error}"))?;
    if selected.egress_interface() != expected_interface
        || selected.source_address() != IpAddr::V4(IPV4_INDEPENDENT_ROUTE_SOURCE)
        || selected.route_prefix() != "1.0.0.0/24"
    {
        return Err(format!(
            "independent route selection changed: interface={:?}, source={}, prefix={}",
            selected.egress_interface(),
            selected.source_address(),
            selected.route_prefix()
        ));
    }
    Ok(())
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

    fn adapter_interface_identity(
        &self,
        name: &[u16],
    ) -> Result<Option<WindowsPacketInterfaceIdentity>, String> {
        let adapter = unsafe { (self.open_adapter)(name.as_ptr()) };
        if adapter.is_null() {
            let error = last_error();
            return if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND) {
                Ok(None)
            } else {
                Err(format!(
                    "adapter identity could not be proven: WintunOpenAdapter failed with {error}"
                ))
            };
        }
        let identity_result = (|| {
            let mut luid = NET_LUID_LH::default();
            unsafe {
                (self.get_adapter_luid)(adapter, &mut luid);
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
            Ok(WindowsPacketInterfaceIdentity {
                luid: luid_value,
                index,
            })
        })();
        unsafe {
            (self.close_adapter)(adapter);
        }
        identity_result.map(Some)
    }

    fn adapter_presence(&self, name: &[u16]) -> Result<bool, String> {
        self.adapter_interface_identity(name)
            .map(|identity| identity.is_some())
    }

    fn require_adapter_absent(&self, name: &[u16], phase: &str) -> Result<(), String> {
        if self.adapter_presence(name)? {
            return Err(format!("test adapter still exists {phase}"));
        }
        Ok(())
    }

    fn wait_for_adapter_absent_until(&self, name: &[u16], deadline: Instant) -> Result<(), String> {
        loop {
            if !self.adapter_presence(name)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(
                    "crash-route adapter remained after bounded child termination".to_owned(),
                );
            }
            thread::sleep(CRASH_PROBE_INTERVAL);
        }
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
    ) -> Result<CapturedUdpRequest, String> {
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

    #[allow(clippy::too_many_arguments)]
    fn receive_matching_ipv4_tcp_segment(
        &self,
        expected_source: Ipv4Addr,
        expected_destination: Ipv4Addr,
        expected_source_port: Option<u16>,
        expected_destination_port: u16,
        expected_payload: &[u8],
        required_flags: u8,
        forbidden_flags: u8,
        deadline: Instant,
    ) -> Result<CapturedTcpSegment, String> {
        loop {
            let packet = self.receive_packet_until(deadline)?;
            if let Some(segment) = parse_ipv4_tcp_segment(
                &packet,
                expected_source,
                expected_destination,
                expected_source_port,
                expected_destination_port,
                expected_payload,
                required_flags,
                forbidden_flags,
            )? {
                return Ok(segment);
            }
        }
    }

    fn receive_matching_ipv6_udp_request(
        &self,
        expected_source: Ipv6Addr,
        expected_destination: Ipv6Addr,
        expected_source_port: u16,
        expected_destination_port: u16,
        expected_payload: &[u8],
        deadline: Instant,
    ) -> Result<CapturedUdpRequest, String> {
        loop {
            let packet = self.receive_packet_until(deadline)?;
            if let Some(request) = parse_ipv6_udp_request(
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
        loop {
            if Instant::now() >= deadline {
                return Err("Wintun packet receive exceeded its bounded deadline".to_owned());
            }
            if let Some(packet) = self.try_receive_packet()? {
                return Ok(packet);
            }
            if Instant::now() >= deadline {
                return Err("Wintun packet receive exceeded its bounded deadline".to_owned());
            }
            thread::sleep(PACKET_DELIVERY_PROBE_INTERVAL);
        }
    }

    fn try_receive_packet(&self) -> Result<Option<Vec<u8>>, String> {
        if self.session.is_null() {
            return Err("Wintun packet receive requires an active owned session".to_owned());
        }
        let mut packet_size = 0u32;
        let packet = unsafe { (self.api.receive_packet)(self.session, &mut packet_size) };
        if packet.is_null() {
            let error = last_error();
            return if error == ERROR_NO_MORE_ITEMS {
                Ok(None)
            } else {
                Err(format!("WintunReceivePacket failed with {error}"))
            };
        }
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
        Ok(Some(packet_copy))
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

fn fixture_route_row(
    interface: WindowsPacketInterfaceIdentity,
    network: IpAddr,
    prefix_length: u8,
    metric: u32,
) -> MIB_IPFORWARD_ROW2 {
    let unspecified = match network {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe {
        InitializeIpForwardEntry(&mut row);
    }
    row.InterfaceLuid = NET_LUID_LH {
        Value: interface.luid,
    };
    row.InterfaceIndex = interface.index;
    row.DestinationPrefix.Prefix = sockaddr_from_ip(network);
    row.DestinationPrefix.PrefixLength = prefix_length;
    row.NextHop = sockaddr_from_ip(unspecified);
    row.SitePrefixLength = prefix_length;
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row.Immortal = false;
    row
}

struct OwnedFixtureBaselineRoute {
    row: MIB_IPFORWARD_ROW2,
    present: bool,
}

impl OwnedFixtureBaselineRoute {
    fn create(
        interface: WindowsPacketInterfaceIdentity,
        network: IpAddr,
        prefix_length: u8,
    ) -> Result<Self, String> {
        let admitted_fixture = matches!(
            (network, prefix_length),
            (IpAddr::V4(address), IPV4_BASELINE_PREFIX_LENGTH)
                if address == IPV4_BASELINE_NETWORK
        ) || matches!(
            (network, prefix_length),
            (IpAddr::V6(address), IPV6_BASELINE_PREFIX_LENGTH)
                if address == IPV6_BASELINE_NETWORK
        );
        if !admitted_fixture {
            return Err(
                "fixture baseline route must remain the fixed IPv4 /24 or IPv6 /64".to_owned(),
            );
        }
        let row = fixture_route_row(interface, network, prefix_length, 5);

        if lookup_fixture_route(row)?.is_some() {
            return Err("fixture baseline route already exists before creation".to_owned());
        }
        let result = unsafe { CreateIpForwardEntry2(&row) };
        if result != 0 {
            return Err(format!(
                "CreateIpForwardEntry2 baseline failed with {result}"
            ));
        }
        let mut owned = Self { row, present: true };
        let verification_error = match lookup_fixture_route(row) {
            Ok(Some(observed)) if same_fixture_route_key(observed, row) => {
                return Ok(owned);
            }
            Ok(Some(_)) => "created route identity changed during verification".to_owned(),
            Ok(None) => "created route was absent during verification".to_owned(),
            Err(error) => format!("created route lookup failed: {error}"),
        };
        let cleanup_result = owned.remove_and_verify();
        Err(format!(
            "fixture baseline route verification failed: {verification_error}; cleanup={cleanup_result:?}"
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
            if lookup_fixture_route(self.row)?.is_none() {
                self.present = false;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("fixture baseline route remained after bounded deletion".to_owned());
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

fn lookup_fixture_route(row: MIB_IPFORWARD_ROW2) -> Result<Option<MIB_IPFORWARD_ROW2>, String> {
    let mut observed = row;
    let result = unsafe { GetIpForwardEntry2(&mut observed) };
    match result {
        0 => Ok(Some(observed)),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Ok(None),
        error => Err(format!(
            "GetIpForwardEntry2 fixture route failed with {error}"
        )),
    }
}

fn same_fixture_route_key(left: MIB_IPFORWARD_ROW2, right: MIB_IPFORWARD_ROW2) -> bool {
    (unsafe { left.InterfaceLuid.Value }) == (unsafe { right.InterfaceLuid.Value })
        && left.InterfaceIndex == right.InterfaceIndex
        && left.DestinationPrefix.PrefixLength == right.DestinationPrefix.PrefixLength
        && ip_from_sockaddr(left.DestinationPrefix.Prefix)
            == ip_from_sockaddr(right.DestinationPrefix.Prefix)
        && ip_from_sockaddr(left.NextHop) == ip_from_sockaddr(right.NextHop)
}

fn wait_for_fixture_route_absent_until(
    row: MIB_IPFORWARD_ROW2,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        if lookup_fixture_route(row)?.is_none() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                "active crash-route /32 remained after bounded child termination".to_owned(),
            );
        }
        thread::sleep(CRASH_PROBE_INTERVAL);
    }
}

fn fixture_unicast_address_row(
    interface: WindowsPacketInterfaceIdentity,
    address: IpAddr,
    prefix_length: u8,
) -> MIB_UNICASTIPADDRESS_ROW {
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
    row
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
        let row = fixture_unicast_address_row(interface, address, prefix_length);

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

fn wait_for_unicast_address_absent_until(
    row: MIB_UNICASTIPADDRESS_ROW,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        if lookup_unicast_address(row)?.is_none() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                "active crash-route address remained after bounded child termination".to_owned(),
            );
        }
        thread::sleep(CRASH_PROBE_INTERVAL);
    }
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

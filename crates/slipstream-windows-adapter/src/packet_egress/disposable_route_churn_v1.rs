//! Disposable native qualification for Windows route-change invalidation.
//!
//! This version is feature-gated and test-only. It creates two exact
//! test-owned routes on one disposable Wintun interface, feeds the observed
//! route-table changes into the sealed transition issuer, and proves exact
//! cleanup plus baseline-route recovery.

use super::{
    observe_windows_packet_route, WindowsOwnedRouteTransitionErrorCode,
    WindowsOwnedRouteTransitionIssuer, WindowsPacketInterfaceIdentity, WindowsRouteChangeKindV1,
    WindowsRouteChangeObserverV1,
};
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, GetIpForwardEntry2, InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_INET,
};

pub const WINDOWS_DISPOSABLE_ROUTE_CHURN_QUALIFICATION_VERSION: u32 = 1;
pub const WINDOWS_DISPOSABLE_ROUTE_CHURN_NETWORK: Ipv4Addr = Ipv4Addr::new(198, 19, 255, 254);
const HOST_PREFIX_LENGTH: u8 = 32;
const ROUTE_EVENT_TIMEOUT: Duration = Duration::from_secs(5);
const ROUTE_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);
const ROUTE_PROBE_INTERVAL: Duration = Duration::from_millis(25);
const DISPOSABLE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_DISPOSABLE_CI";
const EXACT_ROUTE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_EXACT_ROUTE_CI";
const ROUTE_CHURN_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_ROUTE_CHURN_CI";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsDisposableRouteChurnErrorCode {
    GateClosed,
    ObserverSubscribeFailed,
    ObserverWaitFailed,
    ObserverCloseFailed,
    BaselineObservationFailed,
    TransitionStageFailed,
    RouteCreateFailed,
    RouteLookupFailed,
    RouteDeleteFailed,
    TransitionAttestationFailed,
    TransitionEpochFailed,
    ActivationRemainedCurrent,
    BaselineRouteNotRestored,
    CleanupFailed,
}

impl WindowsDisposableRouteChurnErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GateClosed => "gate_closed",
            Self::ObserverSubscribeFailed => "observer_subscribe_failed",
            Self::ObserverWaitFailed => "observer_wait_failed",
            Self::ObserverCloseFailed => "observer_close_failed",
            Self::BaselineObservationFailed => "baseline_observation_failed",
            Self::TransitionStageFailed => "transition_stage_failed",
            Self::RouteCreateFailed => "route_create_failed",
            Self::RouteLookupFailed => "route_lookup_failed",
            Self::RouteDeleteFailed => "route_delete_failed",
            Self::TransitionAttestationFailed => "transition_attestation_failed",
            Self::TransitionEpochFailed => "transition_epoch_failed",
            Self::ActivationRemainedCurrent => "activation_remained_current",
            Self::BaselineRouteNotRestored => "baseline_route_not_restored",
            Self::CleanupFailed => "cleanup_failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsDisposableRouteChurnError {
    code: WindowsDisposableRouteChurnErrorCode,
    detail: String,
}

impl WindowsDisposableRouteChurnError {
    fn new(code: WindowsDisposableRouteChurnErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub const fn code(&self) -> WindowsDisposableRouteChurnErrorCode {
        self.code
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for WindowsDisposableRouteChurnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl Error for WindowsDisposableRouteChurnError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsDisposableRouteChurnQualification {
    destination: IpAddr,
    capture_interface: WindowsPacketInterfaceIdentity,
    exact_route_added_sequence: u64,
    churn_route_added_sequence: u64,
    churn_route_deleted_sequence: u64,
    exact_route_deleted_sequence: u64,
    route_epoch_after_churn: u64,
    route_epoch_after_cleanup: u64,
}

impl WindowsDisposableRouteChurnQualification {
    pub const fn destination(&self) -> IpAddr {
        self.destination
    }

    pub const fn capture_interface(&self) -> WindowsPacketInterfaceIdentity {
        self.capture_interface
    }

    pub const fn exact_route_added_sequence(&self) -> u64 {
        self.exact_route_added_sequence
    }

    pub const fn churn_route_added_sequence(&self) -> u64 {
        self.churn_route_added_sequence
    }

    pub const fn churn_route_deleted_sequence(&self) -> u64 {
        self.churn_route_deleted_sequence
    }

    pub const fn exact_route_deleted_sequence(&self) -> u64 {
        self.exact_route_deleted_sequence
    }

    pub const fn route_epoch_after_churn(&self) -> u64 {
        self.route_epoch_after_churn
    }

    pub const fn route_epoch_after_cleanup(&self) -> u64 {
        self.route_epoch_after_cleanup
    }
}

pub fn qualify_disposable_windows_route_churn(
    issuer: &mut WindowsOwnedRouteTransitionIssuer,
    destination: IpAddr,
) -> Result<WindowsDisposableRouteChurnQualification, WindowsDisposableRouteChurnError> {
    use WindowsDisposableRouteChurnErrorCode as Code;

    require_gate()?;
    let baseline = observe_windows_packet_route(destination).map_err(|error| {
        WindowsDisposableRouteChurnError::new(Code::BaselineObservationFailed, error.to_string())
    })?;
    let baseline_interface = baseline.egress_interface();
    let baseline_source = baseline.source_address();
    let baseline_prefix = baseline.route_prefix().to_owned();
    let baseline_loopback = baseline.route_is_loopback();
    let capture_interface = issuer.capture_interface();
    let mut observer = WindowsRouteChangeObserverV1::subscribe().map_err(|error| {
        WindowsDisposableRouteChurnError::new(Code::ObserverSubscribeFailed, error.to_string())
    })?;
    let mut last_sequence = observer.checkpoint().map_err(|error| {
        WindowsDisposableRouteChurnError::new(Code::ObserverWaitFailed, error.to_string())
    })?;
    let mut exact_route = None;
    let mut churn_route = None;
    let mut exact_route_added_sequence = 0;
    let mut churn_route_added_sequence = 0;
    let mut churn_route_deleted_sequence = 0;
    let mut exact_route_deleted_sequence = 0;
    let mut route_epoch_after_churn = 0;
    let mut route_epoch_after_cleanup = 0;

    let body_result = (|| {
        let intent = issuer
            .begin_exact_host_activation(baseline)
            .map_err(|error| {
                WindowsDisposableRouteChurnError::new(
                    Code::TransitionStageFailed,
                    error.to_string(),
                )
            })?;
        let exact_row = qualification_route_row(destination, capture_interface, 0)?;
        exact_route = Some(OwnedQualificationRoute::create(exact_row)?);
        let exact_added = observer
            .wait_for_route_after(
                last_sequence,
                WindowsRouteChangeKindV1::Added,
                capture_interface,
                destination,
                host_prefix_length(destination),
                ROUTE_EVENT_TIMEOUT,
            )
            .map_err(|error| {
                WindowsDisposableRouteChurnError::new(
                    Code::ObserverWaitFailed,
                    format!("exact route add: {error}"),
                )
            })?;
        exact_route_added_sequence = exact_added.sequence();
        last_sequence = exact_route_added_sequence;

        let post_activation = observe_windows_packet_route(destination).map_err(|error| {
            WindowsDisposableRouteChurnError::new(
                Code::TransitionAttestationFailed,
                error.to_string(),
            )
        })?;
        let activation = issuer
            .attest_exact_host_route_created(intent, post_activation)
            .map_err(|error| {
                WindowsDisposableRouteChurnError::new(
                    Code::TransitionAttestationFailed,
                    error.to_string(),
                )
            })?;
        issuer
            .require_current_activation(&activation)
            .map_err(|error| {
                WindowsDisposableRouteChurnError::new(
                    Code::TransitionAttestationFailed,
                    error.to_string(),
                )
            })?;

        let churn_network = IpAddr::V4(WINDOWS_DISPOSABLE_ROUTE_CHURN_NETWORK);
        let churn_row = qualification_route_row(churn_network, capture_interface, 1)?;
        churn_route = Some(OwnedQualificationRoute::create(churn_row)?);
        let churn_added = observer
            .wait_for_route_after(
                last_sequence,
                WindowsRouteChangeKindV1::Added,
                capture_interface,
                churn_network,
                HOST_PREFIX_LENGTH,
                ROUTE_EVENT_TIMEOUT,
            )
            .map_err(|error| {
                WindowsDisposableRouteChurnError::new(
                    Code::ObserverWaitFailed,
                    format!("churn route add: {error}"),
                )
            })?;
        churn_route_added_sequence = churn_added.sequence();
        last_sequence = churn_route_added_sequence;
        route_epoch_after_churn = issuer.record_route_change().map_err(|error| {
            WindowsDisposableRouteChurnError::new(Code::TransitionEpochFailed, error.to_string())
        })?;
        match issuer.require_current_activation(&activation) {
            Err(error)
                if error.code() == WindowsOwnedRouteTransitionErrorCode::ActivationNotCurrent => {}
            Err(error) => {
                return Err(WindowsDisposableRouteChurnError::new(
                    Code::ActivationRemainedCurrent,
                    format!("unexpected activation error: {error}"),
                ));
            }
            Ok(_) => {
                return Err(WindowsDisposableRouteChurnError::new(
                    Code::ActivationRemainedCurrent,
                    "active token survived a later native route change",
                ));
            }
        }
        Ok(())
    })();

    let mut cleanup_errors = Vec::new();
    if body_result.is_err() {
        match issuer.record_route_change() {
            Ok(_) => {}
            Err(error) => cleanup_errors.push(format!(
                "invalidate transition after qualification failure: {error}"
            )),
        }
    }
    if let Some(route) = churn_route.as_mut() {
        if let Err(error) = route.remove_and_verify() {
            cleanup_errors.push(format!("churn route removal: {error}"));
        } else {
            let churn_network = IpAddr::V4(WINDOWS_DISPOSABLE_ROUTE_CHURN_NETWORK);
            match observer.wait_for_route_after(
                last_sequence,
                WindowsRouteChangeKindV1::Deleted,
                capture_interface,
                churn_network,
                HOST_PREFIX_LENGTH,
                ROUTE_EVENT_TIMEOUT,
            ) {
                Ok(event) => {
                    churn_route_deleted_sequence = event.sequence();
                    last_sequence = churn_route_deleted_sequence;
                    match issuer.record_route_change() {
                        Ok(epoch) => route_epoch_after_cleanup = epoch,
                        Err(error) => cleanup_errors
                            .push(format!("record churn-route deletion epoch: {error}")),
                    }
                }
                Err(error) => cleanup_errors.push(format!("observe churn-route deletion: {error}")),
            }
        }
    }
    if let Some(route) = exact_route.as_mut() {
        if let Err(error) = route.remove_and_verify() {
            cleanup_errors.push(format!("exact route removal: {error}"));
        } else {
            match observer.wait_for_route_after(
                last_sequence,
                WindowsRouteChangeKindV1::Deleted,
                capture_interface,
                destination,
                host_prefix_length(destination),
                ROUTE_EVENT_TIMEOUT,
            ) {
                Ok(event) => {
                    exact_route_deleted_sequence = event.sequence();
                    match issuer.record_route_change() {
                        Ok(epoch) => route_epoch_after_cleanup = epoch,
                        Err(error) => cleanup_errors
                            .push(format!("record exact-route deletion epoch: {error}")),
                    }
                }
                Err(error) => cleanup_errors.push(format!("observe exact-route deletion: {error}")),
            }
        }
    }

    match observe_windows_packet_route(destination) {
        Ok(recovered)
            if recovered.egress_interface() == baseline_interface
                && recovered.source_address() == baseline_source
                && recovered.route_prefix() == baseline_prefix
                && recovered.route_is_loopback() == baseline_loopback => {}
        Ok(_) => cleanup_errors.push("baseline route identity changed after cleanup".to_owned()),
        Err(error) => cleanup_errors.push(format!("baseline recovery observation: {error}")),
    }
    if let Err(error) = observer.close() {
        cleanup_errors.push(format!("observer cancellation: {error}"));
    }

    if let Err(error) = body_result {
        if cleanup_errors.is_empty() {
            return Err(error);
        }
        return Err(WindowsDisposableRouteChurnError::new(
            Code::CleanupFailed,
            format!("{error}; cleanup: {}", cleanup_errors.join("; ")),
        ));
    }
    if !cleanup_errors.is_empty() {
        return Err(WindowsDisposableRouteChurnError::new(
            Code::CleanupFailed,
            cleanup_errors.join("; "),
        ));
    }
    if route_epoch_after_cleanup == 0 {
        return Err(WindowsDisposableRouteChurnError::new(
            Code::TransitionEpochFailed,
            "cleanup route epoch was not recorded",
        ));
    }

    Ok(WindowsDisposableRouteChurnQualification {
        destination,
        capture_interface,
        exact_route_added_sequence,
        churn_route_added_sequence,
        churn_route_deleted_sequence,
        exact_route_deleted_sequence,
        route_epoch_after_churn,
        route_epoch_after_cleanup,
    })
}

fn require_gate() -> Result<(), WindowsDisposableRouteChurnError> {
    if !windows_disposable_route_churn_gate_is_open() {
        return Err(WindowsDisposableRouteChurnError::new(
            WindowsDisposableRouteChurnErrorCode::GateClosed,
            "disposable Windows route-churn gate is closed",
        ));
    }
    Ok(())
}

pub fn windows_disposable_route_churn_gate_is_open() -> bool {
    std::env::var(DISPOSABLE_CI_ENV).as_deref() == Ok("1")
        && std::env::var(EXACT_ROUTE_CI_ENV).as_deref() == Ok("1")
        && std::env::var(ROUTE_CHURN_CI_ENV).as_deref() == Ok("1")
}

fn host_prefix_length(destination: IpAddr) -> u8 {
    match destination {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn qualification_route_row(
    network: IpAddr,
    interface: WindowsPacketInterfaceIdentity,
    metric: u32,
) -> Result<MIB_IPFORWARD_ROW2, WindowsDisposableRouteChurnError> {
    use WindowsDisposableRouteChurnErrorCode as Code;

    let IpAddr::V4(network) = network else {
        return Err(WindowsDisposableRouteChurnError::new(
            Code::RouteCreateFailed,
            "route-churn v1 admits only IPv4 qualification routes",
        ));
    };
    if interface.luid == 0 || interface.index == 0 {
        return Err(WindowsDisposableRouteChurnError::new(
            Code::RouteCreateFailed,
            "capture interface identity is invalid",
        ));
    }
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe {
        InitializeIpForwardEntry(&mut row);
    }
    row.InterfaceLuid = NET_LUID_LH {
        Value: interface.luid,
    };
    row.InterfaceIndex = interface.index;
    row.DestinationPrefix.Prefix = sockaddr_from_ipv4(network);
    row.DestinationPrefix.PrefixLength = HOST_PREFIX_LENGTH;
    row.NextHop = sockaddr_from_ipv4(Ipv4Addr::UNSPECIFIED);
    row.SitePrefixLength = HOST_PREFIX_LENGTH;
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row.Immortal = false;
    Ok(row)
}

fn sockaddr_from_ipv4(address: Ipv4Addr) -> SOCKADDR_INET {
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

struct OwnedQualificationRoute {
    row: MIB_IPFORWARD_ROW2,
    present: bool,
}

impl OwnedQualificationRoute {
    fn create(row: MIB_IPFORWARD_ROW2) -> Result<Self, WindowsDisposableRouteChurnError> {
        use WindowsDisposableRouteChurnErrorCode as Code;

        if lookup_route(row)?.is_some() {
            return Err(WindowsDisposableRouteChurnError::new(
                Code::RouteCreateFailed,
                "qualification route already exists",
            ));
        }
        let result = unsafe { CreateIpForwardEntry2(&row) };
        if result != 0 {
            return Err(WindowsDisposableRouteChurnError::new(
                Code::RouteCreateFailed,
                format!("CreateIpForwardEntry2 returned {result}"),
            ));
        }
        let mut owned = Self { row, present: true };
        match lookup_route(row) {
            Ok(Some(observed)) if same_route_key(observed, row) => Ok(owned),
            Ok(Some(_)) => {
                let cleanup = owned.remove_and_verify();
                Err(route_lookup_failure_after_cleanup(
                    "created route identity changed",
                    cleanup,
                ))
            }
            Ok(None) => {
                let cleanup = owned.remove_and_verify();
                Err(route_lookup_failure_after_cleanup(
                    "created route was absent",
                    cleanup,
                ))
            }
            Err(error) => {
                let cleanup = owned.remove_and_verify();
                Err(route_lookup_failure_after_cleanup(
                    format!("created route lookup failed: {error}"),
                    cleanup,
                ))
            }
        }
    }

    fn remove_and_verify(&mut self) -> Result<(), WindowsDisposableRouteChurnError> {
        use WindowsDisposableRouteChurnErrorCode as Code;

        if !self.present {
            return Ok(());
        }
        let result = unsafe { DeleteIpForwardEntry2(&self.row) };
        if result != 0 && !matches!(result, ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND) {
            return Err(WindowsDisposableRouteChurnError::new(
                Code::RouteDeleteFailed,
                format!("DeleteIpForwardEntry2 returned {result}"),
            ));
        }
        let deadline = Instant::now() + ROUTE_REMOVAL_TIMEOUT;
        loop {
            if lookup_route(self.row)?.is_none() {
                self.present = false;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(WindowsDisposableRouteChurnError::new(
                    Code::RouteDeleteFailed,
                    "qualification route remained after bounded deletion",
                ));
            }
            thread::sleep(ROUTE_PROBE_INTERVAL);
        }
    }
}

impl Drop for OwnedQualificationRoute {
    fn drop(&mut self) {
        if self.present {
            unsafe {
                DeleteIpForwardEntry2(&self.row);
            }
        }
    }
}

fn route_lookup_failure_after_cleanup(
    detail: impl Into<String>,
    cleanup: Result<(), WindowsDisposableRouteChurnError>,
) -> WindowsDisposableRouteChurnError {
    let detail = detail.into();
    match cleanup {
        Ok(()) => WindowsDisposableRouteChurnError::new(
            WindowsDisposableRouteChurnErrorCode::RouteLookupFailed,
            detail,
        ),
        Err(cleanup_error) => WindowsDisposableRouteChurnError::new(
            WindowsDisposableRouteChurnErrorCode::CleanupFailed,
            format!("{detail}; cleanup: {cleanup_error}"),
        ),
    }
}

fn lookup_route(
    mut row: MIB_IPFORWARD_ROW2,
) -> Result<Option<MIB_IPFORWARD_ROW2>, WindowsDisposableRouteChurnError> {
    use WindowsDisposableRouteChurnErrorCode as Code;

    let result = unsafe { GetIpForwardEntry2(&mut row) };
    match result {
        0 => Ok(Some(row)),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Ok(None),
        other => Err(WindowsDisposableRouteChurnError::new(
            Code::RouteLookupFailed,
            format!("GetIpForwardEntry2 returned {other}"),
        )),
    }
}

fn same_route_key(left: MIB_IPFORWARD_ROW2, right: MIB_IPFORWARD_ROW2) -> bool {
    (unsafe { left.InterfaceLuid.Value == right.InterfaceLuid.Value })
        && left.InterfaceIndex == right.InterfaceIndex
        && left.DestinationPrefix.PrefixLength == right.DestinationPrefix.PrefixLength
        && unsafe { left.DestinationPrefix.Prefix.si_family }
            == unsafe { right.DestinationPrefix.Prefix.si_family }
        && unsafe { left.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr }
            == unsafe { right.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr }
}

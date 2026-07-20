//! Disposable owner for one exact Windows capture route.
//!
//! This module is compiled only for the explicit disposable packet fixture. It
//! is not a production route manager: it creates one exact host route, binds
//! that effect to two opaque kernel observations, and proves exact removal.

use super::transition_v1::{
    WindowsOwnedRouteTransitionError, WindowsOwnedRouteTransitionIssuer,
    WindowsPacketRouteObservation,
};
use super::windows::{observe_windows_packet_route, sockaddr_from_ip};
use super::WindowsPacketInterfaceIdentity;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, GetIpForwardEntry2, InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::MIB_IPPROTO_NETMGMT;

pub const WINDOWS_DISPOSABLE_EXACT_ROUTE_OWNER_VERSION: u32 = 1;

const DISPOSABLE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_DISPOSABLE_CI";
const EXACT_ROUTE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_EXACT_ROUTE_CI";
const ROUTE_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);
const ROUTE_PROBE_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsDisposableExactRouteErrorCode {
    DisposableGateClosed,
    BaselineObservationFailed,
    TransitionStageFailed,
    ExactRouteAlreadyPresent,
    ExactRoutePreflightFailed,
    ExactRouteCreateFailed,
    ExactRouteVerificationFailed,
    PostActivationObservationFailed,
    TransitionAttestationFailed,
    ActivationNotCurrent,
    ExactRouteDeleteFailed,
    ExactRouteRemovalUnproven,
    RouteEpochUpdateFailed,
    RecoveryObservationFailed,
    BaselineRouteNotRestored,
}

impl WindowsDisposableExactRouteErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DisposableGateClosed => "disposable_gate_closed",
            Self::BaselineObservationFailed => "baseline_observation_failed",
            Self::TransitionStageFailed => "transition_stage_failed",
            Self::ExactRouteAlreadyPresent => "exact_route_already_present",
            Self::ExactRoutePreflightFailed => "exact_route_preflight_failed",
            Self::ExactRouteCreateFailed => "exact_route_create_failed",
            Self::ExactRouteVerificationFailed => "exact_route_verification_failed",
            Self::PostActivationObservationFailed => "post_activation_observation_failed",
            Self::TransitionAttestationFailed => "transition_attestation_failed",
            Self::ActivationNotCurrent => "activation_not_current",
            Self::ExactRouteDeleteFailed => "exact_route_delete_failed",
            Self::ExactRouteRemovalUnproven => "exact_route_removal_unproven",
            Self::RouteEpochUpdateFailed => "route_epoch_update_failed",
            Self::RecoveryObservationFailed => "recovery_observation_failed",
            Self::BaselineRouteNotRestored => "baseline_route_not_restored",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsDisposableExactRouteError {
    code: WindowsDisposableExactRouteErrorCode,
    win32_code: Option<u32>,
    detail: Option<String>,
}

impl WindowsDisposableExactRouteError {
    fn new(code: WindowsDisposableExactRouteErrorCode) -> Self {
        Self {
            code,
            win32_code: None,
            detail: None,
        }
    }

    fn win32(code: WindowsDisposableExactRouteErrorCode, win32_code: u32) -> Self {
        Self {
            code,
            win32_code: Some(win32_code),
            detail: None,
        }
    }

    fn detail(code: WindowsDisposableExactRouteErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            win32_code: None,
            detail: Some(detail.into()),
        }
    }

    pub const fn code(&self) -> WindowsDisposableExactRouteErrorCode {
        self.code
    }

    pub const fn win32_code(&self) -> Option<u32> {
        self.win32_code
    }
}

impl fmt::Display for WindowsDisposableExactRouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())?;
        if let Some(win32_code) = self.win32_code {
            write!(formatter, " (Win32 error {win32_code})")?;
        }
        if let Some(detail) = &self.detail {
            write!(formatter, ": {detail}")?;
        }
        Ok(())
    }
}

impl Error for WindowsDisposableExactRouteError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsDisposableExactRouteQualification {
    destination: IpAddr,
    exact_route_prefix: String,
    capture_interface: WindowsPacketInterfaceIdentity,
    baseline_egress_interface: WindowsPacketInterfaceIdentity,
    recovered_egress_interface: WindowsPacketInterfaceIdentity,
    route_epoch_after_removal: u64,
}

impl WindowsDisposableExactRouteQualification {
    pub const fn destination(&self) -> IpAddr {
        self.destination
    }

    pub fn exact_route_prefix(&self) -> &str {
        &self.exact_route_prefix
    }

    pub const fn capture_interface(&self) -> WindowsPacketInterfaceIdentity {
        self.capture_interface
    }

    pub const fn baseline_egress_interface(&self) -> WindowsPacketInterfaceIdentity {
        self.baseline_egress_interface
    }

    pub const fn recovered_egress_interface(&self) -> WindowsPacketInterfaceIdentity {
        self.recovered_egress_interface
    }

    pub const fn route_epoch_after_removal(&self) -> u64 {
        self.route_epoch_after_removal
    }
}

/// Qualify one exact capture-route transaction on a disposable Windows host.
///
/// The function is unavailable without the disposable packet feature and also
/// requires two explicit CI environment gates. It never creates a default
/// route and never touches addresses, DNS, proxy, PAC, VPN, or another route.
pub fn qualify_disposable_exact_host_route(
    issuer: &mut WindowsOwnedRouteTransitionIssuer,
    destination: IpAddr,
) -> Result<WindowsDisposableExactRouteQualification, WindowsDisposableExactRouteError> {
    use WindowsDisposableExactRouteErrorCode as Code;

    require_disposable_gate()?;
    let baseline = observe_windows_packet_route(destination).map_err(|error| {
        WindowsDisposableExactRouteError::detail(Code::BaselineObservationFailed, error.to_string())
    })?;
    let baseline_egress_interface = baseline.egress_interface();
    let baseline_source_address = baseline.source_address();
    let baseline_route_prefix = baseline.route_prefix().to_owned();
    let baseline_route_is_loopback = baseline.route_is_loopback();
    let capture_interface = issuer.capture_interface();

    let intent = issuer
        .begin_exact_host_activation(baseline)
        .map_err(|error| transition_error(Code::TransitionStageFailed, error))?;
    let exact_route_prefix = intent.exact_route_prefix().to_owned();
    let row = exact_route_row(destination, capture_interface);
    let mut owned_route = match OwnedExactRoute::create(row) {
        Ok(route) => route,
        Err(error) => {
            issuer
                .cancel_before_effect(intent)
                .map_err(|cancel_error| {
                    transition_error(Code::TransitionStageFailed, cancel_error)
                })?;
            return Err(error);
        }
    };

    let activation_result = (|| {
        owned_route.verify_present()?;
        let post_activation = observe_windows_packet_route(destination).map_err(|error| {
            WindowsDisposableExactRouteError::detail(
                Code::PostActivationObservationFailed,
                error.to_string(),
            )
        })?;
        let activation = issuer
            .attest_exact_host_route_created(intent, post_activation)
            .map_err(|error| transition_error(Code::TransitionAttestationFailed, error))?;
        issuer
            .require_current_activation(&activation)
            .map_err(|error| transition_error(Code::ActivationNotCurrent, error))?;
        Ok::<_, WindowsDisposableExactRouteError>(activation)
    })();

    if activation_result.is_err() {
        let _ = issuer.record_route_change();
    }

    let cleanup_result = owned_route.remove_and_verify();
    if let Err(cleanup_error) = cleanup_result {
        let _ = issuer.record_route_change();
        return Err(cleanup_error);
    }
    let route_epoch_after_removal = issuer
        .record_route_change()
        .map_err(|error| transition_error(Code::RouteEpochUpdateFailed, error))?;

    let activation = activation_result?;
    if issuer.require_current_activation(&activation).is_ok() {
        return Err(WindowsDisposableExactRouteError::new(
            Code::ActivationNotCurrent,
        ));
    }

    let recovered = observe_windows_packet_route(destination).map_err(|error| {
        WindowsDisposableExactRouteError::detail(Code::RecoveryObservationFailed, error.to_string())
    })?;
    if recovered.egress_interface() != baseline_egress_interface
        || recovered.source_address() != baseline_source_address
        || recovered.route_prefix() != baseline_route_prefix
        || recovered.route_is_loopback() != baseline_route_is_loopback
    {
        return Err(WindowsDisposableExactRouteError::new(
            Code::BaselineRouteNotRestored,
        ));
    }

    Ok(WindowsDisposableExactRouteQualification {
        destination,
        exact_route_prefix,
        capture_interface,
        baseline_egress_interface,
        recovered_egress_interface: recovered.egress_interface(),
        route_epoch_after_removal,
    })
}

fn require_disposable_gate() -> Result<(), WindowsDisposableExactRouteError> {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() == Ok("1")
        && std::env::var(EXACT_ROUTE_CI_ENV).as_deref() == Ok("1")
    {
        return Ok(());
    }
    Err(WindowsDisposableExactRouteError::new(
        WindowsDisposableExactRouteErrorCode::DisposableGateClosed,
    ))
}

fn transition_error(
    code: WindowsDisposableExactRouteErrorCode,
    error: WindowsOwnedRouteTransitionError,
) -> WindowsDisposableExactRouteError {
    WindowsDisposableExactRouteError::detail(code, error.to_string())
}

fn exact_route_row(
    destination: IpAddr,
    interface: WindowsPacketInterfaceIdentity,
) -> MIB_IPFORWARD_ROW2 {
    let prefix_length = match destination {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let unspecified = match destination {
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
    row.DestinationPrefix.Prefix = sockaddr_from_ip(destination);
    row.DestinationPrefix.PrefixLength = prefix_length;
    row.NextHop = sockaddr_from_ip(unspecified);
    row.SitePrefixLength = prefix_length;
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row.Immortal = false;
    row
}

struct OwnedExactRoute {
    row: MIB_IPFORWARD_ROW2,
    present: bool,
}

impl OwnedExactRoute {
    fn create(row: MIB_IPFORWARD_ROW2) -> Result<Self, WindowsDisposableExactRouteError> {
        use WindowsDisposableExactRouteErrorCode as Code;

        match lookup_exact_route(row, Code::ExactRoutePreflightFailed)? {
            ExactRoutePresence::Absent => {}
            ExactRoutePresence::Present(_) => {
                return Err(WindowsDisposableExactRouteError::new(
                    Code::ExactRouteAlreadyPresent,
                ));
            }
        }
        let result = unsafe { CreateIpForwardEntry2(&row) };
        if result != 0 {
            return Err(WindowsDisposableExactRouteError::win32(
                Code::ExactRouteCreateFailed,
                result,
            ));
        }
        Ok(Self { row, present: true })
    }

    fn verify_present(&self) -> Result<(), WindowsDisposableExactRouteError> {
        use WindowsDisposableExactRouteErrorCode as Code;

        match lookup_exact_route(self.row, Code::ExactRouteVerificationFailed)? {
            ExactRoutePresence::Absent => Err(WindowsDisposableExactRouteError::new(
                Code::ExactRouteVerificationFailed,
            )),
            ExactRoutePresence::Present(observed)
                if unsafe { observed.InterfaceLuid.Value }
                    == unsafe { self.row.InterfaceLuid.Value }
                    && observed.InterfaceIndex == self.row.InterfaceIndex
                    && observed.DestinationPrefix.PrefixLength
                        == self.row.DestinationPrefix.PrefixLength
                    && observed.Protocol == MIB_IPPROTO_NETMGMT
                    && !observed.Loopback =>
            {
                Ok(())
            }
            ExactRoutePresence::Present(_) => Err(WindowsDisposableExactRouteError::new(
                Code::ExactRouteVerificationFailed,
            )),
        }
    }

    fn remove_and_verify(&mut self) -> Result<(), WindowsDisposableExactRouteError> {
        use WindowsDisposableExactRouteErrorCode as Code;

        let result = unsafe { DeleteIpForwardEntry2(&self.row) };
        if result != 0 {
            return Err(WindowsDisposableExactRouteError::win32(
                Code::ExactRouteDeleteFailed,
                result,
            ));
        }

        let deadline = Instant::now() + ROUTE_REMOVAL_TIMEOUT;
        loop {
            match lookup_exact_route(self.row, Code::ExactRouteRemovalUnproven)? {
                ExactRoutePresence::Absent => {
                    self.present = false;
                    return Ok(());
                }
                ExactRoutePresence::Present(_) if Instant::now() < deadline => {
                    thread::sleep(ROUTE_PROBE_INTERVAL);
                }
                ExactRoutePresence::Present(_) => {
                    return Err(WindowsDisposableExactRouteError::new(
                        Code::ExactRouteRemovalUnproven,
                    ));
                }
            }
        }
    }
}

impl Drop for OwnedExactRoute {
    fn drop(&mut self) {
        if self.present {
            unsafe {
                DeleteIpForwardEntry2(&self.row);
            }
        }
    }
}

enum ExactRoutePresence {
    Absent,
    Present(MIB_IPFORWARD_ROW2),
}

fn lookup_exact_route(
    row: MIB_IPFORWARD_ROW2,
    error_code: WindowsDisposableExactRouteErrorCode,
) -> Result<ExactRoutePresence, WindowsDisposableExactRouteError> {
    let mut observed = row;
    let result = unsafe { GetIpForwardEntry2(&mut observed) };
    match result {
        0 => Ok(ExactRoutePresence::Present(observed)),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Ok(ExactRoutePresence::Absent),
        error => Err(WindowsDisposableExactRouteError::win32(error_code, error)),
    }
}

//! Disposable owner for one exact Windows capture route.
//!
//! This module is compiled only for the explicit disposable packet fixture. It
//! is not a production route manager: it creates one exact host route, binds
//! that effect to two opaque kernel observations, and proves exact removal.

use super::transition_v1::{WindowsOwnedRouteTransitionError, WindowsOwnedRouteTransitionIssuer};
use super::windows::{
    observe_windows_packet_route, observe_windows_packet_route_on_interface, sockaddr_from_ip,
    WindowsPacketRouteObserverError,
};
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
const SOCKET_BINDING_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_SOCKET_BINDING_CI";
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
    BaselineEgressRevalidationFailed,
    BaselineEgressChanged,
    ActiveProbeGateClosed,
    ActiveProbeFailed,
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
            Self::BaselineEgressRevalidationFailed => "baseline_egress_revalidation_failed",
            Self::BaselineEgressChanged => "baseline_egress_changed",
            Self::ActiveProbeGateClosed => "active_probe_gate_closed",
            Self::ActiveProbeFailed => "active_probe_failed",
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

    fn detail_with_win32(
        code: WindowsDisposableExactRouteErrorCode,
        win32_code: Option<u32>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            win32_code,
            detail: Some(detail.into()),
        }
    }

    fn cleanup_after(prior: Self, cleanup: Self) -> Self {
        let code = cleanup.code;
        let win32_code = cleanup.win32_code;
        let detail = format!("prior failure: {prior}; cleanup failure: {cleanup}");
        Self {
            code,
            win32_code,
            detail: Some(detail),
        }
    }

    fn secondary_after(mut prior: Self, secondary: Self) -> Self {
        let secondary_detail = format!("secondary failure: {secondary}");
        prior.detail = Some(match prior.detail.take() {
            Some(detail) => format!("{detail}; {secondary_detail}"),
            None => secondary_detail,
        });
        prior
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsDisposableExactRouteActiveProbe<'a> {
    destination: IpAddr,
    exact_route_prefix: &'a str,
    capture_interface: WindowsPacketInterfaceIdentity,
    capture_source_address: IpAddr,
    baseline_egress_interface: WindowsPacketInterfaceIdentity,
    baseline_source_address: IpAddr,
}

impl WindowsDisposableExactRouteActiveProbe<'_> {
    pub const fn destination(&self) -> IpAddr {
        self.destination
    }

    pub fn exact_route_prefix(&self) -> &str {
        self.exact_route_prefix
    }

    pub const fn capture_interface(&self) -> WindowsPacketInterfaceIdentity {
        self.capture_interface
    }

    pub const fn capture_source_address(&self) -> IpAddr {
        self.capture_source_address
    }

    pub const fn baseline_egress_interface(&self) -> WindowsPacketInterfaceIdentity {
        self.baseline_egress_interface
    }

    pub const fn baseline_source_address(&self) -> IpAddr {
        self.baseline_source_address
    }
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
    qualify_disposable_exact_host_route_impl(issuer, destination, |_| Ok(()))
}

/// Run one disposable probe while the exact route is active and attested.
///
/// This entrypoint requires the additional socket-binding CI gate. The
/// probe-free wrapper retains the original two-gate route qualification.
/// The probe receives read-only route facts and cannot retain the activation.
/// Returning an error still performs exact route removal and recovery proof.
pub fn qualify_disposable_exact_host_route_with_active_probe<F>(
    issuer: &mut WindowsOwnedRouteTransitionIssuer,
    destination: IpAddr,
    active_probe: F,
) -> Result<WindowsDisposableExactRouteQualification, WindowsDisposableExactRouteError>
where
    F: FnOnce(&WindowsDisposableExactRouteActiveProbe<'_>) -> Result<(), String>,
{
    require_active_probe_gate()?;
    qualify_disposable_exact_host_route_impl(issuer, destination, active_probe)
}

fn qualify_disposable_exact_host_route_impl<F>(
    issuer: &mut WindowsOwnedRouteTransitionIssuer,
    destination: IpAddr,
    active_probe: F,
) -> Result<WindowsDisposableExactRouteQualification, WindowsDisposableExactRouteError>
where
    F: FnOnce(&WindowsDisposableExactRouteActiveProbe<'_>) -> Result<(), String>,
{
    use WindowsDisposableExactRouteErrorCode as Code;

    require_disposable_gate()?;
    let baseline = observe_windows_packet_route(destination)
        .map_err(|error| observation_error(Code::BaselineObservationFailed, error))?;
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
        let post_activation = observe_windows_packet_route(destination)
            .map_err(|error| observation_error(Code::PostActivationObservationFailed, error))?;
        let capture_source_address = post_activation.source_address();
        let activation = issuer
            .attest_exact_host_route_created(intent, post_activation)
            .map_err(|error| transition_error(Code::TransitionAttestationFailed, error))?;
        issuer
            .require_current_activation(&activation)
            .map_err(|error| transition_error(Code::ActivationNotCurrent, error))?;
        let revalidated_baseline = observe_windows_packet_route_on_interface(
            destination,
            baseline_egress_interface,
            baseline_source_address,
        )
        .map_err(|error| observation_error(Code::BaselineEgressRevalidationFailed, error))?;
        if revalidated_baseline.egress_interface() != baseline_egress_interface
            || revalidated_baseline.source_address() != baseline_source_address
            || revalidated_baseline.route_prefix() != baseline_route_prefix
            || revalidated_baseline.route_is_loopback() != baseline_route_is_loopback
        {
            return Err(WindowsDisposableExactRouteError::new(
                Code::BaselineEgressChanged,
            ));
        }
        active_probe(&WindowsDisposableExactRouteActiveProbe {
            destination,
            exact_route_prefix: &exact_route_prefix,
            capture_interface,
            capture_source_address,
            baseline_egress_interface,
            baseline_source_address,
        })
        .map_err(|error| {
            WindowsDisposableExactRouteError::detail(Code::ActiveProbeFailed, error)
        })?;
        Ok::<_, WindowsDisposableExactRouteError>(activation)
    })();

    let activation_epoch_error = if activation_result.is_err() {
        issuer
            .record_route_change()
            .err()
            .map(|error| transition_error(Code::RouteEpochUpdateFailed, error))
    } else {
        None
    };

    let cleanup_result = owned_route.remove_and_verify();
    if let Err(cleanup_error) = cleanup_result {
        let recovery_epoch_error = issuer
            .record_route_change()
            .err()
            .map(|error| transition_error(Code::RouteEpochUpdateFailed, error));
        let mut combined = match activation_result {
            Ok(_) => cleanup_error,
            Err(activation_error) => {
                let prior = match activation_epoch_error {
                    Some(epoch_error) => WindowsDisposableExactRouteError::secondary_after(
                        activation_error,
                        epoch_error,
                    ),
                    None => activation_error,
                };
                WindowsDisposableExactRouteError::cleanup_after(prior, cleanup_error)
            }
        };
        if let Some(epoch_error) = recovery_epoch_error {
            combined = WindowsDisposableExactRouteError::secondary_after(combined, epoch_error);
        }
        return Err(combined);
    }
    let (activation, mut pending_error) = match activation_result {
        Ok(activation) => (Some(activation), None),
        Err(activation_error) => {
            let combined = match activation_epoch_error {
                Some(epoch_error) => {
                    WindowsDisposableExactRouteError::secondary_after(activation_error, epoch_error)
                }
                None => activation_error,
            };
            (None, Some(combined))
        }
    };
    let route_epoch_after_removal = match issuer.record_route_change() {
        Ok(epoch) => Some(epoch),
        Err(error) => {
            retain_secondary_error(
                &mut pending_error,
                transition_error(Code::RouteEpochUpdateFailed, error),
            );
            None
        }
    };
    if let Some(activation) = activation.as_ref() {
        if issuer.require_current_activation(activation).is_ok() {
            retain_secondary_error(
                &mut pending_error,
                WindowsDisposableExactRouteError::new(Code::ActivationNotCurrent),
            );
        }
    }

    let recovered = match observe_windows_packet_route(destination) {
        Ok(recovered) => recovered,
        Err(error) => {
            return Err(recovery_error_after(
                pending_error,
                observation_error(Code::RecoveryObservationFailed, error),
            ));
        }
    };
    if recovered.egress_interface() != baseline_egress_interface
        || recovered.source_address() != baseline_source_address
        || recovered.route_prefix() != baseline_route_prefix
        || recovered.route_is_loopback() != baseline_route_is_loopback
    {
        return Err(recovery_error_after(
            pending_error,
            WindowsDisposableExactRouteError::new(Code::BaselineRouteNotRestored),
        ));
    }
    if let Some(error) = pending_error {
        return Err(error);
    }
    let route_epoch_after_removal = route_epoch_after_removal
        .ok_or_else(|| WindowsDisposableExactRouteError::new(Code::RouteEpochUpdateFailed))?;

    Ok(WindowsDisposableExactRouteQualification {
        destination,
        exact_route_prefix,
        capture_interface,
        baseline_egress_interface,
        recovered_egress_interface: recovered.egress_interface(),
        route_epoch_after_removal,
    })
}

fn retain_secondary_error(
    primary: &mut Option<WindowsDisposableExactRouteError>,
    secondary: WindowsDisposableExactRouteError,
) {
    *primary = Some(match primary.take() {
        Some(primary) => WindowsDisposableExactRouteError::secondary_after(primary, secondary),
        None => secondary,
    });
}

fn recovery_error_after(
    prior: Option<WindowsDisposableExactRouteError>,
    recovery: WindowsDisposableExactRouteError,
) -> WindowsDisposableExactRouteError {
    match prior {
        Some(prior) => WindowsDisposableExactRouteError::cleanup_after(prior, recovery),
        None => recovery,
    }
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

fn require_active_probe_gate() -> Result<(), WindowsDisposableExactRouteError> {
    if std::env::var(SOCKET_BINDING_CI_ENV).as_deref() == Ok("1") {
        return Ok(());
    }
    Err(WindowsDisposableExactRouteError::new(
        WindowsDisposableExactRouteErrorCode::ActiveProbeGateClosed,
    ))
}

fn transition_error(
    code: WindowsDisposableExactRouteErrorCode,
    error: WindowsOwnedRouteTransitionError,
) -> WindowsDisposableExactRouteError {
    WindowsDisposableExactRouteError::detail(code, error.to_string())
}

fn observation_error(
    code: WindowsDisposableExactRouteErrorCode,
    error: WindowsPacketRouteObserverError,
) -> WindowsDisposableExactRouteError {
    WindowsDisposableExactRouteError::detail_with_win32(
        code,
        error.win32_code(),
        error.code().as_str(),
    )
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

#[cfg(test)]
mod tests {
    use super::{
        recovery_error_after, WindowsDisposableExactRouteError,
        WindowsDisposableExactRouteErrorCode as Code,
    };

    #[test]
    fn combined_cleanup_failure_retains_both_errors_and_structured_cleanup_code() {
        let prior = WindowsDisposableExactRouteError::detail(
            Code::PostActivationObservationFailed,
            "route_query_failed",
        );
        let cleanup = WindowsDisposableExactRouteError::win32(Code::ExactRouteDeleteFailed, 5);

        let combined = WindowsDisposableExactRouteError::cleanup_after(prior, cleanup);

        assert_eq!(combined.code(), Code::ExactRouteDeleteFailed);
        assert_eq!(combined.win32_code(), Some(5));
        let rendered = combined.to_string();
        assert!(rendered.contains("prior failure: post_activation_observation_failed"));
        assert!(rendered.contains("route_query_failed"));
        assert!(rendered.contains("cleanup failure: exact_route_delete_failed"));
        assert!(rendered.contains("Win32 error 5"));
    }

    #[test]
    fn observation_failure_retains_outer_phase_and_win32_code() {
        let error = WindowsDisposableExactRouteError::detail_with_win32(
            Code::PostActivationObservationFailed,
            Some(1232),
            "route_query_failed",
        );

        assert_eq!(error.code(), Code::PostActivationObservationFailed);
        assert_eq!(error.win32_code(), Some(1232));
        assert_eq!(
            error.to_string(),
            "post_activation_observation_failed (Win32 error 1232): route_query_failed"
        );
    }

    #[test]
    fn secondary_epoch_failure_does_not_mask_activation_failure() {
        let activation = WindowsDisposableExactRouteError::detail_with_win32(
            Code::PostActivationObservationFailed,
            Some(1232),
            "route_query_failed",
        );
        let epoch = WindowsDisposableExactRouteError::detail(
            Code::RouteEpochUpdateFailed,
            "route_epoch_exhausted",
        );

        let combined = WindowsDisposableExactRouteError::secondary_after(activation, epoch);

        assert_eq!(combined.code(), Code::PostActivationObservationFailed);
        assert_eq!(combined.win32_code(), Some(1232));
        let rendered = combined.to_string();
        assert!(rendered.contains("route_query_failed"));
        assert!(rendered.contains("secondary failure: route_epoch_update_failed"));
        assert!(rendered.contains("route_epoch_exhausted"));
    }

    #[test]
    fn recovery_failure_is_primary_and_retains_the_probe_failure() {
        let probe = WindowsDisposableExactRouteError::detail(
            Code::ActiveProbeFailed,
            "socket_binding_failed",
        );
        let recovery = WindowsDisposableExactRouteError::detail_with_win32(
            Code::RecoveryObservationFailed,
            Some(1232),
            "route_query_failed",
        );

        let combined = recovery_error_after(Some(probe), recovery);

        assert_eq!(combined.code(), Code::RecoveryObservationFailed);
        assert_eq!(combined.win32_code(), Some(1232));
        let rendered = combined.to_string();
        assert!(rendered.contains("prior failure: active_probe_failed"));
        assert!(rendered.contains("socket_binding_failed"));
        assert!(rendered.contains("cleanup failure: recovery_observation_failed"));
        assert!(rendered.contains("route_query_failed"));
    }
}

//! Version 1 ownership boundary for one future exact Windows capture route.
//!
//! The issuer serializes one transition in memory and turns two opaque kernel
//! observations into an opaque activation token. It performs no route query,
//! socket operation, route mutation, adapter effect, or production composition.

use super::v1::{
    WindowsPacketBaselineRouteEvidence, WindowsPacketCaptureRouteActivationEvidence,
    WindowsPacketInterfaceIdentity, MAX_PACKET_EGRESS_EVIDENCE_LIFETIME_MS,
};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

pub const WINDOWS_OWNED_ROUTE_TRANSITION_CONTRACT_VERSION: u32 = 1;

/// Opaque route-table fact returned by the native read-only observer.
///
/// Public callers can inspect this value but cannot construct or deserialize
/// one. Consuming it in a transition prevents a caller from editing its fields
/// between observation and staging.
#[derive(Debug, Eq, PartialEq)]
pub struct WindowsPacketRouteObservation {
    observed_at_ms: u64,
    destination: IpAddr,
    egress_interface: WindowsPacketInterfaceIdentity,
    source_address: IpAddr,
    route_prefix: String,
    route_is_loopback: bool,
}

impl WindowsPacketRouteObservation {
    #[cfg(windows)]
    pub(super) fn from_kernel(
        observed_at_ms: u64,
        destination: IpAddr,
        egress_interface: WindowsPacketInterfaceIdentity,
        source_address: IpAddr,
        route_prefix: String,
        route_is_loopback: bool,
    ) -> Self {
        Self {
            observed_at_ms,
            destination,
            egress_interface,
            source_address,
            route_prefix,
            route_is_loopback,
        }
    }

    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }

    pub const fn destination(&self) -> IpAddr {
        self.destination
    }

    pub const fn egress_interface(&self) -> WindowsPacketInterfaceIdentity {
        self.egress_interface
    }

    pub const fn source_address(&self) -> IpAddr {
        self.source_address
    }

    pub fn route_prefix(&self) -> &str {
        &self.route_prefix
    }

    pub const fn route_is_loopback(&self) -> bool {
        self.route_is_loopback
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsOwnedRouteTransitionState {
    Ready,
    Pending,
    Active,
    Invalidated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsOwnedRouteTransitionErrorCode {
    InvalidCaptureGeneration,
    InvalidRouteEpoch,
    InvalidCaptureInterface,
    InvalidObservationWindow,
    ObservationExpired,
    InvalidEgressInterface,
    CaptureInterfaceSelected,
    LoopbackRoute,
    TransitionAlreadyPending,
    ActiveRoutePresent,
    IssuerInvalidated,
    TransitionIdExhausted,
    TransitionMismatch,
    InvalidActivationWindow,
    PostActivationDestinationMismatch,
    PostActivationInterfaceMismatch,
    PostActivationPrefixMismatch,
    PostActivationLoopbackRoute,
    RouteEpochExhausted,
    ActivationNotCurrent,
}

impl WindowsOwnedRouteTransitionErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCaptureGeneration => "invalid_capture_generation",
            Self::InvalidRouteEpoch => "invalid_route_epoch",
            Self::InvalidCaptureInterface => "invalid_capture_interface",
            Self::InvalidObservationWindow => "invalid_observation_window",
            Self::ObservationExpired => "observation_expired",
            Self::InvalidEgressInterface => "invalid_egress_interface",
            Self::CaptureInterfaceSelected => "capture_interface_selected",
            Self::LoopbackRoute => "loopback_route",
            Self::TransitionAlreadyPending => "transition_already_pending",
            Self::ActiveRoutePresent => "active_route_present",
            Self::IssuerInvalidated => "issuer_invalidated",
            Self::TransitionIdExhausted => "transition_id_exhausted",
            Self::TransitionMismatch => "transition_mismatch",
            Self::InvalidActivationWindow => "invalid_activation_window",
            Self::PostActivationDestinationMismatch => "post_activation_destination_mismatch",
            Self::PostActivationInterfaceMismatch => "post_activation_interface_mismatch",
            Self::PostActivationPrefixMismatch => "post_activation_prefix_mismatch",
            Self::PostActivationLoopbackRoute => "post_activation_loopback_route",
            Self::RouteEpochExhausted => "route_epoch_exhausted",
            Self::ActivationNotCurrent => "activation_not_current",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsOwnedRouteTransitionError {
    code: WindowsOwnedRouteTransitionErrorCode,
}

impl WindowsOwnedRouteTransitionError {
    const fn new(code: WindowsOwnedRouteTransitionErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> WindowsOwnedRouteTransitionErrorCode {
        self.code
    }
}

impl fmt::Display for WindowsOwnedRouteTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Error for WindowsOwnedRouteTransitionError {}

#[derive(Debug)]
struct IssuerIdentity;

#[derive(Debug)]
struct PendingTransition {
    transition_id: u64,
    destination: IpAddr,
    exact_route_prefix: String,
}

#[derive(Debug)]
struct ActiveTransition {
    transition_id: u64,
    active_route_epoch: u64,
}

#[derive(Debug)]
enum IssuerState {
    Ready,
    Pending(PendingTransition),
    Active(ActiveTransition),
    Invalidated,
}

/// In-memory serializer for one future exact owned capture-route transition.
///
/// This type is deliberately not a route-table owner. The crate-private
/// attestation method remains uncomposed until a later disposable native route
/// effect can supply the matching post-activation kernel observation.
#[derive(Debug)]
pub struct WindowsOwnedRouteTransitionIssuer {
    identity: Arc<IssuerIdentity>,
    capture_generation: u64,
    capture_interface: WindowsPacketInterfaceIdentity,
    route_epoch: u64,
    next_transition_id: u64,
    state: IssuerState,
}

/// One staged exact-route intent. It is opaque, non-cloneable, and bound to one
/// issuer allocation.
#[derive(Debug)]
pub struct WindowsOwnedCaptureRouteIntent {
    issuer_identity: Arc<IssuerIdentity>,
    transition_id: u64,
    destination: IpAddr,
    exact_route_prefix: String,
    baseline: WindowsPacketBaselineRouteEvidence,
}

impl WindowsOwnedCaptureRouteIntent {
    pub const fn transition_id(&self) -> u64 {
        self.transition_id
    }

    pub const fn destination(&self) -> IpAddr {
        self.destination
    }

    pub fn exact_route_prefix(&self) -> &str {
        &self.exact_route_prefix
    }

    pub fn baseline(&self) -> &WindowsPacketBaselineRouteEvidence {
        &self.baseline
    }
}

/// Opaque proof that one staged exact route became the selected kernel route.
///
/// The serializable evidence remains available for the frozen pure v1 vectors,
/// but future native egress must additionally retain this non-deserializable
/// token and ask its issuer whether it is still current.
#[derive(Debug)]
pub struct WindowsOwnedCaptureRouteActivation {
    issuer_identity: Arc<IssuerIdentity>,
    transition_id: u64,
    evidence: WindowsPacketCaptureRouteActivationEvidence,
}

impl WindowsOwnedCaptureRouteActivation {
    pub fn evidence(&self) -> &WindowsPacketCaptureRouteActivationEvidence {
        &self.evidence
    }
}

impl WindowsOwnedRouteTransitionIssuer {
    pub fn new(
        capture_generation: u64,
        capture_interface: WindowsPacketInterfaceIdentity,
        initial_route_epoch: u64,
    ) -> Result<Self, WindowsOwnedRouteTransitionError> {
        use WindowsOwnedRouteTransitionErrorCode as Code;

        if capture_generation == 0 {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::InvalidCaptureGeneration,
            ));
        }
        if capture_interface.luid == 0 || capture_interface.index == 0 {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::InvalidCaptureInterface,
            ));
        }
        if initial_route_epoch == 0 {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::InvalidRouteEpoch,
            ));
        }
        Ok(Self {
            identity: Arc::new(IssuerIdentity),
            capture_generation,
            capture_interface,
            route_epoch: initial_route_epoch,
            next_transition_id: 1,
            state: IssuerState::Ready,
        })
    }

    pub const fn capture_generation(&self) -> u64 {
        self.capture_generation
    }

    pub const fn capture_interface(&self) -> WindowsPacketInterfaceIdentity {
        self.capture_interface
    }

    pub const fn route_epoch(&self) -> u64 {
        self.route_epoch
    }

    pub const fn state(&self) -> WindowsOwnedRouteTransitionState {
        match self.state {
            IssuerState::Ready => WindowsOwnedRouteTransitionState::Ready,
            IssuerState::Pending(_) => WindowsOwnedRouteTransitionState::Pending,
            IssuerState::Active(_) => WindowsOwnedRouteTransitionState::Active,
            IssuerState::Invalidated => WindowsOwnedRouteTransitionState::Invalidated,
        }
    }

    #[cfg(windows)]
    pub fn begin_exact_host_activation(
        &mut self,
        observation: WindowsPacketRouteObservation,
    ) -> Result<WindowsOwnedCaptureRouteIntent, WindowsOwnedRouteTransitionError> {
        self.begin_exact_host_activation_at(observation, super::windows::windows_uptime_ms())
    }

    fn begin_exact_host_activation_at(
        &mut self,
        observation: WindowsPacketRouteObservation,
        now_ms: u64,
    ) -> Result<WindowsOwnedCaptureRouteIntent, WindowsOwnedRouteTransitionError> {
        use WindowsOwnedRouteTransitionErrorCode as Code;

        match self.state {
            IssuerState::Ready => {}
            IssuerState::Pending(_) => {
                return Err(WindowsOwnedRouteTransitionError::new(
                    Code::TransitionAlreadyPending,
                ));
            }
            IssuerState::Active(_) => {
                return Err(WindowsOwnedRouteTransitionError::new(
                    Code::ActiveRoutePresent,
                ));
            }
            IssuerState::Invalidated => {
                return Err(WindowsOwnedRouteTransitionError::new(
                    Code::IssuerInvalidated,
                ));
            }
        }

        let observed_at_ms = observation.observed_at_ms;
        let Some(expires_at_ms) =
            observed_at_ms.checked_add(MAX_PACKET_EGRESS_EVIDENCE_LIFETIME_MS)
        else {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::InvalidObservationWindow,
            ));
        };
        if now_ms < observed_at_ms {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::InvalidObservationWindow,
            ));
        }
        if now_ms >= expires_at_ms {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::ObservationExpired,
            ));
        }
        if observation.egress_interface.luid == 0 || observation.egress_interface.index == 0 {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::InvalidEgressInterface,
            ));
        }
        if observation.egress_interface.luid == self.capture_interface.luid
            || observation.egress_interface.index == self.capture_interface.index
        {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::CaptureInterfaceSelected,
            ));
        }
        if observation.route_is_loopback {
            return Err(WindowsOwnedRouteTransitionError::new(Code::LoopbackRoute));
        }

        let transition_id = self.next_transition_id;
        let Some(next_transition_id) = transition_id.checked_add(1) else {
            self.state = IssuerState::Invalidated;
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::TransitionIdExhausted,
            ));
        };
        self.next_transition_id = next_transition_id;

        let destination = observation.destination;
        let exact_route_prefix = exact_host_prefix(destination);
        let baseline = WindowsPacketBaselineRouteEvidence {
            capture_generation: self.capture_generation,
            route_epoch: self.route_epoch,
            destination: destination.to_string(),
            observed_at_ms,
            expires_at_ms,
            capture_interface: self.capture_interface,
            egress_interface: observation.egress_interface,
            source_address: observation.source_address.to_string(),
            route_prefix: observation.route_prefix,
            route_is_loopback: observation.route_is_loopback,
        };
        self.state = IssuerState::Pending(PendingTransition {
            transition_id,
            destination,
            exact_route_prefix: exact_route_prefix.clone(),
        });

        Ok(WindowsOwnedCaptureRouteIntent {
            issuer_identity: Arc::clone(&self.identity),
            transition_id,
            destination,
            exact_route_prefix,
            baseline,
        })
    }

    pub fn cancel_before_effect(
        &mut self,
        intent: WindowsOwnedCaptureRouteIntent,
    ) -> Result<(), WindowsOwnedRouteTransitionError> {
        self.require_pending_intent(&intent)?;
        self.state = IssuerState::Ready;
        Ok(())
    }

    /// Advance the logical route epoch after any later owned or external route
    /// change. A pending or active transition becomes unusable immediately.
    pub fn record_route_change(&mut self) -> Result<u64, WindowsOwnedRouteTransitionError> {
        use WindowsOwnedRouteTransitionErrorCode as Code;

        let Some(next_epoch) = self.route_epoch.checked_add(1) else {
            self.state = IssuerState::Invalidated;
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::RouteEpochExhausted,
            ));
        };
        self.route_epoch = next_epoch;
        if !matches!(self.state, IssuerState::Ready) {
            self.state = IssuerState::Invalidated;
        }
        Ok(next_epoch)
    }

    pub fn require_current_activation<'a>(
        &self,
        activation: &'a WindowsOwnedCaptureRouteActivation,
    ) -> Result<&'a WindowsPacketCaptureRouteActivationEvidence, WindowsOwnedRouteTransitionError>
    {
        use WindowsOwnedRouteTransitionErrorCode as Code;

        let IssuerState::Active(active) = &self.state else {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::ActivationNotCurrent,
            ));
        };
        if !Arc::ptr_eq(&self.identity, &activation.issuer_identity)
            || active.transition_id != activation.transition_id
            || active.active_route_epoch != self.route_epoch
            || activation.evidence.active_route_epoch != self.route_epoch
        {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::ActivationNotCurrent,
            ));
        }
        Ok(&activation.evidence)
    }

    // This method stays crate-internal until a later disposable route owner can
    // apply and remove the exact route around the two kernel observations.
    #[cfg(windows)]
    #[allow(dead_code)]
    pub(super) fn attest_exact_host_route_created(
        &mut self,
        intent: WindowsOwnedCaptureRouteIntent,
        post_activation: WindowsPacketRouteObservation,
    ) -> Result<WindowsOwnedCaptureRouteActivation, WindowsOwnedRouteTransitionError> {
        self.attest_exact_host_route_created_at(
            intent,
            post_activation,
            super::windows::windows_uptime_ms(),
        )
    }

    fn attest_exact_host_route_created_at(
        &mut self,
        intent: WindowsOwnedCaptureRouteIntent,
        post_activation: WindowsPacketRouteObservation,
        now_ms: u64,
    ) -> Result<WindowsOwnedCaptureRouteActivation, WindowsOwnedRouteTransitionError> {
        use WindowsOwnedRouteTransitionErrorCode as Code;

        if let Err(error) = self.require_pending_intent(&intent) {
            self.invalidate_after_possible_effect()?;
            return Err(error);
        }
        let activated_at_ms = post_activation.observed_at_ms;
        if now_ms < activated_at_ms
            || now_ms >= intent.baseline.expires_at_ms
            || activated_at_ms < intent.baseline.observed_at_ms
            || activated_at_ms >= intent.baseline.expires_at_ms
        {
            self.invalidate_after_possible_effect()?;
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::InvalidActivationWindow,
            ));
        }
        if post_activation.destination != intent.destination {
            self.invalidate_after_possible_effect()?;
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::PostActivationDestinationMismatch,
            ));
        }
        if post_activation.egress_interface != self.capture_interface {
            self.invalidate_after_possible_effect()?;
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::PostActivationInterfaceMismatch,
            ));
        }
        if post_activation.route_prefix != intent.exact_route_prefix {
            self.invalidate_after_possible_effect()?;
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::PostActivationPrefixMismatch,
            ));
        }
        if post_activation.route_is_loopback {
            self.invalidate_after_possible_effect()?;
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::PostActivationLoopbackRoute,
            ));
        }

        let previous_route_epoch = self.route_epoch;
        let Some(active_route_epoch) = previous_route_epoch.checked_add(1) else {
            self.state = IssuerState::Invalidated;
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::RouteEpochExhausted,
            ));
        };
        self.route_epoch = active_route_epoch;
        let evidence = WindowsPacketCaptureRouteActivationEvidence {
            capture_generation: self.capture_generation,
            destination: intent.destination.to_string(),
            route_prefix: intent.exact_route_prefix,
            previous_route_epoch,
            active_route_epoch,
            activated_at_ms,
            capture_interface: self.capture_interface,
        };
        self.state = IssuerState::Active(ActiveTransition {
            transition_id: intent.transition_id,
            active_route_epoch,
        });
        Ok(WindowsOwnedCaptureRouteActivation {
            issuer_identity: Arc::clone(&self.identity),
            transition_id: intent.transition_id,
            evidence,
        })
    }

    fn require_pending_intent(
        &self,
        intent: &WindowsOwnedCaptureRouteIntent,
    ) -> Result<(), WindowsOwnedRouteTransitionError> {
        use WindowsOwnedRouteTransitionErrorCode as Code;

        let IssuerState::Pending(pending) = &self.state else {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::TransitionMismatch,
            ));
        };
        if !Arc::ptr_eq(&self.identity, &intent.issuer_identity)
            || pending.transition_id != intent.transition_id
            || pending.destination != intent.destination
            || pending.exact_route_prefix != intent.exact_route_prefix
        {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::TransitionMismatch,
            ));
        }
        Ok(())
    }

    fn invalidate_after_possible_effect(&mut self) -> Result<(), WindowsOwnedRouteTransitionError> {
        use WindowsOwnedRouteTransitionErrorCode as Code;

        self.state = IssuerState::Invalidated;
        let Some(next_epoch) = self.route_epoch.checked_add(1) else {
            return Err(WindowsOwnedRouteTransitionError::new(
                Code::RouteEpochExhausted,
            ));
        };
        self.route_epoch = next_epoch;
        Ok(())
    }
}

fn exact_host_prefix(destination: IpAddr) -> String {
    match destination {
        IpAddr::V4(_) => format!("{destination}/32"),
        IpAddr::V6(_) => format!("{destination}/128"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const CAPTURE: WindowsPacketInterfaceIdentity = WindowsPacketInterfaceIdentity {
        luid: 91,
        index: 19,
    };
    const EGRESS: WindowsPacketInterfaceIdentity =
        WindowsPacketInterfaceIdentity { luid: 41, index: 7 };

    fn observation(
        destination: IpAddr,
        egress_interface: WindowsPacketInterfaceIdentity,
        source_address: IpAddr,
        route_prefix: &str,
    ) -> WindowsPacketRouteObservation {
        observation_at(
            destination,
            egress_interface,
            source_address,
            route_prefix,
            1_000,
        )
    }

    fn observation_at(
        destination: IpAddr,
        egress_interface: WindowsPacketInterfaceIdentity,
        source_address: IpAddr,
        route_prefix: &str,
        observed_at_ms: u64,
    ) -> WindowsPacketRouteObservation {
        WindowsPacketRouteObservation {
            observed_at_ms,
            destination,
            egress_interface,
            source_address,
            route_prefix: route_prefix.to_owned(),
            route_is_loopback: false,
        }
    }

    fn issuer() -> WindowsOwnedRouteTransitionIssuer {
        WindowsOwnedRouteTransitionIssuer::new(17, CAPTURE, 5).expect("issuer")
    }

    #[test]
    fn staging_consumes_one_kernel_observation_and_serializes_the_transition() {
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut issuer = issuer();
        let intent = issuer
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                ),
                1_001,
            )
            .expect("stage transition");

        assert_eq!(issuer.state(), WindowsOwnedRouteTransitionState::Pending);
        assert_eq!(intent.destination(), destination);
        assert_eq!(intent.exact_route_prefix(), "1.1.1.1/32");
        assert_eq!(intent.baseline().route_epoch, 5);
        assert_eq!(intent.baseline().observed_at_ms, 1_000);
        assert_eq!(intent.baseline().expires_at_ms, 6_000);
        assert_eq!(intent.baseline().egress_interface, EGRESS);
        assert_eq!(intent.baseline().source_address, "10.0.0.2");

        let error = issuer
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                ),
                1_002,
            )
            .expect_err("a second pending transition must fail");
        assert_eq!(
            error.code(),
            WindowsOwnedRouteTransitionErrorCode::TransitionAlreadyPending
        );

        issuer
            .cancel_before_effect(intent)
            .expect("cancel before any route effect");
        assert_eq!(issuer.state(), WindowsOwnedRouteTransitionState::Ready);
        assert_eq!(issuer.route_epoch(), 5);
    }

    #[test]
    fn route_change_keeps_ready_but_invalidates_a_pending_transition() {
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut issuer = issuer();

        assert_eq!(issuer.record_route_change(), Ok(6));
        assert_eq!(issuer.state(), WindowsOwnedRouteTransitionState::Ready);
        let intent = issuer
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                ),
                1_001,
            )
            .expect("stage transition after a harmless epoch change");
        assert_eq!(intent.baseline().route_epoch, 6);

        assert_eq!(issuer.record_route_change(), Ok(7));
        assert_eq!(
            issuer.state(),
            WindowsOwnedRouteTransitionState::Invalidated
        );
        assert_eq!(issuer.route_epoch(), 7);
    }

    #[test]
    fn matching_post_activation_observation_issues_an_opaque_current_token() {
        let destination = IpAddr::V6(
            "2606:4700:4700::1111"
                .parse::<Ipv6Addr>()
                .expect("IPv6 literal"),
        );
        let mut issuer = issuer();
        let intent = issuer
            .begin_exact_host_activation_at(
                observation_at(
                    destination,
                    EGRESS,
                    IpAddr::V6("fd00::2".parse().expect("source")),
                    "::/0",
                    2_000,
                ),
                2_010,
            )
            .expect("stage transition");
        let activation = issuer
            .attest_exact_host_route_created_at(
                intent,
                observation_at(
                    destination,
                    CAPTURE,
                    IpAddr::V6("fd00::9".parse().expect("capture source")),
                    "2606:4700:4700::1111/128",
                    2_020,
                ),
                2_020,
            )
            .expect("attest exact route");

        assert_eq!(issuer.state(), WindowsOwnedRouteTransitionState::Active);
        assert_eq!(issuer.route_epoch(), 6);
        let evidence = issuer
            .require_current_activation(&activation)
            .expect("current activation");
        assert_eq!(evidence.capture_generation, 17);
        assert_eq!(evidence.previous_route_epoch, 5);
        assert_eq!(evidence.active_route_epoch, 6);
        assert_eq!(evidence.route_prefix, "2606:4700:4700::1111/128");
        assert_eq!(evidence.capture_interface, CAPTURE);
    }

    #[test]
    fn delayed_post_activation_observation_cannot_issue_a_token() {
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut issuer = issuer();
        let intent = issuer
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                ),
                1_100,
            )
            .expect("stage transition");
        let error = issuer
            .attest_exact_host_route_created_at(
                intent,
                observation_at(
                    destination,
                    CAPTURE,
                    IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
                    "1.1.1.1/32",
                    1_200,
                ),
                6_000,
            )
            .expect_err("a retained post-route fact must expire before token issuance");

        assert_eq!(
            error.code(),
            WindowsOwnedRouteTransitionErrorCode::InvalidActivationWindow
        );
        assert_eq!(issuer.route_epoch(), 6);
        assert_eq!(
            issuer.state(),
            WindowsOwnedRouteTransitionState::Invalidated
        );
    }

    #[test]
    fn any_later_route_change_invalidates_the_activation_token() {
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut issuer = issuer();
        let intent = issuer
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                ),
                1_100,
            )
            .expect("stage transition");
        let activation = issuer
            .attest_exact_host_route_created_at(
                intent,
                observation_at(
                    destination,
                    CAPTURE,
                    IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
                    "1.1.1.1/32",
                    1_200,
                ),
                1_200,
            )
            .expect("attest exact route");

        assert_eq!(issuer.record_route_change(), Ok(7));
        assert_eq!(
            issuer.state(),
            WindowsOwnedRouteTransitionState::Invalidated
        );
        assert_eq!(
            issuer
                .require_current_activation(&activation)
                .expect_err("stale activation must fail")
                .code(),
            WindowsOwnedRouteTransitionErrorCode::ActivationNotCurrent
        );
    }

    #[test]
    fn mismatched_post_activation_fact_fails_closed_and_advances_the_epoch() {
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut issuer = issuer();
        let intent = issuer
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                ),
                1_100,
            )
            .expect("stage transition");
        let error = issuer
            .attest_exact_host_route_created_at(
                intent,
                observation_at(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                    1_200,
                ),
                1_200,
            )
            .expect_err("the route did not select the capture interface");

        assert_eq!(
            error.code(),
            WindowsOwnedRouteTransitionErrorCode::PostActivationInterfaceMismatch
        );
        assert_eq!(issuer.route_epoch(), 6);
        assert_eq!(
            issuer.state(),
            WindowsOwnedRouteTransitionState::Invalidated
        );
    }

    #[test]
    fn mismatched_intent_after_possible_effect_invalidates_the_issuer() {
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut primary = issuer();
        let mut other = issuer();
        let _current_intent = primary
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                ),
                1_100,
            )
            .expect("stage current transition");
        let foreign_intent = other
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                ),
                1_100,
            )
            .expect("stage foreign transition");

        let error = primary
            .attest_exact_host_route_created_at(
                foreign_intent,
                observation_at(
                    destination,
                    CAPTURE,
                    IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
                    "1.1.1.1/32",
                    1_200,
                ),
                1_200,
            )
            .expect_err("an uncertain effect with the wrong intent must fail closed");

        assert_eq!(
            error.code(),
            WindowsOwnedRouteTransitionErrorCode::TransitionMismatch
        );
        assert_eq!(primary.route_epoch(), 6);
        assert_eq!(
            primary.state(),
            WindowsOwnedRouteTransitionState::Invalidated
        );
    }

    #[test]
    fn an_activation_token_is_bound_to_one_issuer_allocation() {
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut first = issuer();
        let intent = first
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                ),
                1_100,
            )
            .expect("stage transition");
        let activation = first
            .attest_exact_host_route_created_at(
                intent,
                observation_at(
                    destination,
                    CAPTURE,
                    IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
                    "1.1.1.1/32",
                    1_200,
                ),
                1_200,
            )
            .expect("attest exact route");
        let second = issuer();

        assert_eq!(
            second
                .require_current_activation(&activation)
                .expect_err("another issuer must reject the token")
                .code(),
            WindowsOwnedRouteTransitionErrorCode::ActivationNotCurrent
        );
    }

    #[test]
    fn staging_rejects_expired_loopback_and_capture_selected_facts() {
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let overflow = issuer()
            .begin_exact_host_activation_at(
                observation_at(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                    u64::MAX - 1_000,
                ),
                u64::MAX - 1_000,
            )
            .expect_err("an observation window that cannot be represented must fail");
        assert_eq!(
            overflow.code(),
            WindowsOwnedRouteTransitionErrorCode::InvalidObservationWindow
        );

        let expired = issuer()
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    EGRESS,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "0.0.0.0/0",
                ),
                6_000,
            )
            .expect_err("expired observation");
        assert_eq!(
            expired.code(),
            WindowsOwnedRouteTransitionErrorCode::ObservationExpired
        );

        let selected = issuer()
            .begin_exact_host_activation_at(
                observation(
                    destination,
                    CAPTURE,
                    IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
                    "1.1.1.1/32",
                ),
                1_001,
            )
            .expect_err("capture-selected baseline");
        assert_eq!(
            selected.code(),
            WindowsOwnedRouteTransitionErrorCode::CaptureInterfaceSelected
        );

        let mut loopback = observation(
            destination,
            EGRESS,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "0.0.0.0/0",
        );
        loopback.route_is_loopback = true;
        let loopback = issuer()
            .begin_exact_host_activation_at(loopback, 1_001)
            .expect_err("loopback route");
        assert_eq!(
            loopback.code(),
            WindowsOwnedRouteTransitionErrorCode::LoopbackRoute
        );
    }

    #[test]
    fn every_transition_failure_has_a_stable_machine_code() {
        use WindowsOwnedRouteTransitionErrorCode::*;

        let codes = [
            InvalidCaptureGeneration,
            InvalidRouteEpoch,
            InvalidCaptureInterface,
            InvalidObservationWindow,
            ObservationExpired,
            InvalidEgressInterface,
            CaptureInterfaceSelected,
            LoopbackRoute,
            TransitionAlreadyPending,
            ActiveRoutePresent,
            IssuerInvalidated,
            TransitionIdExhausted,
            TransitionMismatch,
            InvalidActivationWindow,
            PostActivationDestinationMismatch,
            PostActivationInterfaceMismatch,
            PostActivationPrefixMismatch,
            PostActivationLoopbackRoute,
            RouteEpochExhausted,
            ActivationNotCurrent,
        ];
        assert!(codes.iter().all(|code| !code.as_str().is_empty()));
    }
}

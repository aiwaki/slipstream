//! Version 1 outbound-interface admission for a future Windows packet path.
//!
//! This module turns short-lived pre-capture route evidence into an opaque
//! socket-interface plan. It performs no route query, socket operation, route
//! mutation, or adapter effect. A native collector and disposable route test
//! remain separate gates.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const WINDOWS_PACKET_EGRESS_CONTRACT_VERSION: u32 = 1;
pub const MAX_PACKET_EGRESS_EVIDENCE_LIFETIME_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsPacketInterfaceIdentity {
    pub luid: u64,
    pub index: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsPacketBaselineRouteEvidence {
    pub capture_generation: u64,
    pub route_epoch: u64,
    pub destination: String,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub capture_interface: WindowsPacketInterfaceIdentity,
    pub egress_interface: WindowsPacketInterfaceIdentity,
    pub source_address: String,
    pub route_prefix: String,
    pub route_is_loopback: bool,
}

/// Exact route activation evidence that a future trusted native issuer must
/// produce while it owns and serializes the capture-route transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsPacketCaptureRouteActivationEvidence {
    pub capture_generation: u64,
    pub destination: String,
    pub route_prefix: String,
    pub previous_route_epoch: u64,
    pub active_route_epoch: u64,
    pub activated_at_ms: u64,
    pub capture_interface: WindowsPacketInterfaceIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsPacketEgressRequest {
    pub capture_generation: u64,
    pub flow_id: u64,
    pub destination: String,
    pub capture_started_at_ms: u64,
    pub now_ms: u64,
    pub current_route_epoch: u64,
    pub current_capture_interface: WindowsPacketInterfaceIdentity,
    pub current_egress_interface: WindowsPacketInterfaceIdentity,
    pub capture_route: WindowsPacketCaptureRouteActivationEvidence,
    pub baseline: WindowsPacketBaselineRouteEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPacketSocketInterfaceBinding {
    Ipv4NetworkByteOrder(u32),
    Ipv6HostByteOrder(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketEgressPlan {
    capture_generation: u64,
    flow_id: u64,
    route_epoch: u64,
    destination: IpAddr,
    source_address: IpAddr,
    egress_interface: WindowsPacketInterfaceIdentity,
    socket_binding: WindowsPacketSocketInterfaceBinding,
    expires_at_ms: u64,
}

impl WindowsPacketEgressPlan {
    pub const fn capture_generation(&self) -> u64 {
        self.capture_generation
    }

    pub const fn flow_id(&self) -> u64 {
        self.flow_id
    }

    pub const fn route_epoch(&self) -> u64 {
        self.route_epoch
    }

    pub const fn destination(&self) -> IpAddr {
        self.destination
    }

    pub const fn source_address(&self) -> IpAddr {
        self.source_address
    }

    pub const fn egress_interface(&self) -> WindowsPacketInterfaceIdentity {
        self.egress_interface
    }

    pub const fn socket_binding(&self) -> WindowsPacketSocketInterfaceBinding {
        self.socket_binding
    }

    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketEgressErrorCode {
    InvalidCaptureGeneration,
    InvalidFlowId,
    InvalidRouteEpoch,
    CaptureGenerationMismatch,
    CaptureRouteGenerationMismatch,
    CaptureRoutePreviousEpochMismatch,
    InvalidCaptureRouteEpochTransition,
    RouteEpochMismatch,
    InvalidActivationWindow,
    RouteObservedAfterCapture,
    InvalidCaptureRouteActivationWindow,
    InvalidEvidenceWindow,
    EvidenceExpired,
    DestinationNotCanonical,
    BaselineDestinationNotCanonical,
    UnsafeDestination,
    DestinationMismatch,
    CaptureRouteDestinationMismatch,
    CaptureRoutePrefixMismatch,
    InvalidInterfaceIdentity,
    CaptureInterfaceIdentityChanged,
    CaptureRouteInterfaceMismatch,
    EgressInterfaceIdentityChanged,
    CaptureInterfaceSelected,
    SourceAddressNotCanonical,
    SourceAddressFamilyMismatch,
    UnsafeSourceAddress,
    InvalidRoutePrefix,
    RoutePrefixFamilyMismatch,
    DestinationOutsideRoutePrefix,
    LoopbackRoute,
}

impl WindowsPacketEgressErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCaptureGeneration => "invalid_capture_generation",
            Self::InvalidFlowId => "invalid_flow_id",
            Self::InvalidRouteEpoch => "invalid_route_epoch",
            Self::CaptureGenerationMismatch => "capture_generation_mismatch",
            Self::CaptureRouteGenerationMismatch => "capture_route_generation_mismatch",
            Self::CaptureRoutePreviousEpochMismatch => "capture_route_previous_epoch_mismatch",
            Self::InvalidCaptureRouteEpochTransition => "invalid_capture_route_epoch_transition",
            Self::RouteEpochMismatch => "route_epoch_mismatch",
            Self::InvalidActivationWindow => "invalid_activation_window",
            Self::RouteObservedAfterCapture => "route_observed_after_capture",
            Self::InvalidCaptureRouteActivationWindow => "invalid_capture_route_activation_window",
            Self::InvalidEvidenceWindow => "invalid_evidence_window",
            Self::EvidenceExpired => "evidence_expired",
            Self::DestinationNotCanonical => "destination_not_canonical",
            Self::BaselineDestinationNotCanonical => "baseline_destination_not_canonical",
            Self::UnsafeDestination => "unsafe_destination",
            Self::DestinationMismatch => "destination_mismatch",
            Self::CaptureRouteDestinationMismatch => "capture_route_destination_mismatch",
            Self::CaptureRoutePrefixMismatch => "capture_route_prefix_mismatch",
            Self::InvalidInterfaceIdentity => "invalid_interface_identity",
            Self::CaptureInterfaceIdentityChanged => "capture_interface_identity_changed",
            Self::CaptureRouteInterfaceMismatch => "capture_route_interface_mismatch",
            Self::EgressInterfaceIdentityChanged => "egress_interface_identity_changed",
            Self::CaptureInterfaceSelected => "capture_interface_selected",
            Self::SourceAddressNotCanonical => "source_address_not_canonical",
            Self::SourceAddressFamilyMismatch => "source_address_family_mismatch",
            Self::UnsafeSourceAddress => "unsafe_source_address",
            Self::InvalidRoutePrefix => "invalid_route_prefix",
            Self::RoutePrefixFamilyMismatch => "route_prefix_family_mismatch",
            Self::DestinationOutsideRoutePrefix => "destination_outside_route_prefix",
            Self::LoopbackRoute => "loopback_route",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsPacketEgressError {
    code: WindowsPacketEgressErrorCode,
}

impl WindowsPacketEgressError {
    const fn new(code: WindowsPacketEgressErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> WindowsPacketEgressErrorCode {
        self.code
    }
}

pub fn prepare_windows_packet_egress(
    request: &WindowsPacketEgressRequest,
) -> Result<WindowsPacketEgressPlan, WindowsPacketEgressError> {
    use WindowsPacketEgressErrorCode as Code;

    if request.capture_generation == 0 {
        return Err(WindowsPacketEgressError::new(
            Code::InvalidCaptureGeneration,
        ));
    }
    if request.flow_id == 0 {
        return Err(WindowsPacketEgressError::new(Code::InvalidFlowId));
    }
    if request.current_route_epoch == 0
        || request.baseline.route_epoch == 0
        || request.capture_route.previous_route_epoch == 0
        || request.capture_route.active_route_epoch == 0
    {
        return Err(WindowsPacketEgressError::new(Code::InvalidRouteEpoch));
    }
    if request.baseline.capture_generation != request.capture_generation {
        return Err(WindowsPacketEgressError::new(
            Code::CaptureGenerationMismatch,
        ));
    }
    if request.capture_route.capture_generation != request.capture_generation {
        return Err(WindowsPacketEgressError::new(
            Code::CaptureRouteGenerationMismatch,
        ));
    }
    if request.capture_route.previous_route_epoch != request.baseline.route_epoch {
        return Err(WindowsPacketEgressError::new(
            Code::CaptureRoutePreviousEpochMismatch,
        ));
    }
    if request.capture_route.active_route_epoch <= request.capture_route.previous_route_epoch {
        return Err(WindowsPacketEgressError::new(
            Code::InvalidCaptureRouteEpochTransition,
        ));
    }
    if request.capture_route.active_route_epoch != request.current_route_epoch {
        return Err(WindowsPacketEgressError::new(Code::RouteEpochMismatch));
    }
    if request.now_ms < request.capture_started_at_ms {
        return Err(WindowsPacketEgressError::new(Code::InvalidActivationWindow));
    }
    if request.baseline.observed_at_ms > request.capture_started_at_ms {
        return Err(WindowsPacketEgressError::new(
            Code::RouteObservedAfterCapture,
        ));
    }
    if request.capture_route.activated_at_ms < request.baseline.observed_at_ms
        || request.capture_route.activated_at_ms > request.capture_started_at_ms
    {
        return Err(WindowsPacketEgressError::new(
            Code::InvalidCaptureRouteActivationWindow,
        ));
    }
    if request.baseline.observed_at_ms >= request.baseline.expires_at_ms
        || request
            .baseline
            .expires_at_ms
            .saturating_sub(request.baseline.observed_at_ms)
            > MAX_PACKET_EGRESS_EVIDENCE_LIFETIME_MS
        || request.capture_started_at_ms >= request.baseline.expires_at_ms
        || request.now_ms < request.baseline.observed_at_ms
    {
        return Err(WindowsPacketEgressError::new(Code::InvalidEvidenceWindow));
    }
    if request.now_ms >= request.baseline.expires_at_ms {
        return Err(WindowsPacketEgressError::new(Code::EvidenceExpired));
    }

    let destination = parse_canonical_ip(&request.destination)
        .ok_or_else(|| WindowsPacketEgressError::new(Code::DestinationNotCanonical))?;
    let baseline_destination = parse_canonical_ip(&request.baseline.destination)
        .ok_or_else(|| WindowsPacketEgressError::new(Code::BaselineDestinationNotCanonical))?;
    if !is_safe_public_destination(destination) {
        return Err(WindowsPacketEgressError::new(Code::UnsafeDestination));
    }
    if baseline_destination != destination {
        return Err(WindowsPacketEgressError::new(Code::DestinationMismatch));
    }
    let capture_route_destination = parse_canonical_ip(&request.capture_route.destination)
        .ok_or_else(|| WindowsPacketEgressError::new(Code::CaptureRouteDestinationMismatch))?;
    if capture_route_destination != destination {
        return Err(WindowsPacketEgressError::new(
            Code::CaptureRouteDestinationMismatch,
        ));
    }

    for identity in [
        request.baseline.capture_interface,
        request.baseline.egress_interface,
        request.capture_route.capture_interface,
        request.current_capture_interface,
        request.current_egress_interface,
    ] {
        if identity.luid == 0 || identity.index == 0 {
            return Err(WindowsPacketEgressError::new(
                Code::InvalidInterfaceIdentity,
            ));
        }
    }
    if request.current_capture_interface != request.baseline.capture_interface {
        return Err(WindowsPacketEgressError::new(
            Code::CaptureInterfaceIdentityChanged,
        ));
    }
    if request.capture_route.capture_interface != request.baseline.capture_interface {
        return Err(WindowsPacketEgressError::new(
            Code::CaptureRouteInterfaceMismatch,
        ));
    }
    if request.current_egress_interface != request.baseline.egress_interface {
        return Err(WindowsPacketEgressError::new(
            Code::EgressInterfaceIdentityChanged,
        ));
    }
    if request.baseline.egress_interface.luid == request.baseline.capture_interface.luid
        || request.baseline.egress_interface.index == request.baseline.capture_interface.index
    {
        return Err(WindowsPacketEgressError::new(
            Code::CaptureInterfaceSelected,
        ));
    }
    if request.baseline.route_is_loopback {
        return Err(WindowsPacketEgressError::new(Code::LoopbackRoute));
    }

    let source_address = parse_canonical_ip(&request.baseline.source_address)
        .ok_or_else(|| WindowsPacketEgressError::new(Code::SourceAddressNotCanonical))?;
    if !same_family(destination, source_address) {
        return Err(WindowsPacketEgressError::new(
            Code::SourceAddressFamilyMismatch,
        ));
    }
    if !is_usable_source_address(source_address) {
        return Err(WindowsPacketEgressError::new(Code::UnsafeSourceAddress));
    }

    let (route_network, prefix_length) = parse_canonical_prefix(&request.baseline.route_prefix)
        .ok_or_else(|| WindowsPacketEgressError::new(Code::InvalidRoutePrefix))?;
    if !same_family(destination, route_network) {
        return Err(WindowsPacketEgressError::new(
            Code::RoutePrefixFamilyMismatch,
        ));
    }
    if !prefix_contains(route_network, prefix_length, destination) {
        return Err(WindowsPacketEgressError::new(
            Code::DestinationOutsideRoutePrefix,
        ));
    }
    let (capture_route_network, capture_route_prefix_length) =
        parse_canonical_prefix(&request.capture_route.route_prefix)
            .ok_or_else(|| WindowsPacketEgressError::new(Code::CaptureRoutePrefixMismatch))?;
    let expected_capture_prefix_length = match destination {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if capture_route_network != destination
        || capture_route_prefix_length != expected_capture_prefix_length
    {
        return Err(WindowsPacketEgressError::new(
            Code::CaptureRoutePrefixMismatch,
        ));
    }

    let socket_binding = match destination {
        IpAddr::V4(_) => WindowsPacketSocketInterfaceBinding::Ipv4NetworkByteOrder(
            request.baseline.egress_interface.index.to_be(),
        ),
        IpAddr::V6(_) => WindowsPacketSocketInterfaceBinding::Ipv6HostByteOrder(
            request.baseline.egress_interface.index,
        ),
    };

    Ok(WindowsPacketEgressPlan {
        capture_generation: request.capture_generation,
        flow_id: request.flow_id,
        route_epoch: request.current_route_epoch,
        destination,
        source_address,
        egress_interface: request.baseline.egress_interface,
        socket_binding,
        expires_at_ms: request.baseline.expires_at_ms,
    })
}

fn parse_canonical_ip(value: &str) -> Option<IpAddr> {
    let address = value.parse::<IpAddr>().ok()?;
    (address.to_string() == value).then_some(address)
}

fn parse_canonical_prefix(value: &str) -> Option<(IpAddr, u8)> {
    let (network, prefix) = value.split_once('/')?;
    let network = parse_canonical_ip(network)?;
    let prefix = prefix.parse::<u8>().ok()?;
    if prefix.to_string() != value.rsplit_once('/')?.1 {
        return None;
    }
    let valid = match network {
        IpAddr::V4(address) if prefix <= 32 => {
            let bits = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            bits & !mask == 0
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let bits = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            bits & !mask == 0
        }
        _ => false,
    };
    valid.then_some((network, prefix))
}

fn prefix_contains(network: IpAddr, prefix: u8, destination: IpAddr) -> bool {
    match (network, destination) {
        (IpAddr::V4(network), IpAddr::V4(destination)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) == u32::from(destination) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(destination)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) == u128::from(destination) & mask
        }
        _ => false,
    }
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn is_usable_source_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_usable_source_ipv4(address),
        IpAddr::V6(address) => {
            let segments = address.segments();
            (segments[0] & 0xfe00) == 0xfc00 || is_safe_public_ipv6(address)
        }
    }
}

fn is_usable_source_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    is_safe_public_ipv4(address)
        || a == 10
        || (a == 100 && (64..=127).contains(&b))
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
}

fn is_safe_public_destination(destination: IpAddr) -> bool {
    match destination {
        IpAddr::V4(address) => is_safe_public_ipv4(address),
        IpAddr::V6(address) => is_safe_public_ipv6(address),
    }
}

fn is_safe_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn is_safe_public_ipv6(address: Ipv6Addr) -> bool {
    // The positive allocation registry is not enough by itself: these assigned
    // prefixes are explicitly not globally reachable in the IANA
    // special-purpose registry frozen alongside this contract.
    if [
        (Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28),
        (Ipv6Addr::new(0x2001, 0x0030, 0, 0, 0, 0, 0, 0), 28),
        (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
    ]
    .into_iter()
    .any(|(network, prefix_length)| ipv6_in_prefix(address, network, prefix_length))
    {
        return false;
    }

    // Frozen from the IANA IPv6 Global Unicast Address Space registry dated
    // 2025-10-10. Unlisted space inside 2000::/3 is reserved and must fail
    // closed until a new contract version reviews a later registry snapshot.
    [
        (Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 1), 128),
        (Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 2), 128),
        (Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 3), 128),
        (Ipv6Addr::new(0x2001, 0x0003, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x2001, 0x0004, 0x0112, 0, 0, 0, 0, 0), 48),
        (Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28),
        (Ipv6Addr::new(0x2001, 0x0030, 0, 0, 0, 0, 0, 0), 28),
        (Ipv6Addr::new(0x2001, 0x0200, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x0400, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x0600, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x0800, 0, 0, 0, 0, 0, 0), 22),
        (Ipv6Addr::new(0x2001, 0x0c00, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x0e00, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x1200, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x1400, 0, 0, 0, 0, 0, 0), 22),
        (Ipv6Addr::new(0x2001, 0x1800, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x1a00, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x1c00, 0, 0, 0, 0, 0, 0), 22),
        (Ipv6Addr::new(0x2001, 0x2000, 0, 0, 0, 0, 0, 0), 19),
        (Ipv6Addr::new(0x2001, 0x4000, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4200, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4400, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4600, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4800, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4a00, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4c00, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x5000, 0, 0, 0, 0, 0, 0), 20),
        (Ipv6Addr::new(0x2001, 0x8000, 0, 0, 0, 0, 0, 0), 19),
        (Ipv6Addr::new(0x2001, 0xa000, 0, 0, 0, 0, 0, 0), 20),
        (Ipv6Addr::new(0x2001, 0xb000, 0, 0, 0, 0, 0, 0), 20),
        (Ipv6Addr::new(0x2003, 0, 0, 0, 0, 0, 0, 0), 18),
        (Ipv6Addr::new(0x2400, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2410, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2600, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2610, 0, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2620, 0, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2630, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2800, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2a00, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2a10, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2c00, 0, 0, 0, 0, 0, 0, 0), 12),
    ]
    .into_iter()
    .any(|(network, prefix_length)| ipv6_in_prefix(address, network, prefix_length))
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix_length: u8) -> bool {
    let mask = u128::MAX << (128 - prefix_length);
    u128::from(address) & mask == u128::from(network) & mask
}

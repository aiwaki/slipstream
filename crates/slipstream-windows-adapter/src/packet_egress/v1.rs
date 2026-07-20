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
    RouteEpochMismatch,
    InvalidActivationWindow,
    RouteObservedAfterCapture,
    InvalidEvidenceWindow,
    EvidenceExpired,
    DestinationNotCanonical,
    BaselineDestinationNotCanonical,
    UnsafeDestination,
    DestinationMismatch,
    InvalidInterfaceIdentity,
    CaptureInterfaceIdentityChanged,
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
            Self::RouteEpochMismatch => "route_epoch_mismatch",
            Self::InvalidActivationWindow => "invalid_activation_window",
            Self::RouteObservedAfterCapture => "route_observed_after_capture",
            Self::InvalidEvidenceWindow => "invalid_evidence_window",
            Self::EvidenceExpired => "evidence_expired",
            Self::DestinationNotCanonical => "destination_not_canonical",
            Self::BaselineDestinationNotCanonical => "baseline_destination_not_canonical",
            Self::UnsafeDestination => "unsafe_destination",
            Self::DestinationMismatch => "destination_mismatch",
            Self::InvalidInterfaceIdentity => "invalid_interface_identity",
            Self::CaptureInterfaceIdentityChanged => "capture_interface_identity_changed",
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
    if request.current_route_epoch == 0 || request.baseline.route_epoch == 0 {
        return Err(WindowsPacketEgressError::new(Code::InvalidRouteEpoch));
    }
    if request.baseline.capture_generation != request.capture_generation {
        return Err(WindowsPacketEgressError::new(
            Code::CaptureGenerationMismatch,
        ));
    }
    if request.baseline.route_epoch != request.current_route_epoch {
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

    for identity in [
        request.baseline.capture_interface,
        request.baseline.egress_interface,
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
        IpAddr::V4(address) => {
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_link_local())
        }
        IpAddr::V6(address) => {
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (address.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
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
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn is_safe_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4() {
        return is_safe_public_ipv4(mapped);
    }
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

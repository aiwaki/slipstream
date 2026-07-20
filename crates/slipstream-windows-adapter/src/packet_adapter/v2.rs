//! Version 2 capture-only packet classification for Windows.
//!
//! This pure boundary classifies one already-captured flow from bounded
//! in-band hostname evidence. It does not choose or authorize a backend, load
//! Wintun, create an adapter, install a route, open a socket, or compose the
//! production service host. Opaque or invalid evidence always stays on the
//! original direct path.

use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::{
    classify_route_policy, normalize_host, RouteClass, RoutePolicyResult, RoutingPolicyTables,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const WINDOWS_PACKET_CAPTURE_CONTRACT_VERSION: u32 = 2;
pub const MAX_PACKET_CAPTURE_EVIDENCE_LIFETIME_MS: u64 = 5_000;
const MAX_HOST_BYTES: usize = 253;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketCaptureTransport {
    TcpTls,
    UdpQuic,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketHostnameEvidenceSource {
    TlsClientHelloSni,
    QuicInitialSni,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketOpaqueReason {
    HostnameMissing,
    EncryptedClientHello,
    AmbiguousHostname,
    MalformedHandshake,
    UnsupportedTransport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsPacketCaptureAttribution {
    Hostname {
        source: WindowsPacketHostnameEvidenceSource,
        host: String,
    },
    Opaque {
        reason: WindowsPacketOpaqueReason,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsPacketCaptureObservation {
    pub capture_generation: u64,
    pub flow_id: u64,
    pub transport: WindowsPacketCaptureTransport,
    pub destination: String,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub attribution: WindowsPacketCaptureAttribution,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketCapturePassthroughReason {
    InvalidCaptureGeneration,
    InvalidFlowId,
    DestinationNotCanonical,
    UnsafeDestination,
    InvalidEvidenceWindow,
    EvidenceExpired,
    OpaqueHostname,
    InvalidHostname,
    EvidenceTransportMismatch,
    DirectPolicy,
    UnknownPolicy,
}

impl WindowsPacketCapturePassthroughReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCaptureGeneration => "invalid_capture_generation",
            Self::InvalidFlowId => "invalid_flow_id",
            Self::DestinationNotCanonical => "destination_not_canonical",
            Self::UnsafeDestination => "unsafe_destination",
            Self::InvalidEvidenceWindow => "invalid_evidence_window",
            Self::EvidenceExpired => "evidence_expired",
            Self::OpaqueHostname => "opaque_hostname",
            Self::InvalidHostname => "invalid_hostname",
            Self::EvidenceTransportMismatch => "evidence_transport_mismatch",
            Self::DirectPolicy => "direct_policy",
            Self::UnknownPolicy => "unknown_policy",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketPolicyClassification {
    capture_generation: u64,
    flow_id: u64,
    transport: WindowsPacketCaptureTransport,
    destination: IpAddr,
    evidence_source: WindowsPacketHostnameEvidenceSource,
    expires_at_ms: u64,
    policy: RoutePolicyResult,
}

impl WindowsPacketPolicyClassification {
    pub const fn capture_generation(&self) -> u64 {
        self.capture_generation
    }

    pub const fn flow_id(&self) -> u64 {
        self.flow_id
    }

    pub const fn transport(&self) -> WindowsPacketCaptureTransport {
        self.transport
    }

    pub const fn destination(&self) -> IpAddr {
        self.destination
    }

    pub const fn evidence_source(&self) -> WindowsPacketHostnameEvidenceSource {
        self.evidence_source
    }

    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn policy(&self) -> &RoutePolicyResult {
        &self.policy
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsPacketCaptureDecision {
    DirectPassthrough {
        reason: WindowsPacketCapturePassthroughReason,
        opaque_reason: Option<WindowsPacketOpaqueReason>,
    },
    PolicyClassified(WindowsPacketPolicyClassification),
}

fn direct(
    reason: WindowsPacketCapturePassthroughReason,
    opaque_reason: Option<WindowsPacketOpaqueReason>,
) -> WindowsPacketCaptureDecision {
    WindowsPacketCaptureDecision::DirectPassthrough {
        reason,
        opaque_reason,
    }
}

pub fn classify_windows_packet_capture(
    observation: &WindowsPacketCaptureObservation,
    now_ms: u64,
    policy_tables: &RoutingPolicyTables,
) -> WindowsPacketCaptureDecision {
    if observation.capture_generation == 0 {
        return direct(
            WindowsPacketCapturePassthroughReason::InvalidCaptureGeneration,
            None,
        );
    }
    if observation.flow_id == 0 {
        return direct(WindowsPacketCapturePassthroughReason::InvalidFlowId, None);
    }

    let destination = match observation.destination.parse::<IpAddr>() {
        Ok(destination) if destination.to_string() == observation.destination => destination,
        _ => {
            return direct(
                WindowsPacketCapturePassthroughReason::DestinationNotCanonical,
                None,
            )
        }
    };
    if !is_safe_public_destination(destination) {
        return direct(
            WindowsPacketCapturePassthroughReason::UnsafeDestination,
            None,
        );
    }

    if observation.observed_at_ms >= observation.expires_at_ms
        || observation
            .expires_at_ms
            .saturating_sub(observation.observed_at_ms)
            > MAX_PACKET_CAPTURE_EVIDENCE_LIFETIME_MS
        || now_ms < observation.observed_at_ms
    {
        return direct(
            WindowsPacketCapturePassthroughReason::InvalidEvidenceWindow,
            None,
        );
    }
    if now_ms >= observation.expires_at_ms {
        return direct(WindowsPacketCapturePassthroughReason::EvidenceExpired, None);
    }

    let (source, host) = match &observation.attribution {
        WindowsPacketCaptureAttribution::Opaque { reason } => {
            return direct(
                WindowsPacketCapturePassthroughReason::OpaqueHostname,
                Some(*reason),
            )
        }
        WindowsPacketCaptureAttribution::Hostname { source, host } => (*source, host),
    };
    if !evidence_matches_transport(source, observation.transport) {
        return direct(
            WindowsPacketCapturePassthroughReason::EvidenceTransportMismatch,
            None,
        );
    }

    let normalized_host = normalize_host(host);
    if !is_valid_normalized_hostname(&normalized_host) {
        return direct(WindowsPacketCapturePassthroughReason::InvalidHostname, None);
    }
    let policy = classify_route_policy(&normalized_host, policy_tables);
    match policy.route_class {
        RouteClass::LocalBypass | RouteClass::GeoExit => {
            WindowsPacketCaptureDecision::PolicyClassified(WindowsPacketPolicyClassification {
                capture_generation: observation.capture_generation,
                flow_id: observation.flow_id,
                transport: observation.transport,
                destination,
                evidence_source: source,
                expires_at_ms: observation.expires_at_ms,
                policy,
            })
        }
        RouteClass::DirectPassthrough | RouteClass::DirectFirst => {
            direct(WindowsPacketCapturePassthroughReason::DirectPolicy, None)
        }
        RouteClass::Unknown => direct(WindowsPacketCapturePassthroughReason::UnknownPolicy, None),
    }
}

fn evidence_matches_transport(
    source: WindowsPacketHostnameEvidenceSource,
    transport: WindowsPacketCaptureTransport,
) -> bool {
    matches!(
        (source, transport),
        (
            WindowsPacketHostnameEvidenceSource::TlsClientHelloSni,
            WindowsPacketCaptureTransport::TcpTls
        ) | (
            WindowsPacketHostnameEvidenceSource::QuicInitialSni,
            WindowsPacketCaptureTransport::UdpQuic
        )
    )
}

fn is_valid_normalized_hostname(host: &str) -> bool {
    if host.is_empty()
        || host.len() > MAX_HOST_BYTES
        || !host.is_ascii()
        || normalize_host(host) != host
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
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

//! Version 4 capture-only packet classification for Windows.
//!
//! V4 preserves the frozen v3 policy decision and binds the original client
//! source endpoint only after v3 classifies the flow. The endpoint is data for
//! a future userspace-stack bridge, not backend authorization. This module
//! performs no native or network effect.

use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::{RoutePolicyResult, RoutingPolicyTables};
use std::net::{IpAddr, Ipv4Addr};

use super::v3::{
    classify_windows_packet_capture as classify_v3, WindowsPacketCaptureDecision as V3Decision,
    WindowsPacketCaptureObservation as V3Observation,
    WindowsPacketCapturePassthroughReason as V3PassthroughReason,
    WindowsPacketPolicyClassification as V3Classification,
};
pub use super::v3::{
    WindowsPacketCaptureAttribution, WindowsPacketCaptureTransport,
    WindowsPacketHostnameEvidenceSource, WindowsPacketOpaqueReason,
    MAX_PACKET_CAPTURE_EVIDENCE_LIFETIME_MS,
};

pub const WINDOWS_PACKET_CAPTURE_CONTRACT_VERSION: u32 = 4;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WindowsPacketEndpoint {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsPacketCaptureObservation {
    pub capture_generation: u64,
    pub flow_id: u64,
    pub transport: WindowsPacketCaptureTransport,
    pub source_address: IpAddr,
    pub source_port: u16,
    pub destination: String,
    pub destination_port: u16,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub attribution: WindowsPacketCaptureAttribution,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketCapturePassthroughReason {
    InvalidCaptureGeneration,
    InvalidFlowId,
    InvalidSourcePort,
    UnsafeSourceAddress,
    AddressFamilyMismatch,
    InvalidDestinationPort,
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
            Self::InvalidSourcePort => "invalid_source_port",
            Self::UnsafeSourceAddress => "unsafe_source_address",
            Self::AddressFamilyMismatch => "address_family_mismatch",
            Self::InvalidDestinationPort => "invalid_destination_port",
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

impl From<V3PassthroughReason> for WindowsPacketCapturePassthroughReason {
    fn from(reason: V3PassthroughReason) -> Self {
        match reason {
            V3PassthroughReason::InvalidCaptureGeneration => Self::InvalidCaptureGeneration,
            V3PassthroughReason::InvalidFlowId => Self::InvalidFlowId,
            V3PassthroughReason::InvalidDestinationPort => Self::InvalidDestinationPort,
            V3PassthroughReason::DestinationNotCanonical => Self::DestinationNotCanonical,
            V3PassthroughReason::UnsafeDestination => Self::UnsafeDestination,
            V3PassthroughReason::InvalidEvidenceWindow => Self::InvalidEvidenceWindow,
            V3PassthroughReason::EvidenceExpired => Self::EvidenceExpired,
            V3PassthroughReason::OpaqueHostname => Self::OpaqueHostname,
            V3PassthroughReason::InvalidHostname => Self::InvalidHostname,
            V3PassthroughReason::EvidenceTransportMismatch => Self::EvidenceTransportMismatch,
            V3PassthroughReason::DirectPolicy => Self::DirectPolicy,
            V3PassthroughReason::UnknownPolicy => Self::UnknownPolicy,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketPolicyClassification {
    inner: V3Classification,
    source_endpoint: WindowsPacketEndpoint,
}

impl WindowsPacketPolicyClassification {
    pub const fn capture_generation(&self) -> u64 {
        self.inner.capture_generation()
    }

    pub const fn flow_id(&self) -> u64 {
        self.inner.flow_id()
    }

    pub const fn transport(&self) -> WindowsPacketCaptureTransport {
        self.inner.transport()
    }

    pub const fn source_endpoint(&self) -> WindowsPacketEndpoint {
        self.source_endpoint
    }

    pub const fn destination(&self) -> IpAddr {
        self.inner.destination()
    }

    pub const fn destination_port(&self) -> u16 {
        self.inner.destination_port()
    }

    pub const fn evidence_source(&self) -> WindowsPacketHostnameEvidenceSource {
        self.inner.evidence_source()
    }

    pub const fn expires_at_ms(&self) -> u64 {
        self.inner.expires_at_ms()
    }

    pub fn policy(&self) -> &RoutePolicyResult {
        self.inner.policy()
    }

    pub const fn v3_classification(&self) -> &V3Classification {
        &self.inner
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

fn source_address_is_safe(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && address != IpAddr::V4(Ipv4Addr::BROADCAST)
}

fn same_address_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

pub fn classify_windows_packet_capture(
    observation: &WindowsPacketCaptureObservation,
    now_ms: u64,
    policy_tables: &RoutingPolicyTables,
) -> WindowsPacketCaptureDecision {
    let v3_observation = V3Observation {
        capture_generation: observation.capture_generation,
        flow_id: observation.flow_id,
        transport: observation.transport,
        destination: observation.destination.clone(),
        destination_port: observation.destination_port,
        observed_at_ms: observation.observed_at_ms,
        expires_at_ms: observation.expires_at_ms,
        attribution: observation.attribution.clone(),
    };
    let inner = match classify_v3(&v3_observation, now_ms, policy_tables) {
        V3Decision::DirectPassthrough {
            reason,
            opaque_reason,
        } => {
            return WindowsPacketCaptureDecision::DirectPassthrough {
                reason: reason.into(),
                opaque_reason,
            }
        }
        V3Decision::PolicyClassified(classification) => classification,
    };

    let reason = if observation.source_port == 0 {
        Some(WindowsPacketCapturePassthroughReason::InvalidSourcePort)
    } else if !source_address_is_safe(observation.source_address) {
        Some(WindowsPacketCapturePassthroughReason::UnsafeSourceAddress)
    } else if !same_address_family(observation.source_address, inner.destination()) {
        Some(WindowsPacketCapturePassthroughReason::AddressFamilyMismatch)
    } else {
        None
    };
    if let Some(reason) = reason {
        return WindowsPacketCaptureDecision::DirectPassthrough {
            reason,
            opaque_reason: None,
        };
    }

    WindowsPacketCaptureDecision::PolicyClassified(WindowsPacketPolicyClassification {
        inner,
        source_endpoint: WindowsPacketEndpoint {
            address: observation.source_address,
            port: observation.source_port,
        },
    })
}

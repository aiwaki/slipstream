//! Version 3 capture-only packet classification for Windows.
//!
//! V3 preserves the frozen v2 classification behavior and adds the original
//! destination port to the per-flow evidence. The port is data, not backend
//! authorization: this module still performs no native or network effect.

use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::{RoutePolicyResult, RoutingPolicyTables};
use std::net::IpAddr;

use super::v2::{
    classify_windows_packet_capture as classify_v2, WindowsPacketCaptureDecision as V2Decision,
    WindowsPacketCaptureObservation as V2Observation,
    WindowsPacketCapturePassthroughReason as V2PassthroughReason,
    WindowsPacketPolicyClassification as V2Classification,
};
pub use super::v2::{
    WindowsPacketCaptureAttribution, WindowsPacketCaptureTransport,
    WindowsPacketHostnameEvidenceSource, WindowsPacketOpaqueReason,
    MAX_PACKET_CAPTURE_EVIDENCE_LIFETIME_MS,
};

pub const WINDOWS_PACKET_CAPTURE_CONTRACT_VERSION: u32 = 3;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsPacketCaptureObservation {
    pub capture_generation: u64,
    pub flow_id: u64,
    pub transport: WindowsPacketCaptureTransport,
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

impl From<V2PassthroughReason> for WindowsPacketCapturePassthroughReason {
    fn from(reason: V2PassthroughReason) -> Self {
        match reason {
            V2PassthroughReason::InvalidCaptureGeneration => Self::InvalidCaptureGeneration,
            V2PassthroughReason::InvalidFlowId => Self::InvalidFlowId,
            V2PassthroughReason::DestinationNotCanonical => Self::DestinationNotCanonical,
            V2PassthroughReason::UnsafeDestination => Self::UnsafeDestination,
            V2PassthroughReason::InvalidEvidenceWindow => Self::InvalidEvidenceWindow,
            V2PassthroughReason::EvidenceExpired => Self::EvidenceExpired,
            V2PassthroughReason::OpaqueHostname => Self::OpaqueHostname,
            V2PassthroughReason::InvalidHostname => Self::InvalidHostname,
            V2PassthroughReason::EvidenceTransportMismatch => Self::EvidenceTransportMismatch,
            V2PassthroughReason::DirectPolicy => Self::DirectPolicy,
            V2PassthroughReason::UnknownPolicy => Self::UnknownPolicy,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketPolicyClassification {
    inner: V2Classification,
    destination_port: u16,
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

    pub const fn destination(&self) -> IpAddr {
        self.inner.destination()
    }

    pub const fn destination_port(&self) -> u16 {
        self.destination_port
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsPacketCaptureDecision {
    DirectPassthrough {
        reason: WindowsPacketCapturePassthroughReason,
        opaque_reason: Option<WindowsPacketOpaqueReason>,
    },
    PolicyClassified(WindowsPacketPolicyClassification),
}

pub fn classify_windows_packet_capture(
    observation: &WindowsPacketCaptureObservation,
    now_ms: u64,
    policy_tables: &RoutingPolicyTables,
) -> WindowsPacketCaptureDecision {
    if observation.destination_port == 0 {
        return WindowsPacketCaptureDecision::DirectPassthrough {
            reason: WindowsPacketCapturePassthroughReason::InvalidDestinationPort,
            opaque_reason: None,
        };
    }

    let v2_observation = V2Observation {
        capture_generation: observation.capture_generation,
        flow_id: observation.flow_id,
        transport: observation.transport,
        destination: observation.destination.clone(),
        observed_at_ms: observation.observed_at_ms,
        expires_at_ms: observation.expires_at_ms,
        attribution: observation.attribution.clone(),
    };
    match classify_v2(&v2_observation, now_ms, policy_tables) {
        V2Decision::DirectPassthrough {
            reason,
            opaque_reason,
        } => WindowsPacketCaptureDecision::DirectPassthrough {
            reason: reason.into(),
            opaque_reason,
        },
        V2Decision::PolicyClassified(inner) => {
            WindowsPacketCaptureDecision::PolicyClassified(WindowsPacketPolicyClassification {
                inner,
                destination_port: observation.destination_port,
            })
        }
    }
}

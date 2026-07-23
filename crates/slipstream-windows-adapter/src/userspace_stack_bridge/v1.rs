//! Version 1 pure original-tuple binding for the future Windows userspace stack.
//!
//! The binding joins capture v4 source evidence to an already-admitted frozen
//! packet-flow v1 capability. It does not parse packets, own payload bytes,
//! instantiate a userspace stack, or perform any native or network effect.

use crate::packet_adapter::v4::{
    WindowsPacketCaptureTransport, WindowsPacketEndpoint, WindowsPacketPolicyClassification,
};
use crate::packet_flow::{
    WindowsPacketFlowAdmission, WindowsPacketFlowKey, WindowsPacketFlowTransport,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const WINDOWS_USERSPACE_FLOW_BINDING_CONTRACT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WindowsUserspaceFlowTuple {
    pub transport: WindowsPacketFlowTransport,
    pub source: WindowsPacketEndpoint,
    pub destination: WindowsPacketEndpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsUserspaceFlowBinding {
    key: WindowsPacketFlowKey,
    tuple: WindowsUserspaceFlowTuple,
    admission: WindowsPacketFlowAdmission,
    expires_at_ms: u64,
}

impl WindowsUserspaceFlowBinding {
    pub const fn key(&self) -> WindowsPacketFlowKey {
        self.key
    }

    pub const fn tuple(&self) -> WindowsUserspaceFlowTuple {
        self.tuple
    }

    pub const fn admission(&self) -> &WindowsPacketFlowAdmission {
        &self.admission
    }

    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsUserspaceFlowBindingErrorCode {
    UnsupportedTransport,
    ClassificationExpired,
    AdmissionExpired,
    CaptureGenerationMismatch,
    FlowIdMismatch,
    TransportMismatch,
    InvalidAdmissionDestination,
    DestinationAddressMismatch,
    DestinationPortMismatch,
    AddressFamilyMismatch,
    PolicyMismatch,
}

impl WindowsUserspaceFlowBindingErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedTransport => "unsupported_transport",
            Self::ClassificationExpired => "classification_expired",
            Self::AdmissionExpired => "admission_expired",
            Self::CaptureGenerationMismatch => "capture_generation_mismatch",
            Self::FlowIdMismatch => "flow_id_mismatch",
            Self::TransportMismatch => "transport_mismatch",
            Self::InvalidAdmissionDestination => "invalid_admission_destination",
            Self::DestinationAddressMismatch => "destination_address_mismatch",
            Self::DestinationPortMismatch => "destination_port_mismatch",
            Self::AddressFamilyMismatch => "address_family_mismatch",
            Self::PolicyMismatch => "policy_mismatch",
        }
    }
}

fn flow_transport(
    transport: WindowsPacketCaptureTransport,
) -> Result<WindowsPacketFlowTransport, WindowsUserspaceFlowBindingErrorCode> {
    match transport {
        WindowsPacketCaptureTransport::TcpTls => Ok(WindowsPacketFlowTransport::Tcp),
        WindowsPacketCaptureTransport::UdpQuic => Ok(WindowsPacketFlowTransport::Udp),
        WindowsPacketCaptureTransport::Other => {
            Err(WindowsUserspaceFlowBindingErrorCode::UnsupportedTransport)
        }
    }
}

fn same_address_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

pub fn bind_windows_userspace_flow(
    classification: &WindowsPacketPolicyClassification,
    admission: &WindowsPacketFlowAdmission,
    now_ms: u64,
) -> Result<WindowsUserspaceFlowBinding, WindowsUserspaceFlowBindingErrorCode> {
    let transport = flow_transport(classification.transport())?;
    if now_ms >= classification.expires_at_ms() {
        return Err(WindowsUserspaceFlowBindingErrorCode::ClassificationExpired);
    }
    if now_ms >= admission.expires_at_ms() {
        return Err(WindowsUserspaceFlowBindingErrorCode::AdmissionExpired);
    }

    let key = admission.key();
    if classification.capture_generation() != key.capture_generation {
        return Err(WindowsUserspaceFlowBindingErrorCode::CaptureGenerationMismatch);
    }
    if classification.flow_id() != key.flow_id {
        return Err(WindowsUserspaceFlowBindingErrorCode::FlowIdMismatch);
    }
    if transport != key.transport {
        return Err(WindowsUserspaceFlowBindingErrorCode::TransportMismatch);
    }

    let admission_destination = admission
        .destination()
        .parse::<IpAddr>()
        .map_err(|_| WindowsUserspaceFlowBindingErrorCode::InvalidAdmissionDestination)?;
    if classification.destination() != admission_destination {
        return Err(WindowsUserspaceFlowBindingErrorCode::DestinationAddressMismatch);
    }
    if classification.destination_port() != admission.destination_port() {
        return Err(WindowsUserspaceFlowBindingErrorCode::DestinationPortMismatch);
    }
    if !same_address_family(
        classification.source_endpoint().address,
        classification.destination(),
    ) {
        return Err(WindowsUserspaceFlowBindingErrorCode::AddressFamilyMismatch);
    }
    if admission.request().policy != *classification.policy() {
        return Err(WindowsUserspaceFlowBindingErrorCode::PolicyMismatch);
    }

    Ok(WindowsUserspaceFlowBinding {
        key,
        tuple: WindowsUserspaceFlowTuple {
            transport,
            source: classification.source_endpoint(),
            destination: WindowsPacketEndpoint {
                address: classification.destination(),
                port: classification.destination_port(),
            },
        },
        admission: admission.clone(),
        expires_at_ms: classification
            .expires_at_ms()
            .min(admission.expires_at_ms()),
    })
}

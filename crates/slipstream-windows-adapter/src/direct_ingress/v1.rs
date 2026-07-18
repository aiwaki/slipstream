//! Version 1 contract for an adapter-owned Windows direct client stream.
//!
//! This boundary does not accept a hostname resolver, route selector, or OS
//! interception API. It binds one already-admitted direct connector request to
//! fresh numeric original-destination evidence and to one opaque connection ID.

use crate::data_plane::WindowsDataPlaneEvent;
use crate::direct_connector::{
    prepare_windows_direct_connector, WindowsDirectConnectorCancelReason,
    WindowsDirectConnectorEndpoint, WindowsDirectConnectorEvent, WindowsDirectConnectorPlan,
    WindowsDirectConnectorRequest, WindowsDirectConnectorRequestErrorCode,
};
use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::RoutingPolicyTables;

pub const WINDOWS_DIRECT_INGRESS_CONTRACT_VERSION: u32 = 1;
pub const MAX_DIRECT_INGRESS_EVIDENCE_AGE_MS: u64 = 1_000;
pub const MAX_DIRECT_INGRESS_CLIENT_READ_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_DIRECT_INGRESS_BACKPRESSURE_TIMEOUT_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDirectIngressEndpointEvidenceSource {
    OriginalDestination,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsDirectIngressEndpointEvidence {
    pub source: WindowsDirectIngressEndpointEvidenceSource,
    pub connection_id: u64,
    pub request_id: String,
    pub session_id: u64,
    pub endpoint: WindowsDirectConnectorEndpoint,
    pub observed_at_ms: u64,
    pub valid_until_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsDirectIngressRequest {
    pub connector_request: WindowsDirectConnectorRequest,
    pub endpoint_evidence: WindowsDirectIngressEndpointEvidence,
    pub max_client_read_chunk_bytes: usize,
    pub backpressure_timeout_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsDirectIngressPlan {
    pub(super) connector_plan: WindowsDirectConnectorPlan,
    pub(super) connection_id: u64,
    pub(super) max_client_read_chunk_bytes: usize,
    pub(super) backpressure_timeout_ms: u64,
}

impl WindowsDirectIngressPlan {
    pub const fn session_id(&self) -> u64 {
        self.connector_plan.session_id()
    }

    pub fn request_id(&self) -> &str {
        self.connector_plan.request_id()
    }

    pub const fn connection_id(&self) -> u64 {
        self.connection_id
    }

    pub const fn endpoint(&self) -> std::net::SocketAddr {
        self.connector_plan.endpoint()
    }

    pub const fn max_client_read_chunk_bytes(&self) -> usize {
        self.max_client_read_chunk_bytes
    }

    pub const fn backpressure_timeout_ms(&self) -> u64 {
        self.backpressure_timeout_ms
    }

    pub fn connector_plan(&self) -> &WindowsDirectConnectorPlan {
        &self.connector_plan
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDirectIngressRequestErrorCode {
    InvalidConnectorRequest,
    PreloadedPayloadForbidden,
    InvalidConnectionId,
    EvidenceIdentityMismatch,
    EvidenceEndpointMismatch,
    InvalidEvidenceWindow,
    StaleEndpointEvidence,
    InvalidClientReadChunk,
    InvalidBackpressureTimeout,
}

impl WindowsDirectIngressRequestErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConnectorRequest => "invalid_connector_request",
            Self::PreloadedPayloadForbidden => "preloaded_payload_forbidden",
            Self::InvalidConnectionId => "invalid_connection_id",
            Self::EvidenceIdentityMismatch => "evidence_identity_mismatch",
            Self::EvidenceEndpointMismatch => "evidence_endpoint_mismatch",
            Self::InvalidEvidenceWindow => "invalid_evidence_window",
            Self::StaleEndpointEvidence => "stale_endpoint_evidence",
            Self::InvalidClientReadChunk => "invalid_client_read_chunk",
            Self::InvalidBackpressureTimeout => "invalid_backpressure_timeout",
        }
    }
}

pub fn prepare_windows_direct_ingress(
    request: &WindowsDirectIngressRequest,
    policy_tables: &RoutingPolicyTables,
) -> Result<WindowsDirectIngressPlan, WindowsDirectIngressRequestErrorCode> {
    let connector_plan =
        prepare_windows_direct_connector(&request.connector_request, policy_tables).map_err(
            |_error: WindowsDirectConnectorRequestErrorCode| {
                WindowsDirectIngressRequestErrorCode::InvalidConnectorRequest
            },
        )?;
    if !request.connector_request.initial_payload.is_empty() {
        return Err(WindowsDirectIngressRequestErrorCode::PreloadedPayloadForbidden);
    }

    let evidence = &request.endpoint_evidence;
    if evidence.connection_id == 0 {
        return Err(WindowsDirectIngressRequestErrorCode::InvalidConnectionId);
    }
    if evidence.request_id != request.connector_request.data_plane_request.request_id
        || evidence.session_id != request.connector_request.session_id
    {
        return Err(WindowsDirectIngressRequestErrorCode::EvidenceIdentityMismatch);
    }
    if evidence.endpoint != request.connector_request.endpoint {
        return Err(WindowsDirectIngressRequestErrorCode::EvidenceEndpointMismatch);
    }

    let started_at_ms = request.connector_request.data_plane_request.started_at_ms;
    let issued_at_ms = request.connector_request.issued_at_ms;
    let first_payload_deadline_at_ms = request
        .connector_request
        .data_plane_request
        .first_payload_deadline_at_ms;
    if evidence.observed_at_ms < started_at_ms
        || evidence.observed_at_ms > issued_at_ms
        || evidence.valid_until_ms < issued_at_ms
        || evidence.valid_until_ms > first_payload_deadline_at_ms
    {
        return Err(WindowsDirectIngressRequestErrorCode::InvalidEvidenceWindow);
    }
    if issued_at_ms.saturating_sub(evidence.observed_at_ms) > MAX_DIRECT_INGRESS_EVIDENCE_AGE_MS {
        return Err(WindowsDirectIngressRequestErrorCode::StaleEndpointEvidence);
    }
    if request.max_client_read_chunk_bytes == 0
        || request.max_client_read_chunk_bytes > MAX_DIRECT_INGRESS_CLIENT_READ_CHUNK_BYTES
    {
        return Err(WindowsDirectIngressRequestErrorCode::InvalidClientReadChunk);
    }
    if request.backpressure_timeout_ms == 0
        || request.backpressure_timeout_ms > MAX_DIRECT_INGRESS_BACKPRESSURE_TIMEOUT_MS
    {
        return Err(WindowsDirectIngressRequestErrorCode::InvalidBackpressureTimeout);
    }

    Ok(WindowsDirectIngressPlan {
        connector_plan,
        connection_id: evidence.connection_id,
        max_client_read_chunk_bytes: request.max_client_read_chunk_bytes,
        backpressure_timeout_ms: request.backpressure_timeout_ms,
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDirectIngressClientCloseReason {
    Eof,
    ReadFailed,
    WriteFailed,
    WriteBackpressureDeadline,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsDirectIngressEvent {
    Connected {
        request_id: String,
        session_id: u64,
        connection_id: u64,
    },
    PayloadDelivered {
        request_id: String,
        session_id: u64,
        connection_id: u64,
        bytes: u64,
    },
    ConnectFailed {
        request_id: String,
        session_id: u64,
        connection_id: u64,
        reason: String,
    },
    BackendReset {
        request_id: String,
        session_id: u64,
        connection_id: u64,
        reason: String,
    },
    BackendClosed {
        request_id: String,
        session_id: u64,
        connection_id: u64,
    },
    ClientClosed {
        request_id: String,
        session_id: u64,
        connection_id: u64,
        reason: WindowsDirectIngressClientCloseReason,
    },
    FirstPayloadDeadline {
        request_id: String,
        session_id: u64,
        connection_id: u64,
    },
    Cancelled {
        request_id: String,
        session_id: u64,
        connection_id: u64,
        reason: WindowsDirectConnectorCancelReason,
    },
}

impl WindowsDirectIngressEvent {
    pub fn request_id(&self) -> &str {
        match self {
            Self::Connected { request_id, .. }
            | Self::PayloadDelivered { request_id, .. }
            | Self::ConnectFailed { request_id, .. }
            | Self::BackendReset { request_id, .. }
            | Self::BackendClosed { request_id, .. }
            | Self::ClientClosed { request_id, .. }
            | Self::FirstPayloadDeadline { request_id, .. }
            | Self::Cancelled { request_id, .. } => request_id,
        }
    }

    pub const fn session_id(&self) -> u64 {
        match self {
            Self::Connected { session_id, .. }
            | Self::PayloadDelivered { session_id, .. }
            | Self::ConnectFailed { session_id, .. }
            | Self::BackendReset { session_id, .. }
            | Self::BackendClosed { session_id, .. }
            | Self::ClientClosed { session_id, .. }
            | Self::FirstPayloadDeadline { session_id, .. }
            | Self::Cancelled { session_id, .. } => *session_id,
        }
    }

    pub const fn connection_id(&self) -> u64 {
        match self {
            Self::Connected { connection_id, .. }
            | Self::PayloadDelivered { connection_id, .. }
            | Self::ConnectFailed { connection_id, .. }
            | Self::BackendReset { connection_id, .. }
            | Self::BackendClosed { connection_id, .. }
            | Self::ClientClosed { connection_id, .. }
            | Self::FirstPayloadDeadline { connection_id, .. }
            | Self::Cancelled { connection_id, .. } => *connection_id,
        }
    }
}

pub fn windows_direct_ingress_data_plane_event(
    event: &WindowsDirectIngressEvent,
    now_ms: u64,
) -> WindowsDataPlaneEvent {
    match event {
        WindowsDirectIngressEvent::Connected {
            request_id,
            session_id,
            ..
        } => WindowsDataPlaneEvent::BackendConnected {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
        },
        WindowsDirectIngressEvent::PayloadDelivered {
            request_id,
            session_id,
            bytes,
            ..
        } => WindowsDataPlaneEvent::PayloadReceived {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
            bytes: *bytes,
        },
        WindowsDirectIngressEvent::ClientClosed {
            request_id,
            session_id,
            ..
        } => WindowsDataPlaneEvent::CancelRequested {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
        },
        WindowsDirectIngressEvent::ConnectFailed {
            request_id,
            session_id,
            reason,
            ..
        } => WindowsDataPlaneEvent::ConnectFailed {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
            reason: reason.clone(),
        },
        WindowsDirectIngressEvent::BackendReset {
            request_id,
            session_id,
            reason,
            ..
        } => WindowsDataPlaneEvent::BackendReset {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
            reason: reason.clone(),
        },
        WindowsDirectIngressEvent::BackendClosed {
            request_id,
            session_id,
            ..
        } => WindowsDataPlaneEvent::BackendClosed {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
        },
        WindowsDirectIngressEvent::FirstPayloadDeadline {
            request_id,
            session_id,
            ..
        } => WindowsDataPlaneEvent::FirstPayloadDeadline {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
        },
        WindowsDirectIngressEvent::Cancelled {
            request_id,
            session_id,
            ..
        } => WindowsDataPlaneEvent::SessionCancelled {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
        },
    }
}

pub(super) fn connector_event_to_ingress(
    event: WindowsDirectConnectorEvent,
    connection_id: u64,
) -> WindowsDirectIngressEvent {
    match event {
        WindowsDirectConnectorEvent::Connected {
            request_id,
            session_id,
        } => WindowsDirectIngressEvent::Connected {
            request_id,
            session_id,
            connection_id,
        },
        WindowsDirectConnectorEvent::Payload { .. } => {
            unreachable!("payload is emitted only after client delivery")
        }
        WindowsDirectConnectorEvent::ConnectFailed {
            request_id,
            session_id,
            reason,
        } => WindowsDirectIngressEvent::ConnectFailed {
            request_id,
            session_id,
            connection_id,
            reason,
        },
        WindowsDirectConnectorEvent::StreamReset {
            request_id,
            session_id,
            reason,
        } => WindowsDirectIngressEvent::BackendReset {
            request_id,
            session_id,
            connection_id,
            reason,
        },
        WindowsDirectConnectorEvent::BackendClosed {
            request_id,
            session_id,
        } => WindowsDirectIngressEvent::BackendClosed {
            request_id,
            session_id,
            connection_id,
        },
        WindowsDirectConnectorEvent::FirstPayloadDeadline {
            request_id,
            session_id,
        } => WindowsDirectIngressEvent::FirstPayloadDeadline {
            request_id,
            session_id,
            connection_id,
        },
        WindowsDirectConnectorEvent::Cancelled {
            request_id,
            session_id,
            reason,
        } => WindowsDirectIngressEvent::Cancelled {
            request_id,
            session_id,
            connection_id,
            reason,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_plane::{WindowsDataPlaneBackend, WindowsDataPlaneRequest};
    use slipstream_core::routing_policy::{bundled_policy_v1, classify_route_policy};

    fn ingress_request() -> WindowsDirectIngressRequest {
        let policy_tables = bundled_policy_v1();
        let endpoint = WindowsDirectConnectorEndpoint {
            address: "127.0.0.1".to_owned(),
            port: 443,
        };
        WindowsDirectIngressRequest {
            connector_request: WindowsDirectConnectorRequest {
                session_id: 7,
                data_plane_request: WindowsDataPlaneRequest {
                    request_id: "direct-7".to_owned(),
                    policy: classify_route_policy("github.com", &policy_tables),
                    backend: WindowsDataPlaneBackend::Direct,
                    started_at_ms: 10,
                    first_payload_deadline_at_ms: 1_010,
                },
                endpoint: endpoint.clone(),
                issued_at_ms: 20,
                connect_deadline_at_ms: 520,
                initial_payload: Vec::new(),
                max_read_chunk_bytes: 4_096,
            },
            endpoint_evidence: WindowsDirectIngressEndpointEvidence {
                source: WindowsDirectIngressEndpointEvidenceSource::OriginalDestination,
                connection_id: 11,
                request_id: "direct-7".to_owned(),
                session_id: 7,
                endpoint,
                observed_at_ms: 10,
                valid_until_ms: 1_010,
            },
            max_client_read_chunk_bytes: 4_096,
            backpressure_timeout_ms: 500,
        }
    }

    #[test]
    fn ingress_plan_binds_identity_endpoint_and_empty_preload() {
        let policy_tables = bundled_policy_v1();
        let plan = prepare_windows_direct_ingress(&ingress_request(), &policy_tables)
            .expect("fresh direct ingress should be admitted");
        assert_eq!(plan.session_id(), 7);
        assert_eq!(plan.connection_id(), 11);

        let mut preloaded = ingress_request();
        preloaded.connector_request.initial_payload = b"unowned".to_vec();
        assert_eq!(
            prepare_windows_direct_ingress(&preloaded, &policy_tables),
            Err(WindowsDirectIngressRequestErrorCode::PreloadedPayloadForbidden)
        );

        let mut mismatch = ingress_request();
        mismatch.endpoint_evidence.endpoint.port = 8443;
        assert_eq!(
            prepare_windows_direct_ingress(&mismatch, &policy_tables),
            Err(WindowsDirectIngressRequestErrorCode::EvidenceEndpointMismatch)
        );
    }
}

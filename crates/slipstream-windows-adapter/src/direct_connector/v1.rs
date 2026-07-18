//! Version 1 boundary for the native Windows direct TCP connector.
//!
//! The contract accepts only an already-admitted direct data-plane session and
//! a numeric endpoint. It does not resolve names, select a route, or inspect or
//! mutate DNS, proxy, PAC, VPN, or other system networking state.

use crate::data_plane::{
    validate_windows_data_plane_request, WindowsDataPlaneBackend, WindowsDataPlaneEvent,
    WindowsDataPlaneRequest, WindowsDataPlaneRequestErrorCode,
};
use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::RoutingPolicyTables;
use std::net::{IpAddr, SocketAddr};

pub const WINDOWS_DIRECT_CONNECTOR_CONTRACT_VERSION: u32 = 1;
pub const MAX_DIRECT_CONNECTOR_INITIAL_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_DIRECT_CONNECTOR_READ_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_DIRECT_CONNECTOR_CONNECT_TIMEOUT_MS: u64 = 750;
pub const MAX_DIRECT_CONNECTOR_DEADLINE_MS: u64 = 30_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsDirectConnectorEndpoint {
    pub address: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsDirectConnectorRequest {
    pub session_id: u64,
    pub data_plane_request: WindowsDataPlaneRequest,
    pub endpoint: WindowsDirectConnectorEndpoint,
    pub issued_at_ms: u64,
    pub connect_deadline_at_ms: u64,
    pub initial_payload: Vec<u8>,
    pub max_read_chunk_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsDirectConnectorPlan {
    pub(super) session_id: u64,
    pub(super) request_id: String,
    pub(super) data_plane_request: WindowsDataPlaneRequest,
    pub(super) endpoint: SocketAddr,
    pub(super) connect_timeout_ms: u64,
    pub(super) first_payload_timeout_ms: u64,
    pub(super) initial_payload: Vec<u8>,
    pub(super) max_read_chunk_bytes: usize,
}

impl WindowsDirectConnectorPlan {
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn data_plane_request(&self) -> &WindowsDataPlaneRequest {
        &self.data_plane_request
    }

    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub const fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
    }

    pub const fn first_payload_timeout_ms(&self) -> u64 {
        self.first_payload_timeout_ms
    }

    pub fn initial_payload(&self) -> &[u8] {
        &self.initial_payload
    }

    pub const fn max_read_chunk_bytes(&self) -> usize {
        self.max_read_chunk_bytes
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDirectConnectorRequestErrorCode {
    InvalidDataPlaneRequest,
    BackendNotDirect,
    InvalidSessionId,
    EndpointNotNumeric,
    InvalidPort,
    InvalidIssuedAt,
    InvalidConnectDeadline,
    DeadlineTooLarge,
    InitialPayloadTooLarge,
    InvalidReadChunk,
}

impl WindowsDirectConnectorRequestErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidDataPlaneRequest => "invalid_data_plane_request",
            Self::BackendNotDirect => "backend_not_direct",
            Self::InvalidSessionId => "invalid_session_id",
            Self::EndpointNotNumeric => "endpoint_not_numeric",
            Self::InvalidPort => "invalid_port",
            Self::InvalidIssuedAt => "invalid_issued_at",
            Self::InvalidConnectDeadline => "invalid_connect_deadline",
            Self::DeadlineTooLarge => "deadline_too_large",
            Self::InitialPayloadTooLarge => "initial_payload_too_large",
            Self::InvalidReadChunk => "invalid_read_chunk",
        }
    }
}

pub fn prepare_windows_direct_connector(
    request: &WindowsDirectConnectorRequest,
    policy_tables: &RoutingPolicyTables,
) -> Result<WindowsDirectConnectorPlan, WindowsDirectConnectorRequestErrorCode> {
    validate_windows_data_plane_request(&request.data_plane_request, policy_tables).map_err(
        |_error: WindowsDataPlaneRequestErrorCode| {
            WindowsDirectConnectorRequestErrorCode::InvalidDataPlaneRequest
        },
    )?;
    if request.data_plane_request.backend != WindowsDataPlaneBackend::Direct {
        return Err(WindowsDirectConnectorRequestErrorCode::BackendNotDirect);
    }
    if request.session_id == 0 {
        return Err(WindowsDirectConnectorRequestErrorCode::InvalidSessionId);
    }
    let address: IpAddr = request
        .endpoint
        .address
        .parse()
        .map_err(|_| WindowsDirectConnectorRequestErrorCode::EndpointNotNumeric)?;
    if address.to_string() != request.endpoint.address {
        return Err(WindowsDirectConnectorRequestErrorCode::EndpointNotNumeric);
    }
    if request.endpoint.port == 0 {
        return Err(WindowsDirectConnectorRequestErrorCode::InvalidPort);
    }
    if request.issued_at_ms < request.data_plane_request.started_at_ms
        || request.issued_at_ms >= request.data_plane_request.first_payload_deadline_at_ms
    {
        return Err(WindowsDirectConnectorRequestErrorCode::InvalidIssuedAt);
    }
    if request.connect_deadline_at_ms <= request.issued_at_ms
        || request.connect_deadline_at_ms > request.data_plane_request.first_payload_deadline_at_ms
    {
        return Err(WindowsDirectConnectorRequestErrorCode::InvalidConnectDeadline);
    }
    let connect_timeout_ms = request
        .connect_deadline_at_ms
        .saturating_sub(request.issued_at_ms);
    let first_payload_timeout_ms = request
        .data_plane_request
        .first_payload_deadline_at_ms
        .saturating_sub(request.issued_at_ms);
    if connect_timeout_ms > MAX_DIRECT_CONNECTOR_CONNECT_TIMEOUT_MS
        || first_payload_timeout_ms > MAX_DIRECT_CONNECTOR_DEADLINE_MS
    {
        return Err(WindowsDirectConnectorRequestErrorCode::DeadlineTooLarge);
    }
    if request.initial_payload.len() > MAX_DIRECT_CONNECTOR_INITIAL_PAYLOAD_BYTES {
        return Err(WindowsDirectConnectorRequestErrorCode::InitialPayloadTooLarge);
    }
    if request.max_read_chunk_bytes == 0
        || request.max_read_chunk_bytes > MAX_DIRECT_CONNECTOR_READ_CHUNK_BYTES
    {
        return Err(WindowsDirectConnectorRequestErrorCode::InvalidReadChunk);
    }

    Ok(WindowsDirectConnectorPlan {
        session_id: request.session_id,
        request_id: request.data_plane_request.request_id.clone(),
        data_plane_request: request.data_plane_request.clone(),
        endpoint: SocketAddr::new(address, request.endpoint.port),
        connect_timeout_ms,
        first_payload_timeout_ms,
        initial_payload: request.initial_payload.clone(),
        max_read_chunk_bytes: request.max_read_chunk_bytes,
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDirectConnectorCancelReason {
    Caller,
    Shutdown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsDirectConnectorEvent {
    Connected {
        request_id: String,
        session_id: u64,
    },
    Payload {
        request_id: String,
        session_id: u64,
        bytes: Vec<u8>,
    },
    ConnectFailed {
        request_id: String,
        session_id: u64,
        reason: String,
    },
    StreamReset {
        request_id: String,
        session_id: u64,
        reason: String,
    },
    BackendClosed {
        request_id: String,
        session_id: u64,
    },
    FirstPayloadDeadline {
        request_id: String,
        session_id: u64,
    },
    Cancelled {
        request_id: String,
        session_id: u64,
        reason: WindowsDirectConnectorCancelReason,
    },
}

impl WindowsDirectConnectorEvent {
    pub fn request_id(&self) -> &str {
        match self {
            Self::Connected { request_id, .. }
            | Self::Payload { request_id, .. }
            | Self::ConnectFailed { request_id, .. }
            | Self::StreamReset { request_id, .. }
            | Self::BackendClosed { request_id, .. }
            | Self::FirstPayloadDeadline { request_id, .. }
            | Self::Cancelled { request_id, .. } => request_id,
        }
    }

    pub const fn session_id(&self) -> u64 {
        match self {
            Self::Connected { session_id, .. }
            | Self::Payload { session_id, .. }
            | Self::ConnectFailed { session_id, .. }
            | Self::StreamReset { session_id, .. }
            | Self::BackendClosed { session_id, .. }
            | Self::FirstPayloadDeadline { session_id, .. }
            | Self::Cancelled { session_id, .. } => *session_id,
        }
    }
}

pub fn windows_direct_connector_data_plane_event(
    event: &WindowsDirectConnectorEvent,
    now_ms: u64,
) -> WindowsDataPlaneEvent {
    match event {
        WindowsDirectConnectorEvent::Connected {
            request_id,
            session_id,
        } => WindowsDataPlaneEvent::BackendConnected {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
        },
        WindowsDirectConnectorEvent::Payload {
            request_id,
            session_id,
            bytes,
        } => WindowsDataPlaneEvent::PayloadReceived {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
            bytes: bytes.len() as u64,
        },
        WindowsDirectConnectorEvent::ConnectFailed {
            request_id,
            session_id,
            reason,
        } => WindowsDataPlaneEvent::ConnectFailed {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
            reason: reason.clone(),
        },
        WindowsDirectConnectorEvent::StreamReset {
            request_id,
            session_id,
            reason,
        } => WindowsDataPlaneEvent::BackendReset {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
            reason: reason.clone(),
        },
        WindowsDirectConnectorEvent::BackendClosed {
            request_id,
            session_id,
        } => WindowsDataPlaneEvent::BackendClosed {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
        },
        WindowsDirectConnectorEvent::FirstPayloadDeadline {
            request_id,
            session_id,
        } => WindowsDataPlaneEvent::FirstPayloadDeadline {
            now_ms,
            request_id: request_id.clone(),
            session_id: *session_id,
        },
        WindowsDirectConnectorEvent::Cancelled {
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

#[cfg(test)]
mod tests {
    use super::*;
    use slipstream_core::routing_policy::{
        bundled_policy_v1, classify_route_policy, RouteClass, ServiceGroup, StrategySet,
    };

    fn direct_request(host: &str) -> WindowsDirectConnectorRequest {
        let policy_tables = bundled_policy_v1();
        WindowsDirectConnectorRequest {
            session_id: 7,
            data_plane_request: WindowsDataPlaneRequest {
                request_id: "direct-7".to_owned(),
                policy: classify_route_policy(host, &policy_tables),
                backend: WindowsDataPlaneBackend::Direct,
                started_at_ms: 10,
                first_payload_deadline_at_ms: 1_010,
            },
            endpoint: WindowsDirectConnectorEndpoint {
                address: "127.0.0.1".to_owned(),
                port: 443,
            },
            issued_at_ms: 20,
            connect_deadline_at_ms: 520,
            initial_payload: b"hello".to_vec(),
            max_read_chunk_bytes: 4_096,
        }
    }

    #[test]
    fn direct_plan_requires_active_policy_and_numeric_endpoint() {
        let policy_tables = bundled_policy_v1();
        let plan = prepare_windows_direct_connector(&direct_request("github.com"), &policy_tables)
            .expect("direct GitHub request should be admitted");
        assert_eq!(plan.endpoint(), "127.0.0.1:443".parse().unwrap());
        assert_eq!(plan.connect_timeout_ms(), 500);
        assert_eq!(plan.first_payload_timeout_ms(), 990);

        let mut hostname_endpoint = direct_request("github.com");
        hostname_endpoint.endpoint.address = "example.com".to_owned();
        assert_eq!(
            prepare_windows_direct_connector(&hostname_endpoint, &policy_tables),
            Err(WindowsDirectConnectorRequestErrorCode::EndpointNotNumeric)
        );

        let mut protected = direct_request("github.com");
        protected.data_plane_request.policy.host = "gateway.discord.gg".to_owned();
        protected.data_plane_request.policy.route_class = RouteClass::DirectPassthrough;
        protected.data_plane_request.policy.service_group = ServiceGroup::Discord;
        protected.data_plane_request.policy.strategy_set = StrategySet::Direct;
        assert_eq!(
            prepare_windows_direct_connector(&protected, &policy_tables),
            Err(WindowsDirectConnectorRequestErrorCode::InvalidDataPlaneRequest)
        );

        let mut slow_connect = direct_request("github.com");
        slow_connect.connect_deadline_at_ms =
            slow_connect.issued_at_ms + MAX_DIRECT_CONNECTOR_CONNECT_TIMEOUT_MS + 1;
        assert_eq!(
            prepare_windows_direct_connector(&slow_connect, &policy_tables),
            Err(WindowsDirectConnectorRequestErrorCode::DeadlineTooLarge)
        );
    }

    #[test]
    fn connector_events_map_without_changing_route_policy() {
        let payload = WindowsDirectConnectorEvent::Payload {
            request_id: "direct-7".to_owned(),
            session_id: 7,
            bytes: b"payload".to_vec(),
        };
        assert_eq!(
            windows_direct_connector_data_plane_event(&payload, 50),
            WindowsDataPlaneEvent::PayloadReceived {
                now_ms: 50,
                request_id: "direct-7".to_owned(),
                session_id: 7,
                bytes: 7,
            }
        );
    }
}

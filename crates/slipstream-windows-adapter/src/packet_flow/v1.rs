//! Version 1 pure packet-to-flow forwarding state machine.
//!
//! The contract begins after packet capture/classification and outbound-route
//! admission. It owns bounded ordered payload metadata and emits abstract
//! forwarding commands keyed by direction and sequence. A future effect keeps
//! the corresponding immutable bytes under that identity until `Forwarded`;
//! cloning this reducer never clones packet buffers. The contract does not
//! reconstruct TCP, open sockets, load an adapter, install routes, or compose
//! the production service host.

use crate::data_plane::{
    validate_windows_data_plane_request, WindowsDataPlaneEvent, WindowsDataPlaneRequest,
};
use crate::packet_adapter::v2::{WindowsPacketCaptureTransport, WindowsPacketPolicyClassification};
use crate::packet_egress::WindowsPacketEgressPlan;
use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::RoutingPolicyTables;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

pub const WINDOWS_PACKET_FLOW_CONTRACT_VERSION: u32 = 1;
const MAX_ACTIVE_FLOWS: usize = 65_535;
const MAX_RETAINED_TERMINAL_FLOWS: usize = 65_535;
const MAX_RETAINED_FLOW_IDENTITIES: usize = 1_000_000;
const MAX_CHUNK_BYTES: usize = 64 * 1024;
const MAX_BUFFERED_BYTES: usize = 4 * 1024 * 1024;
const MAX_QUEUED_FRAMES_PER_DIRECTION: usize = 65_536;
const MAX_TOTAL_BUFFERED_BYTES: usize = 256 * 1024 * 1024;
const MAX_TOTAL_QUEUED_FRAMES: usize = 1_000_000;
const MAX_TIMEOUT_MS: u64 = 300_000;
const MAX_REASON_CHARS: usize = 200;
const HTTPS_PORT: u16 = 443;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsPacketFlowConfig {
    pub max_active_flows: usize,
    pub max_retained_terminal_flows: usize,
    pub max_retained_flow_identities: usize,
    pub max_chunk_bytes: usize,
    pub max_queued_frames_per_direction: usize,
    pub high_watermark_bytes: usize,
    pub low_watermark_bytes: usize,
    pub max_buffered_bytes: usize,
    pub idle_timeout_ms: u64,
    pub backpressure_timeout_ms: u64,
}

impl WindowsPacketFlowConfig {
    pub fn validate(&self) -> Result<(), WindowsPacketFlowError> {
        if self.max_active_flows == 0 || self.max_active_flows > MAX_ACTIVE_FLOWS {
            return Err(WindowsPacketFlowError::InvalidConfig(
                "max_active_flows must be within 1..=65535",
            ));
        }
        if self.max_retained_terminal_flows == 0
            || self.max_retained_terminal_flows > MAX_RETAINED_TERMINAL_FLOWS
        {
            return Err(WindowsPacketFlowError::InvalidConfig(
                "max_retained_terminal_flows must be within 1..=65535",
            ));
        }
        if self.max_retained_flow_identities == 0
            || self.max_retained_flow_identities > MAX_RETAINED_FLOW_IDENTITIES
            || self.max_retained_flow_identities
                < self
                    .max_active_flows
                    .saturating_add(self.max_retained_terminal_flows)
        {
            return Err(WindowsPacketFlowError::InvalidConfig(
                "max_retained_flow_identities must cover active plus terminal flows and remain <= 1000000",
            ));
        }
        if self.max_chunk_bytes == 0 || self.max_chunk_bytes > MAX_CHUNK_BYTES {
            return Err(WindowsPacketFlowError::InvalidConfig(
                "max_chunk_bytes must be within 1..=65536",
            ));
        }
        if self.max_queued_frames_per_direction == 0
            || self.max_queued_frames_per_direction > MAX_QUEUED_FRAMES_PER_DIRECTION
        {
            return Err(WindowsPacketFlowError::InvalidConfig(
                "max_queued_frames_per_direction must be within 1..=65536",
            ));
        }
        if self.low_watermark_bytes >= self.high_watermark_bytes
            || self.high_watermark_bytes > self.max_buffered_bytes
            || self.max_buffered_bytes > MAX_BUFFERED_BYTES
        {
            return Err(WindowsPacketFlowError::InvalidConfig(
                "watermarks must satisfy low < high <= max <= 4194304",
            ));
        }
        if self.idle_timeout_ms == 0
            || self.idle_timeout_ms > MAX_TIMEOUT_MS
            || self.backpressure_timeout_ms == 0
            || self.backpressure_timeout_ms > MAX_TIMEOUT_MS
        {
            return Err(WindowsPacketFlowError::InvalidConfig(
                "timeouts must be within 1..=300000ms",
            ));
        }
        let total_buffer_budget = self
            .max_active_flows
            .checked_mul(self.max_buffered_bytes)
            .and_then(|value| value.checked_mul(2));
        if !matches!(total_buffer_budget, Some(value) if value <= MAX_TOTAL_BUFFERED_BYTES) {
            return Err(WindowsPacketFlowError::InvalidConfig(
                "aggregate directional byte budget exceeds 268435456",
            ));
        }
        let total_frame_budget = self
            .max_active_flows
            .checked_mul(self.max_queued_frames_per_direction)
            .and_then(|value| value.checked_mul(2));
        if !matches!(total_frame_budget, Some(value) if value <= MAX_TOTAL_QUEUED_FRAMES) {
            return Err(WindowsPacketFlowError::InvalidConfig(
                "aggregate directional frame budget exceeds 1000000",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketFlowTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WindowsPacketFlowKey {
    pub capture_generation: u64,
    pub flow_id: u64,
    pub transport: WindowsPacketFlowTransport,
    pub session_id: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WindowsPacketCaptureFlowIdentity {
    pub capture_generation: u64,
    pub flow_id: u64,
    pub transport: WindowsPacketFlowTransport,
}

impl WindowsPacketFlowKey {
    pub const fn capture_identity(self) -> WindowsPacketCaptureFlowIdentity {
        WindowsPacketCaptureFlowIdentity {
            capture_generation: self.capture_generation,
            flow_id: self.flow_id,
            transport: self.transport,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketFlowDirection {
    ClientToBackend,
    BackendToClient,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketFlowPhase {
    Opening,
    Relaying,
    Draining,
    Succeeded,
    Failed,
    Cancelled,
}

impl WindowsPacketFlowPhase {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketFlowAdmission {
    key: WindowsPacketFlowKey,
    session_id: u64,
    request: WindowsDataPlaneRequest,
    egress: WindowsPacketEgressPlan,
    destination: String,
    destination_port: u16,
    expires_at_ms: u64,
}

impl WindowsPacketFlowAdmission {
    pub const fn key(&self) -> WindowsPacketFlowKey {
        self.key
    }

    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn request(&self) -> &WindowsDataPlaneRequest {
        &self.request
    }

    pub fn egress(&self) -> &WindowsPacketEgressPlan {
        &self.egress
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }

    pub const fn destination_port(&self) -> u16 {
        self.destination_port
    }

    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketFlowAdmissionErrorCode {
    InvalidSessionId,
    UnsupportedTransport,
    ClassificationExpired,
    EgressExpired,
    CaptureGenerationMismatch,
    FlowIdMismatch,
    DestinationMismatch,
    InvalidDataPlaneRequest,
    InvalidDataPlaneWindow,
    PolicyMismatch,
}

/// Binds the three existing pure boundaries without exposing an authorizing
/// constructor for the resulting admission token.
pub fn prepare_windows_packet_flow(
    classification: &WindowsPacketPolicyClassification,
    egress: &WindowsPacketEgressPlan,
    session_id: u64,
    request: &WindowsDataPlaneRequest,
    now_ms: u64,
    policy_tables: &RoutingPolicyTables,
) -> Result<WindowsPacketFlowAdmission, WindowsPacketFlowAdmissionErrorCode> {
    if session_id == 0 {
        return Err(WindowsPacketFlowAdmissionErrorCode::InvalidSessionId);
    }
    let transport = match classification.transport() {
        WindowsPacketCaptureTransport::TcpTls => WindowsPacketFlowTransport::Tcp,
        WindowsPacketCaptureTransport::UdpQuic => WindowsPacketFlowTransport::Udp,
        WindowsPacketCaptureTransport::Other => {
            return Err(WindowsPacketFlowAdmissionErrorCode::UnsupportedTransport)
        }
    };
    if now_ms >= classification.expires_at_ms() {
        return Err(WindowsPacketFlowAdmissionErrorCode::ClassificationExpired);
    }
    if now_ms >= egress.expires_at_ms() {
        return Err(WindowsPacketFlowAdmissionErrorCode::EgressExpired);
    }
    if classification.capture_generation() != egress.capture_generation() {
        return Err(WindowsPacketFlowAdmissionErrorCode::CaptureGenerationMismatch);
    }
    if classification.flow_id() != egress.flow_id() {
        return Err(WindowsPacketFlowAdmissionErrorCode::FlowIdMismatch);
    }
    if classification.destination() != egress.destination() {
        return Err(WindowsPacketFlowAdmissionErrorCode::DestinationMismatch);
    }
    validate_windows_data_plane_request(request, policy_tables)
        .map_err(|_| WindowsPacketFlowAdmissionErrorCode::InvalidDataPlaneRequest)?;
    if now_ms < request.started_at_ms || now_ms >= request.first_payload_deadline_at_ms {
        return Err(WindowsPacketFlowAdmissionErrorCode::InvalidDataPlaneWindow);
    }
    if request.policy != *classification.policy() {
        return Err(WindowsPacketFlowAdmissionErrorCode::PolicyMismatch);
    }

    Ok(WindowsPacketFlowAdmission {
        key: WindowsPacketFlowKey {
            capture_generation: classification.capture_generation(),
            flow_id: classification.flow_id(),
            transport,
            session_id,
        },
        session_id,
        request: request.clone(),
        egress: egress.clone(),
        destination: classification.destination().to_string(),
        destination_port: HTTPS_PORT,
        expires_at_ms: classification
            .expires_at_ms()
            .min(egress.expires_at_ms())
            .min(request.first_payload_deadline_at_ms),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsPacketFlowFrame {
    sequence: u64,
    bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsPacketFlowQueue {
    frames: VecDeque<WindowsPacketFlowFrame>,
    bytes: usize,
    next_sequence: u64,
    paused: bool,
    backpressure_deadline_at_ms: Option<u64>,
}

impl WindowsPacketFlowQueue {
    fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            bytes: 0,
            next_sequence: 1,
            paused: false,
            backpressure_deadline_at_ms: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketFlowState {
    pub admission: WindowsPacketFlowAdmission,
    pub phase: WindowsPacketFlowPhase,
    pub backend_ready: bool,
    pub client_input_open: bool,
    pub backend_input_open: bool,
    pub client_half_close_forwarded: bool,
    pub backend_half_close_forwarded: bool,
    client_to_backend: WindowsPacketFlowQueue,
    backend_to_client: WindowsPacketFlowQueue,
    pub idle_deadline_at_ms: u64,
    pub resource_owned: bool,
    pub terminal_reason: String,
    pub updated_at_ms: u64,
}

impl WindowsPacketFlowState {
    pub fn queued_bytes(&self, direction: WindowsPacketFlowDirection) -> usize {
        self.queue(direction).bytes
    }

    pub fn reads_paused(&self, direction: WindowsPacketFlowDirection) -> bool {
        self.queue(direction).paused
    }

    fn queue(&self, direction: WindowsPacketFlowDirection) -> &WindowsPacketFlowQueue {
        match direction {
            WindowsPacketFlowDirection::ClientToBackend => &self.client_to_backend,
            WindowsPacketFlowDirection::BackendToClient => &self.backend_to_client,
        }
    }

    fn queue_mut(&mut self, direction: WindowsPacketFlowDirection) -> &mut WindowsPacketFlowQueue {
        match direction {
            WindowsPacketFlowDirection::ClientToBackend => &mut self.client_to_backend,
            WindowsPacketFlowDirection::BackendToClient => &mut self.backend_to_client,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketFlowRegistry {
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub retired_capture_generation_high_watermark: u64,
    pub capture_flow_owners: BTreeMap<WindowsPacketCaptureFlowIdentity, WindowsPacketFlowKey>,
    pub flows: BTreeMap<WindowsPacketFlowKey, WindowsPacketFlowState>,
}

impl WindowsPacketFlowRegistry {
    pub fn new(started_at_ms: u64) -> Self {
        Self {
            started_at_ms,
            updated_at_ms: started_at_ms,
            retired_capture_generation_high_watermark: 0,
            capture_flow_owners: BTreeMap::new(),
            flows: BTreeMap::new(),
        }
    }

    pub fn active_flow_count(&self) -> usize {
        self.flows
            .values()
            .filter(|flow| !flow.phase.is_terminal())
            .count()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsPacketFlowEvent {
    FlowOpened {
        now_ms: u64,
        admission: WindowsPacketFlowAdmission,
    },
    BackendReady {
        now_ms: u64,
        key: WindowsPacketFlowKey,
    },
    Payload {
        now_ms: u64,
        key: WindowsPacketFlowKey,
        direction: WindowsPacketFlowDirection,
        sequence: u64,
        bytes: usize,
    },
    Forwarded {
        now_ms: u64,
        key: WindowsPacketFlowKey,
        direction: WindowsPacketFlowDirection,
        through_sequence: u64,
    },
    HalfClosed {
        now_ms: u64,
        key: WindowsPacketFlowKey,
        direction: WindowsPacketFlowDirection,
    },
    DatagramSideClosed {
        now_ms: u64,
        key: WindowsPacketFlowKey,
    },
    Reset {
        now_ms: u64,
        key: WindowsPacketFlowKey,
        direction: WindowsPacketFlowDirection,
        reason: String,
    },
    Cancelled {
        now_ms: u64,
        key: WindowsPacketFlowKey,
    },
    IdleDeadline {
        now_ms: u64,
        key: WindowsPacketFlowKey,
    },
    BackpressureDeadline {
        now_ms: u64,
        key: WindowsPacketFlowKey,
        direction: WindowsPacketFlowDirection,
    },
    CaptureGenerationRetired {
        now_ms: u64,
        capture_generation: u64,
    },
}

impl WindowsPacketFlowEvent {
    pub const fn now_ms(&self) -> u64 {
        match self {
            Self::FlowOpened { now_ms, .. }
            | Self::BackendReady { now_ms, .. }
            | Self::Payload { now_ms, .. }
            | Self::Forwarded { now_ms, .. }
            | Self::HalfClosed { now_ms, .. }
            | Self::DatagramSideClosed { now_ms, .. }
            | Self::Reset { now_ms, .. }
            | Self::Cancelled { now_ms, .. }
            | Self::IdleDeadline { now_ms, .. }
            | Self::BackpressureDeadline { now_ms, .. }
            | Self::CaptureGenerationRetired { now_ms, .. } => *now_ms,
        }
    }

    pub const fn flow_key(&self) -> Option<WindowsPacketFlowKey> {
        match self {
            Self::FlowOpened { admission, .. } => Some(admission.key()),
            Self::BackendReady { key, .. }
            | Self::Payload { key, .. }
            | Self::Forwarded { key, .. }
            | Self::HalfClosed { key, .. }
            | Self::DatagramSideClosed { key, .. }
            | Self::Reset { key, .. }
            | Self::Cancelled { key, .. }
            | Self::IdleDeadline { key, .. }
            | Self::BackpressureDeadline { key, .. } => Some(*key),
            Self::CaptureGenerationRetired { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum WindowsPacketFlowCommand {
    OpenBackend {
        key: WindowsPacketFlowKey,
        session_id: u64,
        request: WindowsDataPlaneRequest,
        egress: WindowsPacketEgressPlan,
        destination_port: u16,
    },
    Forward {
        key: WindowsPacketFlowKey,
        direction: WindowsPacketFlowDirection,
        sequence: u64,
        bytes: usize,
    },
    PauseReads {
        key: WindowsPacketFlowKey,
        direction: WindowsPacketFlowDirection,
    },
    ResumeReads {
        key: WindowsPacketFlowKey,
        direction: WindowsPacketFlowDirection,
    },
    HalfCloseWrite {
        key: WindowsPacketFlowKey,
        direction: WindowsPacketFlowDirection,
    },
    CloseFlow {
        key: WindowsPacketFlowKey,
    },
    ScheduleIdleDeadline {
        key: WindowsPacketFlowKey,
        at_ms: u64,
    },
    ScheduleBackpressureDeadline {
        key: WindowsPacketFlowKey,
        direction: WindowsPacketFlowDirection,
        at_ms: u64,
    },
    DataPlane {
        event: WindowsDataPlaneEvent,
    },
    RejectFlow {
        key: WindowsPacketFlowKey,
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct WindowsPacketFlowTransition {
    pub state: WindowsPacketFlowRegistry,
    pub commands: Vec<WindowsPacketFlowCommand>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsPacketFlowError {
    InvalidConfig(&'static str),
    NonMonotonicEvent,
    ActiveCaptureGenerationRetirement,
    InvalidTransition,
    InvalidTransportTransition,
    EmptyPayload,
    PayloadTooLarge,
    SequenceOverflow,
    OutOfOrderPayload,
    InvalidForwardAcknowledgement,
    ByteCountOverflow,
    QueueAccountingMismatch,
    TimeOverflow,
}

impl fmt::Display for WindowsPacketFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid config: {reason}"),
            Self::NonMonotonicEvent => formatter.write_str("event time moved backwards"),
            Self::ActiveCaptureGenerationRetirement => {
                formatter.write_str("capture generation still owns active flows")
            }
            Self::InvalidTransition => formatter.write_str("invalid packet-flow transition"),
            Self::InvalidTransportTransition => {
                formatter.write_str("transition is invalid for this transport")
            }
            Self::EmptyPayload => formatter.write_str("payload must not be empty"),
            Self::PayloadTooLarge => formatter.write_str("payload exceeds the configured bound"),
            Self::SequenceOverflow => formatter.write_str("payload sequence overflow"),
            Self::OutOfOrderPayload => formatter.write_str("payload sequence is out of order"),
            Self::InvalidForwardAcknowledgement => {
                formatter.write_str("forward acknowledgement is invalid")
            }
            Self::ByteCountOverflow => formatter.write_str("queued byte count overflow"),
            Self::QueueAccountingMismatch => {
                formatter.write_str("queued payload accounting is inconsistent")
            }
            Self::TimeOverflow => formatter.write_str("deadline overflow"),
        }
    }
}

impl std::error::Error for WindowsPacketFlowError {}

fn bounded_reason(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
}

fn reject_admission(
    admission: &WindowsPacketFlowAdmission,
    key: WindowsPacketFlowKey,
    now_ms: u64,
    reason: &str,
    commands: &mut Vec<WindowsPacketFlowCommand>,
) {
    commands.push(WindowsPacketFlowCommand::RejectFlow {
        key,
        reason: reason.to_owned(),
    });
    for event in [
        WindowsDataPlaneEvent::CancelRequested {
            now_ms,
            request_id: admission.request.request_id.clone(),
            session_id: admission.session_id,
        },
        WindowsDataPlaneEvent::SessionCancelled {
            now_ms,
            request_id: admission.request.request_id.clone(),
            session_id: admission.session_id,
        },
    ] {
        commands.push(WindowsPacketFlowCommand::DataPlane { event });
    }
}

fn data_plane_event(
    flow: &WindowsPacketFlowState,
    now_ms: u64,
    event: fn(u64, String, u64) -> WindowsDataPlaneEvent,
) -> WindowsPacketFlowCommand {
    WindowsPacketFlowCommand::DataPlane {
        event: event(
            now_ms,
            flow.admission.request.request_id.clone(),
            flow.admission.session_id,
        ),
    }
}

fn refresh_idle(
    flow: &mut WindowsPacketFlowState,
    key: WindowsPacketFlowKey,
    now_ms: u64,
    config: &WindowsPacketFlowConfig,
    commands: &mut Vec<WindowsPacketFlowCommand>,
) -> Result<(), WindowsPacketFlowError> {
    flow.updated_at_ms = now_ms;
    flow.idle_deadline_at_ms = now_ms
        .checked_add(config.idle_timeout_ms)
        .ok_or(WindowsPacketFlowError::TimeOverflow)?;
    commands.push(WindowsPacketFlowCommand::ScheduleIdleDeadline {
        key,
        at_ms: flow.idle_deadline_at_ms,
    });
    Ok(())
}

fn close_flow(
    flow: &mut WindowsPacketFlowState,
    key: WindowsPacketFlowKey,
    now_ms: u64,
    phase: WindowsPacketFlowPhase,
    reason: &str,
    commands: &mut Vec<WindowsPacketFlowCommand>,
) {
    flow.phase = phase;
    flow.resource_owned = false;
    flow.client_to_backend.frames.clear();
    flow.client_to_backend.bytes = 0;
    flow.client_to_backend.paused = false;
    flow.client_to_backend.backpressure_deadline_at_ms = None;
    flow.backend_to_client.frames.clear();
    flow.backend_to_client.bytes = 0;
    flow.backend_to_client.paused = false;
    flow.backend_to_client.backpressure_deadline_at_ms = None;
    flow.terminal_reason = bounded_reason(reason);
    flow.updated_at_ms = now_ms;
    commands.push(WindowsPacketFlowCommand::CloseFlow { key });
}

fn fail_backend(
    flow: &mut WindowsPacketFlowState,
    key: WindowsPacketFlowKey,
    now_ms: u64,
    reason: &str,
    commands: &mut Vec<WindowsPacketFlowCommand>,
) {
    close_flow(
        flow,
        key,
        now_ms,
        WindowsPacketFlowPhase::Failed,
        reason,
        commands,
    );
    commands.push(WindowsPacketFlowCommand::DataPlane {
        event: WindowsDataPlaneEvent::BackendReset {
            now_ms,
            request_id: flow.admission.request.request_id.clone(),
            session_id: flow.admission.session_id,
            reason: bounded_reason(reason),
        },
    });
}

fn cancel_flow(
    flow: &mut WindowsPacketFlowState,
    key: WindowsPacketFlowKey,
    now_ms: u64,
    reason: &str,
    commands: &mut Vec<WindowsPacketFlowCommand>,
) {
    close_flow(
        flow,
        key,
        now_ms,
        WindowsPacketFlowPhase::Cancelled,
        reason,
        commands,
    );
    for event in [
        WindowsDataPlaneEvent::CancelRequested {
            now_ms,
            request_id: flow.admission.request.request_id.clone(),
            session_id: flow.admission.session_id,
        },
        WindowsDataPlaneEvent::SessionCancelled {
            now_ms,
            request_id: flow.admission.request.request_id.clone(),
            session_id: flow.admission.session_id,
        },
    ] {
        commands.push(WindowsPacketFlowCommand::DataPlane { event });
    }
}

fn maybe_forward_half_close(
    flow: &mut WindowsPacketFlowState,
    key: WindowsPacketFlowKey,
    direction: WindowsPacketFlowDirection,
    commands: &mut Vec<WindowsPacketFlowCommand>,
) {
    if !flow.backend_ready {
        return;
    }
    let queue_empty = flow.queue(direction).frames.is_empty();
    let input_open = match direction {
        WindowsPacketFlowDirection::ClientToBackend => flow.client_input_open,
        WindowsPacketFlowDirection::BackendToClient => flow.backend_input_open,
    };
    let already_forwarded = match direction {
        WindowsPacketFlowDirection::ClientToBackend => flow.client_half_close_forwarded,
        WindowsPacketFlowDirection::BackendToClient => flow.backend_half_close_forwarded,
    };
    if input_open || already_forwarded || !queue_empty {
        return;
    }
    match direction {
        WindowsPacketFlowDirection::ClientToBackend => {
            flow.client_half_close_forwarded = true;
        }
        WindowsPacketFlowDirection::BackendToClient => {
            flow.backend_half_close_forwarded = true;
        }
    }
    commands.push(WindowsPacketFlowCommand::HalfCloseWrite { key, direction });
}

fn maybe_finish_gracefully(
    flow: &mut WindowsPacketFlowState,
    key: WindowsPacketFlowKey,
    now_ms: u64,
    commands: &mut Vec<WindowsPacketFlowCommand>,
) {
    let queues_empty =
        flow.client_to_backend.frames.is_empty() && flow.backend_to_client.frames.is_empty();
    let closed = match flow.admission.key.transport {
        WindowsPacketFlowTransport::Tcp => {
            flow.client_half_close_forwarded && flow.backend_half_close_forwarded
        }
        WindowsPacketFlowTransport::Udp => !flow.client_input_open && !flow.backend_input_open,
    };
    if queues_empty && closed {
        close_flow(
            flow,
            key,
            now_ms,
            WindowsPacketFlowPhase::Succeeded,
            "graceful",
            commands,
        );
        commands.push(data_plane_event(
            flow,
            now_ms,
            |now_ms, request_id, session_id| WindowsDataPlaneEvent::BackendClosed {
                now_ms,
                request_id,
                session_id,
            },
        ));
    } else if !flow.client_input_open || !flow.backend_input_open {
        flow.phase = WindowsPacketFlowPhase::Draining;
    }
}

fn prune_terminal_flows(registry: &mut WindowsPacketFlowRegistry, retained_limit: usize) {
    let terminal_count = registry
        .flows
        .values()
        .filter(|flow| flow.phase.is_terminal())
        .count();
    let remove_count = terminal_count.saturating_sub(retained_limit);
    if remove_count == 0 {
        return;
    }
    let mut terminal: Vec<_> = registry
        .flows
        .iter()
        .filter(|(_, flow)| flow.phase.is_terminal())
        .map(|(key, flow)| (flow.updated_at_ms, *key))
        .collect();
    terminal.sort_unstable();
    for (_, key) in terminal.into_iter().take(remove_count) {
        registry.flows.remove(&key);
    }
}

pub fn reduce_windows_packet_flow(
    registry: &WindowsPacketFlowRegistry,
    event: &WindowsPacketFlowEvent,
    config: &WindowsPacketFlowConfig,
) -> Result<WindowsPacketFlowTransition, WindowsPacketFlowError> {
    config.validate()?;
    let now_ms = event.now_ms();
    if now_ms < registry.updated_at_ms {
        return Err(WindowsPacketFlowError::NonMonotonicEvent);
    }
    let mut next = registry.clone();
    next.updated_at_ms = now_ms;
    let mut commands = Vec::new();

    if let WindowsPacketFlowEvent::CaptureGenerationRetired {
        capture_generation, ..
    } = event
    {
        if *capture_generation == 0
            || *capture_generation <= next.retired_capture_generation_high_watermark
        {
            return Ok(WindowsPacketFlowTransition {
                state: next,
                commands,
            });
        }
        if next.flows.iter().any(|(key, flow)| {
            key.capture_generation <= *capture_generation && !flow.phase.is_terminal()
        }) {
            return Err(WindowsPacketFlowError::ActiveCaptureGenerationRetirement);
        }
        next.retired_capture_generation_high_watermark = *capture_generation;
        next.capture_flow_owners
            .retain(|identity, _| identity.capture_generation > *capture_generation);
        next.flows
            .retain(|key, _| key.capture_generation > *capture_generation);
        return Ok(WindowsPacketFlowTransition {
            state: next,
            commands,
        });
    }

    let key = event
        .flow_key()
        .ok_or(WindowsPacketFlowError::InvalidTransition)?;

    if let WindowsPacketFlowEvent::FlowOpened { admission, .. } = event {
        let identity = key.capture_identity();
        if key.capture_generation <= next.retired_capture_generation_high_watermark {
            reject_admission(
                admission,
                key,
                now_ms,
                "capture_generation_retired",
                &mut commands,
            );
        } else if let Some(owner) = next.capture_flow_owners.get(&identity) {
            if *owner != key {
                reject_admission(
                    admission,
                    key,
                    now_ms,
                    "capture_flow_already_owned",
                    &mut commands,
                );
            }
            return Ok(WindowsPacketFlowTransition {
                state: next,
                commands,
            });
        } else if now_ms >= admission.expires_at_ms {
            reject_admission(admission, key, now_ms, "admission_expired", &mut commands);
        } else if next.capture_flow_owners.len() >= config.max_retained_flow_identities {
            reject_admission(admission, key, now_ms, "identity_limit", &mut commands);
        } else if next.active_flow_count() >= config.max_active_flows {
            reject_admission(admission, key, now_ms, "flow_limit", &mut commands);
        } else {
            let idle_deadline_at_ms = now_ms
                .checked_add(config.idle_timeout_ms)
                .ok_or(WindowsPacketFlowError::TimeOverflow)?;
            next.capture_flow_owners.insert(identity, key);
            next.flows.insert(
                key,
                WindowsPacketFlowState {
                    admission: admission.clone(),
                    phase: WindowsPacketFlowPhase::Opening,
                    backend_ready: false,
                    client_input_open: true,
                    backend_input_open: true,
                    client_half_close_forwarded: false,
                    backend_half_close_forwarded: false,
                    client_to_backend: WindowsPacketFlowQueue::new(),
                    backend_to_client: WindowsPacketFlowQueue::new(),
                    idle_deadline_at_ms,
                    resource_owned: true,
                    terminal_reason: String::new(),
                    updated_at_ms: now_ms,
                },
            );
            commands.push(WindowsPacketFlowCommand::OpenBackend {
                key,
                session_id: admission.session_id,
                request: admission.request.clone(),
                egress: admission.egress.clone(),
                destination_port: admission.destination_port,
            });
            commands.push(WindowsPacketFlowCommand::ScheduleIdleDeadline {
                key,
                at_ms: idle_deadline_at_ms,
            });
        }
        prune_terminal_flows(&mut next, config.max_retained_terminal_flows);
        return Ok(WindowsPacketFlowTransition {
            state: next,
            commands,
        });
    }

    let Some(flow) = next.flows.get_mut(&key) else {
        return Ok(WindowsPacketFlowTransition {
            state: next,
            commands,
        });
    };
    if flow.phase.is_terminal() {
        return Ok(WindowsPacketFlowTransition {
            state: next,
            commands,
        });
    }

    match event {
        WindowsPacketFlowEvent::BackendReady { .. } => {
            if flow.backend_ready {
                return Ok(WindowsPacketFlowTransition {
                    state: next,
                    commands,
                });
            }
            if !matches!(
                flow.phase,
                WindowsPacketFlowPhase::Opening | WindowsPacketFlowPhase::Draining
            ) {
                return Err(WindowsPacketFlowError::InvalidTransition);
            }
            flow.backend_ready = true;
            if flow.phase == WindowsPacketFlowPhase::Opening {
                flow.phase = WindowsPacketFlowPhase::Relaying;
            }
            commands.push(data_plane_event(
                flow,
                now_ms,
                |now_ms, request_id, session_id| WindowsDataPlaneEvent::BackendConnected {
                    now_ms,
                    request_id,
                    session_id,
                },
            ));
            for frame in &flow.client_to_backend.frames {
                commands.push(WindowsPacketFlowCommand::Forward {
                    key,
                    direction: WindowsPacketFlowDirection::ClientToBackend,
                    sequence: frame.sequence,
                    bytes: frame.bytes,
                });
            }
            maybe_forward_half_close(
                flow,
                key,
                WindowsPacketFlowDirection::ClientToBackend,
                &mut commands,
            );
            refresh_idle(flow, key, now_ms, config, &mut commands)?;
        }
        WindowsPacketFlowEvent::Payload {
            direction,
            sequence,
            bytes,
            ..
        } => {
            if *bytes == 0 {
                return Err(WindowsPacketFlowError::EmptyPayload);
            }
            if *bytes > config.max_chunk_bytes {
                return Err(WindowsPacketFlowError::PayloadTooLarge);
            }
            let input_open = match direction {
                WindowsPacketFlowDirection::ClientToBackend => flow.client_input_open,
                WindowsPacketFlowDirection::BackendToClient => flow.backend_input_open,
            };
            if !input_open
                || (*direction == WindowsPacketFlowDirection::BackendToClient
                    && !flow.backend_ready)
            {
                return Err(WindowsPacketFlowError::InvalidTransition);
            }
            let next_sequence = flow.queue(*direction).next_sequence;
            if *sequence < next_sequence {
                return Ok(WindowsPacketFlowTransition {
                    state: next,
                    commands,
                });
            }
            if *sequence != next_sequence {
                return Err(WindowsPacketFlowError::OutOfOrderPayload);
            }
            let new_bytes = flow
                .queue(*direction)
                .bytes
                .checked_add(*bytes)
                .ok_or(WindowsPacketFlowError::ByteCountOverflow)?;
            if flow.queue(*direction).frames.len() >= config.max_queued_frames_per_direction {
                fail_backend(flow, key, now_ms, "packet_flow_frame_limit", &mut commands);
            } else if new_bytes > config.max_buffered_bytes {
                fail_backend(flow, key, now_ms, "packet_flow_buffer_limit", &mut commands);
            } else {
                let backend_ready = flow.backend_ready;
                let mut backpressure_deadline = None;
                {
                    let queue = flow.queue_mut(*direction);
                    queue.frames.push_back(WindowsPacketFlowFrame {
                        sequence: *sequence,
                        bytes: *bytes,
                    });
                    queue.bytes = new_bytes;
                    queue.next_sequence = queue
                        .next_sequence
                        .checked_add(1)
                        .ok_or(WindowsPacketFlowError::SequenceOverflow)?;
                    if queue.bytes >= config.high_watermark_bytes && !queue.paused {
                        queue.paused = true;
                        let deadline = now_ms
                            .checked_add(config.backpressure_timeout_ms)
                            .ok_or(WindowsPacketFlowError::TimeOverflow)?;
                        queue.backpressure_deadline_at_ms = Some(deadline);
                        backpressure_deadline = Some(deadline);
                    }
                }
                let should_forward =
                    *direction == WindowsPacketFlowDirection::BackendToClient || backend_ready;
                if should_forward {
                    commands.push(WindowsPacketFlowCommand::Forward {
                        key,
                        direction: *direction,
                        sequence: *sequence,
                        bytes: *bytes,
                    });
                }
                if let Some(deadline) = backpressure_deadline {
                    commands.push(WindowsPacketFlowCommand::PauseReads {
                        key,
                        direction: *direction,
                    });
                    commands.push(WindowsPacketFlowCommand::ScheduleBackpressureDeadline {
                        key,
                        direction: *direction,
                        at_ms: deadline,
                    });
                }
                refresh_idle(flow, key, now_ms, config, &mut commands)?;
            }
        }
        WindowsPacketFlowEvent::Forwarded {
            direction,
            through_sequence,
            ..
        } => {
            let Some(last_sequence) = flow
                .queue(*direction)
                .frames
                .back()
                .map(|frame| frame.sequence)
            else {
                return Ok(WindowsPacketFlowTransition {
                    state: next,
                    commands,
                });
            };
            if *through_sequence > last_sequence {
                return Err(WindowsPacketFlowError::InvalidForwardAcknowledgement);
            }
            let (forwarded_bytes, resume_reads) = {
                let queue = flow.queue_mut(*direction);
                let mut forwarded_bytes = 0usize;
                while queue
                    .frames
                    .front()
                    .is_some_and(|frame| frame.sequence <= *through_sequence)
                {
                    let Some(frame) = queue.frames.pop_front() else {
                        break;
                    };
                    forwarded_bytes = forwarded_bytes
                        .checked_add(frame.bytes)
                        .ok_or(WindowsPacketFlowError::ByteCountOverflow)?;
                }
                queue.bytes = queue
                    .bytes
                    .checked_sub(forwarded_bytes)
                    .ok_or(WindowsPacketFlowError::QueueAccountingMismatch)?;
                let resume_reads = queue.paused && queue.bytes <= config.low_watermark_bytes;
                if resume_reads {
                    queue.paused = false;
                    queue.backpressure_deadline_at_ms = None;
                }
                (forwarded_bytes, resume_reads)
            };
            if resume_reads {
                commands.push(WindowsPacketFlowCommand::ResumeReads {
                    key,
                    direction: *direction,
                });
            }
            if *direction == WindowsPacketFlowDirection::BackendToClient && forwarded_bytes > 0 {
                commands.push(WindowsPacketFlowCommand::DataPlane {
                    event: WindowsDataPlaneEvent::PayloadReceived {
                        now_ms,
                        request_id: flow.admission.request.request_id.clone(),
                        session_id: flow.admission.session_id,
                        bytes: forwarded_bytes as u64,
                    },
                });
            }
            maybe_forward_half_close(flow, key, *direction, &mut commands);
            maybe_finish_gracefully(flow, key, now_ms, &mut commands);
            if !flow.phase.is_terminal() {
                refresh_idle(flow, key, now_ms, config, &mut commands)?;
            }
        }
        WindowsPacketFlowEvent::HalfClosed { direction, .. } => {
            if flow.admission.key.transport != WindowsPacketFlowTransport::Tcp {
                return Err(WindowsPacketFlowError::InvalidTransportTransition);
            }
            if *direction == WindowsPacketFlowDirection::BackendToClient && !flow.backend_ready {
                return Err(WindowsPacketFlowError::InvalidTransition);
            }
            match direction {
                WindowsPacketFlowDirection::ClientToBackend if flow.client_input_open => {
                    flow.client_input_open = false;
                }
                WindowsPacketFlowDirection::BackendToClient if flow.backend_input_open => {
                    flow.backend_input_open = false;
                }
                _ => {
                    return Ok(WindowsPacketFlowTransition {
                        state: next,
                        commands,
                    })
                }
            }
            maybe_forward_half_close(flow, key, *direction, &mut commands);
            maybe_finish_gracefully(flow, key, now_ms, &mut commands);
            if !flow.phase.is_terminal() {
                refresh_idle(flow, key, now_ms, config, &mut commands)?;
            }
        }
        WindowsPacketFlowEvent::DatagramSideClosed { .. } => {
            if flow.admission.key.transport != WindowsPacketFlowTransport::Udp {
                return Err(WindowsPacketFlowError::InvalidTransportTransition);
            }
            if !flow.backend_ready {
                cancel_flow(
                    flow,
                    key,
                    now_ms,
                    "datagram_closed_before_backend_ready",
                    &mut commands,
                );
                prune_terminal_flows(&mut next, config.max_retained_terminal_flows);
                return Ok(WindowsPacketFlowTransition {
                    state: next,
                    commands,
                });
            }
            flow.client_input_open = false;
            flow.backend_input_open = false;
            maybe_finish_gracefully(flow, key, now_ms, &mut commands);
            if !flow.phase.is_terminal() {
                refresh_idle(flow, key, now_ms, config, &mut commands)?;
            }
        }
        WindowsPacketFlowEvent::Reset {
            direction, reason, ..
        } => {
            if *direction == WindowsPacketFlowDirection::BackendToClient {
                fail_backend(flow, key, now_ms, reason, &mut commands);
            } else {
                cancel_flow(flow, key, now_ms, reason, &mut commands);
            }
        }
        WindowsPacketFlowEvent::Cancelled { .. } => {
            cancel_flow(flow, key, now_ms, "packet_flow_cancelled", &mut commands);
        }
        WindowsPacketFlowEvent::IdleDeadline { .. } => {
            if now_ms < flow.idle_deadline_at_ms {
                return Ok(WindowsPacketFlowTransition {
                    state: next,
                    commands,
                });
            }
            fail_backend(flow, key, now_ms, "packet_flow_idle_timeout", &mut commands);
        }
        WindowsPacketFlowEvent::BackpressureDeadline { direction, .. } => {
            let queue = flow.queue(*direction);
            let Some(deadline) = queue.backpressure_deadline_at_ms else {
                return Ok(WindowsPacketFlowTransition {
                    state: next,
                    commands,
                });
            };
            if now_ms < deadline || !queue.paused {
                return Ok(WindowsPacketFlowTransition {
                    state: next,
                    commands,
                });
            }
            fail_backend(
                flow,
                key,
                now_ms,
                "packet_flow_backpressure_timeout",
                &mut commands,
            );
        }
        WindowsPacketFlowEvent::FlowOpened { .. }
        | WindowsPacketFlowEvent::CaptureGenerationRetired { .. } => {
            unreachable!("handled above")
        }
    }

    prune_terminal_flows(&mut next, config.max_retained_terminal_flows);
    Ok(WindowsPacketFlowTransition {
        state: next,
        commands,
    })
}

//! Version 1 pure packet-to-flow forwarding state machine.
//!
//! The contract begins after packet capture/classification and outbound-route
//! admission. It owns bounded ordered payload metadata and emits abstract
//! forwarding commands keyed by direction and sequence. A future effect keeps
//! the corresponding immutable bytes under that identity until `Forwarded`;
//! one reduction consumes registry ownership and clones only the bounded flow
//! it touches. The contract does not
//! reconstruct TCP, open sockets, load an adapter, install routes, or compose
//! the production service host.

use crate::data_plane::{
    validate_windows_data_plane_request, WindowsDataPlaneEvent, WindowsDataPlaneRequest,
    WindowsDataPlaneSessionPhase, WindowsDataPlaneState, WindowsDataPlaneWorkerPhase,
};
use crate::packet_adapter::v3::{WindowsPacketCaptureTransport, WindowsPacketPolicyClassification};
use crate::packet_egress::WindowsPacketEgressPlan;
use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::RoutingPolicyTables;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
    accepted_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct WindowsPacketFlowSessionBinding {
    session_id: u64,
    request: WindowsDataPlaneRequest,
    accepted_at_ms: u64,
    checked_at_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct WindowsPacketFlowOpen {
    admission: WindowsPacketFlowAdmission,
    current_session: WindowsPacketFlowSessionBinding,
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
    DataPlaneWorkerNotReady,
    DataPlaneSessionNotFound,
    DataPlaneSessionMismatch,
    DataPlaneSessionNotOpening,
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

/// Mints an opaque one-shot binding only from an accepted, still-opening
/// data-plane session. Packet admission never accepts a free-standing session
/// ID beside an unrelated request.
pub fn bind_windows_packet_flow_session(
    data_plane: &WindowsDataPlaneState,
    request_id: &str,
    session_id: u64,
    now_ms: u64,
) -> Result<WindowsPacketFlowSessionBinding, WindowsPacketFlowAdmissionErrorCode> {
    if session_id == 0 {
        return Err(WindowsPacketFlowAdmissionErrorCode::InvalidSessionId);
    }
    if data_plane.worker_phase != WindowsDataPlaneWorkerPhase::Ready {
        return Err(WindowsPacketFlowAdmissionErrorCode::DataPlaneWorkerNotReady);
    }
    let session = data_plane
        .sessions
        .get(request_id)
        .ok_or(WindowsPacketFlowAdmissionErrorCode::DataPlaneSessionNotFound)?;
    if session.session_id != session_id {
        return Err(WindowsPacketFlowAdmissionErrorCode::DataPlaneSessionMismatch);
    }
    if session.phase != WindowsDataPlaneSessionPhase::Opening
        || session.cancel_requested
        || !session.resource_owned
    {
        return Err(WindowsPacketFlowAdmissionErrorCode::DataPlaneSessionNotOpening);
    }
    if now_ms < data_plane.updated_at_ms || now_ms < session.updated_at_ms {
        return Err(WindowsPacketFlowAdmissionErrorCode::InvalidDataPlaneWindow);
    }
    Ok(WindowsPacketFlowSessionBinding {
        session_id,
        request: session.request.clone(),
        accepted_at_ms: session.updated_at_ms,
        checked_at_ms: now_ms,
    })
}

/// Binds the three existing pure boundaries without exposing an authorizing
/// constructor for the resulting admission token.
pub fn prepare_windows_packet_flow(
    classification: &WindowsPacketPolicyClassification,
    egress: &WindowsPacketEgressPlan,
    data_plane: &WindowsDataPlaneState,
    session: WindowsPacketFlowSessionBinding,
    now_ms: u64,
    policy_tables: &RoutingPolicyTables,
) -> Result<WindowsPacketFlowAdmission, WindowsPacketFlowAdmissionErrorCode> {
    let WindowsPacketFlowSessionBinding {
        session_id,
        request,
        accepted_at_ms,
        checked_at_ms,
    } = session;
    if data_plane.worker_phase != WindowsDataPlaneWorkerPhase::Ready {
        return Err(WindowsPacketFlowAdmissionErrorCode::DataPlaneWorkerNotReady);
    }
    let current_session = data_plane
        .sessions
        .get(&request.request_id)
        .ok_or(WindowsPacketFlowAdmissionErrorCode::DataPlaneSessionNotFound)?;
    if current_session.session_id != session_id || current_session.request != request {
        return Err(WindowsPacketFlowAdmissionErrorCode::DataPlaneSessionMismatch);
    }
    if current_session.phase != WindowsDataPlaneSessionPhase::Opening
        || current_session.cancel_requested
        || !current_session.resource_owned
        || current_session.updated_at_ms != accepted_at_ms
        || checked_at_ms != now_ms
    {
        return Err(WindowsPacketFlowAdmissionErrorCode::DataPlaneSessionNotOpening);
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
    validate_windows_data_plane_request(&request, policy_tables)
        .map_err(|_| WindowsPacketFlowAdmissionErrorCode::InvalidDataPlaneRequest)?;
    if now_ms < accepted_at_ms
        || now_ms < request.started_at_ms
        || now_ms >= request.first_payload_deadline_at_ms
    {
        return Err(WindowsPacketFlowAdmissionErrorCode::InvalidDataPlaneWindow);
    }
    if request.policy != *classification.policy() {
        return Err(WindowsPacketFlowAdmissionErrorCode::PolicyMismatch);
    }
    let expires_at_ms = classification
        .expires_at_ms()
        .min(egress.expires_at_ms())
        .min(request.first_payload_deadline_at_ms);

    Ok(WindowsPacketFlowAdmission {
        key: WindowsPacketFlowKey {
            capture_generation: classification.capture_generation(),
            flow_id: classification.flow_id(),
            transport,
            session_id,
        },
        session_id,
        request,
        egress: egress.clone(),
        destination: classification.destination().to_string(),
        destination_port: classification.destination_port(),
        accepted_at_ms,
        expires_at_ms,
    })
}

/// Revalidates the accepted data-plane session at the exact backend-open event
/// boundary. The returned event is opaque and cannot be constructed from a
/// delayed admission alone.
pub fn prepare_windows_packet_flow_open(
    admission: WindowsPacketFlowAdmission,
    data_plane: &WindowsDataPlaneState,
    now_ms: u64,
) -> Result<WindowsPacketFlowEvent, WindowsPacketFlowAdmissionErrorCode> {
    let current_session = bind_windows_packet_flow_session(
        data_plane,
        &admission.request.request_id,
        admission.session_id,
        now_ms,
    )?;
    if current_session.request != admission.request
        || current_session.accepted_at_ms != admission.accepted_at_ms
    {
        return Err(WindowsPacketFlowAdmissionErrorCode::DataPlaneSessionMismatch);
    }
    Ok(WindowsPacketFlowEvent::FlowOpened {
        now_ms,
        open: Box::new(WindowsPacketFlowOpen {
            admission,
            current_session,
        }),
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
    pub data_plane_session_owners: BTreeMap<u64, WindowsPacketFlowKey>,
    pub data_plane_request_owners: BTreeMap<String, WindowsPacketFlowKey>,
    pub flows: BTreeMap<WindowsPacketFlowKey, WindowsPacketFlowState>,
    terminal_flow_order: BTreeSet<(u64, WindowsPacketFlowKey)>,
    active_flows: usize,
}

impl WindowsPacketFlowRegistry {
    pub fn new(started_at_ms: u64) -> Self {
        Self {
            started_at_ms,
            updated_at_ms: started_at_ms,
            retired_capture_generation_high_watermark: 0,
            capture_flow_owners: BTreeMap::new(),
            data_plane_session_owners: BTreeMap::new(),
            data_plane_request_owners: BTreeMap::new(),
            flows: BTreeMap::new(),
            terminal_flow_order: BTreeSet::new(),
            active_flows: 0,
        }
    }

    pub const fn active_flow_count(&self) -> usize {
        self.active_flows
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum WindowsPacketFlowEvent {
    FlowOpened {
        now_ms: u64,
        open: Box<WindowsPacketFlowOpen>,
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
            Self::FlowOpened { open, .. } => Some(open.admission.key()),
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

impl WindowsPacketFlowCommand {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::OpenBackend { .. } => "open_backend",
            Self::Forward { .. } => "forward",
            Self::PauseReads { .. } => "pause_reads",
            Self::ResumeReads { .. } => "resume_reads",
            Self::HalfCloseWrite { .. } => "half_close_write",
            Self::CloseFlow { .. } => "close_flow",
            Self::ScheduleIdleDeadline { .. } => "schedule_idle_deadline",
            Self::ScheduleBackpressureDeadline { .. } => "schedule_backpressure_deadline",
            Self::DataPlane { .. } => "data_plane",
            Self::RejectFlow { .. } => "reject_flow",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WindowsPacketFlowTransition {
    pub state: WindowsPacketFlowRegistry,
    pub commands: Vec<WindowsPacketFlowCommand>,
}

pub trait WindowsPacketFlowEffects {
    type Error: fmt::Display;

    /// Executes one command atomically. A failed command must leave no visible
    /// effect; commands before the retry cursor remain committed.
    fn execute(&mut self, command: &WindowsPacketFlowCommand) -> Result<(), Self::Error>;
}

pub fn execute_windows_packet_flow_transition<E: WindowsPacketFlowEffects>(
    transition: &WindowsPacketFlowTransition,
    effects: &mut E,
) -> Result<(), WindowsPacketFlowEffectExecutionError> {
    execute_windows_packet_flow_transition_from(transition, effects, 0)
}

/// Resumes the retained transition without replaying its completed prefix.
/// The caller commits `transition.state` only after this returns `Ok`.
pub fn execute_windows_packet_flow_transition_from<E: WindowsPacketFlowEffects>(
    transition: &WindowsPacketFlowTransition,
    effects: &mut E,
    next_command_index: usize,
) -> Result<(), WindowsPacketFlowEffectExecutionError> {
    if next_command_index > transition.commands.len() {
        return Err(WindowsPacketFlowEffectExecutionError {
            command: "transition_cursor",
            message: format!(
                "command cursor {next_command_index} exceeds batch length {}",
                transition.commands.len()
            ),
            failed_command_index: next_command_index,
            next_command_index,
            completed_commands: 0,
        });
    }

    for (command_index, command) in transition
        .commands
        .iter()
        .enumerate()
        .skip(next_command_index)
    {
        effects
            .execute(command)
            .map_err(|error| WindowsPacketFlowEffectExecutionError {
                command: command.kind(),
                message: error.to_string(),
                failed_command_index: command_index,
                next_command_index: command_index,
                completed_commands: command_index,
            })?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketFlowEffectExecutionError {
    pub command: &'static str,
    pub message: String,
    pub failed_command_index: usize,
    pub next_command_index: usize,
    pub completed_commands: usize,
}

impl fmt::Display for WindowsPacketFlowEffectExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} effect at command {} failed after {} completed command(s): {}",
            self.command, self.failed_command_index, self.completed_commands, self.message
        )
    }
}

impl std::error::Error for WindowsPacketFlowEffectExecutionError {}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketFlowReductionError {
    pub state: Box<WindowsPacketFlowRegistry>,
    pub error: WindowsPacketFlowError,
}

impl fmt::Display for WindowsPacketFlowReductionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for WindowsPacketFlowReductionError {}

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
    reject_flow(key, reason, commands);
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

fn reject_flow(
    key: WindowsPacketFlowKey,
    reason: &str,
    commands: &mut Vec<WindowsPacketFlowCommand>,
) {
    commands.push(WindowsPacketFlowCommand::RejectFlow {
        key,
        reason: reason.to_owned(),
    });
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

fn close_for_directional_pressure(
    flow: &mut WindowsPacketFlowState,
    key: WindowsPacketFlowKey,
    now_ms: u64,
    direction: WindowsPacketFlowDirection,
    reason: &str,
    commands: &mut Vec<WindowsPacketFlowCommand>,
) {
    match direction {
        WindowsPacketFlowDirection::ClientToBackend => {
            fail_backend(flow, key, now_ms, reason, commands);
        }
        WindowsPacketFlowDirection::BackendToClient => {
            cancel_flow(flow, key, now_ms, reason, commands);
        }
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
    while registry.terminal_flow_order.len() > retained_limit {
        let Some((_, key)) = registry.terminal_flow_order.pop_first() else {
            break;
        };
        registry.flows.remove(&key);
    }
}

fn finish_transition(
    mut state: WindowsPacketFlowRegistry,
    now_ms: u64,
    commands: Vec<WindowsPacketFlowCommand>,
    retained_limit: usize,
) -> WindowsPacketFlowTransition {
    state.updated_at_ms = now_ms;
    prune_terminal_flows(&mut state, retained_limit);
    WindowsPacketFlowTransition { state, commands }
}

pub fn reduce_windows_packet_flow(
    mut registry: WindowsPacketFlowRegistry,
    event: &WindowsPacketFlowEvent,
    config: &WindowsPacketFlowConfig,
) -> Result<WindowsPacketFlowTransition, WindowsPacketFlowReductionError> {
    macro_rules! fail {
        ($error:expr) => {
            return Err(WindowsPacketFlowReductionError {
                state: Box::new(registry),
                error: $error,
            })
        };
    }
    macro_rules! try_flow {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(error) => fail!(error),
            }
        };
    }

    if let Err(error) = config.validate() {
        fail!(error);
    }
    let now_ms = event.now_ms();
    if now_ms < registry.updated_at_ms {
        fail!(WindowsPacketFlowError::NonMonotonicEvent);
    }
    let mut commands = Vec::new();

    if let WindowsPacketFlowEvent::CaptureGenerationRetired {
        capture_generation, ..
    } = event
    {
        if *capture_generation == 0
            || *capture_generation <= registry.retired_capture_generation_high_watermark
        {
            return Ok(finish_transition(
                registry,
                now_ms,
                commands,
                config.max_retained_terminal_flows,
            ));
        }
        if registry.flows.iter().any(|(key, flow)| {
            key.capture_generation <= *capture_generation && !flow.phase.is_terminal()
        }) {
            fail!(WindowsPacketFlowError::ActiveCaptureGenerationRetirement);
        }
        registry.retired_capture_generation_high_watermark = *capture_generation;
        registry
            .capture_flow_owners
            .retain(|identity, _| identity.capture_generation > *capture_generation);
        registry
            .data_plane_session_owners
            .retain(|_, key| key.capture_generation > *capture_generation);
        registry
            .data_plane_request_owners
            .retain(|_, key| key.capture_generation > *capture_generation);
        registry
            .terminal_flow_order
            .retain(|(_, key)| key.capture_generation > *capture_generation);
        registry
            .flows
            .retain(|key, _| key.capture_generation > *capture_generation);
        return Ok(finish_transition(
            registry,
            now_ms,
            commands,
            config.max_retained_terminal_flows,
        ));
    }

    let key = event
        .flow_key()
        .unwrap_or_else(|| unreachable!("capture retirement was handled above"));

    if let WindowsPacketFlowEvent::FlowOpened { open, .. } = event {
        let admission = &open.admission;
        let identity = key.capture_identity();
        let session_owner = registry
            .data_plane_session_owners
            .get(&admission.session_id)
            .copied();
        let request_owner = registry
            .data_plane_request_owners
            .get(&admission.request.request_id)
            .copied();
        if open.current_session.checked_at_ms != now_ms
            || open.current_session.session_id != admission.session_id
            || open.current_session.request != admission.request
            || open.current_session.accepted_at_ms != admission.accepted_at_ms
        {
            reject_flow(key, "data_plane_session_not_current", &mut commands);
        } else if session_owner.is_some_and(|owner| owner != key) {
            reject_flow(key, "data_plane_session_already_owned", &mut commands);
        } else if request_owner.is_some_and(|owner| owner != key) {
            reject_admission(
                admission,
                key,
                now_ms,
                "data_plane_request_already_owned",
                &mut commands,
            );
        } else if key.capture_generation <= registry.retired_capture_generation_high_watermark {
            reject_admission(
                admission,
                key,
                now_ms,
                "capture_generation_retired",
                &mut commands,
            );
        } else if let Some(owner) = registry.capture_flow_owners.get(&identity) {
            if *owner != key {
                reject_admission(
                    admission,
                    key,
                    now_ms,
                    "capture_flow_already_owned",
                    &mut commands,
                );
            }
            return Ok(finish_transition(
                registry,
                now_ms,
                commands,
                config.max_retained_terminal_flows,
            ));
        } else if now_ms >= admission.expires_at_ms {
            reject_admission(admission, key, now_ms, "admission_expired", &mut commands);
        } else if registry.capture_flow_owners.len() >= config.max_retained_flow_identities {
            reject_admission(admission, key, now_ms, "identity_limit", &mut commands);
        } else if registry.active_flow_count() >= config.max_active_flows {
            reject_admission(admission, key, now_ms, "flow_limit", &mut commands);
        } else {
            let idle_deadline_at_ms = match now_ms.checked_add(config.idle_timeout_ms) {
                Some(deadline) => deadline,
                None => fail!(WindowsPacketFlowError::TimeOverflow),
            };
            registry.capture_flow_owners.insert(identity, key);
            registry
                .data_plane_session_owners
                .insert(admission.session_id, key);
            registry
                .data_plane_request_owners
                .insert(admission.request.request_id.clone(), key);
            registry.flows.insert(
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
            registry.active_flows += 1;
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
        return Ok(finish_transition(
            registry,
            now_ms,
            commands,
            config.max_retained_terminal_flows,
        ));
    }

    let Some(existing_flow) = registry.flows.get(&key) else {
        return Ok(finish_transition(
            registry,
            now_ms,
            commands,
            config.max_retained_terminal_flows,
        ));
    };
    if existing_flow.phase.is_terminal() {
        return Ok(finish_transition(
            registry,
            now_ms,
            commands,
            config.max_retained_terminal_flows,
        ));
    }
    let mut flow = existing_flow.clone();

    match event {
        WindowsPacketFlowEvent::BackendReady { .. } => {
            if flow.backend_ready {
                return Ok(finish_transition(
                    registry,
                    now_ms,
                    commands,
                    config.max_retained_terminal_flows,
                ));
            }
            if !matches!(
                flow.phase,
                WindowsPacketFlowPhase::Opening | WindowsPacketFlowPhase::Draining
            ) {
                fail!(WindowsPacketFlowError::InvalidTransition);
            }
            flow.backend_ready = true;
            if flow.phase == WindowsPacketFlowPhase::Opening {
                flow.phase = WindowsPacketFlowPhase::Relaying;
            }
            commands.push(data_plane_event(
                &flow,
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
                &mut flow,
                key,
                WindowsPacketFlowDirection::ClientToBackend,
                &mut commands,
            );
            try_flow!(refresh_idle(&mut flow, key, now_ms, config, &mut commands));
        }
        WindowsPacketFlowEvent::Payload {
            direction,
            sequence,
            bytes,
            ..
        } => {
            if *bytes == 0 {
                fail!(WindowsPacketFlowError::EmptyPayload);
            }
            if *bytes > config.max_chunk_bytes {
                fail!(WindowsPacketFlowError::PayloadTooLarge);
            }
            let input_open = match direction {
                WindowsPacketFlowDirection::ClientToBackend => flow.client_input_open,
                WindowsPacketFlowDirection::BackendToClient => flow.backend_input_open,
            };
            if !input_open
                || (*direction == WindowsPacketFlowDirection::BackendToClient
                    && !flow.backend_ready)
            {
                fail!(WindowsPacketFlowError::InvalidTransition);
            }
            let next_sequence = flow.queue(*direction).next_sequence;
            if *sequence < next_sequence {
                return Ok(finish_transition(
                    registry,
                    now_ms,
                    commands,
                    config.max_retained_terminal_flows,
                ));
            }
            if *sequence != next_sequence {
                fail!(WindowsPacketFlowError::OutOfOrderPayload);
            }
            let new_bytes = match flow.queue(*direction).bytes.checked_add(*bytes) {
                Some(bytes) => bytes,
                None => fail!(WindowsPacketFlowError::ByteCountOverflow),
            };
            if flow.queue(*direction).frames.len() >= config.max_queued_frames_per_direction {
                let reason = match direction {
                    WindowsPacketFlowDirection::ClientToBackend => "packet_flow_frame_limit",
                    WindowsPacketFlowDirection::BackendToClient => "packet_flow_client_frame_limit",
                };
                close_for_directional_pressure(
                    &mut flow,
                    key,
                    now_ms,
                    *direction,
                    reason,
                    &mut commands,
                );
            } else if new_bytes > config.max_buffered_bytes {
                let reason = match direction {
                    WindowsPacketFlowDirection::ClientToBackend => "packet_flow_buffer_limit",
                    WindowsPacketFlowDirection::BackendToClient => {
                        "packet_flow_client_buffer_limit"
                    }
                };
                close_for_directional_pressure(
                    &mut flow,
                    key,
                    now_ms,
                    *direction,
                    reason,
                    &mut commands,
                );
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
                    queue.next_sequence = match queue.next_sequence.checked_add(1) {
                        Some(sequence) => sequence,
                        None => fail!(WindowsPacketFlowError::SequenceOverflow),
                    };
                    if queue.bytes >= config.high_watermark_bytes && !queue.paused {
                        queue.paused = true;
                        let deadline = match now_ms.checked_add(config.backpressure_timeout_ms) {
                            Some(deadline) => deadline,
                            None => fail!(WindowsPacketFlowError::TimeOverflow),
                        };
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
                try_flow!(refresh_idle(&mut flow, key, now_ms, config, &mut commands));
            }
        }
        WindowsPacketFlowEvent::Forwarded {
            direction,
            through_sequence,
            ..
        } => {
            if !flow.backend_ready {
                fail!(WindowsPacketFlowError::InvalidForwardAcknowledgement);
            }
            let input_open = match direction {
                WindowsPacketFlowDirection::ClientToBackend => flow.client_input_open,
                WindowsPacketFlowDirection::BackendToClient => flow.backend_input_open,
            };
            let Some(last_sequence) = flow
                .queue(*direction)
                .frames
                .back()
                .map(|frame| frame.sequence)
            else {
                return Ok(finish_transition(
                    registry,
                    now_ms,
                    commands,
                    config.max_retained_terminal_flows,
                ));
            };
            if *through_sequence > last_sequence {
                fail!(WindowsPacketFlowError::InvalidForwardAcknowledgement);
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
                    forwarded_bytes = match forwarded_bytes.checked_add(frame.bytes) {
                        Some(bytes) => bytes,
                        None => fail!(WindowsPacketFlowError::ByteCountOverflow),
                    };
                }
                queue.bytes = match queue.bytes.checked_sub(forwarded_bytes) {
                    Some(bytes) => bytes,
                    None => fail!(WindowsPacketFlowError::QueueAccountingMismatch),
                };
                let clear_backpressure = queue.paused && queue.bytes <= config.low_watermark_bytes;
                if clear_backpressure {
                    queue.paused = false;
                    queue.backpressure_deadline_at_ms = None;
                }
                (forwarded_bytes, clear_backpressure && input_open)
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
            if forwarded_bytes == 0 {
                return Ok(finish_transition(
                    registry,
                    now_ms,
                    commands,
                    config.max_retained_terminal_flows,
                ));
            }
            maybe_forward_half_close(&mut flow, key, *direction, &mut commands);
            maybe_finish_gracefully(&mut flow, key, now_ms, &mut commands);
            if !flow.phase.is_terminal() {
                try_flow!(refresh_idle(&mut flow, key, now_ms, config, &mut commands));
            }
        }
        WindowsPacketFlowEvent::HalfClosed { direction, .. } => {
            if flow.admission.key.transport != WindowsPacketFlowTransport::Tcp {
                fail!(WindowsPacketFlowError::InvalidTransportTransition);
            }
            if *direction == WindowsPacketFlowDirection::BackendToClient && !flow.backend_ready {
                fail!(WindowsPacketFlowError::InvalidTransition);
            }
            match direction {
                WindowsPacketFlowDirection::ClientToBackend if flow.client_input_open => {
                    flow.client_input_open = false;
                }
                WindowsPacketFlowDirection::BackendToClient if flow.backend_input_open => {
                    flow.backend_input_open = false;
                }
                _ => {
                    return Ok(finish_transition(
                        registry,
                        now_ms,
                        commands,
                        config.max_retained_terminal_flows,
                    ))
                }
            }
            maybe_forward_half_close(&mut flow, key, *direction, &mut commands);
            maybe_finish_gracefully(&mut flow, key, now_ms, &mut commands);
            if !flow.phase.is_terminal() {
                try_flow!(refresh_idle(&mut flow, key, now_ms, config, &mut commands));
            }
        }
        WindowsPacketFlowEvent::DatagramSideClosed { .. } => {
            if flow.admission.key.transport != WindowsPacketFlowTransport::Udp {
                fail!(WindowsPacketFlowError::InvalidTransportTransition);
            }
            if !flow.backend_ready {
                cancel_flow(
                    &mut flow,
                    key,
                    now_ms,
                    "datagram_closed_before_backend_ready",
                    &mut commands,
                );
            } else {
                flow.client_input_open = false;
                flow.backend_input_open = false;
                maybe_finish_gracefully(&mut flow, key, now_ms, &mut commands);
                if !flow.phase.is_terminal() {
                    try_flow!(refresh_idle(&mut flow, key, now_ms, config, &mut commands));
                }
            }
        }
        WindowsPacketFlowEvent::Reset {
            direction, reason, ..
        } => {
            if *direction == WindowsPacketFlowDirection::BackendToClient {
                fail_backend(&mut flow, key, now_ms, reason, &mut commands);
            } else {
                cancel_flow(&mut flow, key, now_ms, reason, &mut commands);
            }
        }
        WindowsPacketFlowEvent::Cancelled { .. } => {
            cancel_flow(
                &mut flow,
                key,
                now_ms,
                "packet_flow_cancelled",
                &mut commands,
            );
        }
        WindowsPacketFlowEvent::IdleDeadline { .. } => {
            if now_ms < flow.idle_deadline_at_ms {
                return Ok(finish_transition(
                    registry,
                    now_ms,
                    commands,
                    config.max_retained_terminal_flows,
                ));
            }
            if flow.backend_to_client.frames.is_empty() {
                fail_backend(
                    &mut flow,
                    key,
                    now_ms,
                    "packet_flow_idle_timeout",
                    &mut commands,
                );
            } else {
                cancel_flow(
                    &mut flow,
                    key,
                    now_ms,
                    "packet_flow_client_idle_timeout",
                    &mut commands,
                );
            }
        }
        WindowsPacketFlowEvent::BackpressureDeadline { direction, .. } => {
            let queue = flow.queue(*direction);
            let Some(deadline) = queue.backpressure_deadline_at_ms else {
                return Ok(finish_transition(
                    registry,
                    now_ms,
                    commands,
                    config.max_retained_terminal_flows,
                ));
            };
            if now_ms < deadline || !queue.paused {
                return Ok(finish_transition(
                    registry,
                    now_ms,
                    commands,
                    config.max_retained_terminal_flows,
                ));
            }
            let reason = match direction {
                WindowsPacketFlowDirection::ClientToBackend => "packet_flow_backpressure_timeout",
                WindowsPacketFlowDirection::BackendToClient => {
                    "packet_flow_client_backpressure_timeout"
                }
            };
            close_for_directional_pressure(
                &mut flow,
                key,
                now_ms,
                *direction,
                reason,
                &mut commands,
            );
        }
        WindowsPacketFlowEvent::FlowOpened { .. }
        | WindowsPacketFlowEvent::CaptureGenerationRetired { .. } => {
            unreachable!("handled above")
        }
    }

    if flow.phase.is_terminal() {
        registry.active_flows = registry.active_flows.saturating_sub(1);
        registry
            .terminal_flow_order
            .insert((flow.updated_at_ms, key));
    }
    registry.flows.insert(key, flow);
    Ok(finish_transition(
        registry,
        now_ms,
        commands,
        config.max_retained_terminal_flows,
    ))
}

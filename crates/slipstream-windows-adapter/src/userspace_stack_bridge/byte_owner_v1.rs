//! Version 1 bounded payload ownership for an injected Windows userspace stack.
//!
//! This module joins an opaque original-tuple binding to successful frozen
//! packet-flow v1 transitions. It owns exact payload bytes until an injected
//! forwarding effect succeeds. It does not instantiate a stack or perform any
//! native, packet, socket, route, DNS, proxy, PAC, VPN, process, or service
//! effect.

use super::WindowsUserspaceFlowBinding;
use crate::packet_flow::{
    WindowsPacketFlowCommand, WindowsPacketFlowConfig, WindowsPacketFlowDirection,
    WindowsPacketFlowEvent, WindowsPacketFlowKey, WindowsPacketFlowPhase,
    WindowsPacketFlowTransition,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

pub const WINDOWS_USERSPACE_BYTE_OWNER_CONTRACT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsUserspaceByteOwnerConfig {
    pub max_active_flows: usize,
    pub max_chunk_bytes: usize,
    pub max_queued_frames_per_direction: usize,
    pub max_buffered_bytes_per_direction: usize,
}

impl WindowsUserspaceByteOwnerConfig {
    pub fn from_packet_flow(
        config: &WindowsPacketFlowConfig,
    ) -> Result<Self, WindowsUserspaceByteOwnerErrorCode> {
        let owner = Self {
            max_active_flows: config.max_active_flows,
            max_chunk_bytes: config.max_chunk_bytes,
            max_queued_frames_per_direction: config.max_queued_frames_per_direction,
            max_buffered_bytes_per_direction: config.max_buffered_bytes,
        };
        owner.validate()?;
        Ok(owner)
    }

    pub fn max_owned_frames(self) -> Option<usize> {
        self.max_active_flows
            .checked_mul(self.max_queued_frames_per_direction)?
            .checked_mul(2)
    }

    pub fn max_owned_bytes(self) -> Option<usize> {
        self.max_active_flows
            .checked_mul(self.max_buffered_bytes_per_direction)?
            .checked_mul(2)
    }

    fn validate(self) -> Result<(), WindowsUserspaceByteOwnerErrorCode> {
        if self.max_active_flows == 0
            || self.max_chunk_bytes == 0
            || self.max_queued_frames_per_direction == 0
            || self.max_buffered_bytes_per_direction == 0
            || self.max_chunk_bytes > self.max_buffered_bytes_per_direction
            || self.max_owned_frames().is_none()
            || self.max_owned_bytes().is_none()
        {
            return Err(WindowsUserspaceByteOwnerErrorCode::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsUserspaceByteOwnerErrorCode {
    InvalidConfig,
    BindingExpired,
    FlowLimit,
    DuplicateFlow,
    UnknownFlow,
    PayloadEventRequired,
    PayloadLengthMismatch,
    PayloadTooLarge,
    TransitionMissingFlow,
    TransitionFlowInactive,
    TransitionDidNotAcceptPayload,
    StaleTransition,
    OutOfOrderPayload,
    FrameLimit,
    BufferLimit,
    ForwardCommandRequired,
    ForwardMetadataMismatch,
    OwnedPayloadMissing,
    EffectFailed,
}

impl WindowsUserspaceByteOwnerErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::BindingExpired => "binding_expired",
            Self::FlowLimit => "flow_limit",
            Self::DuplicateFlow => "duplicate_flow",
            Self::UnknownFlow => "unknown_flow",
            Self::PayloadEventRequired => "payload_event_required",
            Self::PayloadLengthMismatch => "payload_length_mismatch",
            Self::PayloadTooLarge => "payload_too_large",
            Self::TransitionMissingFlow => "transition_missing_flow",
            Self::TransitionFlowInactive => "transition_flow_inactive",
            Self::TransitionDidNotAcceptPayload => "transition_did_not_accept_payload",
            Self::StaleTransition => "stale_transition",
            Self::OutOfOrderPayload => "out_of_order_payload",
            Self::FrameLimit => "frame_limit",
            Self::BufferLimit => "buffer_limit",
            Self::ForwardCommandRequired => "forward_command_required",
            Self::ForwardMetadataMismatch => "forward_metadata_mismatch",
            Self::OwnedPayloadMissing => "owned_payload_missing",
            Self::EffectFailed => "effect_failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsUserspaceByteOwnerError {
    pub code: WindowsUserspaceByteOwnerErrorCode,
    pub message: String,
}

impl WindowsUserspaceByteOwnerError {
    fn new(code: WindowsUserspaceByteOwnerErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for WindowsUserspaceByteOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for WindowsUserspaceByteOwnerError {}

#[derive(Debug)]
struct WindowsUserspaceOwnedPayload {
    sequence: u64,
    bytes: Box<[u8]>,
}

#[derive(Debug)]
struct WindowsUserspaceByteQueue {
    frames: VecDeque<WindowsUserspaceOwnedPayload>,
    bytes: usize,
    next_sequence: u64,
}

impl WindowsUserspaceByteQueue {
    fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            bytes: 0,
            next_sequence: 1,
        }
    }
}

#[derive(Debug)]
struct WindowsUserspaceOwnedFlow {
    binding: WindowsUserspaceFlowBinding,
    client_to_backend: WindowsUserspaceByteQueue,
    backend_to_client: WindowsUserspaceByteQueue,
    updated_at_ms: u64,
}

impl WindowsUserspaceOwnedFlow {
    fn new(binding: WindowsUserspaceFlowBinding, now_ms: u64) -> Self {
        Self {
            binding,
            client_to_backend: WindowsUserspaceByteQueue::new(),
            backend_to_client: WindowsUserspaceByteQueue::new(),
            updated_at_ms: now_ms,
        }
    }

    fn queue(&self, direction: WindowsPacketFlowDirection) -> &WindowsUserspaceByteQueue {
        match direction {
            WindowsPacketFlowDirection::ClientToBackend => &self.client_to_backend,
            WindowsPacketFlowDirection::BackendToClient => &self.backend_to_client,
        }
    }

    fn queue_mut(
        &mut self,
        direction: WindowsPacketFlowDirection,
    ) -> &mut WindowsUserspaceByteQueue {
        match direction {
            WindowsPacketFlowDirection::ClientToBackend => &mut self.client_to_backend,
            WindowsPacketFlowDirection::BackendToClient => &mut self.backend_to_client,
        }
    }

    fn owned_frames(&self) -> usize {
        self.client_to_backend.frames.len() + self.backend_to_client.frames.len()
    }

    fn owned_bytes(&self) -> usize {
        self.client_to_backend.bytes + self.backend_to_client.bytes
    }
}

pub struct WindowsUserspaceByteDelivery<'a> {
    key: WindowsPacketFlowKey,
    binding: &'a WindowsUserspaceFlowBinding,
    direction: WindowsPacketFlowDirection,
    sequence: u64,
    bytes: &'a [u8],
}

impl WindowsUserspaceByteDelivery<'_> {
    pub const fn key(&self) -> WindowsPacketFlowKey {
        self.key
    }

    pub const fn binding(&self) -> &WindowsUserspaceFlowBinding {
        self.binding
    }

    pub const fn direction(&self) -> WindowsPacketFlowDirection {
        self.direction
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

pub trait WindowsUserspaceByteEffects {
    type Error: fmt::Display;

    /// Forwards one payload atomically. `Err` must leave no visible mutation.
    fn forward(&mut self, delivery: &WindowsUserspaceByteDelivery<'_>) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WindowsUserspaceByteCleanup {
    pub removed_flows: usize,
    pub removed_frames: usize,
    pub removed_bytes: usize,
}

pub struct WindowsUserspaceByteOwner {
    config: WindowsUserspaceByteOwnerConfig,
    flows: BTreeMap<WindowsPacketFlowKey, WindowsUserspaceOwnedFlow>,
    owned_frames: usize,
    owned_bytes: usize,
}

impl WindowsUserspaceByteOwner {
    pub fn new(
        config: WindowsUserspaceByteOwnerConfig,
    ) -> Result<Self, WindowsUserspaceByteOwnerError> {
        config.validate().map_err(|code| {
            WindowsUserspaceByteOwnerError::new(code, "byte-owner bounds are invalid")
        })?;
        Ok(Self {
            config,
            flows: BTreeMap::new(),
            owned_frames: 0,
            owned_bytes: 0,
        })
    }

    pub fn open_flow(
        &mut self,
        binding: WindowsUserspaceFlowBinding,
        now_ms: u64,
    ) -> Result<(), WindowsUserspaceByteOwnerError> {
        if now_ms >= binding.expires_at_ms() {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::BindingExpired,
                "userspace flow binding expired before byte ownership",
            ));
        }
        let key = binding.key();
        if self.flows.contains_key(&key) {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::DuplicateFlow,
                "flow already has a byte owner",
            ));
        }
        if self.flows.len() >= self.config.max_active_flows {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::FlowLimit,
                "active byte-owner flow limit reached",
            ));
        }
        self.flows
            .insert(key, WindowsUserspaceOwnedFlow::new(binding, now_ms));
        Ok(())
    }

    pub fn stage_payload(
        &mut self,
        event: &WindowsPacketFlowEvent,
        transition: &WindowsPacketFlowTransition,
        payload: Vec<u8>,
    ) -> Result<(), WindowsUserspaceByteOwnerError> {
        let (now_ms, key, direction, sequence, declared_bytes) = match event {
            WindowsPacketFlowEvent::Payload {
                now_ms,
                key,
                direction,
                sequence,
                bytes,
            } => (*now_ms, *key, *direction, *sequence, *bytes),
            _ => {
                return Err(WindowsUserspaceByteOwnerError::new(
                    WindowsUserspaceByteOwnerErrorCode::PayloadEventRequired,
                    "byte ownership requires a packet-flow payload event",
                ));
            }
        };
        if payload.len() != declared_bytes || payload.is_empty() {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::PayloadLengthMismatch,
                "payload length does not match the packet-flow event",
            ));
        }
        if payload.len() > self.config.max_chunk_bytes {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::PayloadTooLarge,
                "payload exceeds the byte-owner chunk bound",
            ));
        }

        let transition_flow = transition.state.flows.get(&key).ok_or_else(|| {
            WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::TransitionMissingFlow,
                "packet-flow transition does not retain the payload flow",
            )
        })?;
        if !matches!(
            transition_flow.phase,
            WindowsPacketFlowPhase::Opening
                | WindowsPacketFlowPhase::Relaying
                | WindowsPacketFlowPhase::Draining
        ) {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::TransitionFlowInactive,
                "packet-flow transition closed instead of accepting the payload",
            ));
        }
        if transition_flow.updated_at_ms != now_ms {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::TransitionDidNotAcceptPayload,
                "packet-flow transition timestamp does not match the payload event",
            ));
        }
        if transition.state.updated_at_ms != now_ms {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::TransitionDidNotAcceptPayload,
                "packet-flow registry timestamp does not match the payload event",
            ));
        }
        let should_forward = direction == WindowsPacketFlowDirection::BackendToClient
            || transition_flow.backend_ready;
        let exact_forward = transition.commands.iter().any(|command| {
            matches!(
                command,
                WindowsPacketFlowCommand::Forward {
                    key: command_key,
                    direction: command_direction,
                    sequence: command_sequence,
                    bytes: command_bytes,
                } if *command_key == key
                    && *command_direction == direction
                    && *command_sequence == sequence
                    && *command_bytes == declared_bytes
            )
        });
        let idle_refresh = transition.commands.iter().any(|command| {
            matches!(
                command,
                WindowsPacketFlowCommand::ScheduleIdleDeadline {
                    key: command_key,
                    ..
                } if *command_key == key
            )
        });
        if (should_forward && !exact_forward) || (!should_forward && !idle_refresh) {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::TransitionDidNotAcceptPayload,
                "packet-flow transition lacks exact payload acceptance evidence",
            ));
        }

        let flow = self.flows.get_mut(&key).ok_or_else(|| {
            WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::UnknownFlow,
                "payload flow has no byte owner",
            )
        })?;
        if transition_flow.admission.key() != flow.binding.key() {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::TransitionDidNotAcceptPayload,
                "packet-flow transition does not match the opaque tuple binding",
            ));
        }
        if now_ms < flow.updated_at_ms {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::StaleTransition,
                "payload transition predates the byte owner",
            ));
        }
        let queue = flow.queue_mut(direction);
        if sequence != queue.next_sequence {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::OutOfOrderPayload,
                "payload sequence is not the next owned sequence",
            ));
        }
        if queue.frames.len() >= self.config.max_queued_frames_per_direction {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::FrameLimit,
                "directional byte-owner frame limit reached",
            ));
        }
        let new_queue_bytes = queue.bytes.checked_add(payload.len()).ok_or_else(|| {
            WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::BufferLimit,
                "directional byte-owner count overflowed",
            )
        })?;
        if new_queue_bytes > self.config.max_buffered_bytes_per_direction {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::BufferLimit,
                "directional byte-owner byte limit reached",
            ));
        }
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::OutOfOrderPayload,
                "payload sequence overflowed",
            )
        })?;
        queue.frames.push_back(WindowsUserspaceOwnedPayload {
            sequence,
            bytes: payload.into_boxed_slice(),
        });
        queue.bytes = new_queue_bytes;
        queue.next_sequence = next_sequence;
        flow.updated_at_ms = now_ms;
        self.owned_frames += 1;
        self.owned_bytes += declared_bytes;
        Ok(())
    }

    pub fn execute_forward<E: WindowsUserspaceByteEffects>(
        &mut self,
        command: &WindowsPacketFlowCommand,
        effects: &mut E,
        now_ms: u64,
    ) -> Result<WindowsPacketFlowEvent, WindowsUserspaceByteOwnerError> {
        let (key, direction, sequence, declared_bytes) = match command {
            WindowsPacketFlowCommand::Forward {
                key,
                direction,
                sequence,
                bytes,
            } => (*key, *direction, *sequence, *bytes),
            _ => {
                return Err(WindowsUserspaceByteOwnerError::new(
                    WindowsUserspaceByteOwnerErrorCode::ForwardCommandRequired,
                    "byte delivery requires a packet-flow forward command",
                ));
            }
        };

        {
            let flow = self.flows.get(&key).ok_or_else(|| {
                WindowsUserspaceByteOwnerError::new(
                    WindowsUserspaceByteOwnerErrorCode::UnknownFlow,
                    "forward command has no byte owner",
                )
            })?;
            if now_ms < flow.updated_at_ms {
                return Err(WindowsUserspaceByteOwnerError::new(
                    WindowsUserspaceByteOwnerErrorCode::StaleTransition,
                    "forward command predates the retained payload",
                ));
            }
            let frame = flow.queue(direction).frames.front().ok_or_else(|| {
                WindowsUserspaceByteOwnerError::new(
                    WindowsUserspaceByteOwnerErrorCode::OwnedPayloadMissing,
                    "forward command has no retained payload",
                )
            })?;
            if frame.sequence != sequence || frame.bytes.len() != declared_bytes {
                return Err(WindowsUserspaceByteOwnerError::new(
                    WindowsUserspaceByteOwnerErrorCode::ForwardMetadataMismatch,
                    "forward command does not match the retained front payload",
                ));
            }
            let delivery = WindowsUserspaceByteDelivery {
                key,
                binding: &flow.binding,
                direction,
                sequence,
                bytes: &frame.bytes,
            };
            effects.forward(&delivery).map_err(|error| {
                WindowsUserspaceByteOwnerError::new(
                    WindowsUserspaceByteOwnerErrorCode::EffectFailed,
                    error.to_string(),
                )
            })?;
        }

        let flow = self
            .flows
            .get_mut(&key)
            .expect("validated byte-owner flow must remain present");
        let queue = flow.queue_mut(direction);
        let frame = queue
            .frames
            .pop_front()
            .expect("validated front payload must remain present");
        queue.bytes -= frame.bytes.len();
        flow.updated_at_ms = now_ms;
        self.owned_frames -= 1;
        self.owned_bytes -= frame.bytes.len();
        Ok(WindowsPacketFlowEvent::Forwarded {
            now_ms,
            key,
            direction,
            through_sequence: sequence,
        })
    }

    pub fn reconcile(
        &mut self,
        event: &WindowsPacketFlowEvent,
        transition: &WindowsPacketFlowTransition,
    ) -> Result<WindowsUserspaceByteCleanup, WindowsUserspaceByteOwnerError> {
        let now_ms = event.now_ms();
        if transition.state.updated_at_ms != now_ms {
            return Err(WindowsUserspaceByteOwnerError::new(
                WindowsUserspaceByteOwnerErrorCode::StaleTransition,
                "packet-flow registry timestamp does not match the cleanup event",
            ));
        }
        let mut cleanup = WindowsUserspaceByteCleanup::default();
        if let Some(key) = event.flow_key() {
            if let Some(flow) = self.flows.get(&key) {
                if now_ms < flow.updated_at_ms {
                    return Err(WindowsUserspaceByteOwnerError::new(
                        WindowsUserspaceByteOwnerErrorCode::StaleTransition,
                        "cleanup event predates the byte owner flow",
                    ));
                }
            }
            let active = transition.state.flows.get(&key).is_some_and(|state| {
                matches!(
                    state.phase,
                    WindowsPacketFlowPhase::Opening
                        | WindowsPacketFlowPhase::Relaying
                        | WindowsPacketFlowPhase::Draining
                )
            });
            if active {
                if let Some(flow) = self.flows.get_mut(&key) {
                    flow.updated_at_ms = now_ms;
                }
            } else {
                self.remove_flow(key, &mut cleanup);
            }
        } else if let WindowsPacketFlowEvent::CaptureGenerationRetired {
            capture_generation, ..
        } = event
        {
            if transition.state.retired_capture_generation_high_watermark < *capture_generation {
                return Err(WindowsUserspaceByteOwnerError::new(
                    WindowsUserspaceByteOwnerErrorCode::StaleTransition,
                    "packet-flow transition did not retire the requested generation",
                ));
            }
            if self.flows.iter().any(|(key, flow)| {
                key.capture_generation <= *capture_generation && flow.updated_at_ms > now_ms
            }) {
                return Err(WindowsUserspaceByteOwnerError::new(
                    WindowsUserspaceByteOwnerErrorCode::StaleTransition,
                    "generation retirement predates retained byte-owner state",
                ));
            }
            let keys: Vec<_> = self
                .flows
                .iter()
                .filter_map(|(key, flow)| {
                    (key.capture_generation <= *capture_generation && flow.updated_at_ms <= now_ms)
                        .then_some(*key)
                })
                .collect();
            for key in keys {
                self.remove_flow(key, &mut cleanup);
            }
        }
        Ok(cleanup)
    }

    fn remove_flow(
        &mut self,
        key: WindowsPacketFlowKey,
        cleanup: &mut WindowsUserspaceByteCleanup,
    ) {
        if let Some(flow) = self.flows.remove(&key) {
            let frames = flow.owned_frames();
            let bytes = flow.owned_bytes();
            cleanup.removed_flows += 1;
            cleanup.removed_frames += frames;
            cleanup.removed_bytes += bytes;
            self.owned_frames -= frames;
            self.owned_bytes -= bytes;
        }
    }

    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }

    pub const fn owned_frame_count(&self) -> usize {
        self.owned_frames
    }

    pub const fn owned_byte_count(&self) -> usize {
        self.owned_bytes
    }
}

//! Additive v1 queue between the frozen byte owner and native connector writes.
//!
//! Byte-owner delivery is transferred atomically into this bounded queue. Native
//! writes happen later and commit exact progress, so a partial TCP write cannot
//! make the byte owner retry an already-visible prefix.

use slipstream_core::routing_policy::{RouteClass, RoutePolicyResult, ServiceGroup};
use slipstream_windows_adapter::data_plane::WindowsDataPlaneBackend;
use slipstream_windows_adapter::packet_flow::{
    WindowsPacketFlowDirection, WindowsPacketFlowKey, WindowsPacketFlowTransport,
};
use slipstream_windows_adapter::userspace_stack_bridge::{
    WindowsUserspaceByteDelivery, WindowsUserspaceByteEffects,
};
use std::collections::VecDeque;
use std::fmt;

pub const CONTRACT_VERSION: u32 = 1;
pub const DEFAULT_MAX_QUEUED_FRAMES: usize = 8;
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 4_096;
pub const DEFAULT_MAX_FRAME_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeConnectorQueueConfig {
    pub max_queued_frames: usize,
    pub max_queued_bytes: usize,
    pub max_frame_bytes: usize,
}

impl Default for NativeConnectorQueueConfig {
    fn default() -> Self {
        Self {
            max_queued_frames: DEFAULT_MAX_QUEUED_FRAMES,
            max_queued_bytes: DEFAULT_MAX_QUEUED_BYTES,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

impl NativeConnectorQueueConfig {
    fn validate(self) -> Result<(), NativeConnectorError> {
        if self.max_queued_frames == 0
            || self.max_queued_bytes == 0
            || self.max_frame_bytes == 0
            || self.max_frame_bytes > self.max_queued_bytes
        {
            return Err(NativeConnectorError::new(
                NativeConnectorErrorCode::InvalidConfig,
                "native connector queue bounds are invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeConnectorErrorCode {
    InvalidConfig,
    NonMonotonicClock,
    UnsupportedDirection,
    BindingExpired,
    UnsupportedRouteBackend,
    UnsupportedTransportBackend,
    PayloadTooLarge,
    QueueFull,
    QueueBytesExceeded,
    WriterBackendMismatch,
    WriterTransportMismatch,
    NativeWriteFailed,
    InvalidNativeProgress,
}

impl NativeConnectorErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::NonMonotonicClock => "non_monotonic_clock",
            Self::UnsupportedDirection => "unsupported_direction",
            Self::BindingExpired => "binding_expired",
            Self::UnsupportedRouteBackend => "unsupported_route_backend",
            Self::UnsupportedTransportBackend => "unsupported_transport_backend",
            Self::PayloadTooLarge => "payload_too_large",
            Self::QueueFull => "queue_full",
            Self::QueueBytesExceeded => "queue_bytes_exceeded",
            Self::WriterBackendMismatch => "writer_backend_mismatch",
            Self::WriterTransportMismatch => "writer_transport_mismatch",
            Self::NativeWriteFailed => "native_write_failed",
            Self::InvalidNativeProgress => "invalid_native_progress",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct NativeConnectorError {
    pub code: NativeConnectorErrorCode,
    pub message: String,
}

impl NativeConnectorError {
    fn new(code: NativeConnectorErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for NativeConnectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for NativeConnectorError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeConnectorProgress {
    pub committed_bytes: usize,
    pub remaining_bytes: usize,
    pub frame_complete: bool,
}

pub trait NativeConnectorWriter {
    type Error: fmt::Display;

    fn backend(&self) -> WindowsDataPlaneBackend;
    fn transport(&self) -> WindowsPacketFlowTransport;

    /// Returns the exact prefix made visible to the native connector. An error
    /// must mean that no byte from this call became visible. UDP writers must
    /// commit the complete datagram in one call.
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error>;
}

#[derive(Debug)]
struct QueuedFrame {
    key: WindowsPacketFlowKey,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketFlowTransport,
    sequence: u64,
    bytes: Vec<u8>,
    committed: usize,
}

impl QueuedFrame {
    fn remaining(&self) -> &[u8] {
        &self.bytes[self.committed..]
    }
}

pub fn route_backend_is_supported(
    policy: &RoutePolicyResult,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketFlowTransport,
) -> bool {
    if matches!(
        policy.service_group,
        ServiceGroup::Discord | ServiceGroup::YoutubeVideo
    ) && backend == WindowsDataPlaneBackend::Geph
    {
        return false;
    }
    if transport == WindowsPacketFlowTransport::Udp && backend == WindowsDataPlaneBackend::Geph {
        return false;
    }
    matches!(
        (policy.route_class, backend),
        (
            RouteClass::LocalBypass,
            WindowsDataPlaneBackend::LocalEngine
        ) | (
            RouteClass::GeoExit,
            WindowsDataPlaneBackend::SmartDns | WindowsDataPlaneBackend::Geph
        )
    )
}

pub struct NativeConnectorQueue {
    config: NativeConnectorQueueConfig,
    now_ms: u64,
    frames: VecDeque<QueuedFrame>,
    queued_bytes: usize,
}

impl NativeConnectorQueue {
    pub fn new(
        config: NativeConnectorQueueConfig,
        now_ms: u64,
    ) -> Result<Self, NativeConnectorError> {
        config.validate()?;
        Ok(Self {
            config,
            now_ms,
            frames: VecDeque::new(),
            queued_bytes: 0,
        })
    }

    pub fn advance_to(&mut self, now_ms: u64) -> Result<(), NativeConnectorError> {
        if now_ms < self.now_ms {
            return Err(NativeConnectorError::new(
                NativeConnectorErrorCode::NonMonotonicClock,
                "native connector clock cannot move backwards",
            ));
        }
        self.now_ms = now_ms;
        Ok(())
    }

    pub fn queued_frames(&self) -> usize {
        self.frames.len()
    }

    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    pub fn front_remaining_bytes(&self) -> usize {
        self.frames
            .front()
            .map_or(0, |frame| frame.remaining().len())
    }

    pub fn front_key(&self) -> Option<WindowsPacketFlowKey> {
        self.frames.front().map(|frame| frame.key)
    }

    pub fn front_sequence(&self) -> Option<u64> {
        self.frames.front().map(|frame| frame.sequence)
    }

    pub fn flush_front<W: NativeConnectorWriter>(
        &mut self,
        writer: &mut W,
    ) -> Result<NativeConnectorProgress, NativeConnectorError> {
        let (committed, remaining_bytes, frame_complete) = {
            let frame = self.frames.front_mut().ok_or_else(|| {
                NativeConnectorError::new(
                    NativeConnectorErrorCode::InvalidNativeProgress,
                    "native connector queue is empty",
                )
            })?;
            if writer.backend() != frame.backend {
                return Err(NativeConnectorError::new(
                    NativeConnectorErrorCode::WriterBackendMismatch,
                    "native writer backend does not own the queued frame",
                ));
            }
            if writer.transport() != frame.transport {
                return Err(NativeConnectorError::new(
                    NativeConnectorErrorCode::WriterTransportMismatch,
                    "native writer transport does not own the queued frame",
                ));
            }

            let remaining_before = frame.remaining().len();
            let committed = writer.write(frame.remaining()).map_err(|error| {
                NativeConnectorError::new(
                    NativeConnectorErrorCode::NativeWriteFailed,
                    format!("native connector write failed before progress: {error}"),
                )
            })?;
            if committed == 0
                || committed > remaining_before
                || (frame.transport == WindowsPacketFlowTransport::Udp
                    && committed != remaining_before)
            {
                return Err(NativeConnectorError::new(
                    NativeConnectorErrorCode::InvalidNativeProgress,
                    "native writer reported invalid TCP progress or a partial UDP datagram",
                ));
            }

            frame.committed += committed;
            self.queued_bytes -= committed;
            let remaining_bytes = frame.remaining().len();
            (committed, remaining_bytes, remaining_bytes == 0)
        };
        if frame_complete {
            self.frames.pop_front();
        }
        Ok(NativeConnectorProgress {
            committed_bytes: committed,
            remaining_bytes,
            frame_complete,
        })
    }
}

impl WindowsUserspaceByteEffects for NativeConnectorQueue {
    type Error = NativeConnectorError;

    fn forward(&mut self, delivery: &WindowsUserspaceByteDelivery<'_>) -> Result<(), Self::Error> {
        if delivery.direction() != WindowsPacketFlowDirection::ClientToBackend {
            return Err(NativeConnectorError::new(
                NativeConnectorErrorCode::UnsupportedDirection,
                "native connector owns only client-to-backend payload",
            ));
        }
        if self.now_ms >= delivery.binding().expires_at_ms() {
            return Err(NativeConnectorError::new(
                NativeConnectorErrorCode::BindingExpired,
                "userspace flow binding expired before connector handoff",
            ));
        }
        let request = delivery.binding().admission().request();
        let transport = delivery.binding().tuple().transport;
        if !route_backend_is_supported(&request.policy, request.backend, transport) {
            let code = if transport == WindowsPacketFlowTransport::Udp
                && request.backend == WindowsDataPlaneBackend::Geph
            {
                NativeConnectorErrorCode::UnsupportedTransportBackend
            } else {
                NativeConnectorErrorCode::UnsupportedRouteBackend
            };
            return Err(NativeConnectorError::new(
                code,
                "policy route, backend, and transport are not an admitted connector edge",
            ));
        }
        if delivery.bytes().is_empty() || delivery.bytes().len() > self.config.max_frame_bytes {
            return Err(NativeConnectorError::new(
                NativeConnectorErrorCode::PayloadTooLarge,
                "connector frame is empty or exceeds its fixed bound",
            ));
        }
        if self.frames.len() >= self.config.max_queued_frames {
            return Err(NativeConnectorError::new(
                NativeConnectorErrorCode::QueueFull,
                "native connector frame queue is full",
            ));
        }
        let next_bytes = self
            .queued_bytes
            .checked_add(delivery.bytes().len())
            .ok_or_else(|| {
                NativeConnectorError::new(
                    NativeConnectorErrorCode::QueueBytesExceeded,
                    "native connector byte accounting overflowed",
                )
            })?;
        if next_bytes > self.config.max_queued_bytes {
            return Err(NativeConnectorError::new(
                NativeConnectorErrorCode::QueueBytesExceeded,
                "native connector byte queue exceeds its fixed bound",
            ));
        }

        self.frames.push_back(QueuedFrame {
            key: delivery.key(),
            backend: request.backend,
            transport,
            sequence: delivery.sequence(),
            bytes: delivery.bytes().to_vec(),
            committed: 0,
        });
        self.queued_bytes = next_bytes;
        Ok(())
    }
}

//! Additive v1 backend-read queue for selected-stack/native-connector composition.
//!
//! This module is part of a test-only crate. It owns no adapter, route, process,
//! service, DNS, proxy, PAC, VPN, or production-host effect.

use crate::native_connector_v1::route_backend_is_supported;
use slipstream_windows_adapter::data_plane::WindowsDataPlaneBackend;
use slipstream_windows_adapter::packet_flow::{WindowsPacketFlowKey, WindowsPacketFlowTransport};
use slipstream_windows_adapter::userspace_stack_bridge::WindowsUserspaceFlowBinding;
use std::collections::VecDeque;
use std::fmt;

pub const CONTRACT_VERSION: u32 = 1;
pub const DEFAULT_MAX_QUEUED_FRAMES: usize = 8;
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 4_096;
pub const DEFAULT_MAX_FRAME_BYTES: usize = 512;
pub const INITIAL_BACKEND_SEQUENCE: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeBackendReadQueueConfig {
    pub max_queued_frames: usize,
    pub max_queued_bytes: usize,
    pub max_frame_bytes: usize,
}

impl Default for NativeBackendReadQueueConfig {
    fn default() -> Self {
        Self {
            max_queued_frames: DEFAULT_MAX_QUEUED_FRAMES,
            max_queued_bytes: DEFAULT_MAX_QUEUED_BYTES,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

impl NativeBackendReadQueueConfig {
    fn validate(self) -> Result<Self, NativeBackendReadError> {
        if self.max_queued_frames == 0
            || self.max_queued_bytes == 0
            || self.max_frame_bytes == 0
            || self.max_frame_bytes > self.max_queued_bytes
        {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::InvalidConfig,
                "backend-read queue bounds are invalid",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBackendReadErrorCode {
    InvalidConfig,
    ClockMovedBackwards,
    QueueFull,
    QueueBytesExceeded,
    BindingExpired,
    ReaderFlowMismatch,
    ReaderBackendMismatch,
    ReaderTransportMismatch,
    UnsupportedRouteBackend,
    UnsupportedTransportBackend,
    BindingMismatch,
    OutOfOrderSequence,
    SequenceOverflow,
    NativeReadFailed,
    InvalidNativeProgress,
    WriterFlowMismatch,
    WriterBackendMismatch,
    WriterTransportMismatch,
    SelectedStackWriteFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBackendReadError {
    pub code: NativeBackendReadErrorCode,
    pub message: String,
}

impl NativeBackendReadError {
    fn new(code: NativeBackendReadErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for NativeBackendReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl fmt::Display for NativeBackendReadErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for NativeBackendReadError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeBackendReadResult {
    pub bytes_read: usize,
    pub datagram_complete: bool,
}

pub trait NativeConnectorReader {
    type Error: fmt::Display;

    fn key(&self) -> WindowsPacketFlowKey;
    fn backend(&self) -> WindowsDataPlaneBackend;
    fn transport(&self) -> WindowsPacketFlowTransport;

    /// Reads at most `buffer.len()` bytes. `Err` must mean that no byte was
    /// consumed. UDP readers must set `datagram_complete` only when the entire
    /// datagram was retained in `buffer`.
    fn read(&mut self, buffer: &mut [u8]) -> Result<NativeBackendReadResult, Self::Error>;
}

pub trait SelectedStackBackendWriter {
    type Error: fmt::Display;

    fn key(&self) -> WindowsPacketFlowKey;
    fn backend(&self) -> WindowsDataPlaneBackend;
    fn transport(&self) -> WindowsPacketFlowTransport;

    /// Delivers one complete retained frame. `Err` must leave the selected
    /// stack unchanged so the queue can retry the same bytes.
    fn write(&mut self, sequence: u64, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeBackendReadProgress {
    pub delivered_bytes: usize,
    pub frame_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackendReadFrame {
    key: WindowsPacketFlowKey,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketFlowTransport,
    sequence: u64,
    bytes: Vec<u8>,
}

pub struct NativeBackendReadQueue {
    config: NativeBackendReadQueueConfig,
    now_ms: u64,
    key: WindowsPacketFlowKey,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketFlowTransport,
    next_sequence: u64,
    frames: VecDeque<BackendReadFrame>,
    queued_bytes: usize,
}

impl NativeBackendReadQueue {
    pub fn new(
        config: NativeBackendReadQueueConfig,
        binding: &WindowsUserspaceFlowBinding,
        now_ms: u64,
    ) -> Result<Self, NativeBackendReadError> {
        Ok(Self {
            config: config.validate()?,
            now_ms,
            key: binding.key(),
            backend: binding.admission().request().backend,
            transport: binding.tuple().transport,
            next_sequence: INITIAL_BACKEND_SEQUENCE,
            frames: VecDeque::new(),
            queued_bytes: 0,
        })
    }

    pub fn advance_to(&mut self, now_ms: u64) -> Result<(), NativeBackendReadError> {
        if now_ms < self.now_ms {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::ClockMovedBackwards,
                "backend-read queue clock cannot move backwards",
            ));
        }
        self.now_ms = now_ms;
        Ok(())
    }

    pub fn queued_frames(&self) -> usize {
        self.frames.len()
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    pub fn front_key(&self) -> Option<WindowsPacketFlowKey> {
        self.frames.front().map(|frame| frame.key)
    }

    pub fn front_sequence(&self) -> Option<u64> {
        self.frames.front().map(|frame| frame.sequence)
    }

    pub fn capture_from<R: NativeConnectorReader>(
        &mut self,
        binding: &WindowsUserspaceFlowBinding,
        sequence: u64,
        reader: &mut R,
    ) -> Result<usize, NativeBackendReadError> {
        if self.frames.len() >= self.config.max_queued_frames {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::QueueFull,
                "backend-read frame queue is full",
            ));
        }
        let remaining_capacity = self
            .config
            .max_queued_bytes
            .checked_sub(self.queued_bytes)
            .ok_or_else(|| {
                NativeBackendReadError::new(
                    NativeBackendReadErrorCode::QueueBytesExceeded,
                    "backend-read byte accounting exceeded its fixed bound",
                )
            })?;
        let read_capacity = remaining_capacity.min(self.config.max_frame_bytes);
        if read_capacity == 0 {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::QueueBytesExceeded,
                "backend-read byte queue is full",
            ));
        }
        if self.now_ms >= binding.expires_at_ms() {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::BindingExpired,
                "userspace flow binding expired before backend read",
            ));
        }
        let request = binding.admission().request();
        let transport = binding.tuple().transport;
        if binding.key() != self.key
            || request.backend != self.backend
            || transport != self.transport
        {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::BindingMismatch,
                "backend-read queue is bound to a different flow, backend, or transport",
            ));
        }
        if sequence != self.next_sequence {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::OutOfOrderSequence,
                "backend-read sequence does not match reducer-issued next sequence",
            ));
        }
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            NativeBackendReadError::new(
                NativeBackendReadErrorCode::SequenceOverflow,
                "backend-read sequence cannot advance without overflow",
            )
        })?;
        if reader.key() != binding.key() {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::ReaderFlowMismatch,
                "native reader does not own the bound flow",
            ));
        }
        if reader.backend() != request.backend {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::ReaderBackendMismatch,
                "native reader backend does not own the bound flow",
            ));
        }
        if reader.transport() != transport {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::ReaderTransportMismatch,
                "native reader transport does not own the bound flow",
            ));
        }
        if !route_backend_is_supported(&request.policy, request.backend, transport) {
            let code = if transport == WindowsPacketFlowTransport::Udp
                && request.backend == WindowsDataPlaneBackend::Geph
            {
                NativeBackendReadErrorCode::UnsupportedTransportBackend
            } else {
                NativeBackendReadErrorCode::UnsupportedRouteBackend
            };
            return Err(NativeBackendReadError::new(
                code,
                "policy route, backend, and transport are not an admitted read edge",
            ));
        }

        let mut bytes = vec![0; read_capacity];
        let progress = reader.read(&mut bytes).map_err(|error| {
            NativeBackendReadError::new(
                NativeBackendReadErrorCode::NativeReadFailed,
                format!("native backend read failed before progress: {error}"),
            )
        })?;
        if progress.bytes_read == 0
            || progress.bytes_read > read_capacity
            || (transport == WindowsPacketFlowTransport::Udp && !progress.datagram_complete)
        {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::InvalidNativeProgress,
                "native reader reported invalid progress or a partial UDP datagram",
            ));
        }
        bytes.truncate(progress.bytes_read);
        self.queued_bytes += progress.bytes_read;
        self.next_sequence = next_sequence;
        self.frames.push_back(BackendReadFrame {
            key: binding.key(),
            backend: request.backend,
            transport,
            sequence,
            bytes,
        });
        Ok(progress.bytes_read)
    }

    pub fn flush_front<W: SelectedStackBackendWriter>(
        &mut self,
        writer: &mut W,
    ) -> Result<NativeBackendReadProgress, NativeBackendReadError> {
        let frame = self.frames.front().ok_or_else(|| {
            NativeBackendReadError::new(
                NativeBackendReadErrorCode::InvalidNativeProgress,
                "backend-read queue is empty",
            )
        })?;
        if writer.key() != frame.key {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::WriterFlowMismatch,
                "selected-stack writer does not own the retained flow",
            ));
        }
        if writer.backend() != frame.backend {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::WriterBackendMismatch,
                "selected-stack writer backend does not own the retained frame",
            ));
        }
        if writer.transport() != frame.transport {
            return Err(NativeBackendReadError::new(
                NativeBackendReadErrorCode::WriterTransportMismatch,
                "selected-stack writer transport does not own the retained frame",
            ));
        }
        writer
            .write(frame.sequence, &frame.bytes)
            .map_err(|error| {
                NativeBackendReadError::new(
                    NativeBackendReadErrorCode::SelectedStackWriteFailed,
                    format!("selected-stack write failed before mutation: {error}"),
                )
            })?;
        let delivered_bytes = frame.bytes.len();
        self.frames.pop_front();
        self.queued_bytes -= delivered_bytes;
        Ok(NativeBackendReadProgress {
            delivered_bytes,
            frame_complete: true,
        })
    }
}

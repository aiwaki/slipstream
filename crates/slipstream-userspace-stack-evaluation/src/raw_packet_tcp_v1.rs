//! Bounded IPv4 Layer 3 TCP exchange through the selected userspace stack.
//!
//! This additive v1 boundary retains TCP state across a real SYN, handshake
//! ACK, and payload segment. It owns no native adapter, route, socket, process,
//! service, DNS, proxy, PAC, or VPN effect.

use crate::v1::{L3_MTU, MAX_BURST_FRAMES, MAX_LINK_FRAMES_PER_DIRECTION, TCP_BYTES_PER_DIRECTION};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::fmt;
use std::net::Ipv4Addr;

pub const CONTRACT_VERSION: u32 = 1;
pub const MAX_POLL_STEPS: usize = 64;
pub const IPV4_TCP_HEADER_BYTES: usize = 40;
pub const MAX_RESPONSE_PAYLOAD_BYTES: usize = L3_MTU - IPV4_TCP_HEADER_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawPacketTcpPhase {
    Listening,
    SynAckEmitted,
    Established,
    ResponseEmitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawPacketTcpErrorCode {
    InvalidConfig,
    UnexpectedPhase,
    ExchangeBusy,
    PacketTooLarge,
    ResponseInvalid,
    InputQueueFull,
    SegmentRejected,
    UnexpectedStackOutput,
    StackOutputExceededBounds,
    ResponseRejected,
    ResponseMissing,
    MultipleHandshakeFrames,
    ClockOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPacketTcpError {
    pub code: RawPacketTcpErrorCode,
    pub message: String,
}

impl RawPacketTcpError {
    fn new(code: RawPacketTcpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for RawPacketTcpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl fmt::Display for RawPacketTcpErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RawPacketTcpError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPacketTcpExchange {
    pub request_payload: Vec<u8>,
    pub response_packets: Vec<Vec<u8>>,
}

#[derive(Default)]
struct RawPacketTcpDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    fault: Option<RawPacketTcpErrorCode>,
}

impl RawPacketTcpDevice {
    fn enqueue(&mut self, packet: &[u8]) -> Result<(), RawPacketTcpError> {
        if self.inbound.len() >= MAX_LINK_FRAMES_PER_DIRECTION {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::InputQueueFull,
                "raw TCP packet input queue is full",
            ));
        }
        self.inbound.push_back(packet.to_vec());
        Ok(())
    }

    fn is_idle(&self) -> bool {
        self.inbound.is_empty() && self.outbound.is_empty()
    }

    fn take_single_handshake_output(&mut self) -> Result<Vec<u8>, RawPacketTcpError> {
        let packet = self.outbound.pop_front().ok_or_else(|| {
            RawPacketTcpError::new(
                RawPacketTcpErrorCode::ResponseMissing,
                "selected stack emitted no TCP handshake packet",
            )
        })?;
        if !self.outbound.is_empty() {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::MultipleHandshakeFrames,
                "selected stack emitted more than one TCP handshake packet",
            ));
        }
        Ok(packet)
    }

    fn take_all_output(&mut self) -> Vec<Vec<u8>> {
        self.outbound.drain(..).collect()
    }

    fn take_fault(&mut self) -> Option<RawPacketTcpError> {
        self.fault.take().map(|code| {
            RawPacketTcpError::new(code, "selected stack exceeded a fixed TCP output bound")
        })
    }
}

struct RawTcpRxToken(Vec<u8>);

impl phy::RxToken for RawTcpRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct RawTcpTxToken<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
    fault: &'a mut Option<RawPacketTcpErrorCode>,
}

impl phy::TxToken for RawTcpTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        if len > L3_MTU || self.outbound.len() >= MAX_LINK_FRAMES_PER_DIRECTION {
            *self.fault = Some(RawPacketTcpErrorCode::StackOutputExceededBounds);
        } else {
            self.outbound.push_back(packet);
        }
        result
    }
}

impl Device for RawPacketTcpDevice {
    type RxToken<'a> = RawTcpRxToken;
    type TxToken<'a> = RawTcpTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.outbound.len() >= MAX_LINK_FRAMES_PER_DIRECTION {
            return None;
        }
        let packet = self.inbound.pop_front()?;
        Some((
            RawTcpRxToken(packet),
            RawTcpTxToken {
                outbound: &mut self.outbound,
                fault: &mut self.fault,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.outbound.len() < MAX_LINK_FRAMES_PER_DIRECTION).then_some(RawTcpTxToken {
            outbound: &mut self.outbound,
            fault: &mut self.fault,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = L3_MTU;
        capabilities.max_burst_size = Some(MAX_BURST_FRAMES);
        capabilities
    }
}

pub struct RawPacketTcpStackV1 {
    interface: Interface,
    device: RawPacketTcpDevice,
    sockets: SocketSet<'static>,
    socket: SocketHandle,
    phase: RawPacketTcpPhase,
    now_ms: i64,
}

impl RawPacketTcpStackV1 {
    pub fn new_ipv4(
        address: Ipv4Addr,
        prefix_len: u8,
        port: u16,
        random_seed: u64,
    ) -> Result<Self, RawPacketTcpError> {
        if prefix_len > 32 || port == 0 {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::InvalidConfig,
                "IPv4 prefix and TCP port must be valid",
            ));
        }

        let mut device = RawPacketTcpDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = random_seed;
        let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
        let mut address_inserted = false;
        interface.update_ip_addrs(|addresses| {
            address_inserted = addresses
                .push(IpCidr::new(
                    IpAddress::Ipv4(address.octets().into()),
                    prefix_len,
                ))
                .is_ok();
        });
        if !address_inserted {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::InvalidConfig,
                "selected stack could not retain its fixed IPv4 address",
            ));
        }

        let rx = tcp::SocketBuffer::new(vec![0; TCP_BYTES_PER_DIRECTION]);
        let tx = tcp::SocketBuffer::new(vec![0; TCP_BYTES_PER_DIRECTION]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket.listen(port).map_err(|error| {
            RawPacketTcpError::new(
                RawPacketTcpErrorCode::InvalidConfig,
                format!("listen on selected-stack TCP endpoint: {error}"),
            )
        })?;
        let mut sockets = SocketSet::new(Vec::new());
        let socket = sockets.add(socket);

        Ok(Self {
            interface,
            device,
            sockets,
            socket,
            phase: RawPacketTcpPhase::Listening,
            now_ms: 0,
        })
    }

    pub fn phase(&self) -> RawPacketTcpPhase {
        self.phase
    }

    pub fn accept_syn_ipv4(&mut self, syn_packet: &[u8]) -> Result<Vec<u8>, RawPacketTcpError> {
        self.require_phase(RawPacketTcpPhase::Listening)?;
        self.require_idle()?;
        self.validate_packet(syn_packet)?;
        self.device.enqueue(syn_packet)?;

        for _ in 0..MAX_POLL_STEPS {
            self.poll_once()?;
            if !self.device.outbound.is_empty() {
                let syn_ack = self.device.take_single_handshake_output()?;
                self.phase = RawPacketTcpPhase::SynAckEmitted;
                return Ok(syn_ack);
            }
        }
        Err(RawPacketTcpError::new(
            RawPacketTcpErrorCode::SegmentRejected,
            "selected stack rejected the raw IPv4 TCP SYN",
        ))
    }

    pub fn accept_ack_ipv4(&mut self, ack_packet: &[u8]) -> Result<(), RawPacketTcpError> {
        self.require_phase(RawPacketTcpPhase::SynAckEmitted)?;
        self.require_idle()?;
        self.validate_packet(ack_packet)?;
        self.device.enqueue(ack_packet)?;

        for _ in 0..MAX_POLL_STEPS {
            self.poll_once()?;
            if !self.device.outbound.is_empty() {
                return Err(RawPacketTcpError::new(
                    RawPacketTcpErrorCode::UnexpectedStackOutput,
                    "selected stack emitted output while accepting the TCP handshake ACK",
                ));
            }
            if self.sockets.get::<tcp::Socket>(self.socket).state() == tcp::State::Established {
                self.phase = RawPacketTcpPhase::Established;
                return Ok(());
            }
        }
        Err(RawPacketTcpError::new(
            RawPacketTcpErrorCode::SegmentRejected,
            "selected stack did not establish the raw IPv4 TCP session",
        ))
    }

    pub fn exchange_payload_ipv4(
        &mut self,
        request_packet: &[u8],
        response_payload: &[u8],
    ) -> Result<RawPacketTcpExchange, RawPacketTcpError> {
        self.require_phase(RawPacketTcpPhase::Established)?;
        self.require_idle()?;
        self.validate_packet(request_packet)?;
        if response_payload.is_empty() || response_payload.len() > MAX_RESPONSE_PAYLOAD_BYTES {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::ResponseInvalid,
                "TCP response must be non-empty and fit one fixed-MTU IPv4 segment",
            ));
        }
        if self.sockets.get::<tcp::Socket>(self.socket).can_recv()
            || self.sockets.get::<tcp::Socket>(self.socket).send_queue() != 0
        {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::ExchangeBusy,
                "selected-stack TCP socket still owns prior payload state",
            ));
        }

        self.device.enqueue(request_packet)?;
        let mut request_received = false;
        for _ in 0..MAX_POLL_STEPS {
            self.poll_once()?;
            if self.sockets.get::<tcp::Socket>(self.socket).can_recv() {
                request_received = true;
                break;
            }
        }
        if !request_received {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::SegmentRejected,
                "selected stack rejected the raw IPv4 TCP payload segment",
            ));
        }
        let mut response_packets = self.device.take_all_output();

        let mut request_payload = vec![0; TCP_BYTES_PER_DIRECTION];
        let request_length = self
            .sockets
            .get_mut::<tcp::Socket>(self.socket)
            .recv_slice(&mut request_payload)
            .map_err(|error| {
                RawPacketTcpError::new(
                    RawPacketTcpErrorCode::SegmentRejected,
                    format!("receive selected-stack TCP request: {error}"),
                )
            })?;
        request_payload.truncate(request_length);
        self.sockets
            .get_mut::<tcp::Socket>(self.socket)
            .send_slice(response_payload)
            .map_err(|error| {
                RawPacketTcpError::new(
                    RawPacketTcpErrorCode::ResponseRejected,
                    format!("queue selected-stack TCP response: {error}"),
                )
            })?;

        let mut response_emitted = false;
        for _ in 0..MAX_POLL_STEPS {
            self.poll_once()?;
            if !self.device.outbound.is_empty() {
                response_emitted = true;
                break;
            }
        }
        if !response_emitted {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::ResponseRejected,
                "selected stack did not emit the queued TCP response within bounds",
            ));
        }
        response_packets.extend(self.device.take_all_output());
        if response_packets.is_empty() {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::ResponseMissing,
                "selected stack emitted no TCP acknowledgment or response packet",
            ));
        }
        if response_packets.len() > MAX_LINK_FRAMES_PER_DIRECTION {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::StackOutputExceededBounds,
                "selected stack emitted too many TCP response packets",
            ));
        }
        self.phase = RawPacketTcpPhase::ResponseEmitted;

        Ok(RawPacketTcpExchange {
            request_payload,
            response_packets,
        })
    }

    fn require_phase(&self, expected: RawPacketTcpPhase) -> Result<(), RawPacketTcpError> {
        if self.phase != expected {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::UnexpectedPhase,
                format!(
                    "raw TCP phase mismatch: expected {expected:?}, observed {:?}",
                    self.phase
                ),
            ));
        }
        Ok(())
    }

    fn require_idle(&self) -> Result<(), RawPacketTcpError> {
        if !self.device.is_idle() {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::ExchangeBusy,
                "raw TCP exchange still owns prior packet state",
            ));
        }
        Ok(())
    }

    fn validate_packet(&self, packet: &[u8]) -> Result<(), RawPacketTcpError> {
        if packet.is_empty() || packet.len() > L3_MTU {
            return Err(RawPacketTcpError::new(
                RawPacketTcpErrorCode::PacketTooLarge,
                "raw TCP packet is empty or exceeds the fixed L3 MTU",
            ));
        }
        Ok(())
    }

    fn poll_once(&mut self) -> Result<(), RawPacketTcpError> {
        self.now_ms = self.now_ms.checked_add(1).ok_or_else(|| {
            RawPacketTcpError::new(
                RawPacketTcpErrorCode::ClockOverflow,
                "selected-stack TCP poll clock overflowed",
            )
        })?;
        self.interface.poll(
            Instant::from_millis(self.now_ms),
            &mut self.device,
            &mut self.sockets,
        );
        if let Some(error) = self.device.take_fault() {
            return Err(error);
        }
        Ok(())
    }
}

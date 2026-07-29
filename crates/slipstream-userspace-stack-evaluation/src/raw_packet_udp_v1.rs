//! Bounded Layer 3 UDP exchange through the selected userspace stack.
//!
//! This module owns no native adapter, route, socket, process, service, DNS,
//! proxy, PAC, or VPN effect. A qualification harness supplies one raw packet
//! and receives the selected stack's raw response packet.

use crate::v1::{
    L3_MTU, MAX_BURST_FRAMES, MAX_LINK_FRAMES_PER_DIRECTION, UDP_BYTES_PER_DIRECTION,
    UDP_PACKET_SLOTS_PER_DIRECTION,
};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::fmt;
use std::net::Ipv4Addr;

pub const CONTRACT_VERSION: u32 = 1;
pub const MAX_POLL_STEPS: usize = 64;
pub const IPV4_UDP_HEADER_BYTES: usize = 28;
pub const MAX_RESPONSE_PAYLOAD_BYTES: usize = L3_MTU - IPV4_UDP_HEADER_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawPacketUdpErrorCode {
    InvalidConfig,
    ExchangeBusy,
    RequestTooLarge,
    ResponseTooLarge,
    InputQueueFull,
    RequestRejected,
    UnexpectedStackOutput,
    StackOutputExceededBounds,
    ResponseRejected,
    ResponseMissing,
    MultipleResponseFrames,
    ClockOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPacketUdpError {
    pub code: RawPacketUdpErrorCode,
    pub message: String,
}

impl RawPacketUdpError {
    fn new(code: RawPacketUdpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for RawPacketUdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl fmt::Display for RawPacketUdpErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RawPacketUdpError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPacketUdpExchange {
    pub request_payload: Vec<u8>,
    pub response_packet: Vec<u8>,
}

#[derive(Default)]
struct RawPacketDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    fault: Option<RawPacketUdpErrorCode>,
}

impl RawPacketDevice {
    fn enqueue(&mut self, packet: &[u8]) -> Result<(), RawPacketUdpError> {
        if self.inbound.len() >= MAX_LINK_FRAMES_PER_DIRECTION {
            return Err(RawPacketUdpError::new(
                RawPacketUdpErrorCode::InputQueueFull,
                "raw packet input queue is full",
            ));
        }
        self.inbound.push_back(packet.to_vec());
        Ok(())
    }

    fn is_idle(&self) -> bool {
        self.inbound.is_empty() && self.outbound.is_empty()
    }

    fn take_single_output(&mut self) -> Result<Vec<u8>, RawPacketUdpError> {
        let packet = self.outbound.pop_front().ok_or_else(|| {
            RawPacketUdpError::new(
                RawPacketUdpErrorCode::ResponseMissing,
                "selected stack emitted no response packet",
            )
        })?;
        if !self.outbound.is_empty() {
            return Err(RawPacketUdpError::new(
                RawPacketUdpErrorCode::MultipleResponseFrames,
                "selected stack emitted more than one response packet",
            ));
        }
        Ok(packet)
    }

    fn take_fault(&mut self) -> Option<RawPacketUdpError> {
        self.fault.take().map(|code| {
            RawPacketUdpError::new(code, "selected stack exceeded a fixed output bound")
        })
    }
}

struct RawRxToken(Vec<u8>);

impl phy::RxToken for RawRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct RawTxToken<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
    fault: &'a mut Option<RawPacketUdpErrorCode>,
}

impl phy::TxToken for RawTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        if len > L3_MTU || self.outbound.len() >= MAX_LINK_FRAMES_PER_DIRECTION {
            *self.fault = Some(RawPacketUdpErrorCode::StackOutputExceededBounds);
        } else {
            self.outbound.push_back(packet);
        }
        result
    }
}

impl Device for RawPacketDevice {
    type RxToken<'a> = RawRxToken;
    type TxToken<'a> = RawTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.outbound.len() >= MAX_LINK_FRAMES_PER_DIRECTION {
            return None;
        }
        let packet = self.inbound.pop_front()?;
        Some((
            RawRxToken(packet),
            RawTxToken {
                outbound: &mut self.outbound,
                fault: &mut self.fault,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.outbound.len() < MAX_LINK_FRAMES_PER_DIRECTION).then_some(RawTxToken {
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

pub struct RawPacketUdpStackV1 {
    interface: Interface,
    device: RawPacketDevice,
    sockets: SocketSet<'static>,
    socket: SocketHandle,
    now_ms: i64,
}

impl RawPacketUdpStackV1 {
    pub fn new_ipv4(
        address: Ipv4Addr,
        prefix_len: u8,
        port: u16,
        random_seed: u64,
    ) -> Result<Self, RawPacketUdpError> {
        if prefix_len > 32 || port == 0 {
            return Err(RawPacketUdpError::new(
                RawPacketUdpErrorCode::InvalidConfig,
                "IPv4 prefix and UDP port must be valid",
            ));
        }

        let mut device = RawPacketDevice::default();
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
            return Err(RawPacketUdpError::new(
                RawPacketUdpErrorCode::InvalidConfig,
                "selected stack could not retain its fixed IPv4 address",
            ));
        }

        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_PACKET_SLOTS_PER_DIRECTION],
            vec![0; UDP_BYTES_PER_DIRECTION],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_PACKET_SLOTS_PER_DIRECTION],
            vec![0; UDP_BYTES_PER_DIRECTION],
        );
        let mut socket = udp::Socket::new(rx, tx);
        socket.bind(port).map_err(|error| {
            RawPacketUdpError::new(
                RawPacketUdpErrorCode::InvalidConfig,
                format!("bind selected-stack UDP endpoint: {error}"),
            )
        })?;
        let mut sockets = SocketSet::new(Vec::new());
        let socket = sockets.add(socket);

        Ok(Self {
            interface,
            device,
            sockets,
            socket,
            now_ms: 0,
        })
    }

    pub fn exchange_ipv4(
        &mut self,
        request_packet: &[u8],
        response_payload: &[u8],
    ) -> Result<RawPacketUdpExchange, RawPacketUdpError> {
        if !self.device.is_idle()
            || self.sockets.get::<udp::Socket>(self.socket).can_recv()
            || self.sockets.get::<udp::Socket>(self.socket).send_queue() != 0
        {
            return Err(RawPacketUdpError::new(
                RawPacketUdpErrorCode::ExchangeBusy,
                "raw packet exchange still owns prior state",
            ));
        }
        if request_packet.is_empty() || request_packet.len() > L3_MTU {
            return Err(RawPacketUdpError::new(
                RawPacketUdpErrorCode::RequestTooLarge,
                "raw request packet is empty or exceeds the fixed L3 MTU",
            ));
        }
        if response_payload.len() > MAX_RESPONSE_PAYLOAD_BYTES {
            return Err(RawPacketUdpError::new(
                RawPacketUdpErrorCode::ResponseTooLarge,
                "UDP response cannot fit in one fixed-MTU IPv4 packet",
            ));
        }

        self.device.enqueue(request_packet)?;
        let mut received = false;
        for _ in 0..MAX_POLL_STEPS {
            self.poll_once()?;
            if self.sockets.get::<udp::Socket>(self.socket).can_recv() {
                received = true;
                break;
            }
        }
        if !received {
            return Err(RawPacketUdpError::new(
                RawPacketUdpErrorCode::RequestRejected,
                "selected stack rejected the raw IPv4 UDP request",
            ));
        }
        if !self.device.outbound.is_empty() {
            return Err(RawPacketUdpError::new(
                RawPacketUdpErrorCode::UnexpectedStackOutput,
                "selected stack emitted output before the application response",
            ));
        }

        let mut request_payload = vec![0; UDP_BYTES_PER_DIRECTION];
        let (request_length, metadata) = self
            .sockets
            .get_mut::<udp::Socket>(self.socket)
            .recv_slice(&mut request_payload)
            .map_err(|error| {
                RawPacketUdpError::new(
                    RawPacketUdpErrorCode::RequestRejected,
                    format!("receive selected-stack UDP request: {error}"),
                )
            })?;
        request_payload.truncate(request_length);
        self.sockets
            .get_mut::<udp::Socket>(self.socket)
            .send_slice(response_payload, metadata.endpoint)
            .map_err(|error| {
                RawPacketUdpError::new(
                    RawPacketUdpErrorCode::ResponseRejected,
                    format!("queue selected-stack UDP response: {error}"),
                )
            })?;

        for _ in 0..MAX_POLL_STEPS {
            self.poll_once()?;
            if !self.device.outbound.is_empty() {
                break;
            }
        }
        let response_packet = self.device.take_single_output()?;
        Ok(RawPacketUdpExchange {
            request_payload,
            response_packet,
        })
    }

    fn poll_once(&mut self) -> Result<(), RawPacketUdpError> {
        self.now_ms = self.now_ms.checked_add(1).ok_or_else(|| {
            RawPacketUdpError::new(
                RawPacketUdpErrorCode::ClockOverflow,
                "selected-stack poll clock overflowed",
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

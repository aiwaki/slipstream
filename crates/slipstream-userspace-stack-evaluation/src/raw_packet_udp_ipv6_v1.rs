//! Bounded IPv6 Layer 3 UDP exchange through the selected userspace stack.
//!
//! This module is an additive IPv6 qualification boundary. The frozen IPv4
//! `raw_packet_udp_v1` implementation remains unchanged.

use crate::raw_packet_udp_v1::{RawPacketUdpError, RawPacketUdpErrorCode, RawPacketUdpExchange};
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
use std::net::Ipv6Addr;

pub const CONTRACT_VERSION: u32 = 1;
pub const MAX_POLL_STEPS: usize = 64;
pub const IPV6_UDP_HEADER_BYTES: usize = 48;
pub const MAX_RESPONSE_PAYLOAD_BYTES: usize = L3_MTU - IPV6_UDP_HEADER_BYTES;

fn error(code: RawPacketUdpErrorCode, message: impl Into<String>) -> RawPacketUdpError {
    RawPacketUdpError {
        code,
        message: message.into(),
    }
}

#[derive(Default)]
struct RawPacketIpv6Device {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    fault: Option<RawPacketUdpErrorCode>,
}

impl RawPacketIpv6Device {
    fn enqueue(&mut self, packet: &[u8]) -> Result<(), RawPacketUdpError> {
        if self.inbound.len() >= MAX_LINK_FRAMES_PER_DIRECTION {
            return Err(error(
                RawPacketUdpErrorCode::InputQueueFull,
                "raw IPv6 packet input queue is full",
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
            error(
                RawPacketUdpErrorCode::ResponseMissing,
                "selected stack emitted no IPv6 response packet",
            )
        })?;
        if !self.outbound.is_empty() {
            return Err(error(
                RawPacketUdpErrorCode::MultipleResponseFrames,
                "selected stack emitted more than one IPv6 response packet",
            ));
        }
        Ok(packet)
    }

    fn take_fault(&mut self) -> Option<RawPacketUdpError> {
        self.fault
            .take()
            .map(|code| error(code, "selected stack exceeded a fixed IPv6 output bound"))
    }
}

struct RawIpv6RxToken(Vec<u8>);

impl phy::RxToken for RawIpv6RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct RawIpv6TxToken<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
    fault: &'a mut Option<RawPacketUdpErrorCode>,
}

impl phy::TxToken for RawIpv6TxToken<'_> {
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

impl Device for RawPacketIpv6Device {
    type RxToken<'a> = RawIpv6RxToken;
    type TxToken<'a> = RawIpv6TxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.outbound.len() >= MAX_LINK_FRAMES_PER_DIRECTION {
            return None;
        }
        let packet = self.inbound.pop_front()?;
        Some((
            RawIpv6RxToken(packet),
            RawIpv6TxToken {
                outbound: &mut self.outbound,
                fault: &mut self.fault,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.outbound.len() < MAX_LINK_FRAMES_PER_DIRECTION).then_some(RawIpv6TxToken {
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

pub struct RawPacketUdpIpv6StackV1 {
    interface: Interface,
    device: RawPacketIpv6Device,
    sockets: SocketSet<'static>,
    socket: SocketHandle,
    now_ms: i64,
}

impl RawPacketUdpIpv6StackV1 {
    pub fn new_ipv6(
        address: Ipv6Addr,
        prefix_len: u8,
        port: u16,
        random_seed: u64,
    ) -> Result<Self, RawPacketUdpError> {
        if prefix_len > 128 || port == 0 {
            return Err(error(
                RawPacketUdpErrorCode::InvalidConfig,
                "IPv6 prefix and UDP port must be valid",
            ));
        }

        let mut device = RawPacketIpv6Device::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = random_seed;
        let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
        let mut address_inserted = false;
        interface.update_ip_addrs(|addresses| {
            address_inserted = addresses
                .push(IpCidr::new(
                    IpAddress::Ipv6(address.octets().into()),
                    prefix_len,
                ))
                .is_ok();
        });
        if !address_inserted {
            return Err(error(
                RawPacketUdpErrorCode::InvalidConfig,
                "selected stack could not retain its fixed IPv6 address",
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
        socket.bind(port).map_err(|bind_error| {
            error(
                RawPacketUdpErrorCode::InvalidConfig,
                format!("bind selected-stack IPv6 UDP endpoint: {bind_error}"),
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

    pub fn exchange_ipv6(
        &mut self,
        request_packet: &[u8],
        response_payload: &[u8],
    ) -> Result<RawPacketUdpExchange, RawPacketUdpError> {
        if !self.device.is_idle()
            || self.sockets.get::<udp::Socket>(self.socket).can_recv()
            || self.sockets.get::<udp::Socket>(self.socket).send_queue() != 0
        {
            return Err(error(
                RawPacketUdpErrorCode::ExchangeBusy,
                "raw IPv6 packet exchange still owns prior state",
            ));
        }
        if request_packet.is_empty() || request_packet.len() > L3_MTU {
            return Err(error(
                RawPacketUdpErrorCode::RequestTooLarge,
                "raw IPv6 request packet is empty or exceeds the fixed L3 MTU",
            ));
        }
        if response_payload.len() > MAX_RESPONSE_PAYLOAD_BYTES {
            return Err(error(
                RawPacketUdpErrorCode::ResponseTooLarge,
                "UDP response cannot fit in one fixed-MTU IPv6 packet",
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
            return Err(error(
                RawPacketUdpErrorCode::RequestRejected,
                "selected stack rejected the raw IPv6 UDP request",
            ));
        }
        if !self.device.outbound.is_empty() {
            return Err(error(
                RawPacketUdpErrorCode::UnexpectedStackOutput,
                "selected stack emitted IPv6 output before the application response",
            ));
        }

        let mut request_payload = vec![0; UDP_BYTES_PER_DIRECTION];
        let (request_length, metadata) = self
            .sockets
            .get_mut::<udp::Socket>(self.socket)
            .recv_slice(&mut request_payload)
            .map_err(|recv_error| {
                error(
                    RawPacketUdpErrorCode::RequestRejected,
                    format!("receive selected-stack IPv6 UDP request: {recv_error}"),
                )
            })?;
        request_payload.truncate(request_length);
        self.sockets
            .get_mut::<udp::Socket>(self.socket)
            .send_slice(response_payload, metadata.endpoint)
            .map_err(|send_error| {
                error(
                    RawPacketUdpErrorCode::ResponseRejected,
                    format!("queue selected-stack IPv6 UDP response: {send_error}"),
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
            error(
                RawPacketUdpErrorCode::ClockOverflow,
                "selected-stack IPv6 poll clock overflowed",
            )
        })?;
        self.interface.poll(
            Instant::from_millis(self.now_ms),
            &mut self.device,
            &mut self.sockets,
        );
        if let Some(poll_error) = self.device.take_fault() {
            return Err(poll_error);
        }
        Ok(())
    }
}

use slipstream_userspace_stack_evaluation::ipv6_fragment_input_v1::{
    Ipv6FragmentReassembler, ReassemblyError, ReassemblyOutcome, MAX_ACTIVE_ASSEMBLIES,
    MAX_FRAGMENTS_PER_ASSEMBLY, REASSEMBLY_TIMEOUT_MS,
};
use slipstream_userspace_stack_evaluation::v1::L3_MTU;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv6Address, Ipv6Packet, Ipv6Repr,
    UdpPacket, UdpRepr,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

const SOURCE_PORT: u16 = 40_000;
const DESTINATION_PORT: u16 = 53;
const SOURCE: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const DESTINATION: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

#[derive(Default)]
struct DeviceState {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
}

struct QueueDevice {
    state: Rc<RefCell<DeviceState>>,
}

impl QueueDevice {
    fn new() -> (Self, Rc<RefCell<DeviceState>>) {
        let state = Rc::new(RefCell::new(DeviceState::default()));
        (
            Self {
                state: state.clone(),
            },
            state,
        )
    }
}

struct RxToken(Vec<u8>);

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct TxToken(Rc<RefCell<DeviceState>>);

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= L3_MTU);
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.0.borrow_mut().outbound.push(frame);
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.state.borrow_mut().inbound.pop_front()?;
        Some((RxToken(frame), TxToken(self.state.clone())))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken(self.state.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = L3_MTU;
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

struct UdpReceiver {
    interface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    socket: SocketHandle,
    state: Rc<RefCell<DeviceState>>,
}

impl UdpReceiver {
    fn new() -> Self {
        let (mut device, state) = QueueDevice::new();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x5151;
        let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::Ipv6(DESTINATION), 64))
                .unwrap();
        });
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
        let mut socket = udp::Socket::new(rx, tx);
        socket.bind(DESTINATION_PORT).unwrap();
        let mut sockets = SocketSet::new(Vec::new());
        let socket = sockets.add(socket);
        Self {
            interface,
            device,
            sockets,
            socket,
            state,
        }
    }

    fn inject(&mut self, packet: Vec<u8>, now_ms: i64) {
        self.state.borrow_mut().inbound.push_back(packet);
        self.interface.poll(
            Instant::from_millis(now_ms),
            &mut self.device,
            &mut self.sockets,
        );
    }

    fn can_receive(&self) -> bool {
        self.sockets.get::<udp::Socket>(self.socket).can_recv()
    }

    fn receive(&mut self, expected_len: usize) -> (Vec<u8>, IpEndpoint) {
        let mut bytes = vec![0; expected_len];
        let (len, metadata) = self
            .sockets
            .get_mut::<udp::Socket>(self.socket)
            .recv_slice(&mut bytes)
            .unwrap();
        bytes.truncate(len);
        (bytes, metadata.endpoint)
    }
}

fn udp_packet(payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut bytes = vec![0; 40 + udp_len];
    Ipv6Repr {
        src_addr: SOURCE,
        dst_addr: DESTINATION,
        next_header: IpProtocol::Udp,
        payload_len: udp_len,
        hop_limit: 64,
    }
    .emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..]));
    UdpRepr {
        src_port: SOURCE_PORT,
        dst_port: DESTINATION_PORT,
    }
    .emit(
        &mut UdpPacket::new_unchecked(&mut bytes[40..]),
        &IpAddress::Ipv6(SOURCE),
        &IpAddress::Ipv6(DESTINATION),
        payload.len(),
        |buffer| buffer.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );
    bytes
}

fn tcp_packet(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40 + payload.len()];
    Ipv6Repr {
        src_addr: SOURCE,
        dst_addr: DESTINATION,
        next_header: IpProtocol::Tcp,
        payload_len: payload.len(),
        hop_limit: 64,
    }
    .emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..]));
    bytes[40..].copy_from_slice(payload);
    bytes
}

fn fragment(
    packet: &[u8],
    identification: u32,
    offset: usize,
    len: usize,
    more_fragments: bool,
) -> Vec<u8> {
    assert_eq!(offset % 8, 0);
    let payload = &packet[40 + offset..40 + offset + len];
    let mut result = vec![0; 48 + len];
    result[..40].copy_from_slice(&packet[..40]);
    result[4..6].copy_from_slice(&((8 + len) as u16).to_be_bytes());
    result[6] = 44;
    result[40] = packet[6];
    result[41] = 0;
    let mut offset_and_flags = ((offset / 8) as u16) << 3;
    if more_fragments {
        offset_and_flags |= 1;
    }
    result[42..44].copy_from_slice(&offset_and_flags.to_be_bytes());
    result[44..48].copy_from_slice(&identification.to_be_bytes());
    result[48..].copy_from_slice(payload);
    result
}

fn two_fragments(packet: &[u8], identification: u32) -> (Vec<u8>, Vec<u8>) {
    let payload_len = packet.len() - 40;
    let first_len = 256;
    (
        fragment(packet, identification, 0, first_len, true),
        fragment(
            packet,
            identification,
            first_len,
            payload_len - first_len,
            false,
        ),
    )
}

#[test]
fn selected_stack_does_not_natively_deliver_ipv6_fragment_input() {
    let payload = vec![0xa5; 512];
    let packet = udp_packet(&payload);
    let (first, last) = two_fragments(&packet, 0x1020_3040);
    let mut receiver = UdpReceiver::new();

    receiver.inject(first, 1);
    receiver.inject(last, 2);

    assert!(!receiver.can_receive());
}

#[test]
fn bounded_reassembly_delivers_exact_udp_packet_to_selected_stack() {
    let payload = vec![0x5a; 512];
    let packet = udp_packet(&payload);
    let (first, last) = two_fragments(&packet, 0x1122_3344);
    let mut reassembler = Ipv6FragmentReassembler::new();
    assert_eq!(
        reassembler.ingest(1, &first).unwrap(),
        ReassemblyOutcome::Pending
    );
    let ReassemblyOutcome::Complete(reassembled) = reassembler.ingest(2, &last).unwrap() else {
        panic!("the complete fragment set must emit one packet");
    };
    assert_eq!(reassembled, packet);
    assert_eq!(reassembler.active_assemblies(), 0);

    let mut receiver = UdpReceiver::new();
    receiver.inject(reassembled, 3);
    assert!(receiver.can_receive());
    let (received, endpoint) = receiver.receive(payload.len());
    assert_eq!(received, payload);
    assert_eq!(
        endpoint,
        IpEndpoint::new(IpAddress::Ipv6(SOURCE), SOURCE_PORT)
    );
}

#[test]
fn out_of_order_fragments_reassemble_deterministically() {
    let packet = udp_packet(&vec![0x3c; 512]);
    let (first, last) = two_fragments(&packet, 0x5566_7788);
    let mut reassembler = Ipv6FragmentReassembler::new();
    assert_eq!(
        reassembler.ingest(10, &last).unwrap(),
        ReassemblyOutcome::Pending
    );
    assert_eq!(
        reassembler.ingest(11, &first).unwrap(),
        ReassemblyOutcome::Complete(packet)
    );
}

#[test]
fn tcp_fragment_payload_reassembles_exactly_before_stack_processing() {
    let packet = tcp_packet(&vec![0xc3; 512]);
    let (first, last) = two_fragments(&packet, 0xaabb_ccdd);
    let mut reassembler = Ipv6FragmentReassembler::new();
    assert_eq!(
        reassembler.ingest(1, &first),
        Ok(ReassemblyOutcome::Pending)
    );
    assert_eq!(
        reassembler.ingest(2, &last),
        Ok(ReassemblyOutcome::Complete(packet))
    );
}

#[test]
fn legal_two_fragment_split_matrix_reconstructs_exactly() {
    for payload_len in [1, 8, 31, 512, 1024, 2048, 4000] {
        let packet = udp_packet(&vec![payload_len as u8; payload_len]);
        let transport_len = packet.len() - 40;
        for split in (8..transport_len).step_by(8) {
            let first = fragment(&packet, 0x7654_3210, 0, split, true);
            let last = fragment(&packet, 0x7654_3210, split, transport_len - split, false);
            let mut in_order = Ipv6FragmentReassembler::new();
            assert_eq!(in_order.ingest(1, &first), Ok(ReassemblyOutcome::Pending));
            assert_eq!(
                in_order.ingest(2, &last),
                Ok(ReassemblyOutcome::Complete(packet.clone()))
            );

            let mut out_of_order = Ipv6FragmentReassembler::new();
            assert_eq!(
                out_of_order.ingest(1, &last),
                Ok(ReassemblyOutcome::Pending)
            );
            assert_eq!(
                out_of_order.ingest(2, &first),
                Ok(ReassemblyOutcome::Complete(packet.clone()))
            );
        }
    }
}

#[test]
fn overlap_and_conflicting_headers_fail_closed_and_release_the_slot() {
    let packet = udp_packet(&vec![0x81; 512]);
    let first = fragment(&packet, 7, 0, 256, true);
    let overlap = fragment(&packet, 7, 128, 256, true);
    let mut reassembler = Ipv6FragmentReassembler::new();
    assert_eq!(
        reassembler.ingest(1, &first).unwrap(),
        ReassemblyOutcome::Pending
    );
    assert_eq!(
        reassembler.ingest(2, &overlap),
        Err(ReassemblyError::OverlappingFragment)
    );
    assert_eq!(reassembler.active_assemblies(), 0);

    let mut conflicting = fragment(&packet, 8, 256, packet.len() - 40 - 256, false);
    conflicting[7] = 63;
    assert_eq!(
        reassembler.ingest(3, &fragment(&packet, 8, 0, 256, true)),
        Ok(ReassemblyOutcome::Pending)
    );
    assert_eq!(
        reassembler.ingest(4, &conflicting),
        Err(ReassemblyError::ConflictingHeader)
    );
    assert_eq!(reassembler.active_assemblies(), 0);
}

#[test]
fn conflicting_final_sizes_fail_closed_and_release_the_slot() {
    let packet = udp_packet(&vec![0x66; 512]);
    let mut reassembler = Ipv6FragmentReassembler::new();
    assert_eq!(
        reassembler.ingest(1, &fragment(&packet, 9, 512, 8, false)),
        Ok(ReassemblyOutcome::Pending)
    );
    assert_eq!(
        reassembler.ingest(2, &fragment(&packet, 9, 256, 256, false)),
        Err(ReassemblyError::ConflictingTotalSize)
    );
    assert_eq!(reassembler.active_assemblies(), 0);
}

#[test]
fn incomplete_and_excess_assemblies_remain_bounded() {
    let packet = udp_packet(&vec![0x42; 512]);
    let mut reassembler = Ipv6FragmentReassembler::new();
    for identification in 1..=MAX_ACTIVE_ASSEMBLIES as u32 {
        assert_eq!(
            reassembler.ingest(
                identification as u64,
                &fragment(&packet, identification, 0, 256, true)
            ),
            Ok(ReassemblyOutcome::Pending)
        );
    }
    assert_eq!(reassembler.active_assemblies(), MAX_ACTIVE_ASSEMBLIES);
    assert_eq!(
        reassembler.ingest(10, &fragment(&packet, 99, 0, 256, true)),
        Err(ReassemblyError::AssemblyCapacityExceeded)
    );
    assert_eq!(reassembler.active_assemblies(), MAX_ACTIVE_ASSEMBLIES);
    assert_eq!(reassembler.expire(REASSEMBLY_TIMEOUT_MS + 2), 2);
    assert_eq!(reassembler.active_assemblies(), 0);
}

#[test]
fn identification_and_fragment_count_cannot_blend_or_grow_without_bound() {
    let packet = udp_packet(&vec![0x24; 512]);
    let mut reassembler = Ipv6FragmentReassembler::new();
    assert_eq!(
        reassembler.ingest(1, &fragment(&packet, 1, 0, 256, true)),
        Ok(ReassemblyOutcome::Pending)
    );
    assert_eq!(
        reassembler.ingest(
            2,
            &fragment(&packet, 2, 256, packet.len() - 40 - 256, false)
        ),
        Ok(ReassemblyOutcome::Pending)
    );
    assert_eq!(reassembler.active_assemblies(), 2);

    let mut bounded = Ipv6FragmentReassembler::new();
    for index in 0..MAX_FRAGMENTS_PER_ASSEMBLY {
        assert_eq!(
            bounded.ingest(index as u64, &fragment(&packet, 3, index * 8, 8, true)),
            Ok(ReassemblyOutcome::Pending)
        );
    }
    assert_eq!(
        bounded.ingest(
            MAX_FRAGMENTS_PER_ASSEMBLY as u64,
            &fragment(&packet, 3, MAX_FRAGMENTS_PER_ASSEMBLY * 8, 8, true)
        ),
        Err(ReassemblyError::FragmentCountExceeded)
    );
    assert_eq!(bounded.active_assemblies(), 0);
}

#[test]
fn malformed_and_out_of_bound_fragments_are_rejected_before_allocation() {
    let packet = udp_packet(&vec![0x18; 5000]);
    let mut reassembler = Ipv6FragmentReassembler::new();
    let mut unsupported_transport = fragment(&packet, 0, 0, 16, true);
    unsupported_transport[40] = 59;
    assert_eq!(
        reassembler.ingest(0, &unsupported_transport),
        Err(ReassemblyError::UnsupportedFragmentNextHeader)
    );
    let mut reserved = fragment(&packet, 0, 0, 16, true);
    reserved[41] = 1;
    assert_eq!(
        reassembler.ingest(0, &reserved),
        Err(ReassemblyError::ReservedBitsSet)
    );
    assert_eq!(
        reassembler.ingest(1, &fragment(&packet, 1, 0, 15, true)),
        Err(ReassemblyError::NonFinalFragmentNotAligned)
    );
    assert_eq!(
        reassembler.ingest(2, &fragment(&packet, 2, 4096, 8, false)),
        Err(ReassemblyError::FragmentExceedsBuffer)
    );
    assert_eq!(reassembler.active_assemblies(), 0);
}

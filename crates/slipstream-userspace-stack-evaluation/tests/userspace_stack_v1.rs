use slipstream_userspace_stack_evaluation::v1::{
    L3_MTU, MAX_BURST_FRAMES, MAX_LINK_FRAMES_PER_DIRECTION, MAX_SOCKETS_PER_STACK,
    TCP_BYTES_PER_DIRECTION, UDP_BYTES_PER_DIRECTION, UDP_PACKET_SLOTS_PER_DIRECTION,
};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Clone, Copy)]
enum Side {
    A,
    B,
}

#[derive(Default)]
struct LinkState {
    to_a: VecDeque<Vec<u8>>,
    to_b: VecDeque<Vec<u8>>,
    peak_to_a: usize,
    peak_to_b: usize,
    sent_to_a: usize,
    sent_to_b: usize,
}

struct BoundedDevice {
    state: Rc<RefCell<LinkState>>,
    side: Side,
}

impl BoundedDevice {
    fn pair() -> (Self, Self, Rc<RefCell<LinkState>>) {
        let state = Rc::new(RefCell::new(LinkState::default()));
        (
            Self {
                state: state.clone(),
                side: Side::A,
            },
            Self {
                state: state.clone(),
                side: Side::B,
            },
            state,
        )
    }

    fn peer_has_capacity(&self) -> bool {
        let state = self.state.borrow();
        match self.side {
            Side::A => state.to_b.len() < MAX_LINK_FRAMES_PER_DIRECTION,
            Side::B => state.to_a.len() < MAX_LINK_FRAMES_PER_DIRECTION,
        }
    }

    fn corrupt_next_peer_frame(&self) {
        let mut state = self.state.borrow_mut();
        let queue = match self.side {
            Side::A => &mut state.to_b,
            Side::B => &mut state.to_a,
        };
        let frame = queue.front_mut().expect("a frame must be queued");
        let byte = frame.last_mut().expect("the frame must not be empty");
        *byte ^= 0xff;
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

struct TxToken {
    state: Rc<RefCell<LinkState>>,
    side: Side,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= L3_MTU, "stack emitted an oversized L3 frame");
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        let mut state = self.state.borrow_mut();
        match self.side {
            Side::A => {
                assert!(state.to_b.len() < MAX_LINK_FRAMES_PER_DIRECTION);
                state.to_b.push_back(frame);
                state.peak_to_b = state.peak_to_b.max(state.to_b.len());
                state.sent_to_b += 1;
            }
            Side::B => {
                assert!(state.to_a.len() < MAX_LINK_FRAMES_PER_DIRECTION);
                state.to_a.push_back(frame);
                state.peak_to_a = state.peak_to_a.max(state.to_a.len());
                state.sent_to_a += 1;
            }
        }
        result
    }
}

impl Device for BoundedDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if !self.peer_has_capacity() {
            return None;
        }
        let frame = {
            let mut state = self.state.borrow_mut();
            match self.side {
                Side::A => state.to_a.pop_front(),
                Side::B => state.to_b.pop_front(),
            }
        }?;
        Some((
            RxToken(frame),
            TxToken {
                state: self.state.clone(),
                side: self.side,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.peer_has_capacity().then(|| TxToken {
            state: self.state.clone(),
            side: self.side,
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

struct TestStack {
    iface: Interface,
    device: BoundedDevice,
    sockets: SocketSet<'static>,
    socket_count: usize,
}

impl TestStack {
    fn new(mut device: BoundedDevice, ipv4: [u8; 4], ipv6: [u16; 8], seed: u64) -> Self {
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::Ipv4(ipv4.into()), 24))
                .unwrap();
            addresses
                .push(IpCidr::new(IpAddress::Ipv6(ipv6.into()), 64))
                .unwrap();
        });
        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            socket_count: 0,
        }
    }

    fn add_udp(&mut self, port: u16) -> SocketHandle {
        assert!(self.socket_count < MAX_SOCKETS_PER_STACK);
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_PACKET_SLOTS_PER_DIRECTION],
            vec![0; UDP_BYTES_PER_DIRECTION],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_PACKET_SLOTS_PER_DIRECTION],
            vec![0; UDP_BYTES_PER_DIRECTION],
        );
        let mut socket = udp::Socket::new(rx, tx);
        socket.bind(port).unwrap();
        let handle = self.sockets.add(socket);
        self.socket_count += 1;
        handle
    }

    fn add_tcp(&mut self) -> SocketHandle {
        assert!(self.socket_count < MAX_SOCKETS_PER_STACK);
        let rx = tcp::SocketBuffer::new(vec![0; TCP_BYTES_PER_DIRECTION]);
        let tx = tcp::SocketBuffer::new(vec![0; TCP_BYTES_PER_DIRECTION]);
        let handle = self.sockets.add(tcp::Socket::new(rx, tx));
        self.socket_count += 1;
        handle
    }

    fn poll(&mut self, now_ms: i64) {
        self.iface.poll(
            Instant::from_millis(now_ms),
            &mut self.device,
            &mut self.sockets,
        );
    }
}

fn poll_pair(a: &mut TestStack, b: &mut TestStack, now_ms: &mut i64) {
    a.poll(*now_ms);
    b.poll(*now_ms);
    *now_ms += 1;
}

fn addresses(ipv6: bool) -> (IpAddress, IpAddress) {
    if ipv6 {
        (
            IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        )
    } else {
        (IpAddress::v4(10, 0, 0, 1), IpAddress::v4(10, 0, 0, 2))
    }
}

fn assert_link_is_bounded(state: &LinkState) {
    assert!(state.peak_to_a <= MAX_LINK_FRAMES_PER_DIRECTION);
    assert!(state.peak_to_b <= MAX_LINK_FRAMES_PER_DIRECTION);
}

fn udp_round_trip(ipv6: bool, payload: &[u8]) -> (usize, usize) {
    let (a_device, b_device, link) = BoundedDevice::pair();
    let mut a = TestStack::new(a_device, [10, 0, 0, 1], [0xfd00, 0, 0, 0, 0, 0, 0, 1], 1);
    let mut b = TestStack::new(b_device, [10, 0, 0, 2], [0xfd00, 0, 0, 0, 0, 0, 0, 2], 2);
    let a_socket = a.add_udp(40_000);
    let b_socket = b.add_udp(53);
    let (a_addr, b_addr) = addresses(ipv6);
    a.sockets
        .get_mut::<udp::Socket>(a_socket)
        .send_slice(payload, IpEndpoint::new(b_addr, 53))
        .unwrap();

    let mut now_ms = 1;
    for _ in 0..1000 {
        poll_pair(&mut a, &mut b, &mut now_ms);
        if b.sockets.get::<udp::Socket>(b_socket).can_recv() {
            break;
        }
    }
    assert!(b.sockets.get::<udp::Socket>(b_socket).can_recv());
    let mut received = vec![0; payload.len()];
    let (len, metadata) = b
        .sockets
        .get_mut::<udp::Socket>(b_socket)
        .recv_slice(&mut received)
        .unwrap();
    assert_eq!(&received[..len], payload);
    assert_eq!(metadata.endpoint, IpEndpoint::new(a_addr, 40_000));
    b.sockets
        .get_mut::<udp::Socket>(b_socket)
        .send_slice(b"ok", metadata.endpoint)
        .unwrap();
    for _ in 0..1000 {
        poll_pair(&mut a, &mut b, &mut now_ms);
        if a.sockets.get::<udp::Socket>(a_socket).can_recv() {
            break;
        }
    }
    let mut response = [0; 2];
    let (len, _) = a
        .sockets
        .get_mut::<udp::Socket>(a_socket)
        .recv_slice(&mut response)
        .unwrap();
    assert_eq!(&response[..len], b"ok");
    let state = link.borrow();
    assert_link_is_bounded(&state);
    (state.sent_to_a, state.sent_to_b)
}

fn udp_checksum_rejection(ipv6: bool) {
    let (a_device, b_device, link) = BoundedDevice::pair();
    let mut a = TestStack::new(a_device, [10, 0, 0, 1], [0xfd00, 0, 0, 0, 0, 0, 0, 1], 5);
    let mut b = TestStack::new(b_device, [10, 0, 0, 2], [0xfd00, 0, 0, 0, 0, 0, 0, 2], 6);
    let a_socket = a.add_udp(40_002);
    let b_socket = b.add_udp(53);
    let (_, b_addr) = addresses(ipv6);

    a.sockets
        .get_mut::<udp::Socket>(a_socket)
        .send_slice(b"corrupt me", IpEndpoint::new(b_addr, 53))
        .unwrap();
    a.poll(1);
    a.device.corrupt_next_peer_frame();
    b.poll(1);
    assert!(!b.sockets.get::<udp::Socket>(b_socket).can_recv());

    a.sockets
        .get_mut::<udp::Socket>(a_socket)
        .send_slice(b"valid", IpEndpoint::new(b_addr, 53))
        .unwrap();
    let mut now_ms = 2;
    for _ in 0..100 {
        poll_pair(&mut a, &mut b, &mut now_ms);
        if b.sockets.get::<udp::Socket>(b_socket).can_recv() {
            break;
        }
    }
    let mut received = [0; 5];
    let (len, _) = b
        .sockets
        .get_mut::<udp::Socket>(b_socket)
        .recv_slice(&mut received)
        .unwrap();
    assert_eq!(&received[..len], b"valid");
    assert_link_is_bounded(&link.borrow());
}

fn tcp_round_trip(ipv6: bool) {
    let (a_device, b_device, link) = BoundedDevice::pair();
    let mut a = TestStack::new(a_device, [10, 0, 0, 1], [0xfd00, 0, 0, 0, 0, 0, 0, 1], 3);
    let mut b = TestStack::new(b_device, [10, 0, 0, 2], [0xfd00, 0, 0, 0, 0, 0, 0, 2], 4);
    let a_socket = a.add_tcp();
    let b_socket = b.add_tcp();
    let (_, b_addr) = addresses(ipv6);
    b.sockets
        .get_mut::<tcp::Socket>(b_socket)
        .listen(443)
        .unwrap();
    {
        let context = a.iface.context();
        a.sockets
            .get_mut::<tcp::Socket>(a_socket)
            .connect(context, IpEndpoint::new(b_addr, 443), 40_001)
            .unwrap();
    }

    let mut now_ms = 1;
    for _ in 0..5000 {
        poll_pair(&mut a, &mut b, &mut now_ms);
        if a.sockets.get::<tcp::Socket>(a_socket).is_active()
            && b.sockets.get::<tcp::Socket>(b_socket).is_active()
            && a.sockets.get::<tcp::Socket>(a_socket).can_send()
        {
            break;
        }
    }
    assert!(a.sockets.get::<tcp::Socket>(a_socket).can_send());
    a.sockets
        .get_mut::<tcp::Socket>(a_socket)
        .send_slice(b"request")
        .unwrap();
    for _ in 0..5000 {
        poll_pair(&mut a, &mut b, &mut now_ms);
        if b.sockets.get::<tcp::Socket>(b_socket).can_recv() {
            break;
        }
    }
    let mut request = [0; 7];
    let len = b
        .sockets
        .get_mut::<tcp::Socket>(b_socket)
        .recv_slice(&mut request)
        .unwrap();
    assert_eq!(&request[..len], b"request");
    b.sockets
        .get_mut::<tcp::Socket>(b_socket)
        .send_slice(b"response")
        .unwrap();
    for _ in 0..5000 {
        poll_pair(&mut a, &mut b, &mut now_ms);
        if a.sockets.get::<tcp::Socket>(a_socket).can_recv() {
            break;
        }
    }
    let mut response = [0; 8];
    let len = a
        .sockets
        .get_mut::<tcp::Socket>(a_socket)
        .recv_slice(&mut response)
        .unwrap();
    assert_eq!(&response[..len], b"response");
    a.sockets.get_mut::<tcp::Socket>(a_socket).close();
    b.sockets.get_mut::<tcp::Socket>(b_socket).close();
    for _ in 0..5000 {
        poll_pair(&mut a, &mut b, &mut now_ms);
        if !a.sockets.get::<tcp::Socket>(a_socket).is_open()
            && !b.sockets.get::<tcp::Socket>(b_socket).is_open()
        {
            break;
        }
    }
    assert!(!a.sockets.get::<tcp::Socket>(a_socket).is_open());
    assert!(!b.sockets.get::<tcp::Socket>(b_socket).is_open());
    assert_link_is_bounded(&link.borrow());
}

#[test]
fn ipv4_fragmentation_reassembles_inside_fixed_bounds() {
    let (_, client_to_server) = udp_round_trip(false, &vec![0x5a; 2048]);
    assert!(
        client_to_server >= 2,
        "the payload must cross multiple L3 frames"
    );
}

#[test]
fn ipv6_udp_below_mtu_round_trips_inside_fixed_bounds() {
    let (_, client_to_server) = udp_round_trip(true, &vec![0xa5; 512]);
    assert_eq!(client_to_server, 1);
}

#[test]
fn fixed_seeds_produce_the_same_frame_schedule() {
    let first = udp_round_trip(false, b"deterministic");
    let second = udp_round_trip(false, b"deterministic");
    assert_eq!(first, second);
}

#[test]
fn oversized_ipv6_udp_drops_without_emitting_an_l3_frame() {
    let (a_device, _b_device, link) = BoundedDevice::pair();
    let mut a = TestStack::new(a_device, [10, 0, 0, 1], [0xfd00, 0, 0, 0, 0, 0, 0, 1], 7);
    let a_socket = a.add_udp(40_003);
    a.sockets
        .get_mut::<udp::Socket>(a_socket)
        .send_slice(
            &vec![0xff; 2048],
            IpEndpoint::new(IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 2), 53),
        )
        .unwrap();
    a.poll(1);
    let state = link.borrow();
    assert_eq!(state.sent_to_b, 0);
    assert!(state.to_b.is_empty());
}

#[test]
fn dual_stack_udp_checksums_reject_corruption() {
    udp_checksum_rejection(false);
    udp_checksum_rejection(true);
}

#[test]
fn dual_stack_tcp_round_trip_is_bounded() {
    tcp_round_trip(false);
    tcp_round_trip(true);
}

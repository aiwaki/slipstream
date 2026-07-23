#[path = "../../slipstream-windows-adapter/tests/support/userspace_fixture.rs"]
mod userspace_fixture;

use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_userspace_stack_effect_evaluation::v1::{MAX_EFFECT_PAYLOAD_BYTES, MAX_POLL_STEPS};
use slipstream_userspace_stack_evaluation::v1::{
    L3_MTU, MAX_BURST_FRAMES, MAX_LINK_FRAMES_PER_DIRECTION, MAX_SOCKETS_PER_STACK,
    TCP_BYTES_PER_DIRECTION, UDP_BYTES_PER_DIRECTION, UDP_PACKET_SLOTS_PER_DIRECTION,
};
use slipstream_windows_adapter::data_plane::WindowsDataPlaneBackend;
use slipstream_windows_adapter::packet_adapter::v4::WindowsPacketCaptureTransport;
use slipstream_windows_adapter::packet_flow::{
    reduce_windows_packet_flow, WindowsPacketFlowCommand, WindowsPacketFlowConfig,
    WindowsPacketFlowDirection, WindowsPacketFlowEvent, WindowsPacketFlowKey,
    WindowsPacketFlowRegistry, WindowsPacketFlowTransport,
};
use slipstream_windows_adapter::userspace_stack_bridge::{
    bind_windows_userspace_flow, WindowsUserspaceByteDelivery, WindowsUserspaceByteEffects,
    WindowsUserspaceByteOwner, WindowsUserspaceByteOwnerConfig, WindowsUserspaceByteOwnerErrorCode,
    WindowsUserspaceFlowTuple,
};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::net::IpAddr;
use std::rc::Rc;
use userspace_fixture::{
    admission, classification, flow_open_event, AdmissionFixture, ClassificationFixture,
};

#[derive(Clone, Copy)]
enum Side {
    Client,
    Backend,
}

#[derive(Default)]
struct LinkState {
    to_client: VecDeque<Vec<u8>>,
    to_backend: VecDeque<Vec<u8>>,
    peak_to_client: usize,
    peak_to_backend: usize,
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
                side: Side::Client,
            },
            Self {
                state: state.clone(),
                side: Side::Backend,
            },
            state,
        )
    }

    fn peer_has_capacity(&self) -> bool {
        let state = self.state.borrow();
        match self.side {
            Side::Client => state.to_backend.len() < MAX_LINK_FRAMES_PER_DIRECTION,
            Side::Backend => state.to_client.len() < MAX_LINK_FRAMES_PER_DIRECTION,
        }
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
            Side::Client => {
                assert!(state.to_backend.len() < MAX_LINK_FRAMES_PER_DIRECTION);
                state.to_backend.push_back(frame);
                state.peak_to_backend = state.peak_to_backend.max(state.to_backend.len());
            }
            Side::Backend => {
                assert!(state.to_client.len() < MAX_LINK_FRAMES_PER_DIRECTION);
                state.to_client.push_back(frame);
                state.peak_to_client = state.peak_to_client.max(state.to_client.len());
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
                Side::Client => state.to_client.pop_front(),
                Side::Backend => state.to_backend.pop_front(),
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
    fn new(mut device: BoundedDevice, address: IpAddr, seed: u64) -> Self {
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(stack_address(address), 0))
                .expect("one address must fit");
        });
        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            socket_count: 0,
        }
    }

    fn add_tcp(&mut self) -> SocketHandle {
        assert!(self.socket_count < MAX_SOCKETS_PER_STACK);
        let rx = tcp::SocketBuffer::new(vec![0; TCP_BYTES_PER_DIRECTION]);
        let tx = tcp::SocketBuffer::new(vec![0; TCP_BYTES_PER_DIRECTION]);
        let handle = self.sockets.add(tcp::Socket::new(rx, tx));
        self.socket_count += 1;
        handle
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
        socket.bind(port).expect("fixed UDP port must bind");
        let handle = self.sockets.add(socket);
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

fn stack_address(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => IpAddress::Ipv4(address.octets().into()),
        IpAddr::V6(address) => IpAddress::Ipv6(address.segments().into()),
    }
}

fn endpoint(address: IpAddr, port: u16) -> IpEndpoint {
    IpEndpoint::new(stack_address(address), port)
}

#[derive(Clone, Copy)]
enum SocketPair {
    Tcp {
        client: SocketHandle,
        backend: SocketHandle,
    },
    Udp {
        client: SocketHandle,
        backend: SocketHandle,
    },
}

#[derive(Debug, Eq, PartialEq)]
struct VisibleStackState {
    link_to_client: usize,
    link_to_backend: usize,
    client_send_bytes: usize,
    backend_send_bytes: usize,
}

#[derive(Debug, Eq, PartialEq)]
enum SelectedStackEffectError {
    InjectedBeforeMutation,
    TupleMismatch,
    PayloadTooLarge,
    Backpressure,
}

impl fmt::Display for SelectedStackEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InjectedBeforeMutation => "injected before selected-stack mutation",
            Self::TupleMismatch => "delivery tuple does not match the selected stack",
            Self::PayloadTooLarge => "delivery exceeds the test-only effect bound",
            Self::Backpressure => "selected stack cannot atomically accept the payload",
        };
        formatter.write_str(message)
    }
}

struct SelectedStackEffect {
    key: WindowsPacketFlowKey,
    tuple: WindowsUserspaceFlowTuple,
    client: TestStack,
    backend: TestStack,
    sockets: SocketPair,
    link: Rc<RefCell<LinkState>>,
    now_ms: i64,
    fail_next: bool,
}

impl SelectedStackEffect {
    fn new(key: WindowsPacketFlowKey, tuple: WindowsUserspaceFlowTuple) -> Self {
        let (client_device, backend_device, link) = BoundedDevice::pair();
        let mut client = TestStack::new(client_device, tuple.source.address, 101);
        let mut backend = TestStack::new(backend_device, tuple.destination.address, 202);
        let sockets = match tuple.transport {
            WindowsPacketFlowTransport::Tcp => {
                let client_handle = client.add_tcp();
                let backend_handle = backend.add_tcp();
                backend
                    .sockets
                    .get_mut::<tcp::Socket>(backend_handle)
                    .listen(tuple.destination.port)
                    .expect("fixed backend port must listen");
                {
                    let context = client.iface.context();
                    client
                        .sockets
                        .get_mut::<tcp::Socket>(client_handle)
                        .connect(
                            context,
                            endpoint(tuple.destination.address, tuple.destination.port),
                            tuple.source.port,
                        )
                        .expect("fixed client tuple must connect");
                }
                SocketPair::Tcp {
                    client: client_handle,
                    backend: backend_handle,
                }
            }
            WindowsPacketFlowTransport::Udp => SocketPair::Udp {
                client: client.add_udp(tuple.source.port),
                backend: backend.add_udp(tuple.destination.port),
            },
        };
        let mut effect = Self {
            key,
            tuple,
            client,
            backend,
            sockets,
            link,
            now_ms: 1,
            fail_next: false,
        };
        effect.establish();
        effect
    }

    fn establish(&mut self) {
        let SocketPair::Tcp { client, backend } = self.sockets else {
            return;
        };
        for _ in 0..MAX_POLL_STEPS {
            self.poll_pair();
            let client_socket = self.client.sockets.get::<tcp::Socket>(client);
            let backend_socket = self.backend.sockets.get::<tcp::Socket>(backend);
            if client_socket.is_active()
                && backend_socket.is_active()
                && client_socket.can_send()
                && backend_socket.can_send()
            {
                break;
            }
        }
        let client_socket = self.client.sockets.get::<tcp::Socket>(client);
        let backend_socket = self.backend.sockets.get::<tcp::Socket>(backend);
        assert!(client_socket.is_active());
        assert!(backend_socket.is_active());
        assert_eq!(
            client_socket.local_endpoint(),
            Some(endpoint(self.tuple.source.address, self.tuple.source.port))
        );
        assert_eq!(
            client_socket.remote_endpoint(),
            Some(endpoint(
                self.tuple.destination.address,
                self.tuple.destination.port
            ))
        );
        assert_eq!(
            backend_socket.local_endpoint(),
            Some(endpoint(
                self.tuple.destination.address,
                self.tuple.destination.port
            ))
        );
        assert_eq!(
            backend_socket.remote_endpoint(),
            Some(endpoint(self.tuple.source.address, self.tuple.source.port))
        );
        self.settle();
    }

    fn poll_pair(&mut self) {
        self.client.poll(self.now_ms);
        self.backend.poll(self.now_ms);
        self.now_ms += 1;
    }

    fn settle(&mut self) {
        for _ in 0..32 {
            self.poll_pair();
            let link = self.link.borrow();
            if link.to_client.is_empty() && link.to_backend.is_empty() {
                break;
            }
        }
    }

    fn fail_next(&mut self) {
        self.fail_next = true;
    }

    fn visible_state(&self) -> VisibleStackState {
        let (client_send_bytes, backend_send_bytes) = match self.sockets {
            SocketPair::Tcp { client, backend } => (
                self.client.sockets.get::<tcp::Socket>(client).send_queue(),
                self.backend
                    .sockets
                    .get::<tcp::Socket>(backend)
                    .send_queue(),
            ),
            SocketPair::Udp { client, backend } => (
                self.client.sockets.get::<udp::Socket>(client).send_queue(),
                self.backend
                    .sockets
                    .get::<udp::Socket>(backend)
                    .send_queue(),
            ),
        };
        let link = self.link.borrow();
        VisibleStackState {
            link_to_client: link.to_client.len(),
            link_to_backend: link.to_backend.len(),
            client_send_bytes,
            backend_send_bytes,
        }
    }

    fn receive_exact(&mut self, direction: WindowsPacketFlowDirection, expected: &[u8]) {
        match self.sockets {
            SocketPair::Tcp { client, backend } => {
                let (receiver, sender_address, sender_port, client_side) = match direction {
                    WindowsPacketFlowDirection::ClientToBackend => (
                        backend,
                        self.tuple.source.address,
                        self.tuple.source.port,
                        false,
                    ),
                    WindowsPacketFlowDirection::BackendToClient => (
                        client,
                        self.tuple.destination.address,
                        self.tuple.destination.port,
                        true,
                    ),
                };
                let mut received = Vec::with_capacity(expected.len());
                for _ in 0..MAX_POLL_STEPS {
                    self.poll_pair();
                    let stack = if client_side {
                        &mut self.client
                    } else {
                        &mut self.backend
                    };
                    let socket = stack.sockets.get_mut::<tcp::Socket>(receiver);
                    if socket.can_recv() {
                        let mut chunk = vec![0; expected.len() - received.len()];
                        let len = socket.recv_slice(&mut chunk).expect("TCP receive");
                        received.extend_from_slice(&chunk[..len]);
                        if received.len() == expected.len() {
                            assert_eq!(
                                socket.remote_endpoint(),
                                Some(endpoint(sender_address, sender_port))
                            );
                            break;
                        }
                    }
                }
                assert_eq!(received, expected);
            }
            SocketPair::Udp { client, backend } => {
                let (receiver, sender_address, sender_port, client_side) = match direction {
                    WindowsPacketFlowDirection::ClientToBackend => (
                        backend,
                        self.tuple.source.address,
                        self.tuple.source.port,
                        false,
                    ),
                    WindowsPacketFlowDirection::BackendToClient => (
                        client,
                        self.tuple.destination.address,
                        self.tuple.destination.port,
                        true,
                    ),
                };
                for _ in 0..MAX_POLL_STEPS {
                    self.poll_pair();
                    let stack = if client_side {
                        &mut self.client
                    } else {
                        &mut self.backend
                    };
                    let socket = stack.sockets.get_mut::<udp::Socket>(receiver);
                    if socket.can_recv() {
                        let mut received = vec![0; expected.len()];
                        let (len, metadata) =
                            socket.recv_slice(&mut received).expect("UDP receive");
                        assert_eq!(&received[..len], expected);
                        assert_eq!(metadata.endpoint, endpoint(sender_address, sender_port));
                        return;
                    }
                }
                panic!("UDP payload did not arrive inside the fixed poll bound");
            }
        }
        let link = self.link.borrow();
        assert!(link.peak_to_client <= MAX_LINK_FRAMES_PER_DIRECTION);
        assert!(link.peak_to_backend <= MAX_LINK_FRAMES_PER_DIRECTION);
    }
}

impl WindowsUserspaceByteEffects for SelectedStackEffect {
    type Error = SelectedStackEffectError;

    fn forward(&mut self, delivery: &WindowsUserspaceByteDelivery<'_>) -> Result<(), Self::Error> {
        if delivery.key() != self.key
            || delivery.binding().key() != self.key
            || delivery.binding().tuple() != self.tuple
        {
            return Err(SelectedStackEffectError::TupleMismatch);
        }
        if delivery.bytes().len() > MAX_EFFECT_PAYLOAD_BYTES {
            return Err(SelectedStackEffectError::PayloadTooLarge);
        }
        if self.fail_next {
            self.fail_next = false;
            return Err(SelectedStackEffectError::InjectedBeforeMutation);
        }

        match self.sockets {
            SocketPair::Tcp { client, backend } => {
                let (stack, handle) = match delivery.direction() {
                    WindowsPacketFlowDirection::ClientToBackend => (&mut self.client, client),
                    WindowsPacketFlowDirection::BackendToClient => (&mut self.backend, backend),
                };
                let socket = stack.sockets.get_mut::<tcp::Socket>(handle);
                if !socket.can_send()
                    || socket
                        .send_queue()
                        .checked_add(delivery.bytes().len())
                        .is_none_or(|bytes| bytes > socket.send_capacity())
                {
                    return Err(SelectedStackEffectError::Backpressure);
                }
                let sent = socket
                    .send_slice(delivery.bytes())
                    .expect("capacity preflight makes TCP enqueue infallible");
                assert_eq!(sent, delivery.bytes().len());
            }
            SocketPair::Udp { client, backend } => {
                let (stack, handle, remote) = match delivery.direction() {
                    WindowsPacketFlowDirection::ClientToBackend => (
                        &mut self.client,
                        client,
                        endpoint(self.tuple.destination.address, self.tuple.destination.port),
                    ),
                    WindowsPacketFlowDirection::BackendToClient => (
                        &mut self.backend,
                        backend,
                        endpoint(self.tuple.source.address, self.tuple.source.port),
                    ),
                };
                let socket = stack.sockets.get_mut::<udp::Socket>(handle);
                if !socket.can_send()
                    || socket
                        .send_queue()
                        .checked_add(delivery.bytes().len())
                        .is_none_or(|bytes| bytes > socket.payload_send_capacity())
                {
                    return Err(SelectedStackEffectError::Backpressure);
                }
                socket
                    .send_slice(delivery.bytes(), remote)
                    .expect("capacity and tuple preflight make UDP enqueue infallible");
            }
        }
        Ok(())
    }
}

fn packet_flow_config() -> WindowsPacketFlowConfig {
    WindowsPacketFlowConfig {
        max_active_flows: 8,
        max_retained_terminal_flows: 2,
        max_retained_flow_identities: 16,
        max_chunk_bytes: MAX_EFFECT_PAYLOAD_BYTES,
        max_queued_frames_per_direction: 4,
        high_watermark_bytes: 1_024,
        low_watermark_bytes: 256,
        max_buffered_bytes: 2_048,
        idle_timeout_ms: 5_000,
        backpressure_timeout_ms: 500,
    }
}

struct OwnedFixture {
    owner: WindowsUserspaceByteOwner,
    state: WindowsPacketFlowRegistry,
    key: WindowsPacketFlowKey,
    tuple: WindowsUserspaceFlowTuple,
}

fn opened_fixture_for(
    ipv6: bool,
    transport: WindowsPacketCaptureTransport,
    flow_id: u64,
) -> OwnedFixture {
    let (source_address, destination) = if ipv6 {
        (
            "fd00::2".parse().expect("fixed IPv6 source"),
            "2606:4700::6810:3a05",
        )
    } else {
        (
            "10.254.0.2".parse().expect("fixed IPv4 source"),
            "104.16.58.5",
        )
    };
    let classification_fixture = ClassificationFixture {
        capture_generation: 7,
        flow_id,
        transport,
        source_address,
        source_port: 55_041,
        destination: destination.to_owned(),
        destination_port: 443,
        host: "discord.com".to_owned(),
        expires_at_ms: 5_000,
    };
    let admission_fixture = AdmissionFixture {
        capture_generation: 7,
        flow_id,
        transport,
        destination: destination.to_owned(),
        destination_port: 443,
        host: "discord.com".to_owned(),
        backend: WindowsDataPlaneBackend::LocalEngine,
    };
    let policy = bundled_policy_v1();
    let classification = classification(&classification_fixture, &policy);
    let admission = admission(&admission_fixture, &policy);
    let binding =
        bind_windows_userspace_flow(&classification, &admission, 1_300).expect("exact binding");
    let key = binding.key();
    let tuple = binding.tuple();
    let open_event = flow_open_event(admission, 1_300, &policy);
    let config = packet_flow_config();
    let previous = WindowsPacketFlowRegistry::new(1_200);
    let opened = reduce_windows_packet_flow(previous.clone(), &open_event, &config)
        .expect("packet flow opens");
    let owner_config =
        WindowsUserspaceByteOwnerConfig::from_packet_flow(&config).expect("owner bounds");
    let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
    owner
        .open_flow(binding, &open_event, &previous, &opened, &config)
        .expect("byte owner opens");
    let backend_ready_event = WindowsPacketFlowEvent::BackendReady { now_ms: 1_350, key };
    let backend_ready =
        reduce_windows_packet_flow(opened.state.clone(), &backend_ready_event, &config)
            .expect("backend becomes ready");
    owner
        .reconcile(&backend_ready_event, &opened.state, &backend_ready, &config)
        .expect("owner accepts backend readiness");
    OwnedFixture {
        owner,
        state: backend_ready.state,
        key,
        tuple,
    }
}

fn deliver(
    fixture: &mut OwnedFixture,
    effect: &mut SelectedStackEffect,
    direction: WindowsPacketFlowDirection,
    sequence: u64,
    payload: &[u8],
    now_ms: u64,
    inject_failure: bool,
) {
    let config = packet_flow_config();
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms,
        key: fixture.key,
        direction,
        sequence,
        bytes: payload.len(),
    };
    let staged = reduce_windows_packet_flow(fixture.state.clone(), &payload_event, &config)
        .expect("payload transition");
    fixture
        .owner
        .stage_payload(
            &payload_event,
            &fixture.state,
            &staged,
            &config,
            payload.to_vec(),
        )
        .expect("payload ownership");
    let forward = staged
        .commands
        .iter()
        .find(|command| matches!(command, WindowsPacketFlowCommand::Forward { .. }))
        .expect("ready payload must authorize forwarding")
        .clone();

    if inject_failure {
        let before = effect.visible_state();
        effect.fail_next();
        let error = fixture
            .owner
            .execute_forward(&forward, &staged.state, &config, effect, now_ms + 1)
            .expect_err("injected effect failure must remain visible");
        assert_eq!(error.code, WindowsUserspaceByteOwnerErrorCode::EffectFailed);
        assert_eq!(effect.visible_state(), before);
        assert_eq!(fixture.owner.owned_frame_count(), 1);
        assert_eq!(fixture.owner.owned_byte_count(), payload.len());
    }

    let acknowledgement = fixture
        .owner
        .execute_forward(&forward, &staged.state, &config, effect, now_ms + 2)
        .expect("selected-stack enqueue");
    effect.receive_exact(direction, payload);
    let committed = reduce_windows_packet_flow(staged.state, &acknowledgement, &config)
        .expect("forward acknowledgement");
    fixture.state = committed.state;
    assert_eq!(fixture.owner.owned_frame_count(), 0);
    assert_eq!(fixture.owner.owned_byte_count(), 0);
}

fn qualify(ipv6: bool, transport: WindowsPacketCaptureTransport) {
    let mut fixture = opened_fixture_for(ipv6, transport, 41);
    let mut effect = SelectedStackEffect::new(fixture.key, fixture.tuple);
    deliver(
        &mut fixture,
        &mut effect,
        WindowsPacketFlowDirection::ClientToBackend,
        1,
        b"client-to-backend",
        1_400,
        true,
    );
    deliver(
        &mut fixture,
        &mut effect,
        WindowsPacketFlowDirection::BackendToClient,
        1,
        b"backend-to-client",
        1_500,
        false,
    );
}

#[test]
fn ipv4_tcp_byte_owner_reaches_the_selected_stack_in_both_directions() {
    qualify(false, WindowsPacketCaptureTransport::TcpTls);
}

#[test]
fn ipv6_tcp_byte_owner_reaches_the_selected_stack_in_both_directions() {
    qualify(true, WindowsPacketCaptureTransport::TcpTls);
}

#[test]
fn ipv4_udp_byte_owner_reaches_the_selected_stack_in_both_directions() {
    qualify(false, WindowsPacketCaptureTransport::UdpQuic);
}

#[test]
fn ipv6_udp_byte_owner_reaches_the_selected_stack_in_both_directions() {
    qualify(true, WindowsPacketCaptureTransport::UdpQuic);
}

#[test]
fn same_tuple_from_another_flow_is_rejected_before_stack_mutation() {
    let reference = opened_fixture_for(false, WindowsPacketCaptureTransport::TcpTls, 41);
    let mut foreign = opened_fixture_for(false, WindowsPacketCaptureTransport::TcpTls, 42);
    assert_eq!(foreign.tuple, reference.tuple);
    assert_ne!(foreign.key, reference.key);
    let mut effect = SelectedStackEffect::new(reference.key, reference.tuple);
    let config = packet_flow_config();
    let payload = b"foreign-flow";
    let event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_400,
        key: foreign.key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 1,
        bytes: payload.len(),
    };
    let staged = reduce_windows_packet_flow(foreign.state.clone(), &event, &config)
        .expect("foreign payload transition");
    foreign
        .owner
        .stage_payload(&event, &foreign.state, &staged, &config, payload.to_vec())
        .expect("foreign payload ownership");
    let forward = staged
        .commands
        .iter()
        .find(|command| matches!(command, WindowsPacketFlowCommand::Forward { .. }))
        .expect("foreign forward command");
    let before = effect.visible_state();

    let error = foreign
        .owner
        .execute_forward(forward, &staged.state, &config, &mut effect, 1_401)
        .expect_err("same tuple cannot substitute another flow identity");
    assert_eq!(error.code, WindowsUserspaceByteOwnerErrorCode::EffectFailed);
    assert_eq!(effect.visible_state(), before);
    assert_eq!(foreign.owner.owned_frame_count(), 1);
    assert_eq!(foreign.owner.owned_byte_count(), payload.len());
}

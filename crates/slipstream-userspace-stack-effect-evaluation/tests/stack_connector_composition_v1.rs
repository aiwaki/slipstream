mod selected_stack_support {
    use slipstream_core::routing_policy::RoutingPolicyTables;
    use slipstream_windows_adapter::packet_adapter::v4::WindowsPacketPolicyClassification;
    use slipstream_windows_adapter::packet_flow::WindowsPacketFlowAdmission;

    include!("selected_stack_effect_v1.rs");

    pub(crate) fn composition_classification(
        capture_generation: u64,
        flow_id: u64,
        transport: WindowsPacketCaptureTransport,
        source_address: IpAddr,
        destination: &str,
        host: &str,
        policy: &RoutingPolicyTables,
    ) -> WindowsPacketPolicyClassification {
        classification(
            &ClassificationFixture {
                capture_generation,
                flow_id,
                transport,
                source_address,
                source_port: 55_041,
                destination: destination.to_owned(),
                destination_port: 443,
                host: host.to_owned(),
                expires_at_ms: 5_000,
            },
            policy,
        )
    }

    pub(crate) fn composition_admission(
        capture_generation: u64,
        flow_id: u64,
        transport: WindowsPacketCaptureTransport,
        destination: &str,
        host: &str,
        backend: WindowsDataPlaneBackend,
        policy: &RoutingPolicyTables,
    ) -> WindowsPacketFlowAdmission {
        admission(
            &AdmissionFixture {
                capture_generation,
                flow_id,
                transport,
                destination: destination.to_owned(),
                destination_port: 443,
                host: host.to_owned(),
                backend,
            },
            policy,
        )
    }

    pub(crate) fn composition_flow_open_event(
        admission: WindowsPacketFlowAdmission,
        now_ms: u64,
        policy: &RoutingPolicyTables,
    ) -> WindowsPacketFlowEvent {
        flow_open_event(admission, now_ms, policy)
    }

    pub(crate) struct CompositionStack(SelectedStackEffect);

    impl CompositionStack {
        pub(crate) fn new(key: WindowsPacketFlowKey, tuple: WindowsUserspaceFlowTuple) -> Self {
            Self(SelectedStackEffect::new(key, tuple))
        }

        pub(crate) fn forward_delivery(
            &mut self,
            delivery: &WindowsUserspaceByteDelivery<'_>,
        ) -> Result<(), String> {
            WindowsUserspaceByteEffects::forward(&mut self.0, delivery)
                .map_err(|error| error.to_string())
        }

        pub(crate) fn inject_backend(
            &mut self,
            key: WindowsPacketFlowKey,
            tuple: WindowsUserspaceFlowTuple,
            bytes: &[u8],
        ) -> Result<(), String> {
            if key != self.0.key || tuple != self.0.tuple {
                return Err(SelectedStackEffectError::TupleMismatch.to_string());
            }
            if bytes.len() > MAX_EFFECT_PAYLOAD_BYTES {
                return Err(SelectedStackEffectError::PayloadTooLarge.to_string());
            }
            if self.0.fail_next {
                self.0.fail_next = false;
                return Err(SelectedStackEffectError::InjectedBeforeMutation.to_string());
            }

            match self.0.sockets {
                SocketPair::Tcp { backend, .. } => {
                    let socket = self.0.backend.sockets.get_mut::<tcp::Socket>(backend);
                    if !socket.can_send()
                        || socket
                            .send_queue()
                            .checked_add(bytes.len())
                            .is_none_or(|queued| queued > socket.send_capacity())
                    {
                        return Err(SelectedStackEffectError::Backpressure.to_string());
                    }
                    let sent = socket
                        .send_slice(bytes)
                        .expect("capacity preflight makes TCP enqueue infallible");
                    assert_eq!(sent, bytes.len());
                }
                SocketPair::Udp { backend, .. } => {
                    let socket = self.0.backend.sockets.get_mut::<udp::Socket>(backend);
                    if !socket.can_send()
                        || socket
                            .send_queue()
                            .checked_add(bytes.len())
                            .is_none_or(|queued| queued > socket.payload_send_capacity())
                    {
                        return Err(SelectedStackEffectError::Backpressure.to_string());
                    }
                    socket
                        .send_slice(
                            bytes,
                            endpoint(self.0.tuple.source.address, self.0.tuple.source.port),
                        )
                        .expect("capacity and tuple preflight make UDP enqueue infallible");
                }
            }
            Ok(())
        }

        pub(crate) fn fail_next(&mut self) {
            self.0.fail_next();
        }

        pub(crate) fn visible_state(&self) -> (usize, usize, usize, usize) {
            let state = self.0.visible_state();
            (
                state.link_to_client,
                state.link_to_backend,
                state.client_send_bytes,
                state.backend_send_bytes,
            )
        }

        pub(crate) fn receive_exact(
            &mut self,
            direction: WindowsPacketFlowDirection,
            expected: &[u8],
        ) {
            self.0.receive_exact(direction, expected);
        }
    }
}

use selected_stack_support::{
    composition_admission, composition_classification, composition_flow_open_event,
    CompositionStack,
};
use slipstream_core::routing_policy::{bundled_policy_v1, classify_route_policy};
use slipstream_userspace_stack_effect_evaluation::native_connector_v1::{
    route_backend_is_supported, NativeConnectorQueue, NativeConnectorQueueConfig,
    NativeConnectorWriter,
};
use slipstream_userspace_stack_effect_evaluation::stack_connector_composition_v1::{
    NativeBackendReadErrorCode, NativeBackendReadQueue, NativeBackendReadQueueConfig,
    NativeBackendReadResult, NativeConnectorReader, SelectedStackBackendWriter,
};
use slipstream_userspace_stack_effect_evaluation::v1::MAX_EFFECT_PAYLOAD_BYTES;
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
    WindowsUserspaceFlowBinding, WindowsUserspaceFlowTuple,
};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

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
    binding: WindowsUserspaceFlowBinding,
}

fn opened_fixture_for(
    host: &str,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketCaptureTransport,
    flow_id: u64,
    ipv6: bool,
) -> OwnedFixture {
    let (source_address, destination) = if ipv6 {
        (
            "fd00::2".parse::<IpAddr>().expect("fixed IPv6 source"),
            "2606:4700:3030::6810:3a05",
        )
    } else {
        (
            "10.254.0.2".parse::<IpAddr>().expect("fixed IPv4 source"),
            "104.16.58.5",
        )
    };
    let policy = bundled_policy_v1();
    let classification = composition_classification(
        7,
        flow_id,
        transport,
        source_address,
        destination,
        host,
        &policy,
    );
    let admission =
        composition_admission(7, flow_id, transport, destination, host, backend, &policy);
    let binding =
        bind_windows_userspace_flow(&classification, &admission, 1_300).expect("exact binding");
    let key = binding.key();
    let open_event = composition_flow_open_event(admission, 1_300, &policy);
    let config = packet_flow_config();
    let previous = WindowsPacketFlowRegistry::new(1_200);
    let opened = reduce_windows_packet_flow(previous.clone(), &open_event, &config)
        .expect("packet flow opens");
    let owner_config =
        WindowsUserspaceByteOwnerConfig::from_packet_flow(&config).expect("owner bounds");
    let mut owner = WindowsUserspaceByteOwner::new(owner_config).expect("byte owner");
    owner
        .open_flow(binding.clone(), &open_event, &previous, &opened, &config)
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
        binding,
    }
}

#[derive(Debug, Eq, PartialEq)]
enum StackConnectorEffectError {
    UnsupportedDirection,
    PendingConnectorFrame,
    InvalidDelivery,
    BindingExpired,
    UnsupportedRoute,
    SelectedStack(String),
}

impl fmt::Display for StackConnectorEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

struct StackConnectorEffect {
    stack: CompositionStack,
    queue: NativeConnectorQueue,
    key: WindowsPacketFlowKey,
    tuple: WindowsUserspaceFlowTuple,
    now_ms: u64,
}

impl StackConnectorEffect {
    fn new(binding: &WindowsUserspaceFlowBinding, now_ms: u64) -> Self {
        Self {
            stack: CompositionStack::new(binding.key(), binding.tuple()),
            queue: NativeConnectorQueue::new(NativeConnectorQueueConfig::default(), now_ms)
                .expect("bounded connector queue"),
            key: binding.key(),
            tuple: binding.tuple(),
            now_ms,
        }
    }
}

impl WindowsUserspaceByteEffects for StackConnectorEffect {
    type Error = StackConnectorEffectError;

    fn forward(&mut self, delivery: &WindowsUserspaceByteDelivery<'_>) -> Result<(), Self::Error> {
        if delivery.direction() != WindowsPacketFlowDirection::ClientToBackend {
            return Err(StackConnectorEffectError::UnsupportedDirection);
        }
        if self.queue.queued_frames() != 0 {
            return Err(StackConnectorEffectError::PendingConnectorFrame);
        }
        if delivery.key() != self.key
            || delivery.binding().key() != self.key
            || delivery.binding().tuple() != self.tuple
            || delivery.bytes().is_empty()
            || delivery.bytes().len() > MAX_EFFECT_PAYLOAD_BYTES
        {
            return Err(StackConnectorEffectError::InvalidDelivery);
        }
        if self.now_ms >= delivery.binding().expires_at_ms() {
            return Err(StackConnectorEffectError::BindingExpired);
        }
        let request = delivery.binding().admission().request();
        if !route_backend_is_supported(
            &request.policy,
            request.backend,
            delivery.binding().tuple().transport,
        ) {
            return Err(StackConnectorEffectError::UnsupportedRoute);
        }

        self.stack
            .forward_delivery(delivery)
            .map_err(StackConnectorEffectError::SelectedStack)?;
        self.stack
            .receive_exact(delivery.direction(), delivery.bytes());
        WindowsUserspaceByteEffects::forward(&mut self.queue, delivery)
            .expect("composition preflight makes connector handoff infallible");
        Ok(())
    }
}

fn execute_client_forward(
    fixture: &mut OwnedFixture,
    effect: &mut StackConnectorEffect,
    sequence: u64,
    payload: &[u8],
) {
    let config = packet_flow_config();
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_400,
        key: fixture.key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
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
        .expect("ready payload authorizes forwarding")
        .clone();
    let acknowledgement = fixture
        .owner
        .execute_forward(&forward, &staged.state, &config, effect, 1_401)
        .expect("selected-stack-to-connector handoff");
    let committed = reduce_windows_packet_flow(staged.state, &acknowledgement, &config)
        .expect("forward acknowledgement");
    fixture.state = committed.state;

    assert_eq!(fixture.owner.owned_frame_count(), 0);
    assert_eq!(fixture.owner.owned_byte_count(), 0);
    assert_eq!(effect.queue.queued_frames(), 1);
    assert_eq!(effect.queue.queued_bytes(), payload.len());
    assert_eq!(effect.queue.front_key(), Some(fixture.key));
    assert_eq!(effect.queue.front_sequence(), Some(sequence));
}

struct TcpLoopbackWriter {
    stream: TcpStream,
    key: WindowsPacketFlowKey,
    backend: WindowsDataPlaneBackend,
}

impl NativeConnectorWriter for TcpLoopbackWriter {
    type Error = io::Error;

    fn key(&self) -> WindowsPacketFlowKey {
        self.key
    }

    fn backend(&self) -> WindowsDataPlaneBackend {
        self.backend
    }

    fn transport(&self) -> WindowsPacketFlowTransport {
        WindowsPacketFlowTransport::Tcp
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.stream.write(bytes)
    }
}

struct UdpLoopbackWriter {
    socket: UdpSocket,
    key: WindowsPacketFlowKey,
    backend: WindowsDataPlaneBackend,
}

impl NativeConnectorWriter for UdpLoopbackWriter {
    type Error = io::Error;

    fn key(&self) -> WindowsPacketFlowKey {
        self.key
    }

    fn backend(&self) -> WindowsDataPlaneBackend {
        self.backend
    }

    fn transport(&self) -> WindowsPacketFlowTransport {
        WindowsPacketFlowTransport::Udp
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.socket.send(bytes)
    }
}

fn tcp_loopback() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("numeric loopback listener");
    let client = TcpStream::connect(listener.local_addr().expect("listener address"))
        .expect("numeric loopback connect");
    let (server, _) = listener.accept().expect("numeric loopback accept");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client read timeout");
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("server read timeout");
    (client, server)
}

fn qualify_selected_stack_to_connector(
    host: &str,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketCaptureTransport,
    flow_id: u64,
    ipv6: bool,
    payload: &[u8],
) {
    let mut fixture = opened_fixture_for(host, backend, transport, flow_id, ipv6);
    let mut effect = StackConnectorEffect::new(&fixture.binding, 1_300);
    execute_client_forward(&mut fixture, &mut effect, 1, payload);

    match fixture.binding.tuple().transport {
        WindowsPacketFlowTransport::Tcp => {
            let (client, mut server) = tcp_loopback();
            let mut writer = TcpLoopbackWriter {
                stream: client,
                key: fixture.key,
                backend,
            };
            while effect.queue.queued_frames() > 0 {
                effect
                    .queue
                    .flush_front(&mut writer)
                    .expect("flush selected-stack TCP output");
            }
            let mut received = vec![0; payload.len()];
            server
                .read_exact(&mut received)
                .expect("exact TCP connector payload");
            assert_eq!(received, payload);
        }
        WindowsPacketFlowTransport::Udp => {
            let receiver = UdpSocket::bind("127.0.0.1:0").expect("numeric UDP receiver");
            receiver
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("UDP read timeout");
            let sender = UdpSocket::bind("127.0.0.1:0").expect("numeric UDP sender");
            sender
                .connect(receiver.local_addr().expect("receiver address"))
                .expect("connect numeric UDP loopback");
            let mut writer = UdpLoopbackWriter {
                socket: sender,
                key: fixture.key,
                backend,
            };
            effect
                .queue
                .flush_front(&mut writer)
                .expect("flush selected-stack UDP output");
            let mut received = [0; 128];
            let len = receiver.recv(&mut received).expect("exact UDP payload");
            assert_eq!(&received[..len], payload);
        }
    }
    assert_eq!(effect.queue.queued_frames(), 0);
    assert_eq!(effect.queue.queued_bytes(), 0);
}

#[test]
fn selected_stack_output_reaches_exact_native_connector_edges() {
    qualify_selected_stack_to_connector(
        "discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::TcpTls,
        301,
        false,
        b"ipv4-local-tcp",
    );
    qualify_selected_stack_to_connector(
        "discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::UdpQuic,
        302,
        true,
        b"ipv6-local-udp",
    );
    qualify_selected_stack_to_connector(
        "chatgpt.com",
        WindowsDataPlaneBackend::Geph,
        WindowsPacketCaptureTransport::TcpTls,
        303,
        true,
        b"ipv6-geo-tcp",
    );
}

#[test]
fn pending_connector_frame_rejects_the_next_payload_before_stack_mutation() {
    let mut fixture = opened_fixture_for(
        "discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::TcpTls,
        307,
        false,
    );
    let mut effect = StackConnectorEffect::new(&fixture.binding, 1_300);
    let first = b"first-pending-frame";
    execute_client_forward(&mut fixture, &mut effect, 1, first);

    let config = packet_flow_config();
    let second = b"second-owned-frame";
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms: 1_500,
        key: fixture.key,
        direction: WindowsPacketFlowDirection::ClientToBackend,
        sequence: 2,
        bytes: second.len(),
    };
    let staged = reduce_windows_packet_flow(fixture.state.clone(), &payload_event, &config)
        .expect("second payload transition");
    fixture
        .owner
        .stage_payload(
            &payload_event,
            &fixture.state,
            &staged,
            &config,
            second.to_vec(),
        )
        .expect("second payload ownership");
    let forward = staged
        .commands
        .iter()
        .find(|command| matches!(command, WindowsPacketFlowCommand::Forward { .. }))
        .expect("second payload authorizes forwarding");
    let stack_before = effect.stack.visible_state();

    let error = fixture
        .owner
        .execute_forward(forward, &staged.state, &config, &mut effect, 1_501)
        .expect_err("pending connector frame must apply backpressure");

    assert_eq!(error.code, WindowsUserspaceByteOwnerErrorCode::EffectFailed);
    assert_eq!(effect.stack.visible_state(), stack_before);
    assert_eq!(effect.queue.queued_frames(), 1);
    assert_eq!(effect.queue.queued_bytes(), first.len());
    assert_eq!(effect.queue.front_key(), Some(fixture.key));
    assert_eq!(effect.queue.front_sequence(), Some(1));
    assert_eq!(fixture.owner.owned_frame_count(), 1);
    assert_eq!(fixture.owner.owned_byte_count(), second.len());
}

struct TcpLoopbackReader {
    stream: TcpStream,
    key: WindowsPacketFlowKey,
    backend: WindowsDataPlaneBackend,
    expected_len: usize,
    fail_next: bool,
}

impl NativeConnectorReader for TcpLoopbackReader {
    type Error = io::Error;

    fn key(&self) -> WindowsPacketFlowKey {
        self.key
    }

    fn backend(&self) -> WindowsDataPlaneBackend {
        self.backend
    }

    fn transport(&self) -> WindowsPacketFlowTransport {
        WindowsPacketFlowTransport::Tcp
    }

    fn read(&mut self, buffer: &mut [u8]) -> Result<NativeBackendReadResult, Self::Error> {
        if self.fail_next {
            self.fail_next = false;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "injected failure before native read",
            ));
        }
        self.stream.read_exact(&mut buffer[..self.expected_len])?;
        Ok(NativeBackendReadResult {
            bytes_read: self.expected_len,
            datagram_complete: false,
        })
    }
}

struct UdpLoopbackReader {
    socket: UdpSocket,
    key: WindowsPacketFlowKey,
    backend: WindowsDataPlaneBackend,
}

impl NativeConnectorReader for UdpLoopbackReader {
    type Error = io::Error;

    fn key(&self) -> WindowsPacketFlowKey {
        self.key
    }

    fn backend(&self) -> WindowsDataPlaneBackend {
        self.backend
    }

    fn transport(&self) -> WindowsPacketFlowTransport {
        WindowsPacketFlowTransport::Udp
    }

    fn read(&mut self, buffer: &mut [u8]) -> Result<NativeBackendReadResult, Self::Error> {
        let bytes_read = self.socket.recv(buffer)?;
        Ok(NativeBackendReadResult {
            bytes_read,
            datagram_complete: true,
        })
    }
}

struct NeverReadReader {
    key: WindowsPacketFlowKey,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketFlowTransport,
    calls: usize,
}

impl NativeConnectorReader for NeverReadReader {
    type Error = io::Error;

    fn key(&self) -> WindowsPacketFlowKey {
        self.key
    }

    fn backend(&self) -> WindowsDataPlaneBackend {
        self.backend
    }

    fn transport(&self) -> WindowsPacketFlowTransport {
        self.transport
    }

    fn read(&mut self, _buffer: &mut [u8]) -> Result<NativeBackendReadResult, Self::Error> {
        self.calls += 1;
        Err(io::Error::other("identity preflight should prevent read"))
    }
}

struct StackBackendWriter {
    stack: CompositionStack,
    key: WindowsPacketFlowKey,
    tuple: WindowsUserspaceFlowTuple,
    backend: WindowsDataPlaneBackend,
    expected_sequence: u64,
}

impl StackBackendWriter {
    fn new(
        binding: &WindowsUserspaceFlowBinding,
        backend: WindowsDataPlaneBackend,
        expected_sequence: u64,
    ) -> Self {
        Self {
            stack: CompositionStack::new(binding.key(), binding.tuple()),
            key: binding.key(),
            tuple: binding.tuple(),
            backend,
            expected_sequence,
        }
    }

    fn fail_next(&mut self) {
        self.stack.fail_next();
    }

    fn visible_state(&self) -> (usize, usize, usize, usize) {
        self.stack.visible_state()
    }
}

impl SelectedStackBackendWriter for StackBackendWriter {
    type Error = String;

    fn key(&self) -> WindowsPacketFlowKey {
        self.key
    }

    fn backend(&self) -> WindowsDataPlaneBackend {
        self.backend
    }

    fn transport(&self) -> WindowsPacketFlowTransport {
        self.tuple.transport
    }

    fn write(&mut self, sequence: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        assert_eq!(sequence, self.expected_sequence);
        self.stack.inject_backend(self.key, self.tuple, bytes)
    }
}

#[test]
fn backend_tcp_read_is_retained_across_failures_then_reaches_selected_stack_once() {
    let payload = b"backend-to-selected-stack";
    let fixture = opened_fixture_for(
        "chatgpt.com",
        WindowsDataPlaneBackend::Geph,
        WindowsPacketCaptureTransport::TcpTls,
        304,
        false,
    );
    let (reader_stream, mut backend_stream) = tcp_loopback();
    backend_stream
        .write_all(payload)
        .expect("write backend TCP payload");
    let mut reader = TcpLoopbackReader {
        stream: reader_stream,
        key: fixture.key,
        backend: WindowsDataPlaneBackend::Geph,
        expected_len: payload.len(),
        fail_next: true,
    };
    let mut queue = NativeBackendReadQueue::new(NativeBackendReadQueueConfig::default(), 1_300)
        .expect("backend-read queue");

    let error = queue
        .capture_from(&fixture.binding, 7, &mut reader)
        .expect_err("injected native read failure");
    assert_eq!(error.code, NativeBackendReadErrorCode::NativeReadFailed);
    assert_eq!(queue.queued_frames(), 0);
    assert_eq!(queue.queued_bytes(), 0);

    let captured = queue
        .capture_from(&fixture.binding, 7, &mut reader)
        .expect("retry captures exact native bytes");
    assert_eq!(captured, payload.len());
    assert_eq!(queue.front_key(), Some(fixture.key));
    assert_eq!(queue.front_sequence(), Some(7));

    let other_key = opened_fixture_for(
        "chatgpt.com",
        WindowsDataPlaneBackend::Geph,
        WindowsPacketCaptureTransport::TcpTls,
        404,
        false,
    )
    .key;
    let mut writer = StackBackendWriter::new(&fixture.binding, WindowsDataPlaneBackend::Geph, 7);
    writer.key = other_key;
    let error = queue
        .flush_front(&mut writer)
        .expect_err("wrong selected-stack flow");
    assert_eq!(error.code, NativeBackendReadErrorCode::WriterFlowMismatch);
    assert_eq!(queue.queued_bytes(), payload.len());
    writer.key = fixture.key;
    writer.backend = WindowsDataPlaneBackend::LocalEngine;
    let error = queue
        .flush_front(&mut writer)
        .expect_err("wrong selected-stack backend");
    assert_eq!(
        error.code,
        NativeBackendReadErrorCode::WriterBackendMismatch
    );
    assert_eq!(queue.queued_bytes(), payload.len());
    writer.backend = WindowsDataPlaneBackend::Geph;
    writer.tuple.transport = WindowsPacketFlowTransport::Udp;
    let error = queue
        .flush_front(&mut writer)
        .expect_err("wrong selected-stack transport");
    assert_eq!(
        error.code,
        NativeBackendReadErrorCode::WriterTransportMismatch
    );
    assert_eq!(queue.queued_bytes(), payload.len());
    writer.tuple = fixture.binding.tuple();

    writer.fail_next();
    let before = writer.visible_state();
    let error = queue
        .flush_front(&mut writer)
        .expect_err("selected stack fails before mutation");
    assert_eq!(
        error.code,
        NativeBackendReadErrorCode::SelectedStackWriteFailed
    );
    assert_eq!(writer.visible_state(), before);
    assert_eq!(queue.queued_frames(), 1);
    assert_eq!(queue.queued_bytes(), payload.len());

    let progress = queue
        .flush_front(&mut writer)
        .expect("retained backend frame retries once");
    assert_eq!(progress.delivered_bytes, payload.len());
    assert!(progress.frame_complete);
    assert_eq!(queue.queued_frames(), 0);
    writer
        .stack
        .receive_exact(WindowsPacketFlowDirection::BackendToClient, payload);
}

#[test]
fn backend_reader_identity_is_rejected_before_native_bytes_are_consumed() {
    let fixture = opened_fixture_for(
        "chatgpt.com",
        WindowsDataPlaneBackend::Geph,
        WindowsPacketCaptureTransport::TcpTls,
        306,
        false,
    );
    let other_key = opened_fixture_for(
        "chatgpt.com",
        WindowsDataPlaneBackend::Geph,
        WindowsPacketCaptureTransport::TcpTls,
        406,
        false,
    )
    .key;
    let mut queue = NativeBackendReadQueue::new(NativeBackendReadQueueConfig::default(), 1_300)
        .expect("backend-read queue");
    let mut reader = NeverReadReader {
        key: other_key,
        backend: WindowsDataPlaneBackend::Geph,
        transport: WindowsPacketFlowTransport::Tcp,
        calls: 0,
    };

    let error = queue
        .capture_from(&fixture.binding, 9, &mut reader)
        .expect_err("wrong reader flow");
    assert_eq!(error.code, NativeBackendReadErrorCode::ReaderFlowMismatch);
    reader.key = fixture.key;
    reader.backend = WindowsDataPlaneBackend::LocalEngine;
    let error = queue
        .capture_from(&fixture.binding, 9, &mut reader)
        .expect_err("wrong reader backend");
    assert_eq!(
        error.code,
        NativeBackendReadErrorCode::ReaderBackendMismatch
    );
    reader.backend = WindowsDataPlaneBackend::Geph;
    reader.transport = WindowsPacketFlowTransport::Udp;
    let error = queue
        .capture_from(&fixture.binding, 9, &mut reader)
        .expect_err("wrong reader transport");
    assert_eq!(
        error.code,
        NativeBackendReadErrorCode::ReaderTransportMismatch
    );
    assert_eq!(reader.calls, 0);
    assert_eq!(queue.queued_frames(), 0);
    assert_eq!(queue.queued_bytes(), 0);
}

#[test]
fn backend_udp_datagram_reaches_selected_stack_as_one_exact_frame() {
    let payload = b"backend-udp-datagram";
    let fixture = opened_fixture_for(
        "discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::UdpQuic,
        305,
        true,
    );
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("numeric UDP receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("UDP read timeout");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("numeric UDP sender");
    sender
        .send_to(payload, receiver.local_addr().expect("receiver address"))
        .expect("send backend UDP datagram");
    let mut reader = UdpLoopbackReader {
        socket: receiver,
        key: fixture.key,
        backend: WindowsDataPlaneBackend::LocalEngine,
    };
    let mut queue = NativeBackendReadQueue::new(NativeBackendReadQueueConfig::default(), 1_300)
        .expect("backend-read queue");
    queue
        .capture_from(&fixture.binding, 8, &mut reader)
        .expect("capture exact backend datagram");
    let mut writer =
        StackBackendWriter::new(&fixture.binding, WindowsDataPlaneBackend::LocalEngine, 8);
    queue
        .flush_front(&mut writer)
        .expect("deliver exact backend datagram");
    writer
        .stack
        .receive_exact(WindowsPacketFlowDirection::BackendToClient, payload);
    assert_eq!(queue.queued_frames(), 0);
    assert_eq!(queue.queued_bytes(), 0);
}

#[test]
fn composition_keeps_discord_and_youtube_out_of_geph() {
    let policy = bundled_policy_v1();
    for host in ["discord.com", "gateway.discord.gg", "googlevideo.com"] {
        let route = classify_route_policy(host, &policy);
        assert!(!route_backend_is_supported(
            &route,
            WindowsDataPlaneBackend::Geph,
            WindowsPacketFlowTransport::Tcp,
        ));
    }
}

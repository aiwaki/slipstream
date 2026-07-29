#[path = "../../slipstream-windows-adapter/tests/support/userspace_fixture.rs"]
mod userspace_fixture;

use slipstream_core::routing_policy::{bundled_policy_v1, classify_route_policy};
use slipstream_userspace_stack_effect_evaluation::native_connector_v1::{
    route_backend_is_supported, NativeConnectorErrorCode, NativeConnectorQueue,
    NativeConnectorQueueConfig, NativeConnectorWriter,
};
use slipstream_windows_adapter::data_plane::WindowsDataPlaneBackend;
use slipstream_windows_adapter::packet_adapter::v4::WindowsPacketCaptureTransport;
use slipstream_windows_adapter::packet_flow::{
    reduce_windows_packet_flow, WindowsPacketFlowCommand, WindowsPacketFlowConfig,
    WindowsPacketFlowDirection, WindowsPacketFlowEvent, WindowsPacketFlowKey,
    WindowsPacketFlowRegistry, WindowsPacketFlowTransport,
};
use slipstream_windows_adapter::userspace_stack_bridge::{
    bind_windows_userspace_flow, WindowsUserspaceByteOwner, WindowsUserspaceByteOwnerConfig,
    WindowsUserspaceByteOwnerErrorCode,
};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::Duration;
use userspace_fixture::{
    admission, classification, flow_open_event, AdmissionFixture, ClassificationFixture,
};

fn packet_flow_config() -> WindowsPacketFlowConfig {
    WindowsPacketFlowConfig {
        max_active_flows: 8,
        max_retained_terminal_flows: 2,
        max_retained_flow_identities: 16,
        max_chunk_bytes: 512,
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
}

fn opened_fixture_for(
    host: &str,
    backend: WindowsDataPlaneBackend,
    transport: WindowsPacketCaptureTransport,
    flow_id: u64,
) -> OwnedFixture {
    let destination = "104.16.58.5";
    let classification_fixture = ClassificationFixture {
        capture_generation: 7,
        flow_id,
        transport,
        source_address: "10.254.0.2".parse().expect("fixed IPv4 source"),
        source_port: 55_041,
        destination: destination.to_owned(),
        destination_port: 443,
        host: host.to_owned(),
        expires_at_ms: 5_000,
    };
    let admission_fixture = AdmissionFixture {
        capture_generation: 7,
        flow_id,
        transport,
        destination: destination.to_owned(),
        destination_port: 443,
        host: host.to_owned(),
        backend,
    };
    let policy = bundled_policy_v1();
    let classification = classification(&classification_fixture, &policy);
    let admission = admission(&admission_fixture, &policy);
    let binding =
        bind_windows_userspace_flow(&classification, &admission, 1_300).expect("exact binding");
    let key = binding.key();
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
    }
}

fn handoff(
    fixture: &mut OwnedFixture,
    queue: &mut NativeConnectorQueue,
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

    queue.advance_to(1_401).expect("monotonic queue clock");
    let acknowledgement = fixture
        .owner
        .execute_forward(&forward, &staged.state, &config, queue, 1_401)
        .expect("atomic connector queue handoff");
    let committed = reduce_windows_packet_flow(staged.state, &acknowledgement, &config)
        .expect("forward acknowledgement");
    fixture.state = committed.state;

    assert_eq!(fixture.owner.owned_frame_count(), 0);
    assert_eq!(fixture.owner.owned_byte_count(), 0);
    assert_eq!(queue.queued_frames(), 1);
    assert_eq!(queue.queued_bytes(), payload.len());
    assert_eq!(queue.front_key(), Some(fixture.key));
    assert_eq!(queue.front_sequence(), Some(sequence));
}

fn stage_forward(
    fixture: &mut OwnedFixture,
    sequence: u64,
    payload: &[u8],
    now_ms: u64,
) -> (
    slipstream_windows_adapter::packet_flow::WindowsPacketFlowTransition,
    WindowsPacketFlowCommand,
) {
    let config = packet_flow_config();
    let payload_event = WindowsPacketFlowEvent::Payload {
        now_ms,
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
    (staged, forward)
}

struct TcpLoopbackWriter {
    stream: TcpStream,
    key: WindowsPacketFlowKey,
    backend: WindowsDataPlaneBackend,
    max_chunk: usize,
    fail_next: bool,
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
        if self.fail_next {
            self.fail_next = false;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "injected failure before progress",
            ));
        }
        let chunk = bytes.len().min(self.max_chunk);
        self.stream.write(&bytes[..chunk])
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
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    (client, server)
}

#[test]
fn tcp_failure_retains_the_frame_and_partial_writes_commit_the_exact_suffix() {
    let payload = b"connector-owned-tcp-payload";
    let mut fixture = opened_fixture_for(
        "discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::TcpTls,
        41,
    );
    let mut queue =
        NativeConnectorQueue::new(NativeConnectorQueueConfig::default(), 1_300).expect("queue");
    handoff(&mut fixture, &mut queue, 1, payload);
    let (client, mut server) = tcp_loopback();
    let mut writer = TcpLoopbackWriter {
        stream: client,
        key: fixture.key,
        backend: WindowsDataPlaneBackend::LocalEngine,
        max_chunk: 3,
        fail_next: true,
    };

    let error = queue
        .flush_front(&mut writer)
        .expect_err("injected write failure");
    assert_eq!(error.code, NativeConnectorErrorCode::NativeWriteFailed);
    assert_eq!(queue.queued_frames(), 1);
    assert_eq!(queue.queued_bytes(), payload.len());
    assert_eq!(queue.front_remaining_bytes(), payload.len());

    let first = queue.flush_front(&mut writer).expect("first TCP prefix");
    assert_eq!(first.committed_bytes, 3);
    assert_eq!(first.remaining_bytes, payload.len() - 3);
    assert!(!first.frame_complete);
    while queue.queued_frames() > 0 {
        queue
            .flush_front(&mut writer)
            .expect("remaining TCP suffix");
    }

    let mut received = vec![0; payload.len()];
    server.read_exact(&mut received).expect("exact TCP payload");
    assert_eq!(received, payload);
    assert_eq!(queue.queued_bytes(), 0);
}

#[test]
fn udp_handoff_commits_one_exact_datagram() {
    let payload = b"connector-owned-udp-datagram";
    let mut fixture = opened_fixture_for(
        "discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::UdpQuic,
        42,
    );
    let mut queue =
        NativeConnectorQueue::new(NativeConnectorQueueConfig::default(), 1_300).expect("queue");
    handoff(&mut fixture, &mut queue, 1, payload);

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("numeric loopback receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("numeric loopback sender");
    sender
        .connect(receiver.local_addr().expect("receiver address"))
        .expect("connect numeric loopback datagram");
    let mut writer = UdpLoopbackWriter {
        socket: sender,
        key: fixture.key,
        backend: WindowsDataPlaneBackend::LocalEngine,
    };

    let progress = queue.flush_front(&mut writer).expect("exact UDP datagram");
    assert_eq!(progress.committed_bytes, payload.len());
    assert_eq!(progress.remaining_bytes, 0);
    assert!(progress.frame_complete);
    let mut received = [0; 128];
    let received_len = receiver.recv(&mut received).expect("receive UDP datagram");
    assert_eq!(&received[..received_len], payload);
    assert_eq!(queue.queued_frames(), 0);
    assert_eq!(queue.queued_bytes(), 0);
}

#[test]
fn queued_backend_identity_is_revalidated_before_native_write() {
    let payload = b"geo-exit-loopback";
    let mut fixture = opened_fixture_for(
        "chatgpt.com",
        WindowsDataPlaneBackend::Geph,
        WindowsPacketCaptureTransport::TcpTls,
        43,
    );
    let mut queue =
        NativeConnectorQueue::new(NativeConnectorQueueConfig::default(), 1_300).expect("queue");
    handoff(&mut fixture, &mut queue, 1, payload);
    let (client, mut server) = tcp_loopback();
    let other_key = opened_fixture_for(
        "chatgpt.com",
        WindowsDataPlaneBackend::Geph,
        WindowsPacketCaptureTransport::TcpTls,
        143,
    )
    .key;
    let mut wrong_flow_writer = TcpLoopbackWriter {
        stream: client.try_clone().expect("clone loopback stream"),
        key: other_key,
        backend: WindowsDataPlaneBackend::Geph,
        max_chunk: payload.len(),
        fail_next: false,
    };
    let error = queue
        .flush_front(&mut wrong_flow_writer)
        .expect_err("wrong flow must not receive payload");
    assert_eq!(error.code, NativeConnectorErrorCode::WriterFlowMismatch);
    assert_eq!(queue.queued_bytes(), payload.len());

    let mut wrong_writer = TcpLoopbackWriter {
        stream: client.try_clone().expect("clone loopback stream"),
        key: fixture.key,
        backend: WindowsDataPlaneBackend::LocalEngine,
        max_chunk: payload.len(),
        fail_next: false,
    };

    let error = queue
        .flush_front(&mut wrong_writer)
        .expect_err("wrong backend must not receive payload");
    assert_eq!(error.code, NativeConnectorErrorCode::WriterBackendMismatch);
    assert_eq!(queue.queued_bytes(), payload.len());

    let mut geph_writer = TcpLoopbackWriter {
        stream: client,
        key: fixture.key,
        backend: WindowsDataPlaneBackend::Geph,
        max_chunk: payload.len(),
        fail_next: false,
    };
    queue
        .flush_front(&mut geph_writer)
        .expect("matching geo-exit writer");
    let mut received = vec![0; payload.len()];
    server
        .read_exact(&mut received)
        .expect("exact geo-exit loopback payload");
    assert_eq!(received, payload);
}

#[test]
fn policy_edges_reject_geph_for_local_bypass_and_udp() {
    let policy = bundled_policy_v1();
    let discord = classify_route_policy("discord.com", &policy);
    let youtube = classify_route_policy("r1---sn.example.googlevideo.com", &policy);
    let chatgpt = classify_route_policy("chatgpt.com", &policy);
    let google = classify_route_policy("www.google.com", &policy);

    assert!(route_backend_is_supported(
        &discord,
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketFlowTransport::Tcp
    ));
    assert!(!route_backend_is_supported(
        &discord,
        WindowsDataPlaneBackend::Geph,
        WindowsPacketFlowTransport::Tcp
    ));
    assert!(!route_backend_is_supported(
        &youtube,
        WindowsDataPlaneBackend::Geph,
        WindowsPacketFlowTransport::Tcp
    ));
    assert!(route_backend_is_supported(
        &chatgpt,
        WindowsDataPlaneBackend::Geph,
        WindowsPacketFlowTransport::Tcp
    ));
    assert!(!route_backend_is_supported(
        &chatgpt,
        WindowsDataPlaneBackend::Geph,
        WindowsPacketFlowTransport::Udp
    ));
    assert!(!route_backend_is_supported(
        &google,
        WindowsDataPlaneBackend::Direct,
        WindowsPacketFlowTransport::Tcp
    ));
}

#[test]
fn queue_rejection_keeps_the_second_frame_owned_and_unmodified() {
    let first = b"first";
    let second = b"second";
    let mut fixture = opened_fixture_for(
        "discord.com",
        WindowsDataPlaneBackend::LocalEngine,
        WindowsPacketCaptureTransport::TcpTls,
        44,
    );
    let config = NativeConnectorQueueConfig {
        max_queued_frames: 1,
        max_queued_bytes: 64,
        max_frame_bytes: 32,
    };
    let mut queue = NativeConnectorQueue::new(config, 1_300).expect("bounded queue");
    handoff(&mut fixture, &mut queue, 1, first);

    let packet_flow_config = packet_flow_config();
    let (staged, forward) = stage_forward(&mut fixture, 2, second, 1_500);
    queue.advance_to(1_501).expect("monotonic queue clock");
    let error = fixture
        .owner
        .execute_forward(
            &forward,
            &staged.state,
            &packet_flow_config,
            &mut queue,
            1_501,
        )
        .expect_err("full connector queue must reject the handoff");

    assert_eq!(error.code, WindowsUserspaceByteOwnerErrorCode::EffectFailed);
    assert_eq!(queue.queued_frames(), 1);
    assert_eq!(queue.queued_bytes(), first.len());
    assert_eq!(queue.front_sequence(), Some(1));
    assert_eq!(fixture.owner.owned_frame_count(), 1);
    assert_eq!(fixture.owner.owned_byte_count(), second.len());
}

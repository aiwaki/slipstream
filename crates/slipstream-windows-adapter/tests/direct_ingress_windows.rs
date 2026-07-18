use slipstream_core::routing_policy::{
    bundled_policy_v1, classify_route_policy, RoutingPolicyTables,
};
use slipstream_windows_adapter::data_plane::{
    execute_windows_data_plane_transition, reduce_windows_data_plane, WindowsDataPlaneBackend,
    WindowsDataPlaneConfig, WindowsDataPlaneEvent, WindowsDataPlaneRequest,
    WindowsDataPlaneSessionPhase, WindowsDataPlaneState, WindowsDataPlaneWorkerPhase,
};
use slipstream_windows_adapter::direct_connector::{
    WindowsDirectConnectorEndpoint, WindowsDirectConnectorRequest,
};
use slipstream_windows_adapter::direct_ingress::{
    prepare_windows_direct_ingress, windows_direct_ingress_data_plane_event,
    WindowsDirectIngressDataPlaneEffects, WindowsDirectIngressEndpointEvidence,
    WindowsDirectIngressEndpointEvidenceSource, WindowsDirectIngressEvent,
    WindowsDirectIngressRequest, WindowsDirectOwnedClientStream,
};
use socket2::SockRef;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const NATIVE_INGRESS_CI_ENV: &str = "SLIPSTREAM_WINDOWS_DIRECT_INGRESS_CI";
const EVENT_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn native_direct_ingress_loopback_contract_is_bounded_and_owned() {
    if std::env::var_os(NATIVE_INGRESS_CI_ENV).is_none() {
        return;
    }

    qualifies_bidirectional_backpressure_and_clean_close();
    qualifies_upstream_backpressure_deadline();
    qualifies_downstream_backpressure_deadline();
    qualifies_client_close_cancellation();
    qualifies_backend_reset_after_delivered_payload();
    qualifies_caller_cancellation();
    qualifies_first_payload_deadline();
    qualifies_shutdown();
}

fn qualifies_upstream_backpressure_deadline() {
    let backend_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind stalled backend");
    let endpoint = backend_listener
        .local_addr()
        .expect("stalled backend endpoint");
    let backend = thread::spawn(move || {
        let (_stream, _) = backend_listener.accept().expect("accept stalled backend");
        thread::sleep(Duration::from_millis(700));
    });
    let mut running = RunningIngress::start(endpoint, "upstream-stall", 5_000, 100);
    let mut external = running.take_external();
    let writer = thread::spawn(move || {
        let payload = patterned_bytes(32 * 1024 * 1024, 51);
        let _ = external.write_all(&payload);
    });

    let connected = running.next_event();
    assert!(matches!(
        connected,
        WindowsDirectIngressEvent::Connected { .. }
    ));
    running.apply_ingress(connected, 10);
    let reset = running.next_event();
    assert!(matches!(
        &reset,
        WindowsDirectIngressEvent::BackendReset { reason, .. }
            if reason == "backend write backpressure deadline exceeded"
    ));
    running.apply_ingress(reset, 120);
    let outcome = running
        .effects
        .outcomes()
        .next()
        .expect("upstream backpressure outcome");
    assert!(!outcome.ok);
    assert_eq!(outcome.failure_phase, "first_payload");
    writer.join().expect("join stalled client writer");
    backend.join().expect("join stalled backend");
}

fn qualifies_downstream_backpressure_deadline() {
    let backend_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind burst backend");
    let endpoint = backend_listener
        .local_addr()
        .expect("burst backend endpoint");
    let backend = thread::spawn(move || {
        let (mut stream, _) = backend_listener.accept().expect("accept burst backend");
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("bound burst backend write");
        let payload = patterned_bytes(32 * 1024 * 1024, 71);
        let _ = stream.write_all(&payload);
    });
    let mut running = RunningIngress::start(endpoint, "downstream-stall", 5_000, 100);
    let mut now_ms = 10;
    loop {
        let event = running.next_event();
        match &event {
            WindowsDirectIngressEvent::Connected { .. }
            | WindowsDirectIngressEvent::PayloadDelivered { .. } => {
                running.apply_ingress(event, now_ms);
            }
            WindowsDirectIngressEvent::ClientClosed { reason, .. } => {
                assert_eq!(
                    *reason,
                    slipstream_windows_adapter::direct_ingress::WindowsDirectIngressClientCloseReason::WriteBackpressureDeadline
                );
                running.apply_ingress(event, now_ms);
                break;
            }
            event => panic!("unexpected downstream stall event: {event:?}"),
        }
        now_ms += 1;
    }
    let cancelled = running.next_event();
    assert!(matches!(
        cancelled,
        WindowsDirectIngressEvent::Cancelled { .. }
    ));
    running.apply_ingress(cancelled, now_ms + 1);
    assert_eq!(
        running.state.sessions["downstream-stall"].phase,
        WindowsDataPlaneSessionPhase::Cancelled
    );
    assert_eq!(running.effects.outcomes().count(), 0);
    backend.join().expect("join burst backend");
}

fn qualifies_bidirectional_backpressure_and_clean_close() {
    let backend_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind backend");
    let endpoint = backend_listener.local_addr().expect("backend endpoint");
    let request_payload = patterned_bytes(10 * 1024 * 1024, 17);
    let response_payload = patterned_bytes(10 * 1024 * 1024, 93);
    let expected_request = request_payload.clone();
    let server_response = response_payload.clone();
    let backend = thread::spawn(move || {
        let (mut stream, _) = backend_listener.accept().expect("accept backend relay");
        thread::sleep(Duration::from_millis(150));
        let mut request = vec![0u8; expected_request.len()];
        stream
            .read_exact(&mut request)
            .expect("read relayed request");
        assert_eq!(request, expected_request);
        stream
            .write_all(&server_response)
            .expect("write relayed response");
        stream.shutdown(Shutdown::Write).expect("close response");
    });

    let mut running = RunningIngress::start(endpoint, "backpressure", 10_000, 2_000);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(0);
    let expected_response = response_payload.clone();
    let external = running.take_external();
    let client = thread::spawn(move || {
        let mut stream = external;
        stream
            .write_all(&request_payload)
            .expect("write large client request");
        thread::sleep(Duration::from_millis(150));
        let mut response = vec![0u8; expected_response.len()];
        stream
            .read_exact(&mut response)
            .expect("read large client response");
        assert_eq!(response, expected_response);
        release_rx.recv().expect("wait for backend close");
    });

    let mut delivered = 0u64;
    let mut now_ms = 10;
    loop {
        let event = running.next_event();
        match &event {
            WindowsDirectIngressEvent::Connected { .. } => {}
            WindowsDirectIngressEvent::PayloadDelivered { bytes, .. } => delivered += bytes,
            WindowsDirectIngressEvent::BackendClosed { .. } => {
                running.apply_ingress(event, now_ms);
                release_tx.send(()).expect("release client after close");
                break;
            }
            event => panic!("unexpected backpressure ingress event: {event:?}"),
        }
        running.apply_ingress(event, now_ms);
        now_ms += 1;
    }

    assert_eq!(delivered, response_payload.len() as u64);
    let session = running
        .state
        .sessions
        .get("backpressure")
        .expect("retained terminal session");
    assert_eq!(session.phase, WindowsDataPlaneSessionPhase::Succeeded);
    assert_eq!(session.bytes_received, response_payload.len() as u64);
    let outcomes: Vec<_> = running.effects.outcomes().collect();
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].ok);
    assert!(!running.effects.has_relay(1));
    client.join().expect("join client");
    backend.join().expect("join backend");
}

fn qualifies_client_close_cancellation() {
    let backend_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind idle backend");
    let endpoint = backend_listener.local_addr().expect("idle endpoint");
    let backend = thread::spawn(move || {
        let (_stream, _) = backend_listener.accept().expect("accept idle backend");
        thread::sleep(Duration::from_millis(400));
    });
    let mut running = RunningIngress::start(endpoint, "client-close", 2_000, 500);
    let connected = running.next_event();
    assert!(matches!(
        connected,
        WindowsDirectIngressEvent::Connected { .. }
    ));
    running.apply_ingress(connected, 10);
    drop(running.take_external());

    let closed = running.next_event();
    assert!(matches!(
        closed,
        WindowsDirectIngressEvent::ClientClosed { .. }
    ));
    running.apply_ingress(closed, 20);
    let cancelled = running.next_event();
    assert!(matches!(
        cancelled,
        WindowsDirectIngressEvent::Cancelled { .. }
    ));
    running.apply_ingress(cancelled, 30);
    assert_eq!(
        running.state.sessions["client-close"].phase,
        WindowsDataPlaneSessionPhase::Cancelled
    );
    assert_eq!(running.effects.outcomes().count(), 0);
    backend.join().expect("join idle backend");
}

fn qualifies_backend_reset_after_delivered_payload() {
    let backend_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind reset backend");
    let endpoint = backend_listener.local_addr().expect("reset endpoint");
    let backend = thread::spawn(move || {
        let (mut stream, _) = backend_listener.accept().expect("accept reset backend");
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).expect("read reset request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"ok").expect("write before reset");
        thread::sleep(Duration::from_millis(75));
        SockRef::from(&stream)
            .set_linger(Some(Duration::ZERO))
            .expect("force reset");
    });
    let mut running = RunningIngress::start(endpoint, "reset", 2_000, 500);
    running
        .external_mut()
        .write_all(b"ping")
        .expect("write reset request");

    let mut now_ms = 10;
    let mut saw_payload = false;
    loop {
        let event = running.next_event();
        match &event {
            WindowsDirectIngressEvent::Connected { .. } => {}
            WindowsDirectIngressEvent::PayloadDelivered { bytes, .. } => {
                assert_eq!(*bytes, 2);
                let mut response = [0u8; 2];
                running
                    .external_mut()
                    .read_exact(&mut response)
                    .expect("read delivered response");
                assert_eq!(&response, b"ok");
                saw_payload = true;
            }
            WindowsDirectIngressEvent::BackendReset { .. } => {
                running.apply_ingress(event, now_ms);
                break;
            }
            event => panic!("unexpected reset ingress event: {event:?}"),
        }
        running.apply_ingress(event, now_ms);
        now_ms += 10;
    }
    assert!(saw_payload);
    let outcome = running.effects.outcomes().next().expect("reset outcome");
    assert!(!outcome.ok);
    assert_eq!(outcome.failure_phase, "stream");
    assert_eq!(outcome.bytes_received, 2);
    backend.join().expect("join reset backend");
}

fn qualifies_caller_cancellation() {
    let (endpoint, backend) = idle_backend();
    let mut running = RunningIngress::start(endpoint, "cancel", 2_000, 500);
    let connected = running.next_event();
    assert!(matches!(
        connected,
        WindowsDirectIngressEvent::Connected { .. }
    ));
    running.apply_ingress(connected, 10);
    running.apply_data_plane(WindowsDataPlaneEvent::CancelRequested {
        now_ms: 20,
        request_id: "cancel".to_owned(),
        session_id: 1,
    });
    let cancelled = running.next_event();
    assert!(matches!(
        cancelled,
        WindowsDirectIngressEvent::Cancelled { .. }
    ));
    running.apply_ingress(cancelled, 30);
    assert_eq!(
        running.state.sessions["cancel"].phase,
        WindowsDataPlaneSessionPhase::Cancelled
    );
    backend.join().expect("join cancel backend");
}

fn qualifies_first_payload_deadline() {
    let (endpoint, backend) = idle_backend();
    let mut running = RunningIngress::start(endpoint, "deadline", 120, 500);
    let connected = running.next_event();
    running.apply_ingress(connected, 10);
    let deadline = running.next_event();
    assert!(matches!(
        deadline,
        WindowsDirectIngressEvent::FirstPayloadDeadline { .. }
    ));
    running.apply_ingress(deadline, 122);
    let outcome = running.effects.outcomes().next().expect("deadline outcome");
    assert!(!outcome.ok);
    assert_eq!(outcome.failure_phase, "first_payload");
    backend.join().expect("join deadline backend");
}

fn qualifies_shutdown() {
    let (endpoint, backend) = idle_backend();
    let mut running = RunningIngress::start(endpoint, "shutdown", 2_000, 500);
    let connected = running.next_event();
    running.apply_ingress(connected, 10);
    running.apply_data_plane(WindowsDataPlaneEvent::ShutdownRequested { now_ms: 20 });
    let cancelled = running.next_event();
    assert!(matches!(
        cancelled,
        WindowsDirectIngressEvent::Cancelled { .. }
    ));
    running.apply_ingress(cancelled, 30);
    assert_eq!(
        running.state.worker_phase,
        WindowsDataPlaneWorkerPhase::Stopped
    );
    assert!(!running.effects.has_relay(1));
    backend.join().expect("join shutdown backend");
}

fn idle_backend() -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind idle backend");
    let endpoint = listener.local_addr().expect("idle endpoint");
    let backend = thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("accept idle backend");
        thread::sleep(Duration::from_millis(400));
    });
    (endpoint, backend)
}

fn patterned_bytes(length: usize, salt: u8) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

struct RunningIngress {
    state: WindowsDataPlaneState,
    effects: WindowsDirectIngressDataPlaneEffects,
    config: WindowsDataPlaneConfig,
    policy_tables: RoutingPolicyTables,
    external: Option<TcpStream>,
}

impl RunningIngress {
    fn start(
        endpoint: SocketAddr,
        request_id: &str,
        first_payload_timeout_ms: u64,
        backpressure_timeout_ms: u64,
    ) -> Self {
        let client_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind client ingress");
        let external = TcpStream::connect(client_listener.local_addr().unwrap())
            .expect("connect external client");
        external
            .set_read_timeout(Some(EVENT_TIMEOUT))
            .expect("set client read timeout");
        external
            .set_write_timeout(Some(EVENT_TIMEOUT))
            .expect("set client write timeout");
        let (accepted, _) = client_listener.accept().expect("accept owned client");

        let policy_tables = bundled_policy_v1();
        let data_plane_request = WindowsDataPlaneRequest {
            request_id: request_id.to_owned(),
            policy: classify_route_policy("github.com", &policy_tables),
            backend: WindowsDataPlaneBackend::Direct,
            started_at_ms: 2,
            first_payload_deadline_at_ms: 2 + first_payload_timeout_ms,
        };
        let endpoint_model = WindowsDirectConnectorEndpoint {
            address: endpoint.ip().to_string(),
            port: endpoint.port(),
        };
        let ingress_request = WindowsDirectIngressRequest {
            connector_request: WindowsDirectConnectorRequest {
                session_id: 1,
                data_plane_request: data_plane_request.clone(),
                endpoint: endpoint_model.clone(),
                issued_at_ms: 2,
                connect_deadline_at_ms: 2 + first_payload_timeout_ms.min(500),
                initial_payload: Vec::new(),
                max_read_chunk_bytes: 64 * 1024,
            },
            endpoint_evidence: WindowsDirectIngressEndpointEvidence {
                source: WindowsDirectIngressEndpointEvidenceSource::OriginalDestination,
                connection_id: 41,
                request_id: request_id.to_owned(),
                session_id: 1,
                endpoint: endpoint_model,
                observed_at_ms: 2,
                valid_until_ms: 2 + first_payload_timeout_ms,
            },
            max_client_read_chunk_bytes: 64 * 1024,
            backpressure_timeout_ms,
        };
        let plan = prepare_windows_direct_ingress(&ingress_request, &policy_tables)
            .expect("prepare native ingress plan");
        let owned_client = WindowsDirectOwnedClientStream::new(41, accepted)
            .expect("adopt accepted client stream");
        let config = WindowsDataPlaneConfig {
            max_active_sessions: 4,
            max_retained_terminal_sessions: 4,
            cancel_timeout_ms: 500,
            shutdown_timeout_ms: 1_000,
        };
        let mut state = WindowsDataPlaneState::new(0);
        let mut effects = WindowsDirectIngressDataPlaneEffects::default();
        effects
            .stage_ingress(plan, owned_client)
            .expect("stage native ingress");
        apply_data_plane_event(
            &mut state,
            WindowsDataPlaneEvent::WorkerReady { now_ms: 1 },
            &config,
            &policy_tables,
            &mut effects,
        );
        apply_data_plane_event(
            &mut state,
            WindowsDataPlaneEvent::RequestAccepted {
                now_ms: 2,
                request: data_plane_request,
            },
            &config,
            &policy_tables,
            &mut effects,
        );

        Self {
            state,
            effects,
            config,
            policy_tables,
            external: Some(external),
        }
    }

    fn next_event(&self) -> WindowsDirectIngressEvent {
        self.effects
            .recv_event(1, EVENT_TIMEOUT)
            .expect("native ingress event before timeout")
    }

    fn apply_ingress(&mut self, event: WindowsDirectIngressEvent, now_ms: u64) {
        self.apply_data_plane(windows_direct_ingress_data_plane_event(&event, now_ms));
    }

    fn apply_data_plane(&mut self, event: WindowsDataPlaneEvent) {
        apply_data_plane_event(
            &mut self.state,
            event,
            &self.config,
            &self.policy_tables,
            &mut self.effects,
        );
    }

    fn external_mut(&mut self) -> &mut TcpStream {
        self.external.as_mut().expect("external client available")
    }

    fn take_external(&mut self) -> TcpStream {
        self.external.take().expect("external client available")
    }
}

fn apply_data_plane_event(
    state: &mut WindowsDataPlaneState,
    event: WindowsDataPlaneEvent,
    config: &WindowsDataPlaneConfig,
    policy_tables: &RoutingPolicyTables,
    effects: &mut WindowsDirectIngressDataPlaneEffects,
) {
    let transition = reduce_windows_data_plane(state, &event, config, policy_tables)
        .expect("native ingress event satisfies reducer");
    execute_windows_data_plane_transition(&transition, effects)
        .expect("native ingress effect batch completes");
    *state = transition.state;
}

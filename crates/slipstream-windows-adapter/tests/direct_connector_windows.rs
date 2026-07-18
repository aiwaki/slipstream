use slipstream_core::routing_policy::{bundled_policy_v1, classify_route_policy};
use slipstream_windows_adapter::data_plane::{
    execute_windows_data_plane_transition, reduce_windows_data_plane, WindowsDataPlaneBackend,
    WindowsDataPlaneConfig, WindowsDataPlaneEvent, WindowsDataPlaneRequest, WindowsDataPlaneState,
};
use slipstream_windows_adapter::direct_connector::{
    prepare_windows_direct_connector, spawn_windows_direct_connector,
    windows_direct_connector_data_plane_event, WindowsDirectConnectorCancelReason,
    WindowsDirectConnectorEndpoint, WindowsDirectConnectorEvent, WindowsDirectConnectorHandle,
    WindowsDirectConnectorNativeError, WindowsDirectConnectorRequest,
    WindowsDirectDataPlaneEffects,
};
use socket2::SockRef;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

const NATIVE_CONNECTOR_CI_ENV: &str = "SLIPSTREAM_WINDOWS_DIRECT_CONNECTOR_CI";
const EVENT_TIMEOUT: Duration = Duration::from_secs(3);

#[test]
fn native_direct_connector_loopback_contract_is_bounded_and_owned() {
    if std::env::var_os(NATIVE_CONNECTOR_CI_ENV).is_none() {
        return;
    }

    qualifies_connect_first_payload_and_clean_close();
    qualifies_stream_reset_after_first_payload();
    qualifies_caller_cancellation();
    qualifies_first_payload_deadline();
    qualifies_shutdown();
}

fn qualifies_connect_first_payload_and_clean_close() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind happy loopback server");
    let endpoint = listener.local_addr().expect("happy loopback endpoint");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept happy connector");
        let mut request = [0u8; 4];
        stream
            .read_exact(&mut request)
            .expect("read initial payload");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("write first payload");
        stream
            .shutdown(Shutdown::Write)
            .expect("close happy response");
    });

    let policy_tables = bundled_policy_v1();
    let connector_request = connector_request(endpoint, "happy", b"", 1_000);
    let plan = prepare_windows_direct_connector(&connector_request, &policy_tables)
        .expect("happy direct connector plan");
    let mut effects = WindowsDirectDataPlaneEffects::default();
    effects
        .stage_plan(plan)
        .expect("stage happy connector plan");
    let config = data_plane_config();
    let mut state = WindowsDataPlaneState::new(0);
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
            request: connector_request.data_plane_request,
        },
        &config,
        &policy_tables,
        &mut effects,
    );

    let mut payload = Vec::<u8>::new();
    let mut now_ms = 10;
    loop {
        let event = effects
            .recv_event(1, EVENT_TIMEOUT)
            .expect("happy connector event");
        match &event {
            WindowsDirectConnectorEvent::Connected { .. } => effects
                .send_payload(1, "happy", b"ping")
                .expect("queue client payload through owned effect"),
            WindowsDirectConnectorEvent::Payload { bytes, .. } => payload.extend_from_slice(bytes),
            WindowsDirectConnectorEvent::BackendClosed { .. } => {}
            event => panic!("unexpected happy connector event: {event:?}"),
        }
        let terminal = matches!(event, WindowsDirectConnectorEvent::BackendClosed { .. });
        apply_data_plane_event(
            &mut state,
            windows_direct_connector_data_plane_event(&event, now_ms),
            &config,
            &policy_tables,
            &mut effects,
        );
        now_ms += 10;
        if terminal {
            break;
        }
    }
    assert_eq!(payload, b"pong");
    assert_eq!(effects.outcomes().count(), 1);
    assert!(!effects.has_connector(1));
    server.join().expect("join happy loopback server");
}

fn qualifies_stream_reset_after_first_payload() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind reset loopback server");
    let endpoint = listener.local_addr().expect("reset loopback endpoint");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept reset connector");
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).expect("read reset payload");
        stream.write_all(b"ok").expect("write payload before reset");
        thread::sleep(Duration::from_millis(75));
        SockRef::from(&stream)
            .set_linger(Some(Duration::ZERO))
            .expect("configure deterministic reset");
    });

    let connector = spawn(endpoint, "reset", b"ping", 1_000);
    assert!(matches!(
        next(&connector),
        WindowsDirectConnectorEvent::Connected { .. }
    ));
    let mut saw_payload = false;
    loop {
        match next(&connector) {
            WindowsDirectConnectorEvent::Payload { bytes, .. } => {
                assert_eq!(bytes, b"ok");
                saw_payload = true;
            }
            WindowsDirectConnectorEvent::StreamReset { .. } => break,
            event => panic!("unexpected reset connector event: {event:?}"),
        }
    }
    assert!(saw_payload, "reset must follow first payload");
    connector.finish().expect("join reset connector");
    server.join().expect("join reset loopback server");
}

fn qualifies_caller_cancellation() {
    let (connector, server) = spawn_idle("cancel", 1_000);
    assert!(matches!(
        next(&connector),
        WindowsDirectConnectorEvent::Connected { .. }
    ));
    let started = Instant::now();
    connector.cancel();
    assert_eq!(
        connector.send_payload(b"late"),
        Err(WindowsDirectConnectorNativeError::ConnectorStopped)
    );
    assert!(matches!(
        next(&connector),
        WindowsDirectConnectorEvent::Cancelled {
            reason: WindowsDirectConnectorCancelReason::Caller,
            ..
        }
    ));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "caller cancellation must remain below the data-plane deadline"
    );
    connector.finish().expect("join cancelled connector");
    server.join().expect("join cancel loopback server");
}

fn qualifies_first_payload_deadline() {
    let (connector, server) = spawn_idle("deadline", 120);
    assert!(matches!(
        next(&connector),
        WindowsDirectConnectorEvent::Connected { .. }
    ));
    assert!(matches!(
        next(&connector),
        WindowsDirectConnectorEvent::FirstPayloadDeadline { .. }
    ));
    connector.finish().expect("join deadline connector");
    server.join().expect("join deadline loopback server");
}

fn qualifies_shutdown() {
    let (connector, server) = spawn_idle("shutdown", 1_000);
    assert!(matches!(
        next(&connector),
        WindowsDirectConnectorEvent::Connected { .. }
    ));
    let started = Instant::now();
    connector.shutdown();
    assert!(matches!(
        next(&connector),
        WindowsDirectConnectorEvent::Cancelled {
            reason: WindowsDirectConnectorCancelReason::Shutdown,
            ..
        }
    ));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "shutdown must remain below the worker drain deadline"
    );
    connector.finish().expect("join shutdown connector");
    server.join().expect("join shutdown loopback server");
}

fn spawn_idle(
    request_id: &str,
    first_payload_timeout_ms: u64,
) -> (WindowsDirectConnectorHandle, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind idle loopback server");
    let endpoint = listener.local_addr().expect("idle loopback endpoint");
    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("accept idle connector");
        thread::sleep(Duration::from_millis(250));
    });
    (
        spawn(endpoint, request_id, b"ping", first_payload_timeout_ms),
        server,
    )
}

fn spawn(
    endpoint: SocketAddr,
    request_id: &str,
    initial_payload: &[u8],
    first_payload_timeout_ms: u64,
) -> WindowsDirectConnectorHandle {
    let policy_tables = bundled_policy_v1();
    let request = connector_request(
        endpoint,
        request_id,
        initial_payload,
        first_payload_timeout_ms,
    );
    let plan = prepare_windows_direct_connector(&request, &policy_tables)
        .expect("loopback direct connector request must be valid");
    spawn_windows_direct_connector(plan).expect("spawn native direct connector")
}

fn connector_request(
    endpoint: SocketAddr,
    request_id: &str,
    initial_payload: &[u8],
    first_payload_timeout_ms: u64,
) -> WindowsDirectConnectorRequest {
    let policy_tables = bundled_policy_v1();
    WindowsDirectConnectorRequest {
        session_id: 1,
        data_plane_request: WindowsDataPlaneRequest {
            request_id: request_id.to_owned(),
            policy: classify_route_policy("github.com", &policy_tables),
            backend: WindowsDataPlaneBackend::Direct,
            started_at_ms: 2,
            first_payload_deadline_at_ms: 2 + first_payload_timeout_ms,
        },
        endpoint: WindowsDirectConnectorEndpoint {
            address: endpoint.ip().to_string(),
            port: endpoint.port(),
        },
        issued_at_ms: 2,
        connect_deadline_at_ms: 2 + first_payload_timeout_ms.min(500),
        initial_payload: initial_payload.to_vec(),
        max_read_chunk_bytes: 4_096,
    }
}

fn data_plane_config() -> WindowsDataPlaneConfig {
    WindowsDataPlaneConfig {
        max_active_sessions: 4,
        max_retained_terminal_sessions: 4,
        cancel_timeout_ms: 500,
        shutdown_timeout_ms: 1_000,
    }
}

fn apply_data_plane_event(
    state: &mut WindowsDataPlaneState,
    event: WindowsDataPlaneEvent,
    config: &WindowsDataPlaneConfig,
    policy_tables: &slipstream_core::routing_policy::RoutingPolicyTables,
    effects: &mut WindowsDirectDataPlaneEffects,
) {
    let transition = reduce_windows_data_plane(state, &event, config, policy_tables)
        .expect("native event must satisfy the data-plane reducer");
    execute_windows_data_plane_transition(&transition, effects)
        .expect("native effect batch must complete");
    *state = transition.state;
}

fn next(connector: &WindowsDirectConnectorHandle) -> WindowsDirectConnectorEvent {
    connector
        .recv_event(EVENT_TIMEOUT)
        .expect("native connector event before timeout")
}

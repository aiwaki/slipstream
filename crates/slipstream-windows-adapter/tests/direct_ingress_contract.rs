use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_windows_adapter::direct_ingress::{
    prepare_windows_direct_ingress, windows_direct_ingress_data_plane_event,
    WindowsDirectIngressDataPlaneEffectError, WindowsDirectIngressDataPlaneEffects,
    WindowsDirectIngressEvent, WindowsDirectIngressRequest, WindowsDirectOwnedClientStream,
    WINDOWS_DIRECT_INGRESS_CONTRACT_VERSION,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-direct-ingress-v1.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    vectors: Vec<RequestVector>,
    event_vectors: Vec<EventVector>,
}

#[derive(Debug, Deserialize)]
struct RequestVector {
    name: String,
    request: WindowsDirectIngressRequest,
    expected: RequestExpected,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct RequestExpected {
    accepted: bool,
    connection_id: u64,
    endpoint: String,
    client_read_chunk_bytes: usize,
    backpressure_timeout_ms: u64,
    error: String,
}

#[derive(Debug, Deserialize)]
struct EventVector {
    name: String,
    event: WindowsDirectIngressEvent,
    now_ms: u64,
    expected: Value,
}

#[test]
fn rust_executes_windows_direct_ingress_v1_contract() {
    let fixture: ContractFixture = serde_json::from_str(CONTRACT).expect("valid ingress fixture");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_direct_ingress");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_DIRECT_INGRESS_CONTRACT_VERSION
    );
    assert_eq!(
        fixture.invariants["adapter_owned_client_stream_required"],
        Value::Bool(true)
    );
    assert_eq!(fixture.invariants["name_resolution"], Value::Bool(false));
    assert_eq!(fixture.invariants["endpoint_evidence_max_age_ms"], 1000);

    let policy_tables = bundled_policy_v1();
    for vector in fixture.vectors {
        let actual = match prepare_windows_direct_ingress(&vector.request, &policy_tables) {
            Ok(plan) => RequestExpected {
                accepted: true,
                connection_id: plan.connection_id(),
                endpoint: plan.endpoint().to_string(),
                client_read_chunk_bytes: plan.max_client_read_chunk_bytes(),
                backpressure_timeout_ms: plan.backpressure_timeout_ms(),
                error: String::new(),
            },
            Err(error) => RequestExpected {
                accepted: false,
                connection_id: 0,
                endpoint: String::new(),
                client_read_chunk_bytes: 0,
                backpressure_timeout_ms: 0,
                error: error.as_str().to_owned(),
            },
        };
        assert_eq!(actual, vector.expected, "vector {}", vector.name);
    }

    for vector in fixture.event_vectors {
        let actual = serde_json::to_value(windows_direct_ingress_data_plane_event(
            &vector.event,
            vector.now_ms,
        ))
        .expect("serialize mapped data-plane event");
        assert_eq!(actual, vector.expected, "event vector {}", vector.name);
    }
}

#[test]
fn ingress_source_has_no_resolver_or_system_mutation_surface() {
    let pure = include_str!("../src/direct_ingress/v1.rs");
    let native = include_str!("../src/direct_ingress/windows.rs");
    for forbidden in [
        "ToSocketAddrs",
        "lookup_host",
        "UdpSocket",
        "std::process",
        "Command::new",
        "Set-DnsClientServerAddress",
        "netsh",
        "WinHttpSetDefaultProxyConfiguration",
    ] {
        assert!(
            !pure.contains(forbidden),
            "pure ingress contains {forbidden}"
        );
        assert!(
            !native.contains(forbidden),
            "native ingress contains {forbidden}"
        );
    }
    assert!(native.contains("WindowsDirectOwnedClientStream"));
    assert!(native.contains("PayloadDelivered"));
}

#[test]
fn staged_ingress_retains_owned_stream_when_session_identity_is_rejected() {
    use slipstream_windows_adapter::data_plane::{
        WindowsDataPlaneCommand, WindowsDataPlaneEffects,
    };
    use std::net::{TcpListener, TcpStream};

    let fixture: ContractFixture = serde_json::from_str(CONTRACT).expect("valid ingress fixture");
    let policy_tables = bundled_policy_v1();
    let request = fixture.vectors[0].request.clone();
    let plan = prepare_windows_direct_ingress(&request, &policy_tables).expect("valid ingress");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind owned stream fixture");
    let _peer = TcpStream::connect(listener.local_addr().unwrap()).expect("connect fixture peer");
    let (accepted, _) = listener.accept().expect("accept fixture stream");
    let client = WindowsDirectOwnedClientStream::new(plan.connection_id(), accepted)
        .expect("adopt fixture stream");
    let mut effects = WindowsDirectIngressDataPlaneEffects::default();
    effects
        .stage_ingress(plan, client)
        .expect("stage owned ingress");

    let mut changed = request.connector_request.data_plane_request.clone();
    changed.policy =
        slipstream_core::routing_policy::classify_route_policy("telegram.org", &policy_tables);
    assert_eq!(
        effects.execute(&WindowsDataPlaneCommand::StartSession {
            session_id: request.connector_request.session_id,
            request: changed,
        }),
        Err(
            WindowsDirectIngressDataPlaneEffectError::IngressIdentityMismatch(
                request.connector_request.session_id
            )
        )
    );
    assert_eq!(effects.staged_ingress_count(), 1);
    effects
        .execute(&WindowsDataPlaneCommand::RejectRequest {
            request_id: request.connector_request.data_plane_request.request_id,
            reason: "policy_changed".to_owned(),
        })
        .expect("rejection releases staged ingress");
    assert_eq!(effects.staged_ingress_count(), 0);
}

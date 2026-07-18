use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_windows_adapter::direct_connector::{
    prepare_windows_direct_connector, windows_direct_connector_data_plane_event,
    WindowsDirectConnectorEvent, WindowsDirectConnectorRequest, WindowsDirectDataPlaneEffectError,
    WindowsDirectDataPlaneEffects, WINDOWS_DIRECT_CONNECTOR_CONTRACT_VERSION,
};

const CONTRACT: &str = include_str!("../../../contracts/windows-direct-connector-v1.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    vectors: Vec<RequestVector>,
    event_vectors: Vec<EventVector>,
}

#[test]
fn staged_plan_is_bound_to_the_exact_admitted_request() {
    use slipstream_windows_adapter::data_plane::{
        WindowsDataPlaneCommand, WindowsDataPlaneEffects,
    };

    let fixture: ContractFixture = serde_json::from_str(CONTRACT).expect("valid connector fixture");
    let policy_tables = bundled_policy_v1();
    let request = fixture.vectors[0].request.clone();
    let plan = prepare_windows_direct_connector(&request, &policy_tables).expect("valid plan");
    let mut changed = request.data_plane_request.clone();
    changed.policy =
        slipstream_core::routing_policy::classify_route_policy("telegram.org", &policy_tables);
    let mut effects = WindowsDirectDataPlaneEffects::default();
    effects.stage_plan(plan).expect("stage plan");
    assert_eq!(
        effects.execute(&WindowsDataPlaneCommand::StartSession {
            session_id: request.session_id,
            request: changed,
        }),
        Err(WindowsDirectDataPlaneEffectError::PlanIdentityMismatch(
            request.session_id
        ))
    );
    assert_eq!(effects.staged_plan_count(), 1);
    effects
        .execute(&WindowsDataPlaneCommand::RejectRequest {
            request_id: request.data_plane_request.request_id,
            reason: "policy_changed".to_owned(),
        })
        .expect("rejection releases the unused plan");
    assert_eq!(effects.staged_plan_count(), 0);
}

#[derive(Debug, Deserialize)]
struct RequestVector {
    name: String,
    request: WindowsDirectConnectorRequest,
    expected: RequestExpected,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct RequestExpected {
    accepted: bool,
    endpoint: String,
    connect_timeout_ms: u64,
    first_payload_timeout_ms: u64,
    error: String,
}

#[derive(Debug, Deserialize)]
struct EventVector {
    name: String,
    event: WindowsDirectConnectorEvent,
    now_ms: u64,
    expected: Value,
}

#[test]
fn rust_executes_windows_direct_connector_v1_contract() {
    let fixture: ContractFixture = serde_json::from_str(CONTRACT).expect("valid connector fixture");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_direct_connector");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_DIRECT_CONNECTOR_CONTRACT_VERSION
    );
    assert_eq!(
        fixture.invariants["endpoint_is_numeric_only"],
        Value::Bool(true)
    );
    assert_eq!(fixture.invariants["name_resolution"], Value::Bool(false));
    assert_eq!(fixture.invariants["connect_timeout_ceiling_ms"], 750);

    let policy_tables = bundled_policy_v1();
    for vector in fixture.vectors {
        let actual = match prepare_windows_direct_connector(&vector.request, &policy_tables) {
            Ok(plan) => RequestExpected {
                accepted: true,
                endpoint: plan.endpoint().to_string(),
                connect_timeout_ms: plan.connect_timeout_ms(),
                first_payload_timeout_ms: plan.first_payload_timeout_ms(),
                error: String::new(),
            },
            Err(error) => RequestExpected {
                accepted: false,
                endpoint: String::new(),
                connect_timeout_ms: 0,
                first_payload_timeout_ms: 0,
                error: error.as_str().to_owned(),
            },
        };
        assert_eq!(actual, vector.expected, "vector {}", vector.name);
    }

    for vector in fixture.event_vectors {
        let actual = serde_json::to_value(windows_direct_connector_data_plane_event(
            &vector.event,
            vector.now_ms,
        ))
        .expect("serialize mapped data-plane event");
        assert_eq!(actual, vector.expected, "event vector {}", vector.name);
    }
}

#[test]
fn native_connector_source_has_no_name_resolution_or_system_mutation_surface() {
    let source = include_str!("../src/direct_connector/windows.rs");
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
            !source.contains(forbidden),
            "native connector must not contain {forbidden}"
        );
    }
    assert!(source.contains("TcpStream::connect_timeout"));
}

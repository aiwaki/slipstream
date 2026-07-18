use serde_json::Value;
use slipstream_windows_adapter::service_host::{
    parse_windows_service_host_arguments, WindowsServiceHostArgumentErrorCode,
    WindowsServiceHostEvent, WindowsServiceHostFailureCode, WindowsServiceHostFailureV1,
    WindowsServiceHostInvocation, WindowsServiceHostRuntimeV1, WindowsServiceHostStatus,
    WindowsServiceHostTransition, WindowsServiceManagementCommandKind,
    WindowsServiceManagementResultV1, WINDOWS_SERVICE_HOST_CONTRACT_VERSION,
    WINDOWS_SERVICE_HOST_RESULT_SCHEMA_VERSION,
};
use slipstream_windows_adapter::service_lifecycle::{
    WindowsServiceDecision, WindowsServiceLifecycleResult, WindowsServiceState,
    WINDOWS_SERVICE_NAME,
};
use slipstream_windows_adapter::service_ownership::WINDOWS_SERVICE_ARGUMENT;

const HOST_V1: &str = include_str!("../../../contracts/windows-service-host-v1.json");

fn fixture() -> Value {
    serde_json::from_str(HOST_V1).expect("Windows service host fixture must be JSON")
}

#[test]
fn windows_service_host_executes_every_v1_invocation_vector() {
    let contract = fixture();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract"], "slipstream.windows_service_host");
    assert_eq!(
        contract["contract_version"],
        WINDOWS_SERVICE_HOST_CONTRACT_VERSION
    );
    assert_eq!(contract["service_name"], WINDOWS_SERVICE_NAME);
    assert_eq!(contract["service_argument"], WINDOWS_SERVICE_ARGUMENT);
    assert_eq!(
        contract["result_schema_version"],
        WINDOWS_SERVICE_HOST_RESULT_SCHEMA_VERSION
    );

    for vector in contract["invocations"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let arguments = vector["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|argument| argument.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let expected: WindowsServiceHostInvocation =
            serde_json::from_value(vector["expected"].clone())
                .unwrap_or_else(|error| panic!("{name}: invalid expected invocation: {error}"));
        assert_eq!(
            parse_windows_service_host_arguments(&arguments),
            Ok(expected),
            "{name}"
        );
    }
}

#[test]
fn windows_service_host_rejects_every_invalid_v1_invocation() {
    let contract = fixture();
    for vector in contract["invalid_invocations"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let arguments = vector["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|argument| argument.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let expected: WindowsServiceHostArgumentErrorCode =
            serde_json::from_value(vector["error"].clone())
                .unwrap_or_else(|error| panic!("{name}: invalid error code: {error}"));
        let error = parse_windows_service_host_arguments(&arguments)
            .expect_err("invalid invocation must be rejected");
        assert_eq!(error.code, expected, "{name}");
    }
}

#[test]
fn windows_service_host_executes_every_v1_shutdown_scenario() {
    let contract = fixture();
    for scenario in contract["shutdown_scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let initial_status: WindowsServiceHostStatus =
            serde_json::from_value(scenario["initial_status"].clone()).unwrap();
        let mut runtime = WindowsServiceHostRuntimeV1::new();
        assert_eq!(runtime.initial_status(), initial_status, "{name}");

        for step in scenario["events"].as_array().unwrap() {
            let event: WindowsServiceHostEvent =
                serde_json::from_value(step["event"].clone()).unwrap();
            let expected: WindowsServiceHostTransition =
                serde_json::from_value(step["expected"].clone()).unwrap();
            assert_eq!(runtime.transition(event), Ok(expected), "{name}");
        }
    }
}

#[test]
fn windows_service_host_examples_match_the_v1_wire_format() {
    let contract = fixture();
    let result = WindowsServiceManagementResultV1::new(
        WindowsServiceManagementCommandKind::Uninstall,
        WindowsServiceLifecycleResult {
            state: WindowsServiceState::absent(),
            decision: WindowsServiceDecision::NoChange,
            accepted: true,
            error: None,
        },
    );
    result.validate().expect("example result must satisfy v1");
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        contract["result_example"]
    );

    let failure = WindowsServiceHostFailureV1::new(
        WindowsServiceHostFailureCode::InvalidArguments,
        "missing Windows service host mode",
    );
    assert_eq!(
        serde_json::to_value(failure).unwrap(),
        contract["failure_example"]
    );
}

#[test]
fn production_windows_service_host_is_scm_scoped_and_has_no_network_surface() {
    let contract = fixture();
    for invariant in ["network_effects", "process_discovery_or_termination"] {
        assert_eq!(contract["invariants"][invariant], false, "{invariant}");
    }
    for invariant in [
        "service_mode_is_explicit",
        "management_mode_is_explicit",
        "install_uses_current_executable",
        "install_generation_is_positive",
        "management_results_are_json",
        "stop_and_shutdown_share_a_bounded_sequence",
    ] {
        assert_eq!(contract["invariants"][invariant], true, "{invariant}");
    }

    let source = include_str!("../src/service_host/windows.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production service-host source");
    let binary = include_str!("../src/bin/slipstream_windows_service.rs");

    for required in [
        "StartServiceCtrlDispatcherW",
        "RegisterServiceCtrlHandlerW",
        "SetServiceStatus",
        "SERVICE_ACCEPT_STOP",
        "SERVICE_ACCEPT_SHUTDOWN",
        "SERVICE_CONTROL_STOP",
        "SERVICE_CONTROL_SHUTDOWN",
        "WindowsWorkerHostState",
        "reduce_windows_worker_host",
        "execute_windows_worker_host_transition",
        "WindowsDataPlaneEvent::WorkerReady",
        "NoNetworkWindowsWorkerHostEffects",
        "bundled_policy_v1",
        "WindowsServiceController::new",
        "std::env::current_exe",
    ] {
        assert!(
            production.contains(required),
            "production host must use {required}"
        );
    }
    for required in [
        "parse_windows_service_host_arguments",
        "execute_windows_service_host",
        "WindowsServiceHostFailureV1",
    ] {
        assert!(binary.contains(required), "host binary must use {required}");
    }

    for forbidden in [
        "EnumServicesStatus",
        "TerminateProcess",
        "OpenProcess",
        "std::process::Command",
        "Command::new",
        "std::net",
        "TcpStream",
        "UdpSocket",
        "WinHttp",
        "InternetOpen",
        "DnsQuery",
        "Set-DnsClientServerAddress",
        "netsh",
        "ProxyEnable",
        "Vpn",
        "crash-v1",
        "fail-start-v1",
    ] {
        assert!(
            !production.contains(forbidden),
            "production host must not contain {forbidden}"
        );
        assert!(
            !binary.contains(forbidden),
            "host binary must not contain {forbidden}"
        );
    }
}

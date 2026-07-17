use serde_json::Value;
use slipstream_windows_adapter::service_lifecycle::{
    WindowsServiceObservedState, WINDOWS_SERVICE_NAME,
};
use slipstream_windows_adapter::service_observer::{
    WindowsScmState, WindowsServiceObservation, WindowsServiceSnapshot,
    WINDOWS_SERVICE_OBSERVER_CONTRACT_VERSION,
};

#[cfg(windows)]
use slipstream_windows_adapter::service_observer::WindowsServiceObserver;

const OBSERVER_V1: &str = include_str!("../../../contracts/windows-service-observer-v1.json");

fn fixture() -> Value {
    serde_json::from_str(OBSERVER_V1).expect("Windows service observer fixture must be JSON")
}

#[test]
fn windows_service_observer_executes_every_v1_state_vector() {
    let contract = fixture();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract"], "slipstream.windows_service_observer");
    assert_eq!(
        contract["contract_version"],
        WINDOWS_SERVICE_OBSERVER_CONTRACT_VERSION
    );
    assert_eq!(contract["service_name"], WINDOWS_SERVICE_NAME);
    assert_eq!(contract["invariants"]["read_only"], true);
    assert_eq!(contract["invariants"]["ownership_is_not_inferred"], true);
    assert_eq!(contract["invariants"]["network_effects"], false);

    for vector in contract["state_vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let scm_state: WindowsScmState = serde_json::from_value(vector["scm_state"].clone())
            .unwrap_or_else(|error| panic!("{name}: invalid SCM state: {error}"));
        let snapshot = WindowsServiceSnapshot::from_scm(
            r#"\"C:\Program Files\Slipstream\slipstreamd.exe\" --service"#.to_owned(),
            scm_state,
            vector["raw_process_id"].as_u64().unwrap() as u32,
        );
        let expected_observed: WindowsServiceObservedState =
            serde_json::from_value(vector["expected_observed"].clone()).unwrap();
        let expected_process_id = vector["expected_process_id"]
            .as_u64()
            .map(|value| value as u32);

        assert_eq!(snapshot.service_name, WINDOWS_SERVICE_NAME, "{name}");
        assert_eq!(snapshot.observed, expected_observed, "{name}");
        assert_eq!(snapshot.process_id, expected_process_id, "{name}");
        assert!(snapshot.binary_path.contains("slipstreamd.exe"), "{name}");
    }
}

#[test]
fn absent_observation_uses_only_the_exact_service_name() {
    assert_eq!(
        WindowsServiceObservation::absent(),
        WindowsServiceObservation::Absent {
            service_name: WINDOWS_SERVICE_NAME.to_owned(),
        }
    );
}

#[test]
fn native_observer_source_is_read_only_and_has_no_network_surface() {
    let source = include_str!("../src/service_observer/windows.rs");
    let manifest = include_str!("../Cargo.toml");
    assert!(
        manifest.contains("[target.'cfg(windows)'.dependencies]\nwindows-sys"),
        "WinAPI bindings must remain Windows-target-only"
    );
    for forbidden in [
        "CreateServiceW",
        "DeleteService",
        "StartServiceW",
        "ControlService",
        "Win32::Networking",
        "std::net",
        "TcpStream",
        "UdpSocket",
    ] {
        assert!(
            !source.contains(forbidden),
            "native observer contains forbidden surface {forbidden:?}"
        );
    }
}

#[cfg(windows)]
#[test]
fn native_scm_observer_reads_the_disposable_runner_without_mutation() {
    use slipstream_windows_adapter::service_observer::WindowsScmObserver;

    let observation = WindowsScmObserver::new()
        .observe()
        .expect("read-only SCM observation must succeed");
    if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_some() {
        assert_eq!(observation, WindowsServiceObservation::absent());
    }
}

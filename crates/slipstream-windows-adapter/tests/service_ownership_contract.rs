use serde_json::Value;
use slipstream_windows_adapter::service_lifecycle::{
    WindowsServiceDesiredState, WindowsServiceOwnership, WINDOWS_SERVICE_NAME,
};
use slipstream_windows_adapter::service_ownership::{
    assess_windows_service_ownership, canonical_scm_binary_path, WindowsExecutableEvidence,
    WindowsOwnerRecordEvidence, WindowsScmEvidence, WindowsServiceOwnershipAssessment,
    WindowsServiceOwnershipInput, WindowsServiceOwnershipRecord,
    WINDOWS_SERVICE_OWNERSHIP_CONTRACT_VERSION, WINDOWS_SERVICE_OWNERSHIP_RECORD_SCHEMA_VERSION,
};

const OWNERSHIP_V1: &str = include_str!("../../../contracts/windows-service-ownership-v1.json");

fn fixture() -> Value {
    serde_json::from_str(OWNERSHIP_V1).expect("Windows service ownership fixture must be JSON")
}

fn resolve(root: &Value, value: &Value) -> Value {
    if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        let pointer = reference
            .strip_prefix('#')
            .unwrap_or_else(|| panic!("fixture reference must be local: {reference}"));
        return resolve(
            root,
            root.pointer(pointer)
                .unwrap_or_else(|| panic!("fixture reference does not exist: {reference}")),
        );
    }
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|item| resolve(root, item)).collect()),
        Value::Object(items) => Value::Object(
            items
                .iter()
                .map(|(key, item)| (key.clone(), resolve(root, item)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

#[test]
fn windows_service_ownership_executes_every_v1_vector() {
    let contract = fixture();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract"], "slipstream.windows_service_ownership");
    assert_eq!(
        contract["contract_version"],
        WINDOWS_SERVICE_OWNERSHIP_CONTRACT_VERSION
    );
    assert_eq!(contract["service_name"], WINDOWS_SERVICE_NAME);
    assert_eq!(contract["invariants"]["owner_only_record_required"], true);
    assert_eq!(contract["invariants"]["native_effects"], false);
    assert_eq!(contract["invariants"]["network_effects"], false);

    for scenario in contract["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let input: WindowsServiceOwnershipInput =
            serde_json::from_value(resolve(&contract, &scenario["input"]))
                .unwrap_or_else(|error| panic!("{name}: invalid input: {error}"));
        let expected: WindowsServiceOwnershipAssessment =
            serde_json::from_value(resolve(&contract, &scenario["expected"]))
                .unwrap_or_else(|error| panic!("{name}: invalid expected result: {error}"));
        let actual = assess_windows_service_ownership(&input);
        assert_eq!(actual, expected, "{name}");

        let lifecycle = actual.lifecycle_state(WindowsServiceDesiredState::Running, 0);
        lifecycle
            .validate()
            .unwrap_or_else(|error| panic!("{name}: invalid lifecycle projection: {error}"));
        assert_eq!(
            lifecycle.active.is_some(),
            lifecycle.ownership == WindowsServiceOwnership::Owned,
            "{name}: only owned evidence may carry an active identity"
        );
    }
}

#[test]
fn owner_record_is_canonical_and_content_addressed() {
    let contract = fixture();
    let valid: WindowsServiceOwnershipRecord =
        serde_json::from_value(resolve(&contract, &contract["records"]["v1"])).unwrap();
    valid.validate().unwrap();
    assert_eq!(
        valid.scm_binary_path,
        canonical_scm_binary_path(&valid.executable_path)
    );

    let invalid = [
        WindowsServiceOwnershipRecord {
            schema_version: WINDOWS_SERVICE_OWNERSHIP_RECORD_SCHEMA_VERSION + 1,
            ..valid.clone()
        },
        WindowsServiceOwnershipRecord {
            service_name: "Slipstream".to_owned(),
            ..valid.clone()
        },
        WindowsServiceOwnershipRecord {
            executable_path: "relative\\slipstreamd.exe".to_owned(),
            ..valid.clone()
        },
        WindowsServiceOwnershipRecord {
            executable_path: "C:\\Program Files\\..\\slipstreamd.exe".to_owned(),
            ..valid.clone()
        },
        WindowsServiceOwnershipRecord {
            executable_path: "C:\\Program Files\\Slipstream\\slipstreamd.exe:stream".to_owned(),
            ..valid.clone()
        },
        WindowsServiceOwnershipRecord {
            scm_binary_path: "C:\\Temp\\slipstreamd.exe".to_owned(),
            ..valid.clone()
        },
        WindowsServiceOwnershipRecord {
            executable_sha256: "A".repeat(64),
            ..valid.clone()
        },
        WindowsServiceOwnershipRecord {
            generation: 0,
            ..valid
        },
    ];
    for record in invalid {
        assert!(
            record.validate().is_err(),
            "record should be rejected: {record:?}"
        );
    }
}

#[test]
fn owned_requires_the_complete_evidence_conjunction() {
    let contract = fixture();
    let record_names = [
        "missing",
        "owner_only",
        "invalid_record",
        "inaccessible",
        "invalid",
        "untrusted",
    ];
    let scm_names = [
        "absent",
        "running",
        "stopped",
        "running_without_process",
        "inconsistent_state",
        "transitional",
        "binary_mismatch",
        "service_name_mismatch",
        "inaccessible",
        "invalid",
    ];
    let executable_names = [
        "verified",
        "path_mismatch",
        "hash_mismatch",
        "not_checked",
        "missing",
        "inaccessible",
        "invalid",
    ];

    for record_name in record_names {
        let record: WindowsOwnerRecordEvidence = serde_json::from_value(resolve(
            &contract,
            &contract["record_evidence"][record_name],
        ))
        .unwrap();
        for scm_name in scm_names {
            let scm: WindowsScmEvidence =
                serde_json::from_value(resolve(&contract, &contract["scm_evidence"][scm_name]))
                    .unwrap();
            for executable_name in executable_names {
                let executable: WindowsExecutableEvidence = serde_json::from_value(resolve(
                    &contract,
                    &contract["executable_evidence"][executable_name],
                ))
                .unwrap();
                let assessment = assess_windows_service_ownership(&WindowsServiceOwnershipInput {
                    record: record.clone(),
                    scm: scm.clone(),
                    executable,
                });
                let should_be_owned = record_name == "owner_only"
                    && matches!(scm_name, "running" | "stopped")
                    && executable_name == "verified";
                assert_eq!(
                    assessment.ownership == WindowsServiceOwnership::Owned,
                    should_be_owned,
                    "record={record_name}, scm={scm_name}, executable={executable_name}"
                );
            }
        }
    }
}

#[test]
fn ownership_model_has_no_native_or_network_surface() {
    let source = include_str!("../src/service_ownership/v1.rs");
    for forbidden in [
        "windows_sys",
        "Win32",
        "OpenSCManager",
        "OpenService",
        "CreateService",
        "StartService",
        "ControlService",
        "std::net",
        "TcpStream",
        "UdpSocket",
        "std::fs",
    ] {
        assert!(
            !source.contains(forbidden),
            "ownership assessment must remain pure; found {forbidden}"
        );
    }
}

use serde_json::Value;
use slipstream_windows_adapter::service_lifecycle::{
    RecordingWindowsServiceEffects, WindowsServiceAction, WindowsServiceActionKind,
    WindowsServiceCommand, WindowsServiceDecision, WindowsServiceDesiredState,
    WindowsServiceIdentity, WindowsServiceLifecycleError, WindowsServiceLifecycleV1,
    WindowsServiceObservedState, WindowsServiceOwnership, WindowsServiceState,
    WINDOWS_SERVICE_LIFECYCLE_CONTRACT_VERSION, WINDOWS_SERVICE_NAME,
};

const LIFECYCLE_V1: &str = include_str!("../../../contracts/windows-service-lifecycle-v1.json");

fn fixture() -> Value {
    serde_json::from_str(LIFECYCLE_V1).expect("Windows service lifecycle fixture must be JSON")
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

fn stage(value: &str) -> WindowsServiceActionKind {
    match value {
        "persist_intent" => WindowsServiceActionKind::PersistIntent,
        "stage_payload" => WindowsServiceActionKind::StagePayload,
        "register_service" => WindowsServiceActionKind::RegisterService,
        "start_owned_service" => WindowsServiceActionKind::StartOwnedService,
        "verify_ready" => WindowsServiceActionKind::VerifyReady,
        "commit_install" => WindowsServiceActionKind::CommitInstall,
        "clear_active_install_record" => WindowsServiceActionKind::ClearActiveInstallRecord,
        "stop_owned_service" => WindowsServiceActionKind::StopOwnedService,
        "verify_stopped" => WindowsServiceActionKind::VerifyStopped,
        "unregister_owned_service" => WindowsServiceActionKind::UnregisterOwnedService,
        "remove_owned_payload" => WindowsServiceActionKind::RemoveOwnedPayload,
        "verify_absent" => WindowsServiceActionKind::VerifyAbsent,
        other => panic!("unknown service lifecycle stage {other:?}"),
    }
}

fn decision_name(decision: WindowsServiceDecision) -> String {
    serde_json::to_value(decision)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn windows_service_lifecycle_executes_every_v1_scenario() {
    let contract = fixture();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract"], "slipstream.windows_service_lifecycle");
    assert_eq!(
        contract["contract_version"],
        WINDOWS_SERVICE_LIFECYCLE_CONTRACT_VERSION
    );
    assert_eq!(contract["service_name"], WINDOWS_SERVICE_NAME);
    assert_eq!(contract["invariants"]["native_effects"], false);
    assert_eq!(contract["invariants"]["network_effects"], false);

    for scenario in contract["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let initial: WindowsServiceState =
            serde_json::from_value(resolve(&contract, &scenario["initial"]))
                .unwrap_or_else(|error| panic!("{name}: invalid initial state: {error}"));
        let command: WindowsServiceCommand =
            serde_json::from_value(resolve(&contract, &scenario["command"]))
                .unwrap_or_else(|error| panic!("{name}: invalid command: {error}"));
        let expected = resolve(&contract, &scenario["expected"]);
        let expected_state: WindowsServiceState = serde_json::from_value(expected["state"].clone())
            .unwrap_or_else(|error| panic!("{name}: invalid expected state: {error}"));
        let mut lifecycle = WindowsServiceLifecycleV1::new(initial).unwrap();
        let mut effects = RecordingWindowsServiceEffects::default();
        for failure in scenario
            .get("failures")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let stage = stage(failure["stage"].as_str().unwrap());
            let message = failure["message"].as_str().unwrap();
            if let Some(call) = failure.get("call").and_then(Value::as_u64) {
                effects.fail_on_call(stage, call as u32, message);
            } else {
                effects.fail_once(stage, message);
            }
        }

        let result = lifecycle.execute(&command, &mut effects);
        if expected
            .get("hard_error")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let error = result.unwrap_err();
            let fragment = expected["error_contains"].as_str().unwrap();
            assert!(error.to_string().contains(fragment), "{name}: {error}");
            assert_eq!(lifecycle.state(), &expected_state, "{name}: hard state");
        } else {
            let result = result.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                result.accepted,
                expected["accepted"].as_bool().unwrap(),
                "{name}: accepted"
            );
            assert_eq!(
                decision_name(result.decision),
                expected["decision"].as_str().unwrap(),
                "{name}: decision"
            );
            assert_eq!(result.state, expected_state, "{name}: result state");
            assert_eq!(lifecycle.state(), &expected_state, "{name}: stored state");
            if let Some(fragment) = expected.get("error_contains").and_then(Value::as_str) {
                assert!(
                    result
                        .error
                        .as_deref()
                        .unwrap_or_default()
                        .contains(fragment),
                    "{name}: {:?}",
                    result.error
                );
            } else {
                assert_eq!(result.error, None, "{name}: error");
            }
        }

        let actual_effects: Vec<_> = effects
            .events()
            .iter()
            .map(|event| event.kind().as_str())
            .collect();
        let expected_effects: Vec<_> = expected["effects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(actual_effects, expected_effects, "{name}: effects");
    }
}

#[test]
fn failed_stop_intent_never_becomes_crash_recovery() {
    let contract = fixture();
    let initial: WindowsServiceState =
        serde_json::from_value(resolve(&contract, &contract["states"]["owned_running"])).unwrap();
    let mut lifecycle = WindowsServiceLifecycleV1::new(initial).unwrap();
    let mut effects = RecordingWindowsServiceEffects::default();
    effects.fail_once(
        WindowsServiceActionKind::VerifyStopped,
        "fake stopped proof unavailable",
    );

    let stop = lifecycle
        .execute(&WindowsServiceCommand::Stop, &mut effects)
        .unwrap();
    assert!(!stop.accepted);
    assert_eq!(stop.state.desired, WindowsServiceDesiredState::Stopped);
    let before_crash = effects.events().len();

    let crash = lifecycle
        .execute(&WindowsServiceCommand::CrashObserved, &mut effects)
        .unwrap();
    assert!(crash.accepted);
    assert_eq!(crash.decision, WindowsServiceDecision::NoChange);
    assert_eq!(effects.events().len(), before_crash);
}

#[test]
fn failed_start_compensation_enters_non_restarting_unknown_state() {
    let contract = fixture();
    let initial: WindowsServiceState =
        serde_json::from_value(resolve(&contract, &contract["states"]["owned_stopped"])).unwrap();
    let mut lifecycle = WindowsServiceLifecycleV1::new(initial).unwrap();
    let mut effects = RecordingWindowsServiceEffects::default();
    effects.fail_once(
        WindowsServiceActionKind::VerifyReady,
        "fake readiness timeout",
    );
    effects.fail_once(
        WindowsServiceActionKind::VerifyStopped,
        "fake stopped proof unavailable",
    );

    let error = lifecycle
        .execute(&WindowsServiceCommand::Start, &mut effects)
        .unwrap_err();
    match error {
        WindowsServiceLifecycleError::Compensation { failed_stages, .. } => {
            assert_eq!(failed_stages, vec![WindowsServiceActionKind::VerifyStopped]);
        }
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(
        lifecycle.state().desired,
        WindowsServiceDesiredState::Stopped
    );
    assert_eq!(
        lifecycle.state().observed,
        WindowsServiceObservedState::Unknown
    );
    let before_crash = effects.events().len();
    let crash = lifecycle
        .execute(&WindowsServiceCommand::CrashObserved, &mut effects)
        .unwrap();
    assert_eq!(crash.decision, WindowsServiceDecision::NoChange);
    assert_eq!(effects.events().len(), before_crash);
}

#[test]
fn failed_intent_compensation_is_hard_and_suppresses_recovery() {
    let contract = fixture();
    let initial: WindowsServiceState =
        serde_json::from_value(resolve(&contract, &contract["states"]["absent"])).unwrap();
    let identity: WindowsServiceIdentity =
        serde_json::from_value(resolve(&contract, &contract["identities"]["v1"])).unwrap();
    let mut lifecycle = WindowsServiceLifecycleV1::new(initial).unwrap();
    let mut effects = RecordingWindowsServiceEffects::default();
    effects.fail_once(
        WindowsServiceActionKind::VerifyReady,
        "fake readiness timeout",
    );
    effects.fail_on_call(
        WindowsServiceActionKind::PersistIntent,
        2,
        "fake intent restore unavailable",
    );

    let error = lifecycle
        .execute(&WindowsServiceCommand::Install { identity }, &mut effects)
        .unwrap_err();
    match error {
        WindowsServiceLifecycleError::Compensation { failed_stages, .. } => {
            assert!(failed_stages.contains(&WindowsServiceActionKind::PersistIntent));
        }
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(
        lifecycle.state().desired,
        WindowsServiceDesiredState::Unknown
    );
    let before_crash = effects.events().len();
    let crash = lifecycle
        .execute(&WindowsServiceCommand::CrashObserved, &mut effects)
        .unwrap();
    assert_eq!(crash.decision, WindowsServiceDecision::NoChange);
    assert_eq!(effects.events().len(), before_crash);
}

#[test]
fn install_rollback_persists_absent_intent_before_cleanup() {
    let contract = fixture();
    let initial: WindowsServiceState =
        serde_json::from_value(resolve(&contract, &contract["states"]["absent"])).unwrap();
    let identity: WindowsServiceIdentity =
        serde_json::from_value(resolve(&contract, &contract["identities"]["v1"])).unwrap();
    let mut lifecycle = WindowsServiceLifecycleV1::new(initial).unwrap();
    let mut effects = RecordingWindowsServiceEffects::default();
    effects.fail_once(
        WindowsServiceActionKind::VerifyReady,
        "fake readiness timeout",
    );

    lifecycle
        .execute(&WindowsServiceCommand::Install { identity }, &mut effects)
        .unwrap();

    let rollback = &effects.events()[5..];
    assert!(matches!(
        rollback.first(),
        Some(WindowsServiceAction::PersistIntent {
            desired: WindowsServiceDesiredState::Absent,
            identity: None,
            ..
        })
    ));
    assert_eq!(
        rollback[1].kind(),
        WindowsServiceActionKind::StopOwnedService
    );
}

#[test]
fn start_rollback_persists_stopped_intent_before_stop() {
    let contract = fixture();
    let initial: WindowsServiceState =
        serde_json::from_value(resolve(&contract, &contract["states"]["owned_stopped"])).unwrap();
    let mut lifecycle = WindowsServiceLifecycleV1::new(initial).unwrap();
    let mut effects = RecordingWindowsServiceEffects::default();
    effects.fail_once(
        WindowsServiceActionKind::VerifyReady,
        "fake readiness timeout",
    );

    lifecycle
        .execute(&WindowsServiceCommand::Start, &mut effects)
        .unwrap();

    assert!(matches!(
        &effects.events()[3],
        WindowsServiceAction::PersistIntent {
            desired: WindowsServiceDesiredState::Stopped,
            identity: Some(_),
            ..
        }
    ));
    assert_eq!(
        effects.events()[4].kind(),
        WindowsServiceActionKind::StopOwnedService
    );
}

#[test]
fn absent_intent_cannot_be_weakened_by_start_or_stop() {
    let contract = fixture();
    let identity: WindowsServiceIdentity =
        serde_json::from_value(resolve(&contract, &contract["identities"]["v1"])).unwrap();
    let state = WindowsServiceState {
        desired: WindowsServiceDesiredState::Absent,
        observed: WindowsServiceObservedState::Stopped,
        ownership: WindowsServiceOwnership::Owned,
        active: Some(identity),
        crash_restart_attempts: 0,
    };
    let mut lifecycle = WindowsServiceLifecycleV1::new(state).unwrap();
    let mut effects = RecordingWindowsServiceEffects::default();

    for command in [WindowsServiceCommand::Start, WindowsServiceCommand::Stop] {
        let result = lifecycle.execute(&command, &mut effects).unwrap();
        assert_eq!(result.decision, WindowsServiceDecision::Refused);
        assert_eq!(result.state.desired, WindowsServiceDesiredState::Absent);
    }
    assert!(effects.events().is_empty());
}

#[test]
fn durable_intent_effects_are_bound_to_exact_identity() {
    let contract = fixture();
    let initial: WindowsServiceState =
        serde_json::from_value(resolve(&contract, &contract["states"]["absent"])).unwrap();
    let identity: WindowsServiceIdentity =
        serde_json::from_value(resolve(&contract, &contract["identities"]["v1"])).unwrap();
    let mut lifecycle = WindowsServiceLifecycleV1::new(initial).unwrap();
    let mut effects = RecordingWindowsServiceEffects::default();

    lifecycle
        .execute(
            &WindowsServiceCommand::Install {
                identity: identity.clone(),
            },
            &mut effects,
        )
        .unwrap();
    match &effects.events()[0] {
        WindowsServiceAction::PersistIntent {
            desired,
            identity: persisted,
            crash_restart_attempts,
        } => {
            assert_eq!(*desired, WindowsServiceDesiredState::Running);
            assert_eq!(persisted.as_ref(), Some(&identity));
            assert_eq!(*crash_restart_attempts, 0);
        }
        other => panic!("unexpected first effect: {other:?}"),
    }
}

#[test]
fn service_identity_is_exact_and_content_addressed() {
    let valid = WindowsServiceIdentity {
        service_name: WINDOWS_SERVICE_NAME.to_owned(),
        executable_sha256: "a".repeat(64),
        generation: 1,
    };
    valid.validate().unwrap();

    for invalid in [
        WindowsServiceIdentity {
            service_name: "Slipstream".to_owned(),
            ..valid.clone()
        },
        WindowsServiceIdentity {
            executable_sha256: "A".repeat(64),
            ..valid.clone()
        },
        WindowsServiceIdentity {
            generation: 0,
            ..valid
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn lifecycle_source_and_manifest_have_no_native_or_network_dependencies() {
    let source = include_str!("../src/service_lifecycle/v1.rs");
    let manifest = include_str!("../Cargo.toml");
    for forbidden in [
        "std::net",
        "std::process",
        "std::fs",
        "Command::new",
        "TcpStream",
        "UdpSocket",
        "windows_sys",
        "winapi",
    ] {
        assert!(
            !source.contains(forbidden),
            "service lifecycle source contains {forbidden:?}"
        );
        assert!(
            !manifest.contains(forbidden),
            "service lifecycle manifest contains {forbidden:?}"
        );
    }
}

#[test]
fn unowned_state_never_emits_destructive_effects() {
    let state = WindowsServiceState {
        desired: WindowsServiceDesiredState::Absent,
        observed: WindowsServiceObservedState::Running,
        ownership: WindowsServiceOwnership::Foreign,
        active: None,
        crash_restart_attempts: 0,
    };
    let mut lifecycle = WindowsServiceLifecycleV1::new(state).unwrap();
    let mut effects = RecordingWindowsServiceEffects::default();

    let result = lifecycle
        .execute(&WindowsServiceCommand::Uninstall, &mut effects)
        .unwrap();
    assert_eq!(result.decision, WindowsServiceDecision::Refused);
    assert!(effects.events().is_empty());
}

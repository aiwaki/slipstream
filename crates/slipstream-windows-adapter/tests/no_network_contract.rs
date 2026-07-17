use serde_json::Value;
use slipstream_core::route_policy_activation::{
    PolicyActivationDecisionKind, PolicyActivationPhase,
};
use slipstream_core::route_policy_bundle::RoutePolicyBundleErrorCode;
use slipstream_core::route_policy_manifest::parse_route_policy_manifest;
use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_core::routing_recovery::{
    ConnectionOutcome, RecoveryAction, RecoveryActionKind, RecoveryContext,
};
use slipstream_windows_adapter::{
    HealthEvidence, RecordedWindowsEffect, RecordingWindowsEffects, WindowsAdapterError,
    WindowsAdapterV1, WindowsEffectStage, WINDOWS_ADAPTER_CONTRACT_VERSION,
};
use std::collections::BTreeMap;

const ADAPTER_V1: &str = include_str!("../../../contracts/platform-adapter-v1.json");
const BUNDLE_V1: &str = include_str!("../../../contracts/route-policy-bundle-v1.json");
const MANIFEST_V1: &str = include_str!("../../../contracts/route-policy-manifest-v1.json");
const POLICY_V1: &str = include_str!("../../../contracts/routing-policy-v1.json");
const RECOVERY_V1: &str = include_str!("../../../contracts/recovery-v1.json");
const STATUS_V2: &str = include_str!("../../../contracts/status-v2-v1.json");

fn parse_json(raw: &str, label: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|error| panic!("{label} must be valid JSON: {error}"))
}

fn fixture() -> Value {
    parse_json(ADAPTER_V1, "platform adapter contract")
}

fn resolved_bundle(bundle_contract: &Value, manifest_contract: &Value) -> Value {
    let mut bundle = bundle_contract["base_bundle"].clone();
    assert_eq!(
        bundle["manifest"]["$ref"],
        "route-policy-manifest-v1.json#/normalized_manifest"
    );
    bundle["manifest"] = manifest_contract["normalized_manifest"].clone();
    bundle
}

fn trusted_keys(bundle_contract: &Value) -> BTreeMap<String, String> {
    serde_json::from_value(bundle_contract["trusted_keys"].clone())
        .expect("trusted key fixture must be a string map")
}

fn new_adapter(adapter: &Value) -> WindowsAdapterV1 {
    let tables = bundled_policy_v1();
    let manifest = parse_route_policy_manifest(&serde_json::json!({
        "version": 1,
        "source": adapter["bundled_source"],
        "static_routes": tables.static_routes,
        "geo_exit_routes": tables.geo_exit_routes,
        "attempt_limits": {
            "default": 2,
            "local_bypass": 4
        }
    }))
    .expect("bundled adapter manifest must be valid");
    WindowsAdapterV1::new(manifest)
}

fn health(value: &Value) -> HealthEvidence {
    HealthEvidence {
        completed: value["completed"].as_bool().unwrap(),
        ok: value["ok"].as_u64().unwrap() as u32,
        degraded: value["degraded"].as_u64().unwrap() as u32,
        blocked: value["blocked"].as_u64().unwrap() as u32,
        detail: value["detail"].as_str().unwrap().to_owned(),
    }
}

fn stage(value: &str) -> WindowsEffectStage {
    match value {
        "persist_trial_generation" => WindowsEffectStage::PersistTrialGeneration,
        "activate_trial" => WindowsEffectStage::ActivateTrial,
        "run_health_gate" => WindowsEffectStage::RunHealthGate,
        "commit_candidate" => WindowsEffectStage::CommitCandidate,
        "restore_active" => WindowsEffectStage::RestoreActive,
        "record_rejection" => WindowsEffectStage::RecordRejection,
        "commit_and_activate_rollback" => WindowsEffectStage::CommitAndActivateRollback,
        "apply_recovery" => WindowsEffectStage::ApplyRecovery,
        other => panic!("unknown fake effect stage {other:?}"),
    }
}

fn enum_name<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn merge_object(defaults: &Value, overrides: Option<&Value>) -> Value {
    let mut merged = defaults.as_object().unwrap().clone();
    if let Some(overrides) = overrides {
        for (key, value) in overrides.as_object().unwrap() {
            merged.insert(key.clone(), value.clone());
        }
    }
    Value::Object(merged)
}

#[test]
fn windows_harness_executes_platform_adapter_v1_contract() {
    let adapter_contract = fixture();
    let bundle_contract = parse_json(BUNDLE_V1, "route policy bundle contract");
    let manifest_contract = parse_json(MANIFEST_V1, "route policy manifest contract");
    let bundle = resolved_bundle(&bundle_contract, &manifest_contract);
    let keys = trusted_keys(&bundle_contract);

    assert_eq!(adapter_contract["schema_version"], 1);
    assert_eq!(adapter_contract["contract"], "slipstream.platform_adapter");
    assert_eq!(
        adapter_contract["contract_version"],
        WINDOWS_ADAPTER_CONTRACT_VERSION
    );
    assert_eq!(adapter_contract["invariants"]["network_effects"], false);
    assert_eq!(adapter_contract["invariants"]["os_effects"], false);

    for scenario in adapter_contract["activation_scenarios"].as_array().unwrap() {
        let mut adapter = new_adapter(&adapter_contract);
        let mut effects = RecordingWindowsEffects::with_health(health(&scenario["health"]));
        if let Some(failure) = scenario.get("fail_once") {
            effects.fail_once(
                stage(failure["stage"].as_str().unwrap()),
                failure["message"].as_str().unwrap(),
            );
        }

        let result = adapter
            .apply_signed_bundle(&bundle, &keys, &mut effects)
            .unwrap_or_else(|error| panic!("{}: {error}", scenario["name"]));
        let expected = &scenario["expected"];
        assert_eq!(
            result.accepted,
            expected["accepted"].as_bool().unwrap(),
            "{} accepted",
            scenario["name"]
        );
        assert_eq!(
            enum_name(result.decision),
            expected["decision"].as_str().unwrap(),
            "{} decision",
            scenario["name"]
        );
        assert_eq!(
            enum_name(result.reason),
            expected["reason"].as_str().unwrap(),
            "{} reason",
            scenario["name"]
        );
        assert_eq!(
            adapter.active_manifest().unwrap().source,
            expected["active_source"].as_str().unwrap(),
            "{} active source",
            scenario["name"]
        );
        if let Some(fragment) = expected.get("error_contains") {
            assert!(
                result
                    .error
                    .as_deref()
                    .unwrap_or_default()
                    .contains(fragment.as_str().unwrap()),
                "{} error: {:?}",
                scenario["name"],
                result.error
            );
        } else {
            assert_eq!(result.error, None, "{} error", scenario["name"]);
        }

        let actual_effects: Vec<_> = effects.events().iter().map(|event| event.kind()).collect();
        let expected_effects: Vec<_> = expected["effects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(actual_effects, expected_effects, "{}", scenario["name"]);
    }
}

#[test]
fn windows_harness_executes_every_frozen_routing_policy_vector() {
    let adapter_contract = fixture();
    let policy_contract = parse_json(POLICY_V1, "routing policy contract");
    let adapter = new_adapter(&adapter_contract);

    for vector in policy_contract["vectors"].as_array().unwrap() {
        let actual = adapter
            .classify_host(vector["host"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            vector["expected"],
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn windows_harness_executes_every_frozen_recovery_vector_through_fake_effects() {
    let adapter_contract = fixture();
    let recovery_contract = parse_json(RECOVERY_V1, "recovery contract");
    let adapter = new_adapter(&adapter_contract);

    for vector in recovery_contract["vectors"].as_array().unwrap() {
        let outcome: ConnectionOutcome = serde_json::from_value(merge_object(
            &recovery_contract["outcome_defaults"],
            vector.get("outcome"),
        ))
        .unwrap();
        let context: RecoveryContext = serde_json::from_value(merge_object(
            &recovery_contract["context_defaults"],
            vector.get("context"),
        ))
        .unwrap();
        let expected: Vec<RecoveryAction> =
            serde_json::from_value(vector["expected"].clone()).unwrap();
        let mut effects = RecordingWindowsEffects::default();

        let actual = adapter
            .handle_connection_outcome(&outcome, &context, &mut effects)
            .unwrap_or_else(|error| panic!("{}: {error}", vector["name"]));
        assert_eq!(actual, expected, "{}", vector["name"]);

        let recorded: Vec<_> = effects
            .events()
            .iter()
            .map(|event| match event {
                RecordedWindowsEffect::ApplyRecovery { action } => action.clone(),
                other => panic!("unexpected recovery effect {other:?}"),
            })
            .collect();
        let non_empty: Vec<_> = expected
            .into_iter()
            .filter(|action| action.kind != RecoveryActionKind::None)
            .collect();
        assert_eq!(recorded, non_empty, "{} recorded effects", vector["name"]);
        assert!(recorded.iter().all(|action| {
            !(outcome.service_group.is_protected_local_bypass()
                && action.kind == RecoveryActionKind::RestartOwnedGeph)
        }));
    }
}

#[test]
fn windows_harness_consumes_forward_compatible_status_v2() {
    let adapter_contract = fixture();
    let status_contract = parse_json(STATUS_V2, "status contract");
    let mut adapter = new_adapter(&adapter_contract);
    let input = status_contract["vectors"][0]["status"].clone();

    let status = adapter.observe_status(input.clone()).unwrap();
    assert_eq!(status.schema_version, 2);
    assert_eq!(status.updated_at(), 100.0);
    assert_eq!(serde_json::to_value(status).unwrap(), input);
    assert_eq!(
        adapter.status().unwrap().extra["extension_marker"]["enabled"],
        true
    );
}

#[test]
fn windows_harness_verifies_bundle_before_any_effect() {
    let adapter_contract = fixture();
    let bundle_contract = parse_json(BUNDLE_V1, "route policy bundle contract");
    let manifest_contract = parse_json(MANIFEST_V1, "route policy manifest contract");
    let mut bundle = resolved_bundle(&bundle_contract, &manifest_contract);
    let keys = trusted_keys(&bundle_contract);
    let mut adapter = new_adapter(&adapter_contract);
    let mut effects = RecordingWindowsEffects::default();
    bundle["signature"] = Value::String("AA==".to_owned());

    let error = adapter
        .apply_signed_bundle(&bundle, &keys, &mut effects)
        .unwrap_err();
    match error {
        WindowsAdapterError::Bundle(error) => {
            assert_eq!(
                error.code,
                RoutePolicyBundleErrorCode::InvalidSignatureLength
            )
        }
        other => panic!("unexpected error: {other}"),
    }
    assert!(effects.events().is_empty());
    assert_eq!(
        adapter.activation_state().phase,
        PolicyActivationPhase::Stable
    );
}

#[test]
fn windows_harness_rolls_back_only_through_the_effect_boundary() {
    let adapter_contract = fixture();
    let bundle_contract = parse_json(BUNDLE_V1, "route policy bundle contract");
    let manifest_contract = parse_json(MANIFEST_V1, "route policy manifest contract");
    let bundle = resolved_bundle(&bundle_contract, &manifest_contract);
    let keys = trusted_keys(&bundle_contract);
    let mut adapter = new_adapter(&adapter_contract);
    let mut effects = RecordingWindowsEffects::default();

    let apply = adapter
        .apply_signed_bundle(&bundle, &keys, &mut effects)
        .unwrap();
    assert_eq!(
        apply.decision,
        PolicyActivationDecisionKind::CandidateActivated
    );
    effects.clear_events();

    let rollback = adapter.rollback(&mut effects).unwrap();
    assert!(rollback.accepted);
    assert_eq!(rollback.decision, PolicyActivationDecisionKind::RolledBack);
    assert_eq!(adapter.active_manifest().unwrap().source, "bundled:v1");
    assert_eq!(
        effects
            .events()
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>(),
        vec!["commit_and_activate_rollback"]
    );
}

#[test]
fn atomic_rollback_failure_preserves_the_active_policy() {
    let adapter_contract = fixture();
    let bundle_contract = parse_json(BUNDLE_V1, "route policy bundle contract");
    let manifest_contract = parse_json(MANIFEST_V1, "route policy manifest contract");
    let bundle = resolved_bundle(&bundle_contract, &manifest_contract);
    let keys = trusted_keys(&bundle_contract);
    let mut adapter = new_adapter(&adapter_contract);
    let mut effects = RecordingWindowsEffects::default();

    adapter
        .apply_signed_bundle(&bundle, &keys, &mut effects)
        .unwrap();
    let signed_source = adapter.active_manifest().unwrap().source.clone();
    effects.clear_events();
    effects.fail_once(
        WindowsEffectStage::CommitAndActivateRollback,
        "fake atomic rollback unavailable",
    );

    let rollback = adapter.rollback(&mut effects).unwrap();
    assert!(!rollback.accepted);
    assert_eq!(rollback.decision, PolicyActivationDecisionKind::NoChange);
    assert_eq!(adapter.active_manifest().unwrap().source, signed_source);
    assert!(rollback
        .error
        .as_deref()
        .unwrap()
        .contains("commit_and_activate_rollback effect failed"));
    assert_eq!(
        effects
            .events()
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>(),
        vec!["commit_and_activate_rollback"]
    );
}

#[test]
fn compensation_failure_is_hard_and_keeps_the_adapter_in_trial() {
    let adapter_contract = fixture();
    let bundle_contract = parse_json(BUNDLE_V1, "route policy bundle contract");
    let manifest_contract = parse_json(MANIFEST_V1, "route policy manifest contract");
    let bundle = resolved_bundle(&bundle_contract, &manifest_contract);
    let keys = trusted_keys(&bundle_contract);
    let mut adapter = new_adapter(&adapter_contract);
    let mut effects = RecordingWindowsEffects::with_health(HealthEvidence {
        completed: true,
        ok: 1,
        degraded: 1,
        blocked: 0,
        detail: "fake degraded health".to_owned(),
    });
    effects.fail_once(
        WindowsEffectStage::RestoreActive,
        "fake restore unavailable",
    );

    let error = adapter
        .apply_signed_bundle(&bundle, &keys, &mut effects)
        .unwrap_err();
    match error {
        WindowsAdapterError::Effect {
            stage,
            reducer_state,
            ..
        } => {
            assert_eq!(stage, WindowsEffectStage::RestoreActive);
            assert_eq!(reducer_state.phase, PolicyActivationPhase::Stable);
        }
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(
        adapter.activation_state().phase,
        PolicyActivationPhase::Trial
    );
    assert_eq!(
        effects
            .events()
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>(),
        vec![
            "persist_trial_generation",
            "activate_trial",
            "run_health_gate",
            "restore_active",
            "record_rejection"
        ]
    );
}

#[test]
fn invalid_status_does_not_replace_the_last_valid_snapshot() {
    let adapter_contract = fixture();
    let status_contract = parse_json(STATUS_V2, "status contract");
    let mut adapter = new_adapter(&adapter_contract);
    let valid = status_contract["vectors"][0]["status"].clone();
    adapter.observe_status(valid.clone()).unwrap();

    let mut invalid = valid.clone();
    invalid["schema_version"] = Value::from(3);
    assert!(matches!(
        adapter.observe_status(invalid),
        Err(WindowsAdapterError::Status(_))
    ));
    assert_eq!(
        serde_json::to_value(adapter.status().unwrap()).unwrap(),
        valid
    );
}

#[test]
fn harness_source_and_manifest_have_no_native_or_network_dependencies() {
    let source = include_str!("../src/v1.rs");
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
            "no-network harness source contains {forbidden:?}"
        );
        assert!(
            !manifest.contains(forbidden),
            "no-network harness manifest contains {forbidden:?}"
        );
    }
}

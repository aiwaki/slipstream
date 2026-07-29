use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../contracts/windows-capture-generation-recovery-v1.json"
    ))
    .expect("parse Windows capture-generation recovery contract")
}

#[test]
fn capture_generation_recovery_contract_is_frozen_and_disposable() {
    let contract = contract();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract"],
        "slipstream.windows_capture_generation_recovery"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(
        contract["invariants"]["capture_generations"],
        serde_json::json!([1, 2])
    );
    assert_eq!(
        contract["invariants"]["generation_one_absent_before_generation_two"],
        true
    );
    assert_eq!(
        contract["invariants"]["baseline_route_identity_preserved"],
        true
    );
    assert_eq!(contract["invariants"]["driver_install_or_removal"], false);
    assert_eq!(
        contract["invariants"]["production_service_host_composition"],
        false
    );
    assert_eq!(
        contract["disposable_native_qualification"]["architectures"],
        serde_json::json!(["amd64", "arm64"])
    );
}

#[test]
fn native_fixture_reuses_one_owned_name_only_after_exact_absence() {
    let fixture = include_str!("wintun_exact_route_windows.rs").replace("\r\n", "\n");
    let test_start = fixture
        .find("fn native_wintun_same_name_capture_generation_recovers_without_stale_state()")
        .expect("fixture must contain the capture-generation recovery gate");
    let test_end = fixture[test_start..]
        .find("fn native_wintun_route_churn_invalidates_activation_and_cleans_exactly()")
        .map(|offset| test_start + offset)
        .expect("capture-generation gate must end before route-churn qualification");
    let helper_start = fixture
        .find("fn qualify_capture_generation_recovery(")
        .expect("fixture must contain the shared generation helper");
    let helper_end = fixture[helper_start..]
        .find("struct LoadedWintun")
        .map(|offset| helper_start + offset)
        .expect("capture-generation helper must end before the native API wrapper");
    let test = &fixture[test_start..test_end];
    let helper = &fixture[helper_start..helper_end];

    assert!(
        fixture.contains("SLIPSTREAM_WINDOWS_WINTUN_CAPTURE_GENERATION_RECOVERY_CI"),
        "fixture is missing the exact capture-generation gate"
    );
    for required in [
        "let adapter_name = wide(&unique_adapter_name(\"CaptureGeneration\"))",
        "&adapter_name,\n        &tunnel_type,\n        1,",
        "require_adapter_absent(&adapter_name, \"between capture generations\")",
        "&adapter_name,\n        &tunnel_type,\n        2,",
        "require_same_route_observation(&baseline, &recovered",
    ] {
        assert!(
            test.contains(required),
            "recovery gate is missing {required}"
        );
    }

    let generation_one = test
        .find("&adapter_name,\n        &tunnel_type,\n        1,")
        .expect("generation 1 must reuse the owned name");
    let intermediate_absence = test
        .find("require_adapter_absent(&adapter_name, \"between capture generations\")")
        .expect("generation 1 must be absent before generation 2");
    let generation_two = test
        .find("&adapter_name,\n        &tunnel_type,\n        2,")
        .expect("generation 2 must reuse the owned name");
    assert!(generation_one < intermediate_absence && intermediate_absence < generation_two);

    for required in [
        "WindowsOwnedRouteTransitionIssuer::new(capture_generation, capture_interface, 1)",
        "issuer.capture_generation() != capture_generation",
        "wait_for_adapter_absent_until",
        "wait_for_fixture_route_absent_until",
        "wait_for_unicast_address_absent_until",
        "require_same_route_observation",
    ] {
        assert!(
            helper.contains(required),
            "generation helper is missing {required}"
        );
    }
    for forbidden in [
        "WintunDeleteDriver",
        "0.0.0.0/0",
        "::/0",
        "Set-DnsClientServerAddress",
        "ProxyEnable",
        "Command::new",
        "CreateProcess",
        "StartService",
    ] {
        assert!(
            !test.contains(forbidden) && !helper.contains(forbidden),
            "capture-generation gate contains forbidden effect {forbidden}"
        );
    }
}

#[test]
fn native_workflow_runs_the_exact_gate_on_both_architectures() {
    let workflow =
        include_str!("../../../.github/workflows/windows-packet-adapter-qualification.yml")
            .replace("\r\n", "\n");
    for required in [
        "runner: windows-latest\n            architecture: amd64",
        "runner: windows-11-arm\n            architecture: arm64",
        "Qualify same-name Wintun capture-generation recovery",
        "SLIPSTREAM_WINDOWS_WINTUN_CAPTURE_GENERATION_RECOVERY_CI: \"1\"",
        "-TestName native_wintun_same_name_capture_generation_recovers_without_stale_state",
    ] {
        assert!(
            workflow.contains(required),
            "native workflow is missing {required}"
        );
    }
    assert_eq!(
        workflow
            .matches("contracts/windows-capture-generation-recovery-v1.json")
            .count(),
        2,
        "capture-generation contract must trigger both pull_request and main push gates"
    );
}

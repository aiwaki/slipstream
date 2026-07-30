use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../contracts/windows-service-generation-recovery-v1.json"
    ))
    .expect("parse Windows service-generation recovery contract")
}

#[test]
fn service_generation_recovery_contract_is_frozen_and_disposable() {
    let contract = contract();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract"],
        "slipstream.windows_service_generation_recovery"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(
        contract["invariants"]["service_generations"],
        serde_json::json!([1, 2])
    );
    assert_eq!(
        contract["invariants"]["generation_one_absent_before_generation_two"],
        true
    );
    assert_eq!(contract["invariants"]["payload_hashes_differ"], true);
    assert_eq!(contract["invariants"]["independent_owner_preserved"], true);
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
fn native_fixture_reuses_one_service_only_after_exact_absence() {
    let fixture = include_str!("../src/service_native/windows.rs").replace("\r\n", "\n");
    let test_start = fixture
        .find("fn native_service_generation_recovery_replaces_owned_payload_after_exact_absence()")
        .expect("fixture must contain the service-generation recovery gate");
    let test_end = fixture[test_start..]
        .find("fn run_full_lifecycle(")
        .map(|offset| test_start + offset)
        .expect("service-generation gate must end before the existing lifecycle helper");
    let test = &fixture[test_start..test_end];
    let compact: String = test
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();

    assert!(
        fixture.contains("SLIPSTREAM_WINDOWS_SERVICE_GENERATION_RECOVERY_CI"),
        "fixture is missing the exact service-generation gate"
    );
    for required in [
        "letfirst_identity=identity_for(&source,1)",
        "letsecond_identity=identity_for(&second_source,2)",
        "verify_generation_absent_before_reuse(&first_effects,&first_identity)",
        "letsecond_effects=run_owned_generation(",
        "verify_terminal_absence(&second_effects,&second_identity)",
        "fs::read(&independent_owner)",
    ] {
        assert!(
            compact.contains(required),
            "service-generation gate is missing {required}"
        );
    }

    let first_absence = compact
        .find("verify_generation_absent_before_reuse(&first_effects,&first_identity)")
        .expect("generation 1 must prove exact absence");
    let second_install = compact
        .find("letsecond_effects=run_owned_generation(")
        .expect("generation 2 must reuse the service");
    assert!(
        first_absence < second_install,
        "generation 2 started before generation 1 proved exact absence"
    );
    assert_eq!(
        compact.matches("run_owned_generation(&source,").count(),
        1,
        "the gate must qualify generation 1 exactly once"
    );
    assert_eq!(
        compact
            .matches("run_owned_generation(&second_source,")
            .count(),
        1,
        "the gate must qualify generation 2 exactly once"
    );
    assert!(
        fixture.contains("fn verify_generation_absent_before_reuse("),
        "the gate must use the stable exact-absence helper before name reuse"
    );

    for forbidden in [
        "Wintun",
        "0.0.0.0/0",
        "::/0",
        "Set-DnsClientServerAddress",
        "ProxyEnable",
        "CreateProcess",
        "Command::new",
        "production_service_host",
    ] {
        assert!(
            !test.contains(forbidden),
            "service-generation gate contains forbidden effect {forbidden}"
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
        "Qualify same-name Windows service-generation recovery",
        "SLIPSTREAM_WINDOWS_SERVICE_GENERATION_RECOVERY_CI: \"1\"",
        "service_native::windows::tests::native_service_generation_recovery_replaces_owned_payload_after_exact_absence",
    ] {
        assert!(
            workflow.contains(required),
            "native workflow is missing {required}"
        );
    }
    assert_eq!(
        workflow
            .matches("contracts/windows-service-generation-recovery-v1.json")
            .count(),
        1,
        "service-generation contract must be in the pull-request filter; main pushes are intentionally unfiltered"
    );
}

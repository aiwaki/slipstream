use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../contracts/windows-production-host-generation-recovery-v1.json"
    ))
    .expect("parse Windows production-host generation recovery contract")
}

#[test]
fn production_host_generation_recovery_contract_is_frozen_and_disposable() {
    let contract = contract();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract"],
        "slipstream.windows_production_host_generation_recovery"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["invariants"]["real_management_cli"], true);
    assert_eq!(
        contract["invariants"]["service_generations"],
        serde_json::json!([1, 2])
    );
    assert_eq!(
        contract["invariants"]["generation_one_absent_before_generation_two"],
        true
    );
    assert_eq!(contract["invariants"]["payload_hashes_differ"], true);
    assert_eq!(
        contract["invariants"]["durable_absent_intent_matches_generation"],
        true
    );
    assert_eq!(contract["invariants"]["independent_owner_preserved"], true);
    assert_eq!(
        contract["invariants"]["production_networking_composition"],
        false
    );
    assert_eq!(
        contract["disposable_native_qualification"]["architectures"],
        serde_json::json!(["amd64", "arm64"])
    );
}

#[test]
fn production_host_fixture_replaces_only_after_exact_cli_uninstall() {
    let fixture = include_str!("../src/service_host/windows.rs").replace("\r\n", "\n");
    let test_start = fixture
        .find("fn production_host_generation_recovery_uses_exact_cli_uninstall()")
        .expect("fixture must contain the production-host generation gate");
    let test_end = fixture[test_start..]
        .find("fn run_host(")
        .map(|offset| test_start + offset)
        .expect("production-host generation gate must end before the CLI helper");
    let test = &fixture[test_start..test_end];
    let compact: String = test
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();

    for required in [
        "run_host(&first_host,&[\"manage\",\"install\",\"--generation\",\"1\"])",
        "run_host(&first_host,&[\"manage\",\"uninstall\"])",
        "verify_production_generation_absent(&root,&first_identity)",
        "run_host(&second_host,&[\"manage\",\"install\",\"--generation\",\"2\"])",
        "run_host(&second_host,&[\"manage\",\"uninstall\"])",
        "verify_production_generation_absent(&root,&second_identity)",
        "WindowsServiceOwnershipCollector::new().assess()",
        "WindowsServiceLifecycleStateEffects::new().collect().assess()",
        "fs::read(&independent_owner)",
    ] {
        assert!(
            compact.contains(required),
            "production-host generation gate is missing {required}"
        );
    }

    let first_absence = compact
        .find("verify_production_generation_absent(&root,&first_identity)")
        .expect("generation 1 must prove exact absence");
    let second_install = compact
        .find("run_host(&second_host,&[\"manage\",\"install\",\"--generation\",\"2\"])")
        .expect("generation 2 must use the real management CLI");
    assert!(
        first_absence < second_install,
        "generation 2 started before generation 1 proved exact absence"
    );

    for forbidden in [
        "WindowsServiceController",
        "Wintun",
        "0.0.0.0/0",
        "::/0",
        "Set-DnsClientServerAddress",
        "ProxyEnable",
        "production_worker_config",
    ] {
        assert!(
            !test.contains(forbidden),
            "production-host generation gate contains forbidden surface {forbidden}"
        );
    }
}

#[test]
fn native_workflow_runs_the_production_gate_on_both_architectures() {
    let workflow =
        include_str!("../../../.github/workflows/windows-packet-adapter-qualification.yml")
            .replace("\r\n", "\n");
    for required in [
        "runner: windows-latest\n            architecture: amd64",
        "runner: windows-11-arm\n            architecture: arm64",
        "Qualify real production-host generation replacement",
        "SLIPSTREAM_WINDOWS_PRODUCTION_HOST_GENERATION_RECOVERY_CI: \"1\"",
        "service_host::windows::tests::production_host_generation_recovery_uses_exact_cli_uninstall",
    ] {
        assert!(
            workflow.contains(required),
            "native workflow is missing {required}"
        );
    }
    assert_eq!(
        workflow
            .matches("contracts/windows-production-host-generation-recovery-v1.json")
            .count(),
        2,
        "production-host generation contract must trigger pull-request and main gates"
    );
}

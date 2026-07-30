use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../contracts/windows-production-host-crash-recovery-v1.json"
    ))
    .expect("parse Windows production-host crash recovery contract")
}

#[test]
fn production_host_crash_recovery_contract_is_frozen_and_disposable() {
    let contract = contract();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract"],
        "slipstream.windows_production_host_crash_recovery"
    );
    assert_eq!(contract["contract_version"], 1);
    for invariant in [
        "real_management_cli",
        "exact_scm_process_id",
        "held_process_handle",
        "process_image_matches_owned_payload",
        "process_hash_matches_owned_identity",
        "process_creation_time_observed",
        "crash_uses_only_verified_handle",
        "durable_running_intent_survives_crash",
        "recover_uses_public_cli",
        "recovered_process_instance_changes",
        "crash_budget_resets_only_after_readiness",
        "repeated_recover_is_idempotent",
        "independent_owner_preserved",
        "terminal_absence_required",
    ] {
        assert_eq!(contract["invariants"][invariant], true, "{invariant}");
    }
    for invariant in [
        "broad_process_discovery_or_termination",
        "default_route_mutation",
        "system_dns_mutation",
        "proxy_pac_vpn_mutation",
        "external_process_or_service_mutation",
        "driver_install_or_removal",
        "production_networking_composition",
    ] {
        assert_eq!(contract["invariants"][invariant], false, "{invariant}");
    }
    assert_eq!(
        contract["disposable_native_qualification"]["architectures"],
        serde_json::json!(["amd64", "arm64"])
    );
}

#[test]
fn production_host_crash_gate_terminates_only_a_verified_process_handle() {
    let source = include_str!("../src/service_host/windows.rs").replace("\r\n", "\n");
    let test_start = source
        .find("fn production_host_crash_recovery_uses_exact_verified_process()")
        .expect("source must contain the production-host crash gate");
    let helper_start = source[test_start..]
        .find("struct OwnedTestProcessHandle")
        .map(|offset| test_start + offset)
        .expect("crash gate must retain an exact process handle");
    let test = &source[test_start..helper_start];
    let helper = &source[helper_start..];
    let compact_test: String = test
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let compact_helper: String = helper
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();

    for required in [
        "run_host(&host,&[\"manage\",\"install\",\"--generation\",\"31\"])",
        "letcrashed_process=terminate_exact_production_host_process(&active,&identity,&root)",
        "run_host(&host,&[\"manage\",\"recover\"])",
        "WindowsServiceDecision::Restarted",
        "assert_ne!(recovered_process,crashed_process",
        "run_host(&host,&[\"manage\",\"uninstall\"])",
        "verify_production_generation_absent(&root,&identity)",
        "fs::read(&independent_owner)",
    ] {
        assert!(
            compact_test.contains(required),
            "production-host crash gate is missing {required}"
        );
    }

    for required in [
        "PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|SYNCHRONIZE",
        "QueryFullProcessImageNameW",
        "GetProcessTimes",
        "hash_source(&observed_path)",
        "TerminateProcess(self.0",
        "WaitForSingleObject(self.0",
        "WAIT_FAILED",
    ] {
        assert!(
            compact_helper.contains(required),
            "exact process helper is missing {required}"
        );
    }

    for forbidden in [
        "taskkill",
        "Stop-Process",
        "EnumProcesses",
        "CreateToolhelp32Snapshot",
        "Wintun",
        "0.0.0.0/0",
        "::/0",
        "Set-DnsClientServerAddress",
        "ProxyEnable",
    ] {
        assert!(
            !test.contains(forbidden) && !helper.contains(forbidden),
            "production-host crash gate contains forbidden surface {forbidden}"
        );
    }
}

#[test]
fn native_workflow_runs_the_crash_gate_on_both_architectures() {
    let workflow =
        include_str!("../../../.github/workflows/windows-packet-adapter-qualification.yml")
            .replace("\r\n", "\n");
    for required in [
        "runner: windows-latest\n            architecture: amd64",
        "runner: windows-11-arm\n            architecture: arm64",
        "Qualify real production-host exact crash recovery",
        "SLIPSTREAM_WINDOWS_PRODUCTION_HOST_CRASH_RECOVERY_CI: \"1\"",
        "service_host::windows::tests::production_host_crash_recovery_uses_exact_verified_process",
    ] {
        assert!(
            workflow.contains(required),
            "native workflow is missing {required}"
        );
    }
    assert_eq!(
        workflow
            .matches("contracts/windows-production-host-crash-recovery-v1.json")
            .count(),
        2,
        "production-host crash contract must trigger pull-request and main gates"
    );
}

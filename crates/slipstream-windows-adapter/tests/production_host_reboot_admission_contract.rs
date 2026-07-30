use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../contracts/windows-production-host-reboot-admission-v1.json"
    ))
    .expect("parse Windows production-host reboot-admission contract")
}

#[test]
fn production_host_reboot_admission_contract_is_frozen_and_bounded() {
    let contract = contract();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract"],
        "slipstream.windows_production_host_reboot_admission"
    );
    assert_eq!(contract["contract_version"], 1);
    for invariant in [
        "real_management_cli",
        "automatic_start_registration",
        "own_process_service_type",
        "normal_error_control",
        "configuration_revalidated_before_install_start_recover",
        "configuration_drift_fails_closed",
        "stopped_intent_remains_stopped_on_scm_start",
        "unknown_or_inconsistent_intent_fails_closed",
        "explicit_start_required_to_resume_stopped_intent",
        "stop_and_uninstall_remain_available_for_exact_cleanup",
        "independent_owner_preserved",
        "terminal_absence_required",
    ] {
        assert_eq!(contract["invariants"][invariant], true, "{invariant}");
    }
    for invariant in [
        "physical_reboot_claimed",
        "production_networking_composition",
        "default_route_mutation",
        "system_dns_mutation",
        "proxy_pac_vpn_mutation",
        "external_process_or_service_mutation",
        "driver_install_or_removal",
    ] {
        assert_eq!(contract["invariants"][invariant], false, "{invariant}");
    }
    assert_eq!(
        contract["disposable_native_qualification"]["architectures"],
        serde_json::json!(["amd64", "arm64"])
    );
    assert_eq!(
        contract["disposable_native_qualification"]["generation"],
        41
    );
    assert_eq!(
        contract["disposable_native_qualification"]["direct_scm_start_with_stopped_intent"],
        true
    );
}

#[test]
fn production_registration_and_controller_enforce_exact_reboot_admission() {
    let observer = include_str!("../src/service_observer/windows.rs").replace("\r\n", "\n");
    let scm = include_str!("../src/service_scm/windows.rs").replace("\r\n", "\n");
    let controller = include_str!("../src/service_controller/windows.rs").replace("\r\n", "\n");
    let production_scm = scm
        .rsplit_once("#[cfg(test)]\nmod tests")
        .map(|(production, _)| production)
        .expect("SCM source must have a production section");

    for required in [
        "pub(crate) struct WindowsServiceConfiguration",
        "pub(crate) fn query_open_service_configuration",
        "service_type: unsafe { (*config).dwServiceType }",
        "start_type: unsafe { (*config).dwStartType }",
        "error_control: unsafe { (*config).dwErrorControl }",
    ] {
        assert!(
            observer.contains(required),
            "read-only SCM configuration observer is missing {required}"
        );
    }
    for required in [
        "SERVICE_AUTO_START",
        "require_reboot_admission_if_present_locked",
        "WindowsServiceScmError::ConfigurationMismatch",
    ] {
        assert!(
            production_scm.contains(required),
            "production SCM effect is missing {required}"
        );
    }
    assert!(
        !production_scm.contains("SERVICE_DEMAND_START"),
        "production registration must not remain demand-start"
    );

    for required in [
        "command_requires_reboot_admission(command)",
        "WindowsServiceCommand::Install",
        "WindowsServiceCommand::Start",
        "WindowsServiceCommand::CrashObserved",
    ] {
        assert!(
            controller.contains(required),
            "command-wide controller admission is missing {required}"
        );
    }
    let preflight = controller
        .find("native.require_reboot_admission_if_present_locked()?;")
        .expect("controller must perform command-wide reboot admission");
    let reduction = controller
        .find("lifecycle.execute(command, &mut effects)")
        .expect("controller must execute the lifecycle reducer");
    assert!(
        preflight < reduction,
        "configuration admission must run before a no-change reducer result can be accepted"
    );

    let host = include_str!("../src/service_host/windows.rs").replace("\r\n", "\n");
    for required in [
        "observe_windows_service_boot_admission()",
        "WindowsServiceBootAdmission::RemainStopped",
        "WindowsServiceBootAdmission::Refuse",
        "require_reboot_admission_configuration(&configuration)",
    ] {
        assert!(
            host.contains(required),
            "production service boot entry is missing {required}"
        );
    }
}

#[test]
fn native_gate_injects_drift_and_preserves_cleanup() {
    let source = include_str!("../src/service_host/windows.rs").replace("\r\n", "\n");
    let test_start = source
        .find("fn production_host_reboot_admission_requires_exact_automatic_start_configuration()")
        .expect("source must contain the production-host reboot-admission gate");
    let helper_start = source[test_start..]
        .find("fn production_host_generation_recovery_uses_exact_cli_uninstall()")
        .map(|offset| test_start + offset)
        .expect("reboot-admission gate must precede the generation gate");
    let test = &source[test_start..helper_start];
    let compact: String = test
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();

    for required in [
        "run_host(&host,&[\"manage\",\"install\",\"--generation\",\"41\"])",
        "assert_reboot_admission_configuration()",
        "assert_durable_intent(WindowsServiceDesiredState::Stopped)",
        "start_exact_service_through_scm()",
        "assert_durable_intent(WindowsServiceDesiredState::Running)",
        "change_exact_service_start_type(SERVICE_DEMAND_START)",
        "assert_host_rejects_configuration_drift(&host,&[\"manage\",\"recover\"])",
        "assert_host_rejects_configuration_drift(&host,&[\"manage\",\"start\"])",
        "run_host(&host,&[\"manage\",\"stop\"])",
        "run_host(&host,&[\"manage\",\"uninstall\"])",
        "verify_production_generation_absent(&root,&identity)",
        "fs::read(&independent_owner)",
    ] {
        assert!(
            compact.contains(required),
            "production-host reboot-admission gate is missing {required}"
        );
    }
    for forbidden in [
        "Restart-Computer",
        "shutdown.exe",
        "Wintun",
        "0.0.0.0/0",
        "::/0",
        "Set-DnsClientServerAddress",
        "ProxyEnable",
    ] {
        assert!(
            !test.contains(forbidden),
            "reboot-admission gate contains forbidden surface {forbidden}"
        );
    }
}

#[test]
fn native_workflow_runs_reboot_admission_on_both_architectures() {
    let workflow =
        include_str!("../../../.github/workflows/windows-packet-adapter-qualification.yml")
            .replace("\r\n", "\n");
    for required in [
        "runner: windows-latest\n            architecture: amd64",
        "runner: windows-11-arm\n            architecture: arm64",
        "Qualify production-host reboot admission",
        "SLIPSTREAM_WINDOWS_PRODUCTION_HOST_REBOOT_ADMISSION_CI: \"1\"",
        "service_host::windows::tests::production_host_reboot_admission_requires_exact_automatic_start_configuration",
    ] {
        assert!(
            workflow.contains(required),
            "native workflow is missing {required}"
        );
    }
    assert_eq!(
        workflow
            .matches("contracts/windows-production-host-reboot-admission-v1.json")
            .count(),
        2,
        "reboot-admission contract must trigger pull-request and main gates"
    );
}

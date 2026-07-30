use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../contracts/windows-production-host-physical-reboot-v1.json"
    ))
    .expect("parse Windows production-host physical-reboot contract")
}

#[test]
fn physical_reboot_contract_is_frozen_and_does_not_claim_runtime_evidence() {
    let contract = contract();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(
        contract["contract"],
        "slipstream.windows_production_host_physical_reboot"
    );
    assert_eq!(contract["service_name"], "dev.slipstream.service");
    assert_eq!(
        contract["harness"]["phases"],
        serde_json::json!(["prepare", "resume", "cleanup"])
    );
    assert_eq!(contract["harness"]["automatic_reboot"], false);
    assert_eq!(
        contract["runtime_evidence"]["physical_reboot_claimed_by_static_contract"],
        false
    );
    assert_eq!(
        contract["runtime_evidence"]["successful_result_required_for_claim"],
        true
    );
    assert_eq!(contract["runtime_evidence"]["required_outcome"], "passed");

    for required in [
        "administrator_required",
        "exact_service_absence_required_before_prepare",
        "real_management_cli",
        "automatic_start_registration",
        "committed_active_install_required_before_reboot",
        "physical_boot_identity_must_change",
        "post_boot_running_state_required",
        "post_boot_process_created_in_current_boot",
        "exact_executable_identity_required",
        "dns_proxy_pac_snapshot_is_read_only",
        "dns_proxy_pac_snapshot_must_match_after_reboot",
        "independent_owner_preserved",
        "exact_uninstall_required",
        "terminal_product_absence_required",
        "failed_resume_attempts_exact_owned_rollback",
        "identity_mismatch_refuses_mutation",
        "manual_reboot_required",
    ] {
        assert_eq!(
            contract["invariants"][required], true,
            "missing required invariant {required}"
        );
    }
    for prohibited in [
        "production_networking_composition",
        "default_route_mutation",
        "system_dns_mutation",
        "proxy_pac_vpn_mutation",
        "external_process_or_service_mutation",
        "driver_install_or_removal",
    ] {
        assert_eq!(
            contract["invariants"][prohibited], false,
            "physical reboot harness must keep {prohibited} closed"
        );
    }
}

#[test]
fn physical_reboot_harness_is_two_phase_exact_owned_and_non_rebooting() {
    let source = include_str!("../../../scripts/qualify_windows_production_host_reboot.ps1");

    for required in [
        r#"[ValidateSet("prepare", "resume", "cleanup")]"#,
        r#"$ServiceName = "dev.slipstream.service""#,
        "Get-CimInstance -ClassName Win32_OperatingSystem",
        "LastBootUpTime",
        "Get-CimInstance -ClassName Win32_Service",
        r#""manage", "install", "--generation""#,
        r#""manage", "uninstall""#,
        "service-active-v1.json",
        "service-owner-v1.json",
        "service-intent-v1.json",
        "Wait-ExactServiceReady",
        "Assert-ExactTerminalAbsence",
        "Assert-TransactionTerminalAbsence",
        "Invoke-ExactRollback",
        "independent-owner.sentinel",
        ".slipstream-physical-reboot-v1",
        "newly created, empty, or already owned by this harness",
        "Get-DnsClientServerAddress",
        "Get-ItemProperty",
        "WinHttpSettings",
        r#"$result = $text | ConvertFrom-Json"#,
        r#"$shortText = $shortText.Substring"#,
        r#"$Owner.scm_binary_path -Expected $Transaction.scm_binary_path"#,
        r#"$processTime -lt $bootTime"#,
        "The Windows boot identity did not change",
    ] {
        assert!(
            source.contains(required),
            "physical reboot harness is missing {required}"
        );
    }
    assert!(
        !source.contains(r#"$text = $text.Substring"#),
        "management JSON must be parsed before any diagnostic truncation"
    );

    for forbidden in [
        "Restart-Computer",
        "shutdown.exe",
        "Stop-Process",
        "taskkill",
        "Set-DnsClientServerAddress",
        "Set-NetIPInterface",
        "New-NetRoute",
        "Remove-NetRoute",
        "Set-NetRoute",
        "Set-ItemProperty",
        "Remove-Service",
        "sc.exe delete",
        "pkill",
    ] {
        assert!(
            !source.contains(forbidden),
            "physical reboot harness contains forbidden surface {forbidden}"
        );
    }
}

#[test]
fn native_workflow_parses_harness_on_both_windows_architectures() {
    let workflow =
        include_str!("../../../.github/workflows/windows-packet-adapter-qualification.yml")
            .replace('\r', "");
    let push_section = workflow
        .split_once("\n  push:\n")
        .and_then(|(_, rest)| rest.split_once("\n\npermissions:"))
        .map(|(section, _)| section.trim())
        .expect("native workflow must define a bounded main push trigger");
    assert_eq!(
        push_section, "branches: [\"main\"]",
        "main push qualification must remain unfiltered"
    );
    assert!(workflow.contains("Parse physical reboot qualification harness"));
    assert!(workflow.contains("qualify_windows_production_host_reboot.ps1"));
    assert!(workflow.contains(r#""contracts/windows-production-host-physical-reboot-v1.json""#));
    assert!(workflow.contains(r#""scripts/qualify_windows_production_host_reboot.ps1""#));
    assert!(
        workflow
            .matches("scripts/qualify_windows_production_host_reboot.ps1")
            .count()
            >= 4,
        "physical reboot harness must trigger PR/main gates, be parsed, qualified, and packaged natively"
    );
    for required in [
        "Qualify the exact physical reboot production host before packaging",
        "--release `",
        "--bin slipstream-windows-service",
        r#"$result.outcome -ne "cleanup_only""#,
        "exact_uninstall_verified",
        "Package the exact physical reboot qualification bundle",
        "artifact-manifest-v1.json",
        "slipstream.windows_physical_reboot_qualification",
        "slipstream-windows-service.exe",
        "SOURCE_COMMIT: ${{ github.sha }}",
        "github.event_name == 'push' && github.ref == 'refs/heads/main'",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "slipstream-windows-physical-reboot-${{ matrix.architecture }}-${{ github.sha }}",
    ] {
        assert!(
            workflow.contains(required),
            "native workflow is missing qualified artifact invariant {required}"
        );
    }
}

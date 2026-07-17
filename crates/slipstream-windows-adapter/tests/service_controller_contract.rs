use slipstream_windows_adapter::service_controller::{
    reconstruct_windows_service_state, WindowsServiceReconciliationError,
    WINDOWS_SERVICE_CONTROLLER_CONTRACT_VERSION,
};
use slipstream_windows_adapter::service_lifecycle::{
    RecordingWindowsServiceEffects, WindowsServiceCommand, WindowsServiceDecision,
    WindowsServiceDesiredState, WindowsServiceIdentity, WindowsServiceLifecycleV1,
    WindowsServiceObservedState, WindowsServiceOwnership, WINDOWS_SERVICE_NAME,
};
use slipstream_windows_adapter::service_lifecycle_state::{
    WindowsServiceActiveInstallRecordV1, WindowsServiceIntentRecordV1,
    WindowsServiceLifecycleStateAssessment,
};
use slipstream_windows_adapter::service_ownership::{
    WindowsServiceOwnershipAssessment, WindowsServiceOwnershipReason,
};

fn identity(generation: u64, digit: char) -> WindowsServiceIdentity {
    WindowsServiceIdentity {
        service_name: WINDOWS_SERVICE_NAME.to_owned(),
        executable_sha256: digit.to_string().repeat(64),
        generation,
    }
}

fn intent(
    desired: WindowsServiceDesiredState,
    identity: Option<WindowsServiceIdentity>,
    crash_restart_attempts: u32,
) -> WindowsServiceIntentRecordV1 {
    WindowsServiceIntentRecordV1::new(desired, identity, crash_restart_attempts).unwrap()
}

fn active(identity: WindowsServiceIdentity) -> WindowsServiceActiveInstallRecordV1 {
    WindowsServiceActiveInstallRecordV1::new(identity).unwrap()
}

fn stable(
    intent: Option<WindowsServiceIntentRecordV1>,
    active_install: Option<WindowsServiceActiveInstallRecordV1>,
) -> WindowsServiceLifecycleStateAssessment {
    WindowsServiceLifecycleStateAssessment::Stable {
        intent,
        active_install,
    }
}

fn ownership(
    ownership: WindowsServiceOwnership,
    observed: WindowsServiceObservedState,
    identity: Option<WindowsServiceIdentity>,
    reason: WindowsServiceOwnershipReason,
) -> WindowsServiceOwnershipAssessment {
    WindowsServiceOwnershipAssessment {
        ownership,
        observed,
        identity,
        reason,
    }
}

#[test]
fn controller_v1_reconstructs_fresh_terminal_and_owned_states() {
    assert_eq!(WINDOWS_SERVICE_CONTROLLER_CONTRACT_VERSION, 1);
    let absent = ownership(
        WindowsServiceOwnership::Absent,
        WindowsServiceObservedState::Absent,
        None,
        WindowsServiceOwnershipReason::Absent,
    );

    let fresh = reconstruct_windows_service_state(&stable(None, None), &absent).unwrap();
    assert_eq!(
        fresh,
        slipstream_windows_adapter::service_lifecycle::WindowsServiceState::absent()
    );

    let exact = identity(7, 'a');
    let tombstone = intent(WindowsServiceDesiredState::Absent, Some(exact.clone()), 0);
    let terminal =
        reconstruct_windows_service_state(&stable(Some(tombstone), None), &absent).unwrap();
    assert_eq!(terminal, fresh);

    let running_intent = intent(WindowsServiceDesiredState::Running, Some(exact.clone()), 2);
    let running = reconstruct_windows_service_state(
        &stable(Some(running_intent), Some(active(exact.clone()))),
        &ownership(
            WindowsServiceOwnership::Owned,
            WindowsServiceObservedState::Stopped,
            Some(exact.clone()),
            WindowsServiceOwnershipReason::Owned,
        ),
    )
    .unwrap();
    assert_eq!(running.desired, WindowsServiceDesiredState::Running);
    assert_eq!(running.observed, WindowsServiceObservedState::Stopped);
    assert_eq!(running.active, Some(exact));
    assert_eq!(running.crash_restart_attempts, 2);
}

#[test]
fn foreign_and_unknown_ownership_are_neutralized_before_reducer_execution() {
    let foreign = ownership(
        WindowsServiceOwnership::Foreign,
        WindowsServiceObservedState::Running,
        None,
        WindowsServiceOwnershipReason::ServiceWithoutRecord,
    );
    let state = reconstruct_windows_service_state(&stable(None, None), &foreign).unwrap();
    assert_eq!(state.desired, WindowsServiceDesiredState::Unknown);
    assert_eq!(state.ownership, WindowsServiceOwnership::Foreign);

    for command in [
        WindowsServiceCommand::Install {
            identity: identity(1, 'b'),
        },
        WindowsServiceCommand::Start,
        WindowsServiceCommand::Stop,
        WindowsServiceCommand::CrashObserved,
        WindowsServiceCommand::Uninstall,
    ] {
        let mut lifecycle = WindowsServiceLifecycleV1::new(state.clone()).unwrap();
        let mut effects = RecordingWindowsServiceEffects::default();
        let result = lifecycle.execute(&command, &mut effects).unwrap();
        assert!(matches!(
            result.decision,
            WindowsServiceDecision::Refused | WindowsServiceDecision::NoChange
        ));
        assert!(effects.events().is_empty());
    }
}

#[test]
fn lifecycle_evidence_barriers_stop_reconciliation() {
    let absent = ownership(
        WindowsServiceOwnership::Absent,
        WindowsServiceObservedState::Absent,
        None,
        WindowsServiceOwnershipReason::Absent,
    );
    for (assessment, expected) in [
        (
            WindowsServiceLifecycleStateAssessment::InterruptedWrite,
            WindowsServiceReconciliationError::InterruptedWrite,
        ),
        (
            WindowsServiceLifecycleStateAssessment::Unknown,
            WindowsServiceReconciliationError::UnknownLifecycleState,
        ),
        (
            WindowsServiceLifecycleStateAssessment::Inconsistent,
            WindowsServiceReconciliationError::InconsistentLifecycleState,
        ),
    ] {
        assert_eq!(
            reconstruct_windows_service_state(&assessment, &absent),
            Err(expected)
        );
    }
}

#[test]
fn cross_domain_mismatches_never_become_actionable_state() {
    let exact = identity(3, 'c');
    let other = identity(4, 'd');
    let running = intent(WindowsServiceDesiredState::Running, Some(exact.clone()), 0);
    let committed = stable(Some(running.clone()), Some(active(exact.clone())));

    let absent = ownership(
        WindowsServiceOwnership::Absent,
        WindowsServiceObservedState::Absent,
        None,
        WindowsServiceOwnershipReason::Absent,
    );
    assert!(matches!(
        reconstruct_windows_service_state(&committed, &absent),
        Err(WindowsServiceReconciliationError::CrossEvidence(_))
    ));

    let wrong_identity = ownership(
        WindowsServiceOwnership::Owned,
        WindowsServiceObservedState::Running,
        Some(other),
        WindowsServiceOwnershipReason::Owned,
    );
    assert!(matches!(
        reconstruct_windows_service_state(&committed, &wrong_identity),
        Err(WindowsServiceReconciliationError::CrossEvidence(_))
    ));

    let owned_without_commit = ownership(
        WindowsServiceOwnership::Owned,
        WindowsServiceObservedState::Running,
        Some(exact.clone()),
        WindowsServiceOwnershipReason::Owned,
    );
    assert!(matches!(
        reconstruct_windows_service_state(&stable(Some(running), None), &owned_without_commit),
        Err(WindowsServiceReconciliationError::CrossEvidence(_))
    ));
}

#[test]
fn native_controller_holds_one_lock_across_reconstruction_and_execution() {
    let source = include_str!("../src/service_controller/windows.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production controller source");
    let execute = production
        .split("pub fn execute(")
        .nth(1)
        .expect("controller execute implementation");
    let lock = execute.find("acquire_service_operation_lock()?").unwrap();
    let lifecycle = execute
        .find("WindowsServiceLifecycleStateEffects::new()")
        .unwrap();
    let ownership = execute
        .find("WindowsServiceOwnershipCollector::new().assess()")
        .unwrap();
    let reconstruction = execute.find("reconstruct_windows_service_state").unwrap();
    let command = execute.find(".execute(command, &mut effects)").unwrap();
    assert!(lock < lifecycle);
    assert!(lifecycle < ownership);
    assert!(ownership < reconstruction);
    assert!(reconstruction < command);
    assert!(production.contains("self.inner.apply_locked(action)"));

    for forbidden in [
        "std::net",
        "TcpStream",
        "UdpSocket",
        "WinHttp",
        "DnsQuery",
        "Set-DnsClientServerAddress",
        "netsh",
        "ProxyEnable",
        "Vpn",
        "EnumServicesStatus",
        "TerminateProcess",
        "OpenProcess",
        "std::process::Command",
    ] {
        assert!(
            !production.contains(forbidden),
            "native controller contains forbidden surface {forbidden:?}"
        );
    }
}

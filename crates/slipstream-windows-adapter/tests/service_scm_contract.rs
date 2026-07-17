use serde::Deserialize;
use slipstream_windows_adapter::service_lifecycle::{
    WindowsServiceAction, WindowsServiceActionKind, WindowsServiceDesiredState,
    WindowsServiceIdentity, WINDOWS_SERVICE_NAME,
};
use slipstream_windows_adapter::service_lifecycle_state::{
    WindowsServiceActiveInstallRecordV1, WindowsServiceIntentRecordV1,
    WindowsServiceLifecycleStateAssessment,
};
use slipstream_windows_adapter::service_observer::WindowsServiceObservation;
use slipstream_windows_adapter::service_ownership::WindowsStagedPayloadEvidence;
use slipstream_windows_adapter::service_scm::{
    assess_windows_service_scm_action, WindowsServiceScmGateDecision,
    WINDOWS_SERVICE_SCM_GATE_CONTRACT_VERSION,
};
use std::collections::BTreeMap;

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../contracts/windows-service-scm-gate-v1.json"
    ))
    .expect("valid Windows SCM gate fixture")
}

#[test]
fn windows_service_scm_gate_executes_every_v1_vector() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_service_scm_gate");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_SERVICE_SCM_GATE_CONTRACT_VERSION
    );
    assert_eq!(fixture.service_name, WINDOWS_SERVICE_NAME);
    for invariant in [
        "action_specific",
        "stable_lifecycle_state_required",
        "exact_staged_payload_required",
        "same_service_identity_required",
        "register_requires_absence",
        "foreign_or_unknown_service_is_never_mutated",
        "transitional_service_is_never_mutated",
        "install_rollback_absent_intent_is_supported",
    ] {
        assert!(fixture.invariants[invariant], "invariant {invariant}");
    }
    assert!(!fixture.invariants["network_effects"]);

    for vector in fixture.vectors {
        let identity = fixture.identities[&vector.identity].clone();
        let action = action(vector.action, identity);
        let lifecycle = fixture.lifecycle_states[&vector.lifecycle].assessment(&fixture.identities);
        let decision = assess_windows_service_scm_action(
            &action,
            &lifecycle,
            &fixture.observations[&vector.observation],
            &fixture.payloads[&vector.payload],
        );
        assert_eq!(decision, vector.expected, "vector {}", vector.name);
    }
}

#[test]
fn native_scm_source_is_exactly_scoped_and_has_no_network_or_process_surface() {
    let source = include_str!("../src/service_scm/windows.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production SCM source");

    for required in [
        "WINDOWS_SERVICE_NAME",
        "OpenSCManagerW",
        "OpenServiceW",
        "CreateServiceW",
        "StartServiceW",
        "ControlService",
        "DeleteService",
        "SERVICE_QUERY_CONFIG",
        "SERVICE_QUERY_STATUS",
        "assess_windows_service_scm_action",
        "observe_open_service_handle",
        "collect_staged_payload",
        "state_effects.collect()",
        "acquire_service_operation_lock",
        "wait_for_stopped",
    ] {
        assert!(
            production.contains(required),
            "SCM effect must use {required}"
        );
    }
    for forbidden in [
        "EnumServicesStatus",
        "ChangeServiceConfig",
        "SC_MANAGER_ALL_ACCESS",
        "SERVICE_ALL_ACCESS",
        "TerminateProcess",
        "OpenProcess",
        "std::process::Command",
        "Command::",
        "TcpStream",
        "UdpSocket",
        "WinHttp",
        "InternetOpen",
        "DnsQuery",
        "Set-DnsClientServerAddress",
        "netsh",
        "ProxyEnable",
        "Vpn",
    ] {
        assert!(
            !production.contains(forbidden),
            "SCM effect must not contain {forbidden}"
        );
    }
}

#[test]
fn native_operation_lock_is_machine_wide_bounded_and_owner_only() {
    let source = include_str!("../src/service_operation_lock.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production operation-lock source");

    for required in [
        r#"Global\SlipstreamServiceLifecycleV1"#,
        "CreateMutexW",
        "WaitForSingleObject",
        "WAIT_TIMEOUT",
        "ReleaseMutex",
        "OWNER_ONLY_SDDL",
        "OPERATION_LOCK_TIMEOUT_MS",
    ] {
        assert!(
            production.contains(required),
            "operation lock must use {required}"
        );
    }
    for forbidden in [
        "TcpStream",
        "UdpSocket",
        "WinHttp",
        "DnsQuery",
        "Set-DnsClientServerAddress",
        "netsh",
        "ProxyEnable",
        "Vpn",
    ] {
        assert!(
            !production.contains(forbidden),
            "operation lock must not contain {forbidden}"
        );
    }
}

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    service_name: String,
    invariants: BTreeMap<String, bool>,
    identities: BTreeMap<String, WindowsServiceIdentity>,
    lifecycle_states: BTreeMap<String, LifecycleWire>,
    payloads: BTreeMap<String, WindowsStagedPayloadEvidence>,
    observations: BTreeMap<String, WindowsServiceObservation>,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    action: WindowsServiceActionKind,
    identity: String,
    lifecycle: String,
    payload: String,
    observation: String,
    expected: WindowsServiceScmGateDecision,
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum LifecycleWire {
    Stable {
        intent: Option<IntentWire>,
        active_install: Option<String>,
    },
    InterruptedWrite,
    Unknown,
    Inconsistent,
}

impl LifecycleWire {
    fn assessment(
        &self,
        identities: &BTreeMap<String, WindowsServiceIdentity>,
    ) -> WindowsServiceLifecycleStateAssessment {
        match self {
            Self::Stable {
                intent,
                active_install,
            } => WindowsServiceLifecycleStateAssessment::Stable {
                intent: intent.as_ref().map(|wire| wire.record(identities)),
                active_install: active_install.as_ref().map(|name| {
                    WindowsServiceActiveInstallRecordV1::new(identities[name].clone())
                        .expect("valid active-install fixture")
                }),
            },
            Self::InterruptedWrite => WindowsServiceLifecycleStateAssessment::InterruptedWrite,
            Self::Unknown => WindowsServiceLifecycleStateAssessment::Unknown,
            Self::Inconsistent => WindowsServiceLifecycleStateAssessment::Inconsistent,
        }
    }
}

#[derive(Deserialize)]
struct IntentWire {
    desired: WindowsServiceDesiredState,
    identity: Option<String>,
    crash_restart_attempts: u32,
}

impl IntentWire {
    fn record(
        &self,
        identities: &BTreeMap<String, WindowsServiceIdentity>,
    ) -> WindowsServiceIntentRecordV1 {
        WindowsServiceIntentRecordV1::new(
            self.desired,
            self.identity.as_ref().map(|name| identities[name].clone()),
            self.crash_restart_attempts,
        )
        .expect("valid intent fixture")
    }
}

fn action(
    kind: WindowsServiceActionKind,
    identity: WindowsServiceIdentity,
) -> WindowsServiceAction {
    match kind {
        WindowsServiceActionKind::RegisterService => {
            WindowsServiceAction::RegisterService { identity }
        }
        WindowsServiceActionKind::StartOwnedService => {
            WindowsServiceAction::StartOwnedService { identity }
        }
        WindowsServiceActionKind::StopOwnedService => {
            WindowsServiceAction::StopOwnedService { identity }
        }
        WindowsServiceActionKind::UnregisterOwnedService => {
            WindowsServiceAction::UnregisterOwnedService { identity }
        }
        WindowsServiceActionKind::VerifyReady => WindowsServiceAction::VerifyReady { identity },
        other => panic!("fixture action {other:?} is not mapped"),
    }
}

use serde::Deserialize;
use serde_json::Value;
use slipstream_windows_adapter::wfp_capture::WindowsWfpCaptureIdentity;
use slipstream_windows_adapter::wfp_runtime::{WindowsWfpRuntimeBinding, WindowsWfpRuntimeCommand};
use slipstream_windows_adapter::wfp_session::{
    decode_windows_wfp_provider_context_v1, prepare_windows_wfp_dynamic_session_plan,
    RecordingWindowsWfpManagementApi, WindowsWfpDynamicSessionController,
    WindowsWfpManagementObject, WindowsWfpSessionCompletion, WindowsWfpSessionError,
    WINDOWS_WFP_CALLOUT_V4_KEY, WINDOWS_WFP_CALLOUT_V6_KEY, WINDOWS_WFP_CAPTURE_PROTOCOL,
    WINDOWS_WFP_CAPTURE_REMOTE_PORT, WINDOWS_WFP_FILTER_V4_KEY, WINDOWS_WFP_FILTER_V6_KEY,
    WINDOWS_WFP_PROVIDER_CONTEXT_KEY, WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH,
    WINDOWS_WFP_PROVIDER_CONTEXT_VERSION, WINDOWS_WFP_PROVIDER_KEY,
    WINDOWS_WFP_SESSION_CONTRACT_VERSION, WINDOWS_WFP_SUBLAYER_KEY,
    WINDOWS_WFP_TRANSACTION_OBJECT_ORDER,
};
use std::collections::BTreeMap;

const CONTRACT: &str = include_str!("../../../contracts/windows-wfp-session-v1.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    object_keys: BTreeMap<String, String>,
    transaction_order: Vec<String>,
    provider_context: ProviderContextFixture,
    identity: WindowsWfpCaptureIdentity,
    binding: WindowsWfpRuntimeBinding,
    session_generation: u64,
}

#[derive(Debug, Deserialize)]
struct ProviderContextFixture {
    version: u16,
    length: usize,
    magic: String,
    protocol: u8,
    remote_port: u16,
    reserved_offset: usize,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Windows WFP session v1 must be valid JSON")
}

fn controller(
    fixture: &ContractFixture,
) -> WindowsWfpDynamicSessionController<RecordingWindowsWfpManagementApi> {
    WindowsWfpDynamicSessionController::new(
        fixture.identity.clone(),
        RecordingWindowsWfpManagementApi::default(),
    )
    .expect("construct WFP session controller")
}

fn commit_command(fixture: &ContractFixture) -> WindowsWfpRuntimeCommand {
    WindowsWfpRuntimeCommand::CommitAtomicDynamicSession {
        binding: fixture.binding.clone(),
        session_generation: fixture.session_generation,
        target_pid: fixture.identity.target_pid,
    }
}

fn authorize_activation(
    controller: &mut WindowsWfpDynamicSessionController<RecordingWindowsWfpManagementApi>,
    fixture: &ContractFixture,
) {
    controller
        .record_kernel_callouts_registered(&fixture.binding)
        .expect("record exact kernel registration");
    controller
        .record_owned_listeners_ready(&fixture.binding, &fixture.identity.listeners)
        .expect("record exact listener readiness");
}

#[test]
fn contract_freezes_owned_keys_context_and_transaction_order() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_wfp_session");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_WFP_SESSION_CONTRACT_VERSION
    );
    assert_eq!(
        fixture.invariants["production_service_host_composition"],
        false
    );
    assert_eq!(fixture.invariants["live_filter_commit_in_ci"], false);
    assert_eq!(fixture.invariants["capture_scope"], "tcp/443");
    assert_eq!(
        fixture.invariants["filter_absence_bound_to_last_session_generation"],
        true
    );

    let expected_keys = BTreeMap::from([
        ("provider".to_owned(), WINDOWS_WFP_PROVIDER_KEY.to_owned()),
        ("sublayer".to_owned(), WINDOWS_WFP_SUBLAYER_KEY.to_owned()),
        (
            "callout_v4".to_owned(),
            WINDOWS_WFP_CALLOUT_V4_KEY.to_owned(),
        ),
        (
            "callout_v6".to_owned(),
            WINDOWS_WFP_CALLOUT_V6_KEY.to_owned(),
        ),
        (
            "provider_context".to_owned(),
            WINDOWS_WFP_PROVIDER_CONTEXT_KEY.to_owned(),
        ),
        ("filter_v4".to_owned(), WINDOWS_WFP_FILTER_V4_KEY.to_owned()),
        ("filter_v6".to_owned(), WINDOWS_WFP_FILTER_V6_KEY.to_owned()),
    ]);
    assert_eq!(fixture.object_keys, expected_keys);
    assert_eq!(
        fixture.transaction_order,
        WINDOWS_WFP_TRANSACTION_OBJECT_ORDER
            .iter()
            .map(|object| object.as_str().to_owned())
            .collect::<Vec<_>>()
    );

    let plan = prepare_windows_wfp_dynamic_session_plan(
        &fixture.identity,
        &fixture.binding,
        fixture.session_generation,
        fixture.identity.target_pid,
    )
    .expect("prepare exact WFP session plan");
    let encoded = plan.provider_context();
    assert_eq!(encoded.len(), fixture.provider_context.length);
    assert_eq!(
        WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH,
        fixture.provider_context.length
    );
    assert_eq!(
        WINDOWS_WFP_PROVIDER_CONTEXT_VERSION,
        fixture.provider_context.version
    );
    assert_eq!(&encoded[..8], fixture.provider_context.magic.as_bytes());
    assert_eq!(encoded[122], fixture.provider_context.protocol);
    assert_eq!(
        u16::from_be_bytes([encoded[120], encoded[121]]),
        fixture.provider_context.remote_port
    );
    assert!(encoded[fixture.provider_context.reserved_offset..]
        .iter()
        .all(|byte| *byte == 0));
    assert_eq!(WINDOWS_WFP_CAPTURE_PROTOCOL, 6);
    assert_eq!(WINDOWS_WFP_CAPTURE_REMOTE_PORT, 443);

    let decoded =
        decode_windows_wfp_provider_context_v1(encoded).expect("decode exact WFP provider context");
    assert_eq!(
        decoded.service_generation(),
        fixture.identity.service.generation
    );
    assert_eq!(
        decoded.runtime_generation(),
        fixture.binding.runtime_generation
    );
    assert_eq!(decoded.session_generation(), fixture.session_generation);
    assert_eq!(decoded.target_pid(), fixture.identity.target_pid);
    assert_eq!(decoded.ipv4_listener().to_string(), "127.0.0.1:1443");
    assert_eq!(decoded.ipv6_listener().to_string(), "[::1]:1443");
}

#[test]
fn controller_requires_kernel_then_listeners_before_atomic_activation() {
    let fixture = contract();
    let mut controller = controller(&fixture);
    let command = commit_command(&fixture);

    assert!(matches!(
        controller.execute(&command),
        Err(WindowsWfpSessionError::KernelRegistrationMissing)
    ));
    controller
        .record_kernel_callouts_registered(&fixture.binding)
        .unwrap();
    assert!(matches!(
        controller.execute(&command),
        Err(WindowsWfpSessionError::ListenerReadinessMissing)
    ));
    controller
        .record_owned_listeners_ready(&fixture.binding, &fixture.identity.listeners)
        .unwrap();

    assert_eq!(
        controller.execute(&command).unwrap(),
        WindowsWfpSessionCompletion::Activated {
            binding: fixture.binding.clone(),
            session_generation: fixture.session_generation,
        }
    );
    assert_eq!(
        controller.active_session_generation(),
        Some(fixture.session_generation)
    );
    assert_eq!(
        controller.api().steps(),
        [
            "open_dynamic_session",
            "begin_transaction",
            "provider",
            "sublayer",
            "callout_v4",
            "callout_v6",
            "provider_context",
            "filter_v4",
            "filter_v6",
            "commit_transaction",
        ]
    );
    assert_eq!(controller.api().installed_objects().count(), 7);
}

#[test]
fn every_partial_transaction_failure_aborts_closes_and_leaves_no_objects() {
    let fixture = contract();
    let stages = [
        "begin_transaction",
        "provider",
        "sublayer",
        "callout_v4",
        "callout_v6",
        "provider_context",
        "filter_v4",
        "filter_v6",
        "commit_transaction",
    ];

    for stage in stages {
        let mut controller = controller(&fixture);
        authorize_activation(&mut controller, &fixture);
        controller.api_mut().fail_once(stage, "injected failure");
        let error = controller
            .execute(&commit_command(&fixture))
            .expect_err(stage);
        assert!(matches!(
            error,
            WindowsWfpSessionError::ActivationFailed { .. }
        ));
        assert_eq!(controller.active_session_generation(), None, "{stage}");
        assert_eq!(controller.api().installed_objects().count(), 0, "{stage}");
        assert_eq!(
            controller.api().steps().last().map(String::as_str),
            Some("close_dynamic_session"),
            "{stage}"
        );
        if stage != "begin_transaction" {
            assert!(
                controller
                    .api()
                    .steps()
                    .iter()
                    .any(|step| step == "abort_transaction"),
                "{stage} must abort"
            );
        }
    }
}

#[test]
fn session_close_and_exact_filter_absence_gate_teardown() {
    let fixture = contract();
    let mut controller = controller(&fixture);
    authorize_activation(&mut controller, &fixture);
    controller.execute(&commit_command(&fixture)).unwrap();

    let close = WindowsWfpRuntimeCommand::CloseDynamicSession {
        binding: fixture.binding.clone(),
        session_generation: fixture.session_generation,
    };
    controller.execute(&close).unwrap();
    assert_eq!(controller.active_session_generation(), None);

    let inspect = WindowsWfpRuntimeCommand::InspectOwnedFilters {
        binding: fixture.binding.clone(),
        session_generation: Some(fixture.session_generation),
    };
    let WindowsWfpSessionCompletion::FiltersInspected(inspection) =
        controller.execute(&inspect).unwrap()
    else {
        panic!("expected filter inspection completion")
    };
    assert!(inspection.filters_absent());
    controller
        .record_owned_listeners_stopped(&fixture.binding)
        .unwrap();
    controller
        .record_kernel_callouts_unregistered(&fixture.binding)
        .unwrap();
    assert_eq!(
        controller.api().steps()[10..],
        ["close_dynamic_session", "inspect_owned_filters"]
    );
}

#[test]
fn observed_filter_retention_keeps_listener_and_kernel_proofs_live() {
    let fixture = contract();
    let mut controller = controller(&fixture);
    authorize_activation(&mut controller, &fixture);
    controller
        .api_mut()
        .retain_filter_on_close(WindowsWfpManagementObject::FilterV4);
    controller.execute(&commit_command(&fixture)).unwrap();
    controller
        .execute(&WindowsWfpRuntimeCommand::CloseDynamicSession {
            binding: fixture.binding.clone(),
            session_generation: fixture.session_generation,
        })
        .unwrap();
    controller
        .execute(&WindowsWfpRuntimeCommand::InspectOwnedFilters {
            binding: fixture.binding.clone(),
            session_generation: Some(fixture.session_generation),
        })
        .unwrap();

    assert!(matches!(
        controller.record_owned_listeners_stopped(&fixture.binding),
        Err(WindowsWfpSessionError::FilterAbsenceNotProven)
    ));
    assert!(matches!(
        controller.record_kernel_callouts_unregistered(&fixture.binding),
        Err(WindowsWfpSessionError::FilterAbsenceNotProven)
    ));
}

#[test]
fn stale_binding_and_single_stack_identity_are_rejected() {
    let fixture = contract();
    let mut stale = fixture.binding.clone();
    stale.runtime_generation += 1;
    let mut controller = controller(&fixture);
    controller
        .record_kernel_callouts_registered(&fixture.binding)
        .unwrap();
    assert!(matches!(
        controller.record_kernel_callouts_registered(&stale),
        Err(WindowsWfpSessionError::InvalidControllerOrder(_))
    ));

    let mut single_stack = fixture.identity.clone();
    single_stack.listeners.pop();
    assert!(matches!(
        WindowsWfpDynamicSessionController::new(
            single_stack,
            RecordingWindowsWfpManagementApi::default()
        ),
        Err(WindowsWfpSessionError::InvalidListenerSet)
    ));
}

#[test]
fn teardown_completions_cannot_consume_missing_or_stale_proofs() {
    let fixture = contract();
    let mut controller = controller(&fixture);
    authorize_activation(&mut controller, &fixture);
    controller.execute(&commit_command(&fixture)).unwrap();
    controller
        .execute(&WindowsWfpRuntimeCommand::CloseDynamicSession {
            binding: fixture.binding.clone(),
            session_generation: fixture.session_generation,
        })
        .unwrap();
    controller
        .execute(&WindowsWfpRuntimeCommand::InspectOwnedFilters {
            binding: fixture.binding.clone(),
            session_generation: Some(fixture.session_generation),
        })
        .unwrap();

    let mut stale = fixture.binding.clone();
    stale.runtime_generation += 1;
    assert!(matches!(
        controller.record_owned_listeners_stopped(&stale),
        Err(WindowsWfpSessionError::FilterAbsenceNotProven)
            | Err(WindowsWfpSessionError::InvalidRuntimeBinding)
    ));
    controller
        .record_owned_listeners_stopped(&fixture.binding)
        .unwrap();
    assert!(matches!(
        controller.record_owned_listeners_stopped(&fixture.binding),
        Err(WindowsWfpSessionError::InvalidControllerOrder(_))
    ));
    controller
        .record_kernel_callouts_unregistered(&fixture.binding)
        .unwrap();
    assert!(matches!(
        controller.record_kernel_callouts_unregistered(&fixture.binding),
        Err(WindowsWfpSessionError::FilterAbsenceNotProven)
    ));
}

#[test]
fn activation_attempt_invalidates_old_filter_absence_and_binds_fresh_inspection() {
    let fixture = contract();
    let mut controller = controller(&fixture);
    authorize_activation(&mut controller, &fixture);
    controller.execute(&commit_command(&fixture)).unwrap();
    controller
        .execute(&WindowsWfpRuntimeCommand::CloseDynamicSession {
            binding: fixture.binding.clone(),
            session_generation: fixture.session_generation,
        })
        .unwrap();
    controller
        .execute(&WindowsWfpRuntimeCommand::InspectOwnedFilters {
            binding: fixture.binding.clone(),
            session_generation: Some(fixture.session_generation),
        })
        .unwrap();

    let next_generation = fixture.session_generation + 1;
    controller
        .api_mut()
        .fail_once("open_dynamic_session", "injected retry failure");
    assert!(controller
        .execute(&WindowsWfpRuntimeCommand::CommitAtomicDynamicSession {
            binding: fixture.binding.clone(),
            session_generation: next_generation,
            target_pid: fixture.identity.target_pid,
        })
        .is_err());
    assert!(matches!(
        controller.record_owned_listeners_stopped(&fixture.binding),
        Err(WindowsWfpSessionError::FilterAbsenceNotProven)
    ));
    assert!(matches!(
        controller.execute(&WindowsWfpRuntimeCommand::InspectOwnedFilters {
            binding: fixture.binding.clone(),
            session_generation: Some(fixture.session_generation),
        }),
        Err(WindowsWfpSessionError::InspectionSessionMismatch)
    ));

    controller
        .execute(&WindowsWfpRuntimeCommand::InspectOwnedFilters {
            binding: fixture.binding.clone(),
            session_generation: Some(next_generation),
        })
        .unwrap();
    controller
        .record_owned_listeners_stopped(&fixture.binding)
        .unwrap();
    controller
        .record_kernel_callouts_unregistered(&fixture.binding)
        .unwrap();
}

#[test]
fn provider_context_rejects_scope_and_reserved_mutation() {
    let fixture = contract();
    let plan = prepare_windows_wfp_dynamic_session_plan(
        &fixture.identity,
        &fixture.binding,
        fixture.session_generation,
        fixture.identity.target_pid,
    )
    .unwrap();
    let mut wrong_port = *plan.provider_context();
    wrong_port[121] ^= 1;
    assert!(matches!(
        decode_windows_wfp_provider_context_v1(&wrong_port),
        Err(WindowsWfpSessionError::InvalidCaptureScope)
    ));
    let mut reserved = *plan.provider_context();
    reserved[127] = 1;
    assert!(matches!(
        decode_windows_wfp_provider_context_v1(&reserved),
        Err(WindowsWfpSessionError::ProviderContextReservedNotZero)
    ));
}

#[test]
fn native_boundary_is_isolated_from_production_and_uses_no_broad_delete() {
    let native = include_str!("../src/wfp_session/windows.rs");
    let production = include_str!("../src/service_host/windows.rs");
    let binary = include_str!("../src/bin/slipstream_windows_service.rs");

    for required in [
        "FwpmEngineOpen0",
        "FWPM_SESSION_FLAG_DYNAMIC",
        "FwpmTransactionBegin0",
        "FwpmTransactionCommit0",
        "FwpmTransactionAbort0",
        "FwpmEngineClose0",
        "FwpmFilterGetByKey0",
    ] {
        assert!(
            native.contains(required),
            "native WFP boundary misses {required}"
        );
    }
    for forbidden in [
        "FwpmFilterDeleteByKey0",
        "FWPM_FILTER_FLAG_PERSISTENT",
        "FWPM_FILTER_FLAG_BOOTTIME",
        "Set-DnsClientServerAddress",
        "InternetSetOption",
    ] {
        assert!(
            !native.contains(forbidden),
            "native WFP boundary contains forbidden surface {forbidden}"
        );
    }
    for production_source in [production, binary] {
        assert!(!production_source.contains("wfp_session"));
        assert!(!production_source.contains("WindowsFwpmManagementApi"));
        assert!(!production_source.contains("Fwpm"));
    }
}

use serde_json::Value;
use slipstream_windows_adapter::service_lifecycle::{
    WindowsServiceDesiredState, WindowsServiceIdentity,
};
use slipstream_windows_adapter::service_lifecycle_state::{
    parse_windows_service_active_install_record_v1, parse_windows_service_intent_record_v1,
    WindowsDurableRecordEvidence, WindowsServiceActiveInstallRecordV1,
    WindowsServiceLifecycleStateAssessment, WindowsServiceLifecycleStateEvidence,
    WINDOWS_SERVICE_ACTIVE_INSTALL_FILE_NAME, WINDOWS_SERVICE_ACTIVE_INSTALL_PENDING_FILE_NAME,
    WINDOWS_SERVICE_INTENT_FILE_NAME, WINDOWS_SERVICE_INTENT_PENDING_FILE_NAME,
    WINDOWS_SERVICE_LIFECYCLE_STATE_CONTRACT_VERSION,
};

const STATE_V1: &str = include_str!("../../../contracts/windows-service-lifecycle-state-v1.json");

#[test]
fn frozen_state_contract_matches_public_records_and_paths() {
    let contract: Value = serde_json::from_str(STATE_V1).expect("parse lifecycle-state contract");
    assert_eq!(
        contract["contract_version"],
        WINDOWS_SERVICE_LIFECYCLE_STATE_CONTRACT_VERSION
    );
    assert_eq!(
        contract["files"]["intent"],
        WINDOWS_SERVICE_INTENT_FILE_NAME
    );
    assert_eq!(
        contract["files"]["intent_pending"],
        WINDOWS_SERVICE_INTENT_PENDING_FILE_NAME
    );
    assert_eq!(
        contract["files"]["active_install"],
        WINDOWS_SERVICE_ACTIVE_INSTALL_FILE_NAME
    );
    assert_eq!(
        contract["files"]["active_install_pending"],
        WINDOWS_SERVICE_ACTIVE_INSTALL_PENDING_FILE_NAME
    );

    let running = serde_json::to_vec(&contract["records"]["running_intent"])
        .expect("serialize intent fixture");
    let intent = parse_windows_service_intent_record_v1(&running).expect("parse intent fixture");
    assert_eq!(intent.desired, WindowsServiceDesiredState::Running);

    let active = serde_json::to_vec(&contract["records"]["active_install"])
        .expect("serialize active fixture");
    let active =
        parse_windows_service_active_install_record_v1(&active).expect("parse active fixture");
    assert_eq!(intent.identity.as_ref(), Some(&active.identity));
}

#[test]
fn scm_evaluation_requires_stable_matching_records() {
    let identity = WindowsServiceIdentity {
        service_name: "dev.slipstream.service".to_owned(),
        executable_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        generation: 1,
    };
    let intent =
        slipstream_windows_adapter::service_lifecycle_state::WindowsServiceIntentRecordV1::new(
            WindowsServiceDesiredState::Running,
            Some(identity.clone()),
            0,
        )
        .expect("valid intent");
    let active = WindowsServiceActiveInstallRecordV1::new(identity).expect("valid active record");
    let stable = WindowsServiceLifecycleStateEvidence {
        intent: WindowsDurableRecordEvidence::Committed {
            record: intent.clone(),
        },
        active_install: WindowsDurableRecordEvidence::Committed { record: active },
    };
    assert!(stable.is_stable_for_scm_evaluation());

    let interrupted = WindowsServiceLifecycleStateEvidence {
        intent: WindowsDurableRecordEvidence::InterruptedWrite {
            committed: Some(intent),
        },
        active_install: WindowsDurableRecordEvidence::Missing,
    };
    assert_eq!(
        interrupted.assess(),
        WindowsServiceLifecycleStateAssessment::InterruptedWrite
    );
    assert!(!interrupted.is_stable_for_scm_evaluation());
}

#[test]
fn native_state_store_has_only_filesystem_lifecycle_surface() {
    let source = include_str!("../src/service_lifecycle_state/windows.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production lifecycle state source");

    for required in [
        "CreateFileW",
        "CreateDirectoryW",
        "FlushFileBuffers",
        "MoveFileExW",
        "MOVEFILE_REPLACE_EXISTING",
        "MOVEFILE_WRITE_THROUGH",
        "SetFileInformationByHandle",
        "FileDispositionInfo",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        "machine_owner_record_path",
        "WindowsServiceAction::PersistIntent",
        "WindowsServiceAction::CommitInstall",
        "WindowsServiceAction::ClearActiveInstallRecord",
        "acquire_service_operation_lock",
    ] {
        assert!(
            production.contains(required),
            "native lifecycle state must use {required}"
        );
    }

    for forbidden in [
        "OpenSCManager",
        "CreateService",
        "StartService",
        "ControlService",
        "DeleteService",
        "TerminateProcess",
        "std::process",
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
            "native lifecycle state must not contain {forbidden}"
        );
    }
}

#[test]
fn pending_handle_precedes_write_and_commit() {
    let source = include_str!("../src/service_lifecycle_state/windows.rs");
    let create = source
        .find("let mut pending = create_new_secure_file")
        .expect("pending file registration");
    let write = source
        .find(".write_all(request.bytes)")
        .expect("pending file write");
    let flush = source
        .find("flush pending state")
        .expect("pending file flush");
    let commit = source.find("move_file_exact(").expect("atomic commit");
    assert!(create < write);
    assert!(write < flush);
    assert!(flush < commit);
}

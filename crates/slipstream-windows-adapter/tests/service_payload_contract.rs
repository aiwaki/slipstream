#[test]
fn native_payload_staging_is_handle_bound_and_has_no_service_or_network_surface() {
    let source = include_str!("../src/service_payload/windows.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production payload source");

    for required in [
        "CreateFileW",
        "CreateDirectoryW",
        "FlushFileBuffers",
        "MoveFileExW",
        "MOVEFILE_WRITE_THROUGH",
        "SetFileInformationByHandle",
        "FileDispositionInfo",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        "staged_payload_evidence_at",
        "WindowsServiceAction::StagePayload",
        "WindowsServiceAction::RemoveOwnedPayload",
        "acquire_service_operation_lock",
    ] {
        assert!(
            production.contains(required),
            "native payload staging must use {required}"
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
            "native payload staging must not contain {forbidden}"
        );
    }
}

#[test]
fn payload_commit_marker_is_written_after_the_executable() {
    let source = include_str!("../src/service_payload/windows.rs");
    let executable_commit = source
        .find("commit payload executable")
        .expect("payload commit operation");
    let record_commit = source
        .find("commit owner record")
        .expect("owner record commit operation");
    let final_evidence = source
        .rfind("staged_payload_evidence_at")
        .expect("final collector verification");

    assert!(executable_commit < record_commit);
    assert!(record_commit < final_evidence);
}

#[test]
fn pending_handles_are_registered_before_fallible_io() {
    let source = include_str!("../src/service_payload/windows.rs").replace("\r\n", "\n");
    let executable_registration = source
        .find("transaction.executable = Some(create_new_secure_file")
        .expect("pending executable registration");
    let executable_copy = source
        .find("copy_exact_payload")
        .expect("pending executable copy");
    let record_registration = source
        .find("transaction.record = Some(create_new_secure_file")
        .expect("pending record registration");
    let record_write = source
        .find(".write_all(&record_bytes)")
        .expect("pending record write");

    assert!(executable_registration < executable_copy);
    assert!(record_registration < record_write);
}

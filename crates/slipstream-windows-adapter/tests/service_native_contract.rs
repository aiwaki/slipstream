#[test]
fn native_lifecycle_composes_exact_effects_under_one_lock_without_networking() {
    let source = include_str!("../src/service_native/windows.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production native lifecycle source");

    for required in [
        "acquire_service_operation_lock",
        "lifecycle_state.apply_locked",
        "payload.apply_locked",
        "scm.apply_locked",
        "wait_for_owned_state_locked",
        "wait_for_absent_locked",
        "exact_service_is_absent_locked",
        "payload_is_absent_locked",
        "deferred_clear",
        "cleanup_is_absent_locked",
    ] {
        assert!(
            production.contains(required),
            "native lifecycle must use {required}"
        );
    }
    for forbidden in [
        "std::net",
        "TcpStream",
        "UdpSocket",
        "WinHttp",
        "InternetOpen",
        "DnsQuery",
        "Set-DnsClientServerAddress",
        "netsh",
        "ProxyEnable",
        "Vpn",
        "EnumServicesStatus",
        "TerminateProcess",
        "OpenProcess",
        "std::process::Command",
        "Command::",
    ] {
        assert!(
            !production.contains(forbidden),
            "native lifecycle must not contain {forbidden}"
        );
    }
}

#[test]
fn scm_unregister_waits_for_exact_absence_after_closing_the_delete_handle() {
    let source = include_str!("../src/service_scm/windows.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production SCM source");

    for required in [
        "DeleteService",
        "drop(service)",
        "drop(manager)",
        "wait_for_exact_service_absent",
        "ERROR_SERVICE_MARKED_FOR_DELETE",
        "DELETE_WAIT_TIMEOUT",
    ] {
        assert!(
            production.contains(required),
            "SCM unregister must use {required}"
        );
    }
}

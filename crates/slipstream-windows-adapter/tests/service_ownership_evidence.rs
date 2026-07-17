use serde_json::{json, Value};
use slipstream_windows_adapter::service_ownership::{
    canonical_scm_binary_path, parse_windows_owner_record_v1, WindowsOwnerRecordParseError,
    MAX_WINDOWS_OWNER_RECORD_BYTES,
};

fn valid_record() -> Value {
    let executable_path = r"C:\Program Files\Slipstream\slipstream-service.exe";
    json!({
        "schema_version": 1,
        "service_name": "dev.slipstream.service",
        "scm_binary_path": canonical_scm_binary_path(executable_path),
        "executable_path": executable_path,
        "executable_sha256": "a".repeat(64),
        "generation": 1
    })
}

#[test]
fn strict_v1_record_parser_accepts_only_the_frozen_shape() {
    let bytes = serde_json::to_vec(&valid_record()).expect("serialize fixture");
    let record = parse_windows_owner_record_v1(&bytes).expect("parse valid v1 record");
    assert_eq!(record.schema_version, 1);
    assert_eq!(record.service_name, "dev.slipstream.service");
    assert_eq!(record.generation, 1);

    let mut with_extra = valid_record();
    with_extra["unexpected"] = json!(true);
    assert_eq!(
        parse_windows_owner_record_v1(
            &serde_json::to_vec(&with_extra).expect("serialize extra field")
        ),
        Err(WindowsOwnerRecordParseError::InvalidJson)
    );
    assert_eq!(
        parse_windows_owner_record_v1(
            br#"{"schema_version":1,"schema_version":1,"service_name":"dev.slipstream.service","scm_binary_path":"x","executable_path":"x","executable_sha256":"x","generation":1}"#
        ),
        Err(WindowsOwnerRecordParseError::InvalidJson)
    );
}

#[test]
fn strict_v1_record_parser_is_bounded_and_rejects_ambiguous_paths() {
    assert_eq!(
        parse_windows_owner_record_v1(&[]),
        Err(WindowsOwnerRecordParseError::Empty)
    );
    assert_eq!(
        parse_windows_owner_record_v1(&vec![b' '; MAX_WINDOWS_OWNER_RECORD_BYTES + 1]),
        Err(WindowsOwnerRecordParseError::TooLarge)
    );

    for path in [
        r"C:\Program Files\Slipstream.\slipstream-service.exe",
        "C:\\Program Files\\Slipstream \\slipstream-service.exe",
    ] {
        let mut record = valid_record();
        record["executable_path"] = json!(path);
        record["scm_binary_path"] = json!(canonical_scm_binary_path(path));
        assert_eq!(
            parse_windows_owner_record_v1(
                &serde_json::to_vec(&record).expect("serialize ambiguous path")
            ),
            Err(WindowsOwnerRecordParseError::InvalidContract),
            "path should be rejected: {path}"
        );
    }
}

#[test]
fn native_evidence_source_is_handle_bound_and_read_only() {
    let source = include_str!("../src/service_ownership/windows.rs");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source prefix");

    for required in [
        "SHGetKnownFolderPath",
        "FOLDERID_ProgramData",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "GetFileInformationByHandle",
        "GetFinalPathNameByHandleW",
        "GetSecurityInfo",
        "GetAce",
        "Sha256",
    ] {
        assert!(
            production.contains(required),
            "native collector must retain {required}"
        );
    }

    for forbidden in [
        "CreateServiceW",
        "StartServiceW",
        "ControlService",
        "DeleteService",
        "ChangeServiceConfig",
        "SetSecurityInfo",
        "SetNamedSecurityInfo",
        "WriteFile",
        "DeleteFile",
        "MoveFile",
        "std::process::Command",
        "TcpStream",
        "UdpSocket",
        "WinHttp",
        "DnsQuery",
        "env::var",
    ] {
        assert!(
            !production.contains(forbidden),
            "native collector must remain read-only; found {forbidden}"
        );
    }
}

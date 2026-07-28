use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(crate) const INSTALL_ATTESTATION_PATH: &str = "/var/run/slipstream-install-attestation.json";
const INSTALL_ATTESTATION_SCHEMA_VERSION: u32 = 1;
const INSTALL_ATTESTATION_MAX_BYTES: u64 = 4096;
const INSTALLED_DAEMON_MODE: u32 = 0o700;
const EVIDENCE_MODE: u32 = 0o644;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InstalledDaemonIdentity {
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mode: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InstalledLaunchdIdentity {
    pub(crate) label: String,
    pub(crate) pid: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InstalledListenerIdentity {
    pub(crate) host: String,
    pub(crate) port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InstallAttestation {
    pub(crate) schema_version: u32,
    pub(crate) source_sha256: String,
    pub(crate) daemon: InstalledDaemonIdentity,
    pub(crate) launchd: InstalledLaunchdIdentity,
    pub(crate) listener: InstalledListenerIdentity,
    pub(crate) state: String,
    pub(crate) pf_active: bool,
}

fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

pub(crate) fn file_sha256(path: &Path) -> Option<String> {
    let path_metadata = fs::symlink_metadata(path).ok()?;
    if !path_metadata.file_type().is_file() {
        return None;
    }
    let mut file = fs::File::open(path).ok()?;
    let opened_metadata = file.metadata().ok()?;
    if !opened_metadata.file_type().is_file()
        || !same_file_identity(&path_metadata, &opened_metadata)
    {
        return None;
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if !same_file_identity(&opened_metadata, &file.metadata().ok()?) {
        return None;
    }
    Some(format!("{:x}", digest.finalize()))
}

fn read_attestation_at(path: &Path, expected_owner_uid: u32) -> Option<InstallAttestation> {
    let path_metadata = fs::symlink_metadata(path).ok()?;
    if !path_metadata.file_type().is_file()
        || path_metadata.len() > INSTALL_ATTESTATION_MAX_BYTES
        || path_metadata.uid() != expected_owner_uid
        || path_metadata.mode() & 0o7777 != EVIDENCE_MODE
    {
        return None;
    }
    let mut file = fs::File::open(path).ok()?;
    let opened_metadata = file.metadata().ok()?;
    if !opened_metadata.file_type().is_file()
        || !same_file_identity(&path_metadata, &opened_metadata)
    {
        return None;
    }
    let mut payload = Vec::with_capacity(path_metadata.len() as usize);
    file.by_ref()
        .take(INSTALL_ATTESTATION_MAX_BYTES + 1)
        .read_to_end(&mut payload)
        .ok()?;
    if payload.len() as u64 > INSTALL_ATTESTATION_MAX_BYTES
        || !same_file_identity(&opened_metadata, &file.metadata().ok()?)
    {
        return None;
    }
    serde_json::from_slice(&payload).ok()
}

pub(crate) fn install_attestation_at(
    evidence_path: &Path,
    bundled_daemon: &Path,
    installed_daemon: &Path,
    launchd_label: &str,
    listener_port: u16,
    expected_evidence_uid: u32,
) -> Option<InstallAttestation> {
    let evidence = read_attestation_at(evidence_path, expected_evidence_uid)?;
    let bundled_sha256 = file_sha256(bundled_daemon)?;
    let state_and_pf_match = matches!(
        (evidence.state.as_str(), evidence.pf_active),
        ("active", true) | ("dormant", false)
    );
    let valid = evidence.schema_version == INSTALL_ATTESTATION_SCHEMA_VERSION
        && evidence.source_sha256 == bundled_sha256
        && evidence.daemon.sha256 == bundled_sha256
        && Path::new(&evidence.daemon.path) == installed_daemon
        && evidence.daemon.uid == 0
        && evidence.daemon.mode == INSTALLED_DAEMON_MODE
        && evidence.launchd.label == launchd_label
        && evidence.launchd.pid > 0
        && evidence.listener.host == "127.0.0.1"
        && evidence.listener.port == listener_port
        && state_and_pf_match;
    valid.then_some(evidence)
}

pub(crate) fn install_attestation(
    bundled_daemon: &Path,
    installed_daemon: &Path,
    launchd_label: &str,
    listener_port: u16,
) -> Option<InstallAttestation> {
    install_attestation_at(
        Path::new(INSTALL_ATTESTATION_PATH),
        bundled_daemon,
        installed_daemon,
        launchd_label,
        listener_port,
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn exact_root_contract_is_required_without_opening_installed_daemon() {
        let root = std::env::temp_dir().join(format!(
            "slipstream-install-attestation-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let bundled = root.join("bundled-slipstreamd");
        let installed = Path::new("/usr/local/slipstream/slipstreamd");
        let evidence_path = root.join("attestation.json");
        fs::write(&bundled, b"qualified daemon bytes").unwrap();
        let bundled_sha256 = file_sha256(&bundled).unwrap();
        let evidence_uid = fs::symlink_metadata(&root).unwrap().uid();
        let evidence = serde_json::json!({
            "schema_version": 1,
            "source_sha256": bundled_sha256,
            "daemon": {
                "path": installed,
                "sha256": bundled_sha256,
                "uid": 0,
                "gid": 0,
                "mode": 0o700
            },
            "launchd": {
                "label": "dev.slipstream.tproxy",
                "pid": 4242
            },
            "listener": {
                "host": "127.0.0.1",
                "port": 1080
            },
            "state": "active",
            "pf_active": true
        });
        fs::write(&evidence_path, serde_json::to_vec(&evidence).unwrap()).unwrap();
        fs::set_permissions(&evidence_path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(install_attestation_at(
            &evidence_path,
            &bundled,
            installed,
            "dev.slipstream.tproxy",
            1080,
            evidence_uid,
        )
        .is_some());

        let mut tampered = evidence;
        tampered["daemon"]["sha256"] = serde_json::json!("0".repeat(64));
        fs::write(&evidence_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(install_attestation_at(
            &evidence_path,
            &bundled,
            installed,
            "dev.slipstream.tproxy",
            1080,
            evidence_uid,
        )
        .is_none());

        fs::write(
            &evidence_path,
            vec![b' '; INSTALL_ATTESTATION_MAX_BYTES as usize + 1],
        )
        .unwrap();
        assert!(install_attestation_at(
            &evidence_path,
            &bundled,
            installed,
            "dev.slipstream.tproxy",
            1080,
            evidence_uid,
        )
        .is_none());

        fs::remove_file(&evidence_path).unwrap();
        let symlink_target = root.join("attestation-target.json");
        tampered["daemon"]["sha256"] = serde_json::json!(bundled_sha256);
        fs::write(&symlink_target, serde_json::to_vec(&tampered).unwrap()).unwrap();
        fs::set_permissions(&symlink_target, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&symlink_target, &evidence_path).unwrap();
        assert!(install_attestation_at(
            &evidence_path,
            &bundled,
            installed,
            "dev.slipstream.tproxy",
            1080,
            evidence_uid,
        )
        .is_none());

        let _ = fs::remove_dir_all(root);
    }
}

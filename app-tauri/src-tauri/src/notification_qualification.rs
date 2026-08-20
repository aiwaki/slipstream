//! One-shot, exact-candidate native notification qualification.
//!
//! This entry point is inert in ordinary launches. It accepts only a
//! root-created, unlinked capability descriptor inherited by the exact
//! packaged process after a privilege-dropping exec.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const ARGUMENT: &str = "--qualify-update-notification";
const CAPABILITY_ENV: &str = "SLIPSTREAM_UPDATE_NOTIFICATION_QUALIFICATION_FD";
const CAPABILITY_FD: i32 = 3;
const CAPABILITY_MAX_BYTES: usize = 16 * 1024;
const CAPABILITY_MAX_LIFETIME_MS: u64 = 30_000;
const APP_TREE_MAX_ENTRIES: usize = 8_192;
const APP_TREE_MAX_REGULAR_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const INFO_PLIST_MAX_BYTES: u64 = 256 * 1024;
const BUNDLE_IDENTIFIER: &str = "dev.slipstream.tray";
const BUNDLE_EXECUTABLE: &str = "slipstream";
const PURPOSE: &str = "slipstream_update_notification_qualification";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capability {
    schema_version: u8,
    purpose: String,
    nonce: String,
    issued_at_unix_ms: u64,
    deadline_unix_ms: u64,
    expected_uid: u32,
    expected_gid: u32,
    expected_pid: u32,
    home: PathBuf,
    app_bundle: PathBuf,
    executable: PathBuf,
    executable_sha256: String,
    app_tree_sha256: String,
    candidate_manifest_sha256: String,
    candidate_id: String,
    bundle_identifier: String,
}

#[derive(Debug)]
pub(crate) struct ClaimedCapability {
    pub(crate) sha256: String,
}

fn fixed_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn candidate_id(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("release-candidate-") else {
        return false;
    };
    matches!(digest.len(), 40 | 64) && fixed_hex(digest, digest.len() / 2)
}

fn unix_time_ms() -> Result<u64, ()> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_millis();
    u64::try_from(millis).map_err(|_| ())
}

fn sha256_regular_file(path: &Path) -> Result<String, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file() || metadata.nlink() == 0 {
        return Err(());
    }
    let mut file = File::open(path).map_err(|_| ())?;
    let opened = file.metadata().map_err(|_| ())?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        return Err(());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| ())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let after = fs::symlink_metadata(path).map_err(|_| ())?;
    if after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
    {
        return Err(());
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn read_bounded_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file() || metadata.nlink() == 0 || metadata.len() > maximum {
        return Err(());
    }
    let file = File::open(path).map_err(|_| ())?;
    let opened = file.metadata().map_err(|_| ())?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        return Err(());
    }
    let mut payload = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| ())?);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut payload)
        .map_err(|_| ())?;
    if payload.len() as u64 != metadata.len() || payload.len() as u64 > maximum {
        return Err(());
    }
    let after = fs::symlink_metadata(path).map_err(|_| ())?;
    if after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
    {
        return Err(());
    }
    Ok(payload)
}

fn digest_tree_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn collect_tree_entries(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<PathBuf>,
) -> Result<(), ()> {
    for entry in fs::read_dir(directory).map_err(|_| ())? {
        let path = entry.map_err(|_| ())?.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| ())?;
        entries.push(path.clone());
        if entries.len() > APP_TREE_MAX_ENTRIES {
            return Err(());
        }
        if metadata.file_type().is_dir() {
            collect_tree_entries(root, &path, entries)?;
        }
        if !path.starts_with(root) {
            return Err(());
        }
    }
    Ok(())
}

fn deterministic_tree_sha256(root: &Path, deadline_unix_ms: u64) -> Result<String, ()> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| ())?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        return Err(());
    }
    let mut digest = Sha256::new();
    let root_mode = format!("{:o}", root_metadata.mode() & 0o7777);
    for field in [
        b"directory".as_slice(),
        b".".as_slice(),
        root_mode.as_bytes(),
        b"".as_slice(),
    ] {
        digest_tree_field(&mut digest, field);
    }
    let mut entries = Vec::new();
    collect_tree_entries(root, root, &mut entries)?;
    entries.sort_by(|left, right| {
        let left = left.strip_prefix(root).ok().and_then(Path::to_str);
        let right = right.strip_prefix(root).ok().and_then(Path::to_str);
        left.cmp(&right)
    });
    let mut regular_bytes = 0_u64;
    for path in entries {
        if unix_time_ms()? >= deadline_unix_ms {
            return Err(());
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ())?
            .to_str()
            .ok_or(())?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| ())?;
        let (kind, payload) = if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path).map_err(|_| ())?;
            (
                b"symlink".as_slice(),
                target.to_str().ok_or(())?.as_bytes().to_vec(),
            )
        } else if metadata.file_type().is_dir() {
            (b"directory".as_slice(), Vec::new())
        } else if metadata.file_type().is_file() {
            regular_bytes = regular_bytes.checked_add(metadata.len()).ok_or(())?;
            if regular_bytes > APP_TREE_MAX_REGULAR_BYTES {
                return Err(());
            }
            let file_digest = sha256_regular_file(&path)?;
            let payload = (0..file_digest.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&file_digest[index..index + 2], 16).map_err(|_| ()))
                .collect::<Result<Vec<_>, _>>()?;
            (b"file".as_slice(), payload)
        } else {
            return Err(());
        };
        let mode = format!("{:o}", metadata.mode() & 0o7777);
        for field in [
            kind,
            relative.as_bytes(),
            mode.as_bytes(),
            payload.as_slice(),
        ] {
            digest_tree_field(&mut digest, field);
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_bundle(capability: &Capability) -> Result<(), ()> {
    let current_executable = env::current_exe()
        .map_err(|_| ())?
        .canonicalize()
        .map_err(|_| ())?;
    let expected_executable = capability.executable.canonicalize().map_err(|_| ())?;
    let expected_bundle = capability.app_bundle.canonicalize().map_err(|_| ())?;
    if current_executable != expected_executable
        || expected_executable
            .file_name()
            .and_then(|name| name.to_str())
            != Some(BUNDLE_EXECUTABLE)
        || expected_executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            != Some(expected_bundle.as_path())
    {
        return Err(());
    }
    let plist_bytes = read_bounded_regular_file(
        &expected_bundle.join("Contents/Info.plist"),
        INFO_PLIST_MAX_BYTES,
    )?;
    let plist = plist::Value::from_reader(std::io::Cursor::new(plist_bytes)).map_err(|_| ())?;
    let dictionary = plist.as_dictionary().ok_or(())?;
    if dictionary
        .get("CFBundleIdentifier")
        .and_then(plist::Value::as_string)
        != Some(BUNDLE_IDENTIFIER)
        || dictionary
            .get("CFBundleExecutable")
            .and_then(plist::Value::as_string)
            != Some(BUNDLE_EXECUTABLE)
        || dictionary
            .get("LSUIElement")
            .and_then(plist::Value::as_boolean)
            != Some(true)
    {
        return Err(());
    }
    if sha256_regular_file(&expected_executable)? != capability.executable_sha256 {
        return Err(());
    }
    if deterministic_tree_sha256(&expected_bundle, capability.deadline_unix_ms)?
        != capability.app_tree_sha256
    {
        return Err(());
    }
    Ok(())
}

fn validate_capability(capability: &Capability) -> Result<(), ()> {
    let now = unix_time_ms()?;
    if capability.schema_version != 1
        || capability.purpose != PURPOSE
        || capability.bundle_identifier != BUNDLE_IDENTIFIER
        || !fixed_hex(&capability.nonce, 32)
        || !fixed_hex(&capability.executable_sha256, 32)
        || !fixed_hex(&capability.app_tree_sha256, 32)
        || !fixed_hex(&capability.candidate_manifest_sha256, 32)
        || !candidate_id(&capability.candidate_id)
        || capability.issued_at_unix_ms > now.saturating_add(1_000)
        || capability.deadline_unix_ms <= now
        || capability
            .deadline_unix_ms
            .checked_sub(capability.issued_at_unix_ms)
            != Some(CAPABILITY_MAX_LIFETIME_MS)
        || capability.expected_uid == 0
        || capability.expected_gid == 0
        || capability.expected_pid != std::process::id()
        || capability.expected_uid != unsafe { libc::geteuid() }
        || capability.expected_gid != unsafe { libc::getegid() }
    {
        return Err(());
    }
    let expected_home = capability.home.canonicalize().map_err(|_| ())?;
    let configured_home = PathBuf::from(env::var_os("HOME").ok_or(())?)
        .canonicalize()
        .map_err(|_| ())?;
    if expected_home != configured_home {
        return Err(());
    }
    validate_bundle(capability)
}

pub(crate) fn requested() -> bool {
    let mut arguments = env::args_os();
    let _ = arguments.next();
    arguments.next().as_deref() == Some(std::ffi::OsStr::new(ARGUMENT))
        && arguments.next().is_none()
}

pub(crate) fn claim() -> Result<ClaimedCapability, ()> {
    if env::var_os("CI").as_deref() != Some(std::ffi::OsStr::new("true"))
        || env::var_os("GITHUB_ACTIONS").as_deref() != Some(std::ffi::OsStr::new("true"))
        || env::var_os("SLIPSTREAM_DISPOSABLE_CI").as_deref() != Some(std::ffi::OsStr::new("1"))
        || env::var_os(CAPABILITY_ENV).as_deref() != Some(std::ffi::OsStr::new("3"))
    {
        return Err(());
    }
    env::remove_var(CAPABILITY_ENV);

    // SAFETY: fd 3 is transferred exactly once by the root capability launcher
    // and consumed in the early, single-threaded process entry point.
    let mut file = unsafe { File::from_raw_fd(CAPABILITY_FD) };
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > CAPABILITY_MAX_BYTES as u64
    {
        return Err(());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    let mut payload = Vec::new();
    file.take((CAPABILITY_MAX_BYTES + 1) as u64)
        .read_to_end(&mut payload)
        .map_err(|_| ())?;
    if payload.is_empty() || payload.len() > CAPABILITY_MAX_BYTES {
        return Err(());
    }
    let sha256 = format!("{:x}", Sha256::digest(&payload));
    let capability: Capability = serde_json::from_slice(&payload).map_err(|_| ())?;
    validate_capability(&capability)?;
    Ok(ClaimedCapability { sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_hex_and_candidate_identifiers_are_bounded() {
        assert!(fixed_hex(&"a".repeat(64), 32));
        assert!(!fixed_hex(&"A".repeat(64), 32));
        assert!(!fixed_hex(&"a".repeat(63), 32));
        assert!(candidate_id(&format!(
            "release-candidate-{}",
            "1".repeat(40)
        )));
        assert!(candidate_id(&format!(
            "release-candidate-{}",
            "1".repeat(64)
        )));
        assert!(!candidate_id("release-candidate-main"));
    }

    #[test]
    fn ordinary_test_process_does_not_request_qualification() {
        assert!(!requested());
    }

    #[test]
    fn deterministic_tree_digest_changes_with_content_and_metadata() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let file = root.path().join("payload");
        fs::write(&file, b"first").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let directory = root.path().join("nested");
        fs::create_dir(&directory).unwrap();
        symlink("../payload", directory.join("link")).unwrap();
        let deadline = unix_time_ms().unwrap() + 5_000;
        let first = deterministic_tree_sha256(root.path(), deadline).unwrap();
        assert!(fixed_hex(&first, 32));

        fs::write(&file, b"second").unwrap();
        let second = deterministic_tree_sha256(root.path(), deadline).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn bounded_regular_file_rejects_symlinks_and_oversized_payloads() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let regular = root.path().join("regular");
        fs::write(&regular, b"plist").unwrap();
        assert_eq!(read_bounded_regular_file(&regular, 5).unwrap(), b"plist");
        assert!(read_bounded_regular_file(&regular, 4).is_err());

        let link = root.path().join("link");
        symlink(&regular, &link).unwrap();
        assert!(read_bounded_regular_file(&link, 5).is_err());
    }
}

//! Durable, windowless macOS application replacement.
//!
//! Tauri's macOS installer keeps the previous bundle in a `TempDir`; that
//! backup disappears when `Update::install` returns and therefore cannot
//! protect a restart, crash, or power-loss boundary.  Slipstream stages the
//! already signature-verified archive on the target volume, persists every
//! rename in an owner-private journal, and delegates replacement to a small
//! non-AppKit watchdog.  The old bundle is deleted only after the exact new
//! bundle acknowledges a fresh owned-daemon heartbeat.

// This source is compiled into two deliberately disjoint executables. The tray
// uses preparation/acknowledgement; the watchdog uses replacement/recovery.
#![allow(dead_code)]

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const WATCHDOG_BINARY: &str = "slipstream-update-watchdog";
pub const WATCHDOG_LABEL: &str = "dev.slipstream.update-watchdog";
pub const JOURNAL_FILE: &str = "app-update-transaction-v1.json";
pub const TRANSACTION_ENV: &str = "SLIPSTREAM_UPDATE_TRANSACTION";
const JOURNAL_VERSION: u8 = 1;
const ACK_TIMEOUT_SECS: u64 = 60;
const MAX_JOURNAL_BYTES: u64 = 32 * 1024;
const MAX_ACK_BYTES: u64 = 8 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionPhase {
    Prepared,
    BackupMoved,
    NewActivated,
    SuccessorLaunchPlanned,
    SuccessorLaunched,
    Acknowledged,
    RollbackPlanned,
    NewQuarantined,
    RolledBack,
    OldRelaunched,
    CleanupFailed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateJournalV1 {
    pub schema_version: u8,
    pub nonce: String,
    pub uid: u32,
    pub initiator_pid: u32,
    pub target: PathBuf,
    pub backup: PathBuf,
    pub stage: PathBuf,
    pub helper: PathBuf,
    pub launch_agent: PathBuf,
    pub current_version: String,
    pub expected_version: String,
    pub archive_sha256: String,
    pub watchdog_sha256: String,
    pub old_executable_sha256: String,
    pub new_executable_sha256: String,
    pub phase: TransactionPhase,
    pub successor_pid: Option<u32>,
    #[serde(default)]
    pub successor_started: Option<String>,
    pub successor_deadline_unix: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SuccessorAckV1 {
    schema_version: u8,
    nonce: String,
    uid: u32,
    pid: u32,
    version: String,
    target: PathBuf,
    executable_sha256: String,
    heartbeat_seq: u64,
}

#[derive(Clone, Debug)]
pub struct PreparedTransaction {
    pub journal_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct PendingSuccessorAck {
    journal_path: PathBuf,
    ack_path: PathBuf,
    nonce: String,
    uid: u32,
    target: PathBuf,
    version: String,
    executable_sha256: String,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot mutate memory.
    unsafe { libc::getuid() }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > 512 * 1024 * 1024 {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let mut file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn random_nonce() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("secure update nonce unavailable: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?
        .sync_all()
}

fn open_directory_nofollow(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot open directory {} safely: {error}", path.display()))
}

fn ensure_user_directory(path: &Path, owner_private: bool) -> Result<File, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| format!("{} has no parent", path.display()))?;
            let parent_handle = open_directory_nofollow(parent)?;
            let parent_metadata = parent_handle
                .metadata()
                .map_err(|error| format!("cannot inspect {}: {error}", parent.display()))?;
            if !parent_metadata.is_dir()
                || parent_metadata.uid() != current_uid()
                || parent_metadata.permissions().mode() & 0o022 != 0
            {
                return Err(format!(
                    "directory parent {} is not safely user controlled",
                    parent.display()
                ));
            }
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            if let Err(error) = builder.create(path) {
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(format!("cannot create {}: {error}", path.display()));
                }
            }
            parent_handle
                .sync_all()
                .map_err(|error| format!("cannot sync {}: {error}", parent.display()))?;
        }
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    }
    let directory = open_directory_nofollow(path)?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_dir()
        || metadata.uid() != current_uid()
        || (!owner_private && metadata.permissions().mode() & 0o022 != 0)
    {
        return Err(format!(
            "{} is not a safely owned directory",
            path.display()
        ));
    }
    if owner_private && metadata.permissions().mode() & 0o077 != 0 {
        // SAFETY: the descriptor was opened with O_DIRECTORY|O_NOFOLLOW and
        // its ownership was checked immediately above.
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(format!(
                "cannot protect {}: {}",
                path.display(),
                io::Error::last_os_error()
            ));
        }
        let tightened = directory
            .metadata()
            .map_err(|error| format!("cannot re-inspect {}: {error}", path.display()))?;
        if tightened.uid() != current_uid() || tightened.permissions().mode() & 0o077 != 0 {
            return Err(format!("{} did not become owner-private", path.display()));
        }
    }
    Ok(directory)
}

fn read_private_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot open {} safely: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > max_bytes
    {
        return Err(format!(
            "{} is not an owner-private bounded file",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{} exceeded its read bound", path.display()));
    }
    Ok(bytes)
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_atomic(path, bytes, true)
}

fn write_launch_agent_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "LaunchAgent path has no parent".to_string())?;
    ensure_user_directory(parent, false)
        .map_err(|_| "user LaunchAgents directory is not privately controlled".to_string())?;
    write_atomic(path, bytes, false)
}

fn write_atomic(path: &Path, bytes: &[u8], protect_parent: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "private state path has no parent".to_string())?;
    if protect_parent {
        ensure_user_directory(parent, true)?;
    } else {
        ensure_user_directory(parent, false)?;
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("cannot persist {}: {error}", path.display()));
    }
    fs::rename(&temporary, path)
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))?;
    sync_directory(parent).map_err(|error| format!("cannot sync {}: {error}", parent.display()))?;
    Ok(())
}

fn write_journal(path: &Path, journal: &UpdateJournalV1) -> Result<(), String> {
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| format!("update journal serialization failed: {error}"))?;
    write_private_atomic(path, &bytes)
}

fn read_journal(path: &Path) -> Result<UpdateJournalV1, String> {
    let bytes = read_private_file(path, MAX_JOURNAL_BYTES)?;
    let journal: UpdateJournalV1 = serde_json::from_slice(&bytes)
        .map_err(|error| format!("update journal is invalid: {error}"))?;
    validate_journal(path, &journal)?;
    Ok(journal)
}

fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn is_safe_process_start(value: &str) -> bool {
    (20..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b':' | b'-'))
}

fn validate_journal(path: &Path, journal: &UpdateJournalV1) -> Result<(), String> {
    if journal.schema_version != JOURNAL_VERSION
        || journal.uid != current_uid()
        || !(2..=i32::MAX as u32).contains(&journal.initiator_pid)
        || journal
            .successor_pid
            .is_some_and(|pid| !(2..=i32::MAX as u32).contains(&pid))
        || journal.successor_pid.is_some() != journal.successor_started.is_some()
        || journal
            .successor_started
            .as_deref()
            .is_some_and(|value| !is_safe_process_start(value))
        || journal.nonce.len() != 32
        || !journal.nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !is_safe_component(&journal.current_version)
        || !is_safe_component(&journal.expected_version)
        || [
            &journal.archive_sha256,
            &journal.watchdog_sha256,
            &journal.old_executable_sha256,
            &journal.new_executable_sha256,
        ]
        .iter()
        .any(|value| {
            value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        return Err("update journal identity is invalid".into());
    }
    let state_dir = path
        .parent()
        .ok_or_else(|| "update journal parent is missing".to_string())?;
    if path.file_name().and_then(|value| value.to_str()) != Some(JOURNAL_FILE)
        || journal.helper != state_dir.join("runtime").join(WATCHDOG_BINARY)
        || journal
            .launch_agent
            .file_name()
            .and_then(|value| value.to_str())
            != Some("dev.slipstream.update-watchdog.plist")
    {
        return Err("update journal helper paths are invalid".into());
    }
    let parent = journal
        .target
        .parent()
        .ok_or_else(|| "update target parent is missing".to_string())?;
    if journal.target.file_name().and_then(|value| value.to_str()) != Some("Slipstream.app")
        || journal.backup.parent() != Some(parent)
        || journal.stage.parent() != Some(parent)
        || journal.backup.file_name().and_then(|value| value.to_str())
            != Some(format!(".Slipstream.app.slipstream-backup-{}", journal.nonce).as_str())
        || journal.stage.file_name().and_then(|value| value.to_str())
            != Some(format!(".Slipstream.app.slipstream-stage-{}", journal.nonce).as_str())
    {
        return Err("update journal bundle paths are invalid".into());
    }
    Ok(())
}

fn bundle_executable(bundle: &Path) -> PathBuf {
    bundle.join("Contents/MacOS/slipstream")
}

fn bundle_version(bundle: &Path) -> Result<String, String> {
    let plist = plist::Value::from_file(bundle.join("Contents/Info.plist"))
        .map_err(|error| format!("bundle Info.plist is invalid: {error}"))?;
    let dictionary = plist
        .as_dictionary()
        .ok_or_else(|| "bundle Info.plist is not a dictionary".to_string())?;
    let string = |key: &str| {
        dictionary
            .get(key)
            .and_then(plist::Value::as_string)
            .ok_or_else(|| format!("bundle {key} is missing"))
    };
    if string("CFBundleIdentifier")? != "dev.slipstream.tray"
        || string("CFBundleExecutable")? != "slipstream"
        || dictionary
            .get("LSUIElement")
            .and_then(plist::Value::as_boolean)
            != Some(true)
    {
        return Err("bundle identity is not Slipstream background-only".into());
    }
    string("CFBundleShortVersionString").map(str::to_string)
}

fn derive_target(current_exe: &Path) -> Result<PathBuf, String> {
    let canonical = current_exe
        .canonicalize()
        .map_err(|error| format!("cannot resolve current executable: {error}"))?;
    if canonical.file_name().and_then(|value| value.to_str()) != Some("slipstream")
        || canonical
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            != Some("MacOS")
    {
        return Err("current executable is outside the packaged Slipstream layout".into());
    }
    let target = canonical
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| "current application bundle is missing".to_string())?
        .to_path_buf();
    if target.file_name().and_then(|value| value.to_str()) != Some("Slipstream.app") {
        return Err("current application bundle name is invalid".into());
    }
    let metadata = fs::symlink_metadata(&target)
        .map_err(|error| format!("cannot inspect current application: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(
            "in-app update requires a nonsymlinked user-owned application; use the DMG".into(),
        );
    }
    if metadata.permissions().mode() & 0o200 == 0 {
        return Err("installed application is not owner-writable; use the DMG".into());
    }
    Ok(target)
}

fn writable_parent_probe(parent: &Path, nonce: &str) -> Result<u64, String> {
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect update target parent: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || !parent_identity_allowed(
            parent,
            metadata.uid(),
            metadata.permissions().mode(),
            current_uid(),
        )
    {
        return Err("update target parent identity is unsafe; use the DMG".into());
    }
    let probe = parent.join(format!(".slipstream-update-write-{nonce}"));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)
        .map_err(|error| format!("update target parent is not writable: {error}; use the DMG"))?;
    file.sync_all()
        .map_err(|error| format!("update target volume is not durable: {error}"))?;
    fs::remove_file(&probe)
        .map_err(|error| format!("cannot remove update write probe: {error}"))?;
    Ok(metadata.dev())
}

fn parent_identity_allowed(parent: &Path, owner: u32, mode: u32, uid: u32) -> bool {
    (owner == uid && mode & 0o022 == 0)
        || (parent == Path::new("/Applications")
            && owner == 0
            && mode & 0o020 != 0
            && mode & 0o002 == 0)
}

fn relative_archive_path(path: &Path) -> Result<Option<PathBuf>, String> {
    let mut components = path.components();
    if components.next() != Some(Component::Normal("Slipstream.app".as_ref())) {
        return Err("update archive escaped the Slipstream.app root".into());
    }
    let relative: PathBuf = components.collect();
    if relative.as_os_str().is_empty() {
        Ok(None)
    } else if relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        Ok(Some(relative))
    } else {
        Err("update archive path is unsafe".into())
    }
}

fn safe_symlink_target(parent: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut depth = parent.components().count();
    for component in target.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            _ => return false,
        }
    }
    depth >= 1
}

fn sync_staged_directories_with<F>(path: &Path, sync: &F) -> Result<(), String>
where
    F: Fn(&Path) -> io::Result<()>,
{
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect staged directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("staged directory identity changed before sync".into());
    }
    for entry in
        fs::read_dir(path).map_err(|error| format!("cannot enumerate staged directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot read staged directory: {error}"))?;
        let child = entry.path();
        let child_metadata = fs::symlink_metadata(&child)
            .map_err(|error| format!("cannot inspect staged entry: {error}"))?;
        if child_metadata.is_dir() {
            sync_staged_directories_with(&child, sync)?;
        } else if !child_metadata.file_type().is_file() && !child_metadata.file_type().is_symlink()
        {
            return Err("staged entry type changed before sync".into());
        }
    }
    sync(path).map_err(|error| format!("cannot sync staged directory: {error}"))
}

fn extract_archive_with_sync<F, D>(
    archive: &[u8],
    stage: &Path,
    sync_file: &F,
    sync_directory_entry: &D,
) -> Result<(), String>
where
    F: Fn(&File) -> io::Result<()>,
    D: Fn(&Path) -> io::Result<()>,
{
    fs::create_dir(stage)
        .map_err(|error| format!("cannot create update staging bundle: {error}"))?;
    fs::set_permissions(stage, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot protect update staging bundle: {error}"))?;
    let decoder = GzDecoder::new(archive);
    let mut tar = tar::Archive::new(decoder);
    let result = (|| {
        for entry in tar
            .entries()
            .map_err(|_| "update archive is unreadable".to_string())?
        {
            let mut entry = entry.map_err(|_| "update archive entry is invalid".to_string())?;
            let archive_path = entry
                .path()
                .map_err(|_| "update archive path is invalid".to_string())?
                .into_owned();
            let Some(relative) = relative_archive_path(&archive_path)? else {
                continue;
            };
            let destination = stage.join(&relative);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("cannot create staged directory: {error}"))?;
            }
            let entry_type = entry.header().entry_type();
            if entry_type.is_dir() {
                fs::create_dir_all(&destination)
                    .map_err(|error| format!("cannot create staged directory: {error}"))?;
            } else if entry_type.is_file() {
                let mode = entry
                    .header()
                    .mode()
                    .map_err(|_| "staged file mode is invalid".to_string())?
                    & 0o777;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(mode)
                    .open(&destination)
                    .map_err(|error| format!("cannot create staged file: {error}"))?;
                io::copy(&mut entry, &mut output)
                    .map_err(|error| format!("cannot extract staged file: {error}"))?;
                sync_file(&output).map_err(|error| format!("cannot sync staged file: {error}"))?;
            } else if entry_type.is_symlink() {
                let target = entry
                    .link_name()
                    .map_err(|_| "staged symlink is invalid".to_string())?
                    .ok_or_else(|| "staged symlink target is missing".to_string())?;
                if !safe_symlink_target(relative.parent().unwrap_or_else(|| Path::new("")), &target)
                {
                    return Err("staged symlink escapes the application".into());
                }
                symlink(&target, &destination)
                    .map_err(|error| format!("cannot create staged symlink: {error}"))?;
            } else {
                return Err("update archive entry type is unsupported".into());
            }
        }
        sync_staged_directories_with(stage, sync_directory_entry)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(stage);
    }
    result
}

fn extract_archive(archive: &[u8], stage: &Path) -> Result<(), String> {
    extract_archive_with_sync(archive, stage, &File::sync_all, &sync_directory)
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn launch_agent_bytes(helper: &Path, journal: &Path, state_dir: &Path) -> Vec<u8> {
    format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{}</string>
<key>ProgramArguments</key><array><string>{}</string><string>--journal</string><string>{}</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ProcessType</key><string>Background</string>
<key>StandardOutPath</key><string>{}</string>
<key>StandardErrorPath</key><string>{}</string>
</dict></plist>
"#, WATCHDOG_LABEL, xml_escape(&helper.display().to_string()), xml_escape(&journal.display().to_string()), xml_escape(&state_dir.join("update-watchdog.stdout.log").display().to_string()), xml_escape(&state_dir.join("update-watchdog.stderr.log").display().to_string())).into_bytes()
}

fn install_runtime_helper(source: &Path, destination: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("packaged update watchdog is missing: {error}"))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("packaged update watchdog is not executable".into());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "watchdog runtime parent is missing".to_string())?;
    ensure_user_directory(parent, true)
        .map_err(|error| format!("cannot protect watchdog runtime: {error}"))?;
    let temporary = parent.join(format!(".{WATCHDOG_BINARY}.{}.tmp", std::process::id()));
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)
        .map_err(|error| format!("cannot open packaged watchdog safely: {error}"))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&temporary)
        .map_err(|error| format!("cannot create watchdog runtime: {error}"))?;
    io::copy(&mut input, &mut output)
        .map_err(|error| format!("cannot copy watchdog runtime: {error}"))?;
    output
        .sync_all()
        .map_err(|error| format!("cannot sync watchdog runtime: {error}"))?;
    fs::rename(&temporary, destination)
        .map_err(|error| format!("cannot publish watchdog runtime: {error}"))?;
    sync_directory(parent)
        .map_err(|error| format!("cannot sync watchdog runtime directory: {error}"))?;
    let source_hash = sha256_file(source)?;
    if sha256_file(destination)? != source_hash {
        return Err("watchdog runtime digest mismatch".into());
    }
    Ok(source_hash)
}

fn watchdog_domain(uid: u32) -> String {
    format!("gui/{uid}")
}

fn watchdog_service_loaded(uid: u32) -> Result<bool, String> {
    let label = format!("{}/{WATCHDOG_LABEL}", watchdog_domain(uid));
    Command::new("/bin/launchctl")
        .args(["print", &label])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|error| format!("cannot inspect durable update watchdog: {error}"))
}

fn unload_watchdog(uid: u32) -> Result<(), String> {
    let label = format!("{}/{WATCHDOG_LABEL}", watchdog_domain(uid));
    let status = Command::new("/bin/launchctl")
        .args(["bootout", &label])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot unload durable update watchdog: {error}"))?;
    if status.success() || !watchdog_service_loaded(uid)? {
        Ok(())
    } else {
        Err("cannot unload existing durable update watchdog".into())
    }
}

fn bootstrap_watchdog(uid: u32, launch_agent: &Path) -> Result<(), String> {
    let domain = watchdog_domain(uid);
    let status = Command::new("/bin/launchctl")
        .args(["bootstrap", &domain])
        .arg(launch_agent)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|error| format!("cannot start durable update watchdog: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("launchd rejected the durable update watchdog; use the DMG".into())
    }
}

fn bootout_watchdog(uid: u32) {
    let _ = unload_watchdog(uid);
}

fn try_transaction_lock(state_dir: &Path) -> Result<Option<File>, String> {
    let lock_path = state_dir.join(JOURNAL_FILE).with_extension("lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|error| format!("cannot open update watchdog lock: {error}"))?;
    // SAFETY: flock receives a live descriptor and does not outlive it.
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(Some(lock));
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
    ) {
        Ok(None)
    } else {
        Err(format!("cannot lock durable update transaction: {error}"))
    }
}

fn recover_prepared_transaction_with<L, U, B>(
    current_exe: &Path,
    state_dir: &Path,
    launch_agents_dir: &Path,
    service_loaded: L,
    unload: U,
    bootstrap: B,
) -> Result<bool, String>
where
    L: Fn(u32) -> Result<bool, String>,
    U: Fn(u32) -> Result<(), String>,
    B: Fn(u32, &Path) -> Result<(), String>,
{
    match fs::symlink_metadata(state_dir) {
        Ok(_) => {
            ensure_user_directory(state_dir, true)
                .map_err(|error| format!("update state directory is unsafe: {error}"))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot inspect update state directory: {error}")),
    }
    let journal_path = state_dir.join(JOURNAL_FILE);
    match fs::symlink_metadata(&journal_path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot inspect prepared update journal: {error}")),
    }
    let Some(transaction_lock) = try_transaction_lock(state_dir)? else {
        // An exact watchdog already owns the only mutation lock. The caller
        // exits so that helper can continue; recovery never rewrites a phase
        // concurrently with a rename.
        return Ok(true);
    };
    match fs::symlink_metadata(&journal_path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "cannot re-inspect prepared update journal: {error}"
            ))
        }
    }
    let mut journal = read_journal(&journal_path)?;
    if journal.phase != TransactionPhase::Prepared {
        return Ok(false);
    }
    if derive_target(current_exe)? != journal.target
        || sha256_file(current_exe)? != journal.old_executable_sha256
        || !journal.stage.exists()
        || journal.backup.exists()
        || sha256_file(&bundle_executable(&journal.stage))? != journal.new_executable_sha256
        || sha256_file(&journal.helper)? != journal.watchdog_sha256
        || journal.launch_agent != launch_agents_dir.join("dev.slipstream.update-watchdog.plist")
    {
        return Err("prepared update recovery identity is invalid".into());
    }
    ensure_user_directory(launch_agents_dir, false)
        .map_err(|error| format!("user LaunchAgents directory is unsafe: {error}"))?;
    if service_loaded(journal.uid)? {
        unload(journal.uid)?;
        if service_loaded(journal.uid)? {
            return Err("existing durable update watchdog remained loaded".into());
        }
    }
    journal.initiator_pid = std::process::id();
    journal.successor_pid = None;
    journal.successor_started = None;
    journal.successor_deadline_unix = None;
    write_journal(&journal_path, &journal)?;
    write_launch_agent_atomic(
        &journal.launch_agent,
        &launch_agent_bytes(&journal.helper, &journal_path, state_dir),
    )?;
    drop(transaction_lock);
    if let Err(error) = bootstrap(journal.uid, &journal.launch_agent) {
        if service_loaded(journal.uid)? {
            return Ok(true);
        }
        return Err(error);
    }
    Ok(true)
}

/// Resume only the crash window after a fully durable Prepared journal was
/// published but before launchd took ownership. The caller must exit cleanly
/// when this returns true so the watchdog can replace the old bundle.
pub fn recover_prepared_transaction(
    current_exe: &Path,
    state_dir: &Path,
    launch_agents_dir: &Path,
) -> Result<bool, String> {
    if std::env::var_os(TRANSACTION_ENV).is_some() {
        return Ok(false);
    }
    recover_prepared_transaction_with(
        current_exe,
        state_dir,
        launch_agents_dir,
        watchdog_service_loaded,
        unload_watchdog,
        bootstrap_watchdog,
    )
}

pub fn prepare_transaction(
    current_exe: &Path,
    state_dir: &Path,
    launch_agents_dir: &Path,
    archive: &[u8],
    current_version: &str,
    expected_version: &str,
) -> Result<PreparedTransaction, String> {
    let uid = current_uid();
    if uid == 0 {
        return Err("the tray updater must not run as root".into());
    }
    ensure_user_directory(state_dir, true)
        .map_err(|error| format!("update state directory is unsafe: {error}"))?;
    let journal_path = state_dir.join(JOURNAL_FILE);
    match fs::symlink_metadata(&journal_path) {
        Ok(_) => return Err("a durable Slipstream update transaction is already active".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect update transaction state: {error}")),
    }
    let target = derive_target(current_exe)?;
    if bundle_version(&target)? != current_version {
        return Err("installed bundle version differs from the running version".into());
    }
    let nonce = random_nonce()?;
    let parent = target
        .parent()
        .ok_or_else(|| "update target parent is missing".to_string())?;
    let target_device = writable_parent_probe(parent, &nonce)?;
    let backup = parent.join(format!(".Slipstream.app.slipstream-backup-{nonce}"));
    let stage = parent.join(format!(".Slipstream.app.slipstream-stage-{nonce}"));
    if backup.exists() || stage.exists() {
        return Err("update staging paths already exist".into());
    }
    extract_archive(archive, &stage)?;
    let cleanup_stage = |message: String| {
        let _ = fs::remove_dir_all(&stage);
        Err(message)
    };
    if fs::metadata(&stage)
        .map(|value| value.dev())
        .unwrap_or_default()
        != target_device
    {
        return cleanup_stage("update staging is not on the target volume; use the DMG".into());
    }
    if bundle_version(&stage)? != expected_version {
        return cleanup_stage("staged bundle version differs from the signed update".into());
    }
    let old_executable_sha256 = sha256_file(&bundle_executable(&target))?;
    let new_executable_sha256 = sha256_file(&bundle_executable(&stage))?;
    let packaged_helper = target.join("Contents/MacOS").join(WATCHDOG_BINARY);
    let helper = state_dir.join("runtime").join(WATCHDOG_BINARY);
    let watchdog_sha256 = match install_runtime_helper(&packaged_helper, &helper) {
        Ok(digest) => digest,
        Err(error) => return cleanup_stage(error),
    };
    ensure_user_directory(launch_agents_dir, false)
        .map_err(|error| format!("cannot create user LaunchAgents directory: {error}"))?;
    let launch_agent = launch_agents_dir.join("dev.slipstream.update-watchdog.plist");
    let journal = UpdateJournalV1 {
        schema_version: JOURNAL_VERSION,
        nonce,
        uid,
        initiator_pid: std::process::id(),
        target,
        backup,
        stage: stage.clone(),
        helper,
        launch_agent: launch_agent.clone(),
        current_version: current_version.to_string(),
        expected_version: expected_version.to_string(),
        archive_sha256: sha256_bytes(archive),
        watchdog_sha256,
        old_executable_sha256,
        new_executable_sha256,
        phase: TransactionPhase::Prepared,
        successor_pid: None,
        successor_started: None,
        successor_deadline_unix: None,
        last_error: None,
    };
    if let Err(error) = write_journal(&journal_path, &journal) {
        return cleanup_stage(error);
    }
    if let Err(error) = write_launch_agent_atomic(
        &launch_agent,
        &launch_agent_bytes(&journal.helper, &journal_path, state_dir),
    ) {
        let _ = fs::remove_file(&journal_path);
        return cleanup_stage(error);
    }
    bootout_watchdog(uid);
    if let Err(error) = bootstrap_watchdog(uid, &launch_agent) {
        let _ = fs::remove_file(&launch_agent);
        let _ = fs::remove_file(&journal_path);
        return cleanup_stage(error);
    }
    Ok(PreparedTransaction { journal_path })
}

fn process_exists(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) performs a permission/existence check only.
    let result = unsafe { libc::kill(pid as i32, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessSnapshot {
    pid: u32,
    uid: u32,
    state: char,
    started: String,
    command: String,
}

impl ProcessSnapshot {
    fn is_zombie(&self) -> bool {
        self.state == 'Z'
    }
}

fn parse_process_snapshot(line: &str) -> Option<ProcessSnapshot> {
    let mut fields = line.split_whitespace();
    let pid = fields.next()?.parse().ok()?;
    let uid = fields.next()?.parse().ok()?;
    let state = fields.next()?.chars().next()?;
    let started = (0..5)
        .map(|_| fields.next())
        .collect::<Option<Vec<_>>>()?
        .join(" ");
    let command = fields.collect::<Vec<_>>().join(" ");
    if command.is_empty() || !is_safe_process_start(&started) {
        return None;
    }
    Some(ProcessSnapshot {
        pid,
        uid,
        state,
        started,
        command,
    })
}

fn process_snapshot(pid: u32) -> Option<ProcessSnapshot> {
    let output = Command::new("/bin/ps")
        .args([
            "-ww",
            "-p",
            &pid.to_string(),
            "-o",
            "pid=",
            "-o",
            "uid=",
            "-o",
            "state=",
            "-o",
            "lstart=",
            "-o",
            "command=",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_process_snapshot(&String::from_utf8_lossy(&output.stdout))
}

fn process_command(pid: u32) -> Option<String> {
    process_snapshot(pid)
        .filter(|snapshot| !snapshot.is_zombie())
        .map(|snapshot| snapshot.command)
}

fn child_has_exited(child: &mut Child) -> Result<bool, String> {
    child
        .try_wait()
        .map(|status| status.is_some())
        .map_err(|error| format!("cannot inspect update successor: {error}"))
}

fn command_matches_target(command: &str, target: &Path) -> bool {
    let expected = bundle_executable(target).display().to_string();
    command == expected || command.starts_with(&(expected + " "))
}

fn snapshot_matches_successor(snapshot: &ProcessSnapshot, journal: &UpdateJournalV1) -> bool {
    Some(snapshot.pid) == journal.successor_pid
        && snapshot.uid == journal.uid
        && Some(snapshot.started.as_str()) == journal.successor_started.as_deref()
        && !snapshot.is_zombie()
        && command_matches_target(&snapshot.command, &journal.target)
}

fn successor_has_exited(
    journal: &UpdateJournalV1,
    child: Option<&mut Child>,
) -> Result<bool, String> {
    let Some(pid) = journal.successor_pid else {
        return Ok(true);
    };
    if let Some(child) = child {
        if child.id() != pid {
            return Err("spawned successor handle does not match the journal PID".into());
        }
        return child_has_exited(child);
    }
    Ok(!process_exists(pid)
        || process_snapshot(pid).map_or(true, |snapshot| {
            !snapshot_matches_successor(&snapshot, journal)
        }))
}

fn signal_exact_successor(journal: &UpdateJournalV1, signal: i32) -> Result<bool, String> {
    let Some(pid) = journal.successor_pid else {
        return Ok(false);
    };
    let Some(snapshot) = process_snapshot(pid) else {
        if process_exists(pid) {
            return Err("cannot revalidate live update successor identity".into());
        }
        return Ok(false);
    };
    if !snapshot_matches_successor(&snapshot, journal) {
        return Ok(false);
    }
    // SAFETY: PID, UID, process birth time, and exact command were revalidated
    // immediately before this signal.
    if unsafe { libc::kill(pid as i32, signal) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(format!("cannot signal failed update successor: {error}"));
        }
        return Ok(false);
    }
    Ok(true)
}

fn stop_exact_successor(
    journal: &UpdateJournalV1,
    mut spawned_child: Option<&mut Child>,
) -> Result<(), String> {
    if journal.successor_pid.is_none() {
        return Ok(());
    }
    if successor_has_exited(journal, spawned_child.as_deref_mut())? {
        return Ok(());
    }
    if !signal_exact_successor(journal, libc::SIGTERM)? {
        return Ok(());
    }
    for _ in 0..12 {
        if successor_has_exited(journal, spawned_child.as_deref_mut())? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    if !signal_exact_successor(journal, libc::SIGKILL)? {
        return Ok(());
    }
    for _ in 0..20 {
        if successor_has_exited(journal, spawned_child.as_deref_mut())? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("failed update successor did not terminate within the bounded deadline".into())
}

fn move_exact(from: &Path, to: &Path, expected_executable_hash: &str) -> Result<(), String> {
    if sha256_file(&bundle_executable(from))? != expected_executable_hash {
        return Err(format!(
            "bundle digest changed before moving {}",
            from.display()
        ));
    }
    fs::rename(from, to).map_err(|error| {
        format!(
            "cannot move {} to {}: {error}",
            from.display(),
            to.display()
        )
    })?;
    sync_directory(to.parent().unwrap_or_else(|| Path::new("/")))
        .map_err(|error| format!("cannot sync update target directory: {error}"))
}

fn set_phase(
    path: &Path,
    journal: &mut UpdateJournalV1,
    phase: TransactionPhase,
) -> Result<(), String> {
    journal.phase = phase;
    journal.last_error = None;
    write_journal(path, journal)
}

fn record_failure(path: &Path, journal: &mut UpdateJournalV1, error: &str) {
    journal.last_error = Some(error.chars().take(512).collect());
    let _ = write_journal(path, journal);
}

fn spawn_bundle(bundle: &Path, journal_path: &Path) -> Result<Child, String> {
    let executable = bundle_executable(bundle);
    Command::new(&executable)
        .env(TRANSACTION_ENV, journal_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot launch {}: {error}", executable.display()))
}

fn ack_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("ack.json")
}

fn find_exact_successor(journal: &UpdateJournalV1) -> Result<Option<ProcessSnapshot>, String> {
    let output = Command::new("/bin/ps")
        .args(["-ww", "-axo", "pid=,uid=,state=,lstart=,command="])
        .output()
        .map_err(|error| format!("cannot enumerate update successor: {error}"))?;
    if !output.status.success() {
        return Err("cannot enumerate update successor".into());
    }
    let mut matches = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some(snapshot) = parse_process_snapshot(line) else {
            continue;
        };
        if snapshot.uid == journal.uid
            && snapshot.pid != std::process::id()
            && !snapshot.is_zombie()
            && command_matches_target(&snapshot.command, &journal.target)
        {
            matches.push(snapshot);
        }
    }
    match matches.as_slice() {
        [] => Ok(None),
        [snapshot] => Ok(Some(snapshot.clone())),
        _ => Err("multiple exact update successor processes exist".into()),
    }
}

fn wait_for_spawned_successor(
    child: &mut Child,
    journal: &UpdateJournalV1,
) -> Result<ProcessSnapshot, String> {
    for _ in 0..20 {
        if child_has_exited(child)? {
            return Err("new Slipstream successor exited before identity capture".into());
        }
        if let Some(snapshot) = process_snapshot(child.id()) {
            if snapshot.uid == journal.uid
                && !snapshot.is_zombie()
                && command_matches_target(&snapshot.command, &journal.target)
            {
                return Ok(snapshot);
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("new Slipstream successor identity was not observable".into())
}

fn read_valid_ack(
    path: &Path,
    journal: &UpdateJournalV1,
) -> Result<Option<SuccessorAckV1>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let ack: SuccessorAckV1 = serde_json::from_slice(&read_private_file(path, MAX_ACK_BYTES)?)
        .map_err(|error| format!("successor ack is invalid: {error}"))?;
    if ack.schema_version != 1
        || ack.nonce != journal.nonce
        || ack.uid != journal.uid
        || Some(ack.pid) != journal.successor_pid
        || ack.version != journal.expected_version
        || ack.target != journal.target
        || ack.executable_sha256 != journal.new_executable_sha256
        || ack.heartbeat_seq == 0
    {
        return Err("successor ack does not match the durable transaction".into());
    }
    Ok(Some(ack))
}

fn unload_and_remove_with<F>(
    journal: &UpdateJournalV1,
    journal_path: &Path,
    try_bootout: F,
) -> Result<(), String>
where
    F: FnOnce(&str) -> io::Result<()>,
{
    if let Err(error) = fs::remove_file(&journal.launch_agent) {
        if error.kind() != io::ErrorKind::NotFound {
            return Err(format!("cannot remove update LaunchAgent: {error}"));
        }
    }
    let _ = fs::remove_file(ack_path(journal_path));
    fs::remove_file(journal_path)
        .map_err(|error| format!("cannot remove completed update journal: {error}"))?;
    let label = format!("gui/{}/{WATCHDOG_LABEL}", journal.uid);
    // A best-effort self-bootout may fail or terminate this helper before the
    // child command returns.  The LaunchAgent's SuccessfulExit=false policy is
    // the durable fallback: after all transaction state has been removed, this
    // function has no fallible work left and the helper exits successfully, so
    // launchd must not restart it even if the service remains loaded.
    let _ = try_bootout(&label);
    Ok(())
}

fn unload_and_remove(journal: &UpdateJournalV1, journal_path: &Path) -> Result<(), String> {
    unload_and_remove_with(journal, journal_path, request_launchctl_bootout)
}

fn request_launchctl_bootout(label: &str) -> io::Result<()> {
    #[cfg(test)]
    {
        let _ = label;
        Ok(())
    }
    #[cfg(not(test))]
    {
        Command::new("/bin/launchctl")
            .args(["bootout", label])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_| ())
    }
}

fn complete_success(journal_path: &Path, journal: &mut UpdateJournalV1) -> Result<(), String> {
    set_phase(journal_path, journal, TransactionPhase::Acknowledged)?;
    if journal.backup.exists() {
        if sha256_file(&bundle_executable(&journal.backup))? != journal.old_executable_sha256 {
            return Err("old bundle backup digest changed before cleanup".into());
        }
        fs::remove_dir_all(&journal.backup)
            .map_err(|error| format!("cannot remove acknowledged old bundle: {error}"))?;
    }
    if journal.stage.exists() {
        fs::remove_dir_all(&journal.stage)
            .map_err(|error| format!("cannot remove stale update staging bundle: {error}"))?;
    }
    unload_and_remove(journal, journal_path)
}

fn direct_relaunch(bundle: &Path, journal_path: &Path) -> Result<(), String> {
    spawn_bundle(bundle, journal_path).map(|_| ())
}

fn finish_rollback_with<R>(
    journal_path: &Path,
    journal: &mut UpdateJournalV1,
    relaunch: &mut R,
) -> Result<(), String>
where
    R: FnMut(&Path, &Path) -> Result<(), String>,
{
    if journal.phase != TransactionPhase::OldRelaunched {
        relaunch(&journal.target, journal_path)?;
        set_phase(journal_path, journal, TransactionPhase::OldRelaunched)?;
    }
    if journal.stage.exists() {
        fs::remove_dir_all(&journal.stage)
            .map_err(|error| format!("cannot remove failed new bundle: {error}"))?;
    }
    let failed = journal_path.with_file_name(format!(
        "app-update-transaction-failed-{}.json",
        journal.nonce
    ));
    write_private_atomic(
        &failed,
        &serde_json::to_vec(journal).map_err(|error| error.to_string())?,
    )?;
    unload_and_remove(journal, journal_path)
}

fn finish_rollback(journal_path: &Path, journal: &mut UpdateJournalV1) -> Result<(), String> {
    finish_rollback_with(journal_path, journal, &mut direct_relaunch)
}

fn rollback_impl_with_child_and_relaunch<R>(
    journal_path: &Path,
    journal: &mut UpdateJournalV1,
    spawned_child: Option<&mut Child>,
    stop_successor: bool,
    relaunch: &mut R,
) -> Result<(), String>
where
    R: FnMut(&Path, &Path) -> Result<(), String>,
{
    set_phase(journal_path, journal, TransactionPhase::RollbackPlanned)?;
    if stop_successor {
        stop_exact_successor(journal, spawned_child)?;
    }
    if journal.target.exists() {
        let target_hash = sha256_file(&bundle_executable(&journal.target))?;
        if target_hash == journal.old_executable_sha256 && !journal.backup.exists() {
            set_phase(journal_path, journal, TransactionPhase::RolledBack)?;
            return finish_rollback_with(journal_path, journal, relaunch);
        }
        if target_hash != journal.new_executable_sha256 {
            return Err("active bundle digest is unknown during rollback".into());
        }
        if journal.stage.exists() {
            return Err("both active and quarantined new bundles exist during rollback".into());
        }
        move_exact(
            &journal.target,
            &journal.stage,
            &journal.new_executable_sha256,
        )?;
    }
    set_phase(journal_path, journal, TransactionPhase::NewQuarantined)?;
    if !journal.target.exists() {
        move_exact(
            &journal.backup,
            &journal.target,
            &journal.old_executable_sha256,
        )?;
    }
    set_phase(journal_path, journal, TransactionPhase::RolledBack)?;
    finish_rollback_with(journal_path, journal, relaunch)
}

#[cfg(test)]
fn rollback_impl_with_relaunch<R>(
    journal_path: &Path,
    journal: &mut UpdateJournalV1,
    stop_successor: bool,
    relaunch: &mut R,
) -> Result<(), String>
where
    R: FnMut(&Path, &Path) -> Result<(), String>,
{
    rollback_impl_with_child_and_relaunch(journal_path, journal, None, stop_successor, relaunch)
}

fn rollback(
    journal_path: &Path,
    journal: &mut UpdateJournalV1,
    spawned_child: Option<&mut Child>,
) -> Result<(), String> {
    rollback_impl_with_child_and_relaunch(
        journal_path,
        journal,
        spawned_child,
        true,
        &mut direct_relaunch,
    )
}

fn advance_prelaunch_phase(
    journal_path: &Path,
    journal: &mut UpdateJournalV1,
) -> Result<bool, String> {
    if journal.phase == TransactionPhase::Prepared {
        if !journal.target.exists() && journal.backup.exists() {
            if sha256_file(&bundle_executable(&journal.backup))? != journal.old_executable_sha256 {
                return Err("backup digest changed before journal recovery".into());
            }
            set_phase(journal_path, journal, TransactionPhase::BackupMoved)?;
        } else {
            if journal.backup.exists() {
                return Err("unexpected update backup already exists".into());
            }
            move_exact(
                &journal.target,
                &journal.backup,
                &journal.old_executable_sha256,
            )?;
            set_phase(journal_path, journal, TransactionPhase::BackupMoved)?;
        }
        return Ok(true);
    }
    if journal.phase == TransactionPhase::BackupMoved {
        if journal.target.exists() && !journal.stage.exists() {
            if sha256_file(&bundle_executable(&journal.target))? != journal.new_executable_sha256 {
                return Err("activated update digest changed before journal recovery".into());
            }
            set_phase(journal_path, journal, TransactionPhase::NewActivated)?;
        } else {
            if journal.target.exists() || !journal.stage.exists() {
                return Err("update activation filesystem state is ambiguous".into());
            }
            move_exact(
                &journal.stage,
                &journal.target,
                &journal.new_executable_sha256,
            )?;
            set_phase(journal_path, journal, TransactionPhase::NewActivated)?;
        }
        return Ok(true);
    }
    if journal.phase == TransactionPhase::NewActivated {
        if !journal.target.exists()
            || !journal.backup.exists()
            || sha256_file(&bundle_executable(&journal.target))? != journal.new_executable_sha256
            || sha256_file(&bundle_executable(&journal.backup))? != journal.old_executable_sha256
        {
            return Err("activated update filesystem identity is invalid".into());
        }
        set_phase(
            journal_path,
            journal,
            TransactionPhase::SuccessorLaunchPlanned,
        )?;
        return Ok(true);
    }
    Ok(false)
}

fn run_locked_watchdog(journal_path: &Path, journal: &mut UpdateJournalV1) -> Result<(), String> {
    let initiator_executable = bundle_executable(&journal.target).display().to_string();
    while process_exists(journal.initiator_pid)
        && process_command(journal.initiator_pid).is_some_and(|command| {
            command == initiator_executable
                || command.starts_with(&(initiator_executable.clone() + " "))
        })
    {
        thread::sleep(Duration::from_millis(100));
    }
    while advance_prelaunch_phase(journal_path, journal)? {
        // Persist and fsync each rename as its own recovery boundary.
    }
    let mut spawned_successor = None;
    if journal.phase == TransactionPhase::SuccessorLaunchPlanned {
        let snapshot = match find_exact_successor(journal)? {
            Some(snapshot) => snapshot,
            None => {
                let mut child = spawn_bundle(&journal.target, journal_path)?;
                let snapshot = wait_for_spawned_successor(&mut child, journal)?;
                spawned_successor = Some(child);
                snapshot
            }
        };
        journal.successor_pid = Some(snapshot.pid);
        journal.successor_started = Some(snapshot.started);
        journal.successor_deadline_unix = Some(unix_now().saturating_add(ACK_TIMEOUT_SECS));
        set_phase(journal_path, journal, TransactionPhase::SuccessorLaunched)?;
    }
    if journal.phase == TransactionPhase::SuccessorLaunched {
        loop {
            match read_valid_ack(&ack_path(journal_path), journal) {
                Ok(Some(_)) => return complete_success(journal_path, journal),
                Ok(None) => {}
                Err(error) => {
                    return rollback(journal_path, journal, spawned_successor.as_mut()).map_err(
                        |rollback_error| format!("{error}; rollback failed: {rollback_error}"),
                    )
                }
            }
            if unix_now() >= journal.successor_deadline_unix.unwrap_or(0)
                || match journal.successor_pid {
                    Some(_) => successor_has_exited(journal, spawned_successor.as_mut())?,
                    None => true,
                }
            {
                return rollback(journal_path, journal, spawned_successor.as_mut());
            }
            thread::sleep(Duration::from_millis(250));
        }
    }
    if matches!(
        journal.phase,
        TransactionPhase::Acknowledged | TransactionPhase::CleanupFailed
    ) && read_valid_ack(&ack_path(journal_path), journal)?.is_some()
    {
        return complete_success(journal_path, journal);
    }
    if matches!(
        journal.phase,
        TransactionPhase::RollbackPlanned | TransactionPhase::NewQuarantined
    ) {
        return rollback(journal_path, journal, None);
    }
    if matches!(
        journal.phase,
        TransactionPhase::RolledBack | TransactionPhase::OldRelaunched
    ) {
        return finish_rollback(journal_path, journal);
    }
    Ok(())
}

pub fn run_watchdog(journal_path: &Path) -> Result<(), String> {
    let state_dir = journal_path
        .parent()
        .ok_or_else(|| "update journal parent is missing".to_string())?;
    ensure_user_directory(state_dir, true)
        .map_err(|error| format!("update state directory is unsafe: {error}"))?;
    let Some(_lock) = try_transaction_lock(state_dir)? else {
        return Ok(());
    };
    let mut journal = read_journal(journal_path)?;
    let current_exe = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|error| format!("cannot identify update watchdog executable: {error}"))?;
    if current_exe != journal.helper || sha256_file(&current_exe)? != journal.watchdog_sha256 {
        return Err("update watchdog executable identity mismatch".into());
    }
    let result = run_locked_watchdog(journal_path, &mut journal);
    if let Err(error) = &result {
        record_failure(journal_path, &mut journal, error);
    }
    result
}

pub fn pending_successor_ack(
    current_exe: &Path,
    current_version: &str,
) -> Result<Option<PendingSuccessorAck>, String> {
    let Some(value) = std::env::var_os(TRANSACTION_ENV) else {
        return Ok(None);
    };
    let journal_path = PathBuf::from(value);
    let mut journal = read_journal(&journal_path)?;
    if journal.expected_version != current_version
        || derive_target(current_exe)? != journal.target
        || sha256_file(current_exe)? != journal.new_executable_sha256
    {
        return Err("running successor does not match its update transaction".into());
    }
    if journal.phase == TransactionPhase::SuccessorLaunchPlanned {
        for _ in 0..200 {
            thread::sleep(Duration::from_millis(50));
            journal = read_journal(&journal_path)?;
            if journal.phase != TransactionPhase::SuccessorLaunchPlanned {
                break;
            }
        }
    }
    if journal.phase != TransactionPhase::SuccessorLaunched
        || journal.expected_version != current_version
        || derive_target(current_exe)? != journal.target
        || Some(std::process::id()) != journal.successor_pid
        || sha256_file(current_exe)? != journal.new_executable_sha256
    {
        return Err("running successor does not match its update transaction".into());
    }
    Ok(Some(PendingSuccessorAck {
        ack_path: ack_path(&journal_path),
        journal_path,
        nonce: journal.nonce,
        uid: journal.uid,
        target: journal.target,
        version: journal.expected_version,
        executable_sha256: journal.new_executable_sha256,
    }))
}

pub fn acknowledge_successor(
    context: &PendingSuccessorAck,
    heartbeat_seq: u64,
) -> Result<(), String> {
    if heartbeat_seq == 0 {
        return Err("successor acknowledgement requires a fresh daemon heartbeat".into());
    }
    let journal = read_journal(&context.journal_path)?;
    if journal.phase != TransactionPhase::SuccessorLaunched
        || journal.nonce != context.nonce
        || journal.expected_version != context.version
        || journal.target != context.target
    {
        return Err("update transaction changed before successor acknowledgement".into());
    }
    let ack = SuccessorAckV1 {
        schema_version: 1,
        nonce: context.nonce.clone(),
        uid: context.uid,
        pid: std::process::id(),
        version: context.version.clone(),
        target: context.target.clone(),
        executable_sha256: context.executable_sha256.clone(),
        heartbeat_seq,
    };
    write_private_atomic(
        &context.ack_path,
        &serde_json::to_vec(&ack).map_err(|error| error.to_string())?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::cell::{Cell, RefCell};
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn journal(root: &Path) -> (PathBuf, UpdateJournalV1) {
        let state = root.join("state");
        fs::create_dir_all(state.join("runtime")).unwrap();
        let target = root.join("apps/Slipstream.app");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let nonce = "a".repeat(32);
        let value = UpdateJournalV1 {
            schema_version: 1,
            nonce: nonce.clone(),
            uid: current_uid(),
            initiator_pid: std::process::id(),
            target: target.clone(),
            backup: target
                .parent()
                .unwrap()
                .join(format!(".Slipstream.app.slipstream-backup-{nonce}")),
            stage: target
                .parent()
                .unwrap()
                .join(format!(".Slipstream.app.slipstream-stage-{nonce}")),
            helper: state.join("runtime").join(WATCHDOG_BINARY),
            launch_agent: root.join("LaunchAgents/dev.slipstream.update-watchdog.plist"),
            current_version: "0.1.9-preview.23".into(),
            expected_version: "0.1.9-preview.24".into(),
            archive_sha256: "b".repeat(64),
            watchdog_sha256: "e".repeat(64),
            old_executable_sha256: "c".repeat(64),
            new_executable_sha256: "d".repeat(64),
            phase: TransactionPhase::Prepared,
            successor_pid: None,
            successor_started: None,
            successor_deadline_unix: None,
            last_error: None,
        };
        (state.join(JOURNAL_FILE), value)
    }

    fn executable(bundle: &Path, contents: &[u8]) -> String {
        let path = bundle_executable(bundle);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        sha256_file(&path).unwrap()
    }

    fn archive_with_executable(contents: &[u8]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header
            .set_path("Slipstream.app/Contents/MacOS/slipstream")
            .unwrap();
        header.set_mode(0o700);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        builder.append(&header, contents).unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn journal_rejects_cross_target_or_public_state() {
        let root = TempDir::new().unwrap();
        let (path, mut value) = journal(root.path());
        value.backup = root.path().join("elsewhere/backup");
        write_private_atomic(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_journal(&path).unwrap_err().contains("bundle paths"));
        value = journal(root.path()).1;
        write_private_atomic(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_journal(&path).unwrap_err().contains("owner-private"));
    }

    #[test]
    fn successor_ack_is_bound_to_nonce_pid_version_target_digest_and_heartbeat() {
        let root = TempDir::new().unwrap();
        let (path, mut value) = journal(root.path());
        value.phase = TransactionPhase::SuccessorLaunched;
        value.successor_pid = Some(std::process::id());
        value.successor_started = Some("Thu Aug 20 12:34:56 2026".into());
        write_private_atomic(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        let context = PendingSuccessorAck {
            journal_path: path.clone(),
            ack_path: ack_path(&path),
            nonce: value.nonce.clone(),
            uid: value.uid,
            target: value.target.clone(),
            version: value.expected_version.clone(),
            executable_sha256: value.new_executable_sha256.clone(),
        };
        assert!(acknowledge_successor(&context, 0).is_err());
        acknowledge_successor(&context, 7).unwrap();
        assert_eq!(
            read_valid_ack(&ack_path(&path), &value)
                .unwrap()
                .unwrap()
                .heartbeat_seq,
            7
        );
        let mut wrong = value.clone();
        wrong.expected_version = "0.1.9-preview.25".into();
        assert!(read_valid_ack(&ack_path(&path), &wrong).is_err());
    }

    #[test]
    fn launch_agent_is_background_keepalive_and_direct_exec_only() {
        let bytes = launch_agent_bytes(
            Path::new("/private/helper"),
            Path::new("/private/journal"),
            Path::new("/private/state"),
        );
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("<string>Background</string>"));
        assert!(text.contains("<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>"));
        assert!(!text.contains("<key>KeepAlive</key><true/>"));
        assert!(!text.contains("open -"));
        assert!(!text.contains("Aqua"));
    }

    #[test]
    fn exited_spawned_successor_is_reaped_instead_of_reported_alive() {
        let root = TempDir::new().unwrap();
        let (_, mut value) = journal(root.path());
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        value.successor_pid = Some(child.id());
        value.successor_started = Some("Thu Aug 20 12:34:56 2026".into());
        let mut reaped = false;
        for _ in 0..100 {
            if successor_has_exited(&value, Some(&mut child)).unwrap() {
                reaped = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(reaped, "short-lived successor was not reaped");
        assert!(child.try_wait().unwrap().is_some());
        assert!(
            parse_process_snapshot("42 501 Z Thu Aug 20 12:34:56 2026 <defunct>")
                .unwrap()
                .is_zombie()
        );
    }

    #[test]
    fn rollback_restores_old_bundle_before_one_injected_relaunch_request() {
        let root = TempDir::new().unwrap();
        let (path, mut value) = journal(root.path());
        value.new_executable_sha256 = executable(&value.target, b"new");
        value.old_executable_sha256 = executable(&value.backup, b"old");
        value.phase = TransactionPhase::SuccessorLaunched;
        value.successor_deadline_unix = Some(unix_now().saturating_sub(1));
        write_journal(&path, &value).unwrap();

        let relaunches = Cell::new(0usize);
        let expected_target = value.target.clone();
        let mut relaunch = |bundle: &Path, journal_path: &Path| {
            relaunches.set(relaunches.get() + 1);
            assert_eq!(bundle, expected_target);
            assert_eq!(
                fs::read(bundle_executable(bundle)).unwrap(),
                b"old",
                "old bundle must be restored before relaunch is requested"
            );
            assert_eq!(
                read_journal(journal_path).unwrap().phase,
                TransactionPhase::RolledBack
            );
            Ok(())
        };
        rollback_impl_with_relaunch(&path, &mut value, false, &mut relaunch).unwrap();

        assert_eq!(relaunches.get(), 1);
        assert_eq!(value.phase, TransactionPhase::OldRelaunched);
        assert!(!path.exists());
    }

    #[test]
    fn updater_unit_tests_never_launch_a_temporary_app_bundle() {
        let source = include_str!("updater_transaction.rs");
        let tests = source.split("#[cfg(test)]\nmod tests").nth(1).unwrap();
        let forbidden = ["spawn", "_bundle("].concat();
        assert!(!tests.contains(&forbidden));
    }

    #[test]
    fn failed_bootout_cannot_restart_after_successful_cleanup() {
        let root = TempDir::new().unwrap();
        let (path, value) = journal(root.path());
        fs::create_dir_all(value.launch_agent.parent().unwrap()).unwrap();
        fs::write(
            &value.launch_agent,
            launch_agent_bytes(&value.helper, &path, path.parent().unwrap()),
        )
        .unwrap();
        write_journal(&path, &value).unwrap();
        write_private_atomic(&ack_path(&path), b"ack").unwrap();

        unload_and_remove_with(&value, &path, |_| {
            Err(io::Error::other("injected launchctl failure"))
        })
        .unwrap();

        assert!(!value.launch_agent.exists());
        assert!(!path.exists());
        assert!(!ack_path(&path).exists());
        let policy = String::from_utf8(launch_agent_bytes(
            &value.helper,
            &path,
            path.parent().unwrap(),
        ))
        .unwrap();
        assert!(
            policy.contains("<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>")
        );
    }

    #[test]
    fn cleanup_failure_retains_journal_for_launchd_retry() {
        let root = TempDir::new().unwrap();
        let (path, value) = journal(root.path());
        fs::create_dir_all(&value.launch_agent).unwrap();
        write_journal(&path, &value).unwrap();

        let result = unload_and_remove_with(&value, &path, |_| {
            panic!("bootout must not run before durable state cleanup succeeds")
        });

        assert!(result.is_err());
        assert!(path.exists());
    }

    #[test]
    fn symlink_targets_cannot_escape_staging_bundle() {
        assert!(safe_symlink_target(
            Path::new("Contents/Frameworks/F.framework"),
            Path::new("Versions/Current")
        ));
        assert!(!safe_symlink_target(
            Path::new("Contents"),
            Path::new("../../outside")
        ));
        assert!(!safe_symlink_target(
            Path::new("Contents"),
            Path::new("/tmp/outside")
        ));
    }

    #[test]
    fn canonical_applications_parent_allows_root_admin_but_not_other_owners() {
        let uid = 501;
        assert!(parent_identity_allowed(
            Path::new("/Applications"),
            0,
            0o40775,
            uid
        ));
        assert!(!parent_identity_allowed(
            Path::new("/Applications"),
            502,
            0o40777,
            uid
        ));
        assert!(!parent_identity_allowed(
            Path::new("/tmp/Applications"),
            0,
            0o40777,
            uid
        ));
        assert!(parent_identity_allowed(
            Path::new("/Users/me/Applications"),
            uid,
            0o40700,
            uid
        ));
    }

    #[test]
    fn every_prelaunch_rename_is_resumable_from_before_or_after_journal_publish() {
        for crash_after_rename in [false, true] {
            let root = TempDir::new().unwrap();
            let (path, mut value) = journal(root.path());
            value.old_executable_sha256 = executable(&value.target, b"old");
            value.new_executable_sha256 = executable(&value.stage, b"new");
            if crash_after_rename {
                fs::rename(&value.target, &value.backup).unwrap();
            }
            write_journal(&path, &value).unwrap();
            assert!(advance_prelaunch_phase(&path, &mut value).unwrap());
            assert_eq!(value.phase, TransactionPhase::BackupMoved);
            assert!(!value.target.exists());
            assert!(value.backup.exists());

            if crash_after_rename {
                fs::rename(&value.stage, &value.target).unwrap();
            }
            assert!(advance_prelaunch_phase(&path, &mut value).unwrap());
            assert_eq!(value.phase, TransactionPhase::NewActivated);
            assert!(value.target.exists());
            assert!(!value.stage.exists());
            assert!(value.backup.exists());

            assert!(advance_prelaunch_phase(&path, &mut value).unwrap());
            assert_eq!(value.phase, TransactionPhase::SuccessorLaunchPlanned);
            assert!(!advance_prelaunch_phase(&path, &mut value).unwrap());
        }
    }

    #[test]
    fn wrong_or_stale_ack_rolls_back_and_relaunches_exact_old_bundle() {
        let root = TempDir::new().unwrap();
        let (path, mut value) = journal(root.path());
        value.old_executable_sha256 = executable(&value.backup, b"#!/bin/sh\nexit 0\n");
        fs::set_permissions(
            bundle_executable(&value.backup),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let new_hash = executable(&value.target, b"new");
        value.new_executable_sha256 = new_hash.clone();
        value.phase = TransactionPhase::SuccessorLaunched;
        value.successor_pid = Some(std::process::id());
        value.successor_started = Some("Thu Aug 20 12:34:56 2026".into());
        value.successor_deadline_unix = Some(unix_now().saturating_sub(1));
        write_journal(&path, &value).unwrap();

        let wrong = SuccessorAckV1 {
            schema_version: 1,
            nonce: value.nonce.clone(),
            uid: value.uid,
            pid: std::process::id(),
            version: "0.1.9-preview.99".into(),
            target: value.target.clone(),
            executable_sha256: new_hash,
            heartbeat_seq: 1,
        };
        write_private_atomic(&ack_path(&path), &serde_json::to_vec(&wrong).unwrap()).unwrap();
        assert!(read_valid_ack(&ack_path(&path), &value).is_err());

        let relaunches = Cell::new(0usize);
        let mut relaunch = |_: &Path, _: &Path| {
            relaunches.set(relaunches.get() + 1);
            Ok(())
        };
        rollback_impl_with_relaunch(&path, &mut value, false, &mut relaunch).unwrap();
        assert_eq!(relaunches.get(), 1);
        assert_eq!(
            fs::read(bundle_executable(&value.target)).unwrap(),
            b"#!/bin/sh\nexit 0\n"
        );
        assert!(!value.backup.exists());
        assert!(!path.exists());
        assert!(root
            .path()
            .join("state")
            .join(format!(
                "app-update-transaction-failed-{}.json",
                value.nonce
            ))
            .exists());
    }

    #[test]
    fn staged_files_and_directories_are_synced_before_extract_returns() {
        let root = TempDir::new().unwrap();
        let stage = root.path().join("stage/Slipstream.app");
        fs::create_dir(stage.parent().unwrap()).unwrap();
        let file_syncs = Cell::new(0usize);
        let directory_syncs = RefCell::new(Vec::new());
        extract_archive_with_sync(
            &archive_with_executable(b"new"),
            &stage,
            &|_| {
                file_syncs.set(file_syncs.get() + 1);
                Ok(())
            },
            &|path| {
                directory_syncs.borrow_mut().push(path.to_path_buf());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(file_syncs.get(), 1);
        let synced = directory_syncs.borrow();
        assert_eq!(synced.last(), Some(&stage));
        let macos = stage.join("Contents/MacOS");
        let contents = stage.join("Contents");
        assert!(
            synced.iter().position(|path| path == &macos).unwrap()
                < synced.iter().position(|path| path == &contents).unwrap()
        );
        assert!(
            synced.iter().position(|path| path == &contents).unwrap()
                < synced.iter().position(|path| path == &stage).unwrap()
        );
    }

    #[test]
    fn staged_file_sync_failure_removes_unpublished_stage() {
        let root = TempDir::new().unwrap();
        let stage = root.path().join("stage/Slipstream.app");
        fs::create_dir(stage.parent().unwrap()).unwrap();
        let result = extract_archive_with_sync(
            &archive_with_executable(b"new"),
            &stage,
            &|_| Err(io::Error::other("injected file sync failure")),
            &|_| Ok(()),
        );
        assert!(result.unwrap_err().contains("sync staged file"));
        assert!(!stage.exists());
    }

    #[test]
    fn private_state_and_runtime_directories_never_follow_symlinks() {
        let root = TempDir::new().unwrap();
        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        let linked_state = root.path().join("state");
        symlink(&real, &linked_state).unwrap();
        assert!(ensure_user_directory(&linked_state, true).is_err());

        let state = root.path().join("private-state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_user_directory(&state, true).unwrap();
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o077,
            0
        );

        let runtime_link = state.join("runtime");
        symlink(&real, &runtime_link).unwrap();
        assert!(ensure_user_directory(&runtime_link, true).is_err());
    }

    #[test]
    fn private_file_reads_reject_symlinks_even_inside_private_state() {
        let root = TempDir::new().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        ensure_user_directory(&state, true).unwrap();
        let real = state.join("real.json");
        write_private_atomic(&real, b"{}").unwrap();
        let linked = state.join("linked.json");
        symlink(&real, &linked).unwrap();
        assert!(read_private_file(&linked, 16).is_err());
    }

    #[test]
    fn user_owned_update_parent_must_not_be_group_or_other_writable() {
        let uid = current_uid();
        let path = Path::new("/Users/me/Applications");
        assert!(parent_identity_allowed(path, uid, 0o40700, uid));
        assert!(!parent_identity_allowed(path, uid, 0o40720, uid));
        assert!(!parent_identity_allowed(path, uid, 0o40702, uid));
        assert!(!parent_identity_allowed(
            Path::new("/Applications"),
            0,
            0o40777,
            uid
        ));
    }

    #[test]
    fn recovered_successor_pid_is_bound_to_process_birth_time() {
        let root = TempDir::new().unwrap();
        let (_, mut value) = journal(root.path());
        value.successor_pid = Some(4242);
        value.successor_started = Some("Thu Aug 20 12:34:56 2026".into());
        let expected = bundle_executable(&value.target).display().to_string();
        let exact = ProcessSnapshot {
            pid: 4242,
            uid: value.uid,
            state: 'S',
            started: "Thu Aug 20 12:34:56 2026".into(),
            command: expected.clone(),
        };
        assert!(snapshot_matches_successor(&exact, &value));
        assert!(!snapshot_matches_successor(
            &ProcessSnapshot {
                started: "Thu Aug 20 12:34:57 2026".into(),
                ..exact.clone()
            },
            &value
        ));
        assert!(!snapshot_matches_successor(
            &ProcessSnapshot {
                command: format!("{expected}-other"),
                ..exact
            },
            &value
        ));
    }

    #[test]
    fn live_process_snapshot_includes_stable_birth_identity() {
        let snapshot = process_snapshot(std::process::id()).unwrap();
        assert_eq!(snapshot.pid, std::process::id());
        assert_eq!(snapshot.uid, current_uid());
        assert!(!snapshot.is_zombie());
        assert!(is_safe_process_start(&snapshot.started));
        assert!(!snapshot.command.is_empty());
    }

    #[test]
    fn successor_enumeration_uses_parseable_birth_identity_output() {
        let root = TempDir::new().unwrap();
        let (_, value) = journal(root.path());
        assert!(find_exact_successor(&value).unwrap().is_none());
    }

    #[test]
    fn prepared_journal_is_rebootstrapped_and_retained_across_bootstrap_failure() {
        let root = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        let (path, mut value) = journal(root.path());
        value.old_executable_sha256 = executable(&value.target, b"old");
        value.new_executable_sha256 = executable(&value.stage, b"new");
        fs::write(&value.helper, b"watchdog").unwrap();
        value.watchdog_sha256 = sha256_file(&value.helper).unwrap();
        fs::create_dir_all(value.launch_agent.parent().unwrap()).unwrap();
        write_journal(&path, &value).unwrap();
        let current_exe = bundle_executable(&value.target);
        let state_dir = path.parent().unwrap();
        let launch_agents = value.launch_agent.parent().unwrap();

        let failed = recover_prepared_transaction_with(
            &current_exe,
            state_dir,
            launch_agents,
            |_| Ok(false),
            |_| Ok(()),
            |_, _| Err("injected bootstrap failure".into()),
        );
        let error = failed.unwrap_err();
        assert!(error.contains("bootstrap failure"), "{error}");
        assert!(path.exists());
        assert!(value.stage.exists());
        assert!(value.launch_agent.exists());

        let bootstraps = Cell::new(0usize);
        assert!(recover_prepared_transaction_with(
            &current_exe,
            state_dir,
            launch_agents,
            |_| Ok(false),
            |_| Ok(()),
            |_, plist| {
                assert_eq!(plist, value.launch_agent);
                bootstraps.set(bootstraps.get() + 1);
                Ok(())
            },
        )
        .unwrap());
        assert_eq!(bootstraps.get(), 1);
        let recovered = read_journal(&path).unwrap();
        assert_eq!(recovered.initiator_pid, std::process::id());
        assert_eq!(recovered.phase, TransactionPhase::Prepared);

        let loaded = Cell::new(true);
        let unloads = Cell::new(0usize);
        let restarts = Cell::new(0usize);
        assert!(recover_prepared_transaction_with(
            &current_exe,
            state_dir,
            launch_agents,
            |_| Ok(loaded.get()),
            |_| {
                unloads.set(unloads.get() + 1);
                loaded.set(false);
                Ok(())
            },
            |_, _| {
                restarts.set(restarts.get() + 1);
                Ok(())
            },
        )
        .unwrap());
        assert_eq!(unloads.get(), 1);
        assert_eq!(restarts.get(), 1);
    }

    #[test]
    fn prepared_recovery_never_races_an_active_watchdog_lock() {
        let root = TempDir::new().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        ensure_user_directory(&state, true).unwrap();
        write_private_atomic(&state.join(JOURNAL_FILE), b"active").unwrap();
        let lock = try_transaction_lock(&state).unwrap().unwrap();
        assert!(recover_prepared_transaction_with(
            Path::new("/unused"),
            &state,
            root.path(),
            |_| panic!("loaded state must not be queried while watchdog owns lock"),
            |_| panic!("active watchdog must not be unloaded"),
            |_, _| panic!("a second watchdog must not be bootstrapped"),
        )
        .unwrap());
        drop(lock);
    }
}

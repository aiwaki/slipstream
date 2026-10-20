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
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[path = "daemon_update.rs"]
pub mod daemon_update;
use daemon_update::{Action as DaemonAction, Binding as DaemonBinding, Client as DaemonClient};

pub const WATCHDOG_BINARY: &str = "slipstream-update-watchdog";
pub const WATCHDOG_LABEL: &str = "dev.slipstream.update-watchdog";
pub const JOURNAL_FILE: &str = "app-update-transaction-v1.json";
pub const TRANSACTION_ENV: &str = "SLIPSTREAM_UPDATE_TRANSACTION";
pub const ROLLBACK_ENV: &str = "SLIPSTREAM_UPDATE_ROLLBACK";
const JOURNAL_VERSION: u8 = 2;
const ACK_TIMEOUT_SECS: u64 = 60;
const MAX_JOURNAL_BYTES: u64 = 32 * 1024;
const MAX_ACK_BYTES: u64 = 8 * 1024;

fn transaction_markers_present(
    transaction: Option<&std::ffi::OsStr>,
    rollback: Option<&std::ffi::OsStr>,
) -> bool {
    transaction.is_some() || rollback.is_some()
}

pub fn startup_has_transaction() -> bool {
    transaction_markers_present(
        std::env::var_os(TRANSACTION_ENV).as_deref(),
        std::env::var_os(ROLLBACK_ENV).as_deref(),
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionPhase {
    Prepared,
    BackupMoved,
    NewActivated,
    SuccessorLaunchPlanned,
    SuccessorLaunched,
    DaemonCommitRequested,
    CommittedLaunchPlanned,
    CommittedLaunched,
    Acknowledged,
    RollbackPlanned,
    NewQuarantined,
    RolledBack,
    OldRelaunched,
    CleanupFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupKind {
    PreparedCancelled,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupSlot {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupIntent {
    kind: CleanupKind,
    backup: Option<CleanupSlot>,
    stage: Option<CleanupSlot>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_update: Option<DaemonBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_intent: Option<CleanupIntent>,
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

/// Only NotExecuted permits absence to count as no privileged operation.
/// Uncertain retains the exact identity for an idempotent explicit retry.
pub enum AuthorizationOutcome {
    Completed,
    NotExecuted(String),
    Uncertain(String),
}

#[derive(Clone, Debug)]
pub struct PreparedTransaction {
    pub journal_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct PendingSuccessorAck {
    mode: StartupTransactionMode,
    journal_path: PathBuf,
    ack_path: PathBuf,
    nonce: String,
    uid: u32,
    target: PathBuf,
    backup: PathBuf,
    stage: PathBuf,
    launch_agent: PathBuf,
    version: String,
    executable_sha256: String,
    ack_written: bool,
    daemon_update: Option<DaemonBinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupTransactionMode {
    Successor,
    Rollback,
}

impl PendingSuccessorAck {
    pub fn needs_daemon_ack(&self) -> bool {
        self.mode == StartupTransactionMode::Successor
    }
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
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
}

fn is_safe_process_start(value: &str) -> bool {
    (20..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b':' | b'-'))
}

fn validate_journal(path: &Path, journal: &UpdateJournalV1) -> Result<(), String> {
    if !matches!(journal.schema_version, 1 | JOURNAL_VERSION)
        || (journal.schema_version == JOURNAL_VERSION) != journal.daemon_update.is_some()
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
    if let Some(intent) = &journal.cleanup_intent {
        let valid_phase = match intent.kind {
            CleanupKind::PreparedCancelled => {
                journal.phase == TransactionPhase::Prepared && intent.backup.is_none()
            }
            CleanupKind::Committed => matches!(
                journal.phase,
                TransactionPhase::SuccessorLaunched
                    | TransactionPhase::DaemonCommitRequested
                    | TransactionPhase::CommittedLaunchPlanned
                    | TransactionPhase::CommittedLaunched
                    | TransactionPhase::Acknowledged
                    | TransactionPhase::CleanupFailed
            ),
        };
        if !valid_phase
            || [intent.backup.as_ref(), intent.stage.as_ref()]
                .into_iter()
                .flatten()
                .any(|slot| slot.inode == 0)
        {
            return Err("update cleanup intent is invalid".into());
        }
    }
    if let Some(binding) = &journal.daemon_update {
        binding.validate()?;
        let id = &binding.identity;
        if journal.target != Path::new(daemon_update::TARGET)
            || id.nonce != journal.nonce
            || id.uid != journal.uid
            || id.old_app_executable_sha256 != journal.old_executable_sha256
            || id.new_app_executable_sha256 != journal.new_executable_sha256
            || id.old_version != journal.current_version
            || id.new_version != journal.expected_version
            || id.archive_sha256 != journal.archive_sha256
        {
            return Err("app and root daemon transaction identities differ".into());
        }
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
    #[cfg(test)]
    if daemon_update::test_client_active() {
        return Ok(false);
    }
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

// Keep the independent launchd and authorization effects injectable for crash recovery tests.
#[allow(clippy::too_many_arguments)]
fn recover_prepared_transaction_with<L, U, B, A>(
    current_exe: &Path,
    state_dir: &Path,
    launch_agents_dir: &Path,
    startup_transaction_context: bool,
    service_loaded: L,
    unload: U,
    bootstrap: B,
    authorize: A,
) -> Result<bool, String>
where
    L: Fn(u32) -> Result<bool, String>,
    U: Fn(u32) -> Result<(), String>,
    B: Fn(u32, &Path) -> Result<(), String>,
    A: FnOnce(&daemon_update::PrepareIdentity) -> AuthorizationOutcome,
{
    if startup_transaction_context {
        return Ok(false);
    }
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
        || journal.backup.exists()
        || sha256_file(&journal.helper)? != journal.watchdog_sha256
        || journal.launch_agent != launch_agents_dir.join("dev.slipstream.update-watchdog.plist")
    {
        return Err("prepared update recovery identity is invalid".into());
    }
    if journal
        .cleanup_intent
        .as_ref()
        .is_some_and(|intent| intent.kind == CleanupKind::PreparedCancelled)
    {
        remove_prepared_local(&journal_path, &mut journal)?;
        return Ok(false);
    }
    if let Some(binding) = &journal.daemon_update {
        match DaemonClient::system().status(binding) {
            Ok(status) if status.prepared() || status.ready() => {
                journal.daemon_update.as_mut().unwrap().manifest_sha256 =
                    Some(status.manifest_sha256);
            }
            Ok(status) if status.decision.as_deref() == Some("abort") => {
                cancel_prepared(&journal_path, &mut journal)?;
                return Ok(false);
            }
            Ok(_) => return Err("prepared app cannot resume this root decision".into()),
            Err(_) => authorize_prepared(&journal_path, &mut journal, authorize)?,
        }
    }
    // A proven abort may already have removed staging before a crash. Only
    // resuming activation requires both complete immutable app slots.
    if !journal.stage.exists()
        || sha256_file(&bundle_executable(&journal.stage))? != journal.new_executable_sha256
    {
        return Err("prepared update staging identity is invalid".into());
    }
    verify_bundle_binding(&journal, &journal.target, false)?;
    verify_bundle_binding(&journal, &journal.stage, true)?;
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
    authorize: impl FnOnce(&daemon_update::PrepareIdentity) -> AuthorizationOutcome,
) -> Result<bool, String> {
    let result = recover_prepared_transaction_with(
        current_exe,
        state_dir,
        launch_agents_dir,
        startup_has_transaction(),
        watchdog_service_loaded,
        unload_watchdog,
        bootstrap_watchdog,
        authorize,
    );
    // A definitively cancelled authorization has already removed the journal.
    if result.is_err()
        && !state_dir
            .join(JOURNAL_FILE)
            .try_exists()
            .map_err(|e| e.to_string())?
    {
        return Ok(false);
    }
    result
}

/// A retained initiator transaction may be retried from the tray without
/// enabling unrelated daemon mutations. Malformed/foreign journals fail closed.
pub fn resumable_prepared(current_exe: &Path, state_dir: &Path) -> Result<bool, String> {
    let path = state_dir.join(JOURNAL_FILE);
    if !path.try_exists().map_err(|e| e.to_string())? {
        return Ok(false);
    }
    let journal = read_journal(&path)?;
    Ok(journal.phase == TransactionPhase::Prepared
        && journal.daemon_update.is_some()
        && derive_target(current_exe)? == journal.target
        && sha256_file(current_exe)? == journal.old_executable_sha256
        && !journal.backup.try_exists().map_err(|e| e.to_string())?)
}

// Root paths are not accepted here. Every deletable slot is derived from the
// validated app target and nonce, and pinned before any recursive deletion.
fn cleanup_slot(journal: &UpdateJournalV1, path: &Path) -> Result<Option<CleanupSlot>, String> {
    let parent = journal
        .target
        .parent()
        .ok_or("cleanup target parent missing")?;
    let expected_backup = parent.join(format!(
        ".Slipstream.app.slipstream-backup-{}",
        journal.nonce
    ));
    let expected_stage = parent.join(format!(
        ".Slipstream.app.slipstream-stage-{}",
        journal.nonce
    ));
    if path != expected_backup && path != expected_stage {
        return Err("cleanup path is not a transaction-owned slot".into());
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    if !metadata.is_dir() || metadata.uid() != journal.uid || metadata.mode() & 0o7022 != 0 {
        return Err("cleanup slot is not an owned non-writable directory".into());
    }
    Ok(Some(CleanupSlot {
        device: metadata.dev(),
        inode: metadata.ino(),
    }))
}

fn remove_cleanup_slot_with<R>(
    journal: &UpdateJournalV1,
    path: &Path,
    pin: Option<&CleanupSlot>,
    remove: &mut R,
) -> Result<(), String>
where
    R: FnMut(&Path) -> io::Result<()>,
{
    match cleanup_slot(journal, path)? {
        None => Ok(()),
        Some(current) if pin == Some(&current) => {
            remove(path).map_err(|error| format!("cannot remove authorized cleanup slot: {error}"))
        }
        Some(_) => Err("cleanup slot identity changed after authorization".into()),
    }
}

fn remove_prepared_local(path: &Path, journal: &mut UpdateJournalV1) -> Result<(), String> {
    remove_prepared_local_with(path, journal, watchdog_service_loaded, unload_watchdog)
}

fn remove_prepared_local_with<L, U>(
    path: &Path,
    journal: &mut UpdateJournalV1,
    loaded: L,
    unload: U,
) -> Result<(), String>
where
    L: Fn(u32) -> Result<bool, String>,
    U: FnOnce(u32) -> Result<(), String>,
{
    remove_prepared_local_with_remover(path, journal, loaded, unload, &mut |slot: &Path| {
        fs::remove_dir_all(slot)
    })
}

// Caller holds the transaction flock and has established definitive no-op or
// root abort. Persist that cleanup authorization before deleting any content.
fn remove_prepared_local_with_remover<L, U, R>(
    path: &Path,
    journal: &mut UpdateJournalV1,
    loaded: L,
    unload: U,
    remove: &mut R,
) -> Result<(), String>
where
    L: Fn(u32) -> Result<bool, String>,
    U: FnOnce(u32) -> Result<(), String>,
    R: FnMut(&Path) -> io::Result<()>,
{
    if journal.phase != TransactionPhase::Prepared
        || journal.backup.exists()
        || sha256_file(&bundle_executable(&journal.target))? != journal.old_executable_sha256
    {
        return Err("cannot discard a prepared update with changed app slots".into());
    }
    if loaded(journal.uid)? {
        unload(journal.uid)?;
        if loaded(journal.uid)? {
            return Err("cannot discard preparation while watchdog remains loaded".into());
        }
    }
    if journal.cleanup_intent.is_none() {
        let stage = cleanup_slot(journal, &journal.stage)?;
        if stage.is_some() {
            verify_bundle_binding(journal, &journal.stage, true)?;
            if sha256_file(&bundle_executable(&journal.stage))? != journal.new_executable_sha256 {
                return Err("staged bundle changed before cancel cleanup".into());
            }
        }
        journal.cleanup_intent = Some(CleanupIntent {
            kind: CleanupKind::PreparedCancelled,
            backup: None,
            stage,
        });
        write_journal(path, journal)?;
    }
    let intent = journal.cleanup_intent.as_ref().unwrap();
    if intent.kind != CleanupKind::PreparedCancelled || intent.backup.is_some() {
        return Err("prepared update has a different cleanup authorization".into());
    }
    remove_cleanup_slot_with(journal, &journal.stage, intent.stage.as_ref(), remove)?;
    if journal.launch_agent.exists() {
        fs::remove_file(&journal.launch_agent).map_err(|e| e.to_string())?;
    }
    fs::remove_file(path).map_err(|e| e.to_string())?;
    sync_directory(path.parent().ok_or("journal parent missing")?).map_err(|e| e.to_string())
}

fn cancel_prepared(path: &Path, journal: &mut UpdateJournalV1) -> Result<(), String> {
    ensure_daemon_aborted(path, journal)?;
    remove_prepared_local(path, journal)
}

fn authorize_prepared(
    path: &Path,
    journal: &mut UpdateJournalV1,
    authorize: impl FnOnce(&daemon_update::PrepareIdentity) -> AuthorizationOutcome,
) -> Result<(), String> {
    let root = DaemonClient::system();
    let binding = journal
        .daemon_update
        .as_mut()
        .ok_or("missing coordinated identity")?;
    let previous_authorization = binding.authorization_started;
    binding.authorization_started = true;
    write_journal(path, journal)?;
    let binding = journal.daemon_update.as_ref().unwrap();
    let outcome = authorize(&binding.identity);
    if let AuthorizationOutcome::NotExecuted(message) = &outcome {
        // Cancelling this retry cannot cancel an earlier interrupted prompt.
        // The expired lease prevents late activation. A late sealed preparation
        // can still publish, but must abort under the installer lock.
        let earlier_attempt_cannot_start =
            !previous_authorization || unix_now() >= binding.identity.prepare_deadline_unix;
        if earlier_attempt_cannot_start && root.absent_after_rejected_authorization(binding)? {
            remove_prepared_local(path, journal)?;
            return Err(message.clone());
        }
    }
    let status = root.status(binding)?;
    journal.daemon_update.as_mut().unwrap().manifest_sha256 = Some(status.manifest_sha256.clone());
    write_journal(path, journal)?;
    if !matches!(outcome, AuthorizationOutcome::Completed) || !status.prepared() {
        cancel_prepared(path, journal)?;
        return Err(match outcome {
            AuthorizationOutcome::NotExecuted(message)
            | AuthorizationOutcome::Uncertain(message) => message,
            AuthorizationOutcome::Completed => {
                "root daemon did not prepare; update cancelled".into()
            }
        });
    }
    Ok(())
}

// The production entrypoint consumes the real flock; a drop marker lets tests
// prove the launch ordering without depending on process/fork scheduling.
fn start_prepared_watchdog_with<G>(
    path: &Path,
    journal: &UpdateJournalV1,
    transaction_lock: G,
    bootout: impl FnOnce(u32),
    bootstrap: impl FnOnce(u32, &Path) -> Result<(), String>,
    service_loaded: impl FnOnce(u32) -> Result<bool, String>,
) -> Result<(), String> {
    write_launch_agent_atomic(
        &journal.launch_agent,
        &launch_agent_bytes(
            &journal.helper,
            path,
            path.parent().ok_or("journal parent missing")?,
        ),
    )?;
    bootout(journal.uid);
    // RunAtLoad may start the helper before bootstrap returns. It must be able
    // to acquire the transaction lock on that first invocation.
    drop(transaction_lock);
    if let Err(error) = bootstrap(journal.uid, &journal.launch_agent) {
        // A lost reply may still mean launchd accepted the exact helper. Once
        // the lock is handed off, never abort from our stale journal snapshot.
        // A rejected launch retains Prepared for the existing recovery path;
        // the root operation still has its original bounded lease.
        if service_loaded(journal.uid)? {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn start_prepared_watchdog(
    path: &Path,
    journal: &UpdateJournalV1,
    transaction_lock: File,
) -> Result<(), String> {
    start_prepared_watchdog_with(
        path,
        journal,
        transaction_lock,
        bootout_watchdog,
        bootstrap_watchdog,
        watchdog_service_loaded,
    )
}

pub fn prepare_transaction(
    current_exe: &Path,
    state_dir: &Path,
    launch_agents_dir: &Path,
    archive: &[u8],
    current_version: &str,
    expected_version: &str,
    authorize: impl FnOnce(&daemon_update::PrepareIdentity) -> AuthorizationOutcome,
) -> Result<PreparedTransaction, String> {
    let uid = current_uid();
    if uid == 0 {
        return Err("the tray updater must not run as root".into());
    }
    ensure_user_directory(state_dir, true)
        .map_err(|error| format!("update state directory is unsafe: {error}"))?;
    let transaction_lock =
        try_transaction_lock(state_dir)?.ok_or("another update owns the transaction lock")?;
    let journal_path = state_dir.join(JOURNAL_FILE);
    match fs::symlink_metadata(&journal_path) {
        Ok(_) => return Err("a durable Slipstream update transaction is already active".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect update transaction state: {error}")),
    }
    let target = derive_target(current_exe)?;
    if target != Path::new(daemon_update::TARGET) {
        return Err(
            "coordinated updates require /Applications/Slipstream.app; use the signed DMG".into(),
        );
    }
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
    let daemon_identity = daemon_update::PrepareIdentity {
        schema_version: 1,
        nonce: nonce.clone(),
        uid,
        prepare_deadline_unix: unix_now().saturating_add(300),
        old_app_executable_sha256: old_executable_sha256.clone(),
        new_app_executable_sha256: new_executable_sha256.clone(),
        old_daemon_sha256: sha256_file(&target.join(daemon_update::BUNDLE_DAEMON))?,
        new_daemon_sha256: sha256_file(&stage.join(daemon_update::BUNDLE_DAEMON))?,
        old_bundle_tree_sha256: daemon_update::bundle_tree_sha256(&target)?,
        new_bundle_tree_sha256: daemon_update::bundle_tree_sha256(&stage)?,
        old_version: current_version.to_string(),
        new_version: expected_version.to_string(),
        archive_sha256: sha256_bytes(archive),
    };
    let mut journal = UpdateJournalV1 {
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
        daemon_update: Some(DaemonBinding {
            identity: daemon_identity.clone(),
            manifest_sha256: None,
            sequence: 0,
            action: None,
            authorization_started: false,
        }),
        cleanup_intent: None,
    };
    if let Err(error) = write_journal(&journal_path, &journal) {
        return cleanup_stage(error);
    }
    // Root prepare is synchronous; cancellation is distinguished from an
    // unknown result before considering the absence of root-owned evidence.
    authorize_prepared(&journal_path, &mut journal, authorize)?;
    start_prepared_watchdog(&journal_path, &journal, transaction_lock)?;
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
        || process_snapshot(pid)
            .is_none_or(|snapshot| !snapshot_matches_successor(&snapshot, journal)))
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

fn failed_receipt_path(journal_path: &Path, nonce: &str) -> PathBuf {
    journal_path.with_file_name(format!("app-update-transaction-failed-{nonce}.json"))
}

fn bundle_launch_command(
    bundle: &Path,
    journal_path: &Path,
    rollback_receipt: Option<&Path>,
) -> Command {
    let mut command = Command::new(bundle_executable(bundle));
    // launchd cleans up the watchdog's process group when the job exits.
    // Both the successor and restored app must outlive that cleanup.
    command.process_group(0);
    // Old clients use this marker to skip Prepared recovery while the watchdog
    // still holds the lock. Removing it on rollback can make that old app exit.
    command.env(TRANSACTION_ENV, journal_path);
    if let Some(rollback_receipt) = rollback_receipt {
        command.env(ROLLBACK_ENV, rollback_receipt);
    } else {
        command.env_remove(ROLLBACK_ENV);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn spawn_bundle(bundle: &Path, journal_path: &Path) -> Result<Child, String> {
    let executable = bundle_executable(bundle);
    bundle_launch_command(bundle, journal_path, None)
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

fn verify_bundle_binding(
    journal: &UpdateJournalV1,
    bundle: &Path,
    new: bool,
) -> Result<(), String> {
    if let Some(binding) = &journal.daemon_update {
        let expected = if new {
            &binding.identity.new_bundle_tree_sha256
        } else {
            &binding.identity.old_bundle_tree_sha256
        };
        if daemon_update::bundle_tree_sha256(bundle)? != *expected {
            return Err("app bundle tree differs from the root-authorized payload".into());
        }
    }
    Ok(())
}

fn complete_success(journal_path: &Path, journal: &mut UpdateJournalV1) -> Result<(), String> {
    complete_success_with_remover(journal_path, journal, &mut |slot: &Path| {
        fs::remove_dir_all(slot)
    })
}

fn complete_success_with_remover<R>(
    journal_path: &Path,
    journal: &mut UpdateJournalV1,
    remove: &mut R,
) -> Result<(), String>
where
    R: FnMut(&Path) -> io::Result<()>,
{
    verify_bundle_binding(journal, &journal.target, true)?;
    if let Some(binding) = &journal.daemon_update {
        let status = DaemonClient::system().status(binding)?;
        if !status.committed() {
            return Err("app backup cleanup requires committed exact root daemon proof".into());
        }
    }
    if journal.cleanup_intent.is_none() {
        if read_valid_ack(&ack_path(journal_path), journal)?.is_none() {
            return Err("app backup cleanup requires the exact successor ACK".into());
        }
        let backup = cleanup_slot(journal, &journal.backup)?;
        let stage = cleanup_slot(journal, &journal.stage)?;
        if backup.is_some() {
            verify_bundle_binding(journal, &journal.backup, false)?;
            if sha256_file(&bundle_executable(&journal.backup))? != journal.old_executable_sha256 {
                return Err("old bundle backup digest changed before cleanup".into());
            }
        }
        if stage.is_some() {
            verify_bundle_binding(journal, &journal.stage, true)?;
        }
        journal.cleanup_intent = Some(CleanupIntent {
            kind: CleanupKind::Committed,
            backup,
            stage,
        });
        // Fsynced intent survives interrupted recursive removal. On retry the
        // same directory inode may be partial, but a substituted path may not.
        write_journal(journal_path, journal)?;
    }
    let intent = journal.cleanup_intent.clone().unwrap();
    if intent.kind != CleanupKind::Committed {
        return Err("committed update has a different cleanup authorization".into());
    }
    set_phase(journal_path, journal, TransactionPhase::Acknowledged)?;
    remove_cleanup_slot_with(journal, &journal.backup, intent.backup.as_ref(), remove)?;
    remove_cleanup_slot_with(journal, &journal.stage, intent.stage.as_ref(), remove)?;
    unload_and_remove(journal, journal_path)
}

fn direct_relaunch(bundle: &Path, journal_path: &Path) -> Result<(), String> {
    let journal = read_journal(journal_path)?;
    let receipt = failed_receipt_path(journal_path, &journal.nonce);
    bundle_launch_command(bundle, journal_path, Some(&receipt))
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("cannot relaunch {}: {error}", bundle.display()))
}

fn finish_rollback_with<R>(
    journal_path: &Path,
    journal: &mut UpdateJournalV1,
    relaunch: &mut R,
) -> Result<(), String>
where
    R: FnMut(&Path, &Path) -> Result<(), String>,
{
    ensure_daemon_aborted(journal_path, journal)?;
    verify_bundle_binding(journal, &journal.target, false)?;
    let failed = failed_receipt_path(journal_path, &journal.nonce);
    if journal.phase != TransactionPhase::OldRelaunched {
        // Persist the validated rollback context before launching old clients.
        // It survives active-journal cleanup and keeps the existing crash retry.
        write_private_atomic(
            &failed,
            &serde_json::to_vec(journal).map_err(|error| error.to_string())?,
        )?;
        relaunch(&journal.target, journal_path)?;
        set_phase(journal_path, journal, TransactionPhase::OldRelaunched)?;
    }
    if journal.stage.exists() {
        fs::remove_dir_all(&journal.stage)
            .map_err(|error| format!("cannot remove failed new bundle: {error}"))?;
    }
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
    // A live successor must stop before the root worker restores its daemon.
    // Do not persist app rollback until the root decision forbids late writers.
    if stop_successor {
        if journal.successor_pid.is_none()
            && journal.target.try_exists().map_err(|e| e.to_string())?
            && sha256_file(&bundle_executable(&journal.target))? == journal.new_executable_sha256
        {
            if let Some(snapshot) = find_exact_successor(journal)? {
                journal.successor_pid = Some(snapshot.pid);
                journal.successor_started = Some(snapshot.started);
                write_journal(journal_path, journal)?;
            }
        }
        stop_exact_successor(journal, spawned_child)?;
    }
    ensure_daemon_aborted(journal_path, journal)?;
    set_phase(journal_path, journal, TransactionPhase::RollbackPlanned)?;
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
        verify_bundle_binding(journal, &journal.backup, false)?;
        move_exact(
            &journal.backup,
            &journal.target,
            &journal.old_executable_sha256,
        )?;
    }
    set_phase(journal_path, journal, TransactionPhase::RolledBack)?;
    finish_rollback_with(journal_path, journal, relaunch)
}

fn request_daemon_action(
    path: &Path,
    journal: &mut UpdateJournalV1,
    action: DaemonAction,
) -> Result<(), String> {
    let binding = journal
        .daemon_update
        .as_mut()
        .ok_or("missing root daemon binding")?;
    binding.intend(action)?;
    write_journal(path, journal)?;
    DaemonClient::system().request(journal.daemon_update.as_ref().unwrap())
}

fn ensure_daemon_aborted(path: &Path, journal: &mut UpdateJournalV1) -> Result<(), String> {
    let Some(binding) = &journal.daemon_update else {
        return Ok(());
    };
    let root = DaemonClient::system();
    let status = root.status(binding)?;
    if status.aborted() {
        return Ok(());
    }
    if status.decision.as_deref() == Some("commit") {
        return Err("root committed; app rollback is forbidden".into());
    }
    // A persisted commit request may already have been consumed even when its
    // reply was lost. Re-send it and follow the single root decision.
    let action = if binding.action == Some(DaemonAction::Commit) {
        DaemonAction::Commit
    } else {
        DaemonAction::Abort
    };
    request_daemon_action(path, journal, action)?;
    let status = root.wait(journal.daemon_update.as_ref().unwrap(), action)?;
    if !status.aborted() {
        return Err("root has not restored/quiesced the old daemon; app rollback forbidden".into());
    }
    Ok(())
}

fn relaunch_committed_successor_with<F, S, L>(
    path: &Path,
    journal: &mut UpdateJournalV1,
    find: F,
    stop: S,
    launch: L,
) -> Result<(), String>
where
    F: FnOnce(&UpdateJournalV1) -> Result<Option<ProcessSnapshot>, String>,
    S: FnOnce(&UpdateJournalV1) -> Result<(), String>,
    L: FnOnce(&UpdateJournalV1) -> Result<ProcessSnapshot, String>,
{
    verify_bundle_binding(journal, &journal.target, true)?;
    set_phase(path, journal, TransactionPhase::CommittedLaunchPlanned)?;
    match fs::remove_file(ack_path(path)) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    if let Some(snapshot) = find(journal)? {
        // A manually/autostart-launched tray has no transaction ACK context.
        // Even an orphan from the spawn/PID crash window is safely restarted
        // with that context; never adopt a live process that cannot ACK.
        journal.successor_pid = Some(snapshot.pid);
        journal.successor_started = Some(snapshot.started);
        write_journal(path, journal)?;
        stop(journal)?;
    }
    let snapshot = launch(journal)?;
    journal.successor_pid = Some(snapshot.pid);
    journal.successor_started = Some(snapshot.started);
    journal.successor_deadline_unix = Some(unix_now().saturating_add(ACK_TIMEOUT_SECS));
    set_phase(path, journal, TransactionPhase::CommittedLaunched)
}

fn finish_committed_successor(path: &Path, journal: &mut UpdateJournalV1) -> Result<(), String> {
    verify_bundle_binding(journal, &journal.target, true)?;
    if successor_has_exited(journal, None)? {
        // Commit is irreversible. A dead or rebooted tray requires a fresh
        // successor, not an app-only rollback or cleanup of the last backup.
        relaunch_committed_successor_with(
            path,
            journal,
            find_exact_successor,
            |journal| stop_exact_successor(journal, None),
            |journal| {
                let mut child = spawn_bundle(&journal.target, path)?;
                wait_for_spawned_successor(&mut child, journal)
            },
        )?;
    }
    loop {
        if successor_has_exited(journal, None)? {
            return Err("committed successor exited; retain new version for recovery".into());
        }
        // Cleanup can have removed the ACK before the final journal unlink.
        // Its durable intent already records authorization by this live tray.
        // A relaunched tray has CommittedLaunched and must provide a new ACK.
        if matches!(
            journal.phase,
            TransactionPhase::Acknowledged | TransactionPhase::CleanupFailed
        ) && journal
            .cleanup_intent
            .as_ref()
            .is_some_and(|intent| intent.kind == CleanupKind::Committed)
        {
            return complete_success(path, journal);
        }
        if read_valid_ack(&ack_path(path), journal)?.is_some() {
            return complete_success(path, journal);
        }
        if unix_now() >= journal.successor_deadline_unix.unwrap_or(0) {
            return Err("committed successor acknowledgement pending; new version retained".into());
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn commit_daemon_then_app(path: &Path, journal: &mut UpdateJournalV1) -> Result<(), String> {
    let Some(binding) = &journal.daemon_update else {
        return complete_success(path, journal);
    };
    let root = DaemonClient::system();
    if !root.status(binding)?.committed() {
        // Recovery cannot turn a lost commit response into abort merely because
        // its previously verified app ACK subsequently disappears.
        set_phase(path, journal, TransactionPhase::DaemonCommitRequested)?;
        request_daemon_action(path, journal, DaemonAction::Commit)?;
        let status = root.wait(
            journal.daemon_update.as_ref().unwrap(),
            DaemonAction::Commit,
        )?;
        if status.aborted() {
            return rollback(path, journal, None);
        }
        if !status.committed() {
            return Err("root daemon commit not proven".into());
        }
    }
    finish_committed_successor(path, journal)
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
        if journal.target.exists() {
            verify_bundle_binding(journal, &journal.target, false)?;
        }
        verify_bundle_binding(journal, &journal.stage, true)?;
        if journal.daemon_update.is_some() {
            request_daemon_action(journal_path, journal, DaemonAction::Activate)?;
            let status = DaemonClient::system().wait(
                journal.daemon_update.as_ref().unwrap(),
                DaemonAction::Activate,
            )?;
            if !status.ready() {
                return Err(
                    "root daemon was not activated and attested before app replacement".into(),
                );
            }
        }
        if !journal.target.exists() && journal.backup.exists() {
            verify_bundle_binding(journal, &journal.backup, false)?;
            if sha256_file(&bundle_executable(&journal.backup))? != journal.old_executable_sha256 {
                return Err("backup digest changed before journal recovery".into());
            }
            set_phase(journal_path, journal, TransactionPhase::BackupMoved)?;
        } else {
            if journal.backup.exists() {
                return Err("unexpected update backup already exists".into());
            }
            // Root preparation/activation can take time. Recheck the source
            // immediately before moving it, after that privileged wait.
            verify_bundle_binding(journal, &journal.target, false)?;
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
            verify_bundle_binding(journal, &journal.target, true)?;
            if sha256_file(&bundle_executable(&journal.target))? != journal.new_executable_sha256 {
                return Err("activated update digest changed before journal recovery".into());
            }
            set_phase(journal_path, journal, TransactionPhase::NewActivated)?;
        } else {
            if journal.target.exists() || !journal.stage.exists() {
                return Err("update activation filesystem state is ambiguous".into());
            }
            verify_bundle_binding(journal, &journal.stage, true)?;
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
        verify_bundle_binding(journal, &journal.target, true)?;
        verify_bundle_binding(journal, &journal.backup, false)?;
        if !journal.target.exists()
            || !journal.backup.exists()
            || sha256_file(&bundle_executable(&journal.target))? != journal.new_executable_sha256
            || sha256_file(&bundle_executable(&journal.backup))? != journal.old_executable_sha256
        {
            return Err("activated update filesystem identity is invalid".into());
        }
        if let Some(binding) = &journal.daemon_update {
            let status = DaemonClient::system().status(binding)?;
            if !status.ready() {
                return Err(
                    "root daemon was not activated and attested for successor startup".into(),
                );
            }
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
    while journal.phase == TransactionPhase::Prepared
        && process_exists(journal.initiator_pid)
        && process_command(journal.initiator_pid).is_some_and(|command| {
            command == initiator_executable
                || command.starts_with(&(initiator_executable.clone() + " "))
        })
    {
        thread::sleep(Duration::from_millis(100));
    }
    if let Some(binding) = &journal.daemon_update {
        let status = DaemonClient::system().status(binding)?;
        if binding.manifest_sha256.is_none() {
            journal.daemon_update.as_mut().unwrap().manifest_sha256 =
                Some(status.manifest_sha256.clone());
            write_journal(journal_path, journal)?;
        }
        if status.decision.as_deref() == Some("abort") {
            return rollback(journal_path, journal, None);
        }
        if status.decision.as_deref() == Some("commit") {
            if !matches!(
                journal.phase,
                TransactionPhase::DaemonCommitRequested
                    | TransactionPhase::CommittedLaunchPlanned
                    | TransactionPhase::CommittedLaunched
                    | TransactionPhase::Acknowledged
                    | TransactionPhase::CleanupFailed
            ) {
                return Err("root commit has no durable app commit intent".into());
            }
            return commit_daemon_then_app(journal_path, journal);
        }
        if journal.phase == TransactionPhase::DaemonCommitRequested {
            return commit_daemon_then_app(journal_path, journal);
        }
        if journal.phase == TransactionPhase::Prepared && !status.prepared() && !status.ready() {
            return rollback(journal_path, journal, None);
        }
    }
    loop {
        match advance_prelaunch_phase(journal_path, journal) {
            Ok(true) => {}
            Ok(false) => break,
            Err(error) if journal.daemon_update.is_some() => {
                return rollback(journal_path, journal, None)
                    .map_err(|failure| format!("{error}; coordinated rollback: {failure}"));
            }
            Err(error) => return Err(error),
        }
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
                Ok(Some(_)) => return commit_daemon_then_app(journal_path, journal),
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
    ) && (journal
        .cleanup_intent
        .as_ref()
        .is_some_and(|intent| intent.kind == CleanupKind::Committed)
        || read_valid_ack(&ack_path(journal_path), journal)?.is_some())
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
    let journal_path = std::env::var_os(TRANSACTION_ENV).map(PathBuf::from);
    let rollback_receipt = std::env::var_os(ROLLBACK_ENV).map(PathBuf::from);
    pending_successor_ack_at(
        current_exe,
        current_version,
        journal_path.as_deref(),
        rollback_receipt.as_deref(),
    )
}

fn pending_successor_ack_at(
    current_exe: &Path,
    current_version: &str,
    journal_path: Option<&Path>,
    rollback_receipt: Option<&Path>,
) -> Result<Option<PendingSuccessorAck>, String> {
    let Some(journal_path) = journal_path else {
        if rollback_receipt.is_some() {
            return Err("rollback context has no original transaction path".into());
        }
        return Ok(None);
    };
    if let Some(receipt_path) = rollback_receipt {
        let receipt =
            read_valid_rollback_receipt(journal_path, receipt_path, current_exe, current_version)?;
        // New clients keep a rollback guard until the watchdog has finished.
        // Published legacy clients ignore ROLLBACK_ENV and retain their old behavior.
        return Ok(Some(PendingSuccessorAck {
            mode: StartupTransactionMode::Rollback,
            journal_path: journal_path.to_path_buf(),
            ack_path: ack_path(journal_path),
            nonce: receipt.nonce,
            uid: receipt.uid,
            target: receipt.target,
            backup: receipt.backup,
            stage: receipt.stage,
            launch_agent: receipt.launch_agent,
            version: receipt.current_version,
            executable_sha256: receipt.old_executable_sha256,
            ack_written: false,
            daemon_update: receipt.daemon_update,
        }));
    }
    let journal_path = journal_path.to_path_buf();
    let mut journal = read_journal(&journal_path)?;
    if journal.expected_version != current_version
        || derive_target(current_exe)? != journal.target
        || sha256_file(current_exe)? != journal.new_executable_sha256
    {
        return Err("running successor does not match its update transaction".into());
    }
    if matches!(
        journal.phase,
        TransactionPhase::SuccessorLaunchPlanned | TransactionPhase::CommittedLaunchPlanned
    ) {
        for _ in 0..200 {
            thread::sleep(Duration::from_millis(50));
            journal = read_journal(&journal_path)?;
            if !matches!(
                journal.phase,
                TransactionPhase::SuccessorLaunchPlanned | TransactionPhase::CommittedLaunchPlanned
            ) {
                break;
            }
        }
    }
    if !matches!(
        journal.phase,
        TransactionPhase::SuccessorLaunched | TransactionPhase::CommittedLaunched
    ) || journal.expected_version != current_version
        || derive_target(current_exe)? != journal.target
        || Some(std::process::id()) != journal.successor_pid
        || sha256_file(current_exe)? != journal.new_executable_sha256
    {
        return Err("running successor does not match its update transaction".into());
    }
    if journal.phase == TransactionPhase::CommittedLaunched
        && !DaemonClient::system()
            .status(
                journal
                    .daemon_update
                    .as_ref()
                    .ok_or("committed successor has no daemon binding")?,
            )?
            .committed()
    {
        return Err("committed successor has no root commit proof".into());
    }
    Ok(Some(PendingSuccessorAck {
        mode: StartupTransactionMode::Successor,
        ack_path: ack_path(&journal_path),
        journal_path,
        nonce: journal.nonce,
        uid: journal.uid,
        target: journal.target,
        backup: journal.backup,
        stage: journal.stage,
        launch_agent: journal.launch_agent,
        version: journal.expected_version,
        executable_sha256: journal.new_executable_sha256,
        ack_written: false,
        daemon_update: journal.daemon_update,
    }))
}

fn read_valid_rollback_receipt(
    journal_path: &Path,
    receipt_path: &Path,
    current_exe: &Path,
    current_version: &str,
) -> Result<UpdateJournalV1, String> {
    let state_dir = journal_path
        .parent()
        .ok_or_else(|| "rollback transaction parent is missing".to_string())?;
    if !journal_path.is_absolute()
        || state_dir
            .canonicalize()
            .map_err(|error| error.to_string())?
            != state_dir
    {
        return Err("rollback transaction path is not canonical".into());
    }
    ensure_user_directory(state_dir, true)?;
    if receipt_path.parent() != Some(state_dir) {
        return Err("rollback receipt is outside its transaction directory".into());
    }
    let receipt: UpdateJournalV1 =
        serde_json::from_slice(&read_private_file(receipt_path, MAX_JOURNAL_BYTES)?)
            .map_err(|error| format!("rollback receipt is invalid: {error}"))?;
    validate_journal(journal_path, &receipt)?;
    if receipt_path != failed_receipt_path(journal_path, &receipt.nonce)
        || !matches!(
            receipt.phase,
            TransactionPhase::RolledBack | TransactionPhase::OldRelaunched
        )
        || receipt.current_version != current_version
        || derive_target(current_exe)? != receipt.target
        || sha256_file(current_exe)? != receipt.old_executable_sha256
        || bundle_version(&receipt.target)? != receipt.current_version
    {
        return Err("running rollback does not match its retained transaction".into());
    }
    Ok(receipt)
}

pub fn acknowledge_successor(
    context: &mut PendingSuccessorAck,
    heartbeat_seq: u64,
) -> Result<(), String> {
    if !context.needs_daemon_ack() {
        return Err("rollback startup cannot acknowledge a successor".into());
    }
    if heartbeat_seq == 0 {
        return Err("successor acknowledgement requires a fresh daemon heartbeat".into());
    }
    let journal = read_journal(&context.journal_path)?;
    if !matches!(
        journal.phase,
        TransactionPhase::SuccessorLaunched | TransactionPhase::CommittedLaunched
    ) || journal.nonce != context.nonce
        || journal.expected_version != context.version
        || journal.target != context.target
    {
        return Err("update transaction changed before successor acknowledgement".into());
    }
    if let Some(binding) = &context.daemon_update {
        let status = DaemonClient::system().status(binding)?;
        let root_ready = if journal.phase == TransactionPhase::CommittedLaunched {
            status.committed()
        } else {
            status.ready()
        };
        if journal.daemon_update.as_ref() != Some(binding) || !root_ready {
            return Err("root daemon identity/readiness changed before app ACK".into());
        }
    }
    verify_bundle_binding(&journal, &context.target, true)?;
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
    )?;
    context.ack_written = true;
    Ok(())
}

/// Keep both successor and rollback startup guarded until the watchdog releases
/// its lock and the exact app identity and terminal cleanup are proven.
pub fn startup_transaction_finished(
    context: &PendingSuccessorAck,
    current_version: &str,
) -> Result<bool, String> {
    let current_exe = std::env::current_exe()
        .map_err(|error| format!("cannot identify transaction startup: {error}"))?;
    startup_transaction_finished_at(context, &current_exe, current_version)
}

fn startup_transaction_finished_at(
    context: &PendingSuccessorAck,
    current_exe: &Path,
    current_version: &str,
) -> Result<bool, String> {
    if context.needs_daemon_ack() && !context.ack_written {
        return Ok(false);
    }
    let state_dir = context
        .journal_path
        .parent()
        .ok_or_else(|| "update journal parent is missing".to_string())?;
    ensure_user_directory(state_dir, true)?;
    let Some(_lock) = try_transaction_lock(state_dir)? else {
        return Ok(false);
    };
    let failed = failed_receipt_path(&context.journal_path, &context.nonce);
    for path in [
        &context.journal_path,
        &context.ack_path,
        &context.backup,
        &context.stage,
        &context.launch_agent,
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("cannot inspect completed update state: {error}"));
            }
        }
    }
    if context.needs_daemon_ack() {
        match fs::symlink_metadata(&failed) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect failed update receipt: {error}")),
        }
    } else {
        let receipt = read_valid_rollback_receipt(
            &context.journal_path,
            &failed,
            current_exe,
            current_version,
        )?;
        if receipt.phase != TransactionPhase::OldRelaunched {
            return Ok(false);
        }
        if receipt.nonce != context.nonce
            || receipt.uid != context.uid
            || receipt.target != context.target
            || receipt.backup != context.backup
            || receipt.stage != context.stage
            || receipt.launch_agent != context.launch_agent
            || receipt.current_version != context.version
            || receipt.old_executable_sha256 != context.executable_sha256
        {
            return Err("rollback receipt changed before startup guard release".into());
        }
    }
    if context.uid != current_uid()
        || context.version != current_version
        || derive_target(current_exe)? != context.target
        || sha256_file(current_exe)? != context.executable_sha256
        || bundle_version(&context.target)? != context.version
    {
        return Err("finished transaction app identity changed".into());
    }
    if let Some(binding) = &context.daemon_update {
        let status = DaemonClient::system().status(binding)?;
        if !(if context.needs_daemon_ack() {
            status.committed()
        } else {
            status.aborted()
        }) {
            return Ok(false);
        }
    }
    Ok(true)
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
            daemon_update: None,
            cleanup_intent: None,
        };
        (state.join(JOURNAL_FILE), value)
    }

    fn executable(bundle: &Path, contents: &[u8]) -> String {
        let path = bundle_executable(bundle);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        sha256_file(&path).unwrap()
    }

    fn successor_context(path: &Path, journal: &UpdateJournalV1) -> PendingSuccessorAck {
        PendingSuccessorAck {
            mode: StartupTransactionMode::Successor,
            journal_path: path.to_path_buf(),
            ack_path: ack_path(path),
            nonce: journal.nonce.clone(),
            uid: journal.uid,
            target: journal.target.clone(),
            backup: journal.backup.clone(),
            stage: journal.stage.clone(),
            launch_agent: journal.launch_agent.clone(),
            version: journal.expected_version.clone(),
            executable_sha256: journal.new_executable_sha256.clone(),
            ack_written: false,
            daemon_update: journal.daemon_update.clone(),
        }
    }

    fn bundle_metadata(bundle: &Path, version: &str) {
        fs::write(
            bundle.join("Contents/Info.plist"),
            format!(
                "<plist version=\"1.0\"><dict>\
                 <key>CFBundleIdentifier</key><string>dev.slipstream.tray</string>\
                 <key>CFBundleExecutable</key><string>slipstream</string>\
                 <key>LSUIElement</key><true/>\
                 <key>CFBundleShortVersionString</key><string>{version}</string>\
                 </dict></plist>"
            ),
        )
        .unwrap();
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

    fn coordinated_journal(root: &Path) -> (PathBuf, UpdateJournalV1) {
        let (path, mut journal) = journal(root);
        journal.schema_version = JOURNAL_VERSION;
        journal.old_executable_sha256 = executable(&journal.target, b"old");
        journal.new_executable_sha256 = executable(&journal.stage, b"new");
        journal.daemon_update = Some(daemon_update::Binding {
            identity: daemon_update::PrepareIdentity {
                schema_version: 1,
                nonce: journal.nonce.clone(),
                uid: journal.uid,
                prepare_deadline_unix: unix_now() + 300,
                old_app_executable_sha256: journal.old_executable_sha256.clone(),
                new_app_executable_sha256: journal.new_executable_sha256.clone(),
                old_daemon_sha256: "1".repeat(64),
                new_daemon_sha256: "2".repeat(64),
                old_bundle_tree_sha256: daemon_update::bundle_tree_sha256(&journal.target).unwrap(),
                new_bundle_tree_sha256: daemon_update::bundle_tree_sha256(&journal.stage).unwrap(),
                old_version: journal.current_version.clone(),
                new_version: journal.expected_version.clone(),
                archive_sha256: journal.archive_sha256.clone(),
            },
            manifest_sha256: Some("3".repeat(64)),
            sequence: 0,
            action: None,
            authorization_started: false,
        });
        write_journal(&path, &journal).unwrap();
        (path, journal)
    }

    fn root_status(root: &Path, journal: &UpdateJournalV1, phase: &str) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/update-daemon-status-v1.json"
        ))
        .unwrap();
        let mut status = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == phase)
            .unwrap()["status"]
            .clone();
        let binding = journal.daemon_update.as_ref().unwrap();
        status.as_object_mut().unwrap().extend(
            serde_json::to_value(&binding.identity)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
        );
        status["manifest_sha256"] = serde_json::json!(binding.manifest_sha256);
        status["deadline_unix"] = serde_json::json!(binding.identity.prepare_deadline_unix);
        status["accepted_sequence"] = serde_json::json!(binding.sequence);
        status["daemon_sha256"] = serde_json::json!(if phase == "aborted" || phase == "prepared" {
            &binding.identity.old_daemon_sha256
        } else {
            &binding.identity.new_daemon_sha256
        });
        let directory = root.join(&journal.nonce);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("status.json"),
            serde_json::to_vec(&status).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn cancelled_authorization_after_previous_update_releases_local_preparation() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("active.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1, "nonce": "f".repeat(32)
            }))
            .unwrap(),
        )
        .unwrap();
        let deadline = journal
            .daemon_update
            .as_ref()
            .unwrap()
            .identity
            .prepare_deadline_unix;
        daemon_update::with_test_client(&root, &directory.path().join("requests"), || {
            let result = authorize_prepared(&path, &mut journal, |identity| {
                assert_eq!(identity.prepare_deadline_unix, deadline);
                AuthorizationOutcome::NotExecuted("cancelled by user".into())
            });
            assert!(result.unwrap_err().contains("cancelled by user"));
            assert!(!path.exists());
            assert!(!journal.stage.exists());
            assert!(journal.target.exists());
            assert!(!root.join(&journal.nonce).exists());
            assert!(root.join("active.json").exists());
        });
    }

    #[test]
    fn unknown_authorization_retains_same_intent_and_retry_deadline() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        let root = directory.path().join("root");
        let identity = journal.daemon_update.as_ref().unwrap().identity.clone();
        daemon_update::with_test_client(&root, &directory.path().join("requests"), || {
            for _ in 0..2 {
                assert!(authorize_prepared(&path, &mut journal, |retry| {
                    assert_eq!(*retry, identity);
                    AuthorizationOutcome::Uncertain("authorization interrupted".into())
                })
                .is_err());
                assert!(path.exists());
                assert!(journal.stage.exists());
                assert!(journal.target.exists());
            }
        });
    }

    #[test]
    fn cancelled_retry_does_not_abandon_a_previous_authorization_before_its_lease() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        let root = directory.path().join("root");
        daemon_update::with_test_client(&root, &directory.path().join("requests"), || {
            assert!(
                authorize_prepared(&path, &mut journal, |_| AuthorizationOutcome::Uncertain(
                    "lost response".into()
                ))
                .is_err()
            );
            assert!(authorize_prepared(
                &path,
                &mut journal,
                |_| AuthorizationOutcome::NotExecuted("retry cancelled".into())
            )
            .is_err());
            assert!(path.exists());
            assert!(journal.stage.exists());
            // Simulate wall clock passing the original lease, not a new lease.
            journal
                .daemon_update
                .as_mut()
                .unwrap()
                .identity
                .prepare_deadline_unix = unix_now() - 1;
            assert!(authorize_prepared(
                &path,
                &mut journal,
                |_| AuthorizationOutcome::NotExecuted("expired no-op".into())
            )
            .is_err());
            assert!(!path.exists());
            assert!(!journal.stage.exists());
            assert!(journal.target.exists());
        });
    }

    #[test]
    fn cancelled_update_unloads_previous_exited_watchdog_registration() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        let registered = Cell::new(true);
        let unload_count = Cell::new(0);
        remove_prepared_local_with(
            &path,
            &mut journal,
            |_| Ok(registered.get()),
            |_| {
                unload_count.set(unload_count.get() + 1);
                registered.set(false);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(unload_count.get(), 1);
        assert!(!path.exists());
        assert!(journal.target.exists());
    }

    #[test]
    fn aborted_preparation_cleanup_retries_after_stage_was_already_removed() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        let root = directory.path().join("root");
        root_status(&root, &journal, "aborted");
        fs::remove_dir_all(&journal.stage).unwrap();
        daemon_update::with_test_client(&root, &directory.path().join("requests"), || {
            cancel_prepared(&path, &mut journal).unwrap();
            assert!(!path.exists());
            assert!(journal.target.exists());
        });
    }

    #[test]
    fn lost_commit_reply_never_publishes_abort_or_renames_the_app() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        journal
            .daemon_update
            .as_mut()
            .unwrap()
            .intend(DaemonAction::Commit)
            .unwrap();
        write_journal(&path, &journal).unwrap();
        let root = directory.path().join("root");
        let requests = directory.path().join("requests");
        root_status(&root, &journal, "committed");
        daemon_update::with_test_client(&root, &requests, || {
            assert!(ensure_daemon_aborted(&path, &mut journal)
                .unwrap_err()
                .contains("rollback is forbidden"));
            assert!(path.exists());
            assert!(journal.target.exists());
            assert!(journal.stage.exists());
            assert!(!journal.backup.exists());
            assert!(!requests.exists());
            assert_eq!(
                journal.daemon_update.as_ref().unwrap().action,
                Some(DaemonAction::Commit)
            );
        });
    }

    #[test]
    fn committed_cleanup_resumes_after_partial_backup_delete_and_ack_unlink() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        fs::rename(&journal.target, &journal.backup).unwrap();
        fs::rename(&journal.stage, &journal.target).unwrap();
        journal.phase = TransactionPhase::DaemonCommitRequested;
        journal.successor_pid = Some(4242);
        journal.successor_started = Some("Mon Oct 19 10:00:00 2026".into());
        let ack = SuccessorAckV1 {
            schema_version: 1,
            nonce: journal.nonce.clone(),
            uid: journal.uid,
            pid: 4242,
            version: journal.expected_version.clone(),
            target: journal.target.clone(),
            executable_sha256: journal.new_executable_sha256.clone(),
            heartbeat_seq: 7,
        };
        write_private_atomic(&ack_path(&path), &serde_json::to_vec(&ack).unwrap()).unwrap();
        let root = directory.path().join("root");
        root_status(&root, &journal, "committed");
        daemon_update::with_test_client(&root, &directory.path().join("requests"), || {
            let mut partial_delete = |slot: &Path| -> io::Result<()> {
                fs::remove_file(bundle_executable(slot))?;
                Err(io::Error::other("interrupted recursive removal"))
            };
            assert!(
                complete_success_with_remover(&path, &mut journal, &mut partial_delete).is_err()
            );
            assert_eq!(
                journal.cleanup_intent.as_ref().unwrap().kind,
                CleanupKind::Committed
            );
            assert!(journal.backup.exists());
            assert!(!bundle_executable(&journal.backup).exists());
            // Reopen the durable state and cover the later ACK-unlink crash too.
            journal = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            fs::remove_file(ack_path(&path)).unwrap();
            complete_success(&path, &mut journal).unwrap();
            assert!(!journal.backup.exists());
            assert!(!path.exists());
            assert_eq!(
                sha256_file(&bundle_executable(&journal.target)).unwrap(),
                journal.new_executable_sha256
            );
        });
    }

    #[test]
    fn cancelled_cleanup_resumes_when_partial_stage_no_longer_has_executable() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        let mut partial_delete = |slot: &Path| -> io::Result<()> {
            fs::remove_file(bundle_executable(slot))?;
            Err(io::Error::other("interrupted recursive removal"))
        };
        assert!(remove_prepared_local_with_remover(
            &path,
            &mut journal,
            |_| Ok(false),
            |_| Ok(()),
            &mut partial_delete
        )
        .is_err());
        assert!(journal.stage.exists());
        assert!(!bundle_executable(&journal.stage).exists());
        journal = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            journal.cleanup_intent.as_ref().unwrap().kind,
            CleanupKind::PreparedCancelled
        );
        remove_prepared_local_with(&path, &mut journal, |_| Ok(false), |_| Ok(())).unwrap();
        assert!(!path.exists());
        assert!(!journal.stage.exists());
        assert!(journal.target.exists());
    }

    #[test]
    fn cleanup_retry_refuses_a_replaced_directory_even_at_the_pinned_slot_path() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        assert!(remove_prepared_local_with_remover(
            &path,
            &mut journal,
            |_| Ok(false),
            |_| Ok(()),
            &mut |_| Err(io::Error::other("not removed"))
        )
        .is_err());
        fs::rename(
            &journal.stage,
            directory.path().join("retained-original-stage"),
        )
        .unwrap();
        fs::create_dir(&journal.stage).unwrap();
        fs::write(journal.stage.join("unrelated-file"), b"must remain").unwrap();
        assert!(
            remove_prepared_local_with(&path, &mut journal, |_| Ok(false), |_| Ok(()))
                .unwrap_err()
                .contains("identity changed")
        );
        assert!(path.exists());
        assert_eq!(
            fs::read(journal.stage.join("unrelated-file")).unwrap(),
            b"must remain"
        );
    }

    #[test]
    fn changed_non_executable_resource_stops_before_daemon_activation_or_app_move() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        fs::write(
            journal.stage.join("Contents/unapproved-resource"),
            b"changed",
        )
        .unwrap();
        let requests = directory.path().join("requests");
        daemon_update::with_test_client(&directory.path().join("root"), &requests, || {
            assert!(advance_prelaunch_phase(&path, &mut journal)
                .unwrap_err()
                .contains("bundle tree differs"));
            assert_eq!(journal.phase, TransactionPhase::Prepared);
            assert!(journal.target.exists());
            assert!(journal.stage.exists());
            assert!(!journal.backup.exists());
            assert!(!requests.exists());
        });
    }

    #[test]
    fn committed_recovery_restarts_autostart_or_orphan_before_launching_ack_capable_tray() {
        let directory = TempDir::new().unwrap();
        let (path, mut journal) = coordinated_journal(directory.path());
        fs::rename(&journal.target, &journal.backup).unwrap();
        fs::rename(&journal.stage, &journal.target).unwrap();
        journal.phase = TransactionPhase::DaemonCommitRequested;
        journal
            .daemon_update
            .as_mut()
            .unwrap()
            .intend(DaemonAction::Commit)
            .unwrap();
        let events = RefCell::new(Vec::new());
        let orphan = ProcessSnapshot {
            pid: 4242,
            uid: journal.uid,
            state: 'S',
            started: "Mon Oct 19 10:00:00 2026".into(),
            command: bundle_executable(&journal.target).display().to_string(),
        };
        relaunch_committed_successor_with(
            &path,
            &mut journal,
            |_| Ok(Some(orphan.clone())),
            |stopping| {
                events.borrow_mut().push("stop");
                assert_eq!(stopping.phase, TransactionPhase::CommittedLaunchPlanned);
                assert_eq!(stopping.successor_pid, Some(orphan.pid));
                assert_eq!(
                    stopping.successor_started.as_deref(),
                    Some(orphan.started.as_str())
                );
                assert!(!ack_path(&path).exists());
                Ok(())
            },
            |launching| {
                assert_eq!(*events.borrow(), vec!["stop"]);
                events.borrow_mut().push("launch");
                assert!(launching.backup.exists());
                assert_eq!(
                    launching.daemon_update.as_ref().unwrap().action,
                    Some(DaemonAction::Commit)
                );
                Ok(ProcessSnapshot {
                    pid: 4343,
                    ..orphan.clone()
                })
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), vec!["stop", "launch"]);
        assert_eq!(journal.phase, TransactionPhase::CommittedLaunched);
        assert_eq!(journal.successor_pid, Some(4343));
        assert!(journal.backup.exists());
        assert!(path.exists());
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
        let mut context = successor_context(&path, &value);
        assert!(acknowledge_successor(&mut context, 0).is_err());
        assert!(!context.ack_written);
        acknowledge_successor(&mut context, 7).unwrap();
        assert!(context.ack_written);
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
    fn commit_guard_waits_for_own_ack_watchdog_unlock_and_terminal_cleanup() {
        let root = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        let (path, mut value) = journal(root.path());
        value.new_executable_sha256 = executable(&value.target, b"new");
        value.old_executable_sha256 = executable(&value.backup, b"old");
        value.phase = TransactionPhase::SuccessorLaunched;
        value.successor_pid = Some(std::process::id());
        value.successor_started = Some("Thu Aug 20 12:34:56 2026".into());
        bundle_metadata(&value.target, &value.expected_version);
        fs::create_dir_all(value.launch_agent.parent().unwrap()).unwrap();
        fs::write(&value.launch_agent, b"owned watchdog").unwrap();
        write_journal(&path, &value).unwrap();
        let current_exe = bundle_executable(&value.target);
        let mut context = successor_context(&path, &value);
        let never_acknowledged = context.clone();
        acknowledge_successor(&mut context, 7).unwrap();
        let expected_version = value.expected_version.clone();
        let committed = |context: &PendingSuccessorAck| {
            startup_transaction_finished_at(context, &current_exe, &expected_version)
        };
        assert!(!committed(&context).unwrap(), "ACK alone is not commit");
        let watchdog_lock = try_transaction_lock(path.parent().unwrap())
            .unwrap()
            .unwrap();
        complete_success(&path, &mut value).unwrap();
        assert!(
            !committed(&context).unwrap(),
            "watchdog still owns its lock"
        );
        drop(watchdog_lock);
        assert!(!committed(&never_acknowledged).unwrap());
        assert!(committed(&context).unwrap());
        for residue in [&context.backup, &context.stage, &context.launch_agent] {
            fs::write(residue, b"incomplete cleanup").unwrap();
            assert!(!committed(&context).unwrap());
            fs::remove_file(residue).unwrap();
        }
        assert!(startup_transaction_finished_at(&context, &current_exe, "wrong-version").is_err());
        fs::write(&current_exe, b"changed").unwrap();
        assert!(committed(&context).is_err());
    }

    #[test]
    fn commit_guard_rejects_rollback_even_after_successor_wrote_ack() {
        let root = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        let (path, mut value) = journal(root.path());
        value.new_executable_sha256 = executable(&value.target, b"new");
        value.old_executable_sha256 = executable(&value.backup, b"old");
        value.phase = TransactionPhase::SuccessorLaunched;
        value.successor_pid = Some(std::process::id());
        value.successor_started = Some("Thu Aug 20 12:34:56 2026".into());
        write_journal(&path, &value).unwrap();
        let mut context = successor_context(&path, &value);
        acknowledge_successor(&mut context, 7).unwrap();
        rollback_impl_with_relaunch(&path, &mut value, false, &mut |_, _| Ok(())).unwrap();
        let current_exe = bundle_executable(&value.target);
        assert!(!path.exists());
        assert!(!context.backup.exists());
        assert!(!context.stage.exists());
        assert!(
            !startup_transaction_finished_at(&context, &current_exe, &context.version).unwrap()
        );
        fs::remove_file(path.with_file_name(format!(
            "app-update-transaction-failed-{}.json",
            context.nonce
        )))
        .unwrap();
        assert!(startup_transaction_finished_at(&context, &current_exe, &context.version).is_err());
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
        assert!(!text.contains("AbandonProcessGroup"));
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
    fn successor_launch_keeps_the_exact_transaction_journal() {
        let bundle = Path::new("/Applications/Slipstream.app");
        let journal_path = Path::new("/private/update-state/app-update-transaction.json");
        let command = bundle_launch_command(bundle, journal_path, None);
        assert_eq!(command.get_program(), bundle_executable(bundle).as_os_str());
        assert_eq!(command.get_args().count(), 0);
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _)| *name == std::ffi::OsStr::new(TRANSACTION_ENV))
                .map(|(_, value)| value),
            Some(Some(journal_path.as_os_str()))
        );
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _)| *name == std::ffi::OsStr::new(ROLLBACK_ENV))
                .map(|(_, value)| value),
            Some(None),
            "a successor must not inherit a prior rollback context"
        );
    }

    fn assert_app_launch_has_its_own_process_group(rollback: bool) {
        struct ReapedChild(Child);
        impl Drop for ReapedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let root = TempDir::new().unwrap();
        let (journal_path, value) = journal(root.path());
        executable(&value.target, b"#!/bin/sh\nexec /bin/sleep 30\n");
        fs::set_permissions(
            bundle_executable(&value.target),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let receipt = failed_receipt_path(&journal_path, &value.nonce);
        let child = ReapedChild(
            bundle_launch_command(
                &value.target,
                &journal_path,
                rollback.then_some(receipt.as_path()),
            )
            .spawn()
            .unwrap(),
        );
        let child_pid = child.0.id() as libc::pid_t;
        let child_group = unsafe { libc::getpgid(child_pid) };
        let parent_group = unsafe { libc::getpgrp() };
        assert_eq!(child_group, child_pid, "app must lead a new process group");
        assert_ne!(
            child_group, parent_group,
            "app must not share the watchdog's process group"
        );
    }

    #[test]
    fn successor_launch_has_its_own_process_group() {
        assert_app_launch_has_its_own_process_group(false);
    }

    #[test]
    fn rollback_launch_has_its_own_process_group() {
        assert_app_launch_has_its_own_process_group(true);
    }

    #[test]
    fn rollback_restores_old_bundle_before_one_injected_relaunch_request() {
        let root = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        let (path, mut value) = journal(root.path());
        value.new_executable_sha256 = executable(&value.target, b"new");
        value.old_executable_sha256 = executable(&value.backup, b"old");
        bundle_metadata(&value.backup, &value.current_version);
        value.phase = TransactionPhase::SuccessorLaunched;
        value.successor_deadline_unix = Some(unix_now().saturating_sub(1));
        fs::create_dir_all(value.launch_agent.parent().unwrap()).unwrap();
        fs::write(&value.launch_agent, b"owned watchdog").unwrap();
        write_journal(&path, &value).unwrap();

        let relaunches = Cell::new(0usize);
        let rollback_context = RefCell::new(None);
        let expected_target = value.target.clone();
        let expected_nonce = value.nonce.clone();
        let old_version = value.current_version.clone();
        let _watchdog_lock = try_transaction_lock(path.parent().unwrap())
            .unwrap()
            .unwrap();
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
            let receipt_path = failed_receipt_path(journal_path, &expected_nonce);
            let command = bundle_launch_command(bundle, journal_path, Some(&receipt_path));
            assert_eq!(command.get_program(), bundle_executable(bundle).as_os_str());
            assert_eq!(fs::read(Path::new(command.get_program())).unwrap(), b"old");
            assert_eq!(
                command
                    .get_envs()
                    .find(|(name, _)| *name == std::ffi::OsStr::new(TRANSACTION_ENV))
                    .map(|(_, value)| value),
                Some(Some(journal_path.as_os_str())),
                "legacy restored clients must skip Prepared recovery under the watchdog lock"
            );
            assert_eq!(
                command
                    .get_envs()
                    .find(|(name, _)| *name == std::ffi::OsStr::new(ROLLBACK_ENV))
                    .map(|(_, value)| value),
                Some(Some(receipt_path.as_os_str()))
            );
            let mut context = pending_successor_ack_at(
                Path::new(command.get_program()),
                &old_version,
                Some(journal_path),
                Some(&receipt_path),
            )
            .unwrap()
            .unwrap();
            assert!(!context.needs_daemon_ack());
            assert!(acknowledge_successor(&mut context, 7).is_err());
            assert!(!context.ack_path.exists());
            assert!(!startup_transaction_finished_at(
                &context,
                Path::new(command.get_program()),
                &old_version,
            )
            .unwrap());
            *rollback_context.borrow_mut() = Some(context);
            Ok(())
        };
        rollback_impl_with_relaunch(&path, &mut value, false, &mut relaunch).unwrap();

        assert_eq!(relaunches.get(), 1);
        assert_eq!(value.phase, TransactionPhase::OldRelaunched);
        assert!(!path.exists());
        let context = rollback_context.into_inner().unwrap();
        let current_exe = bundle_executable(&value.target);
        let finished =
            || startup_transaction_finished_at(&context, &current_exe, &value.current_version);
        assert!(
            !finished().unwrap(),
            "cleanup alone cannot bypass the watchdog lock"
        );
        drop(_watchdog_lock);
        assert!(finished().unwrap());
        for residue in [
            &context.journal_path,
            &context.ack_path,
            &context.backup,
            &context.stage,
            &context.launch_agent,
        ] {
            fs::write(residue, b"partial cleanup").unwrap();
            assert!(!finished().unwrap(), "rollback cleanup is incomplete");
            fs::remove_file(residue).unwrap();
        }
        assert!(finished().unwrap());
    }

    #[test]
    fn rollback_context_rejects_unbound_or_nonprivate_receipts() {
        let root = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        let (path, mut value) = journal(root.path());
        value.old_executable_sha256 = executable(&value.target, b"old");
        bundle_metadata(&value.target, &value.current_version);
        value.phase = TransactionPhase::RolledBack;
        let receipt_path = failed_receipt_path(&path, &value.nonce);
        let current_exe = bundle_executable(&value.target);
        let validate = || {
            pending_successor_ack_at(
                &current_exe,
                &value.current_version,
                Some(&path),
                Some(&receipt_path),
            )
        };
        for changed in 0..6 {
            let mut receipt = value.clone();
            match changed {
                0 => receipt.nonce = "b".repeat(32),
                1 => receipt.uid = receipt.uid.wrapping_add(1),
                2 => receipt.phase = TransactionPhase::SuccessorLaunched,
                3 => receipt.current_version = "0.1.9-preview.99".into(),
                4 => receipt.old_executable_sha256 = "f".repeat(64),
                _ => receipt.target = root.path().join("other/Slipstream.app"),
            }
            write_private_atomic(&receipt_path, &serde_json::to_vec(&receipt).unwrap()).unwrap();
            assert!(
                validate().is_err(),
                "accepted altered rollback field {changed}"
            );
        }
        write_private_atomic(&receipt_path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!validate().unwrap().unwrap().needs_daemon_ack());
        assert!(pending_successor_ack_at(
            &current_exe,
            &value.current_version,
            None,
            Some(&receipt_path)
        )
        .is_err());
        assert!(pending_successor_ack_at(
            &current_exe,
            &value.expected_version,
            Some(&path),
            Some(&receipt_path)
        )
        .is_err());
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate().is_err());
        fs::remove_file(&receipt_path).unwrap();
        let other = receipt_path.with_extension("other");
        write_private_atomic(&other, &serde_json::to_vec(&value).unwrap()).unwrap();
        symlink(&other, &receipt_path).unwrap();
        assert!(validate().is_err());
    }

    #[test]
    fn rollback_guard_revalidates_terminal_receipt_and_old_identity() {
        let root = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        let (path, mut value) = journal(root.path());
        value.old_executable_sha256 = executable(&value.target, b"old");
        bundle_metadata(&value.target, &value.current_version);
        value.phase = TransactionPhase::OldRelaunched;
        let receipt_path = failed_receipt_path(&path, &value.nonce);
        write_private_atomic(&receipt_path, &serde_json::to_vec(&value).unwrap()).unwrap();
        let current_exe = bundle_executable(&value.target);
        let mut context = pending_successor_ack_at(
            &current_exe,
            &value.current_version,
            Some(&path),
            Some(&receipt_path),
        )
        .unwrap()
        .unwrap();
        assert!(!context.needs_daemon_ack());
        assert!(acknowledge_successor(&mut context, 7).is_err());
        assert!(!context.ack_written);
        assert!(!context.ack_path.exists());
        let finished =
            || startup_transaction_finished_at(&context, &current_exe, &value.current_version);
        assert!(finished().unwrap());
        let mut incomplete = value.clone();
        incomplete.phase = TransactionPhase::RolledBack;
        write_private_atomic(&receipt_path, &serde_json::to_vec(&incomplete).unwrap()).unwrap();
        assert!(!finished().unwrap(), "old app launch is not yet durable");
        for changed in 0..5 {
            let mut receipt = value.clone();
            match changed {
                0 => receipt.nonce = "b".repeat(32),
                1 => receipt.uid = receipt.uid.wrapping_add(1),
                2 => receipt.current_version = "0.1.9-preview.99".into(),
                3 => receipt.old_executable_sha256 = "f".repeat(64),
                _ => {
                    receipt.launch_agent = root
                        .path()
                        .join("other/dev.slipstream.update-watchdog.plist")
                }
            }
            write_private_atomic(&receipt_path, &serde_json::to_vec(&receipt).unwrap()).unwrap();
            assert!(
                finished().is_err(),
                "accepted changed terminal receipt field {changed}"
            );
        }
        write_private_atomic(&receipt_path, &serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(finished().is_err());
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&current_exe, b"different old executable").unwrap();
        assert!(finished().is_err());
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

    struct PreparationLockMarker<'a> {
        held: &'a Cell<bool>,
        events: &'a RefCell<Vec<&'static str>>,
    }

    impl Drop for PreparationLockMarker<'_> {
        fn drop(&mut self) {
            assert!(self.held.replace(false));
            self.events.borrow_mut().push("released");
        }
    }

    #[test]
    fn prepared_handoff_releases_lock_before_immediate_watchdog_launch() {
        let root = TempDir::new().unwrap();
        let (path, value) = journal(root.path());
        fs::create_dir_all(value.launch_agent.parent().unwrap()).unwrap();
        write_journal(&path, &value).unwrap();
        let held = Cell::new(true);
        let events = RefCell::new(Vec::new());
        let lock = PreparationLockMarker {
            held: &held,
            events: &events,
        };
        start_prepared_watchdog_with(
            &path,
            &value,
            lock,
            |uid| {
                assert_eq!(uid, value.uid);
                assert!(held.get(), "retire the old registration before handoff");
                assert!(value.launch_agent.is_file());
                assert_eq!(
                    read_journal(&path).unwrap().phase,
                    TransactionPhase::Prepared
                );
                events.borrow_mut().push("bootout");
            },
            |uid, plist| {
                assert_eq!(uid, value.uid);
                assert_eq!(plist, value.launch_agent);
                assert!(
                    !held.get(),
                    "an immediately started helper must not see our lock"
                );
                assert_eq!(*events.borrow(), ["bootout", "released"]);
                events.borrow_mut().push("bootstrap");
                Ok(())
            },
            |_| panic!("successful bootstrap needs no lost-reply inspection"),
        )
        .unwrap();
        assert_eq!(*events.borrow(), ["bootout", "released", "bootstrap"]);
    }

    #[test]
    fn prepared_handoff_retains_evidence_on_rejected_or_uncertain_bootstrap() {
        // false: rejected; true: accepted despite lost reply; Err: unknown.
        for loaded in [
            Ok(false),
            Ok(true),
            Err("inspection unavailable".to_string()),
        ] {
            let root = TempDir::new().unwrap();
            let (path, mut value) = journal(root.path());
            value.new_executable_sha256 = executable(&value.stage, b"staged successor");
            fs::create_dir_all(value.launch_agent.parent().unwrap()).unwrap();
            write_journal(&path, &value).unwrap();
            let prepared = fs::read(&path).unwrap();
            let held = Cell::new(true);
            let events = RefCell::new(Vec::new());
            let lock = PreparationLockMarker {
                held: &held,
                events: &events,
            };
            let accepted = loaded == Ok(true);
            let inspected = Cell::new(false);
            let result = start_prepared_watchdog_with(
                &path,
                &value,
                lock,
                |_| assert!(held.get()),
                |_, _| {
                    assert!(!held.get());
                    Err("bootstrap reply unavailable".into())
                },
                |_| {
                    assert!(!held.get());
                    inspected.set(true);
                    loaded
                },
            );
            assert_eq!(result.is_ok(), accepted);
            assert!(inspected.get());
            assert_eq!(fs::read(&path).unwrap(), prepared);
            assert_eq!(
                sha256_file(&bundle_executable(&value.stage)).unwrap(),
                value.new_executable_sha256
            );
            assert!(value.launch_agent.is_file());
            assert_eq!(*events.borrow(), ["released"]);
        }
    }

    #[test]
    fn prepared_handoff_retains_evidence_when_launch_agent_write_fails() {
        let root = TempDir::new().unwrap();
        let (path, mut value) = journal(root.path());
        value.new_executable_sha256 = executable(&value.stage, b"staged successor");
        let invalid_parent = root.path().join("not-a-directory");
        fs::write(&invalid_parent, b"existing file").unwrap();
        value.launch_agent = invalid_parent.join("watchdog.plist");
        write_journal(&path, &value).unwrap();
        let prepared = fs::read(&path).unwrap();
        let held = Cell::new(true);
        let events = RefCell::new(Vec::new());
        let result = start_prepared_watchdog_with(
            &path,
            &value,
            PreparationLockMarker {
                held: &held,
                events: &events,
            },
            |_| panic!("failed publication must not unload the existing job"),
            |_, _| panic!("failed publication must not launch a helper"),
            |_| panic!("no launch was attempted"),
        );
        assert!(result.is_err());
        assert!(!held.get());
        assert_eq!(fs::read(&path).unwrap(), prepared);
        assert_eq!(
            sha256_file(&bundle_executable(&value.stage)).unwrap(),
            value.new_executable_sha256
        );
        assert_eq!(fs::read(invalid_parent).unwrap(), b"existing file");
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
            false,
            |_| Ok(false),
            |_| Ok(()),
            |_, _| Err("injected bootstrap failure".into()),
            |_| AuthorizationOutcome::NotExecuted("test authorization not called".into()),
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
            false,
            |_| Ok(false),
            |_| Ok(()),
            |_, plist| {
                assert_eq!(plist, value.launch_agent);
                bootstraps.set(bootstraps.get() + 1);
                Ok(())
            },
            |_| AuthorizationOutcome::NotExecuted("test authorization not called".into()),
        )
        .unwrap());
        assert_eq!(bootstraps.get(), 1);
        let recovered = read_journal(&path).unwrap();
        assert_eq!(recovered.initiator_pid, std::process::id());
        assert_eq!(recovered.phase, TransactionPhase::Prepared);
    }

    #[test]
    fn prepared_recovery_unloads_loaded_watchdog_before_rebootstrap() {
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

        let loaded = Cell::new(true);
        let unloads = Cell::new(0usize);
        let restarts = Cell::new(0usize);
        assert!(recover_prepared_transaction_with(
            &current_exe,
            state_dir,
            launch_agents,
            false,
            |_| Ok(loaded.get()),
            |_| {
                unloads.set(unloads.get() + 1);
                loaded.set(false);
                Ok(())
            },
            |_, _| {
                assert!(!loaded.get());
                restarts.set(restarts.get() + 1);
                Ok(())
            },
            |_| AuthorizationOutcome::NotExecuted("test authorization not called".into()),
        )
        .unwrap());
        assert_eq!(unloads.get(), 1);
        assert_eq!(restarts.get(), 1);
    }

    #[test]
    fn malformed_rollback_marker_skips_recovery_then_fails_startup_validation() {
        let marker = Path::new("malformed-rollback-context");
        let has_context = transaction_markers_present(None, Some(marker.as_os_str()));
        assert!(has_context);
        assert!(!recover_prepared_transaction_with(
            Path::new("/unused"),
            Path::new("/unused-state"),
            Path::new("/unused-agents"),
            has_context,
            |_| panic!("rollback context must not query launchd during recovery"),
            |_| panic!("rollback context must not unload a watchdog"),
            |_, _| panic!("rollback context must not bootstrap a watchdog"),
            |_| AuthorizationOutcome::NotExecuted("test authorization not called".into()),
        )
        .unwrap());
        assert!(pending_successor_ack_at(Path::new("/unused"), "old", None, Some(marker)).is_err());
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
            false,
            |_| panic!("loaded state must not be queried while watchdog owns lock"),
            |_| panic!("active watchdog must not be unloaded"),
            |_, _| panic!("a second watchdog must not be bootstrapped"),
            |_| AuthorizationOutcome::NotExecuted("test authorization not called".into()),
        )
        .unwrap());
        drop(lock);
    }
}

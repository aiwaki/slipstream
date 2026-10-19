//! The unprivileged half of the root daemon update protocol.
//! Paths and actions are fixed; only the root worker decides commit or abort.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use super::{sha256_bytes, sha256_file, unix_now, write_private_atomic};

pub const BUNDLE_DAEMON: &str = "Contents/Resources/slipstreamd/slipstreamd";
pub const TARGET: &str = "/Applications/Slipstream.app";
const ROOT_BASE: &str = "/var/db/dev.slipstream-update";
const REQUEST_BASE: &str = "/var/run/slipstream-update-requests";
const MAX_STATUS_BYTES: u64 = 16 * 1024;
const MAX_SEQUENCE: u64 = (1u64 << 53) - 1;
const TERMINAL_REFRESH_INTERVAL_SECS: u64 = 10;
const TERMINAL_REFRESH_EPISODE_SECS: u64 = 330;
const MAX_TERMINAL_REFRESH_ATTEMPTS: u32 = 33;
const MAX_REFRESH_BYTES: u64 = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeGeneration {
    pid: u32,
    started: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalRefreshEpisode {
    schema_version: u8,
    nonce: String,
    manifest_sha256: String,
    decision: String,
    receipt_pid: u32,
    observed_generation: Option<RuntimeGeneration>,
    started_unix: u64,
    last_sent_unix: u64,
    attempts: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareIdentity {
    pub schema_version: u8,
    pub nonce: String,
    pub uid: u32,
    pub prepare_deadline_unix: u64,
    pub old_app_executable_sha256: String,
    pub new_app_executable_sha256: String,
    pub old_daemon_sha256: String,
    pub new_daemon_sha256: String,
    pub old_bundle_tree_sha256: String,
    pub new_bundle_tree_sha256: String,
    pub old_version: String,
    pub new_version: String,
    pub archive_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Activate,
    Commit,
    Abort,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub identity: PrepareIdentity,
    pub manifest_sha256: Option<String>,
    pub sequence: u64,
    pub action: Option<Action>,
    // App-only durable marker; absent in an older journal means uncertainty.
    #[serde(default = "authorization_already_started")]
    pub authorization_started: bool,
}

fn authorization_already_started() -> bool {
    true
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    #[serde(flatten)]
    pub identity: PrepareIdentity,
    pub manifest_sha256: String,
    pub phase: String,
    pub decision: Option<String>,
    pub accepted_sequence: u64,
    pub deadline_unix: u64,
    pub worker_pid: u32,
    pub daemon_pid: Option<u32>,
    pub daemon_sha256: Option<String>,
    pub heartbeat_seq: Option<u64>,
    pub install_attestation_sha256: Option<String>,
    pub writer_quiescent: bool,
    pub error: Option<String>,
    #[serde(skip)]
    runtime_fresh: bool,
}

pub fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte))
}

impl Binding {
    pub fn validate(&self) -> Result<(), String> {
        let id = &self.identity;
        if id.schema_version != 1
            || id.uid == 0
            || id.prepare_deadline_unix == 0
            || id.nonce.len() != 32
            || !id
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || [
                &id.old_app_executable_sha256,
                &id.new_app_executable_sha256,
                &id.old_daemon_sha256,
                &id.new_daemon_sha256,
                &id.old_bundle_tree_sha256,
                &id.new_bundle_tree_sha256,
                &id.archive_sha256,
            ]
            .iter()
            .any(|s| !valid_sha(s))
            || !valid_version(&id.old_version)
            || !valid_version(&id.new_version)
            || self
                .manifest_sha256
                .as_deref()
                .is_some_and(|s| !valid_sha(s))
            || self.sequence > MAX_SEQUENCE
            || (self.sequence == 0) != self.action.is_none()
        {
            return Err("daemon update binding is invalid".into());
        }
        Ok(())
    }

    /// Persist this new intent in the app journal BEFORE publishing its request.
    /// A retry keeps its sequence; a lost reply cannot reverse a commit request.
    pub fn intend(&mut self, action: Action) -> Result<(), String> {
        self.validate()?;
        if self.action == Some(action) {
            return Ok(());
        }
        if matches!(self.action, Some(Action::Commit | Action::Abort)) {
            return Err(
                "daemon update already has a terminal request; reconcile root decision".into(),
            );
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .filter(|value| *value <= MAX_SEQUENCE)
            .ok_or_else(|| "daemon update sequence exhausted".to_string())?;
        self.action = Some(action);
        Ok(())
    }
}

impl Status {
    pub fn validate(&self, binding: &Binding) -> Result<(), String> {
        binding.validate()?;
        if self.identity != binding.identity
            || !valid_sha(&self.manifest_sha256)
            || binding
                .manifest_sha256
                .as_ref()
                .is_some_and(|sha| sha != &self.manifest_sha256)
            || self.accepted_sequence > MAX_SEQUENCE
            || self.deadline_unix != binding.identity.prepare_deadline_unix
            || self
                .error
                .as_ref()
                .is_some_and(|message| message.len() > 4096)
            || !matches!(
                self.phase.as_str(),
                "prepared"
                    | "activating"
                    | "ready"
                    | "committing"
                    | "committed"
                    | "aborting"
                    | "aborted"
                    | "recovery_incomplete"
            )
            || !matches!(self.decision.as_deref(), None | Some("commit" | "abort"))
            || (matches!(self.phase.as_str(), "committing" | "committed")
                && self.decision.as_deref() != Some("commit"))
            || (matches!(self.phase.as_str(), "aborting" | "aborted")
                && self.decision.as_deref() != Some("abort"))
        {
            return Err("root daemon status does not match the pinned transaction".into());
        }
        Ok(())
    }

    fn exact_runtime(&self, expected: &str) -> bool {
        self.runtime_fresh
            && self.daemon_sha256.as_deref() == Some(expected)
            && self.daemon_pid.is_some_and(|pid| pid > 1)
            && self.heartbeat_seq.is_some_and(|seq| seq > 0)
            && self
                .install_attestation_sha256
                .as_deref()
                .is_some_and(valid_sha)
            && self.writer_quiescent
            && self.worker_pid > 1
    }

    pub fn prepared(&self) -> bool {
        self.phase == "prepared"
            && self.decision.is_none()
            && self.deadline_unix > unix_now()
            && self.writer_quiescent
            && self.worker_pid > 1
    }

    pub fn ready(&self) -> bool {
        self.phase == "ready"
            && self.decision.is_none()
            && self.deadline_unix > unix_now()
            && self.exact_runtime(&self.identity.new_daemon_sha256)
    }

    pub fn committed(&self) -> bool {
        self.phase == "committed"
            && self.decision.as_deref() == Some("commit")
            && self.exact_runtime(&self.identity.new_daemon_sha256)
    }

    pub fn aborted(&self) -> bool {
        self.phase == "aborted"
            && self.decision.as_deref() == Some("abort")
            && self.exact_runtime(&self.identity.old_daemon_sha256)
    }
}

#[derive(Clone)]
pub struct Client {
    root: PathBuf,
    requests: PathBuf,
    owner: u32,
}

impl Client {
    pub fn system() -> Self {
        #[cfg(test)]
        if let Some(client) = TEST_CLIENT.with(|value| value.borrow().clone()) {
            return client;
        }
        Self {
            root: ROOT_BASE.into(),
            requests: REQUEST_BASE.into(),
            owner: 0,
        }
    }

    fn checked_directory(path: &Path, owner: u32, private: bool) -> Result<(), String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        if !metadata.is_dir()
            || metadata.uid() != owner
            || metadata.mode() & if private { 0o7077 } else { 0o7022 } != 0
        {
            return Err(format!(
                "unsafe daemon transaction directory {}",
                path.display()
            ));
        }
        Ok(())
    }

    // Only usable with a definitive authorization rejection. Absence by itself
    // says nothing about an interrupted or still-running privileged command.
    pub fn absent_after_rejected_authorization(&self, binding: &Binding) -> Result<bool, String> {
        binding.validate()?;
        match fs::symlink_metadata(&self.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.to_string()),
            Ok(_) => Self::checked_directory(&self.root, self.owner, false)?,
        }
        match fs::symlink_metadata(self.root.join(&binding.identity.nonce)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
            Ok(_) => return Ok(false),
        }
        let index_path = self.root.join("active.json");
        match fs::symlink_metadata(&index_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.to_string()),
            Ok(_) => {}
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ActiveIndex {
            schema_version: u8,
            nonce: String,
        }
        let bytes = self.read_root_file(&index_path, 256)?;
        let index: ActiveIndex = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if index.schema_version != 1
            || index.nonce.len() != 32
            || !index
                .nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("invalid root operation index".into());
        }
        if index.nonce == binding.identity.nonce {
            return Ok(false);
        }
        Ok(true)
    }

    fn read_root_file(&self, path: &Path, limit: u64) -> Result<Vec<u8>, String> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| format!("root evidence unavailable: {e}"))?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.uid() != self.owner
            || metadata.mode() & 0o7022 != 0
            || metadata.len() > limit
        {
            return Err("root evidence is not a safe bounded file".into());
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > limit {
            return Err("root evidence exceeded limit".into());
        }
        Ok(bytes)
    }

    pub fn status(&self, binding: &Binding) -> Result<Status, String> {
        self.status_with_runtime_check(binding, |status| self.live_runtime_matches(status))
    }

    fn status_with_runtime_check(
        &self,
        binding: &Binding,
        runtime_matches: impl FnOnce(&Status) -> bool,
    ) -> Result<Status, String> {
        binding.validate()?;
        Self::checked_directory(&self.root, self.owner, false)?;
        let directory = self.root.join(&binding.identity.nonce);
        Self::checked_directory(&directory, self.owner, false)?;
        let bytes = self.read_root_file(&directory.join("status.json"), MAX_STATUS_BYTES)?;
        // Parse identity separately: deny_unknown_fields on the flattened type
        // would reject the status fields as if they were prepare arguments.
        let mut value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("invalid root daemon status: {e}"))?;
        let object = value
            .as_object_mut()
            .ok_or("root daemon status is not an object")?;
        let status_keys = [
            "manifest_sha256",
            "phase",
            "decision",
            "accepted_sequence",
            "deadline_unix",
            "worker_pid",
            "daemon_pid",
            "daemon_sha256",
            "heartbeat_seq",
            "install_attestation_sha256",
            "writer_quiescent",
            "error",
        ];
        let mut identity = object.clone();
        for key in status_keys {
            identity.remove(key);
        }
        let parsed_identity: PrepareIdentity = serde_json::from_value(Value::Object(identity))
            .map_err(|e| format!("invalid root status identity: {e}"))?;
        let get = |key: &str| {
            object
                .get(key)
                .cloned()
                .ok_or_else(|| format!("root status missing {key}"))
        };
        let mut status = Status {
            identity: parsed_identity,
            manifest_sha256: serde_json::from_value(get("manifest_sha256")?)
                .map_err(|e| e.to_string())?,
            phase: serde_json::from_value(get("phase")?).map_err(|e| e.to_string())?,
            decision: serde_json::from_value(get("decision")?).map_err(|e| e.to_string())?,
            accepted_sequence: serde_json::from_value(get("accepted_sequence")?)
                .map_err(|e| e.to_string())?,
            deadline_unix: serde_json::from_value(get("deadline_unix")?)
                .map_err(|e| e.to_string())?,
            worker_pid: serde_json::from_value(get("worker_pid")?).map_err(|e| e.to_string())?,
            daemon_pid: serde_json::from_value(get("daemon_pid")?).map_err(|e| e.to_string())?,
            daemon_sha256: serde_json::from_value(get("daemon_sha256")?)
                .map_err(|e| e.to_string())?,
            heartbeat_seq: serde_json::from_value(get("heartbeat_seq")?)
                .map_err(|e| e.to_string())?,
            install_attestation_sha256: serde_json::from_value(get("install_attestation_sha256")?)
                .map_err(|e| e.to_string())?,
            writer_quiescent: serde_json::from_value(get("writer_quiescent")?)
                .map_err(|e| e.to_string())?,
            error: serde_json::from_value(get("error")?).map_err(|e| e.to_string())?,
            runtime_fresh: false,
        };
        status.validate(binding)?;
        status.runtime_fresh = matches!(status.phase.as_str(), "ready" | "committed" | "aborted")
            && runtime_matches(&status);
        // A successful terminal worker exits. Its root-owned WatchPaths job
        // needs a new mailbox event after a normal selected-daemon restart.
        // This is only a wake hint: stale proof stays untrusted until root
        // republishes it and all live-runtime checks pass on a later read.
        self.request_terminal_refresh(binding, &status)?;
        Ok(status)
    }

    fn request_terminal_refresh(&self, binding: &Binding, status: &Status) -> Result<bool, String> {
        if status.runtime_fresh || !matches!(status.phase.as_str(), "committed" | "aborted") {
            return Ok(false);
        }
        let generation = self.observed_runtime_generation();
        self.request_terminal_refresh_at(binding, status, generation, unix_now())
    }

    fn request_terminal_refresh_at(
        &self,
        binding: &Binding,
        status: &Status,
        generation: Option<RuntimeGeneration>,
        now: u64,
    ) -> Result<bool, String> {
        if status.runtime_fresh || !matches!(status.phase.as_str(), "committed" | "aborted") {
            return Ok(false);
        }
        status.validate(binding)?;
        let directory = self.requests.join(format!(
            "{}-{}",
            binding.identity.uid, binding.identity.nonce
        ));
        let marker = directory.join("refresh.json");
        Self::checked_directory(&self.requests, self.owner, false)?;
        Self::checked_directory(&directory, binding.identity.uid, true)?;
        // Reuse the nonblocking private lock primitive. Never replace/unlink its
        // inode: tray and automatically restarted watchdogs share one episode.
        let Some(lock) = super::try_transaction_lock(&directory)? else {
            return Ok(false);
        };
        let metadata = lock.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.uid() != binding.identity.uid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err("unsafe terminal refresh lock".into());
        }
        let mut episode = self.read_refresh_episode(&marker, binding, status)?;
        let receipt_pid = status
            .daemon_pid
            .filter(|pid| *pid > 1)
            .ok_or("terminal receipt has no daemon PID")?;
        // Heartbeat ticks, temporarily absent status and receipt refresh itself
        // cannot renew the budget. Only an independently observed process birth
        // starts another episode; the first verified birth also replaces None.
        let reset = episode.as_ref().is_none_or(|episode| {
            generation
                .as_ref()
                .is_some_and(|generation| episode.observed_generation.as_ref() != Some(generation))
        });
        if reset {
            episode = Some(TerminalRefreshEpisode {
                schema_version: 1,
                nonce: binding.identity.nonce.clone(),
                manifest_sha256: status.manifest_sha256.clone(),
                decision: status
                    .decision
                    .clone()
                    .ok_or("terminal receipt has no decision")?,
                receipt_pid,
                observed_generation: generation,
                started_unix: now,
                last_sent_unix: now,
                attempts: 0,
            });
        }
        let episode = episode
            .as_mut()
            .ok_or("terminal refresh episode is missing")?;
        if now < episode.started_unix || now < episode.last_sent_unix {
            return Err(
                "terminal refresh clock moved backwards; transaction guard retained".into(),
            );
        }
        if now - episode.started_unix >= TERMINAL_REFRESH_EPISODE_SECS
            || episode.attempts >= MAX_TERMINAL_REFRESH_ATTEMPTS
        {
            return Err("terminal daemon proof refresh exhausted (330s/33 attempts); transaction guard retained pending recovery".into());
        }
        if episode.attempts > 0 && now - episode.last_sent_unix < TERMINAL_REFRESH_INTERVAL_SECS {
            return Ok(false);
        }
        episode.attempts += 1;
        episode.last_sent_unix = now;
        // This private marker is only a WatchPaths wake hint. Root never uses
        // these user-owned fields as commit/abort or runtime proof authority.
        let bytes = serde_json::to_vec(episode).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_REFRESH_BYTES {
            return Err("terminal refresh episode exceeded limit".into());
        }
        Self::checked_directory(&self.requests, self.owner, false)?;
        Self::checked_directory(&directory, binding.identity.uid, true)?;
        write_private_atomic(&marker, &bytes)?;
        Ok(true)
    }

    fn read_refresh_episode(
        &self,
        path: &Path,
        binding: &Binding,
        status: &Status,
    ) -> Result<Option<TerminalRefreshEpisode>, String> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("cannot read terminal refresh episode: {error}")),
        };
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.uid() != binding.identity.uid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() > MAX_REFRESH_BYTES
            || metadata.nlink() != 1
        {
            return Err("unsafe terminal refresh episode".into());
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_REFRESH_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_REFRESH_BYTES {
            return Err("terminal refresh episode exceeded limit".into());
        }
        let episode: TerminalRefreshEpisode = serde_json::from_slice(&bytes)
            .map_err(|e| format!("invalid terminal refresh episode: {e}"))?;
        if episode.schema_version != 1
            || episode.nonce != binding.identity.nonce
            || episode.manifest_sha256 != status.manifest_sha256
            || Some(episode.decision.as_str()) != status.decision.as_deref()
            || episode.receipt_pid <= 1
            || episode.started_unix == 0
            || episode.last_sent_unix < episode.started_unix
            || episode.last_sent_unix - episode.started_unix >= TERMINAL_REFRESH_EPISODE_SECS
            || !(1..=MAX_TERMINAL_REFRESH_ATTEMPTS).contains(&episode.attempts)
            || episode
                .observed_generation
                .as_ref()
                .is_some_and(|generation| {
                    generation.pid <= 1 || !super::is_safe_process_start(&generation.started)
                })
        {
            return Err("terminal refresh episode identity or budget is invalid".into());
        }
        Ok(Some(episode))
    }

    fn observed_runtime_generation(&self) -> Option<RuntimeGeneration> {
        #[cfg(test)]
        if test_client_active() {
            return None;
        }
        let path = Path::new("/var/run/slipstream.status");
        let age = fs::symlink_metadata(path)
            .ok()?
            .modified()
            .ok()?
            .elapsed()
            .ok()?;
        if age > Duration::from_secs(6) {
            return None;
        }
        let bytes = self.read_root_file(path, 1024 * 1024).ok()?;
        let value = serde_json::from_slice(&bytes).ok()?;
        let daemon = slipstream_core::status_v2::status_v2_from_value(value)
            .ok()?
            .daemon?;
        if !matches!(daemon.state.as_deref(), Some("active" | "dormant"))
            || daemon.heartbeat_seq.unwrap_or(0) == 0
        {
            return None;
        }
        let pid = u32::try_from(daemon.pid?).ok().filter(|pid| *pid > 1)?;
        let process = super::process_snapshot(pid)?;
        if process.uid != 0
            || process.is_zombie()
            || process.command.split_whitespace().next()? != "/usr/local/slipstream/slipstreamd"
        {
            return None;
        }
        Some(RuntimeGeneration {
            pid,
            started: process.started,
        })
    }

    fn live_runtime_matches(&self, status: &Status) -> bool {
        #[cfg(test)]
        if test_client_active() {
            return true;
        } // Only explicitly scoped hermetic fixtures bypass live runtime inspection.
        let selected = if status.decision.as_deref() == Some("abort") {
            "old.app"
        } else {
            "new.app"
        };
        let bundled = self
            .root
            .join(&status.identity.nonce)
            .join(selected)
            .join(BUNDLE_DAEMON);
        let proof_path = Path::new(crate::install_attestation::INSTALL_ATTESTATION_PATH);
        let Some(attestation) = crate::install_attestation::install_attestation_at(
            proof_path,
            &bundled,
            Path::new("/usr/local/slipstream/slipstreamd"),
            "dev.slipstream.tproxy",
            1080,
            0,
        ) else {
            return false;
        };
        if Some(attestation.launchd.pid) != status.daemon_pid.map(i64::from)
            || Some(attestation.source_sha256.as_str()) != status.daemon_sha256.as_deref()
            || sha256_file(proof_path).ok().as_deref()
                != status.install_attestation_sha256.as_deref()
        {
            return false;
        }
        let Some(snapshot) = super::process_snapshot(attestation.launchd.pid as u32) else {
            return false;
        };
        let command = snapshot.command.split_whitespace().next().unwrap_or("");
        if snapshot.uid != 0
            || snapshot.is_zombie()
            || command != "/usr/local/slipstream/slipstreamd"
        {
            return false;
        }
        let heartbeat_path = Path::new("/var/run/slipstream.status");
        let Ok(metadata) = fs::symlink_metadata(heartbeat_path) else {
            return false;
        };
        let age = metadata
            .modified()
            .ok()
            .and_then(|time| time.elapsed().ok());
        if !age.is_some_and(|duration| duration <= Duration::from_secs(6)) {
            return false;
        }
        let Ok(bytes) = self.read_root_file(heartbeat_path, 1024 * 1024) else {
            return false;
        };
        let Ok(value) = serde_json::from_slice(&bytes) else {
            return false;
        };
        let Ok(snapshot) = slipstream_core::status_v2::status_v2_from_value(value) else {
            return false;
        };
        snapshot.daemon.is_some_and(|daemon| {
            daemon.pid == Some(attestation.launchd.pid)
                && daemon
                    .heartbeat_seq
                    .is_some_and(|seq| seq >= status.heartbeat_seq.unwrap_or(u64::MAX))
        })
    }

    pub fn request(&self, binding: &Binding) -> Result<(), String> {
        binding.validate()?;
        let action = binding
            .action
            .ok_or("daemon request has no durable action")?;
        Self::checked_directory(&self.requests, self.owner, false)?;
        let directory = self.requests.join(format!(
            "{}-{}",
            binding.identity.uid, binding.identity.nonce
        ));
        Self::checked_directory(&directory, binding.identity.uid, true)?;
        let bytes = serde_json::to_vec(&json!({"schema_version": 1, "nonce": binding.identity.nonce, "sequence": binding.sequence, "action": action})).map_err(|e| e.to_string())?;
        write_private_atomic(&directory.join("request.json"), &bytes)
    }

    pub fn wait(&self, binding: &Binding, action: Action) -> Result<Status, String> {
        let started = Instant::now();
        loop {
            let status = self.status(binding)?;
            if status.committed() || status.aborted() {
                return Ok(status);
            }
            if action == Action::Activate
                && status.ready()
                && status.accepted_sequence == binding.sequence
            {
                return Ok(status);
            }
            if status.phase == "recovery_incomplete" {
                return Err("root daemon recovery is incomplete; app slots retained".into());
            }
            // Root has a 300s fixed lease. A failed/slow recovery remains owned
            // by its launchd worker; user timeout grants no rollback authority.
            if started.elapsed() >= Duration::from_secs(330) {
                return Err("root daemon decision unresolved; app slots retained".into());
            }
            thread::sleep(Duration::from_millis(250));
        }
    }
}

/// Shared with Python: compact UTF-8 sorted JSON, POSIX paths, root excluded.
pub fn bundle_tree_sha256(root: &Path) -> Result<String, String> {
    // Explicit field order keeps the contract independent of serde_json's
    // preserve_order feature unification in either executable.
    #[derive(Serialize)]
    struct Entry {
        kind: String,
        mode: u32,
        path: String,
        sha256: String,
        target: String,
    }
    #[derive(Serialize)]
    struct Tree {
        entries: Vec<Entry>,
        schema_version: u8,
    }
    fn visit(root: &Path, directory: &Path, entries: &mut Vec<Entry>) -> Result<(), String> {
        for item in fs::read_dir(directory).map_err(|e| e.to_string())? {
            let path = item.map_err(|e| e.to_string())?.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("bundle path is not UTF-8")?;
            if relative
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == ".." || p.chars().any(char::is_control))
            {
                return Err("bundle tree has an unsafe path".into());
            }
            let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            let mode = metadata.mode();
            if mode & 0o7000 != 0 {
                return Err("bundle tree contains special permission bits".into());
            }
            let (kind, hash, target) = if metadata.file_type().is_symlink() {
                let link = fs::read_link(&path).map_err(|e| e.to_string())?;
                let text = link.to_str().ok_or("bundle link is not UTF-8")?;
                if link.is_absolute()
                    || text.chars().any(char::is_control)
                    || !path
                        .canonicalize()
                        .map_err(|e| e.to_string())?
                        .starts_with(root.canonicalize().map_err(|e| e.to_string())?)
                {
                    return Err("bundle symlink escapes its tree".into());
                }
                ("symlink", String::new(), text.to_string())
            } else if metadata.is_dir() {
                if mode & 0o055 != 0o055 || mode & 0o022 != 0 {
                    return Err("bundle directory lacks safe cross-owner access".into());
                }
                ("directory", String::new(), String::new())
            } else if metadata.is_file() {
                if mode & 0o044 != 0o044 || mode & 0o022 != 0 {
                    return Err("bundle file lacks safe cross-owner access".into());
                }
                ("file", sha256_file(&path)?, String::new())
            } else {
                return Err("bundle tree contains a special file".into());
            };
            entries.push(Entry {
                kind: kind.into(),
                mode: mode & 0o777,
                path: relative.into(),
                sha256: hash,
                target,
            });
            if entries.len() > 100_000 {
                return Err("bundle tree has too many entries".into());
            }
            if metadata.is_dir() {
                visit(root, &path, entries)?;
            }
        }
        Ok(())
    }
    let metadata = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if !metadata.is_dir() {
        return Err("bundle tree root is not a directory".into());
    }
    let mut entries = Vec::new();
    visit(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(sha256_bytes(
        &serde_json::to_vec(&Tree {
            entries,
            schema_version: 1,
        })
        .map_err(|e| e.to_string())?,
    ))
}

#[cfg(test)]
thread_local! {
    static TEST_CLIENT: std::cell::RefCell<Option<Client>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn test_client_active() -> bool {
    TEST_CLIENT.with(|value| value.borrow().is_some())
}

#[cfg(test)]
pub(super) fn with_test_client<R>(root: &Path, requests: &Path, body: impl FnOnce() -> R) -> R {
    struct Reset(Option<Client>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_CLIENT.with(|value| *value.borrow_mut() = self.0.take());
        }
    }
    let old = TEST_CLIENT.with(|value| {
        value.replace(Some(Client {
            root: root.into(),
            requests: requests.into(),
            owner: super::current_uid(),
        }))
    });
    let _reset = Reset(old);
    body()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::TempDir;

    pub(super) fn binding() -> Binding {
        Binding {
            identity: PrepareIdentity {
                schema_version: 1,
                nonce: "a".repeat(32),
                uid: super::super::current_uid(),
                prepare_deadline_unix: unix_now() + 300,
                old_app_executable_sha256: "b".repeat(64),
                new_app_executable_sha256: "c".repeat(64),
                old_daemon_sha256: "d".repeat(64),
                new_daemon_sha256: "e".repeat(64),
                old_bundle_tree_sha256: "f".repeat(64),
                new_bundle_tree_sha256: "1".repeat(64),
                old_version: "0.1.9-preview.25".into(),
                new_version: "0.1.9-preview.26+build.1".into(),
                archive_sha256: "2".repeat(64),
            },
            manifest_sha256: Some("3".repeat(64)),
            sequence: 0,
            action: None,
            authorization_started: false,
        }
    }

    pub(super) fn wire(binding: &Binding, phase: &str) -> Value {
        let mut value = serde_json::to_value(&binding.identity).unwrap();
        let terminal = matches!(phase, "committed" | "aborted");
        let abort = phase == "aborted";
        value.as_object_mut().unwrap().extend(json!({
            "manifest_sha256": "3".repeat(64), "phase": phase,
            "decision": if terminal { Some(if abort { "abort" } else { "commit" }) } else { None },
            "accepted_sequence": binding.sequence, "deadline_unix": binding.identity.prepare_deadline_unix,
            "worker_pid": 42, "daemon_pid": 43,
            "daemon_sha256": if abort { &binding.identity.old_daemon_sha256 } else { &binding.identity.new_daemon_sha256 },
            "heartbeat_seq": 10, "install_attestation_sha256": "4".repeat(64),
            "writer_quiescent": true, "error": null,
        }).as_object().unwrap().clone());
        value
    }

    fn write_status(root: &Path, binding: &Binding, value: &Value) {
        fs::create_dir_all(root.join(&binding.identity.nonce)).unwrap();
        let path = root.join(&binding.identity.nonce).join("status.json");
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn create_mailbox(client: &Client, binding: &Binding) -> PathBuf {
        let directory = client.requests.join(format!(
            "{}-{}",
            binding.identity.uid, binding.identity.nonce
        ));
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn generation(pid: u32, seconds: u32) -> RuntimeGeneration {
        RuntimeGeneration {
            pid,
            started: format!("Mon Oct 19 12:00:{seconds:02} 2026"),
        }
    }

    fn read_episode(mailbox: &Path) -> TerminalRefreshEpisode {
        serde_json::from_slice(&fs::read(mailbox.join("refresh.json")).unwrap()).unwrap()
    }

    #[test]
    fn stale_terminal_status_wakes_worker_without_acknowledging_or_changing_decision() {
        for phase in ["committed", "aborted"] {
            let directory = TempDir::new().unwrap();
            let root = directory.path().join("root");
            let requests = directory.path().join("requests");
            let binding = binding(); // No pending action is needed after app cleanup.
            with_test_client(&root, &requests, || {
                let client = Client::system();
                let mailbox = create_mailbox(&client, &binding);
                let action_path = mailbox.join("request.json");
                fs::write(&action_path, b"existing durable action").unwrap();
                let original = wire(&binding, phase);
                write_status(&root, &binding, &original);

                let status = client
                    .status_with_runtime_check(&binding, |_| false)
                    .unwrap();
                assert!(!status.committed() && !status.aborted());
                assert_eq!(serde_json::to_value(&status).unwrap(), original);
                let marker = mailbox.join("refresh.json");
                let episode = read_episode(&mailbox);
                assert_eq!(episode.nonce, binding.identity.nonce);
                assert_eq!(episode.manifest_sha256, status.manifest_sha256);
                assert_eq!(Some(episode.decision.as_str()), status.decision.as_deref());
                assert_eq!(episode.attempts, 1);
                assert_eq!(
                    fs::metadata(&marker).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                assert_eq!(fs::read(&action_path).unwrap(), b"existing durable action");

                // A fresh root reply is consumed without touching the watched mailbox.
                let before = fs::read(&marker).unwrap();
                let marker_inode = fs::metadata(&marker).unwrap().ino();
                let mut refreshed_wire = original;
                refreshed_wire["daemon_pid"] = json!(44);
                refreshed_wire["heartbeat_seq"] = json!(20);
                refreshed_wire["install_attestation_sha256"] = json!("5".repeat(64));
                write_status(&root, &binding, &refreshed_wire);
                let refreshed = client
                    .status_with_runtime_check(&binding, |_| true)
                    .unwrap();
                assert_eq!(refreshed.committed(), phase == "committed");
                assert_eq!(refreshed.aborted(), phase == "aborted");
                assert_eq!(fs::metadata(&marker).unwrap().ino(), marker_inode);
                assert_eq!(fs::read(&marker).unwrap(), before);
            });
        }
    }

    #[test]
    fn terminal_refresh_retries_missed_wakes_and_preserves_exhaustion_across_clients() {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join("root");
        let requests = directory.path().join("requests");
        let binding = binding();
        with_test_client(&root, &requests, || {
            let client = Client::system();
            let mailbox = create_mailbox(&client, &binding);
            write_status(&root, &binding, &wire(&binding, "committed"));
            let mut status = client.status(&binding).unwrap();
            status.runtime_fresh = false;
            let observed = Some(generation(44, 0));
            assert!(client
                .request_terminal_refresh_at(&binding, &status, observed.clone(), 1000)
                .unwrap());
            let initial_inode = fs::metadata(mailbox.join("refresh.json")).unwrap().ino();
            assert!(!client
                .request_terminal_refresh_at(&binding, &status, observed.clone(), 1009)
                .unwrap());
            assert_eq!(
                fs::metadata(mailbox.join("refresh.json")).unwrap().ino(),
                initial_inode
            );
            // No root reply: a missed WatchPaths event gets another bounded wake.
            for attempt in 1..MAX_TERMINAL_REFRESH_ATTEMPTS {
                status.heartbeat_seq = Some(20 + u64::from(attempt));
                assert!(client
                    .request_terminal_refresh_at(
                        &binding,
                        &status,
                        observed.clone(),
                        1000 + u64::from(attempt) * 10
                    )
                    .unwrap());
            }
            let before = fs::read(mailbox.join("refresh.json")).unwrap();
            assert_eq!(
                read_episode(&mailbox).attempts,
                MAX_TERMINAL_REFRESH_ATTEMPTS
            );
            // A new helper/client reads the same persisted budget. Missing heartbeat,
            // fresh-then-stale proof and a refreshed receipt PID cannot replenish it.
            let next_client = Client::system();
            let error = next_client
                .request_terminal_refresh_at(&binding, &status, observed.clone(), 1330)
                .unwrap_err();
            assert!(error.contains("exhausted"));
            assert!(next_client
                .request_terminal_refresh_at(&binding, &status, None, 1340)
                .is_err());
            status.runtime_fresh = true;
            assert!(!next_client
                .request_terminal_refresh_at(&binding, &status, observed.clone(), 1350)
                .unwrap());
            status.runtime_fresh = false;
            status.daemon_pid = Some(44);
            assert!(next_client
                .request_terminal_refresh_at(&binding, &status, observed, 1360)
                .is_err());
            assert_eq!(fs::read(mailbox.join("refresh.json")).unwrap(), before);
        });
    }

    #[test]
    fn terminal_refresh_resets_only_for_a_verified_process_birth() {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join("root");
        let requests = directory.path().join("requests");
        let binding = binding();
        with_test_client(&root, &requests, || {
            let client = Client::system();
            let mailbox = create_mailbox(&client, &binding);
            write_status(&root, &binding, &wire(&binding, "aborted"));
            let mut status = client.status(&binding).unwrap();
            status.runtime_fresh = false;
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1000)
                .unwrap());
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1330)
                .unwrap_err()
                .contains("exhausted"));
            // First verified generation after None permits a new bounded attempt.
            let observed = generation(44, 0);
            assert!(client
                .request_terminal_refresh_at(&binding, &status, Some(observed.clone()), 1400)
                .unwrap());
            assert_eq!(read_episode(&mailbox).started_unix, 1400);
            assert!(!client
                .request_terminal_refresh_at(&binding, &status, None, 1401)
                .unwrap());
            assert_eq!(
                read_episode(&mailbox).observed_generation,
                Some(observed.clone())
            );
            assert!(client
                .request_terminal_refresh_at(&binding, &status, Some(observed), 1730)
                .is_err());
            // PID reuse with a different verified process start is a genuine restart.
            let restarted = generation(44, 1);
            assert!(client
                .request_terminal_refresh_at(&binding, &status, Some(restarted.clone()), 1800)
                .unwrap());
            let episode = read_episode(&mailbox);
            assert_eq!(episode.started_unix, 1800);
            assert_eq!(episode.attempts, 1);
            assert_eq!(episode.observed_generation, Some(restarted));
            assert!(client
                .request_terminal_refresh_at(&binding, &status, Some(generation(45, 2)), 2200)
                .unwrap());
            assert_eq!(read_episode(&mailbox).attempts, 1);
        });
    }

    #[test]
    fn nonterminal_or_fresh_status_never_requests_terminal_refresh() {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join("root");
        let requests = directory.path().join("requests");
        let binding = binding();
        with_test_client(&root, &requests, || {
            let client = Client::system();
            for phase in ["prepared", "ready", "activating", "recovery_incomplete"] {
                write_status(&root, &binding, &wire(&binding, phase));
                let _ = client
                    .status_with_runtime_check(&binding, |_| false)
                    .unwrap();
                assert!(!requests.exists(), "{phase}");
            }
            for phase in ["committed", "aborted"] {
                write_status(&root, &binding, &wire(&binding, phase));
                let _ = client
                    .status_with_runtime_check(&binding, |_| true)
                    .unwrap();
                assert!(!requests.exists(), "{phase}");
            }
        });
    }

    #[test]
    fn terminal_refresh_rejects_unsafe_mailbox_without_accepting_stale_proof() {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join("root");
        let requests = directory.path().join("requests");
        let binding = binding();
        with_test_client(&root, &requests, || {
            let client = Client::system();
            let mailbox = create_mailbox(&client, &binding);
            write_status(&root, &binding, &wire(&binding, "committed"));
            let mut status = client.status(&binding).unwrap();
            status.runtime_fresh = false;
            fs::set_permissions(&mailbox, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1000)
                .is_err());
            assert!(client
                .status_with_runtime_check(&binding, |_| false)
                .is_err());
            assert!(!mailbox.join("refresh.json").exists());
            fs::set_permissions(&mailbox, fs::Permissions::from_mode(0o700)).unwrap();
            let moved = directory.path().join("foreign-mailbox");
            fs::rename(&mailbox, &moved).unwrap();
            symlink(&moved, &mailbox).unwrap();
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1000)
                .is_err());
            assert!(!moved.join("refresh.json").exists());
            fs::remove_file(&mailbox).unwrap();
            fs::rename(&moved, &mailbox).unwrap();
            let mut foreign_binding = binding.clone();
            foreign_binding.identity.uid += 1;
            let foreign_mailbox = create_mailbox(&client, &foreign_binding);
            status.identity = foreign_binding.identity.clone();
            assert!(client
                .request_terminal_refresh_at(&foreign_binding, &status, None, 1000)
                .is_err());
            assert!(!foreign_mailbox.join("refresh.json").exists());
        });
    }

    #[test]
    fn terminal_refresh_rejects_unsafe_or_unbounded_persisted_episode() {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join("root");
        let requests = directory.path().join("requests");
        let binding = binding();
        with_test_client(&root, &requests, || {
            let client = Client::system();
            let mailbox = create_mailbox(&client, &binding);
            write_status(&root, &binding, &wire(&binding, "committed"));
            let mut status = client.status(&binding).unwrap();
            status.runtime_fresh = false;
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1000)
                .unwrap());
            let marker = mailbox.join("refresh.json");
            let valid = fs::read(&marker).unwrap();
            fs::set_permissions(&marker, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1010)
                .is_err());
            fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&marker, vec![b' '; MAX_REFRESH_BYTES as usize + 1]).unwrap();
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1010)
                .is_err());
            let mut extra: Value = serde_json::from_slice(&valid).unwrap();
            extra["completed"] = json!(true);
            fs::write(&marker, serde_json::to_vec(&extra).unwrap()).unwrap();
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1010)
                .is_err());
            extra.as_object_mut().unwrap().remove("completed");
            extra["manifest_sha256"] = json!("6".repeat(64));
            fs::write(&marker, serde_json::to_vec(&extra).unwrap()).unwrap();
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1010)
                .is_err());
            fs::write(&marker, &valid).unwrap();
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 999)
                .is_err());
            let linked = directory.path().join("linked-episode");
            fs::hard_link(&marker, &linked).unwrap();
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1010)
                .is_err());
            fs::remove_file(&linked).unwrap();
            let target = directory.path().join("unrelated");
            fs::write(&target, b"preserve").unwrap();
            fs::remove_file(&marker).unwrap();
            symlink(&target, &marker).unwrap();
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1010)
                .is_err());
            assert_eq!(fs::read(&target).unwrap(), b"preserve");
            fs::remove_file(&marker).unwrap();
            use std::os::unix::ffi::OsStrExt;
            let fifo_path = std::ffi::CString::new(marker.as_os_str().as_bytes()).unwrap();
            // SAFETY: CString keeps a valid NUL-terminated fixture path alive.
            assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
            // O_NONBLOCK must permit rejecting a FIFO without waiting for a writer.
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1010)
                .is_err());
        });
    }

    #[test]
    fn terminal_refresh_serializes_clients_with_a_stable_nonblocking_mailbox_lock() {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join("root");
        let requests = directory.path().join("requests");
        let binding = binding();
        with_test_client(&root, &requests, || {
            let client = Client::system();
            let mailbox = create_mailbox(&client, &binding);
            write_status(&root, &binding, &wire(&binding, "committed"));
            let mut status = client.status(&binding).unwrap();
            status.runtime_fresh = false;
            let lock = super::super::try_transaction_lock(&mailbox)
                .unwrap()
                .unwrap();
            let lock_inode = lock.metadata().unwrap().ino();
            assert!(!client
                .request_terminal_refresh_at(&binding, &status, None, 1000)
                .unwrap());
            assert!(!mailbox.join("refresh.json").exists());
            drop(lock);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let workers = (0..2)
                .map(|_| {
                    let client = client.clone();
                    let binding = binding.clone();
                    let status = status.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        client
                            .request_terminal_refresh_at(&binding, &status, None, 1000)
                            .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            let sent = workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|sent| *sent)
                .count();
            assert_eq!(sent, 1);
            assert_eq!(read_episode(&mailbox).attempts, 1);
            let lock = super::super::try_transaction_lock(&mailbox)
                .unwrap()
                .unwrap();
            assert_eq!(lock.metadata().unwrap().ino(), lock_inode);
            drop(lock);
            assert!(client
                .request_terminal_refresh_at(&binding, &status, None, 1010)
                .unwrap());
            assert_eq!(read_episode(&mailbox).attempts, 2);
        });
    }

    #[test]
    fn accepts_actual_python_status_projection_and_rejects_extra_wire_fields() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../contracts/update-daemon-status-v1.json"
        ))
        .unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let wire = &vector["status"];
            // Select only the known identity keys; the production Client still
            // receives the complete, unchanged Python-produced status object.
            let keys = serde_json::to_value(binding().identity).unwrap();
            let identity = keys
                .as_object()
                .unwrap()
                .keys()
                .map(|key| (key.clone(), wire[key].clone()))
                .collect::<serde_json::Map<_, _>>();
            let binding = Binding {
                identity: serde_json::from_value(Value::Object(identity)).unwrap(),
                manifest_sha256: Some(wire["manifest_sha256"].as_str().unwrap().into()),
                sequence: 0,
                action: None,
                authorization_started: false,
            };
            let directory = TempDir::new().unwrap();
            let root = directory.path().join("root");
            with_test_client(&root, &directory.path().join("requests"), || {
                write_status(&root, &binding, wire);
                let status = Client::system().status(&binding).unwrap();
                let phase = vector["name"].as_str().unwrap();
                assert_eq!(status.prepared(), phase == "prepared");
                assert_eq!(status.ready(), phase == "ready");
                assert_eq!(status.committed(), phase == "committed");
                assert_eq!(status.aborted(), phase == "aborted");
                assert_eq!(serde_json::to_value(status).unwrap(), *wire);
                let mut extra = wire.clone();
                extra["unexpected"] = json!(true);
                write_status(&root, &binding, &extra);
                assert!(Client::system().status(&binding).is_err());
            });
        }
    }

    #[test]
    fn terminal_intent_is_durable_and_cannot_reverse_after_lost_reply() {
        let mut binding = binding();
        binding.intend(Action::Activate).unwrap();
        assert_eq!(binding.sequence, 1);
        binding.intend(Action::Activate).unwrap();
        assert_eq!(binding.sequence, 1);
        binding.intend(Action::Commit).unwrap();
        assert_eq!(binding.sequence, 2);
        assert!(binding.intend(Action::Abort).is_err());
        binding.intend(Action::Commit).unwrap();
        assert_eq!(binding.sequence, 2);
    }

    #[test]
    fn root_wire_decisions_require_exact_identity_deadline_and_drained_writers() {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join("root");
        let binding = binding();
        with_test_client(&root, &directory.path().join("requests"), || {
            for phase in ["prepared", "ready", "committed", "aborted"] {
                write_status(&root, &binding, &wire(&binding, phase));
                let status = Client::system().status(&binding).unwrap();
                assert_eq!(status.prepared(), phase == "prepared");
                assert_eq!(status.ready(), phase == "ready");
                assert_eq!(status.committed(), phase == "committed");
                assert_eq!(status.aborted(), phase == "aborted");
            }
            for key in ["nonce", "new_daemon_sha256", "manifest_sha256"] {
                let mut value = wire(&binding, "ready");
                value[key] = json!("0".repeat(if key == "nonce" { 32 } else { 64 }));
                write_status(&root, &binding, &value);
                assert!(Client::system().status(&binding).is_err(), "{key}");
            }
            let mut value = wire(&binding, "ready");
            value["deadline_unix"] = json!(binding.identity.prepare_deadline_unix + 1);
            write_status(&root, &binding, &value);
            assert!(Client::system().status(&binding).is_err());
            value = wire(&binding, "ready");
            value["writer_quiescent"] = json!(false);
            write_status(&root, &binding, &value);
            assert!(!Client::system().status(&binding).unwrap().ready());
            value = wire(&binding, "ready");
            value["unexpected_authority"] = json!("ignore safety");
            write_status(&root, &binding, &value);
            assert!(Client::system().status(&binding).is_err());
        });
    }

    #[test]
    fn rejected_authorization_does_not_confuse_another_terminal_operation() {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        let binding = binding();
        with_test_client(&root, &directory.path().join("requests"), || {
            let client = Client::system();
            assert!(client
                .absent_after_rejected_authorization(&binding)
                .unwrap());
            fs::write(
                root.join("active.json"),
                serde_json::to_vec(&json!({"schema_version":1,"nonce":"b".repeat(32)})).unwrap(),
            )
            .unwrap();
            assert!(client
                .absent_after_rejected_authorization(&binding)
                .unwrap());
            fs::write(
                root.join("active.json"),
                serde_json::to_vec(&json!({"schema_version":1,"nonce":binding.identity.nonce}))
                    .unwrap(),
            )
            .unwrap();
            assert!(!client
                .absent_after_rejected_authorization(&binding)
                .unwrap());
            fs::remove_file(root.join("active.json")).unwrap();
            fs::create_dir(root.join(&binding.identity.nonce)).unwrap();
            assert!(!client
                .absent_after_rejected_authorization(&binding)
                .unwrap());
        });
    }

    #[test]
    fn status_rejects_symlink_and_writable_root_evidence() {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join("root");
        let binding = binding();
        write_status(&root, &binding, &wire(&binding, "ready"));
        with_test_client(&root, &directory.path().join("requests"), || {
            let path = root.join(&binding.identity.nonce).join("status.json");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
            assert!(Client::system().status(&binding).is_err());
            fs::rename(&path, path.with_extension("saved")).unwrap();
            symlink("status.saved", &path).unwrap();
            assert!(Client::system().status(&binding).is_err());
        });
    }

    #[test]
    fn bundle_tree_digest_matches_shared_python_vectors_and_detects_resource_change() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../contracts/update-bundle-tree-v1.json"
        ))
        .unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let directory = TempDir::new().unwrap();
            for node in vector["nodes"].as_array().unwrap() {
                let path = directory.path().join(node["path"].as_str().unwrap());
                match node["kind"].as_str().unwrap() {
                    "directory" => fs::create_dir_all(&path).unwrap(),
                    "file" => fs::write(&path, node["content"].as_str().unwrap()).unwrap(),
                    "symlink" => {
                        symlink(node["target"].as_str().unwrap(), &path).unwrap();
                        #[cfg(target_os = "macos")]
                        {
                            use std::os::unix::ffi::OsStrExt;
                            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                            // macOS applies the process umask to symlink modes.
                            assert_eq!(
                                unsafe {
                                    libc::fchmodat(
                                        libc::AT_FDCWD,
                                        path.as_ptr(),
                                        node["mode"].as_u64().unwrap() as libc::mode_t,
                                        libc::AT_SYMLINK_NOFOLLOW,
                                    )
                                },
                                0
                            );
                        }
                        continue;
                    }
                    _ => panic!("unknown vector node"),
                }
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(node["mode"].as_u64().unwrap() as u32),
                )
                .unwrap();
            }
            assert_eq!(
                bundle_tree_sha256(directory.path()).unwrap(),
                vector["expected_sha256"].as_str().unwrap()
            );
            fs::write(
                directory.path().join("Contents/extra-resource"),
                b"changed after authorization",
            )
            .unwrap();
            assert_ne!(
                bundle_tree_sha256(directory.path()).unwrap(),
                vector["expected_sha256"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn bundle_tree_rejects_escape_and_unsafe_cross_owner_access() {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join("bundle");
        fs::create_dir(&root).unwrap();
        fs::write(directory.path().join("outside"), b"not a bundle resource").unwrap();
        symlink("../outside", root.join("escape")).unwrap();
        assert!(bundle_tree_sha256(&root).is_err());
        fs::remove_file(root.join("escape")).unwrap();
        fs::write(root.join("hidden"), b"data").unwrap();
        fs::set_permissions(root.join("hidden"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(bundle_tree_sha256(&root).is_err());
    }
}

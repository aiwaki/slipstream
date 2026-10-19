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
            && self.live_runtime_matches(&status);
        Ok(status)
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

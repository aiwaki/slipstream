//! A durable stop boundary independent of the updater's acknowledgement gate.
//! Settings and credentials are deliberately outside this transaction.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Intent {
    Stopping,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartupAction {
    None,
    FinishStop,
    Resume,
    RemainStopped,
}

pub(crate) fn startup_action(
    intent: Option<Intent>,
    updater_pending: bool,
    autostart: bool,
) -> StartupAction {
    if updater_pending {
        return StartupAction::None;
    }
    match intent {
        None => StartupAction::None,
        Some(Intent::Stopping) => StartupAction::FinishStop,
        Some(Intent::Stopped) if autostart => StartupAction::RemainStopped,
        Some(Intent::Stopped) => StartupAction::Resume,
    }
}

/// Match live settled health to its own PF observation, not an older receipt.
/// Recovering dormant state is not readiness.
pub(crate) fn settled_service_state(state: &str, phase: &str, pf_active: bool) -> bool {
    phase == "active" && matches!((state, pf_active), ("active", true) | ("dormant", false))
}

pub(crate) fn refresh_enabled_login(
    is_enabled: Result<bool, String>,
    enable: impl FnOnce() -> Result<(), String>,
    verify: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if is_enabled? {
        enable()?;
        verify()?;
    }
    Ok(())
}

#[derive(Default)]
struct GateState {
    busy: bool,
    blocked: bool,
    detail: String,
}

#[derive(Clone, Default)]
pub(crate) struct Gate(Arc<Mutex<GateState>>);

pub(crate) struct Lease(Gate);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0 .0.lock().unwrap().busy = false;
    }
}

impl Gate {
    pub(crate) fn block(&self, detail: impl Into<String>) {
        let mut state = self.0.lock().unwrap();
        state.blocked = true;
        state.detail = detail.into();
    }
    pub(crate) fn blocked(&self) -> bool {
        self.0.lock().unwrap().blocked
    }
    pub(crate) fn detail(&self) -> String {
        self.0.lock().unwrap().detail.clone()
    }
    pub(crate) fn acquire(&self, lifecycle: bool) -> Option<Lease> {
        let mut state = self.0.lock().unwrap();
        if state.busy || (state.blocked && !lifecycle) {
            return None;
        }
        state.busy = true;
        if lifecycle {
            state.blocked = true;
        }
        Some(Lease(self.clone()))
    }
    pub(crate) fn resumed(&self) {
        let mut state = self.0.lock().unwrap();
        state.blocked = false;
        state.detail.clear();
    }
}

pub(crate) struct IntentStore(PathBuf);
impl IntentStore {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self(directory.join("service-lifecycle-v1"))
    }
    fn directory(&self) -> Result<File, String> {
        let parent = self.0.parent().ok_or("lifecycle state has no directory")?;
        if !parent.exists() {
            let ancestor = parent.parent().ok_or("lifecycle directory has no parent")?;
            let handle = open_directory(ancestor)?;
            let metadata = handle.metadata().map_err(|e| e.to_string())?;
            if metadata.uid() != current_uid() || metadata.mode() & 0o022 != 0 {
                return Err("lifecycle directory parent is not safely owned".into());
            }
            fs::DirBuilder::new()
                .mode(0o700)
                .create(parent)
                .map_err(|e| e.to_string())?;
            handle.sync_all().map_err(|e| e.to_string())?;
        }
        let directory = open_directory(parent)?;
        let metadata = directory.metadata().map_err(|e| e.to_string())?;
        if metadata.uid() != current_uid() || metadata.mode() & 0o022 != 0 {
            return Err("lifecycle directory is not safely owned".into());
        }
        // The handle cannot follow a substituted final symlink.
        directory
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        Ok(directory)
    }
    pub(crate) fn read(&self) -> Result<Option<Intent>, String> {
        let _directory = self.directory()?;
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.0)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read stop intent: {e}")),
        };
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.uid() != current_uid()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.len() > 32
        {
            return Err("stop intent is not an owner-private bounded file".into());
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(33)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        match bytes.as_slice() {
            b"v1 stopping\n" => Ok(Some(Intent::Stopping)),
            b"v1 stopped\n" => Ok(Some(Intent::Stopped)),
            _ => Err("stop intent is malformed; automatic startup is blocked".into()),
        }
    }
    pub(crate) fn write(&self, intent: Intent) -> Result<(), String> {
        let directory = self.directory()?;
        self.read()?; // Never replace an unsafe or malformed existing record.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let temporary = self
            .0
            .with_extension(format!("{}-{nonce}-tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| format!("cannot create stop intent: {e}"))?;
        let bytes: &[u8] = match intent {
            Intent::Stopping => b"v1 stopping\n",
            Intent::Stopped => b"v1 stopped\n",
        };
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.0)?;
            directory.sync_all()
        })();
        let _ = fs::remove_file(temporary);
        result.map_err(|e| format!("cannot persist stop intent: {e}"))?;
        if self.read()? != Some(intent) {
            return Err("stop intent readback mismatch".into());
        }
        Ok(())
    }
    pub(crate) fn clear(&self) -> Result<(), String> {
        let directory = self.directory()?;
        if self.read()? != Some(Intent::Stopping) {
            return Err("resume intent changed before readiness".into());
        }
        fs::remove_file(&self.0).map_err(|e| e.to_string())?;
        directory.sync_all().map_err(|e| e.to_string())
    }
}
fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn open_directory(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("cannot open lifecycle directory safely: {e}"))
}

pub(crate) trait Effects {
    fn persist(&mut self, intent: Intent) -> Result<(), String>;
    fn stop_root(&mut self) -> Result<(), String>;
    fn stop_geph(&mut self) -> Result<(), String>;
    fn prepare_stopped(&mut self) -> Result<(), String>;
    fn start_root(&mut self) -> Result<(), String>;
    fn root_ready(&mut self) -> Result<(), String>;
    fn start_geph(&mut self) -> Result<(), String>;
    fn all_ready(&mut self) -> Result<(), String>;
    fn clear(&mut self) -> Result<(), String>;
}

pub(crate) fn stop(effects: &mut impl Effects) -> Result<(), String> {
    effects.persist(Intent::Stopping)?;
    effects.stop_root()?;
    effects.stop_geph()?;
    effects.prepare_stopped()?;
    effects.persist(Intent::Stopped)
}

pub(crate) fn resume(effects: &mut impl Effects) -> Result<(), String> {
    // A crash during resume must finish a stop on next open, never assume that
    // a partially started stack is ready. Only observed readiness clears this.
    effects.persist(Intent::Stopping)?;
    effects.start_root()?;
    effects.root_ready()?;
    effects.start_geph()?;
    effects.all_ready()?;
    effects.clear()
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        intent: Option<Intent>,
        preferences: Vec<u8>,
    }
    impl Fake {
        fn new(fail: Option<&'static str>) -> Self {
            Self {
                calls: vec![],
                fail,
                intent: None,
                preferences: b"enabled=1;account=secret;exit=saved;cache=retained".to_vec(),
            }
        }
        fn call(&mut self, name: &'static str) -> Result<(), String> {
            self.calls.push(name);
            if self.fail == Some(name) {
                Err(format!("{name}: cancelled, failed or unknown"))
            } else {
                Ok(())
            }
        }
    }
    impl Effects for Fake {
        fn persist(&mut self, intent: Intent) -> Result<(), String> {
            self.call(if intent == Intent::Stopping {
                "stopping"
            } else {
                "stopped"
            })?;
            self.intent = Some(intent);
            Ok(())
        }
        fn stop_root(&mut self) -> Result<(), String> {
            self.call("stop root")
        }
        fn stop_geph(&mut self) -> Result<(), String> {
            self.call("stop geph")
        }
        fn prepare_stopped(&mut self) -> Result<(), String> {
            self.call("login intent")
        }
        fn start_root(&mut self) -> Result<(), String> {
            self.call("start root")
        }
        fn root_ready(&mut self) -> Result<(), String> {
            self.call("root ready")
        }
        fn start_geph(&mut self) -> Result<(), String> {
            self.call("start geph")
        }
        fn all_ready(&mut self) -> Result<(), String> {
            self.call("all ready")
        }
        fn clear(&mut self) -> Result<(), String> {
            self.call("clear")?;
            self.intent = None;
            Ok(())
        }
    }
    #[test]
    fn stop_drains_root_before_backend_and_preserves_preferences() {
        let mut f = Fake::new(None);
        let before = f.preferences.clone();
        stop(&mut f).unwrap();
        assert_eq!(
            f.calls,
            [
                "stopping",
                "stop root",
                "stop geph",
                "login intent",
                "stopped"
            ]
        );
        assert_eq!(f.intent, Some(Intent::Stopped));
        assert_eq!(f.preferences, before);
    }
    #[test]
    fn failure_at_every_stop_stage_never_claims_stopped_or_starts_anything() {
        for phase in [
            "stopping",
            "stop root",
            "stop geph",
            "login intent",
            "stopped",
        ] {
            let mut f = Fake::new(Some(phase));
            assert!(stop(&mut f).is_err());
            assert_ne!(f.intent, Some(Intent::Stopped));
            assert_eq!(f.calls.last(), Some(&phase));
            assert!(!f.calls.contains(&"start root"));
        }
    }
    #[test]
    fn resume_requires_both_readiness_proofs_before_clearing_intent() {
        let mut f = Fake::new(None);
        f.intent = Some(Intent::Stopped);
        let before = f.preferences.clone();
        resume(&mut f).unwrap();
        assert_eq!(
            f.calls,
            [
                "stopping",
                "start root",
                "root ready",
                "start geph",
                "all ready",
                "clear"
            ]
        );
        assert_eq!(f.intent, None);
        assert_eq!(f.preferences, before);
    }
    #[test]
    fn crash_or_failure_during_resume_forces_stop_before_any_retry() {
        for phase in [
            "start root",
            "root ready",
            "start geph",
            "all ready",
            "clear",
        ] {
            let mut f = Fake::new(Some(phase));
            assert!(resume(&mut f).is_err());
            assert_eq!(f.intent, Some(Intent::Stopping));
            f.fail = None;
            f.calls.clear();
            stop(&mut f).unwrap();
            assert_eq!(
                f.calls,
                [
                    "stopping",
                    "stop root",
                    "stop geph",
                    "login intent",
                    "stopped"
                ]
            );
        }
    }
    #[test]
    fn gate_serializes_stop_update_install_and_geph_and_stays_blocked_after_failure() {
        let gate = Gate::default();
        let mutation = gate.acquire(false).unwrap();
        assert!(gate.acquire(true).is_none());
        drop(mutation);
        let stopping = gate.acquire(true).unwrap();
        assert!(gate.acquire(false).is_none());
        assert!(gate.acquire(true).is_none());
        drop(stopping);
        assert!(gate.acquire(false).is_none());
        let retry = gate.acquire(true).unwrap();
        gate.resumed();
        assert!(gate.acquire(false).is_none());
        drop(retry);
        assert!(gate.acquire(false).is_some());
    }
    #[test]
    fn disk_intent_survives_reopen_and_rejects_unsafe_files() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let store = IntentStore::new(dir.path().to_path_buf());
        assert_eq!(store.read().unwrap(), None);
        store.write(Intent::Stopping).unwrap();
        assert_eq!(
            IntentStore::new(dir.path().to_path_buf()).read().unwrap(),
            Some(Intent::Stopping)
        );
        store.write(Intent::Stopped).unwrap();
        assert_eq!(store.read().unwrap(), Some(Intent::Stopped));
        store.write(Intent::Stopping).unwrap();
        store.clear().unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, b"keep").unwrap();
        symlink(&outside, &store.0).unwrap();
        assert!(store.read().is_err());
        assert!(store.write(Intent::Stopped).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"keep");
    }
    #[test]
    fn malformed_or_public_intent_never_allows_automatic_startup() {
        let dir = tempfile::tempdir().unwrap();
        let store = IntentStore::new(dir.path().to_path_buf());
        store.write(Intent::Stopping).unwrap();
        fs::write(&store.0, b"v1 maybe\n").unwrap();
        assert!(store.read().is_err());
        assert!(store.write(Intent::Stopped).is_err());
        fs::write(&store.0, b"v1 stopped\n").unwrap();
        fs::set_permissions(&store.0, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.read().is_err());
    }
    #[test]
    fn reopen_resumes_only_confirmed_stop_and_defers_to_updater() {
        assert_eq!(startup_action(None, false, false), StartupAction::None);
        assert_eq!(
            startup_action(Some(Intent::Stopped), false, false),
            StartupAction::Resume
        );
        assert_eq!(
            startup_action(Some(Intent::Stopped), false, true),
            StartupAction::RemainStopped
        );
        for auto in [false, true] {
            assert_eq!(
                startup_action(Some(Intent::Stopping), false, auto),
                StartupAction::FinishStop
            );
            for intent in [None, Some(Intent::Stopping), Some(Intent::Stopped)] {
                assert_eq!(startup_action(intent, true, auto), StartupAction::None);
            }
        }
    }
    #[test]
    fn concurrent_stop_cannot_overlap_an_inflight_admin_action() {
        let gate = Gate::default();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_gate = gate.clone();
        let worker = std::thread::spawn(move || {
            let _lease = worker_gate.acquire(false).unwrap();
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        entered_rx.recv().unwrap();
        assert!(gate.acquire(true).is_none());
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        let _stop = gate.acquire(true).unwrap();
        let other = gate.clone();
        assert!(!std::thread::spawn(move || other.acquire(false).is_some())
            .join()
            .unwrap());
    }
    #[test]
    fn orphaned_temporary_from_crash_does_not_block_retry_or_touch_preferences() {
        let dir = tempfile::tempdir().unwrap();
        let store = IntentStore::new(dir.path().to_path_buf());
        let preferences = dir.path().join("geph.json");
        let contents = br#"{"enabled":"1","exit":"saved","account":"unchanged"}"#;
        fs::write(&preferences, contents).unwrap();
        let orphan = store
            .0
            .with_extension(format!("{}-tmp", std::process::id()));
        fs::write(&orphan, b"partial").unwrap();
        store.write(Intent::Stopping).unwrap();
        store.write(Intent::Stopped).unwrap();
        assert_eq!(store.read().unwrap(), Some(Intent::Stopped));
        assert_eq!(fs::read(&preferences).unwrap(), contents);
        assert_eq!(fs::read(&orphan).unwrap(), b"partial");
    }
    #[test]
    fn dormant_vpn_resume_requires_settled_current_pf_evidence() {
        assert!(settled_service_state("active", "active", true));
        assert!(settled_service_state("dormant", "active", false));
        for phase in ["recovering", "paused", "waiting", "unknown"] {
            assert!(!settled_service_state("dormant", phase, false));
        }
        assert!(!settled_service_state("dormant", "active", true));
        assert!(!settled_service_state("active", "active", false));
    }
    #[test]
    fn login_refresh_keeps_disabled_preference_and_requires_enabled_readback() {
        refresh_enabled_login(
            Ok(false),
            || panic!("disabled login must remain disabled"),
            || panic!("no registration to inspect"),
        )
        .unwrap();
        let order = std::cell::RefCell::new(Vec::new());
        refresh_enabled_login(
            Ok(true),
            || {
                order.borrow_mut().push("enable");
                Ok(())
            },
            || {
                order.borrow_mut().push("verify");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*order.borrow(), ["enable", "verify"]);
        assert!(
            refresh_enabled_login(Err("unknown login state".into()), || panic!(), || panic!())
                .is_err()
        );
        assert!(
            refresh_enabled_login(Ok(true), || Err("write failed".into()), || panic!()).is_err()
        );
        assert!(
            refresh_enabled_login(Ok(true), || Ok(()), || Err("argument missing".into())).is_err()
        );
    }
}

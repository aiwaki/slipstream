//! Keep pending app successors from installing or acknowledging the wrong daemon.

use crate::install_attestation::InstallAttestation;
use crate::status_client::StatusRead;
use serde_json::Value;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Default)]
struct HeartbeatProgress {
    baseline: Option<(Value, u64)>,
}

impl HeartbeatProgress {
    fn observe(
        &mut self,
        attestation: Option<InstallAttestation>,
        status: &StatusRead,
        owned: impl FnOnce(i64) -> bool,
    ) -> Option<u64> {
        let observation = (|| {
            let attestation = attestation?;
            let StatusRead::Fresh(status) = status else {
                return None;
            };
            let pid = status.get("pid")?.as_i64()?;
            let sequence = status.get("heartbeat_seq")?.as_u64()?;
            if sequence == 0 || pid != attestation.launchd.pid || !owned(pid) {
                return None;
            }
            Some((serde_json::to_value(attestation).ok()?, sequence))
        })();
        let Some((identity, sequence)) = observation else {
            self.baseline = None;
            return None;
        };
        let advanced = self
            .baseline
            .as_ref()
            .is_some_and(|(previous, baseline)| previous == &identity && sequence > *baseline);
        // Missing/stale proof, a changed attestation/PID, and a counter reset
        // all require a new observation before acknowledgement is possible.
        self.baseline = Some((identity, sequence));
        advanced.then_some(sequence)
    }
}

pub(crate) struct SuccessorDaemonGuard<T> {
    context: Option<T>,
    heartbeat: HeartbeatProgress,
    acknowledged: bool,
    blocked: Arc<AtomicBool>,
}

impl<T> SuccessorDaemonGuard<T> {
    pub(crate) fn prepare(
        pending: Result<Option<T>, String>,
        attest: impl FnOnce() -> Option<InstallAttestation>,
    ) -> Result<Self, String> {
        let context = pending?;
        if context.is_some() && attest().is_none() {
            return Err(
                "pending update requires an exact bundled daemon install attestation".into(),
            );
        }
        Ok(Self {
            blocked: Arc::new(AtomicBool::new(context.is_some())),
            context,
            heartbeat: HeartbeatProgress::default(),
            acknowledged: false,
        })
    }

    pub(crate) fn blocker(&self) -> Arc<AtomicBool> {
        self.blocked.clone()
    }

    pub(crate) fn start_normal_daemon(&self, install: impl FnOnce()) {
        if !self.blocked.load(Ordering::Acquire) {
            install();
        }
    }

    /// ACK alone does not release privileged actions: the watchdog must have
    /// committed under its transaction lock and removed its rollback state.
    pub(crate) fn poll(
        &mut self,
        attest: impl FnOnce() -> Option<InstallAttestation>,
        status: &StatusRead,
        owned: impl FnOnce(i64) -> bool,
        acknowledge: impl FnOnce(&mut T, u64) -> Result<(), String>,
        committed: impl FnOnce(&T) -> Result<bool, String>,
    ) -> Result<bool, String> {
        let Some(context) = self.context.as_mut() else {
            return Ok(false);
        };
        if !self.acknowledged {
            if let Some(sequence) = self.heartbeat.observe(attest(), status, owned) {
                acknowledge(context, sequence)?;
                self.acknowledged = true;
            }
        }
        if self.acknowledged && committed(context)? {
            self.context = None;
            self.blocked.store(false, Ordering::Release);
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_attestation::{file_sha256, install_attestation_at};
    use serde_json::json;
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn evidence(pid: i64) -> InstallAttestation {
        serde_json::from_value(json!({
            "schema_version": 3,
            "source_sha256": "new daemon",
            "daemon": {"path": "/installed/slipstreamd", "sha256": "new daemon",
                "uid": 0, "gid": 0, "mode": 448},
            "witness": {"path": "/evidence.daemon", "dev": 1, "ino": 2,
                "size": 100, "mtime": 3, "mtime_nsec": 4},
            "launchd": {"label": "dev.slipstream.tproxy", "pid": pid},
            "listener": {"host": "127.0.0.1", "hosts": ["127.0.0.1", "::1"], "port": 1080},
            "state": "active", "pf_active": true
        }))
        .unwrap()
    }

    fn fresh(pid: i64, sequence: u64) -> StatusRead {
        StatusRead::Fresh(json!({"pid": pid, "heartbeat_seq": sequence}))
    }

    fn poll(
        guard: &mut SuccessorDaemonGuard<()>,
        attestation: Option<InstallAttestation>,
        status: StatusRead,
        owned: bool,
        acknowledgements: &Cell<usize>,
        committed: Result<bool, String>,
    ) -> Result<bool, String> {
        guard.poll(
            || attestation,
            &status,
            |_| owned,
            |_, _| {
                acknowledgements.set(acknowledgements.get() + 1);
                Ok(())
            },
            |_| committed,
        )
    }

    #[test]
    fn normal_startup_keeps_install_behavior_without_pending_checks() {
        let mut guard = SuccessorDaemonGuard::<()>::prepare(Ok(None), || {
            panic!("normal startup must not require successor attestation")
        })
        .unwrap();
        let installs = Cell::new(0);
        guard.start_normal_daemon(|| installs.set(installs.get() + 1));
        assert_eq!(installs.get(), 1);
        assert!(!guard.blocker().load(Ordering::Acquire));
        assert!(!guard
            .poll(
                || panic!("no pending attestation read"),
                &StatusRead::Missing,
                |_| panic!("no pending ownership probe"),
                |_, _| panic!("no pending ACK"),
                |_| panic!("no pending commit probe"),
            )
            .unwrap());
    }

    #[test]
    fn invalid_transaction_never_falls_back_to_normal_install() {
        let installs = Cell::new(0);
        let result = SuccessorDaemonGuard::<()>::prepare(Err("invalid transaction".into()), || {
            panic!("invalid transaction must stop before attestation")
        })
        .map(|guard| guard.start_normal_daemon(|| installs.set(installs.get() + 1)));
        assert_eq!(result.unwrap_err(), "invalid transaction");
        assert_eq!(installs.get(), 0);
    }

    #[test]
    fn changed_bundled_bytes_cannot_install_or_ack_the_old_live_daemon() {
        let root = tempfile::tempdir().unwrap();
        let bundled = root.path().join("bundled");
        let installed = root.path().join("installed");
        let attestation_path = root.path().join("attestation.json");
        let witness = root.path().join("attestation.json.daemon");
        fs::write(&bundled, b"old daemon").unwrap();
        fs::write(&installed, b"old daemon").unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o700)).unwrap();
        fs::hard_link(&installed, &witness).unwrap();
        let metadata = fs::symlink_metadata(&witness).unwrap();
        let mut attestation = evidence(4242);
        attestation.source_sha256 = file_sha256(&bundled).unwrap();
        attestation.daemon.sha256 = attestation.source_sha256.clone();
        attestation.daemon.path = installed.to_string_lossy().into_owned();
        attestation.witness.path = witness.to_string_lossy().into_owned();
        attestation.witness.dev = metadata.dev();
        attestation.witness.ino = metadata.ino();
        attestation.witness.size = metadata.len();
        attestation.witness.mtime = metadata.mtime();
        attestation.witness.mtime_nsec = metadata.mtime_nsec();
        fs::write(&attestation_path, serde_json::to_vec(&attestation).unwrap()).unwrap();
        fs::set_permissions(&attestation_path, fs::Permissions::from_mode(0o644)).unwrap();
        let attest = || {
            install_attestation_at(
                &attestation_path,
                &bundled,
                &installed,
                "dev.slipstream.tproxy",
                1080,
                metadata.uid(),
            )
        };
        assert!(attest().is_some());
        fs::write(&bundled, b"new successor daemon").unwrap();
        assert!(attest().is_none());
        let installs = Cell::new(0);
        let acknowledgements = Cell::new(0);
        let result = SuccessorDaemonGuard::prepare(Ok(Some(())), attest).map(|mut guard| {
            guard.start_normal_daemon(|| installs.set(installs.get() + 1));
            for sequence in [100, 101] {
                guard
                    .poll(
                        attest,
                        &fresh(4242, sequence),
                        |_| true,
                        |_, _| {
                            acknowledgements.set(acknowledgements.get() + 1);
                            Ok(())
                        },
                        |_| Ok(false),
                    )
                    .unwrap();
            }
        });
        assert!(result.unwrap_err().contains("exact bundled daemon"));
        assert_eq!(installs.get(), 0);
        assert_eq!(acknowledgements.get(), 0);
    }

    #[test]
    fn fresh_matching_heartbeat_acks_but_only_commit_releases_actions() {
        let mut guard =
            SuccessorDaemonGuard::prepare(Ok(Some(())), || Some(evidence(4242))).unwrap();
        let blocker = guard.blocker();
        guard.start_normal_daemon(|| panic!("pending successor must never install"));
        let acknowledgements = Cell::new(0);
        for sequence in [100, 100, 101] {
            assert!(!poll(
                &mut guard,
                Some(evidence(4242)),
                fresh(4242, sequence),
                true,
                &acknowledgements,
                Ok(false),
            )
            .unwrap());
            assert!(blocker.load(Ordering::Acquire));
        }
        assert_eq!(acknowledgements.get(), 1);
        assert!(poll(
            &mut guard,
            None,
            StatusRead::Missing,
            false,
            &acknowledgements,
            Err("commit proof unavailable".into()),
        )
        .is_err());
        assert!(blocker.load(Ordering::Acquire));
        assert!(poll(
            &mut guard,
            None,
            StatusRead::Missing,
            false,
            &acknowledgements,
            Ok(true),
        )
        .unwrap());
        assert!(!blocker.load(Ordering::Acquire));
        assert_eq!(acknowledgements.get(), 1);
        let actions = Cell::new(0);
        guard.start_normal_daemon(|| actions.set(actions.get() + 1));
        assert_eq!(actions.get(), 1);
    }

    #[test]
    fn missing_stale_unowned_or_wrong_pid_proof_resets_heartbeat_baseline() {
        for (attestation, status, owned) in [
            (None, fresh(4242, 101), true),
            (Some(evidence(4242)), StatusRead::Missing, true),
            (
                Some(evidence(4242)),
                StatusRead::Stale(json!({"pid": 4242, "heartbeat_seq": 101})),
                true,
            ),
            (Some(evidence(4242)), fresh(4243, 101), true),
            (Some(evidence(4242)), fresh(4242, 101), false),
            (Some(evidence(4242)), fresh(4242, 0), true),
        ] {
            let mut progress = HeartbeatProgress::default();
            assert_eq!(
                progress.observe(Some(evidence(4242)), &fresh(4242, 100), |_| true),
                None
            );
            assert_eq!(progress.observe(attestation, &status, |_| owned), None);
            assert_eq!(
                progress.observe(Some(evidence(4242)), &fresh(4242, 102), |_| true),
                None
            );
            assert_eq!(
                progress.observe(Some(evidence(4242)), &fresh(4242, 103), |_| true),
                Some(103)
            );
        }
    }

    #[test]
    fn changed_attestation_or_pid_requires_its_own_heartbeat_advance() {
        let mut replacement = evidence(4242);
        replacement.witness.ino += 1;
        for changed in [replacement, evidence(4243)] {
            let mut progress = HeartbeatProgress::default();
            assert_eq!(
                progress.observe(Some(evidence(4242)), &fresh(4242, 100), |_| true),
                None
            );
            assert_eq!(
                progress.observe(
                    Some(changed.clone()),
                    &fresh(changed.launchd.pid, 101),
                    |_| true
                ),
                None
            );
            assert_eq!(
                progress.observe(
                    Some(changed.clone()),
                    &fresh(changed.launchd.pid, 102),
                    |_| true
                ),
                Some(102)
            );
        }
    }

    #[test]
    fn heartbeat_counter_regression_requires_a_new_advance() {
        let mut progress = HeartbeatProgress::default();
        for sequence in [100, 1, 1] {
            assert_eq!(
                progress.observe(Some(evidence(4242)), &fresh(4242, sequence), |_| true),
                None
            );
        }
        assert_eq!(
            progress.observe(Some(evidence(4242)), &fresh(4242, 2), |_| true),
            Some(2)
        );
    }

    #[test]
    fn failed_ack_never_probes_commit_or_releases_actions() {
        let mut guard =
            SuccessorDaemonGuard::prepare(Ok(Some(())), || Some(evidence(4242))).unwrap();
        let acknowledgements = Cell::new(0);
        assert!(!poll(
            &mut guard,
            Some(evidence(4242)),
            fresh(4242, 100),
            true,
            &acknowledgements,
            Ok(false)
        )
        .unwrap());
        assert_eq!(
            guard
                .poll(
                    || Some(evidence(4242)),
                    &fresh(4242, 101),
                    |_| true,
                    |_, _| Err("ACK write failed".into()),
                    |_| panic!("commit cannot be inferred before own ACK success"),
                )
                .unwrap_err(),
            "ACK write failed"
        );
        assert!(guard.blocker().load(Ordering::Acquire));
    }
}

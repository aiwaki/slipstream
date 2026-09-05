//! Serialize explicit stop with in-flight and queued daemon mutations.
//!
//! Crash recovery is still independent of the tray. Only an explicit Quit
//! invalidates old requests and waits for the daemon's non-destructive stop.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex,
};

pub(crate) struct Lifecycle {
    gate: Mutex<()>,
    generation: AtomicU64,
    stopping: AtomicBool,
}

impl Lifecycle {
    pub(crate) const fn new() -> Self {
        Self {
            gate: Mutex::new(()),
            generation: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
        }
    }

    pub(crate) fn ticket(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub(crate) fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    pub(crate) fn start_action<T>(&self, ticket: u64, action: impl FnOnce() -> T) -> Option<T> {
        let _guard = self.gate.lock().ok()?;
        if self.stopping() || ticket != self.ticket() {
            return None;
        }
        Some(action())
    }

    /// Called while holding the update-state lock, so an offered update cannot
    /// be admitted between the caller's busy check and publication of stop.
    pub(crate) fn begin_stop(&self) -> bool {
        if self
            .stopping
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        true
    }

    pub(crate) fn stop(
        &self,
        daemon: impl FnOnce() -> Result<(), String>,
        geph: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let result = (|| {
            let _guard = self
                .gate
                .lock()
                .map_err(|_| "lifecycle lock unavailable".to_string())?;
            if !self.stopping() {
                return Err("stop was not requested".into());
            }
            daemon()?;
            geph()
        })();
        // A failed stop stays visible and can be retried. The generation is
        // never restored: old queued repair/install actions remain cancelled.
        if result.is_err() {
            self.stopping.store(false, Ordering::SeqCst);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::Lifecycle;
    use std::sync::{mpsc, Arc, Mutex};

    #[test]
    fn quit_waits_for_inflight_repair_then_stops_daemon_before_geph() {
        let lifecycle = Arc::new(Lifecycle::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = lifecycle.clone();
        let recorded = events.clone();
        let ticket = lifecycle.ticket();
        let repair = std::thread::spawn(move || {
            worker.start_action(ticket, || {
                recorded.lock().unwrap().push("repair");
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                recorded.lock().unwrap().push("repair_done");
            })
        });
        entered_rx.recv().unwrap();
        assert!(lifecycle.begin_stop());
        assert!(!lifecycle.begin_stop());
        release_tx.send(()).unwrap();
        lifecycle
            .stop(
                || {
                    events.lock().unwrap().push("daemon_stop");
                    Ok(())
                },
                || {
                    events.lock().unwrap().push("geph_stop");
                    Ok(())
                },
            )
            .unwrap();
        repair.join().unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            ["repair", "repair_done", "daemon_stop", "geph_stop"]
        );
        assert!(lifecycle
            .start_action(ticket, || panic!("old repair ran after Quit"))
            .is_none());
    }

    #[test]
    fn failed_stop_keeps_geph_alive_and_never_readmits_old_repairs() {
        let lifecycle = Lifecycle::new();
        let old = lifecycle.ticket();
        assert!(lifecycle.begin_stop());
        assert!(lifecycle
            .stop(
                || Err("PF cleanup failed".into()),
                || panic!("Geph stopped before PF cleanup")
            )
            .is_err());
        assert!(!lifecycle.stopping());
        assert!(lifecycle
            .start_action(old, || panic!("stale restart"))
            .is_none());
        assert_eq!(
            lifecycle.start_action(lifecycle.ticket(), || "explicit retry"),
            Some("explicit retry")
        );
        assert!(lifecycle.begin_stop());
        assert!(lifecycle.stop(|| Ok(()), || Ok(())).is_ok());
    }

    #[test]
    fn geph_cleanup_failure_remains_retryable_without_claiming_exit() {
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.begin_stop());
        assert!(lifecycle
            .stop(|| Ok(()), || Err("owned process remains".into()))
            .is_err());
        assert!(!lifecycle.stopping());
        assert!(lifecycle.begin_stop());
    }
}

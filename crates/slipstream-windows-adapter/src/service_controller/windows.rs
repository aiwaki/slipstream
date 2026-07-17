//! Command-wide native Windows service reconciliation and lifecycle execution.

use super::{reconstruct_windows_service_state, WindowsServiceReconciliationError};
use crate::service_lifecycle::{
    WindowsServiceAction, WindowsServiceCommand, WindowsServiceEffects,
    WindowsServiceLifecycleError, WindowsServiceLifecycleResult, WindowsServiceLifecycleV1,
    DEFAULT_MAX_CRASH_RESTARTS,
};
use crate::service_lifecycle_state::WindowsServiceLifecycleStateEffects;
use crate::service_native::{WindowsServiceNativeEffects, WindowsServiceNativeError};
use crate::service_operation_lock::{
    acquire_service_operation_lock, WindowsServiceOperationLockError,
};
use crate::service_ownership::WindowsServiceOwnershipCollector;
use std::fmt;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct WindowsServiceController {
    source_path: PathBuf,
    max_crash_restarts: u32,
}

impl WindowsServiceController {
    pub fn new(source_path: impl Into<PathBuf>) -> Self {
        Self {
            source_path: source_path.into(),
            max_crash_restarts: DEFAULT_MAX_CRASH_RESTARTS,
        }
    }

    pub fn with_restart_limit(
        source_path: impl Into<PathBuf>,
        max_crash_restarts: u32,
    ) -> Result<Self, WindowsServiceControllerError> {
        if max_crash_restarts == 0 {
            return Err(WindowsServiceControllerError::InvalidRestartLimit);
        }
        Ok(Self {
            source_path: source_path.into(),
            max_crash_restarts,
        })
    }

    pub fn execute(
        &self,
        command: &WindowsServiceCommand,
    ) -> Result<WindowsServiceLifecycleResult, WindowsServiceControllerError> {
        let _operation_guard = acquire_service_operation_lock()?;

        let lifecycle_evidence = WindowsServiceLifecycleStateEffects::new()
            .collect()
            .assess();
        let ownership_evidence = WindowsServiceOwnershipCollector::new().assess();
        let state = reconstruct_windows_service_state(&lifecycle_evidence, &ownership_evidence)?;

        let mut lifecycle =
            WindowsServiceLifecycleV1::with_restart_limit(state, self.max_crash_restarts)?;
        let mut native = WindowsServiceNativeEffects::new(self.source_path.clone());
        let mut effects = LockedNativeEffects { inner: &mut native };
        lifecycle.execute(command, &mut effects).map_err(Into::into)
    }
}

struct LockedNativeEffects<'a> {
    inner: &'a mut WindowsServiceNativeEffects,
}

impl WindowsServiceEffects for LockedNativeEffects<'_> {
    type Error = WindowsServiceNativeError;

    fn apply(&mut self, action: &WindowsServiceAction) -> Result<(), Self::Error> {
        self.inner.apply_locked(action)
    }
}

#[derive(Debug)]
pub enum WindowsServiceControllerError {
    InvalidRestartLimit,
    OperationLock(String),
    Reconciliation(WindowsServiceReconciliationError),
    Lifecycle(WindowsServiceLifecycleError),
}

impl fmt::Display for WindowsServiceControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRestartLimit => {
                formatter.write_str("Windows service crash restart limit must be positive")
            }
            Self::OperationLock(error) => write!(formatter, "{error}"),
            Self::Reconciliation(error) => write!(formatter, "{error}"),
            Self::Lifecycle(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WindowsServiceControllerError {}

impl From<WindowsServiceOperationLockError> for WindowsServiceControllerError {
    fn from(value: WindowsServiceOperationLockError) -> Self {
        Self::OperationLock(value.to_string())
    }
}

impl From<WindowsServiceReconciliationError> for WindowsServiceControllerError {
    fn from(value: WindowsServiceReconciliationError) -> Self {
        Self::Reconciliation(value)
    }
}

impl From<WindowsServiceLifecycleError> for WindowsServiceControllerError {
    fn from(value: WindowsServiceLifecycleError) -> Self {
        Self::Lifecycle(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_lifecycle::{
        WindowsServiceDecision, WindowsServiceObservedState, WindowsServiceOwnership,
    };
    use crate::service_observer::{
        WindowsScmObserver, WindowsScmState, WindowsServiceObservation, WindowsServiceObserver,
    };
    use crate::service_ownership::{
        parse_windows_owner_record_v1, windows::machine_owner_record_path,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    const CONTROLLER_RESTART_ENV: &str = "SLIPSTREAM_WINDOWS_CONTROLLER_RESTART_CI";
    const SERVICE_FIXTURE_ENV: &str = "SLIPSTREAM_WINDOWS_SERVICE_FIXTURE";
    const CONTROLLER_FIXTURE_ENV: &str = "SLIPSTREAM_WINDOWS_CONTROLLER_FIXTURE";
    const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(20);
    const OBSERVATION_INTERVAL: Duration = Duration::from_millis(50);

    #[test]
    fn controller_process_restarts_preserve_idempotence_and_recovery_budget() {
        if std::env::var_os(CONTROLLER_RESTART_ENV).is_none() {
            return;
        }

        assert_eq!(
            WindowsScmObserver::new().observe(),
            Ok(WindowsServiceObservation::absent()),
            "the disposable runner must not already contain the Slipstream service"
        );
        let source = PathBuf::from(
            std::env::var_os(SERVICE_FIXTURE_ENV)
                .expect("the disposable service fixture path must be provided"),
        );
        let controller = PathBuf::from(
            std::env::var_os(CONTROLLER_FIXTURE_ENV)
                .expect("the disposable controller fixture path must be provided"),
        );
        let owner_record_path = machine_owner_record_path().expect("resolve machine owner record");
        let root = owner_record_path
            .parent()
            .expect("owner record must have a parent");
        if root.exists() {
            fs::remove_dir_all(root).expect("remove stale disposable controller state");
        }

        let installed = run_controller(&controller, &source, 11, "install");
        assert_eq!(installed.decision, WindowsServiceDecision::Installed);
        let first_pid = wait_for_state(WindowsScmState::Running)
            .process_id
            .expect("installed service must have a process ID");

        let repeated_install = run_controller(&controller, &source, 11, "install");
        assert_eq!(repeated_install.decision, WindowsServiceDecision::NoChange);
        assert!(repeated_install.accepted);
        assert_eq!(
            wait_for_state(WindowsScmState::Running).process_id,
            Some(first_pid),
            "idempotent install must not restart the service"
        );

        let record = parse_windows_owner_record_v1(
            &fs::read(&owner_record_path).expect("read installed owner record"),
        )
        .expect("parse installed owner record");
        let installed_executable = PathBuf::from(record.executable_path);
        let crash_sentinel = installed_executable.with_extension("crash-v1");
        fs::write(&crash_sentinel, b"crash once").expect("write crash sentinel");
        wait_for_state(WindowsScmState::Stopped);
        fs::remove_file(&crash_sentinel).expect("remove crash sentinel");

        let fail_start_sentinel = installed_executable.with_extension("fail-start-v1");
        fs::write(&fail_start_sentinel, b"fail one restart").expect("write failed-start sentinel");
        let first_recovery = run_controller(&controller, &source, 11, "crash");
        assert_eq!(first_recovery.decision, WindowsServiceDecision::Incomplete);
        assert!(!first_recovery.accepted);
        assert_eq!(first_recovery.state.crash_restart_attempts, 1);
        assert_eq!(
            first_recovery.state.ownership,
            WindowsServiceOwnership::Owned
        );
        fs::remove_file(&fail_start_sentinel).expect("remove failed-start sentinel");

        let recovered = run_controller(&controller, &source, 11, "crash");
        assert_eq!(recovered.decision, WindowsServiceDecision::Restarted);
        assert!(recovered.accepted);
        assert_eq!(recovered.state.crash_restart_attempts, 0);
        let recovered_pid = wait_for_state(WindowsScmState::Running)
            .process_id
            .expect("recovered service must have a process ID");
        assert_ne!(recovered_pid, first_pid);

        let uninstalled = run_controller(&controller, &source, 11, "uninstall");
        assert_eq!(uninstalled.decision, WindowsServiceDecision::Uninstalled);
        assert!(uninstalled.accepted);
        assert_eq!(
            uninstalled.state.observed,
            WindowsServiceObservedState::Absent
        );
        assert_eq!(
            WindowsScmObserver::new().observe(),
            Ok(WindowsServiceObservation::absent())
        );

        let repeated_uninstall = run_controller(&controller, &source, 11, "uninstall");
        assert_eq!(
            repeated_uninstall.decision,
            WindowsServiceDecision::NoChange
        );
        assert!(repeated_uninstall.accepted);
        fs::remove_dir_all(root).expect("remove disposable terminal intent");
    }

    fn run_controller(
        controller: &Path,
        source: &Path,
        generation: u64,
        command: &str,
    ) -> WindowsServiceLifecycleResult {
        let output = Command::new(controller)
            .arg(source)
            .arg(generation.to_string())
            .arg(command)
            .output()
            .expect("start disposable controller process");
        assert!(
            output.status.success(),
            "controller {command:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("controller output must be lifecycle JSON")
    }

    fn wait_for_state(
        expected: WindowsScmState,
    ) -> crate::service_observer::WindowsServiceSnapshot {
        let deadline = Instant::now() + OBSERVATION_TIMEOUT;
        loop {
            match WindowsScmObserver::new().observe() {
                Ok(WindowsServiceObservation::Present { snapshot })
                    if snapshot.scm_state == expected =>
                {
                    return snapshot;
                }
                Ok(_) => {}
                Err(error) => panic!("observe disposable service: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "service did not reach {expected:?} before the deadline"
            );
            thread::sleep(OBSERVATION_INTERVAL);
        }
    }
}

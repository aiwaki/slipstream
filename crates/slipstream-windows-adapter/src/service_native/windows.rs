//! Single-lock composition of durable state, owned payload, and exact SCM effects.

use crate::service_lifecycle::{
    WindowsServiceAction, WindowsServiceActionKind, WindowsServiceDesiredState,
    WindowsServiceEffects, WindowsServiceIdentity,
};
use crate::service_lifecycle_state::{
    WindowsServiceActiveInstallRecordV1, WindowsServiceIntentRecordV1,
    WindowsServiceLifecycleStateAssessment, WindowsServiceLifecycleStateEffects,
    WindowsServiceLifecycleStateError,
};
use crate::service_observer::WindowsScmState;
use crate::service_operation_lock::{
    acquire_service_operation_lock, WindowsServiceOperationLockError,
};
use crate::service_payload::{WindowsServicePayloadEffects, WindowsServicePayloadError};
use crate::service_scm::{WindowsServiceScmEffects, WindowsServiceScmError};
use std::fmt;
use std::path::PathBuf;

#[cfg(test)]
use crate::service_ownership::WINDOWS_OWNER_RECORD_FILE_NAME;

pub struct WindowsServiceNativeEffects {
    lifecycle_state: WindowsServiceLifecycleStateEffects,
    payload: WindowsServicePayloadEffects,
    scm: WindowsServiceScmEffects,
    deferred_clear: Option<WindowsServiceIdentity>,
}

impl WindowsServiceNativeEffects {
    pub fn new(source_path: impl Into<PathBuf>) -> Self {
        Self {
            lifecycle_state: WindowsServiceLifecycleStateEffects::new(),
            payload: WindowsServicePayloadEffects::new(source_path),
            scm: WindowsServiceScmEffects::new(),
            deferred_clear: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_disposable_test(
        source_path: PathBuf,
        destination_directory: PathBuf,
    ) -> Self {
        let lifecycle_state =
            WindowsServiceLifecycleStateEffects::for_disposable_test(destination_directory.clone());
        let scm_state =
            WindowsServiceLifecycleStateEffects::for_disposable_test(destination_directory.clone());
        let owner_record = destination_directory.join(WINDOWS_OWNER_RECORD_FILE_NAME);
        Self {
            lifecycle_state,
            payload: WindowsServicePayloadEffects::for_disposable_test(
                source_path,
                destination_directory,
            ),
            scm: WindowsServiceScmEffects::for_disposable_test(scm_state, owner_record),
            deferred_clear: None,
        }
    }

    fn apply_locked(
        &mut self,
        action: &WindowsServiceAction,
    ) -> Result<(), WindowsServiceNativeError> {
        match action {
            WindowsServiceAction::PersistIntent { .. } => {
                self.persist_intent_locked(action)?;
            }
            WindowsServiceAction::StagePayload { identity } => {
                self.require_running_intent(identity, true)?;
                self.payload.apply_locked(action)?;
            }
            WindowsServiceAction::RegisterService { .. }
            | WindowsServiceAction::StartOwnedService { .. }
            | WindowsServiceAction::StopOwnedService { .. }
            | WindowsServiceAction::UnregisterOwnedService { .. } => {
                self.scm.apply_locked(action)?;
            }
            WindowsServiceAction::VerifyReady { identity } => {
                self.require_running_intent(identity, false)?;
                self.scm
                    .wait_for_owned_state_locked(identity, WindowsScmState::Running)?;
            }
            WindowsServiceAction::CommitInstall { identity } => {
                self.require_running_intent(identity, true)?;
                self.scm
                    .wait_for_owned_state_locked(identity, WindowsScmState::Running)?;
                self.lifecycle_state.apply_locked(action)?;
            }
            WindowsServiceAction::ClearActiveInstallRecord { identity } => {
                self.clear_or_defer_locked(action, identity)?;
            }
            WindowsServiceAction::VerifyStopped { identity } => {
                self.require_stopped_or_absent_intent(identity)?;
                self.scm
                    .wait_for_owned_state_locked(identity, WindowsScmState::Stopped)?;
            }
            WindowsServiceAction::RemoveOwnedPayload { identity } => {
                self.remove_owned_payload_locked(action, identity)?;
            }
            WindowsServiceAction::VerifyAbsent { identity } => {
                self.verify_absent_locked(identity)?;
            }
        }
        Ok(())
    }

    fn persist_intent_locked(
        &mut self,
        action: &WindowsServiceAction,
    ) -> Result<(), WindowsServiceNativeError> {
        let WindowsServiceAction::PersistIntent {
            desired,
            identity,
            crash_restart_attempts,
        } = action
        else {
            return Err(WindowsServiceNativeError::UnsupportedAction(action.kind()));
        };
        if *desired == WindowsServiceDesiredState::Absent && identity.is_none() {
            let (_, active_install) = self.stable_records()?;
            if let Some(active_install) = active_install {
                let tombstone = WindowsServiceAction::PersistIntent {
                    desired: WindowsServiceDesiredState::Absent,
                    identity: Some(active_install.identity),
                    crash_restart_attempts: *crash_restart_attempts,
                };
                self.lifecycle_state.apply_locked(&tombstone)?;
                return Ok(());
            }
        }
        self.lifecycle_state.apply_locked(action)?;
        Ok(())
    }

    fn stable_records(
        &self,
    ) -> Result<
        (
            Option<WindowsServiceIntentRecordV1>,
            Option<WindowsServiceActiveInstallRecordV1>,
        ),
        WindowsServiceNativeError,
    > {
        match self.lifecycle_state.collect().assess() {
            WindowsServiceLifecycleStateAssessment::Stable {
                intent,
                active_install,
            } => Ok((intent, active_install)),
            WindowsServiceLifecycleStateAssessment::InterruptedWrite => Err(
                WindowsServiceNativeError::Verification("lifecycle state has an interrupted write"),
            ),
            WindowsServiceLifecycleStateAssessment::Unknown => {
                Err(WindowsServiceNativeError::Verification(
                    "lifecycle state is inaccessible or invalid",
                ))
            }
            WindowsServiceLifecycleStateAssessment::Inconsistent => Err(
                WindowsServiceNativeError::Verification("lifecycle state records are inconsistent"),
            ),
        }
    }

    fn require_running_intent(
        &self,
        identity: &WindowsServiceIdentity,
        require_uncommitted: bool,
    ) -> Result<(), WindowsServiceNativeError> {
        identity
            .validate()
            .map_err(|_| WindowsServiceNativeError::InvalidIdentity)?;
        let (intent, active_install) = self.stable_records()?;
        let Some(intent) = intent else {
            return Err(WindowsServiceNativeError::Verification(
                "running verification requires durable intent",
            ));
        };
        if intent.desired != WindowsServiceDesiredState::Running
            || intent.identity.as_ref() != Some(identity)
        {
            return Err(WindowsServiceNativeError::Verification(
                "durable running intent does not match the exact identity",
            ));
        }
        if require_uncommitted && (intent.crash_restart_attempts != 0 || active_install.is_some()) {
            return Err(WindowsServiceNativeError::Verification(
                "install step requires an uncommitted zero-attempt running intent",
            ));
        }
        if active_install
            .as_ref()
            .is_some_and(|active| active.identity != *identity)
        {
            return Err(WindowsServiceNativeError::Verification(
                "active install does not match the exact identity",
            ));
        }
        Ok(())
    }

    fn require_stopped_or_absent_intent(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServiceNativeError> {
        identity
            .validate()
            .map_err(|_| WindowsServiceNativeError::InvalidIdentity)?;
        let (intent, active_install) = self.stable_records()?;
        let Some(intent) = intent else {
            return Err(WindowsServiceNativeError::Verification(
                "stopped verification requires durable intent",
            ));
        };
        if !matches!(
            intent.desired,
            WindowsServiceDesiredState::Stopped | WindowsServiceDesiredState::Absent
        ) || intent
            .identity
            .as_ref()
            .is_some_and(|persisted| persisted != identity)
            || intent.crash_restart_attempts != 0
        {
            return Err(WindowsServiceNativeError::Verification(
                "durable stopped or absent intent does not match the exact identity",
            ));
        }
        if active_install
            .as_ref()
            .is_some_and(|active| active.identity != *identity)
        {
            return Err(WindowsServiceNativeError::Verification(
                "active install does not match the exact identity",
            ));
        }
        Ok(())
    }

    fn require_absent_intent(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<Option<WindowsServiceActiveInstallRecordV1>, WindowsServiceNativeError> {
        identity
            .validate()
            .map_err(|_| WindowsServiceNativeError::InvalidIdentity)?;
        let (intent, active_install) = self.stable_records()?;
        let Some(intent) = intent else {
            return Err(WindowsServiceNativeError::Verification(
                "absence verification requires durable intent",
            ));
        };
        if intent.desired != WindowsServiceDesiredState::Absent
            || intent
                .identity
                .as_ref()
                .is_some_and(|persisted| persisted != identity)
            || intent.crash_restart_attempts != 0
        {
            return Err(WindowsServiceNativeError::Verification(
                "durable absent intent does not match the exact identity",
            ));
        }
        if active_install
            .as_ref()
            .is_some_and(|active| active.identity != *identity)
        {
            return Err(WindowsServiceNativeError::Verification(
                "active install does not match the exact identity",
            ));
        }
        Ok(active_install)
    }

    fn clear_or_defer_locked(
        &mut self,
        action: &WindowsServiceAction,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServiceNativeError> {
        let active_install = self.require_absent_intent(identity)?;
        if active_install.is_none() {
            if self.deferred_clear.as_ref() == Some(identity) {
                if !self.cleanup_is_absent_locked(identity)? {
                    return Err(WindowsServiceNativeError::Verification(
                        "deferred active-install clear lost its durable record before cleanup",
                    ));
                }
                self.deferred_clear = None;
            }
            return Ok(());
        }
        if self.cleanup_is_absent_locked(identity)? {
            self.lifecycle_state.apply_locked(action)?;
            if self.deferred_clear.as_ref() == Some(identity) {
                self.deferred_clear = None;
            }
            return Ok(());
        }
        match self.deferred_clear.as_ref() {
            None => self.deferred_clear = Some(identity.clone()),
            Some(deferred) if deferred == identity => {}
            Some(_) => {
                return Err(WindowsServiceNativeError::Verification(
                    "a different active-install clear is already deferred",
                ))
            }
        }
        Ok(())
    }

    fn remove_owned_payload_locked(
        &mut self,
        action: &WindowsServiceAction,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServiceNativeError> {
        self.require_absent_intent(identity)?;
        self.scm.wait_for_absent_locked()?;
        if !self.payload.payload_is_absent_locked(identity)? {
            self.payload.apply_locked(action)?;
        }
        self.payload.verify_payload_absent_locked(identity)?;
        if let Some(deferred) = self.deferred_clear.as_ref() {
            if deferred != identity {
                return Err(WindowsServiceNativeError::Verification(
                    "deferred active-install clear belongs to a different identity",
                ));
            }
            let clear = WindowsServiceAction::ClearActiveInstallRecord {
                identity: identity.clone(),
            };
            self.lifecycle_state.apply_locked(&clear)?;
            self.deferred_clear = None;
        }
        Ok(())
    }

    fn verify_absent_locked(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServiceNativeError> {
        let active_install = self.require_absent_intent(identity)?;
        if active_install.is_some() || self.deferred_clear.is_some() {
            return Err(WindowsServiceNativeError::Verification(
                "active install remains during final absence verification",
            ));
        }
        self.scm.wait_for_absent_locked()?;
        self.payload.verify_payload_absent_locked(identity)?;
        Ok(())
    }

    fn cleanup_is_absent_locked(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<bool, WindowsServiceNativeError> {
        Ok(self.scm.exact_service_is_absent_locked()?
            && self.payload.payload_is_absent_locked(identity)?)
    }
}

impl WindowsServiceEffects for WindowsServiceNativeEffects {
    type Error = WindowsServiceNativeError;

    fn apply(&mut self, action: &WindowsServiceAction) -> Result<(), Self::Error> {
        let _operation_guard = acquire_service_operation_lock()?;
        self.apply_locked(action)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsServiceNativeError {
    UnsupportedAction(WindowsServiceActionKind),
    InvalidIdentity,
    LifecycleState(WindowsServiceLifecycleStateError),
    Payload(WindowsServicePayloadError),
    Scm(WindowsServiceScmError),
    Verification(&'static str),
    OperationLock(String),
}

impl fmt::Display for WindowsServiceNativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAction(action) => {
                write!(
                    formatter,
                    "unsupported native Windows service action: {action:?}"
                )
            }
            Self::InvalidIdentity => formatter.write_str("invalid Windows service identity"),
            Self::LifecycleState(error) => write!(formatter, "{error}"),
            Self::Payload(error) => write!(formatter, "{error}"),
            Self::Scm(error) => write!(formatter, "{error}"),
            Self::Verification(detail) => {
                write!(formatter, "native lifecycle verification failed: {detail}")
            }
            Self::OperationLock(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WindowsServiceNativeError {}

impl From<WindowsServiceLifecycleStateError> for WindowsServiceNativeError {
    fn from(value: WindowsServiceLifecycleStateError) -> Self {
        Self::LifecycleState(value)
    }
}

impl From<WindowsServicePayloadError> for WindowsServiceNativeError {
    fn from(value: WindowsServicePayloadError) -> Self {
        Self::Payload(value)
    }
}

impl From<WindowsServiceScmError> for WindowsServiceNativeError {
    fn from(value: WindowsServiceScmError) -> Self {
        Self::Scm(value)
    }
}

impl From<WindowsServiceOperationLockError> for WindowsServiceNativeError {
    fn from(value: WindowsServiceOperationLockError) -> Self {
        Self::OperationLock(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_lifecycle::{
        WindowsServiceCommand, WindowsServiceDecision, WindowsServiceLifecycleV1,
        WindowsServiceObservedState, WindowsServiceOwnership, WindowsServiceState,
        WINDOWS_SERVICE_NAME,
    };
    use crate::service_observer::{
        WindowsScmObserver, WindowsServiceObservation, WindowsServiceObserver,
    };
    use crate::service_ownership::{parse_windows_owner_record_v1, WINDOWS_OWNER_RECORD_FILE_NAME};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Read;
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, Instant};

    const FULL_LIFECYCLE_ENV: &str = "SLIPSTREAM_WINDOWS_FULL_LIFECYCLE_CI";
    const FIXTURE_PATH_ENV: &str = "SLIPSTREAM_WINDOWS_SERVICE_FIXTURE";
    const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(20);
    const OBSERVATION_INTERVAL: Duration = Duration::from_millis(50);

    #[test]
    fn native_full_lifecycle_and_post_commit_compensation_are_disposable() {
        if std::env::var_os(FULL_LIFECYCLE_ENV).is_none() {
            return;
        }
        assert_eq!(
            WindowsScmObserver::new().observe(),
            Ok(WindowsServiceObservation::absent()),
            "the disposable runner must not already contain the Slipstream service"
        );
        let source = PathBuf::from(
            std::env::var_os(FIXTURE_PATH_ENV)
                .expect("the disposable service fixture path must be provided"),
        );
        let first = run_full_lifecycle(&source, 1);
        assert!(first.is_ok(), "full lifecycle failed: {first:?}");
        let compensation = run_post_commit_compensation(&source, 2);
        assert!(
            compensation.is_ok(),
            "post-commit compensation failed: {compensation:?}"
        );
        assert_eq!(
            WindowsScmObserver::new().observe(),
            Ok(WindowsServiceObservation::absent()),
            "the disposable tests must leave the exact service absent"
        );
    }

    fn run_full_lifecycle(source: &Path, generation: u64) -> Result<(), String> {
        let root = disposable_root("full");
        let destination = root.join("Slipstream");
        let identity = identity_for(source, generation)?;
        let mut effects = WindowsServiceNativeEffects::for_disposable_test(
            source.to_path_buf(),
            destination.clone(),
        );
        let mut lifecycle = WindowsServiceLifecycleV1::new(WindowsServiceState::absent())
            .map_err(|error| error.to_string())?;

        let installed = lifecycle
            .execute(
                &WindowsServiceCommand::Install {
                    identity: identity.clone(),
                },
                &mut effects,
            )
            .map_err(|error| error.to_string())?;
        require_decision(installed.decision, WindowsServiceDecision::Installed)?;
        let first_pid = wait_for_state(WindowsScmState::Running)?
            .process_id
            .ok_or_else(|| "running fixture has no process ID".to_owned())?;

        let stopped = lifecycle
            .execute(&WindowsServiceCommand::Stop, &mut effects)
            .map_err(|error| error.to_string())?;
        require_decision(stopped.decision, WindowsServiceDecision::Stopped)?;
        wait_for_state(WindowsScmState::Stopped)?;

        let started = lifecycle
            .execute(&WindowsServiceCommand::Start, &mut effects)
            .map_err(|error| error.to_string())?;
        require_decision(started.decision, WindowsServiceDecision::Started)?;
        wait_for_state(WindowsScmState::Running)?;

        let owner_record = parse_windows_owner_record_v1(
            &fs::read(destination.join(WINDOWS_OWNER_RECORD_FILE_NAME))
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let crash_sentinel = PathBuf::from(owner_record.executable_path).with_extension("crash-v1");
        fs::write(&crash_sentinel, b"crash once").map_err(|error| error.to_string())?;
        wait_for_state(WindowsScmState::Stopped)?;
        fs::remove_file(&crash_sentinel).map_err(|error| error.to_string())?;

        let crashed_state = WindowsServiceState {
            desired: WindowsServiceDesiredState::Running,
            observed: WindowsServiceObservedState::Stopped,
            ownership: WindowsServiceOwnership::Owned,
            active: Some(identity.clone()),
            crash_restart_attempts: 0,
        };
        let mut lifecycle =
            WindowsServiceLifecycleV1::new(crashed_state).map_err(|error| error.to_string())?;
        let restarted = lifecycle
            .execute(&WindowsServiceCommand::CrashObserved, &mut effects)
            .map_err(|error| error.to_string())?;
        require_decision(restarted.decision, WindowsServiceDecision::Restarted)?;
        let restarted_pid = wait_for_state(WindowsScmState::Running)?
            .process_id
            .ok_or_else(|| "restarted fixture has no process ID".to_owned())?;
        if restarted_pid == first_pid {
            return Err("crash recovery did not replace the service process".to_owned());
        }

        let uninstalled = lifecycle
            .execute(&WindowsServiceCommand::Uninstall, &mut effects)
            .map_err(|error| error.to_string())?;
        require_decision(uninstalled.decision, WindowsServiceDecision::Uninstalled)?;
        verify_terminal_absence(&effects, &identity)?;
        fs::remove_dir_all(&root).map_err(|error| error.to_string())?;
        Ok(())
    }

    fn run_post_commit_compensation(source: &Path, generation: u64) -> Result<(), String> {
        let root = disposable_root("compensation");
        let destination = root.join("Slipstream");
        let identity = identity_for(source, generation)?;
        let mut effects =
            WindowsServiceNativeEffects::for_disposable_test(source.to_path_buf(), destination);
        let mut lifecycle = WindowsServiceLifecycleV1::new(WindowsServiceState::absent())
            .map_err(|error| error.to_string())?;
        let (result, failure_was_injected) = {
            let mut injected = FailAfterCommittedInstall {
                inner: &mut effects,
                fired: false,
            };
            let result = lifecycle
                .execute(
                    &WindowsServiceCommand::Install {
                        identity: identity.clone(),
                    },
                    &mut injected,
                )
                .map_err(|error| error.to_string())?;
            (result, injected.fired)
        };
        if !failure_was_injected {
            return Err("post-commit failure was not injected".to_owned());
        }
        require_decision(result.decision, WindowsServiceDecision::RolledBack)?;
        if result.accepted || result.state != WindowsServiceState::absent() {
            return Err("post-commit failure did not restore the absent reducer state".to_owned());
        }
        verify_terminal_absence(&effects, &identity)?;
        fs::remove_dir_all(&root).map_err(|error| error.to_string())?;
        Ok(())
    }

    struct FailAfterCommittedInstall<'a> {
        inner: &'a mut WindowsServiceNativeEffects,
        fired: bool,
    }

    impl WindowsServiceEffects for FailAfterCommittedInstall<'_> {
        type Error = String;

        fn apply(&mut self, action: &WindowsServiceAction) -> Result<(), Self::Error> {
            self.inner
                .apply(action)
                .map_err(|error| error.to_string())?;
            if !self.fired && action.kind() == WindowsServiceActionKind::CommitInstall {
                self.fired = true;
                return Err("injected failure after durable install commit".to_owned());
            }
            Ok(())
        }
    }

    fn verify_terminal_absence(
        effects: &WindowsServiceNativeEffects,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), String> {
        effects
            .scm
            .wait_for_absent_locked()
            .map_err(|error| error.to_string())?;
        effects
            .payload
            .verify_payload_absent_locked(identity)
            .map_err(|error| error.to_string())?;
        match effects.lifecycle_state.collect().assess() {
            WindowsServiceLifecycleStateAssessment::Stable {
                intent: Some(intent),
                active_install: None,
            } if intent.desired == WindowsServiceDesiredState::Absent
                && intent.crash_restart_attempts == 0 => {}
            state => return Err(format!("terminal lifecycle state is not absent: {state:?}")),
        }
        if effects.deferred_clear.is_some() {
            return Err("terminal lifecycle retained a deferred clear".to_owned());
        }
        Ok(())
    }

    fn wait_for_state(
        expected: WindowsScmState,
    ) -> Result<crate::service_observer::WindowsServiceSnapshot, String> {
        let deadline = Instant::now() + OBSERVATION_TIMEOUT;
        loop {
            match WindowsScmObserver::new().observe() {
                Ok(WindowsServiceObservation::Present { snapshot })
                    if snapshot.scm_state == expected =>
                {
                    return Ok(snapshot)
                }
                Ok(_) => {}
                Err(error) => return Err(error.to_string()),
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "service did not reach {expected:?} before the deadline"
                ));
            }
            thread::sleep(OBSERVATION_INTERVAL);
        }
    }

    fn require_decision(
        actual: WindowsServiceDecision,
        expected: WindowsServiceDecision,
    ) -> Result<(), String> {
        if actual == expected {
            Ok(())
        } else {
            Err(format!("expected {expected:?}, got {actual:?}"))
        }
    }

    fn disposable_root(case: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("slipstream-native-{case}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create disposable native lifecycle root");
        root
    }

    fn identity_for(source: &Path, generation: u64) -> Result<WindowsServiceIdentity, String> {
        Ok(WindowsServiceIdentity {
            service_name: WINDOWS_SERVICE_NAME.to_owned(),
            executable_sha256: sha256_file(source)?,
            generation,
        })
    }

    fn sha256_file(path: &Path) -> Result<String, String> {
        let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}

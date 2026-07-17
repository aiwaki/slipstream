//! Native, action-gated SCM effects for the exact Slipstream service.

use super::{
    assess_windows_service_scm_action, snapshot_is_exact_owned, snapshot_matches_staged_payload,
    WindowsServiceScmGateOutcome, WindowsServiceScmGateReason,
};
use crate::service_lifecycle::{
    WindowsServiceAction, WindowsServiceEffects, WindowsServiceIdentity, WINDOWS_SERVICE_NAME,
};
use crate::service_lifecycle_state::WindowsServiceLifecycleStateEffects;
use crate::service_observer::windows::observe_open_service_handle;
use crate::service_observer::{
    WindowsScmState, WindowsServiceObservation, WindowsServiceObserverError, WindowsServiceSnapshot,
};
use crate::service_operation_lock::{
    acquire_service_operation_lock, WindowsServiceOperationLockError,
};
use crate::service_ownership::{
    WindowsOwnerRecordEvidence, WindowsServiceOwnershipCollector, WindowsStagedPayloadEvidence,
};
use std::fmt;
use std::mem::MaybeUninit;
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
use crate::service_ownership::windows::staged_payload_evidence_at;
#[cfg(test)]
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, StartServiceW, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_WIN32_OWN_PROCESS,
};

// DELETE is a standard access right; windows-sys has no service-specific alias.
const SERVICE_DELETE_ACCESS: u32 = 0x0001_0000;
const SERVICE_DISPLAY_NAME: &str = "Slipstream";
const STOP_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_WAIT_INTERVAL: Duration = Duration::from_millis(50);
const DELETE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const DELETE_WAIT_INTERVAL: Duration = Duration::from_millis(50);

pub struct WindowsServiceScmEffects {
    state_effects: WindowsServiceLifecycleStateEffects,
    #[cfg(test)]
    owner_record_path_override: Option<PathBuf>,
}

impl WindowsServiceScmEffects {
    pub fn new() -> Self {
        Self {
            state_effects: WindowsServiceLifecycleStateEffects::new(),
            #[cfg(test)]
            owner_record_path_override: None,
        }
    }

    fn register_service(
        &self,
        action: &WindowsServiceAction,
        identity: &WindowsServiceIdentity,
        lifecycle: &crate::service_lifecycle_state::WindowsServiceLifecycleStateAssessment,
        payload: &WindowsStagedPayloadEvidence,
    ) -> Result<(), WindowsServiceScmError> {
        let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
        if let Some(service) =
            open_exact_service(manager.raw(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?
        {
            let observation = observe_open_service_handle(service.raw())?;
            return require_no_mutation(assess_windows_service_scm_action(
                action,
                lifecycle,
                &observation,
                payload,
            ));
        }

        let decision = assess_windows_service_scm_action(
            action,
            lifecycle,
            &WindowsServiceObservation::absent(),
            payload,
        );
        require_mutation(decision)?;

        let record = match &payload.record {
            WindowsOwnerRecordEvidence::OwnerOnly { record } => record,
            _ => {
                return Err(WindowsServiceScmError::Gate(
                    WindowsServiceScmGateReason::PayloadMismatch,
                ))
            }
        };
        let service_name = wide_null(WINDOWS_SERVICE_NAME);
        let display_name = wide_null(SERVICE_DISPLAY_NAME);
        let binary_path = wide_null(&record.scm_binary_path);
        let service_handle = unsafe {
            CreateServiceW(
                manager.raw(),
                service_name.as_ptr(),
                display_name.as_ptr(),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                binary_path.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
            )
        };
        let service = OwnedScHandle::open(service_handle, "CreateServiceW")?;
        let snapshot = present_snapshot(observe_open_service_handle(service.raw())?)?;
        if snapshot.scm_state != WindowsScmState::Stopped
            || !snapshot_is_exact_owned(snapshot, identity, payload)
        {
            return Err(WindowsServiceScmError::Verification(
                "created service did not reproduce the exact stopped ownership evidence",
            ));
        }
        Ok(())
    }

    fn mutate_existing_service(
        &self,
        action: &WindowsServiceAction,
        identity: &WindowsServiceIdentity,
        lifecycle: &crate::service_lifecycle_state::WindowsServiceLifecycleStateAssessment,
        payload: &WindowsStagedPayloadEvidence,
        desired_access: u32,
        mutation: ExistingMutation,
    ) -> Result<(), WindowsServiceScmError> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let Some(service) = open_exact_service(
            manager.raw(),
            desired_access | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )?
        else {
            let decision = assess_windows_service_scm_action(
                action,
                lifecycle,
                &WindowsServiceObservation::absent(),
                payload,
            );
            return require_no_mutation(decision);
        };

        let observation = observe_open_service_handle(service.raw())?;
        let decision = assess_windows_service_scm_action(action, lifecycle, &observation, payload);
        match decision.outcome {
            WindowsServiceScmGateOutcome::NoChange => return Ok(()),
            WindowsServiceScmGateOutcome::Refuse => {
                return Err(WindowsServiceScmError::Gate(decision.reason))
            }
            WindowsServiceScmGateOutcome::Mutate => {}
        }

        match mutation {
            ExistingMutation::Start => start_exact_service(&service, identity, payload),
            ExistingMutation::Stop => stop_exact_service(&service, identity, payload),
            ExistingMutation::Unregister => {
                delete_exact_service(&service)?;
                drop(service);
                drop(manager);
                wait_for_exact_service_absent()
            }
        }
    }

    fn collect_payload(&self) -> WindowsStagedPayloadEvidence {
        #[cfg(test)]
        if let Some(path) = &self.owner_record_path_override {
            return staged_payload_evidence_at(path);
        }
        WindowsServiceOwnershipCollector::new().collect_staged_payload()
    }

    #[cfg(test)]
    pub(crate) fn for_disposable_test(
        state_effects: WindowsServiceLifecycleStateEffects,
        owner_record_path: PathBuf,
    ) -> Self {
        Self {
            state_effects,
            owner_record_path_override: Some(owner_record_path),
        }
    }

    pub(crate) fn wait_for_owned_state_locked(
        &self,
        identity: &WindowsServiceIdentity,
        expected: WindowsScmState,
    ) -> Result<(), WindowsServiceScmError> {
        identity.validate().map_err(|_| {
            WindowsServiceScmError::Gate(WindowsServiceScmGateReason::InvalidIdentity)
        })?;
        let payload = self.collect_payload();
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service =
            open_exact_service(manager.raw(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?.ok_or(
                WindowsServiceScmError::Verification(
                    "owned service is absent during state verification",
                ),
            )?;
        wait_for_owned_state(&service, identity, &payload, expected)
    }

    pub(crate) fn wait_for_absent_locked(&self) -> Result<(), WindowsServiceScmError> {
        wait_for_exact_service_absent()
    }

    pub(crate) fn exact_service_is_absent_locked(&self) -> Result<bool, WindowsServiceScmError> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        exact_service_is_absent(&manager)
    }

    pub(crate) fn apply_locked(
        &mut self,
        action: &WindowsServiceAction,
    ) -> Result<(), WindowsServiceScmError> {
        let identity = match action {
            WindowsServiceAction::RegisterService { identity }
            | WindowsServiceAction::StartOwnedService { identity }
            | WindowsServiceAction::StopOwnedService { identity }
            | WindowsServiceAction::UnregisterOwnedService { identity } => identity,
            _ => return Err(WindowsServiceScmError::UnsupportedAction),
        };
        identity.validate().map_err(|_| {
            WindowsServiceScmError::Gate(WindowsServiceScmGateReason::InvalidIdentity)
        })?;
        let lifecycle = self.state_effects.collect().assess();
        let payload = self.collect_payload();

        match action {
            WindowsServiceAction::RegisterService { .. } => {
                self.register_service(action, identity, &lifecycle, &payload)
            }
            WindowsServiceAction::StartOwnedService { .. } => self.mutate_existing_service(
                action,
                identity,
                &lifecycle,
                &payload,
                SERVICE_START,
                ExistingMutation::Start,
            ),
            WindowsServiceAction::StopOwnedService { .. } => self.mutate_existing_service(
                action,
                identity,
                &lifecycle,
                &payload,
                SERVICE_STOP,
                ExistingMutation::Stop,
            ),
            WindowsServiceAction::UnregisterOwnedService { .. } => self.mutate_existing_service(
                action,
                identity,
                &lifecycle,
                &payload,
                SERVICE_DELETE_ACCESS,
                ExistingMutation::Unregister,
            ),
            _ => Err(WindowsServiceScmError::UnsupportedAction),
        }
    }
}

impl Default for WindowsServiceScmEffects {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsServiceEffects for WindowsServiceScmEffects {
    type Error = WindowsServiceScmError;

    fn apply(&mut self, action: &WindowsServiceAction) -> Result<(), Self::Error> {
        let _operation_guard = acquire_service_operation_lock()?;
        self.apply_locked(action)
    }
}

#[derive(Clone, Copy)]
enum ExistingMutation {
    Start,
    Stop,
    Unregister,
}

fn start_exact_service(
    service: &OwnedScHandle,
    identity: &WindowsServiceIdentity,
    payload: &WindowsStagedPayloadEvidence,
) -> Result<(), WindowsServiceScmError> {
    let ok = unsafe { StartServiceW(service.raw(), 0, null()) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_SERVICE_ALREADY_RUNNING
            && verify_stable_state(service, identity, payload, WindowsScmState::Running)?
        {
            return Ok(());
        }
        return Err(WindowsServiceScmError::Win32 {
            operation: "StartServiceW",
            code,
        });
    }
    verify_post_request(
        service,
        identity,
        payload,
        "started service changed identity after the accepted request",
    )
}

fn stop_exact_service(
    service: &OwnedScHandle,
    identity: &WindowsServiceIdentity,
    payload: &WindowsStagedPayloadEvidence,
) -> Result<(), WindowsServiceScmError> {
    let mut status = MaybeUninit::<SERVICE_STATUS>::zeroed();
    let ok = unsafe { ControlService(service.raw(), SERVICE_CONTROL_STOP, status.as_mut_ptr()) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_SERVICE_NOT_ACTIVE
            && verify_stable_state(service, identity, payload, WindowsScmState::Stopped)?
        {
            return Ok(());
        }
        return Err(WindowsServiceScmError::Win32 {
            operation: "ControlService(STOP)",
            code,
        });
    }
    wait_for_stopped(service, identity, payload)
}

fn delete_exact_service(service: &OwnedScHandle) -> Result<(), WindowsServiceScmError> {
    let ok = unsafe { DeleteService(service.raw()) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_SERVICE_MARKED_FOR_DELETE {
            return Ok(());
        }
        return Err(WindowsServiceScmError::Win32 {
            operation: "DeleteService",
            code,
        });
    }
    Ok(())
}

fn wait_for_owned_state(
    service: &OwnedScHandle,
    identity: &WindowsServiceIdentity,
    payload: &WindowsStagedPayloadEvidence,
    expected: WindowsScmState,
) -> Result<(), WindowsServiceScmError> {
    let deadline = Instant::now() + STOP_WAIT_TIMEOUT;
    loop {
        let snapshot = present_snapshot(observe_open_service_handle(service.raw())?)?;
        if !snapshot_matches_staged_payload(&snapshot, identity, payload) {
            return Err(WindowsServiceScmError::Verification(
                "service changed identity during state verification",
            ));
        }
        if snapshot.scm_state == expected {
            return Ok(());
        }
        let transitional = matches!(
            (expected, snapshot.scm_state),
            (WindowsScmState::Running, WindowsScmState::StartPending)
                | (WindowsScmState::Stopped, WindowsScmState::Running)
                | (WindowsScmState::Stopped, WindowsScmState::StopPending)
        );
        if !transitional {
            return Err(WindowsServiceScmError::Verification(
                "service entered an unexpected SCM state",
            ));
        }
        if Instant::now() >= deadline {
            return Err(WindowsServiceScmError::Verification(
                "service did not reach the expected state before the bounded deadline",
            ));
        }
        thread::sleep(STOP_WAIT_INTERVAL);
    }
}

fn wait_for_exact_service_absent() -> Result<(), WindowsServiceScmError> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let deadline = Instant::now() + DELETE_WAIT_TIMEOUT;
    loop {
        if exact_service_is_absent(&manager)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(WindowsServiceScmError::Verification(
                "service remained registered after deletion before the bounded deadline",
            ));
        }
        thread::sleep(DELETE_WAIT_INTERVAL);
    }
}

fn exact_service_is_absent(manager: &OwnedScHandle) -> Result<bool, WindowsServiceScmError> {
    match open_exact_service(manager.raw(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS) {
        Ok(None) => Ok(true),
        Ok(Some(service)) => {
            drop(service);
            Ok(false)
        }
        Err(WindowsServiceScmError::Win32 {
            operation: "OpenServiceW",
            code: ERROR_SERVICE_MARKED_FOR_DELETE,
        }) => Ok(false),
        Err(error) => Err(error),
    }
}

fn verify_stable_state(
    service: &OwnedScHandle,
    identity: &WindowsServiceIdentity,
    payload: &WindowsStagedPayloadEvidence,
    expected: WindowsScmState,
) -> Result<bool, WindowsServiceScmError> {
    let snapshot = present_snapshot(observe_open_service_handle(service.raw())?)?;
    Ok(snapshot.scm_state == expected
        && snapshot_matches_staged_payload(&snapshot, identity, payload))
}

fn verify_post_request(
    service: &OwnedScHandle,
    identity: &WindowsServiceIdentity,
    payload: &WindowsStagedPayloadEvidence,
    detail: &'static str,
) -> Result<(), WindowsServiceScmError> {
    let snapshot = present_snapshot(observe_open_service_handle(service.raw())?)?;
    if snapshot_matches_staged_payload(&snapshot, identity, payload) {
        return Ok(());
    }
    Err(WindowsServiceScmError::Verification(detail))
}

fn wait_for_stopped(
    service: &OwnedScHandle,
    identity: &WindowsServiceIdentity,
    payload: &WindowsStagedPayloadEvidence,
) -> Result<(), WindowsServiceScmError> {
    let deadline = Instant::now() + STOP_WAIT_TIMEOUT;
    loop {
        let snapshot = present_snapshot(observe_open_service_handle(service.raw())?)?;
        if !snapshot_matches_staged_payload(&snapshot, identity, payload) {
            return Err(WindowsServiceScmError::Verification(
                "stopping service changed identity",
            ));
        }
        match snapshot.scm_state {
            WindowsScmState::Stopped => return Ok(()),
            WindowsScmState::Running | WindowsScmState::StopPending => {}
            _ => {
                return Err(WindowsServiceScmError::Verification(
                    "stopping service entered an unexpected SCM state",
                ))
            }
        }
        if Instant::now() >= deadline {
            return Err(WindowsServiceScmError::Verification(
                "service did not reach stopped state before the bounded deadline",
            ));
        }
        thread::sleep(STOP_WAIT_INTERVAL);
    }
}

fn present_snapshot(
    observation: WindowsServiceObservation,
) -> Result<WindowsServiceSnapshot, WindowsServiceScmError> {
    match observation {
        WindowsServiceObservation::Present { snapshot } => Ok(snapshot),
        WindowsServiceObservation::Absent { .. } => Err(WindowsServiceScmError::Verification(
            "an open service handle was reported absent",
        )),
    }
}

fn require_mutation(
    decision: super::WindowsServiceScmGateDecision,
) -> Result<(), WindowsServiceScmError> {
    match decision.outcome {
        WindowsServiceScmGateOutcome::Mutate => Ok(()),
        WindowsServiceScmGateOutcome::NoChange | WindowsServiceScmGateOutcome::Refuse => {
            Err(WindowsServiceScmError::Gate(decision.reason))
        }
    }
}

fn require_no_mutation(
    decision: super::WindowsServiceScmGateDecision,
) -> Result<(), WindowsServiceScmError> {
    match decision.outcome {
        WindowsServiceScmGateOutcome::NoChange => Ok(()),
        WindowsServiceScmGateOutcome::Mutate | WindowsServiceScmGateOutcome::Refuse => {
            Err(WindowsServiceScmError::Gate(decision.reason))
        }
    }
}

fn open_manager(access: u32) -> Result<OwnedScHandle, WindowsServiceScmError> {
    let handle = unsafe { OpenSCManagerW(null(), null(), access) };
    OwnedScHandle::open(handle, "OpenSCManagerW")
}

fn open_exact_service(
    manager: SC_HANDLE,
    access: u32,
) -> Result<Option<OwnedScHandle>, WindowsServiceScmError> {
    let service_name = wide_null(WINDOWS_SERVICE_NAME);
    let handle = unsafe { OpenServiceW(manager, service_name.as_ptr(), access) };
    if handle.is_null() {
        let code = unsafe { GetLastError() };
        if code == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(None);
        }
        return Err(WindowsServiceScmError::Win32 {
            operation: "OpenServiceW",
            code,
        });
    }
    Ok(Some(OwnedScHandle(handle)))
}

struct OwnedScHandle(SC_HANDLE);

impl OwnedScHandle {
    fn open(handle: SC_HANDLE, operation: &'static str) -> Result<Self, WindowsServiceScmError> {
        if handle.is_null() {
            return Err(last_error(operation));
        }
        Ok(Self(handle))
    }

    const fn raw(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for OwnedScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error(operation: &'static str) -> WindowsServiceScmError {
    WindowsServiceScmError::Win32 {
        operation,
        code: unsafe { GetLastError() },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsServiceScmError {
    UnsupportedAction,
    Gate(WindowsServiceScmGateReason),
    Observer(WindowsServiceObserverError),
    Win32 { operation: &'static str, code: u32 },
    Verification(&'static str),
    OperationLock(String),
}

impl fmt::Display for WindowsServiceScmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAction => formatter.write_str("action is outside the SCM effect"),
            Self::Gate(reason) => write!(formatter, "SCM mutation refused: {reason:?}"),
            Self::Observer(error) => write!(formatter, "SCM observation failed: {error}"),
            Self::Win32 { operation, code } => {
                write!(formatter, "{operation} failed with Win32 error {code}")
            }
            Self::Verification(detail) => write!(formatter, "SCM verification failed: {detail}"),
            Self::OperationLock(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WindowsServiceScmError {}

impl From<WindowsServiceOperationLockError> for WindowsServiceScmError {
    fn from(value: WindowsServiceOperationLockError) -> Self {
        Self::OperationLock(value.to_string())
    }
}

impl From<WindowsServiceObserverError> for WindowsServiceScmError {
    fn from(value: WindowsServiceObserverError) -> Self {
        Self::Observer(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_lifecycle::WindowsServiceDesiredState;
    use crate::service_observer::{WindowsScmObserver, WindowsServiceObserver};
    use crate::service_ownership::WINDOWS_OWNER_RECORD_FILE_NAME;
    use crate::service_payload::WindowsServicePayloadEffects;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Read;

    #[test]
    fn native_register_and_unregister_are_exact_and_disposable() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_SCM_DISPOSABLE_CI").is_none() {
            return;
        }
        assert_eq!(
            WindowsScmObserver::new().observe(),
            Ok(WindowsServiceObservation::absent()),
            "the disposable runner must not already contain the Slipstream service"
        );

        let root =
            std::env::temp_dir().join(format!("slipstream-scm-effects-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create disposable SCM root");
        let destination = root.join("Slipstream");
        let source = std::env::current_exe().expect("resolve current test executable");
        let identity = WindowsServiceIdentity {
            service_name: WINDOWS_SERVICE_NAME.to_owned(),
            executable_sha256: sha256_file(&source),
            generation: 1,
        };
        let mut payload_effects =
            WindowsServicePayloadEffects::for_disposable_test(source, destination.clone());
        let mut state_effects =
            WindowsServiceLifecycleStateEffects::for_disposable_test(destination.clone());
        state_effects
            .apply(&WindowsServiceAction::PersistIntent {
                desired: WindowsServiceDesiredState::Running,
                identity: Some(identity.clone()),
                crash_restart_attempts: 0,
            })
            .expect("persist disposable running intent");
        payload_effects
            .apply(&WindowsServiceAction::StagePayload {
                identity: identity.clone(),
            })
            .expect("stage disposable service payload");

        let owner_record = destination.join(WINDOWS_OWNER_RECORD_FILE_NAME);
        let mut effects =
            WindowsServiceScmEffects::for_disposable_test(state_effects, owner_record);
        let result = effects.apply(&WindowsServiceAction::RegisterService {
            identity: identity.clone(),
        });

        let registered = WindowsScmObserver::new().observe();
        let _ = effects
            .state_effects
            .apply(&WindowsServiceAction::PersistIntent {
                desired: WindowsServiceDesiredState::Absent,
                identity: Some(identity.clone()),
                crash_restart_attempts: 0,
            });
        let stop_result = effects.apply(&WindowsServiceAction::StopOwnedService {
            identity: identity.clone(),
        });
        let unregister_result = effects.apply(&WindowsServiceAction::UnregisterOwnedService {
            identity: identity.clone(),
        });
        let absent = WindowsScmObserver::new().observe();
        let service_is_absent = absent == Ok(WindowsServiceObservation::absent());
        let remove_result = service_is_absent
            .then(|| payload_effects.apply(&WindowsServiceAction::RemoveOwnedPayload { identity }));
        if matches!(remove_result, Some(Ok(()))) {
            let _ = fs::remove_dir_all(&root);
        }

        result.expect("register exact disposable service");
        let snapshot = match registered.expect("observe registered service") {
            WindowsServiceObservation::Present { snapshot } => snapshot,
            WindowsServiceObservation::Absent { .. } => panic!("registered service is absent"),
        };
        assert_eq!(snapshot.scm_state, WindowsScmState::Stopped);
        stop_result.expect("already-stopped service is a safe no-op");
        unregister_result.expect("unregister exact disposable service");
        assert_eq!(absent, Ok(WindowsServiceObservation::absent()));
        remove_result
            .expect("service must be absent before payload removal")
            .expect("remove disposable staged payload");
    }

    fn sha256_file(path: &std::path::Path) -> String {
        let mut file = fs::File::open(path).expect("open test executable");
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).expect("hash test executable");
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        format!("{:x}", hasher.finalize())
    }
}

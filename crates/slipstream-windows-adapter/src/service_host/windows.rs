//! Native Windows service dispatcher and self-managing controller entry point.

use super::{
    WindowsServiceHostContractError, WindowsServiceHostFailureCode, WindowsServiceHostInvocation,
    WindowsServiceHostPhase, WindowsServiceHostStatus, WindowsServiceManagementCommand,
    WindowsServiceManagementResultV1,
};
use crate::data_plane::{WindowsDataPlaneCommand, WindowsDataPlaneConfig, WindowsDataPlaneEvent};
use crate::service_controller::{WindowsServiceController, WindowsServiceControllerError};
use crate::service_lifecycle::{
    WindowsServiceCommand, WindowsServiceIdentity, WINDOWS_SERVICE_NAME,
};
use crate::worker_host::{
    execute_windows_worker_host_transition, reduce_windows_worker_host, WindowsWorkerHostCommand,
    WindowsWorkerHostEffects, WindowsWorkerHostEvent, WindowsWorkerHostState,
};
use sha2::{Digest, Sha256};
use slipstream_core::routing_policy::{bundled_policy_v1, RoutingPolicyTables};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

const SOURCE_READ_BUFFER_BYTES: usize = 64 * 1024;
const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;
const STATUS_WAIT_HINT_MILLIS: u32 = 5_000;
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(25);
const WORKER_CANCEL_TIMEOUT_MILLIS: u64 = 1_000;
const WORKER_SHUTDOWN_TIMEOUT_MILLIS: u64 = 4_000;
const WORKER_SESSION_LIMIT: usize = 1_024;
const CONTROL_NONE: u32 = 0;

static REQUESTED_CONTROL: AtomicU32 = AtomicU32::new(CONTROL_NONE);

pub fn execute_windows_service_host(
    invocation: WindowsServiceHostInvocation,
) -> Result<Option<WindowsServiceManagementResultV1>, WindowsServiceHostNativeError> {
    match invocation {
        WindowsServiceHostInvocation::Service => {
            run_service_dispatcher()?;
            Ok(None)
        }
        WindowsServiceHostInvocation::Manage { command } => {
            execute_management_command(command).map(Some)
        }
    }
}

fn execute_management_command(
    command: WindowsServiceManagementCommand,
) -> Result<WindowsServiceManagementResultV1, WindowsServiceHostNativeError> {
    let source_path = std::env::current_exe()
        .map_err(|_| WindowsServiceHostNativeError::CurrentExecutableUnavailable)?;
    let command_kind = command.kind();
    let lifecycle_command = match command {
        WindowsServiceManagementCommand::Install { generation } => WindowsServiceCommand::Install {
            identity: WindowsServiceIdentity {
                service_name: WINDOWS_SERVICE_NAME.to_owned(),
                executable_sha256: hash_source(&source_path)?,
                generation,
            },
        },
        WindowsServiceManagementCommand::Start => WindowsServiceCommand::Start,
        WindowsServiceManagementCommand::Stop => WindowsServiceCommand::Stop,
        WindowsServiceManagementCommand::Recover => WindowsServiceCommand::CrashObserved,
        WindowsServiceManagementCommand::Uninstall => WindowsServiceCommand::Uninstall,
    };

    let lifecycle = WindowsServiceController::new(source_path).execute(&lifecycle_command)?;
    let result = WindowsServiceManagementResultV1::new(command_kind, lifecycle);
    result.validate()?;
    Ok(result)
}

fn hash_source(path: &Path) -> Result<String, WindowsServiceHostNativeError> {
    let mut file = File::open(path).map_err(|_| WindowsServiceHostNativeError::SourceHashFailed)?;
    let metadata = file
        .metadata()
        .map_err(|_| WindowsServiceHostNativeError::SourceHashFailed)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_SOURCE_BYTES {
        return Err(WindowsServiceHostNativeError::SourceHashFailed);
    }

    let expected_size = metadata.len();
    let mut total = 0u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; SOURCE_READ_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| WindowsServiceHostNativeError::SourceHashFailed)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(WindowsServiceHostNativeError::SourceHashFailed)?;
        if total > MAX_SOURCE_BYTES {
            return Err(WindowsServiceHostNativeError::SourceHashFailed);
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err(WindowsServiceHostNativeError::SourceHashFailed);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn run_service_dispatcher() -> Result<(), WindowsServiceHostNativeError> {
    let mut service_name = wide_null(WINDOWS_SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service_name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        return Err(WindowsServiceHostNativeError::Win32 {
            operation: "StartServiceCtrlDispatcherW",
            code: unsafe { GetLastError() },
        });
    }
    Ok(())
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    REQUESTED_CONTROL.store(CONTROL_NONE, Ordering::Release);
    let service_name = wide_null(WINDOWS_SERVICE_NAME);
    let status_handle = unsafe {
        RegisterServiceCtrlHandlerW(service_name.as_ptr(), Some(service_control_handler))
    };
    if status_handle.is_null() {
        return;
    }

    let started = Instant::now();
    let mut state = WindowsWorkerHostState::new(0);
    let config = production_worker_config();
    let policy_tables = bundled_policy_v1();
    let mut effects = NoNetworkWindowsWorkerHostEffects::new(status_handle);
    if !report_status(status_handle, state.initial_service_status(), 0) {
        return;
    }
    if apply_worker_host_event(
        &mut state,
        WindowsWorkerHostEvent::Worker {
            event: WindowsDataPlaneEvent::WorkerReady {
                now_ms: elapsed_ms(started),
            },
        },
        &config,
        &policy_tables,
        &mut effects,
    )
    .is_err()
    {
        let _ = report_status(status_handle, WindowsServiceHostStatus::Stopped, 1);
        return;
    }

    loop {
        let control = REQUESTED_CONTROL.load(Ordering::Acquire);
        let now_ms = elapsed_ms(started);
        let event = match control {
            SERVICE_CONTROL_STOP => Some(WindowsWorkerHostEvent::StopRequested { now_ms }),
            SERVICE_CONTROL_SHUTDOWN => Some(WindowsWorkerHostEvent::ShutdownRequested { now_ms }),
            _ => None,
        };
        let Some(event) = event else {
            thread::sleep(STOP_POLL_INTERVAL);
            continue;
        };

        if apply_worker_host_event(&mut state, event, &config, &policy_tables, &mut effects)
            .is_err()
        {
            let _ = report_status(status_handle, WindowsServiceHostStatus::Stopped, 1);
            return;
        }
        if state.service_host.phase() == WindowsServiceHostPhase::Stopped {
            return;
        }
    }
}

unsafe extern "system" fn service_control_handler(control: u32) {
    if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
        let _ = REQUESTED_CONTROL.compare_exchange(
            CONTROL_NONE,
            control,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

fn production_worker_config() -> WindowsDataPlaneConfig {
    WindowsDataPlaneConfig {
        max_active_sessions: WORKER_SESSION_LIMIT,
        max_retained_terminal_sessions: WORKER_SESSION_LIMIT,
        cancel_timeout_ms: WORKER_CANCEL_TIMEOUT_MILLIS,
        shutdown_timeout_ms: WORKER_SHUTDOWN_TIMEOUT_MILLIS,
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn apply_worker_host_event(
    state: &mut WindowsWorkerHostState,
    event: WindowsWorkerHostEvent,
    config: &WindowsDataPlaneConfig,
    policy_tables: &RoutingPolicyTables,
    effects: &mut NoNetworkWindowsWorkerHostEffects,
) -> Result<(), WindowsProductionWorkerHostError> {
    let transition = reduce_windows_worker_host(state, &event, config, policy_tables)
        .map_err(|error| WindowsProductionWorkerHostError::Contract(error.to_string()))?;
    execute_windows_worker_host_transition(&transition, effects)
        .map_err(|error| WindowsProductionWorkerHostError::Effect(error.to_string()))?;
    *state = transition.state;
    Ok(())
}

struct NoNetworkWindowsWorkerHostEffects {
    status_handle: SERVICE_STATUS_HANDLE,
}

impl NoNetworkWindowsWorkerHostEffects {
    const fn new(status_handle: SERVICE_STATUS_HANDLE) -> Self {
        Self { status_handle }
    }
}

impl WindowsWorkerHostEffects for NoNetworkWindowsWorkerHostEffects {
    type Error = WindowsProductionWorkerHostError;

    fn execute(&mut self, command: &WindowsWorkerHostCommand) -> Result<(), Self::Error> {
        match command {
            WindowsWorkerHostCommand::DataPlane {
                command:
                    WindowsDataPlaneCommand::ReportWorkerReady
                    | WindowsDataPlaneCommand::ReportWorkerStartupFailed { .. }
                    | WindowsDataPlaneCommand::ReportWorkerStopped,
            } => Ok(()),
            WindowsWorkerHostCommand::DataPlane { command } => {
                Err(WindowsProductionWorkerHostError::UnexpectedNoNetworkCommand(command.kind()))
            }
            WindowsWorkerHostCommand::ReportServiceStatus {
                status,
                win32_exit_code,
            } => {
                if report_status(self.status_handle, *status, *win32_exit_code) {
                    Ok(())
                } else {
                    Err(WindowsProductionWorkerHostError::StatusReportFailed(
                        unsafe { GetLastError() },
                    ))
                }
            }
        }
    }
}

#[derive(Debug)]
enum WindowsProductionWorkerHostError {
    Contract(String),
    Effect(String),
    UnexpectedNoNetworkCommand(&'static str),
    StatusReportFailed(u32),
}

impl fmt::Display for WindowsProductionWorkerHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(message) => write!(formatter, "worker-host contract failed: {message}"),
            Self::Effect(message) => write!(formatter, "worker-host effect failed: {message}"),
            Self::UnexpectedNoNetworkCommand(command) => {
                write!(formatter, "no-network worker rejected {command}")
            }
            Self::StatusReportFailed(code) => {
                write!(formatter, "SetServiceStatus failed with {code}")
            }
        }
    }
}

fn report_status(
    status_handle: SERVICE_STATUS_HANDLE,
    status: WindowsServiceHostStatus,
    win32_exit_code: u32,
) -> bool {
    let (current_state, controls_accepted, checkpoint, wait_hint) = match status {
        WindowsServiceHostStatus::StartPending => {
            (SERVICE_START_PENDING, 0, 1, STATUS_WAIT_HINT_MILLIS)
        }
        WindowsServiceHostStatus::Running => (
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            0,
            0,
        ),
        WindowsServiceHostStatus::StopPending => {
            (SERVICE_STOP_PENDING, 0, 1, STATUS_WAIT_HINT_MILLIS)
        }
        WindowsServiceHostStatus::Stopped => (SERVICE_STOPPED, 0, 0, 0),
    };
    let native_status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: current_state,
        dwControlsAccepted: controls_accepted,
        dwWin32ExitCode: win32_exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };
    unsafe { SetServiceStatus(status_handle, &native_status) != 0 }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Debug)]
pub enum WindowsServiceHostNativeError {
    CurrentExecutableUnavailable,
    SourceHashFailed,
    Controller(WindowsServiceControllerError),
    Contract(WindowsServiceHostContractError),
    Win32 { operation: &'static str, code: u32 },
}

impl WindowsServiceHostNativeError {
    pub const fn failure_code(&self) -> WindowsServiceHostFailureCode {
        match self {
            Self::CurrentExecutableUnavailable => {
                WindowsServiceHostFailureCode::CurrentExecutableUnavailable
            }
            Self::SourceHashFailed => WindowsServiceHostFailureCode::SourceHashFailed,
            Self::Controller(_) => WindowsServiceHostFailureCode::ControllerFailed,
            Self::Contract(_) => WindowsServiceHostFailureCode::ContractFailed,
            Self::Win32 { .. } => WindowsServiceHostFailureCode::ServiceDispatcherFailed,
        }
    }
}

impl fmt::Display for WindowsServiceHostNativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentExecutableUnavailable => {
                formatter.write_str("current Windows service executable is unavailable")
            }
            Self::SourceHashFailed => {
                formatter.write_str("current Windows service executable could not be hashed")
            }
            Self::Controller(error) => write!(formatter, "{error}"),
            Self::Contract(error) => write!(formatter, "{error}"),
            Self::Win32 { operation, code } => {
                write!(
                    formatter,
                    "Windows service host {operation} failed with {code}"
                )
            }
        }
    }
}

impl std::error::Error for WindowsServiceHostNativeError {}

impl From<WindowsServiceControllerError> for WindowsServiceHostNativeError {
    fn from(value: WindowsServiceControllerError) -> Self {
        Self::Controller(value)
    }
}

impl From<WindowsServiceHostContractError> for WindowsServiceHostNativeError {
    fn from(value: WindowsServiceHostContractError) -> Self {
        Self::Contract(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_host::WindowsServiceManagementCommandKind;
    use crate::service_lifecycle::{
        WindowsServiceDecision, WindowsServiceObservedState, WindowsServiceOwnership,
    };
    use crate::service_observer::{
        WindowsScmObserver, WindowsScmState, WindowsServiceObservation, WindowsServiceObserver,
    };
    use crate::service_ownership::windows::machine_owner_record_path;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Instant;

    const HOST_CI_ENV: &str = "SLIPSTREAM_WINDOWS_PRODUCTION_HOST_CI";
    const HOST_PATH_ENV: &str = "SLIPSTREAM_WINDOWS_PRODUCTION_HOST";
    const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(20);

    #[test]
    fn production_host_is_self_managing_idempotent_and_stops_through_scm() {
        if std::env::var_os(HOST_CI_ENV).is_none() {
            return;
        }

        assert_eq!(
            WindowsScmObserver::new().observe(),
            Ok(WindowsServiceObservation::absent()),
            "the disposable runner must not already contain the Slipstream service"
        );
        let host = PathBuf::from(
            std::env::var_os(HOST_PATH_ENV)
                .expect("the production Windows service host path must be provided"),
        );
        let owner_record_path = machine_owner_record_path().expect("resolve machine owner record");
        let root = owner_record_path
            .parent()
            .expect("owner record must have a parent");
        if root.exists() {
            fs::remove_dir_all(root).expect("remove stale disposable host state");
        }

        let installed = run_host(&host, &["manage", "install", "--generation", "23"]);
        assert_eq!(
            installed.command,
            WindowsServiceManagementCommandKind::Install
        );
        assert_eq!(
            installed.lifecycle.decision,
            WindowsServiceDecision::Installed
        );
        assert!(installed.lifecycle.accepted);
        let first_pid = wait_for_state(WindowsScmState::Running)
            .process_id
            .expect("installed production host must have a process ID");

        let repeated_install = run_host(&host, &["manage", "install", "--generation", "23"]);
        assert_eq!(
            repeated_install.lifecycle.decision,
            WindowsServiceDecision::NoChange
        );
        assert!(repeated_install.lifecycle.accepted);
        assert_eq!(
            wait_for_state(WindowsScmState::Running).process_id,
            Some(first_pid),
            "idempotent install must not restart the production host"
        );

        let stopped = run_host(&host, &["manage", "stop"]);
        assert_eq!(stopped.lifecycle.decision, WindowsServiceDecision::Stopped);
        assert!(stopped.lifecycle.accepted);
        assert_eq!(
            stopped.lifecycle.state.observed,
            WindowsServiceObservedState::Stopped
        );
        wait_for_state(WindowsScmState::Stopped);

        let repeated_stop = run_host(&host, &["manage", "stop"]);
        assert_eq!(
            repeated_stop.lifecycle.decision,
            WindowsServiceDecision::NoChange
        );
        assert!(repeated_stop.lifecycle.accepted);

        let started = run_host(&host, &["manage", "start"]);
        assert_eq!(started.lifecycle.decision, WindowsServiceDecision::Started);
        assert!(started.lifecycle.accepted);
        let second_pid = wait_for_state(WindowsScmState::Running)
            .process_id
            .expect("restarted production host must have a process ID");
        assert_ne!(second_pid, first_pid);

        let repeated_start = run_host(&host, &["manage", "start"]);
        assert_eq!(
            repeated_start.lifecycle.decision,
            WindowsServiceDecision::NoChange
        );
        assert!(repeated_start.lifecycle.accepted);

        let uninstalled = run_host(&host, &["manage", "uninstall"]);
        assert_eq!(
            uninstalled.lifecycle.decision,
            WindowsServiceDecision::Uninstalled
        );
        assert!(uninstalled.lifecycle.accepted);
        assert_eq!(
            uninstalled.lifecycle.state.ownership,
            WindowsServiceOwnership::Absent
        );
        assert_eq!(
            WindowsScmObserver::new().observe(),
            Ok(WindowsServiceObservation::absent())
        );

        let repeated_uninstall = run_host(&host, &["manage", "uninstall"]);
        assert_eq!(
            repeated_uninstall.lifecycle.decision,
            WindowsServiceDecision::NoChange
        );
        assert!(repeated_uninstall.lifecycle.accepted);
        fs::remove_dir_all(root).expect("remove disposable terminal intent");
    }

    fn run_host(host: &Path, arguments: &[&str]) -> WindowsServiceManagementResultV1 {
        let output = Command::new(host)
            .args(arguments)
            .output()
            .expect("start production Windows service host manager");
        assert!(
            output.status.success(),
            "production host command {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: WindowsServiceManagementResultV1 =
            serde_json::from_slice(&output.stdout).expect("host output must be result JSON");
        result.validate().expect("host result must satisfy v1");
        result
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
                Err(error) => panic!("observe production Windows service host: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "production host did not reach {expected:?} before the deadline"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

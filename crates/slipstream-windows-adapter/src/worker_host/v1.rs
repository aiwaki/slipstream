//! Version 1 composition of the Windows SCM host and no-network worker contract.
//!
//! This module owns no native or network API. It orders the already-frozen
//! service-host and data-plane reducers so SCM readiness follows worker
//! readiness and SCM shutdown remains pending until bounded worker drain ends.

use crate::data_plane::{
    reduce_windows_data_plane, RecordingWindowsDataPlaneEffects, WindowsDataPlaneCommand,
    WindowsDataPlaneConfig, WindowsDataPlaneEffectError, WindowsDataPlaneEffects,
    WindowsDataPlaneError, WindowsDataPlaneEvent, WindowsDataPlaneState,
    WindowsDataPlaneWorkerPhase,
};
use crate::service_host::{
    WindowsServiceHostContractError, WindowsServiceHostEvent, WindowsServiceHostPhase,
    WindowsServiceHostRuntimeV1, WindowsServiceHostStatus,
};
use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::RoutingPolicyTables;
use std::collections::BTreeMap;
use std::fmt;

pub const WINDOWS_WORKER_HOST_CONTRACT_VERSION: u32 = 1;
pub const WINDOWS_WORKER_STARTUP_FAILURE_EXIT_CODE: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWorkerHostState {
    pub service_host: WindowsServiceHostRuntimeV1,
    pub data_plane: WindowsDataPlaneState,
}

impl WindowsWorkerHostState {
    pub fn new(started_at_ms: u64) -> Self {
        Self {
            service_host: WindowsServiceHostRuntimeV1::new(),
            data_plane: WindowsDataPlaneState::new(started_at_ms),
        }
    }

    pub const fn initial_service_status(&self) -> WindowsServiceHostStatus {
        self.service_host.initial_status()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsWorkerHostEvent {
    Worker { event: WindowsDataPlaneEvent },
    StopRequested { now_ms: u64 },
    ShutdownRequested { now_ms: u64 },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsWorkerHostCommand {
    DataPlane {
        command: WindowsDataPlaneCommand,
    },
    ReportServiceStatus {
        status: WindowsServiceHostStatus,
        win32_exit_code: u32,
    },
}

impl WindowsWorkerHostCommand {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::DataPlane { command } => command.kind(),
            Self::ReportServiceStatus {
                status: WindowsServiceHostStatus::StartPending,
                ..
            } => "report_service_start_pending",
            Self::ReportServiceStatus {
                status: WindowsServiceHostStatus::Running,
                ..
            } => "report_service_running",
            Self::ReportServiceStatus {
                status: WindowsServiceHostStatus::StopPending,
                ..
            } => "report_service_stop_pending",
            Self::ReportServiceStatus {
                status: WindowsServiceHostStatus::Stopped,
                ..
            } => "report_service_stopped",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WindowsWorkerHostTransition {
    pub state: WindowsWorkerHostState,
    pub commands: Vec<WindowsWorkerHostCommand>,
}

pub fn reduce_windows_worker_host(
    state: &WindowsWorkerHostState,
    event: &WindowsWorkerHostEvent,
    config: &WindowsDataPlaneConfig,
    policy_tables: &RoutingPolicyTables,
) -> Result<WindowsWorkerHostTransition, WindowsWorkerHostError> {
    validate_worker_host_state(state)?;
    let mut next = state.clone();
    let mut commands = Vec::new();

    match event {
        WindowsWorkerHostEvent::Worker { event } => {
            if matches!(event, WindowsDataPlaneEvent::ShutdownRequested { .. }) {
                return Err(WindowsWorkerHostError::HostOwnedShutdownRequired);
            }
            append_worker_transition(&mut next, event, config, policy_tables, &mut commands)?;
        }
        WindowsWorkerHostEvent::StopRequested { now_ms } => append_shutdown_transition(
            &mut next,
            WindowsServiceHostEvent::StopRequested,
            *now_ms,
            config,
            policy_tables,
            &mut commands,
        )?,
        WindowsWorkerHostEvent::ShutdownRequested { now_ms } => append_shutdown_transition(
            &mut next,
            WindowsServiceHostEvent::ShutdownRequested,
            *now_ms,
            config,
            policy_tables,
            &mut commands,
        )?,
    }

    validate_worker_host_state(&next)?;
    Ok(WindowsWorkerHostTransition {
        state: next,
        commands,
    })
}

fn validate_worker_host_state(
    state: &WindowsWorkerHostState,
) -> Result<(), WindowsWorkerHostError> {
    let valid = matches!(
        (state.service_host.phase(), state.data_plane.worker_phase,),
        (
            WindowsServiceHostPhase::StartPending,
            WindowsDataPlaneWorkerPhase::Starting
        ) | (
            WindowsServiceHostPhase::Running,
            WindowsDataPlaneWorkerPhase::Ready
        ) | (
            WindowsServiceHostPhase::StopPending,
            WindowsDataPlaneWorkerPhase::Draining
        ) | (
            WindowsServiceHostPhase::Stopped,
            WindowsDataPlaneWorkerPhase::Stopped | WindowsDataPlaneWorkerPhase::Failed
        )
    );
    if valid {
        Ok(())
    } else {
        Err(WindowsWorkerHostError::InvalidCompositionState {
            service_phase: state.service_host.phase(),
            worker_phase: state.data_plane.worker_phase,
        })
    }
}

fn append_shutdown_transition(
    state: &mut WindowsWorkerHostState,
    host_event: WindowsServiceHostEvent,
    now_ms: u64,
    config: &WindowsDataPlaneConfig,
    policy_tables: &RoutingPolicyTables,
    commands: &mut Vec<WindowsWorkerHostCommand>,
) -> Result<(), WindowsWorkerHostError> {
    let host_transition = state.service_host.transition(host_event)?;
    append_service_report(commands, host_transition.report, 0);
    if host_transition.request_worker_stop {
        append_worker_transition(
            state,
            &WindowsDataPlaneEvent::ShutdownRequested { now_ms },
            config,
            policy_tables,
            commands,
        )?;
    }
    Ok(())
}

fn append_worker_transition(
    state: &mut WindowsWorkerHostState,
    event: &WindowsDataPlaneEvent,
    config: &WindowsDataPlaneConfig,
    policy_tables: &RoutingPolicyTables,
    commands: &mut Vec<WindowsWorkerHostCommand>,
) -> Result<(), WindowsWorkerHostError> {
    let previous_phase = state.data_plane.worker_phase;
    let worker_transition =
        reduce_windows_data_plane(&state.data_plane, event, config, policy_tables)?;
    let next_phase = worker_transition.state.worker_phase;
    commands.extend(
        worker_transition
            .commands
            .into_iter()
            .map(|command| WindowsWorkerHostCommand::DataPlane { command }),
    );
    state.data_plane = worker_transition.state;

    match (previous_phase, next_phase) {
        (WindowsDataPlaneWorkerPhase::Starting, WindowsDataPlaneWorkerPhase::Ready) => {
            let host_transition = state
                .service_host
                .transition(WindowsServiceHostEvent::Ready)?;
            append_service_report(commands, host_transition.report, 0);
        }
        (WindowsDataPlaneWorkerPhase::Starting, WindowsDataPlaneWorkerPhase::Failed) => {
            let host_transition = state
                .service_host
                .transition(WindowsServiceHostEvent::StartupFailed)?;
            append_service_report(
                commands,
                host_transition.report,
                WINDOWS_WORKER_STARTUP_FAILURE_EXIT_CODE,
            );
        }
        (_, WindowsDataPlaneWorkerPhase::Stopped)
            if previous_phase != WindowsDataPlaneWorkerPhase::Stopped =>
        {
            let host_transition = state
                .service_host
                .transition(WindowsServiceHostEvent::WorkerStopped)?;
            append_service_report(commands, host_transition.report, 0);
        }
        _ => {}
    }
    Ok(())
}

fn append_service_report(
    commands: &mut Vec<WindowsWorkerHostCommand>,
    report: Option<WindowsServiceHostStatus>,
    win32_exit_code: u32,
) {
    if let Some(status) = report {
        commands.push(WindowsWorkerHostCommand::ReportServiceStatus {
            status,
            win32_exit_code,
        });
    }
}

pub trait WindowsWorkerHostEffects {
    type Error: fmt::Display;

    /// Executes one command atomically. Earlier commands in the same batch may
    /// already be committed and are resumed through the returned cursor.
    fn execute(&mut self, command: &WindowsWorkerHostCommand) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default)]
pub struct RecordingWindowsWorkerHostEffects {
    commands: Vec<WindowsWorkerHostCommand>,
    data_plane: RecordingWindowsDataPlaneEffects,
    service_reports: Vec<(WindowsServiceHostStatus, u32)>,
    fail_once: BTreeMap<String, String>,
}

impl RecordingWindowsWorkerHostEffects {
    pub fn commands(&self) -> &[WindowsWorkerHostCommand] {
        &self.commands
    }

    pub fn data_plane(&self) -> &RecordingWindowsDataPlaneEffects {
        &self.data_plane
    }

    pub fn service_reports(&self) -> &[(WindowsServiceHostStatus, u32)] {
        &self.service_reports
    }

    pub fn fail_once(&mut self, command: &str, message: impl Into<String>) {
        self.fail_once.insert(command.to_owned(), message.into());
    }
}

impl WindowsWorkerHostEffects for RecordingWindowsWorkerHostEffects {
    type Error = WindowsWorkerHostEffectError;

    fn execute(&mut self, command: &WindowsWorkerHostCommand) -> Result<(), Self::Error> {
        if let Some(message) = self.fail_once.remove(command.kind()) {
            return Err(WindowsWorkerHostEffectError::InjectedFailure {
                command: command.kind().to_owned(),
                message,
            });
        }
        match command {
            WindowsWorkerHostCommand::DataPlane { command } => {
                self.data_plane
                    .execute(command)
                    .map_err(WindowsWorkerHostEffectError::DataPlane)?;
            }
            WindowsWorkerHostCommand::ReportServiceStatus {
                status,
                win32_exit_code,
            } => self.service_reports.push((*status, *win32_exit_code)),
        }
        self.commands.push(command.clone());
        Ok(())
    }
}

pub fn execute_windows_worker_host_transition<E: WindowsWorkerHostEffects>(
    transition: &WindowsWorkerHostTransition,
    effects: &mut E,
) -> Result<(), WindowsWorkerHostEffectExecutionError> {
    execute_windows_worker_host_transition_from(transition, effects, 0)
}

/// Resumes the exact same transition without replaying its completed prefix.
pub fn execute_windows_worker_host_transition_from<E: WindowsWorkerHostEffects>(
    transition: &WindowsWorkerHostTransition,
    effects: &mut E,
    next_command_index: usize,
) -> Result<(), WindowsWorkerHostEffectExecutionError> {
    if next_command_index > transition.commands.len() {
        return Err(WindowsWorkerHostEffectExecutionError {
            command: "transition_cursor",
            message: format!(
                "command cursor {next_command_index} exceeds batch length {}",
                transition.commands.len()
            ),
            failed_command_index: next_command_index,
            next_command_index,
            completed_commands: 0,
        });
    }

    for (command_index, command) in transition
        .commands
        .iter()
        .enumerate()
        .skip(next_command_index)
    {
        effects
            .execute(command)
            .map_err(|error| WindowsWorkerHostEffectExecutionError {
                command: command.kind(),
                message: error.to_string(),
                failed_command_index: command_index,
                next_command_index: command_index,
                completed_commands: command_index,
            })?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsWorkerHostEffectError {
    InjectedFailure { command: String, message: String },
    DataPlane(WindowsDataPlaneEffectError),
}

impl fmt::Display for WindowsWorkerHostEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InjectedFailure { command, message } => {
                write!(formatter, "injected {command} failure: {message}")
            }
            Self::DataPlane(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WindowsWorkerHostEffectError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWorkerHostEffectExecutionError {
    pub command: &'static str,
    pub message: String,
    pub failed_command_index: usize,
    pub next_command_index: usize,
    pub completed_commands: usize,
}

impl fmt::Display for WindowsWorkerHostEffectExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} effect at command {} failed after {} completed command(s): {}",
            self.command, self.failed_command_index, self.completed_commands, self.message
        )
    }
}

impl std::error::Error for WindowsWorkerHostEffectExecutionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsWorkerHostError {
    HostOwnedShutdownRequired,
    InvalidCompositionState {
        service_phase: WindowsServiceHostPhase,
        worker_phase: WindowsDataPlaneWorkerPhase,
    },
    DataPlane(WindowsDataPlaneError),
    ServiceHost(WindowsServiceHostContractError),
}

impl fmt::Display for WindowsWorkerHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostOwnedShutdownRequired => {
                formatter.write_str("worker shutdown must be initiated by the service host")
            }
            Self::InvalidCompositionState {
                service_phase,
                worker_phase,
            } => write!(
                formatter,
                "invalid worker-host composition state {service_phase:?}/{worker_phase:?}"
            ),
            Self::DataPlane(error) => write!(formatter, "{error}"),
            Self::ServiceHost(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WindowsWorkerHostError {}

impl From<WindowsDataPlaneError> for WindowsWorkerHostError {
    fn from(value: WindowsDataPlaneError) -> Self {
        Self::DataPlane(value)
    }
}

impl From<WindowsServiceHostContractError> for WindowsWorkerHostError {
    fn from(value: WindowsServiceHostContractError) -> Self {
        Self::ServiceHost(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_host::WindowsServiceHostPhase;
    use slipstream_core::routing_policy::bundled_policy_v1;

    fn config() -> WindowsDataPlaneConfig {
        WindowsDataPlaneConfig {
            max_active_sessions: 16,
            max_retained_terminal_sessions: 16,
            cancel_timeout_ms: 50,
            shutdown_timeout_ms: 100,
        }
    }

    #[test]
    fn worker_cannot_bypass_host_owned_shutdown() {
        let state = WindowsWorkerHostState::new(0);
        let error = reduce_windows_worker_host(
            &state,
            &WindowsWorkerHostEvent::Worker {
                event: WindowsDataPlaneEvent::ShutdownRequested { now_ms: 1 },
            },
            &config(),
            &bundled_policy_v1(),
        )
        .expect_err("worker-owned shutdown must be rejected");
        assert_eq!(error, WindowsWorkerHostError::HostOwnedShutdownRequired);
        assert_eq!(
            state.service_host.phase(),
            WindowsServiceHostPhase::StartPending
        );
        assert_eq!(
            state.data_plane.worker_phase,
            WindowsDataPlaneWorkerPhase::Starting
        );
    }

    #[test]
    fn effect_resume_cursor_must_not_exceed_the_batch() {
        let transition = WindowsWorkerHostTransition {
            state: WindowsWorkerHostState::new(0),
            commands: vec![WindowsWorkerHostCommand::ReportServiceStatus {
                status: WindowsServiceHostStatus::Running,
                win32_exit_code: 0,
            }],
        };
        let mut effects = RecordingWindowsWorkerHostEffects::default();
        let error = execute_windows_worker_host_transition_from(&transition, &mut effects, 2)
            .expect_err("out-of-range cursor must fail");
        assert_eq!(error.command, "transition_cursor");
        assert!(effects.commands().is_empty());
    }

    #[test]
    fn inconsistent_service_and_worker_phases_are_rejected() {
        let mut state = WindowsWorkerHostState::new(0);
        state.data_plane.worker_phase = WindowsDataPlaneWorkerPhase::Ready;
        let error = reduce_windows_worker_host(
            &state,
            &WindowsWorkerHostEvent::StopRequested { now_ms: 1 },
            &config(),
            &bundled_policy_v1(),
        )
        .expect_err("inconsistent composition must fail closed");
        assert_eq!(
            error,
            WindowsWorkerHostError::InvalidCompositionState {
                service_phase: WindowsServiceHostPhase::StartPending,
                worker_phase: WindowsDataPlaneWorkerPhase::Ready,
            }
        );
    }
}

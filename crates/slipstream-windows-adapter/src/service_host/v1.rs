//! Pure version 1 command, result, and shutdown contracts for the Windows host.

use crate::service_lifecycle::{WindowsServiceLifecycleResult, WINDOWS_SERVICE_NAME};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const WINDOWS_SERVICE_HOST_CONTRACT_VERSION: u32 = 1;
pub const WINDOWS_SERVICE_HOST_RESULT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsServiceHostInvocation {
    Service,
    Manage {
        command: WindowsServiceManagementCommand,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsServiceManagementCommand {
    Install { generation: u64 },
    Start,
    Stop,
    Recover,
    Uninstall,
}

impl WindowsServiceManagementCommand {
    pub const fn kind(&self) -> WindowsServiceManagementCommandKind {
        match self {
            Self::Install { .. } => WindowsServiceManagementCommandKind::Install,
            Self::Start => WindowsServiceManagementCommandKind::Start,
            Self::Stop => WindowsServiceManagementCommandKind::Stop,
            Self::Recover => WindowsServiceManagementCommandKind::Recover,
            Self::Uninstall => WindowsServiceManagementCommandKind::Uninstall,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceManagementCommandKind {
    Install,
    Start,
    Stop,
    Recover,
    Uninstall,
}

pub fn parse_windows_service_host_arguments(
    arguments: &[String],
) -> Result<WindowsServiceHostInvocation, WindowsServiceHostArgumentError> {
    let Some(mode) = arguments.first() else {
        return Err(WindowsServiceHostArgumentError::new(
            WindowsServiceHostArgumentErrorCode::MissingMode,
            "missing Windows service host mode",
        ));
    };

    match mode.as_str() {
        "--service" => {
            if arguments.len() != 1 {
                return Err(unexpected_argument());
            }
            Ok(WindowsServiceHostInvocation::Service)
        }
        "manage" => parse_management_arguments(&arguments[1..])
            .map(|command| WindowsServiceHostInvocation::Manage { command }),
        _ => Err(WindowsServiceHostArgumentError::new(
            WindowsServiceHostArgumentErrorCode::UnknownMode,
            "unknown Windows service host mode",
        )),
    }
}

fn parse_management_arguments(
    arguments: &[String],
) -> Result<WindowsServiceManagementCommand, WindowsServiceHostArgumentError> {
    let Some(command) = arguments.first() else {
        return Err(WindowsServiceHostArgumentError::new(
            WindowsServiceHostArgumentErrorCode::MissingCommand,
            "missing Windows service management command",
        ));
    };

    match command.as_str() {
        "install" => parse_install_arguments(&arguments[1..]),
        "start" => exact_no_argument_command(arguments, WindowsServiceManagementCommand::Start),
        "stop" => exact_no_argument_command(arguments, WindowsServiceManagementCommand::Stop),
        "recover" => exact_no_argument_command(arguments, WindowsServiceManagementCommand::Recover),
        "uninstall" => {
            exact_no_argument_command(arguments, WindowsServiceManagementCommand::Uninstall)
        }
        _ => Err(WindowsServiceHostArgumentError::new(
            WindowsServiceHostArgumentErrorCode::UnknownCommand,
            "unknown Windows service management command",
        )),
    }
}

fn exact_no_argument_command(
    arguments: &[String],
    command: WindowsServiceManagementCommand,
) -> Result<WindowsServiceManagementCommand, WindowsServiceHostArgumentError> {
    if arguments.len() != 1 {
        return Err(unexpected_argument());
    }
    Ok(command)
}

fn parse_install_arguments(
    arguments: &[String],
) -> Result<WindowsServiceManagementCommand, WindowsServiceHostArgumentError> {
    if arguments.len() < 2 {
        return Err(WindowsServiceHostArgumentError::new(
            WindowsServiceHostArgumentErrorCode::MissingGeneration,
            "install requires --generation and a positive integer",
        ));
    }
    if arguments.len() != 2 || arguments[0] != "--generation" {
        return Err(unexpected_argument());
    }
    let generation = arguments[1].parse::<u64>().map_err(|_| {
        WindowsServiceHostArgumentError::new(
            WindowsServiceHostArgumentErrorCode::InvalidGeneration,
            "install generation must be a positive integer",
        )
    })?;
    if generation == 0 {
        return Err(WindowsServiceHostArgumentError::new(
            WindowsServiceHostArgumentErrorCode::InvalidGeneration,
            "install generation must be a positive integer",
        ));
    }
    Ok(WindowsServiceManagementCommand::Install { generation })
}

fn unexpected_argument() -> WindowsServiceHostArgumentError {
    WindowsServiceHostArgumentError::new(
        WindowsServiceHostArgumentErrorCode::UnexpectedArgument,
        "unexpected Windows service host argument",
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceHostArgumentErrorCode {
    MissingMode,
    UnknownMode,
    MissingCommand,
    UnknownCommand,
    MissingGeneration,
    InvalidGeneration,
    UnexpectedArgument,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsServiceHostArgumentError {
    pub code: WindowsServiceHostArgumentErrorCode,
    message: &'static str,
}

impl WindowsServiceHostArgumentError {
    const fn new(code: WindowsServiceHostArgumentErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl fmt::Display for WindowsServiceHostArgumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for WindowsServiceHostArgumentError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceManagementResultV1 {
    pub schema_version: u32,
    pub service_name: String,
    pub command: WindowsServiceManagementCommandKind,
    pub lifecycle: WindowsServiceLifecycleResult,
}

impl WindowsServiceManagementResultV1 {
    pub fn new(
        command: WindowsServiceManagementCommandKind,
        lifecycle: WindowsServiceLifecycleResult,
    ) -> Self {
        Self {
            schema_version: WINDOWS_SERVICE_HOST_RESULT_SCHEMA_VERSION,
            service_name: WINDOWS_SERVICE_NAME.to_owned(),
            command,
            lifecycle,
        }
    }

    pub fn validate(&self) -> Result<(), WindowsServiceHostContractError> {
        if self.schema_version != WINDOWS_SERVICE_HOST_RESULT_SCHEMA_VERSION {
            return Err(WindowsServiceHostContractError::InvalidResult(
                "schema_version",
            ));
        }
        if self.service_name != WINDOWS_SERVICE_NAME {
            return Err(WindowsServiceHostContractError::InvalidResult(
                "service_name",
            ));
        }
        self.lifecycle
            .state
            .validate()
            .map_err(|_| WindowsServiceHostContractError::InvalidResult("lifecycle.state"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceHostFailureCode {
    InvalidArguments,
    UnsupportedPlatform,
    CurrentExecutableUnavailable,
    SourceHashFailed,
    ControllerFailed,
    ContractFailed,
    ServiceDispatcherFailed,
    OutputFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceHostFailureV1 {
    pub schema_version: u32,
    pub service_name: String,
    pub code: WindowsServiceHostFailureCode,
    pub message: String,
}

impl WindowsServiceHostFailureV1 {
    pub fn new(code: WindowsServiceHostFailureCode, message: impl Into<String>) -> Self {
        Self {
            schema_version: WINDOWS_SERVICE_HOST_RESULT_SCHEMA_VERSION,
            service_name: WINDOWS_SERVICE_NAME.to_owned(),
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceHostPhase {
    StartPending,
    Running,
    StopPending,
    Stopped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceHostEvent {
    Ready,
    StopRequested,
    ShutdownRequested,
    WorkerStopped,
    StartupFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceHostStatus {
    StartPending,
    Running,
    StopPending,
    Stopped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceHostTransition {
    pub phase: WindowsServiceHostPhase,
    pub report: Option<WindowsServiceHostStatus>,
    pub request_worker_stop: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsServiceHostRuntimeV1 {
    phase: WindowsServiceHostPhase,
}

impl WindowsServiceHostRuntimeV1 {
    pub const fn new() -> Self {
        Self {
            phase: WindowsServiceHostPhase::StartPending,
        }
    }

    pub const fn phase(&self) -> WindowsServiceHostPhase {
        self.phase
    }

    pub const fn initial_status(&self) -> WindowsServiceHostStatus {
        WindowsServiceHostStatus::StartPending
    }

    pub fn transition(
        &mut self,
        event: WindowsServiceHostEvent,
    ) -> Result<WindowsServiceHostTransition, WindowsServiceHostContractError> {
        let (phase, report, request_worker_stop) = match (self.phase, event) {
            (WindowsServiceHostPhase::StartPending, WindowsServiceHostEvent::Ready) => (
                WindowsServiceHostPhase::Running,
                Some(WindowsServiceHostStatus::Running),
                false,
            ),
            (
                WindowsServiceHostPhase::StartPending | WindowsServiceHostPhase::Running,
                WindowsServiceHostEvent::StopRequested | WindowsServiceHostEvent::ShutdownRequested,
            ) => (
                WindowsServiceHostPhase::StopPending,
                Some(WindowsServiceHostStatus::StopPending),
                true,
            ),
            (
                WindowsServiceHostPhase::StopPending,
                WindowsServiceHostEvent::StopRequested | WindowsServiceHostEvent::ShutdownRequested,
            )
            | (
                WindowsServiceHostPhase::Stopped,
                WindowsServiceHostEvent::StopRequested | WindowsServiceHostEvent::ShutdownRequested,
            ) => (self.phase, None, false),
            (WindowsServiceHostPhase::StopPending, WindowsServiceHostEvent::WorkerStopped) => (
                WindowsServiceHostPhase::Stopped,
                Some(WindowsServiceHostStatus::Stopped),
                false,
            ),
            (WindowsServiceHostPhase::StartPending, WindowsServiceHostEvent::StartupFailed) => (
                WindowsServiceHostPhase::Stopped,
                Some(WindowsServiceHostStatus::Stopped),
                false,
            ),
            _ => {
                return Err(WindowsServiceHostContractError::InvalidTransition {
                    phase: self.phase,
                    event,
                })
            }
        };
        self.phase = phase;
        Ok(WindowsServiceHostTransition {
            phase,
            report,
            request_worker_stop,
        })
    }
}

impl Default for WindowsServiceHostRuntimeV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsServiceHostContractError {
    InvalidResult(&'static str),
    InvalidTransition {
        phase: WindowsServiceHostPhase,
        event: WindowsServiceHostEvent,
    },
}

impl fmt::Display for WindowsServiceHostContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidResult(field) => {
                write!(
                    formatter,
                    "invalid Windows service host result field {field}"
                )
            }
            Self::InvalidTransition { phase, event } => write!(
                formatter,
                "invalid Windows service host transition from {phase:?} with {event:?}"
            ),
        }
    }
}

impl std::error::Error for WindowsServiceHostContractError {}

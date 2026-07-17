//! Platform-neutral model for the version 1 SCM observer.

use crate::service_lifecycle::{WindowsServiceObservedState, WINDOWS_SERVICE_NAME};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const WINDOWS_SERVICE_OBSERVER_CONTRACT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsScmState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown(u32),
}

impl WindowsScmState {
    pub const fn observed(self) -> WindowsServiceObservedState {
        match self {
            Self::Stopped => WindowsServiceObservedState::Stopped,
            Self::Running => WindowsServiceObservedState::Running,
            Self::StartPending
            | Self::StopPending
            | Self::ContinuePending
            | Self::PausePending
            | Self::Paused
            | Self::Unknown(_) => WindowsServiceObservedState::Unknown,
        }
    }

    pub const fn has_ready_process_id(self) -> bool {
        matches!(self, Self::Running)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceSnapshot {
    pub service_name: String,
    pub binary_path: String,
    pub scm_state: WindowsScmState,
    pub observed: WindowsServiceObservedState,
    pub process_id: Option<u32>,
}

impl WindowsServiceSnapshot {
    pub fn from_scm(binary_path: String, scm_state: WindowsScmState, raw_process_id: u32) -> Self {
        Self {
            service_name: WINDOWS_SERVICE_NAME.to_owned(),
            binary_path,
            scm_state,
            observed: scm_state.observed(),
            process_id: (scm_state.has_ready_process_id() && raw_process_id > 0)
                .then_some(raw_process_id),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "presence", rename_all = "snake_case")]
pub enum WindowsServiceObservation {
    Absent { service_name: String },
    Present { snapshot: WindowsServiceSnapshot },
}

impl WindowsServiceObservation {
    pub fn absent() -> Self {
        Self::Absent {
            service_name: WINDOWS_SERVICE_NAME.to_owned(),
        }
    }
}

pub trait WindowsServiceObserver {
    fn observe(&self) -> Result<WindowsServiceObservation, WindowsServiceObserverError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsServiceObserverError {
    Win32 {
        operation: &'static str,
        code: u32,
    },
    InvalidData {
        field: &'static str,
        detail: &'static str,
    },
}

impl fmt::Display for WindowsServiceObserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Win32 { operation, code } => {
                write!(formatter, "{operation} failed with Win32 error {code}")
            }
            Self::InvalidData { field, detail } => {
                write!(formatter, "invalid SCM {field}: {detail}")
            }
        }
    }
}

impl std::error::Error for WindowsServiceObserverError {}

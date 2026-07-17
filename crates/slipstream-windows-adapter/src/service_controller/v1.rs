//! Pure version 1 reconciliation for the Windows service controller.

use crate::service_lifecycle::{
    WindowsServiceDesiredState, WindowsServiceObservedState, WindowsServiceOwnership,
    WindowsServiceState,
};
use crate::service_lifecycle_state::WindowsServiceLifecycleStateAssessment;
use crate::service_ownership::WindowsServiceOwnershipAssessment;
use std::fmt;

pub const WINDOWS_SERVICE_CONTROLLER_CONTRACT_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsServiceControllerEvidence {
    pub lifecycle: WindowsServiceLifecycleStateAssessment,
    pub ownership: WindowsServiceOwnershipAssessment,
}

impl WindowsServiceControllerEvidence {
    pub fn reconstruct(&self) -> Result<WindowsServiceState, WindowsServiceReconciliationError> {
        reconstruct_windows_service_state(&self.lifecycle, &self.ownership)
    }
}

pub fn reconstruct_windows_service_state(
    lifecycle: &WindowsServiceLifecycleStateAssessment,
    ownership: &WindowsServiceOwnershipAssessment,
) -> Result<WindowsServiceState, WindowsServiceReconciliationError> {
    let (intent, active_install) = match lifecycle {
        WindowsServiceLifecycleStateAssessment::Stable {
            intent,
            active_install,
        } => (intent.as_ref(), active_install.as_ref()),
        WindowsServiceLifecycleStateAssessment::InterruptedWrite => {
            return Err(WindowsServiceReconciliationError::InterruptedWrite)
        }
        WindowsServiceLifecycleStateAssessment::Unknown => {
            return Err(WindowsServiceReconciliationError::UnknownLifecycleState)
        }
        WindowsServiceLifecycleStateAssessment::Inconsistent => {
            return Err(WindowsServiceReconciliationError::InconsistentLifecycleState)
        }
    };

    if let Some(intent) = intent {
        intent
            .validate()
            .map_err(|_| WindowsServiceReconciliationError::InvalidDurableRecord("intent"))?;
    }
    if let Some(active_install) = active_install {
        active_install.validate().map_err(|_| {
            WindowsServiceReconciliationError::InvalidDurableRecord("active install")
        })?;
    }

    if let Some(active_install) = active_install {
        let intent = intent.ok_or(WindowsServiceReconciliationError::CrossEvidence(
            "active install exists without durable intent",
        ))?;
        if intent.identity.as_ref() != Some(&active_install.identity) {
            return Err(WindowsServiceReconciliationError::CrossEvidence(
                "durable intent and active install identify different services",
            ));
        }
        if ownership.ownership != WindowsServiceOwnership::Owned
            || ownership.identity.as_ref() != Some(&active_install.identity)
        {
            return Err(WindowsServiceReconciliationError::CrossEvidence(
                "committed install lacks exact live ownership evidence",
            ));
        }

        let state = ownership.lifecycle_state(intent.desired, intent.crash_restart_attempts);
        state.validate().map_err(|_| {
            WindowsServiceReconciliationError::CrossEvidence(
                "reconstructed owned service state violates the lifecycle contract",
            )
        })?;
        return Ok(state);
    }

    match ownership.ownership {
        WindowsServiceOwnership::Absent => {
            if ownership.observed != WindowsServiceObservedState::Absent
                || ownership.identity.is_some()
            {
                return Err(WindowsServiceReconciliationError::CrossEvidence(
                    "absent ownership evidence is internally inconsistent",
                ));
            }
            if let Some(intent) = intent {
                if intent.desired != WindowsServiceDesiredState::Absent
                    || intent.crash_restart_attempts != 0
                {
                    return Err(WindowsServiceReconciliationError::CrossEvidence(
                        "absent service conflicts with actionable durable intent",
                    ));
                }
            }
            Ok(WindowsServiceState::absent())
        }
        WindowsServiceOwnership::Owned => Err(WindowsServiceReconciliationError::CrossEvidence(
            "owned service exists without a committed active install",
        )),
        WindowsServiceOwnership::Foreign | WindowsServiceOwnership::Unknown => {
            if ownership.identity.is_some() {
                return Err(WindowsServiceReconciliationError::CrossEvidence(
                    "unowned evidence carries an owned service identity",
                ));
            }
            let state = WindowsServiceState {
                desired: WindowsServiceDesiredState::Unknown,
                observed: ownership.observed,
                ownership: ownership.ownership,
                active: None,
                crash_restart_attempts: 0,
            };
            state.validate().map_err(|_| {
                WindowsServiceReconciliationError::CrossEvidence(
                    "neutralized unowned service state violates the lifecycle contract",
                )
            })?;
            Ok(state)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsServiceReconciliationError {
    InterruptedWrite,
    UnknownLifecycleState,
    InconsistentLifecycleState,
    InvalidDurableRecord(&'static str),
    CrossEvidence(&'static str),
}

impl fmt::Display for WindowsServiceReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterruptedWrite => formatter.write_str(
                "Windows service reconciliation blocked by an interrupted durable write",
            ),
            Self::UnknownLifecycleState => formatter.write_str(
                "Windows service reconciliation blocked by inaccessible or invalid durable state",
            ),
            Self::InconsistentLifecycleState => formatter
                .write_str("Windows service reconciliation blocked by inconsistent durable state"),
            Self::InvalidDurableRecord(record) => {
                write!(
                    formatter,
                    "Windows service reconciliation rejected {record}"
                )
            }
            Self::CrossEvidence(detail) => {
                write!(formatter, "Windows service reconciliation failed: {detail}")
            }
        }
    }
}

impl std::error::Error for WindowsServiceReconciliationError {}

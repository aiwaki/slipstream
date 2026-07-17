//! Pure version 1 authorization gate for Windows SCM mutations.

use crate::service_lifecycle::{
    WindowsServiceAction, WindowsServiceDesiredState, WindowsServiceIdentity,
    WindowsServiceObservedState, WindowsServiceOwnership,
};
use crate::service_lifecycle_state::{
    WindowsServiceActiveInstallRecordV1, WindowsServiceIntentRecordV1,
    WindowsServiceLifecycleStateAssessment,
};
use crate::service_observer::WindowsServiceObservation;
#[cfg(windows)]
use crate::service_observer::WindowsServiceSnapshot;
use crate::service_ownership::{
    assess_windows_service_ownership, WindowsExecutableEvidence, WindowsOwnerRecordEvidence,
    WindowsScmEvidence, WindowsServiceOwnershipInput, WindowsStagedPayloadEvidence,
};
use serde::{Deserialize, Serialize};

pub const WINDOWS_SERVICE_SCM_GATE_CONTRACT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceScmGateOutcome {
    Mutate,
    NoChange,
    Refuse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceScmGateReason {
    Authorized,
    AlreadySatisfied,
    UnsupportedAction,
    InvalidIdentity,
    LifecycleStateUnavailable,
    IntentMismatch,
    ActiveInstallMismatch,
    PayloadMismatch,
    ServiceMustBeAbsent,
    ServiceNotOwned,
    ServiceStateMismatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceScmGateDecision {
    pub outcome: WindowsServiceScmGateOutcome,
    pub reason: WindowsServiceScmGateReason,
}

impl WindowsServiceScmGateDecision {
    const fn mutate() -> Self {
        Self {
            outcome: WindowsServiceScmGateOutcome::Mutate,
            reason: WindowsServiceScmGateReason::Authorized,
        }
    }

    const fn no_change() -> Self {
        Self {
            outcome: WindowsServiceScmGateOutcome::NoChange,
            reason: WindowsServiceScmGateReason::AlreadySatisfied,
        }
    }

    const fn refuse(reason: WindowsServiceScmGateReason) -> Self {
        Self {
            outcome: WindowsServiceScmGateOutcome::Refuse,
            reason,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScmActionKind {
    Register,
    Start,
    Stop,
    Unregister,
}

/// Decides whether one native SCM action is safe from already-collected
/// evidence. This function performs no I/O and grants no authority by itself.
pub fn assess_windows_service_scm_action(
    action: &WindowsServiceAction,
    lifecycle: &WindowsServiceLifecycleStateAssessment,
    observation: &WindowsServiceObservation,
    payload: &WindowsStagedPayloadEvidence,
) -> WindowsServiceScmGateDecision {
    let Some((kind, identity)) = action_identity(action) else {
        return WindowsServiceScmGateDecision::refuse(
            WindowsServiceScmGateReason::UnsupportedAction,
        );
    };
    if identity.validate().is_err() {
        return WindowsServiceScmGateDecision::refuse(WindowsServiceScmGateReason::InvalidIdentity);
    }

    let WindowsServiceLifecycleStateAssessment::Stable {
        intent,
        active_install,
    } = lifecycle
    else {
        return WindowsServiceScmGateDecision::refuse(
            WindowsServiceScmGateReason::LifecycleStateUnavailable,
        );
    };
    if !valid_stable_records(intent.as_ref(), active_install.as_ref()) {
        return WindowsServiceScmGateDecision::refuse(
            WindowsServiceScmGateReason::LifecycleStateUnavailable,
        );
    }
    if !intent_allows(kind, intent.as_ref(), identity) {
        return WindowsServiceScmGateDecision::refuse(WindowsServiceScmGateReason::IntentMismatch);
    }
    if !active_install_allows(kind, active_install.as_ref(), identity) {
        return WindowsServiceScmGateDecision::refuse(
            WindowsServiceScmGateReason::ActiveInstallMismatch,
        );
    }
    if !payload_matches(payload, identity) {
        return WindowsServiceScmGateDecision::refuse(WindowsServiceScmGateReason::PayloadMismatch);
    }

    match kind {
        ScmActionKind::Register => match observation {
            WindowsServiceObservation::Absent { service_name }
                if service_name == &identity.service_name =>
            {
                WindowsServiceScmGateDecision::mutate()
            }
            _ => WindowsServiceScmGateDecision::refuse(
                WindowsServiceScmGateReason::ServiceMustBeAbsent,
            ),
        },
        ScmActionKind::Unregister
            if matches!(
                observation,
                WindowsServiceObservation::Absent { service_name }
                    if service_name == &identity.service_name
            ) =>
        {
            WindowsServiceScmGateDecision::no_change()
        }
        ScmActionKind::Start | ScmActionKind::Stop | ScmActionKind::Unregister => {
            assess_existing_service(kind, identity, observation, payload)
        }
    }
}

fn action_identity(
    action: &WindowsServiceAction,
) -> Option<(ScmActionKind, &WindowsServiceIdentity)> {
    match action {
        WindowsServiceAction::RegisterService { identity } => {
            Some((ScmActionKind::Register, identity))
        }
        WindowsServiceAction::StartOwnedService { identity } => {
            Some((ScmActionKind::Start, identity))
        }
        WindowsServiceAction::StopOwnedService { identity } => {
            Some((ScmActionKind::Stop, identity))
        }
        WindowsServiceAction::UnregisterOwnedService { identity } => {
            Some((ScmActionKind::Unregister, identity))
        }
        _ => None,
    }
}

fn valid_stable_records(
    intent: Option<&WindowsServiceIntentRecordV1>,
    active_install: Option<&WindowsServiceActiveInstallRecordV1>,
) -> bool {
    intent.map_or(true, |record| record.validate().is_ok())
        && active_install.map_or(true, |record| record.validate().is_ok())
        && active_install.map_or(true, |active| {
            intent.and_then(|record| record.identity.as_ref()) == Some(&active.identity)
        })
}

fn intent_allows(
    kind: ScmActionKind,
    intent: Option<&WindowsServiceIntentRecordV1>,
    identity: &WindowsServiceIdentity,
) -> bool {
    let Some(intent) = intent else {
        return false;
    };
    match kind {
        ScmActionKind::Register => {
            intent.desired == WindowsServiceDesiredState::Running
                && intent.identity.as_ref() == Some(identity)
                && intent.crash_restart_attempts == 0
        }
        ScmActionKind::Start => {
            intent.desired == WindowsServiceDesiredState::Running
                && intent.identity.as_ref() == Some(identity)
        }
        ScmActionKind::Stop => match intent.desired {
            WindowsServiceDesiredState::Stopped => {
                intent.identity.as_ref() == Some(identity) && intent.crash_restart_attempts == 0
            }
            WindowsServiceDesiredState::Absent => {
                intent
                    .identity
                    .as_ref()
                    .map_or(true, |value| value == identity)
                    && intent.crash_restart_attempts == 0
            }
            WindowsServiceDesiredState::Unknown | WindowsServiceDesiredState::Running => false,
        },
        ScmActionKind::Unregister => {
            intent.desired == WindowsServiceDesiredState::Absent
                && intent
                    .identity
                    .as_ref()
                    .map_or(true, |value| value == identity)
                && intent.crash_restart_attempts == 0
        }
    }
}

fn active_install_allows(
    kind: ScmActionKind,
    active_install: Option<&WindowsServiceActiveInstallRecordV1>,
    identity: &WindowsServiceIdentity,
) -> bool {
    match kind {
        ScmActionKind::Register => active_install.is_none(),
        ScmActionKind::Start | ScmActionKind::Stop | ScmActionKind::Unregister => {
            active_install.map_or(true, |record| &record.identity == identity)
        }
    }
}

fn payload_matches(
    payload: &WindowsStagedPayloadEvidence,
    identity: &WindowsServiceIdentity,
) -> bool {
    let WindowsOwnerRecordEvidence::OwnerOnly { record } = &payload.record else {
        return false;
    };
    let WindowsExecutableEvidence::Verified {
        executable_path,
        executable_sha256,
    } = &payload.executable
    else {
        return false;
    };
    record.validate().is_ok()
        && record.identity() == *identity
        && executable_path == &record.executable_path
        && executable_sha256 == &record.executable_sha256
}

fn assess_existing_service(
    kind: ScmActionKind,
    identity: &WindowsServiceIdentity,
    observation: &WindowsServiceObservation,
    payload: &WindowsStagedPayloadEvidence,
) -> WindowsServiceScmGateDecision {
    let assessment = assess_windows_service_ownership(&WindowsServiceOwnershipInput {
        record: payload.record.clone(),
        scm: WindowsScmEvidence::Observed {
            observation: observation.clone(),
        },
        executable: payload.executable.clone(),
    });
    if assessment.ownership != WindowsServiceOwnership::Owned
        || assessment.identity.as_ref() != Some(identity)
    {
        return WindowsServiceScmGateDecision::refuse(WindowsServiceScmGateReason::ServiceNotOwned);
    }

    match (kind, assessment.observed) {
        (ScmActionKind::Start, WindowsServiceObservedState::Stopped)
        | (ScmActionKind::Stop, WindowsServiceObservedState::Running)
        | (ScmActionKind::Unregister, WindowsServiceObservedState::Stopped) => {
            WindowsServiceScmGateDecision::mutate()
        }
        (ScmActionKind::Start, WindowsServiceObservedState::Running)
        | (ScmActionKind::Stop, WindowsServiceObservedState::Stopped) => {
            WindowsServiceScmGateDecision::no_change()
        }
        _ => {
            WindowsServiceScmGateDecision::refuse(WindowsServiceScmGateReason::ServiceStateMismatch)
        }
    }
}

#[cfg(windows)]
pub(crate) fn snapshot_is_exact_owned(
    snapshot: WindowsServiceSnapshot,
    identity: &WindowsServiceIdentity,
    payload: &WindowsStagedPayloadEvidence,
) -> bool {
    let observation = WindowsServiceObservation::Present { snapshot };
    let assessment = assess_windows_service_ownership(&WindowsServiceOwnershipInput {
        record: payload.record.clone(),
        scm: WindowsScmEvidence::Observed { observation },
        executable: payload.executable.clone(),
    });
    assessment.ownership == WindowsServiceOwnership::Owned
        && assessment.identity.as_ref() == Some(identity)
}

#[cfg(windows)]
pub(crate) fn snapshot_matches_staged_payload(
    snapshot: &WindowsServiceSnapshot,
    identity: &WindowsServiceIdentity,
    payload: &WindowsStagedPayloadEvidence,
) -> bool {
    let WindowsOwnerRecordEvidence::OwnerOnly { record } = &payload.record else {
        return false;
    };
    payload_matches(payload, identity)
        && snapshot.service_name == identity.service_name
        && snapshot.binary_path == record.scm_binary_path
}

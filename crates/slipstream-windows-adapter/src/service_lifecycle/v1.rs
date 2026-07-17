//! Version 1 of the effect-injected Windows service lifecycle contract.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const WINDOWS_SERVICE_LIFECYCLE_CONTRACT_VERSION: u32 = 1;
pub const WINDOWS_SERVICE_NAME: &str = "dev.slipstream.service";
pub const DEFAULT_MAX_CRASH_RESTARTS: u32 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceDesiredState {
    Unknown,
    Absent,
    Stopped,
    Running,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceObservedState {
    Absent,
    Stopped,
    Running,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceOwnership {
    Absent,
    Owned,
    Foreign,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceIdentity {
    pub service_name: String,
    pub executable_sha256: String,
    pub generation: u64,
}

impl WindowsServiceIdentity {
    pub fn validate(&self) -> Result<(), WindowsServiceLifecycleError> {
        if self.service_name != WINDOWS_SERVICE_NAME {
            return Err(WindowsServiceLifecycleError::Contract(format!(
                "service name {:?} is not the owned Slipstream service",
                self.service_name
            )));
        }
        if self.generation == 0 {
            return Err(WindowsServiceLifecycleError::Contract(
                "service generation must be positive".to_owned(),
            ));
        }
        if self.executable_sha256.len() != 64
            || !self
                .executable_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(WindowsServiceLifecycleError::Contract(
                "service executable SHA-256 must be 64 lowercase hexadecimal characters".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceState {
    pub desired: WindowsServiceDesiredState,
    pub observed: WindowsServiceObservedState,
    pub ownership: WindowsServiceOwnership,
    pub active: Option<WindowsServiceIdentity>,
    pub crash_restart_attempts: u32,
}

impl WindowsServiceState {
    pub fn absent() -> Self {
        Self {
            desired: WindowsServiceDesiredState::Absent,
            observed: WindowsServiceObservedState::Absent,
            ownership: WindowsServiceOwnership::Absent,
            active: None,
            crash_restart_attempts: 0,
        }
    }

    fn uncertain() -> Self {
        Self {
            desired: WindowsServiceDesiredState::Unknown,
            observed: WindowsServiceObservedState::Unknown,
            ownership: WindowsServiceOwnership::Unknown,
            active: None,
            crash_restart_attempts: 0,
        }
    }

    fn uncertain_owned(
        identity: WindowsServiceIdentity,
        desired: WindowsServiceDesiredState,
        crash_restart_attempts: u32,
    ) -> Self {
        Self {
            desired,
            observed: WindowsServiceObservedState::Unknown,
            ownership: WindowsServiceOwnership::Owned,
            active: Some(identity),
            crash_restart_attempts,
        }
    }

    pub fn validate(&self) -> Result<(), WindowsServiceLifecycleError> {
        match self.ownership {
            WindowsServiceOwnership::Absent => {
                if self.observed != WindowsServiceObservedState::Absent || self.active.is_some() {
                    return Err(WindowsServiceLifecycleError::Contract(
                        "absent ownership requires absent observation and no active identity"
                            .to_owned(),
                    ));
                }
            }
            WindowsServiceOwnership::Owned => {
                let identity = self.active.as_ref().ok_or_else(|| {
                    WindowsServiceLifecycleError::Contract(
                        "owned service state requires an active identity".to_owned(),
                    )
                })?;
                identity.validate()?;
                if self.observed == WindowsServiceObservedState::Absent {
                    return Err(WindowsServiceLifecycleError::Contract(
                        "owned service state cannot be observed absent".to_owned(),
                    ));
                }
            }
            WindowsServiceOwnership::Foreign | WindowsServiceOwnership::Unknown => {
                if self.active.is_some() {
                    return Err(WindowsServiceLifecycleError::Contract(
                        "unowned service state cannot carry an owned active identity".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsServiceCommand {
    Install { identity: WindowsServiceIdentity },
    Start,
    Stop,
    CrashObserved,
    Uninstall,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceDecision {
    Installed,
    Started,
    Stopped,
    Restarted,
    Uninstalled,
    RolledBack,
    NoChange,
    Refused,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceActionKind {
    PersistIntent,
    StagePayload,
    RegisterService,
    StartOwnedService,
    VerifyReady,
    CommitInstall,
    ClearActiveInstallRecord,
    StopOwnedService,
    VerifyStopped,
    UnregisterOwnedService,
    RemoveOwnedPayload,
    VerifyAbsent,
}

impl WindowsServiceActionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersistIntent => "persist_intent",
            Self::StagePayload => "stage_payload",
            Self::RegisterService => "register_service",
            Self::StartOwnedService => "start_owned_service",
            Self::VerifyReady => "verify_ready",
            Self::CommitInstall => "commit_install",
            Self::ClearActiveInstallRecord => "clear_active_install_record",
            Self::StopOwnedService => "stop_owned_service",
            Self::VerifyStopped => "verify_stopped",
            Self::UnregisterOwnedService => "unregister_owned_service",
            Self::RemoveOwnedPayload => "remove_owned_payload",
            Self::VerifyAbsent => "verify_absent",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsServiceAction {
    PersistIntent {
        desired: WindowsServiceDesiredState,
        identity: Option<WindowsServiceIdentity>,
        crash_restart_attempts: u32,
    },
    StagePayload {
        identity: WindowsServiceIdentity,
    },
    RegisterService {
        identity: WindowsServiceIdentity,
    },
    StartOwnedService {
        identity: WindowsServiceIdentity,
    },
    VerifyReady {
        identity: WindowsServiceIdentity,
    },
    CommitInstall {
        identity: WindowsServiceIdentity,
    },
    ClearActiveInstallRecord {
        identity: WindowsServiceIdentity,
    },
    StopOwnedService {
        identity: WindowsServiceIdentity,
    },
    VerifyStopped {
        identity: WindowsServiceIdentity,
    },
    UnregisterOwnedService {
        identity: WindowsServiceIdentity,
    },
    RemoveOwnedPayload {
        identity: WindowsServiceIdentity,
    },
    VerifyAbsent {
        identity: WindowsServiceIdentity,
    },
}

impl WindowsServiceAction {
    pub const fn kind(&self) -> WindowsServiceActionKind {
        match self {
            Self::PersistIntent { .. } => WindowsServiceActionKind::PersistIntent,
            Self::StagePayload { .. } => WindowsServiceActionKind::StagePayload,
            Self::RegisterService { .. } => WindowsServiceActionKind::RegisterService,
            Self::StartOwnedService { .. } => WindowsServiceActionKind::StartOwnedService,
            Self::VerifyReady { .. } => WindowsServiceActionKind::VerifyReady,
            Self::CommitInstall { .. } => WindowsServiceActionKind::CommitInstall,
            Self::ClearActiveInstallRecord { .. } => {
                WindowsServiceActionKind::ClearActiveInstallRecord
            }
            Self::StopOwnedService { .. } => WindowsServiceActionKind::StopOwnedService,
            Self::VerifyStopped { .. } => WindowsServiceActionKind::VerifyStopped,
            Self::UnregisterOwnedService { .. } => WindowsServiceActionKind::UnregisterOwnedService,
            Self::RemoveOwnedPayload { .. } => WindowsServiceActionKind::RemoveOwnedPayload,
            Self::VerifyAbsent { .. } => WindowsServiceActionKind::VerifyAbsent,
        }
    }
}

pub trait WindowsServiceEffects {
    type Error: fmt::Display;

    fn apply(&mut self, action: &WindowsServiceAction) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default)]
pub struct RecordingWindowsServiceEffects {
    failures: BTreeMap<(WindowsServiceActionKind, u32), String>,
    calls: BTreeMap<WindowsServiceActionKind, u32>,
    events: Vec<WindowsServiceAction>,
}

impl RecordingWindowsServiceEffects {
    pub fn fail_once(&mut self, stage: WindowsServiceActionKind, message: impl Into<String>) {
        let next_call = self.calls.get(&stage).copied().unwrap_or_default() + 1;
        self.fail_on_call(stage, next_call, message);
    }

    pub fn fail_on_call(
        &mut self,
        stage: WindowsServiceActionKind,
        call: u32,
        message: impl Into<String>,
    ) {
        assert!(call > 0, "effect call index must be positive");
        self.failures.insert((stage, call), message.into());
    }

    pub fn events(&self) -> &[WindowsServiceAction] {
        &self.events
    }

    pub fn clear_events(&mut self) {
        self.events.clear();
    }
}

impl WindowsServiceEffects for RecordingWindowsServiceEffects {
    type Error = String;

    fn apply(&mut self, action: &WindowsServiceAction) -> Result<(), Self::Error> {
        self.events.push(action.clone());
        let call = self.calls.entry(action.kind()).or_default();
        *call += 1;
        match self.failures.remove(&(action.kind(), *call)) {
            Some(message) => Err(message),
            None => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceLifecycleResult {
    pub state: WindowsServiceState,
    pub decision: WindowsServiceDecision,
    pub accepted: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
pub enum WindowsServiceLifecycleError {
    Contract(String),
    Compensation {
        primary_stage: WindowsServiceActionKind,
        primary_message: String,
        failed_stages: Vec<WindowsServiceActionKind>,
        state: Box<WindowsServiceState>,
    },
}

impl fmt::Display for WindowsServiceLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(message) => write!(formatter, "service lifecycle contract: {message}"),
            Self::Compensation {
                primary_stage,
                primary_message,
                failed_stages,
                ..
            } => write!(
                formatter,
                "{} failed: {}; compensation incomplete at {:?}",
                primary_stage.as_str(),
                primary_message,
                failed_stages
            ),
        }
    }
}

impl std::error::Error for WindowsServiceLifecycleError {}

pub struct WindowsServiceLifecycleV1 {
    state: WindowsServiceState,
    max_crash_restarts: u32,
}

impl WindowsServiceLifecycleV1 {
    pub fn new(state: WindowsServiceState) -> Result<Self, WindowsServiceLifecycleError> {
        Self::with_restart_limit(state, DEFAULT_MAX_CRASH_RESTARTS)
    }

    pub fn with_restart_limit(
        state: WindowsServiceState,
        max_crash_restarts: u32,
    ) -> Result<Self, WindowsServiceLifecycleError> {
        state.validate()?;
        if max_crash_restarts == 0 {
            return Err(WindowsServiceLifecycleError::Contract(
                "crash restart limit must be positive".to_owned(),
            ));
        }
        Ok(Self {
            state,
            max_crash_restarts,
        })
    }

    pub fn state(&self) -> &WindowsServiceState {
        &self.state
    }

    pub fn execute<E: WindowsServiceEffects>(
        &mut self,
        command: &WindowsServiceCommand,
        effects: &mut E,
    ) -> Result<WindowsServiceLifecycleResult, WindowsServiceLifecycleError> {
        self.state.validate()?;
        match command {
            WindowsServiceCommand::Install { identity } => self.install(identity.clone(), effects),
            WindowsServiceCommand::Start => self.start(effects),
            WindowsServiceCommand::Stop => self.stop(effects),
            WindowsServiceCommand::CrashObserved => self.recover_crash(effects),
            WindowsServiceCommand::Uninstall => self.uninstall(effects),
        }
    }

    fn install<E: WindowsServiceEffects>(
        &mut self,
        identity: WindowsServiceIdentity,
        effects: &mut E,
    ) -> Result<WindowsServiceLifecycleResult, WindowsServiceLifecycleError> {
        identity.validate()?;
        if self.state != WindowsServiceState::absent() {
            return Ok(self
                .refused("install requires a verified absent service and absent durable intent"));
        }

        let prior = self.state.clone();
        let forward = [
            (
                WindowsServiceAction::PersistIntent {
                    desired: WindowsServiceDesiredState::Running,
                    identity: Some(identity.clone()),
                    crash_restart_attempts: 0,
                },
                Some(WindowsServiceAction::PersistIntent {
                    desired: prior.desired,
                    identity: prior.active.clone(),
                    crash_restart_attempts: prior.crash_restart_attempts,
                }),
            ),
            (
                WindowsServiceAction::StagePayload {
                    identity: identity.clone(),
                },
                Some(WindowsServiceAction::RemoveOwnedPayload {
                    identity: identity.clone(),
                }),
            ),
            (
                WindowsServiceAction::RegisterService {
                    identity: identity.clone(),
                },
                Some(WindowsServiceAction::UnregisterOwnedService {
                    identity: identity.clone(),
                }),
            ),
            (
                WindowsServiceAction::StartOwnedService {
                    identity: identity.clone(),
                },
                Some(WindowsServiceAction::StopOwnedService {
                    identity: identity.clone(),
                }),
            ),
            (
                WindowsServiceAction::VerifyReady {
                    identity: identity.clone(),
                },
                None,
            ),
            (
                WindowsServiceAction::CommitInstall {
                    identity: identity.clone(),
                },
                Some(WindowsServiceAction::ClearActiveInstallRecord {
                    identity: identity.clone(),
                }),
            ),
        ];
        let mut compensation = Vec::new();
        for (action, undo) in forward {
            if let Some(undo) = undo {
                compensation.push(undo);
            }
            if let Err(message) = apply_effect(effects, &action) {
                return self.rollback_install(
                    prior,
                    identity.clone(),
                    compensation,
                    action.kind(),
                    message,
                    effects,
                );
            }
        }

        self.state = WindowsServiceState {
            desired: WindowsServiceDesiredState::Running,
            observed: WindowsServiceObservedState::Running,
            ownership: WindowsServiceOwnership::Owned,
            active: Some(identity),
            crash_restart_attempts: 0,
        };
        Ok(self.result(WindowsServiceDecision::Installed, true, None))
    }

    fn rollback_install<E: WindowsServiceEffects>(
        &mut self,
        prior: WindowsServiceState,
        identity: WindowsServiceIdentity,
        compensation: Vec<WindowsServiceAction>,
        primary_stage: WindowsServiceActionKind,
        primary_message: String,
        effects: &mut E,
    ) -> Result<WindowsServiceLifecycleResult, WindowsServiceLifecycleError> {
        let mut failed_stages = Vec::new();
        let mut intent_restored = true;
        for action in compensation.into_iter().rev() {
            if apply_effect(effects, &action).is_err() {
                if action.kind() == WindowsServiceActionKind::PersistIntent {
                    intent_restored = false;
                }
                failed_stages.push(action.kind());
            }
        }
        let verify = WindowsServiceAction::VerifyAbsent { identity };
        let absence_verified = match apply_effect(effects, &verify) {
            Ok(()) => true,
            Err(_) => {
                failed_stages.push(WindowsServiceActionKind::VerifyAbsent);
                false
            }
        };

        if intent_restored && absence_verified {
            self.state = prior;
            return Ok(self.result(
                WindowsServiceDecision::RolledBack,
                false,
                Some(format!(
                    "{} effect failed: {primary_message}",
                    primary_stage.as_str()
                )),
            ));
        }

        self.state = WindowsServiceState::uncertain();
        Err(WindowsServiceLifecycleError::Compensation {
            primary_stage,
            primary_message,
            failed_stages,
            state: Box::new(self.state.clone()),
        })
    }

    fn start<E: WindowsServiceEffects>(
        &mut self,
        effects: &mut E,
    ) -> Result<WindowsServiceLifecycleResult, WindowsServiceLifecycleError> {
        let identity = match self.owned_identity() {
            Some(identity) => identity,
            None => return Ok(self.refused("start requires exact owned service identity")),
        };
        if self.state.desired == WindowsServiceDesiredState::Running
            && self.state.observed == WindowsServiceObservedState::Running
        {
            return Ok(self.result(WindowsServiceDecision::NoChange, true, None));
        }
        if matches!(
            self.state.desired,
            WindowsServiceDesiredState::Absent | WindowsServiceDesiredState::Unknown
        ) {
            return Ok(self.refused("start cannot override absent or unknown durable intent"));
        }

        let prior = self.state.clone();
        let persist = WindowsServiceAction::PersistIntent {
            desired: WindowsServiceDesiredState::Running,
            identity: Some(identity.clone()),
            crash_restart_attempts: 0,
        };
        if let Err(message) = apply_effect(effects, &persist) {
            return Ok(self.result(
                WindowsServiceDecision::Incomplete,
                false,
                Some(format!("persist_intent effect failed: {message}")),
            ));
        }

        let start = WindowsServiceAction::StartOwnedService {
            identity: identity.clone(),
        };
        let start_error = apply_effect(effects, &start).err();
        let verify = WindowsServiceAction::VerifyReady {
            identity: identity.clone(),
        };
        if apply_effect(effects, &verify).is_ok() {
            self.state = WindowsServiceState {
                desired: WindowsServiceDesiredState::Running,
                observed: WindowsServiceObservedState::Running,
                ownership: WindowsServiceOwnership::Owned,
                active: Some(identity),
                crash_restart_attempts: 0,
            };
            return Ok(self.result(WindowsServiceDecision::Started, true, None));
        }

        let primary_message = join_failures(start_error, Some("readiness verification failed"));
        self.rollback_start(prior, identity, primary_message, effects)
    }

    fn rollback_start<E: WindowsServiceEffects>(
        &mut self,
        prior: WindowsServiceState,
        identity: WindowsServiceIdentity,
        primary_message: String,
        effects: &mut E,
    ) -> Result<WindowsServiceLifecycleResult, WindowsServiceLifecycleError> {
        let stop = WindowsServiceAction::StopOwnedService {
            identity: identity.clone(),
        };
        let stop_reported_success = apply_effect(effects, &stop).is_ok();
        let persist = WindowsServiceAction::PersistIntent {
            desired: prior.desired,
            identity: prior.active.clone(),
            crash_restart_attempts: prior.crash_restart_attempts,
        };
        let intent_restored = apply_effect(effects, &persist).is_ok();
        let verify = WindowsServiceAction::VerifyStopped {
            identity: identity.clone(),
        };
        let stopped = apply_effect(effects, &verify).is_ok();
        if intent_restored && stopped {
            self.state = prior;
            return Ok(self.result(
                WindowsServiceDecision::RolledBack,
                false,
                Some(primary_message),
            ));
        }

        let mut failed_stages = Vec::new();
        if !stop_reported_success && !stopped {
            failed_stages.push(WindowsServiceActionKind::StopOwnedService);
        }
        if !intent_restored {
            failed_stages.push(WindowsServiceActionKind::PersistIntent);
        }
        if !stopped {
            failed_stages.push(WindowsServiceActionKind::VerifyStopped);
        }
        let desired = if intent_restored {
            prior.desired
        } else {
            WindowsServiceDesiredState::Unknown
        };
        self.state =
            WindowsServiceState::uncertain_owned(identity, desired, prior.crash_restart_attempts);
        Err(WindowsServiceLifecycleError::Compensation {
            primary_stage: WindowsServiceActionKind::VerifyReady,
            primary_message,
            failed_stages,
            state: Box::new(self.state.clone()),
        })
    }

    fn stop<E: WindowsServiceEffects>(
        &mut self,
        effects: &mut E,
    ) -> Result<WindowsServiceLifecycleResult, WindowsServiceLifecycleError> {
        let identity = match self.owned_identity() {
            Some(identity) => identity,
            None => return Ok(self.refused("stop requires exact owned service identity")),
        };
        if self.state.desired == WindowsServiceDesiredState::Absent {
            return Ok(
                self.refused("stop cannot weaken absent intent; uninstall cleanup must continue")
            );
        }
        if self.state.desired == WindowsServiceDesiredState::Stopped
            && self.state.observed == WindowsServiceObservedState::Stopped
        {
            return Ok(self.result(WindowsServiceDecision::NoChange, true, None));
        }

        let persist = WindowsServiceAction::PersistIntent {
            desired: WindowsServiceDesiredState::Stopped,
            identity: Some(identity.clone()),
            crash_restart_attempts: 0,
        };
        if let Err(message) = apply_effect(effects, &persist) {
            return Ok(self.result(
                WindowsServiceDecision::Incomplete,
                false,
                Some(format!("persist_intent effect failed: {message}")),
            ));
        }

        let stop = WindowsServiceAction::StopOwnedService {
            identity: identity.clone(),
        };
        let stop_error = apply_effect(effects, &stop).err();
        let verify = WindowsServiceAction::VerifyStopped {
            identity: identity.clone(),
        };
        if apply_effect(effects, &verify).is_ok() {
            self.state = WindowsServiceState {
                desired: WindowsServiceDesiredState::Stopped,
                observed: WindowsServiceObservedState::Stopped,
                ownership: WindowsServiceOwnership::Owned,
                active: Some(identity),
                crash_restart_attempts: 0,
            };
            return Ok(self.result(WindowsServiceDecision::Stopped, true, None));
        }

        self.state =
            WindowsServiceState::uncertain_owned(identity, WindowsServiceDesiredState::Stopped, 0);
        Ok(self.result(
            WindowsServiceDecision::Incomplete,
            false,
            Some(join_failures(
                stop_error,
                Some("stopped-state verification failed"),
            )),
        ))
    }

    fn recover_crash<E: WindowsServiceEffects>(
        &mut self,
        effects: &mut E,
    ) -> Result<WindowsServiceLifecycleResult, WindowsServiceLifecycleError> {
        if self.state.desired != WindowsServiceDesiredState::Running {
            return Ok(self.result(WindowsServiceDecision::NoChange, true, None));
        }
        let identity = match self.owned_identity() {
            Some(identity) => identity,
            None => return Ok(self.refused("crash recovery requires exact owned service identity")),
        };
        if self.state.observed == WindowsServiceObservedState::Running {
            return Ok(self.result(WindowsServiceDecision::NoChange, true, None));
        }
        if self.state.crash_restart_attempts >= self.max_crash_restarts {
            return Ok(self.refused("crash restart budget exhausted"));
        }

        let attempt = self.state.crash_restart_attempts + 1;
        let persist_attempt = WindowsServiceAction::PersistIntent {
            desired: WindowsServiceDesiredState::Running,
            identity: Some(identity.clone()),
            crash_restart_attempts: attempt,
        };
        if let Err(message) = apply_effect(effects, &persist_attempt) {
            return Ok(self.result(
                WindowsServiceDecision::Incomplete,
                false,
                Some(format!("persist_intent effect failed: {message}")),
            ));
        }

        let start = WindowsServiceAction::StartOwnedService {
            identity: identity.clone(),
        };
        let start_error = apply_effect(effects, &start).err();
        let verify = WindowsServiceAction::VerifyReady {
            identity: identity.clone(),
        };
        if apply_effect(effects, &verify).is_ok() {
            let reset_budget = WindowsServiceAction::PersistIntent {
                desired: WindowsServiceDesiredState::Running,
                identity: Some(identity.clone()),
                crash_restart_attempts: 0,
            };
            let reset_error = apply_effect(effects, &reset_budget).err();
            self.state = WindowsServiceState {
                desired: WindowsServiceDesiredState::Running,
                observed: WindowsServiceObservedState::Running,
                ownership: WindowsServiceOwnership::Owned,
                active: Some(identity),
                crash_restart_attempts: if reset_error.is_some() { attempt } else { 0 },
            };
            return Ok(self.result(
                WindowsServiceDecision::Restarted,
                true,
                reset_error.map(|error| {
                    format!("restart succeeded but crash budget reset failed: {error}")
                }),
            ));
        }

        self.state = WindowsServiceState::uncertain_owned(
            identity,
            WindowsServiceDesiredState::Running,
            attempt,
        );
        Ok(self.result(
            WindowsServiceDecision::Incomplete,
            false,
            Some(join_failures(
                start_error,
                Some("restart readiness verification failed"),
            )),
        ))
    }

    fn uninstall<E: WindowsServiceEffects>(
        &mut self,
        effects: &mut E,
    ) -> Result<WindowsServiceLifecycleResult, WindowsServiceLifecycleError> {
        if self.state.ownership == WindowsServiceOwnership::Absent {
            if self.state.desired == WindowsServiceDesiredState::Absent {
                return Ok(self.result(WindowsServiceDecision::NoChange, true, None));
            }
            let persist = WindowsServiceAction::PersistIntent {
                desired: WindowsServiceDesiredState::Absent,
                identity: None,
                crash_restart_attempts: 0,
            };
            return match apply_effect(effects, &persist) {
                Ok(()) => {
                    self.state = WindowsServiceState::absent();
                    Ok(self.result(WindowsServiceDecision::Uninstalled, true, None))
                }
                Err(message) => Ok(self.result(
                    WindowsServiceDecision::Incomplete,
                    false,
                    Some(format!("persist_intent effect failed: {message}")),
                )),
            };
        }

        let identity = match self.owned_identity() {
            Some(identity) => identity,
            None => return Ok(self.refused("uninstall refuses unowned service state")),
        };
        let persist = WindowsServiceAction::PersistIntent {
            desired: WindowsServiceDesiredState::Absent,
            identity: Some(identity.clone()),
            crash_restart_attempts: 0,
        };
        if let Err(message) = apply_effect(effects, &persist) {
            return Ok(self.result(
                WindowsServiceDecision::Incomplete,
                false,
                Some(format!("persist_intent effect failed: {message}")),
            ));
        }

        let cleanup = [
            WindowsServiceAction::StopOwnedService {
                identity: identity.clone(),
            },
            WindowsServiceAction::UnregisterOwnedService {
                identity: identity.clone(),
            },
            WindowsServiceAction::RemoveOwnedPayload {
                identity: identity.clone(),
            },
            WindowsServiceAction::ClearActiveInstallRecord {
                identity: identity.clone(),
            },
        ];
        let mut failures = Vec::new();
        for action in cleanup {
            if apply_effect(effects, &action).is_err() {
                failures.push(action.kind().as_str());
            }
        }
        let verify = WindowsServiceAction::VerifyAbsent { identity };
        if apply_effect(effects, &verify).is_ok() {
            self.state = WindowsServiceState::absent();
            return Ok(self.result(WindowsServiceDecision::Uninstalled, true, None));
        }
        failures.push(WindowsServiceActionKind::VerifyAbsent.as_str());
        self.state = WindowsServiceState {
            desired: WindowsServiceDesiredState::Absent,
            ..WindowsServiceState::uncertain()
        };
        Ok(self.result(
            WindowsServiceDecision::Incomplete,
            false,
            Some(format!("cleanup incomplete at {}", failures.join(", "))),
        ))
    }

    fn owned_identity(&self) -> Option<WindowsServiceIdentity> {
        if self.state.ownership != WindowsServiceOwnership::Owned {
            return None;
        }
        self.state.active.clone()
    }

    fn refused(&self, message: &str) -> WindowsServiceLifecycleResult {
        self.result(
            WindowsServiceDecision::Refused,
            false,
            Some(message.to_owned()),
        )
    }

    fn result(
        &self,
        decision: WindowsServiceDecision,
        accepted: bool,
        error: Option<String>,
    ) -> WindowsServiceLifecycleResult {
        WindowsServiceLifecycleResult {
            state: self.state.clone(),
            decision,
            accepted,
            error,
        }
    }
}

fn apply_effect<E: WindowsServiceEffects>(
    effects: &mut E,
    action: &WindowsServiceAction,
) -> Result<(), String> {
    effects.apply(action).map_err(|error| error.to_string())
}

fn join_failures(first: Option<String>, final_failure: Option<&str>) -> String {
    match (first, final_failure) {
        (Some(first), Some(final_failure)) => format!("{first}; {final_failure}"),
        (Some(first), None) => first,
        (None, Some(final_failure)) => final_failure.to_owned(),
        (None, None) => "service lifecycle operation failed".to_owned(),
    }
}

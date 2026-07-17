//! Version 1 of the no-network Windows adapter harness.

use serde_json::Value;
use slipstream_core::route_policy_activation::{
    reduce_policy_activation, PolicyActivationAction, PolicyActivationActionKind,
    PolicyActivationDecisionKind, PolicyActivationError, PolicyActivationEvent,
    PolicyActivationPhase, PolicyActivationReason, PolicyActivationState, PolicyIdentity,
    PolicyKind,
};
use slipstream_core::route_policy_bundle::{
    route_policy_hash, verify_signed_route_policy_bundle, RoutePolicyBundleError,
};
use slipstream_core::route_policy_manifest::RoutePolicyManifest;
use slipstream_core::routing_policy::{classify_route_policy, RoutePolicyResult};
use slipstream_core::routing_recovery::{
    reduce_connection_outcome, ConnectionOutcome, RecoveryAction, RecoveryActionKind,
    RecoveryContext,
};
use slipstream_core::status_v2::{status_v2_from_value, StatusV2};
use std::collections::BTreeMap;
use std::fmt;

pub const WINDOWS_ADAPTER_CONTRACT_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthEvidence {
    pub completed: bool,
    pub ok: u32,
    pub degraded: u32,
    pub blocked: u32,
    pub detail: String,
}

impl HealthEvidence {
    pub fn healthy() -> Self {
        Self {
            completed: true,
            ok: 1,
            degraded: 0,
            blocked: 0,
            detail: String::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WindowsEffectStage {
    PersistTrialGeneration,
    ActivateTrial,
    RunHealthGate,
    CommitCandidate,
    RestoreActive,
    RecordRejection,
    CommitAndActivateRollback,
    ApplyRecovery,
}

impl WindowsEffectStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersistTrialGeneration => "persist_trial_generation",
            Self::ActivateTrial => "activate_trial",
            Self::RunHealthGate => "run_health_gate",
            Self::CommitCandidate => "commit_candidate",
            Self::RestoreActive => "restore_active",
            Self::RecordRejection => "record_rejection",
            Self::CommitAndActivateRollback => "commit_and_activate_rollback",
            Self::ApplyRecovery => "apply_recovery",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedWindowsEffect {
    PersistTrialGeneration {
        generation: u64,
    },
    ActivateTrial {
        policy: PolicyIdentity,
    },
    RunHealthGate {
        policy: PolicyIdentity,
        generation: u64,
    },
    CommitCandidate {
        policy: PolicyIdentity,
        previous: PolicyIdentity,
        generation: u64,
    },
    RestoreActive {
        policy: PolicyIdentity,
    },
    RecordRejection {
        policy: PolicyIdentity,
        reason: String,
        detail: String,
    },
    CommitAndActivateRollback {
        policy: PolicyIdentity,
        generation: u64,
    },
    ApplyRecovery {
        action: RecoveryAction,
    },
}

impl RecordedWindowsEffect {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::PersistTrialGeneration { .. } => "persist_trial_generation",
            Self::ActivateTrial { .. } => "activate_trial",
            Self::RunHealthGate { .. } => "run_health_gate",
            Self::CommitCandidate { .. } => "commit_candidate",
            Self::RestoreActive { .. } => "restore_active",
            Self::RecordRejection { .. } => "record_rejection",
            Self::CommitAndActivateRollback { .. } => "commit_and_activate_rollback",
            Self::ApplyRecovery { .. } => "apply_recovery",
        }
    }
}

pub trait WindowsEffects {
    type Error: fmt::Display;

    fn persist_trial_generation(&mut self, generation: u64) -> Result<(), Self::Error>;

    fn activate_trial(
        &mut self,
        manifest: &RoutePolicyManifest,
        policy: &PolicyIdentity,
    ) -> Result<(), Self::Error>;

    fn run_health_gate(
        &mut self,
        manifest: &RoutePolicyManifest,
        policy: &PolicyIdentity,
        generation: u64,
    ) -> Result<HealthEvidence, Self::Error>;

    fn commit_candidate(
        &mut self,
        manifest: &RoutePolicyManifest,
        policy: &PolicyIdentity,
        previous: &PolicyIdentity,
        generation: u64,
    ) -> Result<(), Self::Error>;

    fn restore_active(
        &mut self,
        manifest: &RoutePolicyManifest,
        policy: &PolicyIdentity,
    ) -> Result<(), Self::Error>;

    fn record_rejection(
        &mut self,
        policy: &PolicyIdentity,
        reason: &str,
        detail: &str,
    ) -> Result<(), Self::Error>;

    fn commit_and_activate_rollback(
        &mut self,
        manifest: &RoutePolicyManifest,
        policy: &PolicyIdentity,
        generation: u64,
    ) -> Result<(), Self::Error>;

    fn apply_recovery(&mut self, action: &RecoveryAction) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug)]
pub struct RecordingWindowsEffects {
    health: HealthEvidence,
    failures: BTreeMap<WindowsEffectStage, String>,
    events: Vec<RecordedWindowsEffect>,
}

impl Default for RecordingWindowsEffects {
    fn default() -> Self {
        Self {
            health: HealthEvidence::healthy(),
            failures: BTreeMap::new(),
            events: Vec::new(),
        }
    }
}

impl RecordingWindowsEffects {
    pub fn with_health(health: HealthEvidence) -> Self {
        Self {
            health,
            ..Self::default()
        }
    }

    pub fn set_health(&mut self, health: HealthEvidence) {
        self.health = health;
    }

    pub fn fail_once(&mut self, stage: WindowsEffectStage, message: impl Into<String>) {
        self.failures.insert(stage, message.into());
    }

    pub fn events(&self) -> &[RecordedWindowsEffect] {
        &self.events
    }

    pub fn clear_events(&mut self) {
        self.events.clear();
    }

    fn finish(&mut self, stage: WindowsEffectStage) -> Result<(), String> {
        match self.failures.remove(&stage) {
            Some(message) => Err(message),
            None => Ok(()),
        }
    }
}

impl WindowsEffects for RecordingWindowsEffects {
    type Error = String;

    fn persist_trial_generation(&mut self, generation: u64) -> Result<(), Self::Error> {
        self.events
            .push(RecordedWindowsEffect::PersistTrialGeneration { generation });
        self.finish(WindowsEffectStage::PersistTrialGeneration)
    }

    fn activate_trial(
        &mut self,
        _manifest: &RoutePolicyManifest,
        policy: &PolicyIdentity,
    ) -> Result<(), Self::Error> {
        self.events.push(RecordedWindowsEffect::ActivateTrial {
            policy: policy.clone(),
        });
        self.finish(WindowsEffectStage::ActivateTrial)
    }

    fn run_health_gate(
        &mut self,
        _manifest: &RoutePolicyManifest,
        policy: &PolicyIdentity,
        generation: u64,
    ) -> Result<HealthEvidence, Self::Error> {
        self.events.push(RecordedWindowsEffect::RunHealthGate {
            policy: policy.clone(),
            generation,
        });
        self.finish(WindowsEffectStage::RunHealthGate)?;
        Ok(self.health.clone())
    }

    fn commit_candidate(
        &mut self,
        _manifest: &RoutePolicyManifest,
        policy: &PolicyIdentity,
        previous: &PolicyIdentity,
        generation: u64,
    ) -> Result<(), Self::Error> {
        self.events.push(RecordedWindowsEffect::CommitCandidate {
            policy: policy.clone(),
            previous: previous.clone(),
            generation,
        });
        self.finish(WindowsEffectStage::CommitCandidate)
    }

    fn restore_active(
        &mut self,
        _manifest: &RoutePolicyManifest,
        policy: &PolicyIdentity,
    ) -> Result<(), Self::Error> {
        self.events.push(RecordedWindowsEffect::RestoreActive {
            policy: policy.clone(),
        });
        self.finish(WindowsEffectStage::RestoreActive)
    }

    fn record_rejection(
        &mut self,
        policy: &PolicyIdentity,
        reason: &str,
        detail: &str,
    ) -> Result<(), Self::Error> {
        self.events.push(RecordedWindowsEffect::RecordRejection {
            policy: policy.clone(),
            reason: reason.to_owned(),
            detail: detail.to_owned(),
        });
        self.finish(WindowsEffectStage::RecordRejection)
    }

    fn commit_and_activate_rollback(
        &mut self,
        _manifest: &RoutePolicyManifest,
        policy: &PolicyIdentity,
        generation: u64,
    ) -> Result<(), Self::Error> {
        self.events
            .push(RecordedWindowsEffect::CommitAndActivateRollback {
                policy: policy.clone(),
                generation,
            });
        self.finish(WindowsEffectStage::CommitAndActivateRollback)
    }

    fn apply_recovery(&mut self, action: &RecoveryAction) -> Result<(), Self::Error> {
        self.events.push(RecordedWindowsEffect::ApplyRecovery {
            action: action.clone(),
        });
        self.finish(WindowsEffectStage::ApplyRecovery)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPolicyResult {
    pub state: PolicyActivationState,
    pub decision: PolicyActivationDecisionKind,
    pub reason: PolicyActivationReason,
    pub accepted: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
pub enum WindowsAdapterError {
    Bundle(RoutePolicyBundleError),
    Activation(PolicyActivationError),
    Status(String),
    MissingPolicy(String),
    Contract(String),
    Effect {
        stage: WindowsEffectStage,
        message: String,
        reducer_state: Box<PolicyActivationState>,
    },
}

impl fmt::Display for WindowsAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bundle(error) => write!(formatter, "signed policy bundle: {error}"),
            Self::Activation(error) => write!(formatter, "policy activation: {error}"),
            Self::Status(error) => formatter.write_str(error),
            Self::MissingPolicy(sha256) => {
                write!(
                    formatter,
                    "policy content {sha256} is unavailable to the adapter"
                )
            }
            Self::Contract(message) => write!(formatter, "activation contract: {message}"),
            Self::Effect { stage, message, .. } => {
                write!(formatter, "{} effect failed: {message}", stage.as_str())
            }
        }
    }
}

impl std::error::Error for WindowsAdapterError {}

impl From<RoutePolicyBundleError> for WindowsAdapterError {
    fn from(error: RoutePolicyBundleError) -> Self {
        Self::Bundle(error)
    }
}

impl From<PolicyActivationError> for WindowsAdapterError {
    fn from(error: PolicyActivationError) -> Self {
        Self::Activation(error)
    }
}

pub struct WindowsAdapterV1 {
    activation_state: PolicyActivationState,
    policies: BTreeMap<String, RoutePolicyManifest>,
    status: Option<StatusV2>,
}

impl WindowsAdapterV1 {
    pub fn new(bundled: RoutePolicyManifest) -> Self {
        let sha256 = route_policy_hash(&bundled);
        let identity = PolicyIdentity {
            kind: PolicyKind::Bundled,
            source: bundled.source.clone(),
            sha256: sha256.clone(),
        };
        let mut policies = BTreeMap::new();
        policies.insert(sha256, bundled);
        Self {
            activation_state: PolicyActivationState {
                bundled: identity.clone(),
                active: identity,
                trial_generation: 0,
                previous: None,
                candidate: None,
                phase: PolicyActivationPhase::Stable,
            },
            policies,
            status: None,
        }
    }

    pub fn activation_state(&self) -> &PolicyActivationState {
        &self.activation_state
    }

    pub fn status(&self) -> Option<&StatusV2> {
        self.status.as_ref()
    }

    pub fn active_manifest(&self) -> Result<&RoutePolicyManifest, WindowsAdapterError> {
        self.policies
            .get(&self.activation_state.active.sha256)
            .ok_or_else(|| {
                WindowsAdapterError::MissingPolicy(self.activation_state.active.sha256.clone())
            })
    }

    pub fn classify_host(&self, host: &str) -> Result<RoutePolicyResult, WindowsAdapterError> {
        let tables = self.active_manifest()?.routing_tables();
        Ok(classify_route_policy(host, &tables))
    }

    pub fn observe_status(&mut self, value: Value) -> Result<&StatusV2, WindowsAdapterError> {
        let status = status_v2_from_value(value).map_err(WindowsAdapterError::Status)?;
        self.status = Some(status);
        Ok(self.status.as_ref().expect("status was just stored"))
    }

    pub fn handle_connection_outcome<E: WindowsEffects>(
        &self,
        outcome: &ConnectionOutcome,
        context: &RecoveryContext,
        effects: &mut E,
    ) -> Result<Vec<RecoveryAction>, WindowsAdapterError> {
        let actions = reduce_connection_outcome(outcome, context);
        for action in &actions {
            if action.kind == RecoveryActionKind::None {
                continue;
            }
            effects
                .apply_recovery(action)
                .map_err(|error| WindowsAdapterError::Effect {
                    stage: WindowsEffectStage::ApplyRecovery,
                    message: error.to_string(),
                    reducer_state: Box::new(self.activation_state.clone()),
                })?;
        }
        Ok(actions)
    }

    pub fn verify_signed_bundle(
        &self,
        bundle: &Value,
        trusted_keys: &BTreeMap<String, String>,
    ) -> Result<RoutePolicyManifest, WindowsAdapterError> {
        Ok(verify_signed_route_policy_bundle(bundle, trusted_keys)?)
    }

    pub fn apply_signed_bundle<E: WindowsEffects>(
        &mut self,
        bundle: &Value,
        trusted_keys: &BTreeMap<String, String>,
        effects: &mut E,
    ) -> Result<WindowsPolicyResult, WindowsAdapterError> {
        let manifest = self.verify_signed_bundle(bundle, trusted_keys)?;
        let candidate = PolicyIdentity {
            kind: PolicyKind::Signed,
            source: manifest.source.clone(),
            sha256: route_policy_hash(&manifest),
        };
        self.activate_candidate(manifest, candidate, effects)
    }

    pub fn rollback<E: WindowsEffects>(
        &mut self,
        effects: &mut E,
    ) -> Result<WindowsPolicyResult, WindowsAdapterError> {
        let original_state = self.activation_state.clone();
        let transition = reduce_policy_activation(
            &original_state,
            &PolicyActivationEvent::Rollback {
                expected_active_sha256: original_state.active.sha256.clone(),
            },
        )?;

        match transition.decision {
            PolicyActivationDecisionKind::NoChange => {
                require_action_kinds(&transition.actions, &[])?;
                self.activation_state = transition.state.clone();
                Ok(policy_result(&transition, true, None))
            }
            PolicyActivationDecisionKind::TrialAborted => {
                self.run_rejection(&transition, effects, "rollback_requested")?;
                self.activation_state = transition.state.clone();
                Ok(policy_result(&transition, true, None))
            }
            PolicyActivationDecisionKind::RolledBack => {
                require_action_kinds(
                    &transition.actions,
                    &[
                        PolicyActivationActionKind::CommitRollback,
                        PolicyActivationActionKind::ActivateRollback,
                    ],
                )?;
                let action = &transition.actions[0];
                let manifest = self.manifest_for(&action.policy)?;
                if let Err(error) = effects.commit_and_activate_rollback(
                    &manifest,
                    &action.policy,
                    transition.state.trial_generation,
                ) {
                    return Ok(WindowsPolicyResult {
                        state: original_state,
                        decision: PolicyActivationDecisionKind::NoChange,
                        reason: transition.reason,
                        accepted: false,
                        error: Some(format!(
                            "commit_and_activate_rollback effect failed: {error}"
                        )),
                    });
                }
                self.activation_state = transition.state.clone();
                Ok(policy_result(&transition, true, None))
            }
            decision => Err(WindowsAdapterError::Contract(format!(
                "rollback returned unexpected decision {decision:?}"
            ))),
        }
    }

    fn activate_candidate<E: WindowsEffects>(
        &mut self,
        manifest: RoutePolicyManifest,
        candidate: PolicyIdentity,
        effects: &mut E,
    ) -> Result<WindowsPolicyResult, WindowsAdapterError> {
        let begin = reduce_policy_activation(
            &self.activation_state,
            &PolicyActivationEvent::BeginTrial {
                expected_active_sha256: self.activation_state.active.sha256.clone(),
                policy: candidate.clone(),
            },
        )?;

        if begin.decision == PolicyActivationDecisionKind::NoChange {
            require_action_kinds(&begin.actions, &[])?;
            self.activation_state = begin.state.clone();
            return Ok(policy_result(&begin, true, None));
        }

        require_action_kinds(
            &begin.actions,
            &[
                PolicyActivationActionKind::ActivateTrial,
                PolicyActivationActionKind::RunHealthGate,
            ],
        )?;
        let trial_state = begin.state.clone();
        self.activation_state = trial_state.clone();

        if let Err(error) = effects.persist_trial_generation(trial_state.trial_generation) {
            let detail = format!("persist_trial_generation effect failed: {error}");
            return self.abort_trial(&trial_state, effects, &detail);
        }

        if let Err(error) = effects.activate_trial(&manifest, &candidate) {
            let detail = format!("activate_trial effect failed: {error}");
            return self.abort_trial(&trial_state, effects, &detail);
        }

        let evidence =
            match effects.run_health_gate(&manifest, &candidate, trial_state.trial_generation) {
                Ok(evidence) => evidence,
                Err(error) => HealthEvidence {
                    completed: false,
                    ok: 0,
                    degraded: 0,
                    blocked: 0,
                    detail: format!("health gate error: {error}"),
                },
            };

        let health = match reduce_policy_activation(
            &trial_state,
            &PolicyActivationEvent::HealthResult {
                candidate_sha256: candidate.sha256.clone(),
                trial_generation: trial_state.trial_generation,
                completed: evidence.completed,
                ok: evidence.ok,
                degraded: evidence.degraded,
                blocked: evidence.blocked,
            },
        ) {
            Ok(transition) => transition,
            Err(error) => {
                let detail = if evidence.detail.is_empty() {
                    format!("health evidence invalid: {error}")
                } else {
                    evidence.detail
                };
                return self.abort_trial(&trial_state, effects, &detail);
            }
        };

        if health.decision == PolicyActivationDecisionKind::CandidateRejected {
            let detail = if evidence.detail.is_empty() {
                health.reason.as_str().to_owned()
            } else {
                evidence.detail
            };
            self.run_rejection(&health, effects, &detail)?;
            self.activation_state = health.state.clone();
            return Ok(policy_result(&health, false, Some(detail)));
        }

        require_action_kinds(
            &health.actions,
            &[PolicyActivationActionKind::CommitCandidate],
        )?;
        let commit = &health.actions[0];
        let previous = commit.previous.as_ref().ok_or_else(|| {
            WindowsAdapterError::Contract("commit_candidate omitted previous policy".to_owned())
        })?;
        if let Err(error) = effects.commit_candidate(
            &manifest,
            &commit.policy,
            previous,
            health.state.trial_generation,
        ) {
            let detail = format!("commit_candidate effect failed: {error}");
            return self.abort_trial(&trial_state, effects, &detail);
        }

        self.policies.insert(candidate.sha256.clone(), manifest);
        self.activation_state = health.state.clone();
        Ok(policy_result(&health, true, None))
    }

    fn abort_trial<E: WindowsEffects>(
        &mut self,
        trial_state: &PolicyActivationState,
        effects: &mut E,
        detail: &str,
    ) -> Result<WindowsPolicyResult, WindowsAdapterError> {
        let transition = reduce_policy_activation(
            trial_state,
            &PolicyActivationEvent::Rollback {
                expected_active_sha256: trial_state.active.sha256.clone(),
            },
        )?;
        self.run_rejection(&transition, effects, detail)?;
        self.activation_state = transition.state.clone();
        Ok(policy_result(&transition, false, Some(detail.to_owned())))
    }

    fn run_rejection<E: WindowsEffects>(
        &self,
        transition: &slipstream_core::route_policy_activation::PolicyActivationTransition,
        effects: &mut E,
        detail: &str,
    ) -> Result<(), WindowsAdapterError> {
        require_action_kinds(
            &transition.actions,
            &[
                PolicyActivationActionKind::RestoreActive,
                PolicyActivationActionKind::RecordRejection,
            ],
        )?;
        let restore = &transition.actions[0];
        let rejection = &transition.actions[1];
        let manifest = self.manifest_for(&restore.policy)?;
        let reason = if rejection.reason.is_empty() {
            transition.reason.as_str()
        } else {
            rejection.reason.as_str()
        };

        let mut first_failure = None;
        if let Err(error) = effects.restore_active(&manifest, &restore.policy) {
            first_failure = Some((WindowsEffectStage::RestoreActive, error.to_string()));
        }
        if let Err(error) = effects.record_rejection(&rejection.policy, reason, detail) {
            if first_failure.is_none() {
                first_failure = Some((WindowsEffectStage::RecordRejection, error.to_string()));
            }
        }
        if let Some((stage, message)) = first_failure {
            return Err(WindowsAdapterError::Effect {
                stage,
                message,
                reducer_state: Box::new(transition.state.clone()),
            });
        }
        Ok(())
    }

    fn manifest_for(
        &self,
        policy: &PolicyIdentity,
    ) -> Result<RoutePolicyManifest, WindowsAdapterError> {
        self.policies
            .get(&policy.sha256)
            .cloned()
            .ok_or_else(|| WindowsAdapterError::MissingPolicy(policy.sha256.clone()))
    }
}

fn policy_result(
    transition: &slipstream_core::route_policy_activation::PolicyActivationTransition,
    accepted: bool,
    error: Option<String>,
) -> WindowsPolicyResult {
    WindowsPolicyResult {
        state: transition.state.clone(),
        decision: transition.decision,
        reason: transition.reason,
        accepted,
        error,
    }
}

fn require_action_kinds(
    actions: &[PolicyActivationAction],
    expected: &[PolicyActivationActionKind],
) -> Result<(), WindowsAdapterError> {
    let actual: Vec<_> = actions.iter().map(|action| action.kind).collect();
    if actual == expected {
        return Ok(());
    }
    Err(WindowsAdapterError::Contract(format!(
        "emitted actions {actual:?}, expected {expected:?}"
    )))
}

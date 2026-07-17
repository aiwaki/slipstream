//! Pure version 1 activation and rollback reducer for verified route policies.

use serde::{Deserialize, Serialize};
use std::fmt;

pub const ROUTE_POLICY_ACTIVATION_CONTRACT_VERSION: u32 = 1;

const MAX_SOURCE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    Bundled,
    Signed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyIdentity {
    pub kind: PolicyKind,
    pub source: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActivationPhase {
    Stable,
    Trial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyActivationState {
    pub bundled: PolicyIdentity,
    pub active: PolicyIdentity,
    pub trial_generation: u64,
    pub previous: Option<PolicyIdentity>,
    pub candidate: Option<PolicyIdentity>,
    pub phase: PolicyActivationPhase,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyActivationEvent {
    BeginTrial {
        expected_active_sha256: String,
        policy: PolicyIdentity,
    },
    HealthResult {
        candidate_sha256: String,
        trial_generation: u64,
        completed: bool,
        ok: u32,
        degraded: u32,
        blocked: u32,
    },
    Rollback {
        expected_active_sha256: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActivationActionKind {
    ActivateTrial,
    RunHealthGate,
    CommitCandidate,
    RestoreActive,
    RecordRejection,
    CommitRollback,
    ActivateRollback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyActivationAction {
    pub kind: PolicyActivationActionKind,
    pub policy: PolicyIdentity,
    pub previous: Option<PolicyIdentity>,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActivationDecisionKind {
    TrialStarted,
    CandidateActivated,
    CandidateRejected,
    TrialAborted,
    RolledBack,
    NoChange,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActivationReason {
    CandidateVerified,
    AlreadyActive,
    HealthPassed,
    HealthIncomplete,
    HealthBlocked,
    HealthDegraded,
    HealthNoSuccess,
    RollbackRequested,
    PreviousPolicy,
    BundledPolicy,
    AlreadyBundled,
}

impl PolicyActivationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CandidateVerified => "candidate_verified",
            Self::AlreadyActive => "already_active",
            Self::HealthPassed => "health_passed",
            Self::HealthIncomplete => "health_incomplete",
            Self::HealthBlocked => "health_blocked",
            Self::HealthDegraded => "health_degraded",
            Self::HealthNoSuccess => "health_no_success",
            Self::RollbackRequested => "rollback_requested",
            Self::PreviousPolicy => "previous_policy",
            Self::BundledPolicy => "bundled_policy",
            Self::AlreadyBundled => "already_bundled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyActivationTransition {
    pub decision: PolicyActivationDecisionKind,
    pub reason: PolicyActivationReason,
    pub state: PolicyActivationState,
    pub actions: Vec<PolicyActivationAction>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActivationErrorCode {
    InvalidPolicyKind,
    InvalidSource,
    InvalidSha256,
    InvalidPhase,
    InconsistentState,
    CandidateInProgress,
    CandidateMustBeSigned,
    NoCandidate,
    StaleCandidate,
    StaleActive,
    StaleTrial,
    TrialGenerationExhausted,
}

impl PolicyActivationErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPolicyKind => "invalid_policy_kind",
            Self::InvalidSource => "invalid_source",
            Self::InvalidSha256 => "invalid_sha256",
            Self::InvalidPhase => "invalid_phase",
            Self::InconsistentState => "inconsistent_state",
            Self::CandidateInProgress => "candidate_in_progress",
            Self::CandidateMustBeSigned => "candidate_must_be_signed",
            Self::NoCandidate => "no_candidate",
            Self::StaleCandidate => "stale_candidate",
            Self::StaleActive => "stale_active",
            Self::StaleTrial => "stale_trial",
            Self::TrialGenerationExhausted => "trial_generation_exhausted",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyActivationError {
    pub code: PolicyActivationErrorCode,
    pub path: String,
    pub message: String,
}

impl PolicyActivationError {
    fn new(
        code: PolicyActivationErrorCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for PolicyActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at {}", self.message, self.path)
    }
}

impl std::error::Error for PolicyActivationError {}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_sha256(value: &str, path: &str) -> Result<(), PolicyActivationError> {
    if valid_sha256(value) {
        Ok(())
    } else {
        Err(PolicyActivationError::new(
            PolicyActivationErrorCode::InvalidSha256,
            path,
            "policy hash must be lowercase SHA-256",
        ))
    }
}

fn validate_policy(policy: &PolicyIdentity, path: &str) -> Result<(), PolicyActivationError> {
    if policy.source.trim().is_empty() {
        return Err(PolicyActivationError::new(
            PolicyActivationErrorCode::InvalidSource,
            format!("{path}.source"),
            "policy source must not be empty",
        ));
    }
    if policy.source.len() > MAX_SOURCE_BYTES {
        return Err(PolicyActivationError::new(
            PolicyActivationErrorCode::InvalidSource,
            format!("{path}.source"),
            format!("policy source exceeds {MAX_SOURCE_BYTES} bytes"),
        ));
    }
    validate_sha256(&policy.sha256, &format!("{path}.sha256"))
}

fn validate_bundled_identity(
    policy: &PolicyIdentity,
    bundled: &PolicyIdentity,
    path: &str,
) -> Result<(), PolicyActivationError> {
    if policy.kind == PolicyKind::Bundled && policy != bundled {
        return Err(PolicyActivationError::new(
            PolicyActivationErrorCode::InconsistentState,
            path,
            "bundled policy identity must match the fallback",
        ));
    }
    Ok(())
}

fn validate_state(state: &PolicyActivationState) -> Result<(), PolicyActivationError> {
    validate_policy(&state.bundled, "$.bundled")?;
    if state.bundled.kind != PolicyKind::Bundled {
        return Err(PolicyActivationError::new(
            PolicyActivationErrorCode::InvalidPolicyKind,
            "$.bundled.kind",
            "bundled fallback must use bundled policy kind",
        ));
    }

    validate_policy(&state.active, "$.active")?;
    validate_bundled_identity(&state.active, &state.bundled, "$.active")?;
    if let Some(previous) = &state.previous {
        validate_policy(previous, "$.previous")?;
        validate_bundled_identity(previous, &state.bundled, "$.previous")?;
        if previous == &state.active {
            return Err(PolicyActivationError::new(
                PolicyActivationErrorCode::InconsistentState,
                "$.previous.sha256",
                "previous policy must differ from the active policy",
            ));
        }
    }

    if state.phase == PolicyActivationPhase::Trial && state.trial_generation == 0 {
        return Err(PolicyActivationError::new(
            PolicyActivationErrorCode::InconsistentState,
            "$.trial_generation",
            "trial state requires a non-zero generation",
        ));
    }

    match (state.phase, &state.candidate) {
        (PolicyActivationPhase::Stable, None) => {}
        (PolicyActivationPhase::Stable, Some(_)) => {
            return Err(PolicyActivationError::new(
                PolicyActivationErrorCode::InconsistentState,
                "$.candidate",
                "stable state cannot contain a candidate",
            ));
        }
        (PolicyActivationPhase::Trial, None) => {
            return Err(PolicyActivationError::new(
                PolicyActivationErrorCode::InconsistentState,
                "$.candidate",
                "trial state requires a candidate",
            ));
        }
        (PolicyActivationPhase::Trial, Some(candidate)) => {
            validate_policy(candidate, "$.candidate")?;
            if candidate.kind != PolicyKind::Signed {
                return Err(PolicyActivationError::new(
                    PolicyActivationErrorCode::CandidateMustBeSigned,
                    "$.candidate.kind",
                    "candidate policy must be signed",
                ));
            }
            if candidate.sha256 == state.active.sha256 {
                return Err(PolicyActivationError::new(
                    PolicyActivationErrorCode::InconsistentState,
                    "$.candidate.sha256",
                    "candidate must differ from the active policy",
                ));
            }
        }
    }
    Ok(())
}

fn action(
    kind: PolicyActivationActionKind,
    policy: PolicyIdentity,
    previous: Option<PolicyIdentity>,
    reason: Option<PolicyActivationReason>,
) -> PolicyActivationAction {
    PolicyActivationAction {
        kind,
        policy,
        previous,
        reason: reason.map_or_else(String::new, |value| value.as_str().to_owned()),
    }
}

fn transition(
    decision: PolicyActivationDecisionKind,
    reason: PolicyActivationReason,
    state: PolicyActivationState,
    actions: Vec<PolicyActivationAction>,
) -> PolicyActivationTransition {
    PolicyActivationTransition {
        decision,
        reason,
        state,
        actions,
    }
}

fn require_expected_active(
    state: &PolicyActivationState,
    expected: &str,
) -> Result<(), PolicyActivationError> {
    validate_sha256(expected, "$.event.expected_active_sha256")?;
    if expected != state.active.sha256 {
        return Err(PolicyActivationError::new(
            PolicyActivationErrorCode::StaleActive,
            "$.event.expected_active_sha256",
            "event does not match the active policy",
        ));
    }
    Ok(())
}

fn begin_trial(
    state: &PolicyActivationState,
    expected_active_sha256: &str,
    policy: &PolicyIdentity,
) -> Result<PolicyActivationTransition, PolicyActivationError> {
    require_expected_active(state, expected_active_sha256)?;
    if state.phase == PolicyActivationPhase::Trial {
        return Err(PolicyActivationError::new(
            PolicyActivationErrorCode::CandidateInProgress,
            "$.phase",
            "another candidate is already in trial",
        ));
    }
    validate_policy(policy, "$.event.policy")?;
    if policy.kind != PolicyKind::Signed {
        return Err(PolicyActivationError::new(
            PolicyActivationErrorCode::CandidateMustBeSigned,
            "$.event.policy.kind",
            "candidate policy must be signed",
        ));
    }
    if policy.sha256 == state.active.sha256 {
        return Ok(transition(
            PolicyActivationDecisionKind::NoChange,
            PolicyActivationReason::AlreadyActive,
            state.clone(),
            Vec::new(),
        ));
    }

    let trial_generation = state.trial_generation.checked_add(1).ok_or_else(|| {
        PolicyActivationError::new(
            PolicyActivationErrorCode::TrialGenerationExhausted,
            "$.trial_generation",
            "trial generation is exhausted",
        )
    })?;

    let mut next_state = state.clone();
    next_state.candidate = Some(policy.clone());
    next_state.phase = PolicyActivationPhase::Trial;
    next_state.trial_generation = trial_generation;
    Ok(transition(
        PolicyActivationDecisionKind::TrialStarted,
        PolicyActivationReason::CandidateVerified,
        next_state,
        vec![
            action(
                PolicyActivationActionKind::ActivateTrial,
                policy.clone(),
                None,
                None,
            ),
            action(
                PolicyActivationActionKind::RunHealthGate,
                policy.clone(),
                None,
                None,
            ),
        ],
    ))
}

fn health_reason(completed: bool, ok: u32, degraded: u32, blocked: u32) -> PolicyActivationReason {
    if !completed {
        PolicyActivationReason::HealthIncomplete
    } else if blocked > 0 {
        PolicyActivationReason::HealthBlocked
    } else if degraded > 0 {
        PolicyActivationReason::HealthDegraded
    } else if ok == 0 {
        PolicyActivationReason::HealthNoSuccess
    } else {
        PolicyActivationReason::HealthPassed
    }
}

fn apply_health_result(
    state: &PolicyActivationState,
    candidate_sha256: &str,
    trial_generation: u64,
    completed: bool,
    ok: u32,
    degraded: u32,
    blocked: u32,
) -> Result<PolicyActivationTransition, PolicyActivationError> {
    let candidate = match (state.phase, &state.candidate) {
        (PolicyActivationPhase::Trial, Some(candidate)) => candidate,
        _ => {
            return Err(PolicyActivationError::new(
                PolicyActivationErrorCode::NoCandidate,
                "$.candidate",
                "no candidate is awaiting health",
            ));
        }
    };
    if trial_generation != state.trial_generation {
        return Err(PolicyActivationError::new(
            PolicyActivationErrorCode::StaleTrial,
            "$.event.trial_generation",
            "health result does not match the current trial generation",
        ));
    }
    validate_sha256(candidate_sha256, "$.event.candidate_sha256")?;
    if candidate_sha256 != candidate.sha256 {
        return Err(PolicyActivationError::new(
            PolicyActivationErrorCode::StaleCandidate,
            "$.event.candidate_sha256",
            "health result does not match the current candidate",
        ));
    }

    let reason = health_reason(completed, ok, degraded, blocked);
    if reason == PolicyActivationReason::HealthPassed {
        let next_state = PolicyActivationState {
            bundled: state.bundled.clone(),
            active: candidate.clone(),
            trial_generation: state.trial_generation,
            previous: Some(state.active.clone()),
            candidate: None,
            phase: PolicyActivationPhase::Stable,
        };
        return Ok(transition(
            PolicyActivationDecisionKind::CandidateActivated,
            reason,
            next_state,
            vec![action(
                PolicyActivationActionKind::CommitCandidate,
                candidate.clone(),
                Some(state.active.clone()),
                None,
            )],
        ));
    }

    let mut next_state = state.clone();
    next_state.candidate = None;
    next_state.phase = PolicyActivationPhase::Stable;
    Ok(transition(
        PolicyActivationDecisionKind::CandidateRejected,
        reason,
        next_state,
        vec![
            action(
                PolicyActivationActionKind::RestoreActive,
                state.active.clone(),
                None,
                None,
            ),
            action(
                PolicyActivationActionKind::RecordRejection,
                candidate.clone(),
                None,
                Some(reason),
            ),
        ],
    ))
}

fn rollback(
    state: &PolicyActivationState,
    expected_active_sha256: &str,
) -> Result<PolicyActivationTransition, PolicyActivationError> {
    require_expected_active(state, expected_active_sha256)?;
    if state.phase == PolicyActivationPhase::Trial {
        let candidate = state
            .candidate
            .as_ref()
            .expect("validated trial state has a candidate");
        let mut next_state = state.clone();
        next_state.candidate = None;
        next_state.phase = PolicyActivationPhase::Stable;
        return Ok(transition(
            PolicyActivationDecisionKind::TrialAborted,
            PolicyActivationReason::RollbackRequested,
            next_state,
            vec![
                action(
                    PolicyActivationActionKind::RestoreActive,
                    state.active.clone(),
                    None,
                    None,
                ),
                action(
                    PolicyActivationActionKind::RecordRejection,
                    candidate.clone(),
                    None,
                    Some(PolicyActivationReason::RollbackRequested),
                ),
            ],
        ));
    }

    let (target, reason) = match &state.previous {
        Some(previous) => (previous.clone(), PolicyActivationReason::PreviousPolicy),
        None => (state.bundled.clone(), PolicyActivationReason::BundledPolicy),
    };
    if target == state.active {
        return Ok(transition(
            PolicyActivationDecisionKind::NoChange,
            PolicyActivationReason::AlreadyBundled,
            state.clone(),
            Vec::new(),
        ));
    }

    let next_state = PolicyActivationState {
        bundled: state.bundled.clone(),
        active: target.clone(),
        trial_generation: state.trial_generation,
        previous: None,
        candidate: None,
        phase: PolicyActivationPhase::Stable,
    };
    Ok(transition(
        PolicyActivationDecisionKind::RolledBack,
        reason,
        next_state,
        vec![
            action(
                PolicyActivationActionKind::CommitRollback,
                target.clone(),
                None,
                None,
            ),
            action(
                PolicyActivationActionKind::ActivateRollback,
                target,
                None,
                None,
            ),
        ],
    ))
}

pub fn reduce_policy_activation(
    state: &PolicyActivationState,
    event: &PolicyActivationEvent,
) -> Result<PolicyActivationTransition, PolicyActivationError> {
    validate_state(state)?;
    match event {
        PolicyActivationEvent::BeginTrial {
            expected_active_sha256,
            policy,
        } => begin_trial(state, expected_active_sha256, policy),
        PolicyActivationEvent::HealthResult {
            candidate_sha256,
            trial_generation,
            completed,
            ok,
            degraded,
            blocked,
        } => apply_health_result(
            state,
            candidate_sha256,
            *trial_generation,
            *completed,
            *ok,
            *degraded,
            *blocked,
        ),
        PolicyActivationEvent::Rollback {
            expected_active_sha256,
        } => rollback(state, expected_active_sha256),
    }
}

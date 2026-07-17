"""Pure signed route-policy activation and rollback state machine."""

from dataclasses import dataclass, replace


CONTRACT_VERSION = 1
MAX_SOURCE_BYTES = 128
MAX_COUNTER = (1 << 32) - 1

POLICY_BUNDLED = "bundled"
POLICY_SIGNED = "signed"

PHASE_STABLE = "stable"
PHASE_TRIAL = "trial"

EVENT_BEGIN_TRIAL = "begin_trial"
EVENT_HEALTH_RESULT = "health_result"
EVENT_ROLLBACK = "rollback"

DECISION_TRIAL_STARTED = "trial_started"
DECISION_CANDIDATE_ACTIVATED = "candidate_activated"
DECISION_CANDIDATE_REJECTED = "candidate_rejected"
DECISION_TRIAL_ABORTED = "trial_aborted"
DECISION_ROLLED_BACK = "rolled_back"
DECISION_NO_CHANGE = "no_change"

REASON_CANDIDATE_VERIFIED = "candidate_verified"
REASON_ALREADY_ACTIVE = "already_active"
REASON_HEALTH_PASSED = "health_passed"
REASON_HEALTH_INCOMPLETE = "health_incomplete"
REASON_HEALTH_BLOCKED = "health_blocked"
REASON_HEALTH_DEGRADED = "health_degraded"
REASON_HEALTH_NO_SUCCESS = "health_no_success"
REASON_ROLLBACK_REQUESTED = "rollback_requested"
REASON_PREVIOUS_POLICY = "previous_policy"
REASON_BUNDLED_POLICY = "bundled_policy"
REASON_ALREADY_BUNDLED = "already_bundled"

ACTION_ACTIVATE_TRIAL = "activate_trial"
ACTION_RUN_HEALTH_GATE = "run_health_gate"
ACTION_COMMIT_CANDIDATE = "commit_candidate"
ACTION_RESTORE_ACTIVE = "restore_active"
ACTION_RECORD_REJECTION = "record_rejection"
ACTION_COMMIT_ROLLBACK = "commit_rollback"
ACTION_ACTIVATE_ROLLBACK = "activate_rollback"

ERROR_INVALID_POLICY_KIND = "invalid_policy_kind"
ERROR_INVALID_SOURCE = "invalid_source"
ERROR_INVALID_SHA256 = "invalid_sha256"
ERROR_INVALID_PHASE = "invalid_phase"
ERROR_INCONSISTENT_STATE = "inconsistent_state"
ERROR_CANDIDATE_IN_PROGRESS = "candidate_in_progress"
ERROR_CANDIDATE_MUST_BE_SIGNED = "candidate_must_be_signed"
ERROR_NO_CANDIDATE = "no_candidate"
ERROR_STALE_CANDIDATE = "stale_candidate"
ERROR_STALE_ACTIVE = "stale_active"
ERROR_INVALID_COUNTER = "invalid_counter"
ERROR_UNSUPPORTED_EVENT = "unsupported_event"


@dataclass(frozen=True)
class PolicyIdentity:
    kind: str
    source: str
    sha256: str


@dataclass(frozen=True)
class PolicyActivationState:
    bundled: PolicyIdentity
    active: PolicyIdentity
    previous: PolicyIdentity | None = None
    candidate: PolicyIdentity | None = None
    phase: str = PHASE_STABLE


@dataclass(frozen=True)
class PolicyActivationEvent:
    kind: str
    expected_active_sha256: str = ""
    policy: PolicyIdentity | None = None
    candidate_sha256: str = ""
    completed: bool = False
    ok: int = 0
    degraded: int = 0
    blocked: int = 0


@dataclass(frozen=True)
class PolicyActivationAction:
    kind: str
    policy: PolicyIdentity
    previous: PolicyIdentity | None = None
    reason: str = ""


@dataclass(frozen=True)
class PolicyActivationTransition:
    decision: str
    reason: str
    state: PolicyActivationState
    actions: tuple[PolicyActivationAction, ...] = ()


class PolicyActivationError(ValueError):
    def __init__(self, code, path, message):
        super().__init__(f"{message} at {path}")
        self.code = code
        self.path = path
        self.message = message


def _error(code, path, message):
    raise PolicyActivationError(code, path, message)


def _valid_sha256(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_sha256(value, path):
    if not _valid_sha256(value):
        _error(ERROR_INVALID_SHA256, path, "policy hash must be lowercase SHA-256")


def _validate_policy(policy, path):
    if not isinstance(policy, PolicyIdentity):
        _error(ERROR_INCONSISTENT_STATE, path, "policy identity is required")
    if policy.kind not in (POLICY_BUNDLED, POLICY_SIGNED):
        _error(ERROR_INVALID_POLICY_KIND, f"{path}.kind", "unsupported policy kind")
    if not isinstance(policy.source, str) or not policy.source.strip():
        _error(ERROR_INVALID_SOURCE, f"{path}.source", "policy source must not be empty")
    if len(policy.source.encode("utf-8")) > MAX_SOURCE_BYTES:
        _error(
            ERROR_INVALID_SOURCE,
            f"{path}.source",
            f"policy source exceeds {MAX_SOURCE_BYTES} bytes",
        )
    _validate_sha256(policy.sha256, f"{path}.sha256")


def _validate_state(state):
    if not isinstance(state, PolicyActivationState):
        _error(ERROR_INCONSISTENT_STATE, "$", "activation state is required")

    _validate_policy(state.bundled, "$.bundled")
    if state.bundled.kind != POLICY_BUNDLED:
        _error(
            ERROR_INVALID_POLICY_KIND,
            "$.bundled.kind",
            "bundled fallback must use bundled policy kind",
        )

    for name, policy in (("active", state.active), ("previous", state.previous)):
        if policy is None:
            if name == "active":
                _error(ERROR_INCONSISTENT_STATE, "$.active", "active policy is required")
            continue
        _validate_policy(policy, f"$.{name}")
        if policy.kind == POLICY_BUNDLED and policy != state.bundled:
            _error(
                ERROR_INCONSISTENT_STATE,
                f"$.{name}",
                "bundled policy identity must match the fallback",
            )

    if state.previous is not None and state.previous == state.active:
        _error(
            ERROR_INCONSISTENT_STATE,
            "$.previous.sha256",
            "previous policy must differ from the active policy",
        )

    if state.phase not in (PHASE_STABLE, PHASE_TRIAL):
        _error(ERROR_INVALID_PHASE, "$.phase", "unsupported activation phase")
    if state.phase == PHASE_STABLE and state.candidate is not None:
        _error(
            ERROR_INCONSISTENT_STATE,
            "$.candidate",
            "stable state cannot contain a candidate",
        )
    if state.phase == PHASE_TRIAL and state.candidate is None:
        _error(
            ERROR_INCONSISTENT_STATE,
            "$.candidate",
            "trial state requires a candidate",
        )
    if state.candidate is not None:
        _validate_policy(state.candidate, "$.candidate")
        if state.candidate.kind != POLICY_SIGNED:
            _error(
                ERROR_CANDIDATE_MUST_BE_SIGNED,
                "$.candidate.kind",
                "candidate policy must be signed",
            )
        if state.candidate.sha256 == state.active.sha256:
            _error(
                ERROR_INCONSISTENT_STATE,
                "$.candidate.sha256",
                "candidate must differ from the active policy",
            )


def _validate_counter(value, path):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_COUNTER:
        _error(ERROR_INVALID_COUNTER, path, "health counter must be an unsigned 32-bit integer")


def _action(kind, policy, *, previous=None, reason=""):
    return PolicyActivationAction(kind, policy, previous, reason)


def _health_reason(event):
    if not isinstance(event.completed, bool):
        _error(ERROR_INVALID_COUNTER, "$.event.completed", "completed must be boolean")
    _validate_counter(event.ok, "$.event.ok")
    _validate_counter(event.degraded, "$.event.degraded")
    _validate_counter(event.blocked, "$.event.blocked")
    if not event.completed:
        return REASON_HEALTH_INCOMPLETE
    if event.blocked:
        return REASON_HEALTH_BLOCKED
    if event.degraded:
        return REASON_HEALTH_DEGRADED
    if not event.ok:
        return REASON_HEALTH_NO_SUCCESS
    return REASON_HEALTH_PASSED


def _require_expected_active(state, expected):
    _validate_sha256(expected, "$.event.expected_active_sha256")
    if expected != state.active.sha256:
        _error(
            ERROR_STALE_ACTIVE,
            "$.event.expected_active_sha256",
            "event does not match the active policy",
        )


def _begin_trial(state, event):
    _require_expected_active(state, event.expected_active_sha256)
    if state.phase == PHASE_TRIAL:
        _error(
            ERROR_CANDIDATE_IN_PROGRESS,
            "$.phase",
            "another candidate is already in trial",
        )
    _validate_policy(event.policy, "$.event.policy")
    if event.policy.kind != POLICY_SIGNED:
        _error(
            ERROR_CANDIDATE_MUST_BE_SIGNED,
            "$.event.policy.kind",
            "candidate policy must be signed",
        )
    if event.policy.sha256 == state.active.sha256:
        return PolicyActivationTransition(
            DECISION_NO_CHANGE,
            REASON_ALREADY_ACTIVE,
            state,
        )

    next_state = replace(state, candidate=event.policy, phase=PHASE_TRIAL)
    return PolicyActivationTransition(
        DECISION_TRIAL_STARTED,
        REASON_CANDIDATE_VERIFIED,
        next_state,
        (
            _action(ACTION_ACTIVATE_TRIAL, event.policy),
            _action(ACTION_RUN_HEALTH_GATE, event.policy),
        ),
    )


def _apply_health_result(state, event):
    if state.phase != PHASE_TRIAL or state.candidate is None:
        _error(ERROR_NO_CANDIDATE, "$.candidate", "no candidate is awaiting health")
    _validate_sha256(event.candidate_sha256, "$.event.candidate_sha256")
    if event.candidate_sha256 != state.candidate.sha256:
        _error(
            ERROR_STALE_CANDIDATE,
            "$.event.candidate_sha256",
            "health result does not match the current candidate",
        )

    reason = _health_reason(event)
    candidate = state.candidate
    if reason == REASON_HEALTH_PASSED:
        next_state = PolicyActivationState(
            bundled=state.bundled,
            active=candidate,
            previous=state.active,
            candidate=None,
            phase=PHASE_STABLE,
        )
        return PolicyActivationTransition(
            DECISION_CANDIDATE_ACTIVATED,
            reason,
            next_state,
            (
                _action(
                    ACTION_COMMIT_CANDIDATE,
                    candidate,
                    previous=state.active,
                ),
            ),
        )

    next_state = replace(state, candidate=None, phase=PHASE_STABLE)
    return PolicyActivationTransition(
        DECISION_CANDIDATE_REJECTED,
        reason,
        next_state,
        (
            _action(ACTION_RESTORE_ACTIVE, state.active),
            _action(ACTION_RECORD_REJECTION, candidate, reason=reason),
        ),
    )


def _rollback(state, event):
    _require_expected_active(state, event.expected_active_sha256)
    if state.phase == PHASE_TRIAL:
        candidate = state.candidate
        next_state = replace(state, candidate=None, phase=PHASE_STABLE)
        return PolicyActivationTransition(
            DECISION_TRIAL_ABORTED,
            REASON_ROLLBACK_REQUESTED,
            next_state,
            (
                _action(ACTION_RESTORE_ACTIVE, state.active),
                _action(
                    ACTION_RECORD_REJECTION,
                    candidate,
                    reason=REASON_ROLLBACK_REQUESTED,
                ),
            ),
        )

    target = state.previous or state.bundled
    if target == state.active:
        return PolicyActivationTransition(
            DECISION_NO_CHANGE,
            REASON_ALREADY_BUNDLED,
            state,
        )

    reason = REASON_PREVIOUS_POLICY if state.previous is not None else REASON_BUNDLED_POLICY
    next_state = PolicyActivationState(
        bundled=state.bundled,
        active=target,
        previous=None,
        candidate=None,
        phase=PHASE_STABLE,
    )
    return PolicyActivationTransition(
        DECISION_ROLLED_BACK,
        reason,
        next_state,
        (
            _action(ACTION_COMMIT_ROLLBACK, target),
            _action(ACTION_ACTIVATE_ROLLBACK, target),
        ),
    )


def reduce_policy_activation(state, event):
    """Reduce one verified-policy event without performing adapter effects."""
    _validate_state(state)
    if not isinstance(event, PolicyActivationEvent):
        _error(ERROR_UNSUPPORTED_EVENT, "$.event", "activation event is required")
    if event.kind == EVENT_BEGIN_TRIAL:
        return _begin_trial(state, event)
    if event.kind == EVENT_HEALTH_RESULT:
        return _apply_health_result(state, event)
    if event.kind == EVENT_ROLLBACK:
        return _rollback(state, event)
    _error(ERROR_UNSUPPORTED_EVENT, "$.event.kind", "unsupported activation event")

"""Effect adapter for the pure signed route-policy activation reducer."""

from dataclasses import dataclass
from typing import Any, Callable

import route_policy_activation as activation


@dataclass(frozen=True)
class HealthEvidence:
    completed: bool
    ok: int = 0
    degraded: int = 0
    blocked: int = 0
    detail: str = ""


@dataclass(frozen=True)
class CandidateEffects:
    activate_trial: Callable[[activation.PolicyIdentity], None]
    run_health_gate: Callable[[activation.PolicyIdentity, int], HealthEvidence]
    commit_candidate: Callable[
        [activation.PolicyIdentity, activation.PolicyIdentity, int], Any
    ]
    restore_active: Callable[[activation.PolicyIdentity], None]
    record_rejection: Callable[[activation.PolicyIdentity, str, str], None]


@dataclass(frozen=True)
class RollbackEffects:
    commit_rollback: Callable[[activation.PolicyIdentity, int], Any]
    restore_active: Callable[[activation.PolicyIdentity], None]
    record_rejection: Callable[[activation.PolicyIdentity, str, str], None]


@dataclass(frozen=True)
class AdapterResult:
    state: activation.PolicyActivationState
    decision: str
    reason: str
    accepted: bool
    value: Any = None
    error: str = ""


class PolicyActivationAdapterError(RuntimeError):
    """An adapter compensation failed, so the concrete state is uncertain."""

    def __init__(self, stage, cause, state):
        super().__init__(f"{stage} effect failed: {cause}")
        self.stage = stage
        self.cause = cause
        self.state = state


def _require_actions(transition, expected):
    actual = tuple(action.kind for action in transition.actions)
    if actual != tuple(expected):
        raise RuntimeError(
            f"activation contract emitted actions {actual!r}, expected {tuple(expected)!r}"
        )


def _run_rejection(transition, effects, detail):
    _require_actions(
        transition,
        (activation.ACTION_RESTORE_ACTIVE, activation.ACTION_RECORD_REJECTION),
    )
    restore_action, reject_action = transition.actions
    failures = []
    try:
        effects.restore_active(restore_action.policy)
    except Exception as exc:  # pragma: no cover - paired failure is asserted by caller
        failures.append(("restore_active", exc))
    try:
        effects.record_rejection(
            reject_action.policy,
            reject_action.reason or transition.reason,
            detail,
        )
    except Exception as exc:  # pragma: no cover - paired failure is asserted by caller
        failures.append(("record_rejection", exc))
    if failures:
        stage, cause = failures[0]
        raise PolicyActivationAdapterError(stage, cause, transition.state)


def _abort_trial(trial_state, effects, detail):
    transition = activation.reduce_policy_activation(
        trial_state,
        activation.PolicyActivationEvent(
            kind=activation.EVENT_ROLLBACK,
            expected_active_sha256=trial_state.active.sha256,
        ),
    )
    _run_rejection(transition, effects, detail)
    return transition


def activate_candidate(state, candidate, effects):
    """Run one verified candidate trial and compensate every failed effect."""
    begin = activation.reduce_policy_activation(
        state,
        activation.PolicyActivationEvent(
            kind=activation.EVENT_BEGIN_TRIAL,
            expected_active_sha256=state.active.sha256,
            policy=candidate,
        ),
    )
    if begin.decision == activation.DECISION_NO_CHANGE:
        _require_actions(begin, ())
        return AdapterResult(
            state=begin.state,
            decision=begin.decision,
            reason=begin.reason,
            accepted=True,
        )

    _require_actions(
        begin,
        (activation.ACTION_ACTIVATE_TRIAL, activation.ACTION_RUN_HEALTH_GATE),
    )
    trial_state = begin.state
    try:
        effects.activate_trial(begin.actions[0].policy)
    except Exception as exc:
        detail = f"activate_trial effect failed: {exc}"
        aborted = _abort_trial(trial_state, effects, detail)
        return AdapterResult(
            state=aborted.state,
            decision=aborted.decision,
            reason=aborted.reason,
            accepted=False,
            error=detail,
        )

    try:
        evidence = effects.run_health_gate(candidate, trial_state.trial_generation)
    except Exception as exc:
        evidence = HealthEvidence(
            completed=False,
            detail=f"health gate error: {exc}",
        )

    try:
        health = activation.reduce_policy_activation(
            trial_state,
            activation.PolicyActivationEvent(
                kind=activation.EVENT_HEALTH_RESULT,
                candidate_sha256=candidate.sha256,
                trial_generation=trial_state.trial_generation,
                completed=evidence.completed,
                ok=evidence.ok,
                degraded=evidence.degraded,
                blocked=evidence.blocked,
            ),
        )
    except activation.PolicyActivationError as exc:
        detail = evidence.detail or f"health evidence invalid: {exc}"
        aborted = _abort_trial(trial_state, effects, detail)
        return AdapterResult(
            state=aborted.state,
            decision=aborted.decision,
            reason=aborted.reason,
            accepted=False,
            error=detail,
        )

    if health.decision == activation.DECISION_CANDIDATE_REJECTED:
        detail = evidence.detail or health.reason
        _run_rejection(health, effects, detail)
        return AdapterResult(
            state=health.state,
            decision=health.decision,
            reason=health.reason,
            accepted=False,
            error=detail,
        )

    _require_actions(health, (activation.ACTION_COMMIT_CANDIDATE,))
    commit = health.actions[0]
    try:
        value = effects.commit_candidate(
            commit.policy,
            commit.previous,
            health.state.trial_generation,
        )
    except Exception as exc:
        detail = f"commit_candidate effect failed: {exc}"
        aborted = _abort_trial(trial_state, effects, detail)
        return AdapterResult(
            state=aborted.state,
            decision=aborted.decision,
            reason=aborted.reason,
            accepted=False,
            error=detail,
        )

    return AdapterResult(
        state=health.state,
        decision=health.decision,
        reason=health.reason,
        accepted=True,
        value=value,
    )


def rollback_policy(state, effects):
    """Apply one reducer-authorized rollback through an atomic concrete effect."""
    transition = activation.reduce_policy_activation(
        state,
        activation.PolicyActivationEvent(
            kind=activation.EVENT_ROLLBACK,
            expected_active_sha256=state.active.sha256,
        ),
    )
    if transition.decision == activation.DECISION_NO_CHANGE:
        _require_actions(transition, ())
        return AdapterResult(
            state=transition.state,
            decision=transition.decision,
            reason=transition.reason,
            accepted=True,
        )
    if transition.decision == activation.DECISION_TRIAL_ABORTED:
        _run_rejection(transition, effects, activation.REASON_ROLLBACK_REQUESTED)
        return AdapterResult(
            state=transition.state,
            decision=transition.decision,
            reason=transition.reason,
            accepted=True,
        )

    _require_actions(
        transition,
        (activation.ACTION_COMMIT_ROLLBACK, activation.ACTION_ACTIVATE_ROLLBACK),
    )
    try:
        value = effects.commit_rollback(
            transition.actions[0].policy,
            transition.state.trial_generation,
        )
    except Exception as exc:
        return AdapterResult(
            state=state,
            decision=activation.DECISION_NO_CHANGE,
            reason=transition.reason,
            accepted=False,
            error=f"commit_rollback effect failed: {exc}",
        )
    return AdapterResult(
        state=transition.state,
        decision=transition.decision,
        reason=transition.reason,
        accepted=True,
        value=value,
    )

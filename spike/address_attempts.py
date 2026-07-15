"""Pure deterministic address-attempt planning with no DNS or socket I/O."""

from dataclasses import dataclass
from typing import Optional


FAMILY_IPV4 = "ipv4"
FAMILY_IPV6 = "ipv6"

ATTEMPT_RUNNING = "running"
ATTEMPT_FAILED = "failed"
ATTEMPT_SUCCEEDED = "succeeded"
ATTEMPT_CANCELLED = "cancelled"

DECISION_START = "start"
DECISION_WAIT = "wait"
DECISION_SELECT = "select"
DECISION_TIMEOUT = "timeout"
DECISION_EXHAUSTED = "exhausted"


@dataclass(frozen=True)
class AddressCandidate:
    id: str
    family: str
    address: str
    source: str
    expires_at_ms: Optional[int] = None


@dataclass(frozen=True)
class AddressAttempt:
    candidate_id: str
    state: str
    started_at_ms: int
    completed_at_ms: Optional[int] = None


@dataclass(frozen=True)
class AddressPlanContext:
    now_ms: int
    started_at_ms: int
    deadline_at_ms: int
    stagger_ms: int
    max_concurrent: int
    preferred_family: str


@dataclass(frozen=True)
class AddressPlanDecision:
    kind: str
    candidate_id: str = ""
    cancel: tuple = ()
    wake_at_ms: Optional[int] = None


@dataclass(frozen=True)
class AddressPlanResult:
    ordered_candidates: tuple
    decision: AddressPlanDecision


def _validate_context(context):
    if context.preferred_family not in (FAMILY_IPV4, FAMILY_IPV6):
        raise ValueError("preferred_family must be ipv4 or ipv6")
    if context.max_concurrent < 1:
        raise ValueError("max_concurrent must be positive")
    if context.stagger_ms < 0:
        raise ValueError("stagger_ms must not be negative")
    if context.deadline_at_ms <= context.started_at_ms:
        raise ValueError("deadline must be after the race start")


def _ordered_candidates(candidates, attempts, context):
    candidate_ids = set()
    for candidate in candidates:
        if not candidate.id or not candidate.address:
            raise ValueError("candidate id and address must not be empty")
        if candidate.id in candidate_ids:
            raise ValueError("candidate ids must be unique")
        if candidate.family not in (FAMILY_IPV4, FAMILY_IPV6):
            raise ValueError("candidate family must be ipv4 or ipv6")
        candidate_ids.add(candidate.id)

    attempt_ids = set()
    for attempt in attempts:
        if attempt.candidate_id in attempt_ids:
            raise ValueError("attempt candidate ids must be unique")
        if attempt.candidate_id not in candidate_ids:
            raise ValueError("attempt references an unknown candidate")
        if attempt.state not in (
            ATTEMPT_RUNNING,
            ATTEMPT_FAILED,
            ATTEMPT_SUCCEEDED,
            ATTEMPT_CANCELLED,
        ):
            raise ValueError("unknown attempt state")
        if attempt.state == ATTEMPT_SUCCEEDED and attempt.completed_at_ms is None:
            raise ValueError("successful attempt requires completed_at_ms")
        attempt_ids.add(attempt.candidate_id)

    by_family = {FAMILY_IPV4: [], FAMILY_IPV6: []}
    seen_addresses = set()
    for candidate in candidates:
        already_started = candidate.id in attempt_ids
        unexpired = (
            candidate.expires_at_ms is None
            or candidate.expires_at_ms > context.now_ms
        )
        if not already_started and not unexpired:
            continue
        address_key = (candidate.family, candidate.address)
        if address_key in seen_addresses:
            if already_started:
                raise ValueError("attempt references a duplicate address candidate")
            continue
        seen_addresses.add(address_key)
        by_family[candidate.family].append(candidate)

    preferred = by_family[context.preferred_family]
    alternate_family = (
        FAMILY_IPV4 if context.preferred_family == FAMILY_IPV6 else FAMILY_IPV6
    )
    alternate = by_family[alternate_family]
    ordered = []
    for index in range(max(len(preferred), len(alternate))):
        if index < len(preferred):
            ordered.append(preferred[index])
        if index < len(alternate):
            ordered.append(alternate[index])
    return ordered


def plan_address_attempts(candidates, attempts, context):
    """Return the next bounded Happy-Eyeballs-style action for one snapshot."""
    _validate_context(context)
    ordered = _ordered_candidates(candidates, attempts, context)
    ordered_ids = tuple(candidate.id for candidate in ordered)
    order_index = {candidate_id: index for index, candidate_id in enumerate(ordered_ids)}
    attempts_by_id = {attempt.candidate_id: attempt for attempt in attempts}

    missing = set(attempts_by_id) - set(ordered_ids)
    if missing:
        raise ValueError("attempt references a candidate unavailable to this plan")

    successful = [
        attempt for attempt in attempts if attempt.state == ATTEMPT_SUCCEEDED
    ]
    if successful:
        winner = min(
            successful,
            key=lambda attempt: (
                attempt.completed_at_ms,
                order_index[attempt.candidate_id],
            ),
        )
        cancel = tuple(
            candidate_id
            for candidate_id in ordered_ids
            if candidate_id != winner.candidate_id
            and attempts_by_id.get(candidate_id)
            and attempts_by_id[candidate_id].state == ATTEMPT_RUNNING
        )
        return AddressPlanResult(
            ordered_ids,
            AddressPlanDecision(DECISION_SELECT, winner.candidate_id, cancel),
        )

    running = [attempt for attempt in attempts if attempt.state == ATTEMPT_RUNNING]
    if context.now_ms >= context.deadline_at_ms:
        cancel = tuple(
            candidate_id
            for candidate_id in ordered_ids
            if attempts_by_id.get(candidate_id)
            and attempts_by_id[candidate_id].state == ATTEMPT_RUNNING
        )
        return AddressPlanResult(
            ordered_ids,
            AddressPlanDecision(DECISION_TIMEOUT, cancel=cancel),
        )

    pending = [
        candidate_id for candidate_id in ordered_ids if candidate_id not in attempts_by_id
    ]
    if not pending:
        if running:
            return AddressPlanResult(
                ordered_ids,
                AddressPlanDecision(
                    DECISION_WAIT, wake_at_ms=context.deadline_at_ms
                ),
            )
        return AddressPlanResult(
            ordered_ids,
            AddressPlanDecision(DECISION_EXHAUSTED),
        )

    if not running:
        return AddressPlanResult(
            ordered_ids,
            AddressPlanDecision(DECISION_START, pending[0]),
        )

    if len(running) >= context.max_concurrent:
        return AddressPlanResult(
            ordered_ids,
            AddressPlanDecision(DECISION_WAIT, wake_at_ms=context.deadline_at_ms),
        )

    next_start_at = max(attempt.started_at_ms for attempt in attempts) + context.stagger_ms
    if context.now_ms >= next_start_at:
        return AddressPlanResult(
            ordered_ids,
            AddressPlanDecision(DECISION_START, pending[0]),
        )

    return AddressPlanResult(
        ordered_ids,
        AddressPlanDecision(
            DECISION_WAIT,
            wake_at_ms=min(next_start_at, context.deadline_at_ms),
        ),
    )

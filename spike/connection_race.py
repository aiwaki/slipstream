"""Pure connection-race orchestration with no DNS, clock, or socket I/O."""

from dataclasses import dataclass, replace
from typing import Optional

import address_attempts
import route_circuit


PHASE_RESOLVING = "resolving"
PHASE_CONNECTING = "connecting"
PHASE_CONNECTED = "connected"
PHASE_REJECTED = "rejected"
PHASE_FAILED = "failed"
PHASE_TIMED_OUT = "timed_out"
PHASE_EXHAUSTED = "exhausted"

EVENT_RESOLVED = "resolved"
EVENT_RESOLVE_FAILED = "resolve_failed"
EVENT_ATTEMPT_SUCCEEDED = "attempt_succeeded"
EVENT_ATTEMPT_FAILED = "attempt_failed"
EVENT_WAKE = "wake"

COMMAND_RESOLVE = "resolve"
COMMAND_START = "start"
COMMAND_CANCEL = "cancel"
COMMAND_WAKE = "wake"

TERMINAL_PHASES = frozenset(
    (
        PHASE_CONNECTED,
        PHASE_REJECTED,
        PHASE_FAILED,
        PHASE_TIMED_OUT,
        PHASE_EXHAUSTED,
    )
)


@dataclass(frozen=True)
class ConnectionRaceConfig:
    timeout_ms: int
    stagger_ms: int
    max_concurrent: int
    preferred_family: str


@dataclass(frozen=True)
class ConnectionRaceState:
    key: route_circuit.RouteCircuitKey
    phase: str
    started_at_ms: int
    updated_at_ms: int
    deadline_at_ms: int
    candidates: tuple = ()
    attempts: tuple = ()
    winner_candidate_id: str = ""
    reason: str = ""


@dataclass(frozen=True)
class ConnectionRaceEvent:
    kind: str
    now_ms: int
    candidate_id: str = ""
    candidates: tuple = ()


@dataclass(frozen=True)
class ConnectionRaceCommand:
    kind: str
    candidate_id: str = ""
    at_ms: Optional[int] = None


@dataclass(frozen=True)
class ConnectionRaceTransition:
    state: ConnectionRaceState
    circuit_states: dict
    commands: tuple = ()
    circuit_decisions: tuple = ()


def _validate_config(config):
    if config.timeout_ms < 1:
        raise ValueError("timeout_ms must be positive")
    if config.stagger_ms < 0:
        raise ValueError("stagger_ms must not be negative")
    if config.max_concurrent < 1:
        raise ValueError("max_concurrent must be positive")
    if config.preferred_family not in (
        address_attempts.FAMILY_IPV4,
        address_attempts.FAMILY_IPV6,
    ):
        raise ValueError("preferred_family must be ipv4 or ipv6")


def _address_context(state, config, now_ms):
    return address_attempts.AddressPlanContext(
        now_ms=now_ms,
        started_at_ms=state.started_at_ms,
        deadline_at_ms=state.deadline_at_ms,
        stagger_ms=config.stagger_ms,
        max_concurrent=config.max_concurrent,
        preferred_family=config.preferred_family,
    )


def _record_terminal(
    circuit_states,
    state,
    circuit_config,
    now_ms,
    phase,
    reason,
    winner_candidate_id="",
):
    event_kind = (
        route_circuit.EVENT_RECORD_SUCCESS
        if phase == PHASE_CONNECTED
        else route_circuit.EVENT_RECORD_FAILURE
    )
    updated_circuits, decision = route_circuit.reduce_route_circuit(
        circuit_states,
        route_circuit.CircuitEvent(event_kind, state.key, now_ms),
        circuit_config,
    )
    terminal = replace(
        state,
        phase=phase,
        updated_at_ms=now_ms,
        winner_candidate_id=winner_candidate_id,
        reason=reason,
    )
    return terminal, updated_circuits, decision


def _cancel_attempts(attempts, candidate_ids, now_ms):
    cancelled = set(candidate_ids)
    return tuple(
        replace(
            attempt,
            state=address_attempts.ATTEMPT_CANCELLED,
            completed_at_ms=now_ms,
        )
        if attempt.candidate_id in cancelled
        and attempt.state == address_attempts.ATTEMPT_RUNNING
        else attempt
        for attempt in attempts
    )


def _settle(circuit_states, state, config, circuit_config, now_ms):
    commands = []
    while True:
        result = address_attempts.plan_address_attempts(
            state.candidates,
            state.attempts,
            _address_context(state, config, now_ms),
        )
        decision = result.decision

        if decision.kind == address_attempts.DECISION_START:
            state = replace(
                state,
                updated_at_ms=now_ms,
                attempts=state.attempts
                + (
                    address_attempts.AddressAttempt(
                        candidate_id=decision.candidate_id,
                        state=address_attempts.ATTEMPT_RUNNING,
                        started_at_ms=now_ms,
                    ),
                ),
            )
            commands.append(
                ConnectionRaceCommand(COMMAND_START, decision.candidate_id)
            )
            continue

        if decision.kind == address_attempts.DECISION_WAIT:
            commands.append(
                ConnectionRaceCommand(COMMAND_WAKE, at_ms=decision.wake_at_ms)
            )
            return ConnectionRaceTransition(state, dict(circuit_states), tuple(commands))

        if decision.kind == address_attempts.DECISION_SELECT:
            cancel_commands = tuple(
                ConnectionRaceCommand(COMMAND_CANCEL, candidate_id)
                for candidate_id in decision.cancel
            )
            state = replace(
                state,
                attempts=_cancel_attempts(state.attempts, decision.cancel, now_ms),
            )
            state, circuit_states, circuit_decision = _record_terminal(
                circuit_states,
                state,
                circuit_config,
                now_ms,
                PHASE_CONNECTED,
                "connected",
                decision.candidate_id,
            )
            return ConnectionRaceTransition(
                state,
                circuit_states,
                tuple(commands) + cancel_commands,
                (circuit_decision,),
            )

        if decision.kind == address_attempts.DECISION_TIMEOUT:
            cancel_commands = tuple(
                ConnectionRaceCommand(COMMAND_CANCEL, candidate_id)
                for candidate_id in decision.cancel
            )
            state = replace(
                state,
                attempts=_cancel_attempts(state.attempts, decision.cancel, now_ms),
            )
            state, circuit_states, circuit_decision = _record_terminal(
                circuit_states,
                state,
                circuit_config,
                now_ms,
                PHASE_TIMED_OUT,
                "deadline",
            )
            return ConnectionRaceTransition(
                state,
                circuit_states,
                tuple(commands) + cancel_commands,
                (circuit_decision,),
            )

        if decision.kind == address_attempts.DECISION_EXHAUSTED:
            state, circuit_states, circuit_decision = _record_terminal(
                circuit_states,
                state,
                circuit_config,
                now_ms,
                PHASE_EXHAUSTED,
                "all_attempts_failed",
            )
            return ConnectionRaceTransition(
                state,
                circuit_states,
                tuple(commands),
                (circuit_decision,),
            )

        raise ValueError("unknown address-plan decision")


def start_connection_race(circuit_states, key, config, circuit_config, now_ms):
    """Gate one logical request before asking an adapter to resolve it."""
    _validate_config(config)
    deadline_at_ms = now_ms + config.timeout_ms
    state = ConnectionRaceState(
        key=key,
        phase=PHASE_RESOLVING,
        started_at_ms=now_ms,
        updated_at_ms=now_ms,
        deadline_at_ms=deadline_at_ms,
    )
    updated_circuits, decision = route_circuit.reduce_route_circuit(
        circuit_states,
        route_circuit.CircuitEvent(
            route_circuit.EVENT_BEFORE_REQUEST, key, now_ms
        ),
        circuit_config,
    )
    if decision.kind == route_circuit.DECISION_REJECT:
        return ConnectionRaceTransition(
            replace(state, phase=PHASE_REJECTED, reason=decision.reason),
            updated_circuits,
            circuit_decisions=(decision,),
        )
    return ConnectionRaceTransition(
        state,
        updated_circuits,
        (
            ConnectionRaceCommand(COMMAND_RESOLVE),
            ConnectionRaceCommand(COMMAND_WAKE, at_ms=deadline_at_ms),
        ),
        (decision,),
    )


def _replace_running_attempt(state, candidate_id, attempt_state, now_ms):
    matched = False
    attempts = []
    for attempt in state.attempts:
        if attempt.candidate_id != candidate_id:
            attempts.append(attempt)
            continue
        matched = True
        if attempt.state != address_attempts.ATTEMPT_RUNNING:
            raise ValueError("attempt completion requires a running candidate")
        attempts.append(
            replace(
                attempt,
                state=attempt_state,
                completed_at_ms=now_ms,
            )
        )
    if not matched:
        raise ValueError("attempt completion references an unknown candidate")
    return replace(state, attempts=tuple(attempts), updated_at_ms=now_ms)


def _advance_resolving(circuit_states, state, event, config, circuit_config):
    if event.kind == EVENT_WAKE:
        if event.now_ms < state.deadline_at_ms:
            return ConnectionRaceTransition(
                replace(state, updated_at_ms=event.now_ms),
                dict(circuit_states),
                (ConnectionRaceCommand(COMMAND_WAKE, at_ms=state.deadline_at_ms),),
            )
        state, circuit_states, decision = _record_terminal(
            circuit_states,
            state,
            circuit_config,
            event.now_ms,
            PHASE_TIMED_OUT,
            "resolver_deadline",
        )
        return ConnectionRaceTransition(
            state, circuit_states, circuit_decisions=(decision,)
        )
    if event.kind == EVENT_RESOLVE_FAILED:
        state, circuit_states, decision = _record_terminal(
            circuit_states,
            state,
            circuit_config,
            event.now_ms,
            PHASE_FAILED,
            "resolve_failed",
        )
        return ConnectionRaceTransition(
            state, circuit_states, circuit_decisions=(decision,)
        )
    if event.kind != EVENT_RESOLVED:
        raise ValueError("resolver phase accepts only resolver events or wake")
    state = replace(
        state,
        phase=PHASE_CONNECTING,
        updated_at_ms=event.now_ms,
        candidates=tuple(event.candidates),
    )
    return _settle(circuit_states, state, config, circuit_config, event.now_ms)


def _advance_connecting(circuit_states, state, event, config, circuit_config):
    if event.kind == EVENT_WAKE:
        state = replace(state, updated_at_ms=event.now_ms)
    elif event.kind == EVENT_ATTEMPT_SUCCEEDED:
        state = _replace_running_attempt(
            state,
            event.candidate_id,
            address_attempts.ATTEMPT_SUCCEEDED,
            event.now_ms,
        )
    elif event.kind == EVENT_ATTEMPT_FAILED:
        state = _replace_running_attempt(
            state,
            event.candidate_id,
            address_attempts.ATTEMPT_FAILED,
            event.now_ms,
        )
    else:
        raise ValueError("connecting phase accepts only attempt events or wake")
    return _settle(circuit_states, state, config, circuit_config, event.now_ms)


def advance_connection_race(
    circuit_states,
    state,
    event,
    config,
    circuit_config,
):
    """Apply one adapter event and return deterministic follow-up commands."""
    _validate_config(config)
    if state.phase in TERMINAL_PHASES:
        return ConnectionRaceTransition(state, dict(circuit_states))
    if event.now_ms < state.updated_at_ms:
        raise ValueError("connection-race events must be monotonic")
    if state.phase == PHASE_RESOLVING:
        return _advance_resolving(
            circuit_states, state, event, config, circuit_config
        )
    if state.phase == PHASE_CONNECTING:
        return _advance_connecting(
            circuit_states, state, event, config, circuit_config
        )
    raise ValueError("unknown connection-race phase")

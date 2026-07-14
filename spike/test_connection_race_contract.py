from dataclasses import asdict
import heapq
import itertools
import json
from pathlib import Path

import pytest

import address_attempts
import connection_race
import route_circuit


CONTRACT_PATH = (
    Path(__file__).resolve().parents[1] / "contracts" / "connection-race-v1.json"
)
CONTRACT = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


class ScriptedResolver:
    def __init__(self, script):
        self.script = script
        self.calls = 0

    def start(self, now_ms, schedule):
        self.calls += 1
        outcome = self.script["outcome"]
        if outcome == "stall":
            return
        event_kind = (
            connection_race.EVENT_RESOLVED
            if outcome == "success"
            else connection_race.EVENT_RESOLVE_FAILED
        )
        candidates = tuple(
            address_attempts.AddressCandidate(**candidate)
            for candidate in self.script.get("candidates", ())
        )
        schedule(
            connection_race.ConnectionRaceEvent(
                event_kind,
                now_ms + self.script["delay_ms"],
                candidates=candidates,
            ),
            0,
        )


class ScriptedConnector:
    def __init__(self, scripts):
        self.scripts = scripts
        self.starts = []
        self.cancelled = []
        self._cancelled = set()

    def start(self, candidate_id, now_ms, schedule):
        if candidate_id not in self.scripts:
            raise AssertionError(f"missing connector script for {candidate_id}")
        self.starts.append({"candidate_id": candidate_id, "at_ms": now_ms})
        script = self.scripts[candidate_id]
        outcome = script["outcome"]
        if outcome == "stall":
            return
        event_kind = (
            connection_race.EVENT_ATTEMPT_SUCCEEDED
            if outcome == "success"
            else connection_race.EVENT_ATTEMPT_FAILED
        )
        schedule(
            connection_race.ConnectionRaceEvent(
                event_kind,
                now_ms + script["delay_ms"],
                candidate_id=candidate_id,
            ),
            0,
        )

    def cancel(self, candidate_id):
        if candidate_id not in self._cancelled:
            self._cancelled.add(candidate_id)
            self.cancelled.append(candidate_id)

    def event_is_cancelled(self, event):
        return event.candidate_id in self._cancelled


def _snapshot_request(transition, resolver, connector, circuit_decisions):
    return {
        "phase": transition.state.phase,
        "reason": transition.state.reason,
        "winner_candidate_id": transition.state.winner_candidate_id,
        "completed_at_ms": transition.state.updated_at_ms,
        "resolver_calls": resolver.calls,
        "starts": [
            f"{item['candidate_id']}@{item['at_ms']}" for item in connector.starts
        ],
        "cancelled": connector.cancelled,
        "attempts": [
            ":".join(
                (
                    attempt.candidate_id,
                    attempt.state,
                    str(attempt.started_at_ms),
                    str(attempt.completed_at_ms),
                )
            )
            for attempt in transition.state.attempts
        ],
        "circuit_decisions": [
            f"{decision.kind}:{decision.reason}:{decision.phase}"
            for decision in circuit_decisions
        ],
    }


def run_scripted_request(circuit_states, request, config, circuit_config):
    resolver = ScriptedResolver(request["resolver"])
    connector = ScriptedConnector(request["connector"])
    queue = []
    serial = itertools.count()
    wake_times = set()

    def schedule(event, priority):
        heapq.heappush(
            queue,
            (event.now_ms, priority, next(serial), event),
        )

    def apply_commands(commands, now_ms):
        for command in commands:
            if command.kind == connection_race.COMMAND_RESOLVE:
                resolver.start(now_ms, schedule)
            elif command.kind == connection_race.COMMAND_START:
                connector.start(command.candidate_id, now_ms, schedule)
            elif command.kind == connection_race.COMMAND_CANCEL:
                connector.cancel(command.candidate_id)
            elif command.kind == connection_race.COMMAND_WAKE:
                if command.at_ms not in wake_times:
                    wake_times.add(command.at_ms)
                    schedule(
                        connection_race.ConnectionRaceEvent(
                            connection_race.EVENT_WAKE, command.at_ms
                        ),
                        1,
                    )
            else:
                raise AssertionError(f"unknown command {command.kind}")

    transition = connection_race.start_connection_race(
        circuit_states,
        route_circuit.RouteCircuitKey(**request["key"]),
        config,
        circuit_config,
        request["started_at_ms"],
    )
    circuit_decisions = list(transition.circuit_decisions)
    apply_commands(transition.commands, request["started_at_ms"])

    for _ in range(100):
        if transition.state.phase in connection_race.TERMINAL_PHASES:
            break
        if not queue:
            raise AssertionError("scripted adapters left an active race without events")
        _, _, _, event = heapq.heappop(queue)
        if event.kind == connection_race.EVENT_WAKE:
            wake_times.discard(event.now_ms)
        elif connector.event_is_cancelled(event):
            continue
        transition = connection_race.advance_connection_race(
            transition.circuit_states,
            transition.state,
            event,
            config,
            circuit_config,
        )
        circuit_decisions.extend(transition.circuit_decisions)
        apply_commands(transition.commands, event.now_ms)
    else:
        raise AssertionError("scripted connection race exceeded the step bound")

    return (
        transition.circuit_states,
        _snapshot_request(
            transition, resolver, connector, circuit_decisions
        ),
    )


def run_vector(case):
    config = connection_race.ConnectionRaceConfig(**CONTRACT["race_config"])
    circuit_config = route_circuit.CircuitConfig(**CONTRACT["circuit_config"])
    circuit_states = {}
    requests = []
    for request in case["requests"]:
        request_config = connection_race.ConnectionRaceConfig(
            **{**CONTRACT["race_config"], **request.get("config", {})}
        )
        circuit_states, snapshot = run_scripted_request(
            circuit_states,
            request,
            request_config,
            circuit_config,
        )
        requests.append(snapshot)
    return {
        "requests": requests,
        "circuit_states": [
            asdict(snapshot)
            for snapshot in route_circuit.circuit_snapshot(circuit_states)
        ],
    }


def test_connection_race_contract_metadata_is_stable():
    assert CONTRACT["schema_version"] == 1
    assert CONTRACT["contract"] == "slipstream.connection_race"
    assert CONTRACT["contract_version"] == 1
    names = [case["name"] for case in CONTRACT["vectors"]]
    assert names
    assert len(names) == len(set(names))


@pytest.mark.parametrize(
    "case",
    CONTRACT["vectors"],
    ids=[case["name"] for case in CONTRACT["vectors"]],
)
def test_scripted_connection_race_contract(case):
    actual = run_vector(case)
    assert actual["requests"] == case["expected_requests"]
    assert actual["circuit_states"] == case["expected_circuit_states"]


def test_terminal_race_ignores_late_adapter_completion():
    case = CONTRACT["vectors"][1]
    config = connection_race.ConnectionRaceConfig(**CONTRACT["race_config"])
    circuit_config = route_circuit.CircuitConfig(**CONTRACT["circuit_config"])
    _, snapshot = run_scripted_request({}, case["requests"][0], config, circuit_config)
    assert snapshot["phase"] == connection_race.PHASE_CONNECTED

    transition = connection_race.start_connection_race(
        {},
        route_circuit.RouteCircuitKey(**case["requests"][0]["key"]),
        config,
        circuit_config,
        0,
    )
    resolved = connection_race.ConnectionRaceEvent(
        connection_race.EVENT_RESOLVED,
        0,
        candidates=tuple(
            address_attempts.AddressCandidate(**candidate)
            for candidate in case["requests"][0]["resolver"]["candidates"]
        ),
    )
    transition = connection_race.advance_connection_race(
        transition.circuit_states,
        transition.state,
        resolved,
        config,
        circuit_config,
    )
    success = connection_race.ConnectionRaceEvent(
        connection_race.EVENT_ATTEMPT_SUCCEEDED,
        100,
        candidate_id="v6-a",
    )
    transition = connection_race.advance_connection_race(
        transition.circuit_states,
        transition.state,
        success,
        config,
        circuit_config,
    )
    late = connection_race.ConnectionRaceEvent(
        connection_race.EVENT_ATTEMPT_SUCCEEDED,
        500,
        candidate_id="v4-a",
    )
    ignored = connection_race.advance_connection_race(
        transition.circuit_states,
        transition.state,
        late,
        config,
        circuit_config,
    )
    assert ignored.state == transition.state
    assert ignored.circuit_states == transition.circuit_states
    assert ignored.commands == ()
    assert ignored.circuit_decisions == ()

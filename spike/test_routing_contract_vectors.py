from dataclasses import asdict
import json
from pathlib import Path

import pytest

import address_attempts
import route_circuit
import route_circuit_registry
import routing_policy
import routing_recovery
import tproxy


CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"


def load_contract(name):
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


POLICY = load_contract("routing-policy-v1.json")
RECOVERY = load_contract("recovery-v1.json")
ADDRESS_ATTEMPTS = load_contract("address-attempts-v1.json")
ROUTE_CIRCUIT = load_contract("route-circuit-v1.json")
ROUTE_CIRCUIT_REGISTRY = load_contract("route-circuit-registry-v1.json")
CONNECTION_RACE = load_contract("connection-race-v1.json")
STATUS_V2 = load_contract("status-v2-v1.json")


def merge(defaults, override):
    return {**defaults, **(override or {})}


def json_ready(value):
    return json.loads(json.dumps(value))


def test_contract_metadata_and_vector_names_are_stable():
    assert POLICY["schema_version"] == 1
    assert POLICY["contract"] == "slipstream.routing_policy"
    assert POLICY["contract_version"] == 1
    assert RECOVERY["schema_version"] == 1
    assert RECOVERY["contract"] == "slipstream.recovery"
    assert RECOVERY["contract_version"] == 1
    assert ADDRESS_ATTEMPTS["schema_version"] == 1
    assert ADDRESS_ATTEMPTS["contract"] == "slipstream.address_attempts"
    assert ADDRESS_ATTEMPTS["contract_version"] == 1
    assert ROUTE_CIRCUIT["schema_version"] == 1
    assert ROUTE_CIRCUIT["contract"] == "slipstream.route_circuit"
    assert ROUTE_CIRCUIT["contract_version"] == 1
    assert ROUTE_CIRCUIT_REGISTRY["schema_version"] == 1
    assert ROUTE_CIRCUIT_REGISTRY["contract"] == "slipstream.route_circuit_registry"
    assert ROUTE_CIRCUIT_REGISTRY["contract_version"] == 1
    assert CONNECTION_RACE["schema_version"] == 1
    assert CONNECTION_RACE["contract"] == "slipstream.connection_race"
    assert CONNECTION_RACE["contract_version"] == 1
    assert STATUS_V2["schema_version"] == 1
    assert STATUS_V2["contract"] == "slipstream.status_v2"
    assert STATUS_V2["contract_version"] == 1

    for contract in (
        POLICY,
        RECOVERY,
        ADDRESS_ATTEMPTS,
        ROUTE_CIRCUIT,
        ROUTE_CIRCUIT_REGISTRY,
        CONNECTION_RACE,
        STATUS_V2,
    ):
        names = [item["name"] for item in contract["vectors"]]
        assert names
        assert len(names) == len(set(names))


def test_status_v2_fixture_is_privacy_bounded():
    public_status = json.dumps(STATUS_V2["vectors"][0]["status"], sort_keys=True)
    for private_value in STATUS_V2["privacy_forbidden_values"]:
        assert private_value not in public_status


@pytest.mark.parametrize(
    "case",
    ADDRESS_ATTEMPTS["vectors"],
    ids=[item["name"] for item in ADDRESS_ATTEMPTS["vectors"]],
)
def test_address_attempt_contract(case):
    inputs = case["input"]
    candidates = [
        address_attempts.AddressCandidate(**candidate)
        for candidate in inputs["candidates"]
    ]
    attempts = [
        address_attempts.AddressAttempt(**attempt)
        for attempt in inputs["attempts"]
    ]
    context = address_attempts.AddressPlanContext(**inputs["context"])

    actual = address_attempts.plan_address_attempts(candidates, attempts, context)

    assert json_ready(asdict(actual)) == case["expected"]


@pytest.mark.parametrize(
    "case",
    ROUTE_CIRCUIT["vectors"],
    ids=[item["name"] for item in ROUTE_CIRCUIT["vectors"]],
)
def test_route_circuit_contract(case):
    config = route_circuit.CircuitConfig(**ROUTE_CIRCUIT["config"])
    states = {}
    decisions = []
    for item in case["events"]:
        event = route_circuit.CircuitEvent(
            kind=item["kind"],
            key=route_circuit.RouteCircuitKey(**item["key"]),
            now_ms=item["now_ms"],
        )
        states, decision = route_circuit.reduce_route_circuit(
            states, event, config
        )
        decisions.append(asdict(decision))

    snapshots = [
        asdict(snapshot) for snapshot in route_circuit.circuit_snapshot(states)
    ]
    assert json_ready(decisions) == case["expected_decisions"]
    assert json_ready(snapshots) == case["expected_states"]


@pytest.mark.parametrize(
    "case",
    ROUTE_CIRCUIT_REGISTRY["vectors"],
    ids=[item["name"] for item in ROUTE_CIRCUIT_REGISTRY["vectors"]],
)
def test_route_circuit_registry_contract(case):
    registry = route_circuit_registry.RouteCircuitRegistry(
        route_circuit.CircuitConfig(**ROUTE_CIRCUIT_REGISTRY["circuit_config"]),
        route_circuit_registry.RouteCircuitRegistryConfig(
            **ROUTE_CIRCUIT_REGISTRY["registry_config"]
        ),
    )
    decisions = []
    for item in case["events"]:
        decision = registry.apply(
            route_circuit.CircuitEvent(
                kind=item["kind"],
                key=route_circuit.RouteCircuitKey(**item["key"]),
                now_ms=item["now_ms"],
            )
        )
        decisions.append(asdict(decision))

    assert json_ready(decisions) == case["expected_decisions"]
    assert json_ready([asdict(item) for item in registry.snapshot()]) == case[
        "expected_entries"
    ]


@pytest.mark.parametrize(
    "case",
    POLICY["vectors"],
    ids=[item["name"] for item in POLICY["vectors"]],
)
def test_routing_policy_contract(case):
    policy_tables = tproxy.route_policy_tables()
    actual = routing_policy.classify_route_policy(case["host"], *policy_tables)

    assert actual == case["expected"]
    assert tproxy.route_policy(case["host"]) == actual


@pytest.mark.parametrize(
    "case",
    RECOVERY["vectors"],
    ids=[item["name"] for item in RECOVERY["vectors"]],
)
def test_recovery_contract(case):
    outcome = routing_recovery.ConnectionOutcome(
        **merge(RECOVERY["outcome_defaults"], case.get("outcome"))
    )
    context = routing_recovery.RecoveryContext(
        **merge(RECOVERY["context_defaults"], case.get("context"))
    )

    actions = routing_recovery.reduce_connection_outcome(outcome, context)
    actual = [asdict(action) for action in actions]

    assert actual == case["expected"]
    prohibited = set(case.get("prohibited_actions", ()))
    assert prohibited.isdisjoint(action["kind"] for action in actual)


def test_protected_groups_have_no_geph_policy_or_recovery_edge():
    protected = set(RECOVERY["invariants"]["protected_local_bypass_groups"])
    forbidden = RECOVERY["invariants"]["forbidden_protected_action"]

    for case in POLICY["vectors"]:
        expected = case["expected"]
        if expected["service_group"] in protected:
            assert expected["route_class"] == "local_bypass"
            assert expected["strategy_set"] == "fake_only"

    for case in RECOVERY["vectors"]:
        outcome = merge(RECOVERY["outcome_defaults"], case.get("outcome"))
        if outcome["service_group"] in protected:
            assert forbidden not in {item["kind"] for item in case["expected"]}

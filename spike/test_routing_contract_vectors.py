from dataclasses import asdict
import json
from pathlib import Path

import pytest

import routing_policy
import routing_recovery
import tproxy


CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"


def load_contract(name):
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


POLICY = load_contract("routing-policy-v1.json")
RECOVERY = load_contract("recovery-v1.json")


def merge(defaults, override):
    return {**defaults, **(override or {})}


def test_contract_metadata_and_vector_names_are_stable():
    assert POLICY["schema_version"] == 1
    assert POLICY["contract"] == "slipstream.routing_policy"
    assert POLICY["contract_version"] == 1
    assert RECOVERY["schema_version"] == 1
    assert RECOVERY["contract"] == "slipstream.recovery"
    assert RECOVERY["contract_version"] == 1

    for contract in (POLICY, RECOVERY):
        names = [item["name"] for item in contract["vectors"]]
        assert names
        assert len(names) == len(set(names))


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

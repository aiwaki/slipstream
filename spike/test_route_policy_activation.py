from dataclasses import asdict
import copy
import json
from pathlib import Path

import pytest

import route_policy_activation as activation


CONTRACT = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "contracts"
        / "route-policy-activation-v1.json"
    ).read_text(encoding="utf-8")
)


def resolve_policy_refs(value):
    if isinstance(value, dict):
        if set(value) == {"$policy"}:
            return copy.deepcopy(CONTRACT["policies"][value["$policy"]])
        return {key: resolve_policy_refs(item) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_policy_refs(item) for item in value]
    return copy.deepcopy(value)


def policy_identity(value):
    return activation.PolicyIdentity(**value)


def activation_state(value):
    return activation.PolicyActivationState(
        bundled=policy_identity(value["bundled"]),
        active=policy_identity(value["active"]),
        previous=(
            policy_identity(value["previous"])
            if value.get("previous") is not None
            else None
        ),
        candidate=(
            policy_identity(value["candidate"])
            if value.get("candidate") is not None
            else None
        ),
        phase=value["phase"],
    )


def activation_event(value):
    data = dict(value)
    if data.get("policy") is not None:
        data["policy"] = policy_identity(data["policy"])
    return activation.PolicyActivationEvent(**data)


def json_ready(value):
    return json.loads(json.dumps(value))


@pytest.mark.parametrize(
    "case",
    CONTRACT["vectors"],
    ids=[item["name"] for item in CONTRACT["vectors"]],
)
def test_route_policy_activation_contract(case):
    state = activation_state(resolve_policy_refs(case["initial_state"]))

    for event_value, expected in zip(case["events"], case["expected"], strict=True):
        event = activation_event(resolve_policy_refs(event_value))
        before = state
        if expected["ok"]:
            transition = activation.reduce_policy_activation(state, event)
            actual = json_ready(asdict(transition))
            assert actual["decision"] == expected["decision"]
            assert actual["reason"] == expected["reason"]
            assert actual["actions"] == resolve_policy_refs(expected["actions"])
            state = transition.state
            continue

        with pytest.raises(activation.PolicyActivationError) as caught:
            activation.reduce_policy_activation(state, event)
        assert caught.value.code == expected["error"]["code"]
        assert caught.value.path == expected["error"]["path"]
        assert expected["error"]["message_contains"] in str(caught.value)
        assert state == before

    assert json_ready(asdict(state)) == resolve_policy_refs(case["expected_final_state"])


def test_policy_source_limit_is_measured_in_utf8_bytes():
    bundled = policy_identity(CONTRACT["policies"]["bundled"])
    state = activation.PolicyActivationState(bundled=bundled, active=bundled)
    candidate = activation.PolicyIdentity(
        kind=activation.POLICY_SIGNED,
        source="я" * 65,
        sha256="5" * 64,
    )
    event = activation.PolicyActivationEvent(
        kind=activation.EVENT_BEGIN_TRIAL,
        expected_active_sha256=bundled.sha256,
        policy=candidate,
    )

    with pytest.raises(activation.PolicyActivationError) as caught:
        activation.reduce_policy_activation(state, event)
    assert caught.value.code == activation.ERROR_INVALID_SOURCE
    assert caught.value.path == "$.event.policy.source"


def test_health_counters_reject_python_booleans():
    bundled = policy_identity(CONTRACT["policies"]["bundled"])
    candidate = policy_identity(CONTRACT["policies"]["signed_a"])
    state = activation.PolicyActivationState(
        bundled=bundled,
        active=bundled,
        candidate=candidate,
        phase=activation.PHASE_TRIAL,
    )
    event = activation.PolicyActivationEvent(
        kind=activation.EVENT_HEALTH_RESULT,
        candidate_sha256=candidate.sha256,
        completed=True,
        ok=True,
    )

    with pytest.raises(activation.PolicyActivationError) as caught:
        activation.reduce_policy_activation(state, event)
    assert caught.value.code == activation.ERROR_INVALID_COUNTER
    assert caught.value.path == "$.event.ok"


def test_activation_module_has_no_runtime_adapter_dependencies():
    source = Path(activation.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "import os",
        "import socket",
        "import subprocess",
        "import time",
        "import tproxy",
    ):
        assert forbidden not in source

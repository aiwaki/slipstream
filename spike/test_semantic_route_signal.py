import json
from pathlib import Path

import pytest

from semantic_route_signal import (
    ACTION_NONE,
    MAX_SIGNAL_BYTES,
    SemanticRouteSignalContext,
    SemanticSignalError,
    parse_semantic_route_signal_v1,
    reduce_semantic_route_signal,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "semantic-route-signal-v1.json"


def _merged(defaults, override):
    return {**defaults, **(override or {})}


def test_python_executes_semantic_route_signal_contract():
    contract = json.loads(CONTRACT.read_text())

    for vector in contract["vectors"]:
        signal_payload = _merged(contract["signal_defaults"], vector.get("signal"))
        signal = parse_semantic_route_signal_v1(json.dumps(signal_payload))
        context = SemanticRouteSignalContext(
            **_merged(contract["context_defaults"], vector.get("context"))
        )

        decision = reduce_semantic_route_signal(signal, context)

        assert decision.__dict__ == vector["expected"], vector["name"]


def test_python_executes_semantic_route_signal_parser_contract():
    contract = json.loads(CONTRACT.read_text())
    for vector in contract["parser_vectors"]:
        payload = {
            **contract["signal_defaults"],
            **vector.get("replace", {}),
            **vector.get("add", {}),
        }
        if field := vector.get("remove"):
            payload.pop(field)

        with pytest.raises(SemanticSignalError) as caught:
            parse_semantic_route_signal_v1(json.dumps(payload))

        assert caught.value.code == vector["expected_error"], vector["name"]


def test_semantic_signal_parser_rejects_every_forbidden_field():
    contract = json.loads(CONTRACT.read_text())
    for field in contract["privacy"]["forbidden_fields"]:
        payload = dict(contract["signal_defaults"])
        payload[field] = "private"

        with pytest.raises(SemanticSignalError, match="invalid_shape"):
            parse_semantic_route_signal_v1(json.dumps(payload))


def test_semantic_signal_parser_rejects_oversized_input():
    with pytest.raises(SemanticSignalError, match="payload_too_large"):
        parse_semantic_route_signal_v1(b"{" + b" " * MAX_SIGNAL_BYTES + b"}")


@pytest.mark.parametrize(
    "host",
    (
        "localhost",
        "127.0.0.1",
        ".weather.com",
        "weather..com",
        "-weather.com",
        "weather.com/path",
        " weather.com",
    ),
)
def test_semantic_signal_parser_rejects_non_host_identifiers(host):
    contract = json.loads(CONTRACT.read_text())
    payload = dict(contract["signal_defaults"])
    payload["host"] = host

    with pytest.raises(SemanticSignalError, match="invalid_host"):
        parse_semantic_route_signal_v1(json.dumps(payload))


def test_rejected_signal_never_returns_an_action():
    contract = json.loads(CONTRACT.read_text())
    signal = parse_semantic_route_signal_v1(json.dumps(contract["signal_defaults"]))
    context = SemanticRouteSignalContext(
        **{
            **contract["context_defaults"],
            "route_class": "local_bypass",
        }
    )

    decision = reduce_semantic_route_signal(signal, context)

    assert not decision.accepted
    assert decision.action == ACTION_NONE

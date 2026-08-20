import json
from pathlib import Path

import pytest

from route_preflight import (
    OUTCOMES,
    REASON_ACCEPTED,
    REASON_BINDING_MISMATCH,
    REASON_CANDIDATE_NOT_ALLOWED,
    REASON_EXPIRED,
    REASON_REPLAY,
    RoutePreflightError,
    parse_route_preflight_job_v1,
    parse_route_preflight_result_v1,
    validate_route_preflight_result_v1,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "route-preflight-v1.json"


def _contract():
    return json.loads(CONTRACT.read_text())


def test_route_preflight_contract_binds_exact_job_and_result():
    contract = _contract()
    job = parse_route_preflight_job_v1(json.dumps(contract["job_defaults"]))
    result = parse_route_preflight_result_v1(json.dumps(contract["result_defaults"]))

    decision = validate_route_preflight_result_v1(
        job, result, now_unix_ms=1_000_600
    )
    assert decision.accepted
    assert decision.reason == REASON_ACCEPTED

    wrong_host = parse_route_preflight_result_v1(
        json.dumps({**contract["result_defaults"], "host": "other.example"})
    )
    assert (
        validate_route_preflight_result_v1(
            job, wrong_host, now_unix_ms=1_000_600
        ).reason
        == REASON_BINDING_MISMATCH
    )

    unlisted = parse_route_preflight_result_v1(
        json.dumps({**contract["result_defaults"], "candidate_route": "app_doh"})
    )
    assert (
        validate_route_preflight_result_v1(
            job, unlisted, now_unix_ms=1_000_600
        ).reason
        == REASON_CANDIDATE_NOT_ALLOWED
    )
    assert (
        validate_route_preflight_result_v1(
            job, result, now_unix_ms=1_008_001
        ).reason
        == REASON_EXPIRED
    )
    assert (
        validate_route_preflight_result_v1(
            job, result, now_unix_ms=1_000_600, capability_seen=True
        ).reason
        == REASON_REPLAY
    )


def test_route_preflight_accepts_only_fixed_outcomes():
    contract = _contract()
    assert OUTCOMES == frozenset(contract["outcomes"])
    for outcome in contract["outcomes"]:
        result = parse_route_preflight_result_v1(
            json.dumps({**contract["result_defaults"], "outcome": outcome})
        )
        assert result.outcome == outcome

    with pytest.raises(RoutePreflightError, match="invalid_outcome"):
        parse_route_preflight_result_v1(
            json.dumps({**contract["result_defaults"], "outcome": "route_geph"})
        )


def test_route_preflight_rejects_private_fields_duplicates_and_long_deadline():
    contract = _contract()
    for field in contract["privacy"]["forbidden_fields"]:
        with pytest.raises(RoutePreflightError, match="invalid_shape"):
            parse_route_preflight_result_v1(
                json.dumps({**contract["result_defaults"], field: "private"})
            )

    with pytest.raises(RoutePreflightError, match="invalid_candidate_routes"):
        parse_route_preflight_job_v1(
            json.dumps(
                {**contract["job_defaults"], "candidate_routes": ["system", "system"]}
            )
        )
    with pytest.raises(RoutePreflightError, match="invalid_deadline"):
        parse_route_preflight_job_v1(
            json.dumps({**contract["job_defaults"], "deadline_unix_ms": 1_008_001})
        )

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


def test_browser_comparison_v2_vectors_preserve_v1_budget():
    from route_preflight import parse_route_preflight_job_v2
    contract = json.loads((ROOT / 'contracts/route-preflight-v2.json').read_text())
    for vector in contract['vectors']:
        payload = json.dumps(dict(schema_version=vector['version'], capability='a'*32,
                                  host='example.com', candidate_routes=vector['routes'],
                                  issued_at_unix_ms=1000,
                                  deadline_unix_ms=1000+vector['duration_ms']))
        parser = parse_route_preflight_job_v2 if vector['version']==2 else parse_route_preflight_job_v1
        if vector['valid']:
            assert parser(payload).schema_version == 2
            with pytest.raises(RoutePreflightError):
                parse_route_preflight_job_v1(payload)
        else:
            with pytest.raises(RoutePreflightError):
                parser(payload)


def test_browser_comparison_v2_result_binding_and_expiry():
    from route_preflight import parse_route_preflight_job_v2, parse_route_preflight_result_v2
    job = parse_route_preflight_job_v2(json.dumps(dict(schema_version=2,
        capability='a'*32,host='example.com',candidate_routes=['owned_geph'],
        issued_at_unix_ms=1000,deadline_unix_ms=21000)))
    payload=dict(schema_version=2,capability='a'*32,host='example.com',
                 candidate_route='owned_geph',outcome='usable',observed_at_unix_ms=12000)
    result=parse_route_preflight_result_v2(json.dumps(payload))
    assert validate_route_preflight_result_v1(job,result,now_unix_ms=12000).accepted
    assert not validate_route_preflight_result_v1(job,result,now_unix_ms=21001).accepted
    assert not validate_route_preflight_result_v1(job,result,now_unix_ms=12000,capability_seen=True).accepted
    with pytest.raises(RoutePreflightError):parse_route_preflight_result_v1(json.dumps(payload))
    with pytest.raises(RoutePreflightError):parse_route_preflight_result_v2(json.dumps(dict(payload,candidate_route='system')))

"""Public JSON recovery needs complete framing and exact-object evidence."""
from dataclasses import replace
import json
import pickle

import pytest
import bootstrap_asset_preflight as probe


def response(body, *, length=None, status=200, content_type='application/json', extra=b''):
    length = len(body) if length is None else length
    return (f'HTTP/1.1 {status} Test\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\n'.encode()
            + extra + b'\r\n' + body)


def inspect(data, **overrides):
    kw = dict(stream_closed=True, idle_timed_out=False, truncated=False,
              deadline=10, clock=lambda: 0)
    kw.update(overrides)
    return probe.inspect_public_json_response(data, **kw)


def test_partial_json_and_full_same_object_bind_without_retaining_payload():
    body = json.dumps({'items': ['public data'] * 500}).encode()
    partial = inspect(response(body[:2048], length=len(body)))
    complete = inspect(response(body))
    assert partial.outcome is probe.RangeProbeOutcome.INCOMPLETE
    assert complete.outcome is probe.RangeProbeOutcome.COMPLETE
    assert partial.proves_same_object_as(complete)
    assert 'public data' not in repr(complete)
    assert not partial.proves_same_object_as(replace(complete, object_kind='range'))
    changed = b' ' + body[1:]
    assert not partial.proves_same_object_as(inspect(response(changed)))


@pytest.mark.parametrize('data', [
    response(b'<html>denied</html>'), response(b'not json'), response(b'null'),
    response(b'{"value": NaN}'), response(b'{"value": Infinity}'),
    response(b'{}', status=403), response(b'{}', status=206),
    response(b'{}', content_type='text/html'),
    response(b'{}', extra=b'Content-Length: 2\r\n'),
    response(b'{}', extra=b'Transfer-Encoding: chunked\r\n'),
    response(b'{}', extra=b'Content-Encoding: gzip\r\n'),
    response(b'{}', extra=b'Content-Range: bytes 0-1/2\r\n'),
    response(b'{}', length=probe.MAX_RANGE_END + 2),
    response(b'{}junk', length=2),
    b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}',
])
def test_ambiguous_or_wrong_responses_never_prove_a_route(data):
    assert inspect(data).outcome is probe.RangeProbeOutcome.UNKNOWN


def test_local_capture_limit_and_deadline_are_not_network_failure():
    data = response(b'{', length=4000)
    assert inspect(data, truncated=True).outcome is probe.RangeProbeOutcome.UNKNOWN
    assert inspect(data, stream_closed=False).outcome is probe.RangeProbeOutcome.UNKNOWN
    assert inspect(data, deadline=0).outcome is probe.RangeProbeOutcome.DEADLINE_EXCEEDED
    assert inspect(data, stream_closed=False, idle_timed_out=True).outcome is probe.RangeProbeOutcome.INCOMPLETE


def test_json_requires_enough_same_object_evidence():
    partial = inspect(response(b'{', length=2))
    complete = inspect(response(b'{}'))
    assert not partial.proves_same_object_as(complete)
    etag = b'ETag: "same"\r\n'
    assert inspect(response(b'{', length=2, extra=etag)).proves_same_object_as(inspect(response(b'{}', extra=etag)))
    assert not inspect(response(b'{', length=2, extra=b'ETag: W/"same"\r\n')).proves_same_object_as(complete)


def test_json_conflicting_strong_validators_override_common_prefix():
    body = json.dumps({'items': ['common data'] * 500}).encode()
    partial = inspect(response(body[:2048], length=len(body), extra=b'ETag: "first"\r\n'))
    complete = inspect(response(body, extra=b'ETag: "second"\r\n'))
    assert partial.prefix_digest == complete.prefix_digest
    assert not partial.proves_same_object_as(complete)


def test_ephemeral_json_request_is_anonymous_consumed_and_not_serializable():
    asset = probe.ephemeral_public_json_asset('https://api.example.net/feed?anonymous=1', 'api.example.net')
    request = asset.build_range_request()
    assert request.startswith(b'GET /feed?anonymous=1 HTTP/1.1\r\n')
    assert b'Accept: application/json\r\n' in request
    assert b'Range:' not in request and b'Cookie:' not in request and b'Authorization:' not in request
    assert 'anonymous' not in repr(asset)
    with pytest.raises(RuntimeError): asset.build_range_request()
    with pytest.raises(TypeError): pickle.dumps(asset)
    assert probe.ephemeral_public_json_asset('https://other.example/a', 'api.example.net') is None


def test_existing_range_contract_does_not_accept_json_200():
    assert probe.inspect_range_response(response(b'{}'), stream_closed=True,
        idle_timed_out=False, truncated=False, deadline=10, clock=lambda: 0).outcome is probe.RangeProbeOutcome.UNKNOWN


def test_v4_bound_discovery_broker_and_old_contracts(monkeypatch):
    from dataclasses import asdict
    from concurrent.futures import Future
    import time
    import route_preflight as contract
    import pending_navigation_probe_runtime as runtime
    import tproxy
    now = time.monotonic(); wall = int(time.time() * 1000)
    job = contract.RoutePreflightJobV4('b'*32, 'parent.example', ('owned_geph',),
        wall, wall+20000, asset_hosts=('api.example.net',))
    result = contract.RoutePreflightResultV4('b'*32, 'parent.example', 'owned_geph',
        'usable', wall, asset_url='https://api.example.net/items?ephemeral=1', asset_kind='public_json')
    assert contract.parse_route_preflight_job_v4(json.dumps(asdict(job))) == job
    assert contract.parse_route_preflight_result_v4(json.dumps(asdict(result))) == result
    assert runtime._validate_job(asdict(job), wall)
    assert 'ephemeral' not in repr(result)
    for old in (contract.parse_route_preflight_result_v1, contract.parse_route_preflight_result_v2,
                contract.parse_route_preflight_result_v3):
        with pytest.raises(contract.RoutePreflightError): old(json.dumps(asdict(result)))
    for kind in ('', 'post', None, 'html'):
        with pytest.raises(contract.RoutePreflightError):
            contract.parse_route_preflight_result_v4(json.dumps(asdict(replace(result, asset_kind=kind))))
    assert not contract.validate_route_preflight_result_v1(job,
        replace(result, asset_url='https://foreign.example/items'), now_unix_ms=wall).accepted
    future = Future()
    monkeypatch.setattr(tproxy, '_route_preflight_browser_capabilities', {
        job.capability: tproxy._RoutePreflightBrowserCapability(job, future, 41, now+20)})
    monkeypatch.setattr(tproxy, '_route_preflight_browser_claims', {})
    monkeypatch.setattr(tproxy, '_owned_geph_confirmation_pid_matches', lambda pid: pid == 41)
    assert tproxy._pending_navigation_probe_worker_claimed(tproxy._route_preflight_job_payload(job), '0123456789abcdef', now=now)
    assert tproxy._submit_browser_probe_result(asdict(result), '0123456789abcdef', now=now)
    assert future.result() == result
    assert not tproxy._submit_browser_probe_result(asdict(result), '0123456789abcdef', now=now)


def test_transport_selects_json_contract_only_for_explicit_anonymous_request(monkeypatch):
    import tproxy
    from test_bootstrap_tls_stream import Context, RawSocket, Clock
    data = response(json.dumps({'items': ['x'] * 1000}).encode())
    clock = Clock()
    class ReplyContext(Context):
        def wrap_bio(self, *a, **kw):
            tls = super().wrap_bio(*a, **kw)
            tls.read_actions.append(data)
            return tls
    monkeypatch.setattr(tproxy, '_local_payload_ssl_context', ReplyContext)
    inspect_json = probe.inspect_public_json_response
    monkeypatch.setattr(probe, 'inspect_public_json_response',
        lambda data, **kw: inspect_json(data, **kw, clock=lambda: clock.now))
    for factory, expected in ((probe.ephemeral_public_json_asset, probe.RangeProbeOutcome.COMPLETE),
                              (probe.ephemeral_dynamic_asset, probe.RangeProbeOutcome.UNKNOWN)):
        request = factory('https://api.example.net/items', 'api.example.net').build_range_request()
        # The real reader uses a real monotonic deadline; the simulated stream
        # provides all bytes without waiting or touching the network.
        result = tproxy._bootstrap_range_response_on_tls_socket(RawSocket(clock), 'api.example.net',
            request, tproxy.time.monotonic()+10)
        assert result.evidence.outcome is expected


def test_frozen_v4_vectors():
    from pathlib import Path
    import route_preflight as contract
    vectors = json.loads((Path(__file__).resolve().parents[1] / 'contracts/route-preflight-v4.json').read_text())
    for v in vectors['vectors']:
        payload = dict(schema_version=4, capability='a'*32, host='parent.example',
            candidate_route='owned_geph', outcome='usable', observed_at_unix_ms=1500,
            asset_url=v['url'], asset_kind=v['kind'])
        if v['valid']:
            assert contract.parse_route_preflight_result_v4(json.dumps(payload))
        else:
            with pytest.raises(contract.RoutePreflightError):
                contract.parse_route_preflight_result_v4(json.dumps(payload))

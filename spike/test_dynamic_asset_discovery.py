"""Dynamic discovery hints never substitute for independent object proof."""
import asyncio
import json
import time
from dataclasses import asdict

import pytest
import route_preflight as contract
import tproxy
import pending_navigation_probe_runtime as runtime
from test_owned_parent_assets import learned_parent  # noqa: F401
from test_tproxy_doh import reset_smart_dns_state  # noqa: F401


def job():
    return contract.RoutePreflightJobV3('a'*32, 'parent.example', ('owned_geph',),
                                      1000, 21000, asset_hosts=('images.example.net',))


def result(url='https://images.example.net/dynamic.png?Signature=ephemeral'):
    return contract.RoutePreflightResultV3('a'*32, 'parent.example', 'owned_geph',
                                         'usable', 1500, asset_url=url)


def test_v3_roundtrip_binding_runtime_and_private_repr():
    j = contract.parse_route_preflight_job_v3(json.dumps(asdict(job())))
    r = contract.parse_route_preflight_result_v3(json.dumps(asdict(result())))
    assert contract.validate_route_preflight_result_v1(j, r, now_unix_ms=1600).accepted
    assert 'Signature' not in repr(r)
    assert runtime._validate_job(json.loads(json.dumps(asdict(j))), 1200)
    assert not contract.validate_route_preflight_result_v1(j, result('https://other.example/image.png'), now_unix_ms=1600).accepted
    assert not contract.validate_route_preflight_result_v1(j, r, now_unix_ms=21001).accepted
    assert not contract.validate_route_preflight_result_v1(j, r, now_unix_ms=1600, capability_seen=True).accepted


@pytest.mark.parametrize('url', ['http://images.example.net/a', 'https://127.0.0.1/a',
    'https://images.example.net:444/a', 'https://user@images.example.net/a',
    'https://images.example.net/a#fragment', 'https://images.example.net/a\r\nX:y',
    'https://images.example.net/'+'a'*1024, 'https://images.example.net\\@evil.example/a', None])
def test_unsafe_hint_refused(url):
    with pytest.raises(contract.RoutePreflightError):
        contract.parse_route_preflight_result_v3(json.dumps(asdict(result(url))))


def test_old_protocols_do_not_gain_url_fields():
    for parser in (contract.parse_route_preflight_result_v1, contract.parse_route_preflight_result_v2):
        with pytest.raises(contract.RoutePreflightError):
            parser(json.dumps(asdict(result())))
    bad = asdict(result()); bad['outcome'] = 'challenge_or_auth'
    with pytest.raises(contract.RoutePreflightError):
        contract.parse_route_preflight_result_v3(json.dumps(bad))


def test_candidate_requires_fresh_unprotected_unlearned_failure(monkeypatch, learned_parent):
    now = time.monotonic()
    monkeypatch.setattr(tproxy, '_local_partial_stalls', {
        'stale.example': {'system': now-10000}, 'discord.com': {'system': now},
        'googlevideo.com': {'system': now}, learned_parent: {'system': now}})
    assert tproxy._dynamic_asset_failure_candidates(learned_parent) == ()
    tproxy._local_partial_stalls['images.example.net'] = {'system': now}
    assert tproxy._dynamic_asset_failure_candidates(learned_parent) == ('images.example.net',)


def test_dynamic_hint_runs_independent_child_proof_and_is_forgotten(monkeypatch, learned_parent):
    monkeypatch.setattr(tproxy, '_discover_owned_preflight_assets', lambda *a: None)
    tproxy._local_partial_stalls['images.example.net'] = {'system': time.monotonic()}
    asset = tproxy.bootstrap_asset_preflight.ephemeral_dynamic_asset(result().asset_url, 'images.example.net')
    async def browser(j, peer, deadline, **kw):
        assert isinstance(j, contract.RoutePreflightJobV3)
        assert j.asset_hosts == ('images.example.net',)
        kw['asset_sink'].append(asset)
        return None  # discovery MUST NOT need or generate parent proof
    monkeypatch.setattr(tproxy, '_run_headless_owned_geph_preflight', browser)
    calls = []
    async def child(item, parent, ip, healthy, final, **kw):
        assert tproxy._route_preflight_child_lease_valid_locked(kw['execution_lease'], parent, ip)
        assert b'Signature=ephemeral' in item.build_range_request()
        assert not tproxy._auto_geph_learned_exact_host(item.exact_host)
        calls.append(item.exact_host)
        return False, tproxy.SEMANTIC_OUTCOME_NAVIGATION_PENDING
    monkeypatch.setattr(tproxy, '_run_bootstrap_asset_preflight', child)
    asyncio.run(tproxy._check_learned_parent_assets(learned_parent, '8.8.8.8'))
    assert calls == ['images.example.net']
    assert not tproxy._auto_geph_learned_exact_host('images.example.net')
    assert not tproxy._route_preflight_execution_leases
    with pytest.raises(RuntimeError): asset.build_range_request()


def test_real_broker_claim_is_bound_and_hint_is_not_route_authority(monkeypatch, learned_parent):
    from concurrent.futures import Future
    from dataclasses import replace
    now = time.monotonic(); now_ms = int(time.time()*1000)
    j = replace(job(), issued_at_unix_ms=now_ms, deadline_unix_ms=now_ms+20000)
    future = Future()
    monkeypatch.setattr(tproxy, '_route_preflight_browser_capabilities', {
        j.capability: tproxy._RoutePreflightBrowserCapability(j, future, 41, now+20)})
    monkeypatch.setattr(tproxy, '_route_preflight_browser_claims', {})
    assert tproxy._pending_navigation_probe_worker_claimed(tproxy._route_preflight_job_payload(j), '0123456789abcdef', now=now)
    r = replace(result(), observed_at_unix_ms=now_ms)
    assert tproxy._submit_browser_probe_result(asdict(r), '0123456789abcdef', now=now)
    assert future.result().asset_url == r.asset_url
    assert not tproxy._submit_browser_probe_result(asdict(r), '0123456789abcdef', now=now)
    assert not tproxy._auto_geph_learned_exact_host(j.asset_hosts[0])


def test_dynamic_cancellation_forgets_targets_and_releases_lease(monkeypatch, learned_parent):
    monkeypatch.setattr(tproxy, '_discover_owned_preflight_assets', lambda *a: None)
    asset = tproxy.bootstrap_asset_preflight.ephemeral_dynamic_asset(result().asset_url, 'images.example.net')
    async def scenario():
        entered = asyncio.Event()
        async def discover(parent, address, sink):
            sink.append(asset); entered.set()
            await asyncio.Future()
        monkeypatch.setattr(tproxy, '_discover_dynamic_parent_asset', discover)
        task = asyncio.create_task(tproxy._check_learned_parent_assets(learned_parent, '8.8.8.8'))
        await entered.wait(); task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(scenario())
    assert not tproxy._route_preflight_execution_leases
    with pytest.raises(RuntimeError): asset.build_range_request()


def test_newer_api_failure_cannot_starve_older_image_hint(monkeypatch, learned_parent):
    from dataclasses import replace
    now = time.monotonic()
    monkeypatch.setattr(tproxy, '_local_partial_stalls', {
        'api.example.net': {'system': now}, 'images.example.net': {'system': now-1}})
    hosts = tproxy._dynamic_asset_failure_candidates(learned_parent)
    assert hosts == ('api.example.net', 'images.example.net')
    j = contract.parse_route_preflight_job_v3(json.dumps(asdict(replace(job(), asset_hosts=hosts))))
    r = contract.parse_route_preflight_result_v3(json.dumps(asdict(result())))
    assert contract.validate_route_preflight_result_v1(j, r, now_unix_ms=1600).accepted
    for bad in ([], list(hosts)*3, ['images.example.net']*2):
        payload = asdict(j); payload['asset_hosts'] = bad
        with pytest.raises(contract.RoutePreflightError):
            contract.parse_route_preflight_job_v3(json.dumps(payload))

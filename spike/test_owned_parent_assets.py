"""An owned-only root enumerates objects without lending them route authority."""
import asyncio
import time

import pytest
import tproxy
from test_tproxy_doh import _enable_owned_geph_preflight, reset_smart_dns_state  # noqa: F401


def response(body):
    return (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
            + str(len(body)).encode() + b'\r\n\r\n' + body, False, False)


def test_complete_owned_redirect_discovers_critical_image(monkeypatch):
    body = b'<html><body><h1>Useful page</h1><img fetchpriority="high" src="https://images.example.net/hero.webp"></body></html>'
    calls = []
    def fetch(host, deadline, target='/'):
        calls.append((host, target))
        if target == '/':
            return (b'HTTP/1.1 302 Found\r\nLocation: /en\r\nContent-Length: 0\r\n\r\n', False, False)
        return response(body)
    monkeypatch.setattr(tproxy, '_semantic_geph_root_response', fetch)
    assets = []
    assert tproxy._semantic_geph_payload_probe('parent.example', _asset_sink=assets) > 0
    assert calls == [('parent.example', '/'), ('parent.example', '/en')]
    assert len(assets) == 1
    assert assets[0].exact_host == 'images.example.net'
    assert b'/hero.webp' in assets[0].build_range_request()
    assert not tproxy._auto_geph
    assets[0].forget()


@pytest.mark.parametrize('complete', [False, True])
def test_owned_discovery_requires_complete_body_and_same_process(monkeypatch, complete):
    monkeypatch.setattr(tproxy, '_owned_geph_confirmation_pid', lambda: 41)
    monkeypatch.setattr(tproxy, '_owned_geph_ready_for_semantic_confirmation', lambda: True)
    monkeypatch.setattr(tproxy, '_owned_geph_confirmation_pid_matches', lambda _: False)
    body = b'<img fetchpriority="high" src="https://images.example.net/hero.webp">'
    raw, _, _ = response(body)
    monkeypatch.setattr(tproxy, '_semantic_geph_root_response', lambda *a: (raw if complete else raw[:-5], False, False))
    assets = []
    tproxy._discover_owned_preflight_assets('parent.example', time.monotonic()+2, assets)
    assert not assets


@pytest.mark.parametrize('parent_proven', [False, True])
def test_owned_parent_retains_child_lease_and_requires_independent_child_proof(monkeypatch, parent_proven):
    _enable_owned_geph_preflight(monkeypatch)
    host = 'parent.example'
    asset = tproxy.bootstrap_asset_preflight.EphemeralBootstrapAsset(
        exact_host='images.example.net', host_header='images.example.net', request_target='/hero.webp')
    monkeypatch.setattr(tproxy, '_discover_owned_preflight_assets', lambda h, d, sink: sink.append(asset))
    async def browser(job, peer, deadline, **kwargs):
        if not parent_proven:
            return None
        return tproxy._RoutePreflightOwnedGephProof(
            marker=tproxy._ROUTE_PREFLIGHT_OWNED_GEPH_PROOF,
            capability=job.capability, host=job.host, exact_address=kwargs['exact_address'],
            deadline_monotonic=deadline, issued_at_unix_ms=job.issued_at_unix_ms,
            deadline_unix_ms=job.deadline_unix_ms, confirmed_pid=41,
            reason='fixture', schema_version=2, bytes_read=1)
    monkeypatch.setattr(tproxy, '_run_headless_owned_geph_preflight', browser)
    calls = []
    async def child(item, parent, ip, healthy, final, **kwargs):
        lease = kwargs['execution_lease']
        assert lease.child_reserved and lease.child_ready
        assert tproxy._route_preflight_child_lease_valid_locked(lease, parent, ip)
        assert final > healthy > time.monotonic()
        assert not tproxy._auto_geph_learned_exact_host(item.exact_host)
        calls.append(item.exact_host)
        # Parent proof alone must NOT commit the child.
        return False, tproxy.SEMANTIC_OUTCOME_NAVIGATION_PENDING
    monkeypatch.setattr(tproxy, '_run_bootstrap_asset_preflight', child)
    claim = asyncio.run(tproxy._run_initial_route_preflight(host, '8.8.8.8',
        direct_probe=lambda *a: tproxy._SemanticPlainPreflightObservation(
            tproxy.SEMANTIC_OUTCOME_NAVIGATION_PENDING, safe_incomplete=True)))
    assert bool(claim) == parent_proven
    assert calls == (['images.example.net'] if parent_proven else [])
    assert not tproxy._auto_geph_learned_exact_host('images.example.net')
    with pytest.raises(RuntimeError):
        asset.build_range_request()
    assert not tproxy._route_preflight_inflight
    assert not tproxy._route_preflight_execution_leases


def test_cancellation_drains_owned_discovery_before_releasing_lease(monkeypatch):
    import threading
    _enable_owned_geph_preflight(monkeypatch)
    entered, release = threading.Event(), threading.Event()
    asset = tproxy.bootstrap_asset_preflight.EphemeralBootstrapAsset(
        exact_host='images.example.net', host_header='images.example.net', request_target='/hero.webp')
    def discover(h, deadline, sink):
        entered.set()
        assert release.wait(2)
        sink.append(asset)
    monkeypatch.setattr(tproxy, '_discover_owned_preflight_assets', discover)
    async def browser(*args, **kwargs):
        await asyncio.Future()
    monkeypatch.setattr(tproxy, '_run_headless_owned_geph_preflight', browser)
    async def scenario():
        task = asyncio.create_task(tproxy._run_initial_route_preflight('parent.example', '8.8.8.8',
            direct_probe=lambda *a: tproxy._SemanticPlainPreflightObservation(
                tproxy.SEMANTIC_OUTCOME_NAVIGATION_PENDING, safe_incomplete=True)))
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        assert tproxy._route_preflight_execution_leases
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(scenario())
    assert not tproxy._route_preflight_inflight
    assert not tproxy._route_preflight_execution_leases
    with pytest.raises(RuntimeError):
        asset.build_range_request()


def test_expired_discovery_never_starts_network_work(monkeypatch):
    monkeypatch.setattr(tproxy, '_owned_geph_confirmation_pid',
                        lambda: pytest.fail('expired work must not start'))
    tproxy._discover_owned_preflight_assets('parent.example', time.monotonic()-1, [])

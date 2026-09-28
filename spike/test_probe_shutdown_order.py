"""Workers must finish using the broker before its socket is removed."""
import asyncio
import pytest
import tproxy


@pytest.mark.parametrize('listener_finishes', [False, True])
def test_worker_quiesces_before_broker_close(monkeypatch, listener_finishes):
    events = []
    class Listener:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def serve_forever(self):
            if not listener_finishes:
                await asyncio.Future()
        def close(self): events.append('listener_closed')
        async def wait_closed(self): pass
    class Broker:
        async def close(self): events.append('broker_closed')
    async def quiesce():
        assert 'broker_closed' not in events
        await asyncio.sleep(0)
        events.append('worker_finished')
    async def cancel_discovery(): events.append('discovery_drained')
    monkeypatch.setattr(tproxy, '_cancel_recent_parent_asset_recovery', cancel_discovery)
    async def drain(timeout): return True
    monkeypatch.setattr(tproxy, 'pf_teardown', lambda: True)
    monkeypatch.setattr(tproxy, 'wait_for_connections_to_drain', drain)
    async def run():
        stop = asyncio.Event()
        if not listener_finishes: stop.set()
        return await tproxy.serve_until_shutdown(
            Listener(), stop, auxiliary_servers=(Broker(),),
            before_auxiliary_close=quiesce)
    assert asyncio.run(run())
    assert events.index('discovery_drained') < events.index('worker_finished') < events.index('broker_closed')


def test_quiesce_disables_admission_before_worker_wait(monkeypatch):
    monkeypatch.setattr(tproxy, '_pending_navigation_probe_available', True)
    monkeypatch.setattr(tproxy, '_route_preflight_headless_available', True)
    def finish():
        assert not tproxy._pending_navigation_probe_available
        assert not tproxy._route_preflight_headless_available
        return True
    monkeypatch.setattr(tproxy, '_close_pending_navigation_probe_worker', finish)
    assert asyncio.run(tproxy._quiesce_pending_navigation_probe_worker())


@pytest.mark.parametrize('existing', [False, True])
def test_shutdown_refuses_late_worker_acquisition(monkeypatch, existing):
    import threading
    stopped = threading.Event()
    stopped.set()
    monkeypatch.setattr(tproxy, '_shutdown_started', stopped)
    monkeypatch.setattr(tproxy, '_pending_navigation_probe_worker',
                        object() if existing else None)
    monkeypatch.setattr(tproxy, '_get_pending_navigation_probe_runtime',
                        lambda: pytest.fail('shutdown must not create a runtime'))
    with pytest.raises(RuntimeError, match='shutting down'):
        tproxy._get_pending_navigation_probe_worker(allow_production_headless=True)


def test_owned_stop_allows_worker_drain_before_force_kill(monkeypatch):
    import signal
    clock = [0.0]
    signals = []
    monkeypatch.setattr(tproxy.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(tproxy.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(tproxy, '_process_command_for_pid',
                        lambda pid: 'owned' if clock[0] < 20 else None)
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda cmd: cmd == 'owned')
    monkeypatch.setattr(tproxy.os, 'kill', lambda pid, sig: signals.append(sig))
    monkeypatch.setattr(tproxy, '_flush_private_pf_with_retry', lambda **kw: True)
    monkeypatch.setattr(tproxy, '_restore_pf_loopback_skip', lambda: True)
    assert tproxy._stop_owned_daemon_pid(4242)
    assert signals == [signal.SIGTERM]


def test_launchd_preserves_existing_exit_policy():
    import plistlib
    plist = plistlib.loads(tproxy.launchd_plist_text(['/owned/daemon'], '/owned').encode())
    # A launchd exit-policy change also requires changing its absence protocol.
    assert 'ExitTimeOut' not in plist

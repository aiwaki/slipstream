"""Workers must finish using the broker before its socket is removed."""
import asyncio
import threading
import pytest
import tproxy


@pytest.mark.parametrize('listener_finishes', [False, True])
def test_worker_quiesces_before_broker_close(monkeypatch, listener_finishes):
    events = []
    monkeypatch.setattr(tproxy, '_shutdown_started', threading.Event())
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


@pytest.mark.parametrize('listener_raises', [False, True])
@pytest.mark.parametrize('drained', [False, True])
def test_unexpected_listener_completion_clears_pf_and_drains_connections(
    monkeypatch, listener_raises, drained
):
    events = []
    failure = OSError('injected accept loop failure')
    terminal = threading.Event()
    monkeypatch.setattr(tproxy, '_shutdown_started', terminal)

    class Listener:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): events.append('listener_context_closed')
        async def serve_forever(self):
            if listener_raises:
                raise failure
        def close(self): events.append('listener_closed')
        async def wait_closed(self): events.append('listener_wait_closed')

    async def cancel_discovery(): events.append('discovery_drained')
    async def drain(timeout):
        events.append('connections_drained')
        return drained
    async def cancel_connections(): events.append('connections_cancelled')
    def clear_pf():
        # A transient pfctl failure must not bypass the ordered shutdown path.
        if 'pf_retry' not in events:
            events.append('pf_retry')
            return False
        events.append('pf_cleared')
        return True

    monkeypatch.setattr(tproxy, '_cancel_recent_parent_asset_recovery', cancel_discovery)
    monkeypatch.setattr(tproxy, 'pf_teardown', clear_pf)
    monkeypatch.setattr(tproxy, 'wait_for_connections_to_drain', drain)
    monkeypatch.setattr(tproxy, 'cancel_active_connections', cancel_connections)

    async def run():
        shutdown = asyncio.Event()
        def before_stop():
            assert terminal.is_set()
            assert shutdown.is_set()
        if listener_raises:
            with pytest.raises(OSError) as raised:
                await tproxy.serve_until_shutdown(Listener(), shutdown, before_stop=before_stop)
            assert raised.value is failure
        else:
            assert await tproxy.serve_until_shutdown(
                Listener(), shutdown, before_stop=before_stop
            ) is drained
        assert not [task for task in asyncio.all_tasks()
                    if task is not asyncio.current_task() and not task.done()]

    asyncio.run(run())
    assert 'pf_cleared' in events, events
    assert events.index('pf_retry') < events.index('pf_cleared') < events.index('listener_closed')
    assert events.index('listener_wait_closed') < events.index('connections_drained')
    assert events.index('connections_drained') < events.index('listener_context_closed')
    assert ('connections_cancelled' in events) == (not drained)


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

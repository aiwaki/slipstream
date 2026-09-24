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
    assert events.index('worker_finished') < events.index('broker_closed')


def test_quiesce_disables_admission_before_worker_wait(monkeypatch):
    monkeypatch.setattr(tproxy, '_pending_navigation_probe_available', True)
    monkeypatch.setattr(tproxy, '_route_preflight_headless_available', True)
    def finish():
        assert not tproxy._pending_navigation_probe_available
        assert not tproxy._route_preflight_headless_available
        return True
    monkeypatch.setattr(tproxy, '_close_pending_navigation_probe_worker', finish)
    assert asyncio.run(tproxy._quiesce_pending_navigation_probe_worker())

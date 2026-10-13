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
    assert events.index('connections_drained') < events.index('listener_closed')
    assert events.index('listener_closed') < events.index('listener_wait_closed')
    assert events.index('connections_drained') < events.index('listener_context_closed')
    assert ('connections_cancelled' in events) == (not drained)
    if not drained:
        assert events.index('connections_cancelled') < events.index('listener_closed')


@pytest.mark.parametrize('legacy_listener', [False, True])
def test_real_listener_shutdown_bounds_an_idle_accepted_stream(monkeypatch, legacy_listener):
    """Server.wait_closed also waits for clients on Python 3.13."""
    monkeypatch.setattr(tproxy, '_shutdown_started', threading.Event())
    monkeypatch.setattr(tproxy, '_connection_tasks', set())
    monkeypatch.setattr(tproxy, '_conn_count', 0)
    monkeypatch.setattr(tproxy, 'pf_teardown', lambda: True)

    async def cancel_discovery(): pass
    monkeypatch.setattr(tproxy, '_cancel_recent_parent_asset_recovery', cancel_discovery)

    async def scenario():
        accepted = asyncio.Event()
        handler_finished = asyncio.Event()

        async def handle(reader, writer):
            task = asyncio.current_task()
            tproxy._connection_tasks.add(task)
            tproxy._conn_count += 1
            accepted.set()
            try:
                await reader.read()
            finally:
                writer.close()
                await writer.wait_closed()
                tproxy._conn_count -= 1
                tproxy._connection_tasks.discard(task)
                handler_finished.set()

        server = await asyncio.start_server(handle, '127.0.0.1', 0)
        class LegacyListener:
            """3.13.14 close/cancel waits for clients without closing them."""
            serving = None
            async def __aenter__(self): return self
            async def __aexit__(self, *args):
                self.close()
                await self.wait_closed()
            async def serve_forever(self):
                self.serving = asyncio.current_task()
                try:
                    await asyncio.Future()
                except asyncio.CancelledError:
                    server.close()
                    await server.wait_closed()
                    raise
            def close(self):
                server.close()
                if self.serving is not None:
                    self.serving.cancel()
            async def wait_closed(self): await server.wait_closed()

        listener = LegacyListener() if legacy_listener else server
        client = None
        stopping = None
        try:
            reader, client = await asyncio.open_connection(
                '127.0.0.1', server.sockets[0].getsockname()[1],
            )
            await asyncio.wait_for(accepted.wait(), timeout=1)
            shutdown = asyncio.Event()
            shutdown.set()
            stopping = asyncio.create_task(tproxy.serve_until_shutdown(
                listener, shutdown, drain_timeout=0.02,
            ))
            done, _ = await asyncio.wait((stopping,), timeout=0.5)
            stopped_within_budget = stopping in done
            if not stopped_within_budget:
                # Unblock a broken implementation without hiding the failure
                # behind an unbounded asyncio.run teardown or outer timeout.
                client.close()
            drained = await asyncio.wait_for(stopping, timeout=1)
            assert stopped_within_budget, 'wait_closed blocked before grace/cancellation'
            assert not drained
            assert handler_finished.is_set()
            assert await asyncio.wait_for(reader.read(), timeout=1) == b''
            assert not tproxy._connection_tasks
        finally:
            if client is not None:
                client.close()
                await client.wait_closed()
            server.close()
            for task in tuple(tproxy._connection_tasks):
                task.cancel()
            await asyncio.gather(*tuple(tproxy._connection_tasks), return_exceptions=True)
            await server.wait_closed()
            if stopping is not None and not stopping.done():
                stopping.cancel()
                await asyncio.gather(stopping, return_exceptions=True)

    asyncio.run(scenario())


def test_real_listener_preserves_accepted_stream_during_grace(monkeypatch):
    monkeypatch.setattr(tproxy, '_shutdown_started', threading.Event())
    monkeypatch.setattr(tproxy, '_connection_tasks', set())
    monkeypatch.setattr(tproxy, '_conn_count', 0)

    async def cancel_discovery(): pass
    monkeypatch.setattr(tproxy, '_cancel_recent_parent_asset_recovery', cancel_discovery)

    async def scenario():
        accepted = asyncio.Event()
        pf_cleared = asyncio.Event()
        monkeypatch.setattr(tproxy, 'pf_teardown', lambda: pf_cleared.set() or True)

        async def respond(reader, writer):
            accepted.set()
            if await reader.readline() == b'ping\n':
                writer.write(b'pong\n')
                await writer.drain()
            await reader.read()

        monkeypatch.setattr(tproxy, '_handle_impl', respond)
        server = await asyncio.start_server(tproxy.handle, '127.0.0.1', 0)
        reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
        stopping = None
        try:
            await asyncio.wait_for(accepted.wait(), timeout=1)
            shutdown = asyncio.Event()
            shutdown.set()
            stopping = asyncio.create_task(tproxy.serve_until_shutdown(
                server, shutdown, drain_timeout=0.5,
            ))
            await asyncio.wait_for(pf_cleared.wait(), timeout=1)
            writer.write(b'ping\n')
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), timeout=1)
            writer.close()
            await writer.wait_closed()
            assert await asyncio.wait_for(stopping, timeout=1)
            assert response == b'pong\n', 'accepted stream was closed before its grace period'
        finally:
            writer.close()
            await writer.wait_closed()
            for task in tuple(tproxy._connection_tasks):
                task.cancel()
            await asyncio.gather(*tuple(tproxy._connection_tasks), return_exceptions=True)
            server.close()
            await server.wait_closed()
            if stopping is not None and not stopping.done():
                stopping.cancel()
                await asyncio.gather(stopping, return_exceptions=True)

    asyncio.run(scenario())


def test_terminal_shutdown_rejects_new_stream_before_upstream_admission(monkeypatch):
    stopped = threading.Event()
    stopped.set()
    monkeypatch.setattr(tproxy, '_shutdown_started', stopped)
    monkeypatch.setattr(tproxy, '_connection_tasks', set())
    monkeypatch.setattr(tproxy, '_conn_count', 0)
    class Writer:
        closed = False
        def close(self): self.closed = True
        async def wait_closed(self): pass
    async def unexpected_admission(*args):
        pytest.fail('terminal shutdown must not admit a new upstream stream')
    monkeypatch.setattr(tproxy, '_handle_impl', unexpected_admission)
    writer = Writer()
    asyncio.run(tproxy.handle(object(), writer))
    assert writer.closed
    assert tproxy._conn_count == 0
    assert not tproxy._connection_tasks


@pytest.mark.parametrize('cancel_during_relay', [False, True])
def test_handle_releases_bookkeeping_when_cancelled_during_writer_close(
    monkeypatch, cancel_during_relay
):
    monkeypatch.setattr(tproxy, '_shutdown_started', threading.Event())
    monkeypatch.setattr(tproxy, '_connection_tasks', set())
    monkeypatch.setattr(tproxy, '_conn_count', 0)

    async def scenario():
        entered = asyncio.Event()
        closing = asyncio.Event()
        class Writer:
            def __init__(self):
                self.transport = self
                self.aborted = False
            def close(self): pass
            def abort(self): self.aborted = True
            async def wait_closed(self):
                closing.set()
                await asyncio.Future()
        async def relay(*args):
            entered.set()
            if cancel_during_relay:
                await asyncio.Future()
        monkeypatch.setattr(tproxy, '_handle_impl', relay)
        writer = Writer()
        task = asyncio.create_task(tproxy.handle(object(), writer))
        await entered.wait()
        if cancel_during_relay:
            task.cancel()
        await asyncio.wait_for(closing.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert tproxy._conn_count == 0
        assert task not in tproxy._connection_tasks
        assert writer.aborted

    asyncio.run(scenario())


def test_timed_out_writer_close_releases_real_server_transport(monkeypatch):
    """A peer which stops reading must not strand Server.wait_closed forever."""
    monkeypatch.setattr(tproxy, '_shutdown_started', threading.Event())
    monkeypatch.setattr(tproxy, '_connection_tasks', set())
    monkeypatch.setattr(tproxy, '_conn_count', 0)

    async def scenario():
        import socket
        accepted = asyncio.Event()
        start_write = asyncio.Event()
        handler_done = asyncio.Event()
        transports = []
        buffered = []

        async def relay(reader, writer):
            task = asyncio.current_task()
            task.add_done_callback(lambda _task: handler_done.set())
            transports.append(writer.transport)
            writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            accepted.set()
            await start_write.wait()
            writer.write(b'x' * (8 * 1024 * 1024))
            buffered.append(writer.transport.get_write_buffer_size())

        monkeypatch.setattr(tproxy, '_handle_impl', relay)
        server = await asyncio.start_server(tproxy.handle, '127.0.0.1', 0)
        _, client = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
        waiting = None
        try:
            client.transport.pause_reading()
            await asyncio.wait_for(accepted.wait(), timeout=1)
            start_write.set()
            await asyncio.wait_for(handler_done.wait(), timeout=3)
            assert buffered[0] > 0
            assert tproxy._conn_count == 0
            server.close()
            waiting = asyncio.create_task(server.wait_closed())
            done, _ = await asyncio.wait((waiting,), timeout=0.2)
            released_without_external_abort = waiting in done
        finally:
            for transport in transports:
                transport.abort()
            client.transport.abort()
            for task in tuple(tproxy._connection_tasks):
                task.cancel()
            await asyncio.gather(*tuple(tproxy._connection_tasks), return_exceptions=True)
            server.close()
            await server.wait_closed()
            if waiting is not None:
                await waiting
        assert released_without_external_abort, 'close timeout left an accepted transport alive'

    asyncio.run(scenario())


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

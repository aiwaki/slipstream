"""Local-only regressions for the bundled Telegram byte stream and ownership."""
import asyncio
import importlib
import importlib.util
from pathlib import Path
import sys

import pytest

_ROOT = Path(__file__).resolve().parents[1] / 'vendor/tg-ws-proxy/proxy'
_NAME = 'slipstream_tg_vendor'
if _NAME not in sys.modules:
    spec = importlib.util.spec_from_file_location(
        _NAME, _ROOT / '__init__.py', submodule_search_locations=[str(_ROOT)])
    package = importlib.util.module_from_spec(spec)
    sys.modules[_NAME] = package
    spec.loader.exec_module(package)
raw = importlib.import_module(_NAME + '.raw_websocket')
pool = importlib.import_module(_NAME + '.pool')
runtime = importlib.import_module(_NAME + '.tg_ws_proxy')


class Writer:
    def __init__(self):
        self.closed = False
        self.sent = []
        self.transport = self
        self.drain_entered = asyncio.Event()
        self.block_drain = False

    def get_extra_info(self, name, default=None):
        return default

    def write(self, data):
        self.sent.append(data)

    async def drain(self):
        self.drain_entered.set()
        if self.block_drain:
            await asyncio.Future()

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def is_closing(self):
        return self.closed


def test_fragmented_upstream_websocket_preserves_all_mtproto_bytes():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(b'\x02\x03one\x89\x01p\x80\x03two\x88\x00')
        reader.feed_eof()
        ws = raw.RawWebSocket(reader, Writer())
        chunks = []
        while (chunk := await ws.recv()) is not None:
            chunks.append(chunk)
        assert b''.join(chunks) == b'onetwo'
    asyncio.run(scenario())


def test_upstream_close_does_not_skip_transport_cleanup():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(b'\x88\x00')
        writer = Writer()
        ws = raw.RawWebSocket(reader, writer)
        assert await ws.recv() is None
        await ws.close()
        assert writer.closed
    asyncio.run(scenario())


def test_cancelled_upgrade_closes_connected_writer(monkeypatch):
    async def scenario():
        writer = Writer()
        reader = asyncio.StreamReader()
        async def connect(*args, **kwargs):
            return reader, writer
        monkeypatch.setattr(raw.asyncio, 'open_connection', connect)
        task = asyncio.create_task(raw.RawWebSocket.connect('unused', 'unused'))
        await writer.drain_entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert writer.closed
    asyncio.run(scenario())


def test_cancelled_close_still_closes_transport():
    async def scenario():
        writer = Writer()
        writer.block_drain = True
        ws = raw.RawWebSocket(asyncio.StreamReader(), writer)
        task = asyncio.create_task(ws.close())
        await writer.drain_entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert writer.closed
    asyncio.run(scenario())


@pytest.mark.parametrize('kind', ['direct', 'worker'])
def test_cancelled_refill_reclaims_successful_unconsumed_connections(monkeypatch, kind):
    async def scenario():
        instance = pool._WsPool() if kind == 'direct' else pool._CfWorkerPool()
        monkeypatch.setattr(pool.proxy_config, 'pool_size', 2)
        sibling_ready = asyncio.Event()
        writer = Writer()
        ws = raw.RawWebSocket(asyncio.StreamReader(), writer)
        calls = 0
        async def connect(*args):
            nonlocal calls
            calls += 1
            if calls == 1:
                await asyncio.Future()
            sibling_ready.set()
            return ws
        monkeypatch.setattr(instance, '_connect_one', connect)
        args = ((2, False), 'unused', ['unused']) if kind == 'direct' else ((2, 'unused'), 'unused')
        task = asyncio.create_task(instance._refill(*args))
        await sibling_ready.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert writer.closed
    asyncio.run(scenario())


@pytest.mark.parametrize('mode', ['cancel', 'stop', 'restart_stop'])
@pytest.mark.parametrize('auto_close_clients', [True, False])
def test_proxy_shutdown_drains_listener_and_client_tasks(monkeypatch, mode, auto_close_clients):
    if not auto_close_clients:
        # Some supported Python releases join accepted transports when
        # serve_forever is cancelled without proactively closing them. Use a
        # real Server and real TCP clients, disabling only that implicit close.
        monkeypatch.setattr(asyncio.Server, 'close_clients', lambda self: None)
    async def scenario():
        entered, finished = asyncio.Event(), asyncio.Event()
        async def client(reader, writer, secret):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                writer.close()
                await writer.wait_closed()
                finished.set()
        monkeypatch.setattr(runtime, '_handle_client', client)
        for name, value in [('host', '127.0.0.1'), ('port', 0),
                            ('fallback_cfproxy', False), ('dc_redirects', {}),
                            ('cfproxy_worker_domains', [])]:
            monkeypatch.setattr(runtime.proxy_config, name, value)
        baseline = asyncio.all_tasks()
        stop = asyncio.Event()
        monkeypatch.setattr(runtime, 'LISTENER_RESTART_DELAY', .001)
        monkeypatch.setattr(runtime, 'LISTENER_CHECK_INTERVAL', .002)
        run = asyncio.create_task(runtime._run(stop))
        writer = None
        try:
            for _ in range(50):
                if runtime._server_instance is not None:
                    break
                await asyncio.sleep(0.002)
            server = runtime._server_instance
            assert server is not None
            _, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            await entered.wait()
            if mode == 'restart_stop':
                server.close()
                for _ in range(100):
                    if runtime._server_instance is not server:
                        break
                    await asyncio.sleep(.002)
                assert runtime._server_instance is not server
            if mode == 'cancel':
                run.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await run
            else:
                stop.set()
                await run
            await asyncio.sleep(0)
            assert finished.is_set(), 'accepted client survived owner cancellation'
            assert runtime._server_instance is None
            leaked = [t for t in asyncio.all_tasks() - baseline if not t.done()]
            assert not leaked
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
            remaining = [t for t in asyncio.all_tasks() - baseline if not t.done()]
            for task in remaining:
                task.cancel()
            await asyncio.gather(*remaining, return_exceptions=True)
            runtime._server_instance = None
    asyncio.run(scenario())


@pytest.mark.parametrize('batch', [False, True])
def test_cancelled_initial_websocket_send_closes_transport(batch):
    async def scenario():
        writer = Writer()
        writer.block_drain = True
        ws = raw.RawWebSocket(asyncio.StreamReader(), writer)
        task = asyncio.create_task(ws.send_batch([b'init']) if batch else ws.send(b'init'))
        await writer.drain_entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert writer.closed
    asyncio.run(scenario())


def test_empty_websocket_fragments_do_not_signal_stream_eof():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(b'\x02\x00\x00\x00\x80\x03end\x82\x00\x82\x04next')
        ws = raw.RawWebSocket(reader, Writer())
        assert await ws.recv() == b'end'
        assert await ws.recv() == b'next'
    asyncio.run(scenario())


def test_empty_fake_tls_record_does_not_signal_stream_eof():
    fake_tls = importlib.import_module(_NAME + '.fake_tls')
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(b'\x17\x03\x03\x00\x00\x17\x03\x03\x00\x04data')
        stream = fake_tls.FakeTlsStream(reader, Writer())
        assert await stream.readexactly(4) == b'data'
    asyncio.run(scenario())


def test_cancelled_tcp_initial_send_closes_upstream(monkeypatch):
    bridge = importlib.import_module(_NAME + '.bridge')
    async def scenario():
        writer = Writer()
        writer.block_drain = True
        async def connect(*args, **kwargs):
            return asyncio.StreamReader(), writer
        monkeypatch.setattr(bridge.asyncio, 'open_connection', connect)
        task = asyncio.create_task(bridge._tcp_fallback(None, None, 'unused', 443, b'init', 'test', None))
        await writer.drain_entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert writer.closed
    asyncio.run(scenario())


@pytest.mark.parametrize('kind', ['direct', 'worker'])
def test_pool_reset_closes_idle_and_cancels_pending_refill(monkeypatch, kind):
    async def scenario():
        instance = pool._WsPool() if kind == 'direct' else pool._CfWorkerPool()
        monkeypatch.setattr(pool.proxy_config, 'pool_size', 1)
        key = (2, False) if kind == 'direct' else (2, 'unused')
        idle_writer = Writer()
        from collections import deque
        instance._idle[key] = deque([(raw.RawWebSocket(asyncio.StreamReader(), idle_writer), 0)])
        entered, finished = asyncio.Event(), asyncio.Event()
        async def connect(*args):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                finished.set()
        monkeypatch.setattr(instance, '_connect_one', connect)
        args = ((3, False), 'unused', ['unused']) if kind == 'direct' else ((3, 'unused'), 'unused')
        instance._schedule_refill(*args)
        await entered.wait()
        await instance.reset()
        assert finished.is_set()
        assert idle_writer.closed
        assert not instance._tasks and not instance._idle and not instance._refilling
    asyncio.run(scenario())


def test_cancelled_proxy_run_stops_domain_refresh_and_rejects_late_result(monkeypatch):
    import threading
    config = importlib.import_module(_NAME + '.config')
    entered, release = threading.Event(), threading.Event()
    updates, threads = [], []
    real_thread = threading.Thread
    def capture_thread(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        if kwargs.get('name') == 'cfproxy-domains-refresh':
            threads.append(thread)
        return thread
    monkeypatch.setattr(config.threading, 'Thread', capture_thread)
    def fetch():
        entered.set()
        release.wait(2)
        return ['valid%d.example' % i for i in range(20)]
    monkeypatch.setattr(config, '_fetch_cfproxy_domain_list', fetch)
    monkeypatch.setattr(config.balancer, 'update_domains_list', lambda domains: updates.append(list(domains)))
    for name, value in [('host', '127.0.0.1'), ('port', 0),
                        ('fallback_cfproxy', True), ('dc_redirects', {}),
                        ('cfproxy_user_domains', []), ('cfproxy_worker_domains', [])]:
        monkeypatch.setattr(runtime.proxy_config, name, value)
    async def scenario():
        run = asyncio.create_task(runtime._run(asyncio.Event()))
        try:
            for _ in range(100):
                if entered.is_set() and runtime._server_instance is not None:
                    break
                await asyncio.sleep(.002)
            assert entered.is_set()
            run.cancel()
            with pytest.raises(asyncio.CancelledError):
                await run
            stopped = config._refresh_stop.is_set()
            release.set()
            threads[0].join(timeout=1)
            assert not threads[0].is_alive()
            assert stopped, 'owner shutdown left periodic refresh running'
            assert len(updates) == 1, 'stopped generation published its late fetch'
        finally:
            config._refresh_stop.set()
            release.set()
            for thread in threads:
                thread.join(timeout=1)
            if not run.done():
                run.cancel()
                await asyncio.gather(run, return_exceptions=True)
    asyncio.run(scenario())


@pytest.mark.parametrize('kind', ['direct', 'worker'])
def test_immediate_shutdown_owns_expired_socket_before_close_task_starts(monkeypatch, kind):
    from collections import deque
    import time
    async def scenario():
        instance = pool._WsPool() if kind == 'direct' else pool._CfWorkerPool()
        monkeypatch.setattr(pool.proxy_config, 'pool_size', 0)
        key = (2, False) if kind == 'direct' else (2, 'unused')
        writer = Writer()
        ws = raw.RawWebSocket(asyncio.StreamReader(), writer)
        instance._idle[key] = deque([(ws, time.monotonic() - 200)])
        args = (2, False, 'unused', []) if kind == 'direct' else (2, 'unused', 'unused')
        assert await instance.get(*args) is None
        await instance.close()
        assert writer.closed
        assert not instance._tasks
    asyncio.run(scenario())


@pytest.mark.parametrize('kind', ['raw', 'handler', 'ws_bridge', 'tcp_bridge'])
def test_stuck_writer_shutdown_is_bounded(monkeypatch, kind):
    bridge = importlib.import_module(_NAME + '.bridge')
    class StuckWriter(Writer):
        def __init__(self):
            super().__init__()
            self.aborted = False
            self.close_entered = asyncio.Event()
        async def wait_closed(self):
            self.close_entered.set()
            await asyncio.Future()
        def abort(self):
            self.aborted = True
    async def scenario():
        monkeypatch.setattr(raw, 'CLOSE_TIMEOUT', .01, raising=False)
        writer = StuckWriter()
        reader = asyncio.StreamReader()
        reader.feed_eof()
        if kind == 'raw':
            operation = raw.RawWebSocket(reader, writer).close()
        elif kind == 'handler':
            async def no_init(*args):
                return None
            monkeypatch.setattr(runtime, '_read_client_init', no_init)
            operation = runtime._handle_client(reader, writer, b'')
        elif kind == 'ws_bridge':
            ws_reader = asyncio.StreamReader()
            ws_reader.feed_data(b'\x88\x00')
            operation = bridge.bridge_ws_reencrypt(reader, writer, raw.RawWebSocket(ws_reader, Writer()), 'test', None)
        else:
            other = asyncio.StreamReader()
            other.feed_eof()
            operation = bridge._bridge_tcp_reencrypt(reader, writer, other, Writer(), 'test', None)
        task = asyncio.create_task(operation)
        try:
            # A busy runner can delay bridge startup before close_writer even
            # starts its own deadline. Synchronize on the actual stuck close,
            # then use a generous outer watchdog, not a scheduler-speed test.
            await asyncio.wait_for(writer.close_entered.wait(), timeout=3)
            done, _ = await asyncio.wait([task], timeout=3)
            assert done, 'close waited indefinitely for a non-responsive transport'
            await task
            assert writer.closed and writer.aborted
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    asyncio.run(scenario())


@pytest.mark.parametrize('kind', ['direct', 'worker'])
def test_cancelled_pool_shutdown_drains_unclaimed_and_idle_sockets(monkeypatch, kind):
    from collections import deque
    async def scenario():
        monkeypatch.setattr(raw, 'CLOSE_TIMEOUT', .01)
        monkeypatch.setattr(pool.proxy_config, 'pool_size', 3)
        instance = pool._WsPool() if kind == 'direct' else pool._CfWorkerPool()
        baseline = asyncio.all_tasks()
        writers = [Writer() for _ in range(3)]
        writers[0].block_drain = True
        connected = asyncio.Event()
        calls = 0
        async def connect(*args):
            nonlocal calls
            calls += 1
            if calls == 1:
                await asyncio.Future()
            if calls == 3:
                connected.set()
            return raw.RawWebSocket(asyncio.StreamReader(), writers[calls - 2])
        monkeypatch.setattr(instance, '_connect_one', connect)
        idle_key = (4, False) if kind == 'direct' else (4, 'unused')
        instance._idle[idle_key] = deque([(raw.RawWebSocket(asyncio.StreamReader(), writers[2]), 0)])
        args = ((2, False), 'unused', ['unused']) if kind == 'direct' else ((2, 'unused'), 'unused')
        instance._schedule_refill(*args)
        await connected.wait()
        shutdown = asyncio.create_task(instance.close())
        await writers[0].drain_entered.wait()
        shutdown.cancel()
        with pytest.raises(asyncio.CancelledError):
            await shutdown
        assert all(w.closed for w in writers)
        assert not instance._tasks and not instance._idle
        assert not [t for t in asyncio.all_tasks() - baseline if not t.done()]
    asyncio.run(scenario())


@pytest.mark.parametrize('case', ['eof', 'headers', 'drain', 'slow_lines'])
def test_websocket_upgrade_is_complete_bounded_and_has_one_deadline(monkeypatch, case):
    async def scenario():
        writer = Writer()
        reader = asyncio.StreamReader()
        if case == 'eof':
            reader.feed_data(b'HTTP/1.1 101 Switching Protocols\r\n')
            reader.feed_eof()
        elif case == 'headers':
            monkeypatch.setattr(raw, 'MAX_UPGRADE_HEADERS', 128, raising=False)
            reader.feed_data(b'HTTP/1.1 101 Switching Protocols\r\n' + b'X-Test: ' + b'a' * 256 + b'\r\n\r\n')
        elif case == 'drain':
            writer.block_drain = True
        else:
            class SlowReader:
                def __init__(self):
                    self.lines = iter([b'HTTP/1.1 101 Switching Protocols\r\n', b'X-One: 1\r\n', b'X-Two: 2\r\n', b'\r\n'])
                async def readline(self):
                    await asyncio.sleep(.008)
                    return next(self.lines)
            reader = SlowReader()
        async def connect(*args, **kwargs):
            return reader, writer
        monkeypatch.setattr(raw.asyncio, 'open_connection', connect)
        task = asyncio.create_task(raw.RawWebSocket.connect('unused', 'unused', timeout=.02))
        done, _ = await asyncio.wait([task], timeout=.15)
        if not done:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert done, 'upgrade drain escaped the connection deadline'
        with pytest.raises((raw.WsHandshakeError, asyncio.TimeoutError)):
            await task
        assert writer.closed
    asyncio.run(scenario())


def test_repeated_proxy_cancellation_still_drains_pools(monkeypatch):
    from collections import deque
    async def scenario():
        entered, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def client(reader, writer, secret):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleaning.set()
                try:
                    await release.wait()
                finally:
                    writer.close()
        monkeypatch.setattr(runtime, '_handle_client', client)
        for name, value in [('host', '127.0.0.1'), ('port', 0),
                            ('fallback_cfproxy', False), ('dc_redirects', {}),
                            ('cfproxy_worker_domains', [])]:
            monkeypatch.setattr(runtime.proxy_config, name, value)
        run = asyncio.create_task(runtime._run(asyncio.Event()))
        for _ in range(100):
            if runtime._server_instance is not None:
                break
            await asyncio.sleep(.002)
        server = runtime._server_instance
        _, client_writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
        await entered.wait()
        idle_writer = Writer()
        pool.ws_pool._idle[(2, False)] = deque([(raw.RawWebSocket(asyncio.StreamReader(), idle_writer), 0)])
        try:
            run.cancel()
            await cleaning.wait()
            run.cancel()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await run
            assert idle_writer.closed, 'second owner cancellation skipped pool shutdown'
        finally:
            release.set()
            client_writer.close()
            await client_writer.wait_closed()
            await pool.ws_pool.close()
    asyncio.run(scenario())

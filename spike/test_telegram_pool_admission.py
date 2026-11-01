"""CF pool recovery with real pool coroutines and in-memory transports only."""
import asyncio
import importlib
import importlib.util
from pathlib import Path
import socket
import subprocess
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


@pytest.fixture(autouse=True)
def prohibit_external_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('This regression must not perform external I/O')

    for name in ('connect', 'connect_ex', 'bind', 'listen'):
        monkeypatch.setattr(socket.socket, name, forbidden)
    for name in ('create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ('open_connection', 'start_server',
                 'create_subprocess_exec', 'create_subprocess_shell'):
        monkeypatch.setattr(asyncio, name, forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)


class Writer:
    def __init__(self):
        self.closed = False
        self.transport = self

    def write(self, data):
        pass

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def is_closing(self):
        return self.closed


async def drain_pool_tasks(instance):
    # The fake connector never waits for real I/O. Bound unexpected task churn.
    for _ in range(30):
        tasks = list(instance._tasks)
        if not tasks:
            return
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=1)
        await asyncio.sleep(0)
    raise AssertionError('Pool tasks failed to settle')


@pytest.mark.parametrize('initial_state', ['cold', 'failed_warmup', 'redirected_dc'])
def test_cf_miss_recovers_with_one_refill_under_concurrent_load(monkeypatch, initial_state):
    async def scenario():
        baseline = asyncio.all_tasks()
        instance = pool._CfWorkerPool()
        monkeypatch.setattr(pool.proxy_config, 'pool_size', 4)
        monkeypatch.setattr(pool.proxy_config, 'disable_secure', False)
        monkeypatch.setattr(pool.proxy_config, 'cfproxy_worker_domains', ['worker.invalid'])
        monkeypatch.setattr(pool.proxy_config, 'dc_redirects',
                            {2: 'redirect.invalid'} if initial_state == 'redirected_dc' else {})
        monkeypatch.setattr(pool, 'DC_DEFAULT_IPS', {2: '203.0.113.2'})
        release = asyncio.Event()
        fail_warmup = initial_state == 'failed_warmup'
        calls, writers, checked_out = [], [], []

        async def connect(*args, **kwargs):
            calls.append((args, kwargs))
            if fail_warmup:
                raise OSError('Scripted warmup failure')
            await release.wait()
            writer = Writer()
            writers.append(writer)
            return raw.RawWebSocket(asyncio.StreamReader(), writer)

        monkeypatch.setattr(raw.RawWebSocket, 'connect', staticmethod(connect))
        try:
            if initial_state != 'cold':
                await instance.warmup()
                await drain_pool_tasks(instance)
                assert len(calls) == (1 if fail_warmup else 0)
                assert not any(instance._idle.values())
            fail_warmup = False
            before = len(calls)
            results = await asyncio.gather(*(
                instance.get(2, '203.0.113.2', ['worker.invalid']) for _ in range(100)))
            assert results == [None] * 100
            for _ in range(30):
                if len(calls) > before:
                    break
                await asyncio.sleep(0)
            assert len(calls) == before + 1, 'A miss must start exactly one background refill'
            assert len(instance._refill_tasks) == 1
            assert instance._refilling == {2}
            assert calls[-1] == (('worker.invalid', 'worker.invalid'), {
                'timeout': 8, 'path': '/apiws?dst=203.0.113.2&dc=2', 'secure': True})

            release.set()
            await drain_pool_tasks(instance)
            connection = await instance.get(2, '203.0.113.2', ['worker.invalid'])
            assert connection is not None
            checked_out.append(connection[0])
            assert connection[1] == 'worker.invalid'
            assert not connection[0].writer.closed
        finally:
            release.set()
            await instance.close()
            for connection in checked_out:
                await connection.close()
        assert all(writer.closed for writer in writers)
        assert not [task for task in asyncio.all_tasks() - baseline if not task.done()]

    asyncio.run(scenario())


def test_cf_completed_connector_is_reclaimed_when_parent_cancel_wins(monkeypatch):
    async def scenario():
        baseline = asyncio.all_tasks()
        instance = pool._CfWorkerPool()
        monkeypatch.setattr(pool.proxy_config, 'pool_size', 1)
        writer = Writer()
        child_tasks = []
        owner = {}

        async def connect(*args, **kwargs):
            child_tasks.append(asyncio.current_task())
            # Queue cancellation before the completed child's wakeup of its
            # parent: this exercises one connector at the production DC cap.
            asyncio.get_running_loop().call_soon(owner['refill'].cancel)
            return raw.RawWebSocket(asyncio.StreamReader(), writer)

        monkeypatch.setattr(raw.RawWebSocket, 'connect', staticmethod(connect))
        try:
            instance._schedule_refill(2, '203.0.113.2', ['worker.invalid'])
            owner['refill'] = next(iter(instance._refill_tasks))
            with pytest.raises(asyncio.CancelledError):
                await owner['refill']
            assert len(child_tasks) == 1
            child = child_tasks[0]
            assert child.done() and not child.cancelled()
            assert child.result()[0].writer is writer
            assert writer.closed, 'Cancellation must reclaim the completed, unclaimed result'
            assert not any(instance._idle.values())
        finally:
            await instance.close()
        assert not [task for task in asyncio.all_tasks() - baseline if not task.done()]

    asyncio.run(scenario())

"""Shared DNS cancellation contracts with actual functions and in-memory work."""
import ast
import asyncio
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
ANSWER = ['203.0.113.22']


class ObservedCompletion(asyncio.Future):
    exception_reads = 0

    def exception(self):
        self.exception_reads += 1
        return super().exception()


@pytest.fixture(autouse=True)
def forbid_external_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('external I/O prohibited')
    for name in ('connect', 'connect_ex', 'bind', 'listen'):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    for name in ('open_connection', 'start_server', 'create_subprocess_exec',
                 'create_subprocess_shell', 'to_thread'):
        monkeypatch.setattr(asyncio, name, forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)


class Fixture:
    def __init__(self, name):
        loop = asyncio.get_running_loop()
        self.jobs = []
        self.tasks = []
        self.inflight = {}

        def never_resolve(_host):
            raise AssertionError('resolver body must not run')

        def fake_executor(pool, function, host):
            assert pool is sentinel and function is never_resolve
            assert host == 'fixture.invalid'
            result = ObservedCompletion(loop=loop)
            self.jobs.append(result)
            return result

        sentinel = object()
        api = SimpleNamespace(
            get_running_loop=lambda: SimpleNamespace(
                create_future=loop.create_future, run_in_executor=fake_executor),
            shield=asyncio.shield,
        )
        ns = {'asyncio': api, '_POOL': sentinel, '_doh_inflight': self.inflight,
              '_app_dns_inflight': self.inflight, 'doh_resolve': never_resolve,
              'app_dns_resolve': never_resolve, 'normalize_host': lambda host: host}
        # Compile the actual functions, without daemon startup or real executor
        # threads. This also works against the pre-fix source for causal proof.
        source = ast.parse((ROOT / 'spike/tproxy.py').read_text())
        names = {'_shared_dns_resolve', 'doh_resolve_async', 'app_dns_resolve_async'}
        functions = [node for node in source.body
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and node.name in names]
        exec(compile(ast.Module(body=functions, type_ignores=[]), 'shared-dns', 'exec'), ns)
        self.lookup = ns[name]

    async def caller(self):
        task = asyncio.create_task(self.lookup('fixture.invalid'))
        self.tasks.append(task)
        await asyncio.sleep(0)
        return task

    async def cleanup(self):
        for result in self.jobs:
            if not result.done():
                result.set_result(ANSWER)
        await asyncio.sleep(0)
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await asyncio.sleep(0)
        assert all(task.done() for task in self.tasks)
        assert all(result.done() for result in self.jobs)


@pytest.mark.parametrize('name', ['doh_resolve_async', 'app_dns_resolve_async'])
def test_cancelled_follower_does_not_cancel_shared_result(name):
    async def case():
        f = Fixture(name)
        try:
            first = await f.caller()
            leaving = await f.caller()
            staying = await f.caller()
            leaving.cancel()
            result = (await asyncio.gather(leaving, return_exceptions=True))[0]
            assert isinstance(result, asyncio.CancelledError)
            await asyncio.sleep(0)
            assert not staying.done(), 'one follower cancelled another follower'
            assert len(f.jobs) == 1
            f.jobs[0].set_result(ANSWER)
            assert await staying == ANSWER
            assert await first == ANSWER
        finally:
            await f.cleanup()
    asyncio.run(case())


@pytest.mark.parametrize('name', ['doh_resolve_async', 'app_dns_resolve_async'])
def test_cancelled_first_caller_keeps_worker_coalesced_for_new_caller(name):
    async def case():
        f = Fixture(name)
        try:
            first = await f.caller()
            first.cancel()
            result = (await asyncio.gather(first, return_exceptions=True))[0]
            assert isinstance(result, asyncio.CancelledError), type(result).__name__
            assert 'fixture.invalid' in f.inflight, 'running lookup was evicted'
            assert not f.jobs[0].cancelled(), 'resolver completion was cancelled'
            following = await f.caller()
            assert len(f.jobs) == 1, 'same host submitted another running lookup'
            f.jobs[0].set_result(ANSWER)
            assert await following == ANSWER
            await asyncio.sleep(0)
            assert not f.inflight
        finally:
            await f.cleanup()
    asyncio.run(case())


@pytest.mark.parametrize('name', ['doh_resolve_async', 'app_dns_resolve_async'])
def test_actual_worker_failure_still_clears_inflight_and_returns_empty(name):
    async def case():
        f = Fixture(name)
        try:
            first = await f.caller()
            following = await f.caller()
            f.jobs[0].set_exception(OSError('synthetic resolver error'))
            assert await first == []
            assert await following == []
            await asyncio.sleep(0)
            assert not f.inflight
        finally:
            await f.cleanup()
    asyncio.run(case())


@pytest.mark.parametrize('name', ['doh_resolve_async', 'app_dns_resolve_async'])
@pytest.mark.parametrize('answer', [None, []])
def test_completed_empty_or_unobserved_answer_is_not_reclassified(name, answer):
    async def case():
        f = Fixture(name)
        try:
            first = await f.caller()
            following = await f.caller()
            f.jobs[0].set_result(answer)
            assert await first is answer
            assert await following is answer
            await asyncio.sleep(0)
            assert not f.inflight
        finally:
            await f.cleanup()
    asyncio.run(case())


@pytest.mark.parametrize('name', ['doh_resolve_async', 'app_dns_resolve_async'])
def test_worker_failure_after_all_callers_leave_is_observed_and_cleared(name):
    async def case():
        f = Fixture(name)
        try:
            first = await f.caller()
            following = await f.caller()
            first.cancel()
            following.cancel()
            results = await asyncio.gather(first, following, return_exceptions=True)
            assert all(isinstance(result, asyncio.CancelledError) for result in results)
            completion = f.jobs[0]
            assert not completion.done()
            assert 'fixture.invalid' in f.inflight
            completion.set_exception(OSError('late synthetic resolver error'))
            await asyncio.sleep(0)
            assert not f.inflight
            assert completion.exception_reads == 1, 'abandoned failure was not observed'
        finally:
            await f.cleanup()
    asyncio.run(case())

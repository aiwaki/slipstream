"""Memory-only broker generation ownership; never open browsers or sockets."""
import asyncio
import json
import socket
import stat
import subprocess
import threading
from types import SimpleNamespace

import pytest
import pending_navigation_probe_runtime as broker


class Writer:
    def __init__(self):
        self.closed = False
        self.data = bytearray()

    def write(self, value):
        self.data.extend(value)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class Listener:
    def __init__(self):
        self.closed = False
        self.callback = None
        self.start_error = None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    async def start_serving(self):
        if self.start_error:
            raise self.start_error


def forbidden(*_args, **_kwargs):
    raise AssertionError("lifecycle fixture attempted external I/O")


@pytest.fixture(autouse=True)
def forbid_io(monkeypatch):
    for name in ("run", "Popen"):
        monkeypatch.setattr(subprocess, name, forbidden)
    for name in ("connect", "connect_ex", "bind"):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    for name in ("kill", "unlink", "chown", "chmod"):
        monkeypatch.setattr(broker.os, name, forbidden)
    for name in ("open_connection", "open_unix_connection", "start_server", "start_unix_server"):
        monkeypatch.setattr(asyncio, name, forbidden)
    monkeypatch.setattr(broker, "remove_owned_socket", lambda *_args: True)


def payload(operation="submit"):
    request = {"schema_version": 1, "operation": operation,
               "launch_id": "0123456789abcdef"}
    if operation == "submit":
        request["result"] = {"capability": "a" * 32}
    return json.dumps(request).encode()


def reader(operation="submit"):
    value = asyncio.StreamReader()
    value.feed_data(broker.encode_frame(payload(operation)))
    return value


def runtime(effects):
    return broker.PendingNavigationProbeRuntime(
        submit_result=lambda *_args: effects.append("submitted") or True,
        claim_job=lambda *_args: effects.append("claimed") or True,
        wall_clock_ms=lambda: 1_010_000,
        monotonic_clock=lambda: 100.0,
    )


async def eventually(predicate):
    deadline = asyncio.get_running_loop().time() + 1
    while not predicate():
        assert asyncio.get_running_loop().time() < deadline, "fixture did not progress"
        await asyncio.sleep(0.001)


async def fake_server(monkeypatch, value, *, listener=None):
    listener = listener or Listener()
    calls = []

    async def bind(callback, **kwargs):
        assert kwargs == {"path": "/memory/probe.sock", "limit": broker.MAX_IPC_BYTES + 4,
                          "start_serving": False}
        def accepted(reader, writer):
            result = callback(reader, writer)
            if asyncio.iscoroutine(result):
                return asyncio.create_task(result)  # StreamReaderProtocol behavior.
            return result
        listener.callback = accepted
        return listener

    def lstat(_path):
        calls.append(_path)
        if len(calls) == 1:
            raise FileNotFoundError
        return SimpleNamespace(st_uid=501, st_gid=20, st_mode=stat.S_IFSOCK | 0o600)

    monkeypatch.setattr(asyncio, "start_unix_server", bind)
    monkeypatch.setattr(broker.os, "lstat", lstat)
    monkeypatch.setattr(broker.os, "chown", lambda *_args: None)
    monkeypatch.setattr(broker.os, "chmod", lambda *_args: None)
    monkeypatch.setattr(broker, "_socket_identity", lambda _path: broker.UnixSocketIdentity(1, 2))
    owned = await broker.start_owned_pending_navigation_probe_server("/memory/probe.sock", 501, 20, value)
    return owned, listener


@pytest.mark.parametrize("operation", ["claim", "submit"])
def test_queued_thread_cannot_mutate_runtime_after_owner_close(monkeypatch, operation):
    async def scenario():
        effects, queued = [], []
        value = runtime(effects)
        job = {"schema_version": 1, "capability": "a" * 32, "host": "example.invalid",
               "request_started_at_unix_ms": 1_000_000, "issued_at_unix_ms": 1_000_000,
               "expires_at_unix_ms": 1_030_000}
        assert value.enqueue(job)
        owned, listener = await fake_server(monkeypatch, value)
        pending = asyncio.get_running_loop().create_future()

        async def queued_thread(fn, *args):
            queued.append((fn, args))
            return await pending

        monkeypatch.setattr(asyncio, "to_thread", queued_thread)
        writer = Writer()
        listener.callback(reader(operation), writer)
        await eventually(lambda: bool(queued))
        await owned.close()
        # Executor work can run after cancellation of the awaiting client task.
        fn, args = queued.pop()
        response = fn(*args)
        assert response["accepted"] is False
        assert response["reason"] == broker.REASON_EFFECT_UNAVAILABLE
        assert effects == [] and value.state_size() == 1
        assert writer.closed and owned._closed and not owned._clients
        successor = broker._RuntimeAuthority(value)
        assert successor.handle(payload("claim"))["job"] == job
        assert effects == ["claimed"]  # Old queued work consumed neither job nor lease.
        late_writer = Writer()
        listener.callback(reader(), late_writer)
        assert late_writer.closed and not owned._clients
    asyncio.run(scenario())


def test_normal_request_completes_before_close(monkeypatch):
    async def scenario():
        effects = []
        owned, listener = await fake_server(monkeypatch, runtime(effects))

        async def immediate_thread(fn, *args):
            return fn(*args)

        monkeypatch.setattr(asyncio, "to_thread", immediate_thread)
        writer = Writer()
        listener.callback(reader(), writer)
        await eventually(lambda: writer.closed and not owned._clients)
        response = json.loads(writer.data[4:])
        assert response["accepted"] is True and effects == ["submitted"]
        await owned.close()
        assert owned._closed and listener.closed
    asyncio.run(scenario())


def test_cancelling_frame_read_closes_writer():
    async def scenario():
        writer = Writer()
        task = asyncio.create_task(broker.handle_pending_navigation_probe_client(
            asyncio.StreamReader(), writer, runtime([]),
        ))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert writer.closed
    asyncio.run(scenario())


def test_close_before_client_first_instruction_closes_writer(monkeypatch):
    async def scenario():
        owned, listener = await fake_server(monkeypatch, runtime([]))
        writer = Writer()
        listener.callback(asyncio.StreamReader(), writer)
        # _finish_close executes without yielding to the newly accepted task.
        await owned._finish_close()
        assert writer.closed and owned._closed and not owned._clients
    asyncio.run(scenario())


@pytest.mark.parametrize("timeout", [False, True])
def test_inflight_effect_is_nonblocking_and_retained_until_drained(monkeypatch, timeout):
    async def scenario():
        entered, release = threading.Event(), threading.Event()
        outcomes, effects = [], []

        def effect(*_args):
            entered.set()
            if not release.wait(1):
                raise AssertionError("fixture effect release deadline")
            effects.append("submitted")
            return True

        value = broker.PendingNavigationProbeRuntime(submit_result=effect)
        owned, _ = await fake_server(monkeypatch, value)
        authority = owned._authority
        worker = threading.Thread(target=lambda: outcomes.append(authority.handle(payload())), daemon=True)
        worker.start()
        try:
            await eventually(entered.is_set)
            if timeout:
                monkeypatch.setattr(broker, "IPC_TIMEOUT_SECONDS", 0.025)
                supervisor = broker.OwnedPendingNavigationProbeServerSupervisor(
                    "/memory/probe.sock", value, lambda: (501, 20, "new"),
                )
                supervisor._server = owned
                supervisor._session_identity = (501, 20, "old")
                monkeypatch.setattr(broker, "start_owned_pending_navigation_probe_server", forbidden)
                with pytest.raises(TimeoutError):
                    await supervisor._reconcile()
                assert supervisor._server is owned and supervisor._session_identity is None
                assert not owned._closed and not authority.active()
                assert not authority.handle(payload())["accepted"]
                assert effects == []
                # Changing the desired identity back must not reuse a revoked server.
                supervisor.identity_provider = lambda: (501, 20, "old")
                with pytest.raises(TimeoutError):
                    await supervisor._reconcile()
                assert supervisor._server is owned
                release.set()
                await eventually(lambda: bool(outcomes))
                successor = SimpleNamespace(_closing=False)
                starts = []

                async def replacement(*args):
                    starts.append(args)
                    assert effects == ["submitted"] and owned._closed
                    return successor

                monkeypatch.setattr(broker, "start_owned_pending_navigation_probe_server", replacement)
                await supervisor._reconcile()
                assert supervisor._server is successor and len(starts) == 1
                assert supervisor._session_identity == (501, 20, "old")
            else:
                first = asyncio.create_task(owned.close())
                second = asyncio.create_task(owned.close())
                await eventually(lambda: not authority.active())
                # These awaits run while the real effect thread is blocked.
                assert not first.done() and not second.done() and effects == []
                first.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await first
                assert not second.done()
                release.set()
                await asyncio.wait_for(second, 1)
                assert owned._closed and effects == ["submitted"]
                await owned.close()
            assert not authority.handle(payload())["accepted"]
            assert effects == ["submitted"]
        finally:
            release.set()
            worker.join(1)
            assert not worker.is_alive()
    asyncio.run(scenario())


def test_supervisor_failed_close_keeps_handle_and_next_close_retries(monkeypatch):
    async def scenario():
        value = runtime([])
        owned, _ = await fake_server(monkeypatch, value)
        attempts = []
        actual_close = owned.close

        async def fail_once():
            attempts.append(1)
            if len(attempts) == 1:
                owned._closing = True
                owned._authority.revoke()
                raise TimeoutError("synthetic bounded cleanup timeout")
            await actual_close()

        owned.close = fail_once
        supervisor = broker.OwnedPendingNavigationProbeServerSupervisor(
            "/memory/probe.sock", value, lambda: (501, 20, "old"),
        )
        supervisor._server = owned
        supervisor._session_identity = (501, 20, "old")
        with pytest.raises(TimeoutError):
            await supervisor.close()
        assert supervisor._server is owned and supervisor._session_identity is None
        await supervisor.close()
        assert supervisor._server is None and owned._closed and len(attempts) == 2
    asyncio.run(scenario())


def test_cancelled_supervisor_close_does_not_publish_successor(monkeypatch):
    async def scenario():
        value = runtime([])
        owned, _ = await fake_server(monkeypatch, value)
        entered, release = asyncio.Event(), asyncio.Event()
        actual_close = owned.close

        async def delayed_close():
            entered.set()
            await release.wait()
            await actual_close()

        owned.close = delayed_close
        supervisor = broker.OwnedPendingNavigationProbeServerSupervisor(
            "/memory/probe.sock", value, lambda: (501, 20, "new"), poll_interval=0.001,
        )
        supervisor._server = owned
        supervisor._session_identity = (501, 20, "old")
        monkeypatch.setattr(broker, "start_owned_pending_navigation_probe_server", forbidden)
        supervisor._task = asyncio.create_task(supervisor._run())
        await asyncio.wait_for(entered.wait(), 1)
        close = asyncio.create_task(supervisor.close())
        await asyncio.sleep(0)
        close.cancel()
        with pytest.raises(asyncio.CancelledError):
            await close
        assert not supervisor._task.cancelled()
        release.set()
        await asyncio.wait_for(supervisor.close(), 1)
        assert supervisor._server is None and owned._closed
    asyncio.run(scenario())


@pytest.mark.parametrize("cancelled_owner", ["close", "supervisor"])
def test_completed_cancelled_owner_does_not_prevent_cleanup_retry(monkeypatch, cancelled_owner):
    async def scenario():
        value = runtime([])
        owned, _ = await fake_server(monkeypatch, value)
        never = asyncio.Event()
        cancelled = asyncio.create_task(never.wait())
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        owned._authority.revoke()
        owned._closing = True
        if cancelled_owner == "close":
            owned._close_task = cancelled
            await owned.close()
        else:
            supervisor = broker.OwnedPendingNavigationProbeServerSupervisor(
                "/memory/probe.sock", value, lambda: None,
            )
            supervisor._server = owned
            supervisor._task = cancelled
            await supervisor.close()
            assert supervisor._server is None
        assert owned._closed
    asyncio.run(scenario())


def test_start_failure_drains_only_owned_clients(monkeypatch):
    async def scenario():
        listener = Listener()
        listener.start_error = RuntimeError("fixture start failed")
        with pytest.raises(RuntimeError, match="fixture start failed"):
            await fake_server(monkeypatch, runtime([]), listener=listener)
        assert listener.closed
    asyncio.run(scenario())


def test_replaced_socket_is_not_removed(monkeypatch):
    monkeypatch.setattr(broker, "_socket_identity", lambda _: broker.UnixSocketIdentity(9, 9))
    assert _ORIGINAL_REMOVE_SOCKET("/memory/probe.sock", broker.UnixSocketIdentity(1, 2)) is False


_ORIGINAL_REMOVE_SOCKET = broker.remove_owned_socket

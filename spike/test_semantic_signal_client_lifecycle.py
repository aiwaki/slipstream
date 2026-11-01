"""Accepted-client cleanup, without real IPC, threads or backend effects."""
import asyncio
import json
import os
import socket
import struct
import subprocess
import threading

import pytest

import semantic_route_signal_runtime as runtime


PAYLOAD = b"fixture"
RESPONSE = {"schema_version": 1, "accepted": True, "action": "none", "reason": "fixture"}


@pytest.fixture(autouse=True)
def no_external_io(monkeypatch):
    attempted = []

    def denied(*args, **kwargs):
        attempted.append(True)
        raise AssertionError("external I/O is forbidden")

    for owner, names in (
        (socket.socket, ("connect", "connect_ex", "bind", "listen")),
        (socket, ("getaddrinfo", "gethostbyname", "create_connection")),
        (asyncio, ("open_connection", "open_unix_connection", "start_server", "start_unix_server",
                   "create_subprocess_exec", "create_subprocess_shell")),
        (asyncio.BaseEventLoop, ("run_in_executor",)),
        (subprocess, ("Popen", "run")), (os, ("system",)), (threading.Thread, ("start",)),
    ):
        for name in names:
            monkeypatch.setattr(owner, name, denied)

    async def in_memory_dispatch(function, *args):
        return function(*args)

    monkeypatch.setattr(asyncio, "to_thread", in_memory_dispatch)
    yield
    assert attempted == []


class Writer:
    def __init__(self):
        self.writes = []
        self.close_calls = 0
        self.wait_calls = 0

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        pass

    def close(self):
        self.close_calls += 1

    async def wait_closed(self):
        self.wait_calls += 1
        assert self.close_calls == 1


class Runtime:
    def __init__(self, *, error=None, response=None):
        self.seen = []
        self.error = error
        self.response = RESPONSE if response is None else response

    def handle(self, payload):
        self.seen.append(payload)
        if self.error is not None:
            raise self.error
        return self.response


def framed(response):
    return runtime.encode_frame(json.dumps(response, separators=(",", ":"), sort_keys=True).encode("ascii"))


@pytest.mark.parametrize("phase", ["header", "payload", "dispatch", "drain"])
def test_cancel_closes_writer_and_preserves_cancellation(monkeypatch, phase):
    async def case():
        entered = asyncio.Event()

        class Reader(asyncio.StreamReader):
            async def readexactly(self, count):
                if (phase == "header" and count == 4) or (phase == "payload" and count == len(PAYLOAD)):
                    entered.set()
                return await super().readexactly(count)

        reader, writer, handler_runtime = Reader(), Writer(), Runtime()
        if phase != "header":
            reader.feed_data(struct.pack("<I", len(PAYLOAD)))
        if phase in {"dispatch", "drain"}:
            reader.feed_data(PAYLOAD)

        async def blocked(*args):
            entered.set()
            await asyncio.Event().wait()

        if phase == "dispatch":
            monkeypatch.setattr(asyncio, "to_thread", blocked)
        if phase == "drain":
            writer.drain = blocked
        task = asyncio.create_task(runtime.handle_semantic_signal_client(reader, writer, handler_runtime))
        try:
            await asyncio.wait_for(entered.wait(), timeout=0.5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert writer.close_calls == writer.wait_calls == 1
            assert writer.writes == ([framed(RESPONSE)] if phase == "drain" else [])
            assert handler_runtime.seen == ([PAYLOAD] if phase == "drain" else [])
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    asyncio.run(case())


@pytest.mark.parametrize("kind", ["happy", "eof", "dispatch_error", "semantic_error", "read_timeout"])
def test_exact_response_and_single_cleanup(monkeypatch, kind):
    async def case():
        reader, writer = asyncio.StreamReader(), Writer()
        error = (RuntimeError("fixture") if kind == "dispatch_error" else
                 runtime.SemanticSignalError("fixture_signal_error") if kind == "semantic_error" else None)
        handler_runtime = Runtime(error=error)
        if kind == "eof":
            reader.feed_eof()
        else:
            reader.feed_data(runtime.encode_frame(PAYLOAD))
        if kind == "read_timeout":
            async def timed_out(_count):
                raise asyncio.TimeoutError
            reader.readexactly = timed_out
        await runtime.handle_semantic_signal_client(reader, writer, handler_runtime)
        expected = RESPONSE if kind == "happy" else {
            "schema_version": 1, "accepted": False, "action": runtime.ACTION_NONE,
            "reason": {"eof": "invalid_frame", "dispatch_error": "context_unavailable",
                       "semantic_error": "fixture_signal_error", "read_timeout": "read_timeout"}[kind],
        }
        assert writer.writes == [framed(expected)]
        assert writer.close_calls == writer.wait_calls == 1
        assert handler_runtime.seen == ([] if kind in {"eof", "read_timeout"} else [PAYLOAD])
    asyncio.run(case())


def test_encoding_error_propagates_after_writer_cleanup():
    async def case():
        reader, writer = asyncio.StreamReader(), Writer()
        reader.feed_data(runtime.encode_frame(PAYLOAD))
        handler_runtime = Runtime(response={"unserializable": object()})
        with pytest.raises(TypeError):
            await runtime.handle_semantic_signal_client(reader, writer, handler_runtime)
        assert handler_runtime.seen == [PAYLOAD]
        assert writer.writes == []
        assert writer.close_calls == writer.wait_calls == 1
    asyncio.run(case())


@pytest.mark.parametrize("error", [ConnectionError, OSError])
def test_cleanup_connection_errors_stay_ignored(error):
    async def case():
        class BrokenWriter(Writer):
            async def wait_closed(self):
                await super().wait_closed()
                raise error("fixture")

        reader, writer = asyncio.StreamReader(), BrokenWriter()
        reader.feed_data(runtime.encode_frame(PAYLOAD))
        await runtime.handle_semantic_signal_client(reader, writer, Runtime())
        assert writer.writes == [framed(RESPONSE)]
        assert writer.close_calls == writer.wait_calls == 1
    asyncio.run(case())


def test_cleanup_wait_uses_existing_two_second_budget(monkeypatch):
    async def case():
        class BlockedWriter(Writer):
            cancelled = False

            async def wait_closed(self):
                await super().wait_closed()
                try:
                    await asyncio.Event().wait()
                finally:
                    self.cancelled = True

        reader, writer = asyncio.StreamReader(), BlockedWriter()
        reader.feed_data(runtime.encode_frame(PAYLOAD))
        original_wait_for = asyncio.wait_for
        budgets = []

        async def bounded_wait_for(awaitable, timeout):
            if getattr(awaitable, "cr_code", None) is BlockedWriter.wait_closed.__code__:
                budgets.append(timeout)
                # Exercise real cancellation without spending two seconds per fixture.
                return await original_wait_for(awaitable, timeout=0.01)
            return await original_wait_for(awaitable, timeout=timeout)

        monkeypatch.setattr(asyncio, "wait_for", bounded_wait_for)
        await original_wait_for(runtime.handle_semantic_signal_client(reader, writer, Runtime()), timeout=0.5)
        assert runtime.IPC_WRITE_TIMEOUT_SECONDS == 2.0 and budgets == [2.0]
        assert writer.writes == [framed(RESPONSE)]
        assert writer.close_calls == writer.wait_calls == 1 and writer.cancelled
    asyncio.run(case())

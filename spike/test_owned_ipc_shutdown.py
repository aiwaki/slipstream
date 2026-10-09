"""Real local sockets exercise owner shutdown independently of client progress."""
import asyncio
import importlib
import json
import os
from pathlib import Path
import tempfile
import threading
import struct

import pytest


@pytest.fixture(params=["pending_navigation_probe", "semantic_route_signal"])
def ipc(request):
    module = importlib.import_module(request.param + "_runtime")
    name = ("start_owned_pending_navigation_probe_server"
            if request.param == "pending_navigation_probe"
            else "start_owned_semantic_signal_server")
    return module, getattr(module, name)


def test_owned_ipc_close_reclaims_client_blocked_in_runtime(ipc):
    module, start = ipc

    async def scenario(path):
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        release = threading.Event()

        class Runtime:
            def handle(self, _payload):
                loop.call_soon_threadsafe(entered.set)
                assert release.wait(2), "test did not release its worker"
                return {"accepted": False}

        owned = await start(str(path), os.getuid(), os.getgid(), Runtime())
        reader, writer = await asyncio.open_unix_connection(path)
        closing = None
        try:
            writer.write(module.encode_frame(b"{}"))
            await writer.drain()
            await asyncio.wait_for(entered.wait(), .5)
            closing = asyncio.create_task(owned.close())
            await asyncio.wait_for(asyncio.shield(closing), .2)
            assert await asyncio.wait_for(reader.read(), .2) == b""
            assert not path.exists()
            assert not release.is_set(), "shutdown depended on the held worker"
        finally:
            release.set()
            writer.close()
            await writer.wait_closed()
            if closing is not None:
                await asyncio.wait_for(asyncio.gather(closing, return_exceptions=True), 1)
            await owned.close()

    with tempfile.TemporaryDirectory(prefix="ss-ipc-stop-", dir="/tmp") as directory:
        asyncio.run(scenario(Path(directory) / "broker.sock"))


def test_owned_ipc_cancelled_close_keeps_cleanup_owned_and_coalesces(ipc, monkeypatch):
    _module, start = ipc

    async def scenario(path):
        owned = await start(str(path), os.getuid(), os.getgid(), None)
        entered, release = asyncio.Event(), asyncio.Event()
        real_wait = owned.server.wait_closed

        async def held_wait():
            entered.set()
            await release.wait()
            await real_wait()

        monkeypatch.setattr(owned.server, "wait_closed", held_wait)
        closing = asyncio.create_task(owned.close())
        follower = None
        try:
            await asyncio.wait_for(entered.wait(), .5)
            closing.cancel()
            await asyncio.sleep(0)
            closing.cancel()
            follower = asyncio.create_task(owned.close())
            await asyncio.sleep(0)
            assert not follower.done(), "second close returned before cleanup finished"
            release.set()
            results = await asyncio.wait_for(
                asyncio.gather(closing, follower, return_exceptions=True), .5)
            assert isinstance(results[0], asyncio.CancelledError)
            assert results[1] is None
            assert not path.exists()
        finally:
            release.set()
            await asyncio.gather(closing, *([follower] if follower else []), return_exceptions=True)
            await owned.close()

    with tempfile.TemporaryDirectory(prefix="ss-ipc-stop-", dir="/tmp") as directory:
        asyncio.run(scenario(Path(directory) / "broker.sock"))


def test_owned_ipc_client_cancelled_before_first_step_keeps_writer_owned(ipc):
    _module, start = ipc

    class Writer:
        closed = False

        def close(self):
            self.closed = True

    async def scenario(path):
        owned = await start(str(path), os.getuid(), os.getgid(), None)
        writer = Writer()
        try:
            owned.accept_client(asyncio.StreamReader(), writer, None)
            task = next(iter(owned._clients))
            task.cancel()  # Its finally block has never started.
            await asyncio.gather(task, return_exceptions=True)
            assert writer.closed
            assert not owned._clients
        finally:
            await owned.close()

    with tempfile.TemporaryDirectory(prefix="ss-ipc-stop-", dir="/tmp") as directory:
        asyncio.run(scenario(Path(directory) / "broker.sock"))


def _runtime_and_payload(module, effect):
    if hasattr(module, "SemanticRouteSignalRuntime"):
        contract = json.loads((Path(__file__).resolve().parents[1] /
                               "contracts/semantic-route-signal-v1.json").read_text())
        runtime = module.SemanticRouteSignalRuntime(
            route_class_for_host=lambda host: "unknown",
            owned_geph_ready=lambda: True,
            request_confirmation=effect,
            wall_clock_ms=lambda: 1_050_000,
            monotonic_clock=lambda: 10.0,
        )
        return runtime, json.dumps(contract["signal_defaults"]).encode(), "parse_semantic_route_signal"
    runtime = module.PendingNavigationProbeRuntime(submit_result=effect)
    payload = json.dumps({"schema_version": 1, "operation": "submit",
                          "launch_id": "0123456789abcdef",
                          "result": {"capability": "a" * 32}}).encode()
    return runtime, payload, "_parse_request"


def test_closed_owner_cannot_publish_late_effect_into_successor(ipc, monkeypatch):
    module, start = ipc

    async def scenario(path):
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        release, finished = threading.Event(), threading.Event()
        effects = []
        runtime, payload, parser_name = _runtime_and_payload(
            module, lambda *args: effects.append(args) is None)
        real_parse, real_handle = getattr(module, parser_name), runtime.handle

        def held_parse(data):
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(2)
            return real_parse(data)

        def observed_handle(*args, **kwargs):
            try:
                return real_handle(*args, **kwargs)
            finally:
                finished.set()

        monkeypatch.setattr(module, parser_name, held_parse)
        monkeypatch.setattr(runtime, "handle", observed_handle)
        owned = await start(str(path), os.getuid(), os.getgid(), runtime)
        _, writer = await asyncio.open_unix_connection(path)
        successor = None
        try:
            writer.write(module.encode_frame(payload))
            await writer.drain()
            await asyncio.wait_for(entered.wait(), .5)
            await asyncio.wait_for(owned.close(), .2)
            successor = await start(str(path), os.getuid(), os.getgid(), runtime)
            release.set()
            assert await asyncio.to_thread(finished.wait, 1)
            assert effects == [], "retired IPC owner published an effect after replacement"
            reader2, writer2 = await asyncio.open_unix_connection(path)
            try:
                writer2.write(module.encode_frame(payload))
                await writer2.drain()
                header = await asyncio.wait_for(reader2.readexactly(4), .5)
                response = json.loads(await reader2.readexactly(struct.unpack("<I", header)[0]))
                assert response["accepted"]
                assert len(effects) == 1
            finally:
                writer2.close()
                await writer2.wait_closed()
        finally:
            release.set()
            writer.close()
            await writer.wait_closed()
            await owned.close()
            if successor:
                await successor.close()

    with tempfile.TemporaryDirectory(prefix="ss-ipc-stop-", dir="/tmp") as directory:
        asyncio.run(scenario(Path(directory) / "broker.sock"))


def test_owned_ipc_close_drains_effect_already_admitted(ipc):
    module, start = ipc

    async def scenario(path):
        loop = asyncio.get_running_loop()
        entered, release = asyncio.Event(), threading.Event()
        effects = []

        def effect(*args):
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(2)
            effects.append(args)
            return True

        runtime, payload, _parser = _runtime_and_payload(module, effect)
        owned = await start(str(path), os.getuid(), os.getgid(), runtime)
        _, writer = await asyncio.open_unix_connection(path)
        closing = None
        try:
            writer.write(module.encode_frame(payload))
            await writer.drain()
            await asyncio.wait_for(entered.wait(), .5)
            closing = asyncio.create_task(owned.close())
            await asyncio.sleep(.01)
            assert not closing.done(), "close reported completion while an admitted effect was running"
            with pytest.raises(OSError, match="already active"):
                await start(str(path), os.getuid(), os.getgid(), runtime)
            closing.cancel()
            await asyncio.sleep(0)
            closing.cancel()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(closing, .5)
            assert len(effects) == 1
            assert not path.exists()
        finally:
            release.set()
            writer.close()
            await writer.wait_closed()
            if closing:
                await asyncio.gather(closing, return_exceptions=True)
            await owned.close()

    with tempfile.TemporaryDirectory(prefix="ss-ipc-stop-", dir="/tmp") as directory:
        asyncio.run(scenario(Path(directory) / "broker.sock"))

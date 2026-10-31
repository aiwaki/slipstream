"""Explicit handler cancellation must not suppress an owned route forever."""

import asyncio

import pytest
import tproxy
from test_traffic_contracts import (
    CaptureWriter,
    ScriptedReader,
    isolate_runtime_state,
    tls_client,
)


def test_cancelled_owned_geph_handler_recovers_after_idle_ttl(monkeypatch):
    isolate_runtime_state(monkeypatch)
    registry = tproxy.route_circuit_registry.RouteCircuitRegistry(
        tproxy.RUNTIME_ROUTE_CIRCUIT_CONFIG,
        tproxy.RUNTIME_ROUTE_CIRCUIT_REGISTRY_CONFIG,
    )
    monkeypatch.setattr(tproxy, "_runtime_route_circuits", registry)
    monkeypatch.setattr(tproxy, "_connection_tasks", set())
    monkeypatch.setattr(tproxy, "_conn_count", 0)
    monkeypatch.setattr(tproxy, "_active_route_policy_manifest", None)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    # Seed already confirmed owned intent in memory; never read user settings.
    monkeypatch.setattr(tproxy, "_geph_route_intent", (None, True))
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.19", 443))
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "suspend_geo_exit_backend", lambda _reason: None)
    monkeypatch.setattr(tproxy, "log_geph_route_failure", lambda *_args: None)
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: None)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("handler fixture must not perform external I/O")

    for name in (
        "dial_plain", "dial_strategy", "resolve_connection_ips", "_run",
        "_coalesced_owned_geph_recovery_for_replay",
    ):
        monkeypatch.setattr(tproxy, name, forbidden)
    monkeypatch.setattr(tproxy.geph_backend, "read_enabled", forbidden)
    monkeypatch.setattr(tproxy.subprocess, "Popen", forbidden)
    monkeypatch.setattr(tproxy.socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(tproxy.socket, "create_connection", forbidden)
    monkeypatch.setattr(tproxy.socket.socket, "connect", forbidden)
    monkeypatch.setattr(tproxy.socket.socket, "connect_ex", forbidden)

    clock = [0]
    monkeypatch.setattr(tproxy, "_runtime_route_circuit_now_ms", lambda: clock[0])
    host = "ws.chatgpt.com"
    policy = tproxy.route_policy(host)
    assert policy["route_class"] == tproxy.ROUTE_GEO_EXIT
    for now_ms in (0, 1):
        clock[0] = now_ms
        tproxy.runtime_route_circuit_record_result(
            policy, tproxy.GEO_BACKEND_GEPH, False, owned=True,
        )

    async def sequence():
        first_read_started = asyncio.Event()
        calls = []
        upstream_writers = []
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nrecovered"

        class BlockFirstPayload(ScriptedReader):
            async def read(self, _size=-1):
                first_read_started.set()
                await asyncio.Event().wait()

        async def geph(actual_host, port, first_flight):
            assert tproxy.geph_active_session_count() == 1
            assert (actual_host, port) == (host, 443)
            calls.append((actual_host, port, first_flight))
            upstream = CaptureWriter()
            upstream_writers.append(upstream)
            reader = (
                BlockFirstPayload()
                if len(calls) == 1
                else ScriptedReader(stream=(response[:16], response[16:]))
            )
            return reader, upstream

        monkeypatch.setattr(tproxy, "dial_via_geph", geph)
        clock[0] = 1001
        client, first_flight = tls_client(host, block_after_hello=True)
        writer = CaptureWriter()
        task = asyncio.create_task(tproxy.handle(client, writer))
        try:
            await asyncio.wait_for(first_read_started.wait(), timeout=1)
            entry = registry.snapshot()[0]
            assert entry.state.phase == "half_open"
            assert entry.state.half_open_in_flight == 1
            assert tproxy._conn_count == 1
            assert task in tproxy._connection_tasks
        finally:
            # Explicit task cancellation, not a claim about browser tab close.
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert upstream_writers[0].closed and writer.closed
        assert bytes(writer.payload) == b""
        assert tproxy.geph_active_session_count() == 0
        assert tproxy._conn_count == 0 and not tproxy._connection_tasks

        async def request():
            client, _ = tls_client(host, block_after_hello=True)
            writer = CaptureWriter()
            await asyncio.wait_for(tproxy.handle(client, writer), timeout=1)
            assert writer.closed
            assert tproxy.geph_active_session_count() == 0
            assert tproxy._conn_count == 0 and not tproxy._connection_tasks
            return bytes(writer.payload)

        ttl = tproxy.RUNTIME_ROUTE_CIRCUIT_REGISTRY_CONFIG.idle_ttl_ms
        assert ttl == 300000
        for now_ms in (60000, 120000, 300000):
            clock[0] = now_ms
            assert await request() == b""
            assert len(calls) == 1
        clock[0] = 1001 + ttl
        assert await request() == response
        assert calls == [(host, 443, first_flight)] * 2
        assert all(upstream.closed for upstream in upstream_writers)
        assert not registry.snapshot()

    asyncio.run(sequence())

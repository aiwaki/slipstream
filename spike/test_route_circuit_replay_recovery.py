"""A separately successful owned replay preserves actual handler health."""

import asyncio
from dataclasses import asdict
import os
import socket
import subprocess

import tproxy
from test_traffic_contracts import (
    CaptureWriter,
    ScriptedReader,
    isolate_runtime_state,
    tls_client,
)


def test_successful_owned_replays_do_not_accumulate_closed_failures(monkeypatch):
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
    monkeypatch.setattr(tproxy, "_geph_route_intent", (None, True))
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.19", 443))
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "log_geph_route_failure", lambda *_args: None)
    cleared, suspended = [], []
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: cleared.append(True))
    monkeypatch.setattr(tproxy, "suspend_geo_exit_backend", suspended.append)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("replay handler fixture forbids external I/O")

    for name in (
        "dial_plain", "dial_strategy", "resolve_connection_ips", "_run",
        "_recover_owned_geph_for_replay_blocking",
    ):
        monkeypatch.setattr(tproxy, name, forbidden)
    monkeypatch.setattr(tproxy.geph_backend, "read_enabled", forbidden)
    for owner, names in (
        (socket.socket, ("connect", "connect_ex", "bind", "listen")),
        (socket, ("getaddrinfo", "create_connection")),
        (asyncio, ("open_connection", "start_server", "to_thread",
                   "create_subprocess_exec", "create_subprocess_shell")),
        (subprocess, ("Popen",)), (os, ("system",)),
    ):
        for name in names:
            monkeypatch.setattr(owner, name, forbidden)

    clock = [0]
    monkeypatch.setattr(tproxy, "_runtime_route_circuit_now_ms", lambda: clock[0])
    host = "ws.chatgpt.com"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nrecovered"
    calls, recoveries, upstream_writers, snapshots, payloads = [], [], [], [], []
    _, first_flight = tls_client(host, block_after_hello=True)

    async def dial(actual_host, port, payload):
        assert (actual_host, port, payload) == (host, 443, first_flight)
        assert tproxy.geph_active_session_count() == 1
        calls.append((actual_host, port, payload))
        if len(calls) % 2:
            # A real first-payload helper observes the failed initial dial.
            return None
        upstream = CaptureWriter()
        upstream_writers.append(upstream)
        return ScriptedReader(stream=(response[:16], response[16:])), upstream

    async def recovery(actual_host):
        assert actual_host == host
        assert tproxy.geph_active_session_count() == 0
        recoveries.append(actual_host)
        # Model the existing authorized recovery result, without starting a
        # backend, advancing the circuit phase, or clearing its state.
        return True

    monkeypatch.setattr(tproxy, "dial_via_geph", dial)
    monkeypatch.setattr(tproxy, "_coalesced_owned_geph_recovery_for_replay", recovery)

    async def sequence():
        assert tproxy.RUNTIME_ROUTE_CIRCUIT_CONFIG.failure_threshold == 2
        assert tproxy.RUNTIME_ROUTE_CIRCUIT_CONFIG.open_duration_ms == 1000
        for index in range(3):
            clock[0] = index * 10
            client, _ = tls_client(host, block_after_hello=True)
            writer = CaptureWriter()
            task = asyncio.create_task(tproxy.handle(client, writer))
            try:
                await asyncio.wait_for(task, timeout=1)
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await asyncio.sleep(0)  # Drain the owner task's done callbacks.
            assert writer.closed
            assert tproxy.geph_active_session_count() == 0
            assert tproxy._conn_count == 0 and not tproxy._connection_tasks
            assert not hasattr(task, "_slipstream_route_circuit_permits")
            payloads.append(bytes(writer.payload))
            snapshots.append([asdict(entry) for entry in registry.snapshot()])
        assert all(writer.closed for writer in upstream_writers)
        assert not [task for task in asyncio.all_tasks()
                    if task is not asyncio.current_task() and not task.done()]

    asyncio.run(sequence())
    assert payloads == [response] * 3, {
        "payloads": payloads, "snapshots": snapshots,
        "dials": len(calls), "recoveries": len(recoveries),
    }
    assert snapshots == [[], [], []], "successful replay retained Closed failure evidence"
    assert len(calls) == 6 and recoveries == [host] * 3
    assert cleared == [True] * 3 and suspended == []

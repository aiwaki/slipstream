"""Admission denial is not a global backend failure."""

import asyncio
from collections import deque

import pytest
import tproxy
from test_traffic_contracts import CaptureWriter, ScriptedReader, isolate_runtime_state, tls_client


@pytest.mark.parametrize("cause", ["circuit_rejected", "initially_unready", "payload_eof"])
def test_admission_only_does_not_pause_another_geph_group(monkeypatch, cause):
    health_event = tproxy.route_health_event
    isolate_runtime_state(monkeypatch)
    monkeypatch.setattr(tproxy, "route_health_event", health_event)
    monkeypatch.setattr(tproxy, "_route_health", {})
    monkeypatch.setattr(tproxy, "_route_failure_windows", {})
    monkeypatch.setattr(tproxy, "_geph_restart_failures", deque())
    monkeypatch.setattr(tproxy, "_geph_restart_hint", dict(tproxy._geph_restart_hint))
    monkeypatch.setattr(tproxy, "_geph_last_failure", {"host": "", "reason": "", "ts": 0.0})
    monkeypatch.setattr(tproxy, "_geph_fail_log", {})
    monkeypatch.setattr(tproxy, "_connection_tasks", set())
    monkeypatch.setattr(tproxy, "_conn_count", 0)
    monkeypatch.setattr(tproxy, "_active_route_policy_manifest", None)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_geph_up", cause != "initially_unready")
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_route_intent", (None, True))
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.19", 443))
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    clock = [100.0]
    monkeypatch.setattr(tproxy.time, "time", lambda: clock[0])
    monkeypatch.setattr(tproxy, "_runtime_route_circuit_now_ms", lambda: 60000)
    registry = tproxy.route_circuit_registry.RouteCircuitRegistry(
        tproxy.RUNTIME_ROUTE_CIRCUIT_CONFIG,
        tproxy.RUNTIME_ROUTE_CIRCUIT_REGISTRY_CONFIG,
    )
    monkeypatch.setattr(tproxy, "_runtime_route_circuits", registry)
    host_a, host_b = "ws.chatgpt.com", "store.steampowered.com"
    policy_a, policy_b = map(tproxy.route_policy, (host_a, host_b))
    assert policy_a["route_class"] == policy_b["route_class"] == tproxy.ROUTE_GEO_EXIT
    assert policy_a["service_group"] != policy_b["service_group"]

    def forbidden(*_args, **_kwargs):
        raise AssertionError("private fixture attempted external I/O")

    for name in ("dial_plain", "dial_strategy", "resolve_connection_ips", "_run",
                 "execute_owned_geph_restart", "request_owned_geph_restart",
                 "save_auto_geph", "save_strat_cache"):
        monkeypatch.setattr(tproxy, name, forbidden)
    monkeypatch.setattr(tproxy.geph_backend, "read_enabled", forbidden)
    monkeypatch.setattr(tproxy.subprocess, "Popen", forbidden)
    for name in ("getaddrinfo", "create_connection"):
        monkeypatch.setattr(tproxy.socket, name, forbidden)
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(tproxy.socket.socket, name, forbidden)

    calls, recoveries, upstreams = [], [], []
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nsteam"

    async def geph(host, port, _first_flight):
        assert port == 443 and tproxy.geph_active_session_count() == 1
        calls.append(host)
        writer = CaptureWriter()
        upstreams.append(writer)
        return ScriptedReader(stream=(response,) if host == host_b else ()), writer

    async def recovery(host):
        assert cause == "payload_eof" and host == host_a
        recoveries.append(host)
        return False

    monkeypatch.setattr(tproxy, "dial_via_geph", geph)
    monkeypatch.setattr(tproxy, "_coalesced_owned_geph_recovery_for_replay", recovery)
    if cause == "circuit_rejected":
        for now_ms in (0, 1):
            tproxy.runtime_route_circuit_record_result(
                policy_a, tproxy.GEO_BACKEND_GEPH, False, now_ms=now_ms,
            )
        assert tproxy.runtime_route_circuit_allows(
            policy_a, tproxy.GEO_BACKEND_GEPH, now_ms=1001,
        )

    async def request(host):
        reader, _ = tls_client(host, block_after_hello=False)
        writer = CaptureWriter()
        await asyncio.wait_for(tproxy.handle(reader, writer), 1)
        assert writer.closed and tproxy.geph_active_session_count() == 0
        assert tproxy._conn_count == 0 and not tproxy._connection_tasks
        return bytes(writer.payload)

    async def sequence():
        assert await request(host_a) == b""
        first_state = (tproxy._geph_up, tproxy._geph_backend_hold_until)
        if cause == "initially_unready":
            assert not calls and not recoveries
            # Apply the monitor's actual reducer to a healthy probe five seconds
            # later, without running a probe or changing any connection state.
            clock[0] += 5.0
            tproxy._geph_up, strikes = tproxy.reduce_geph_probe_state(
                previous_up=tproxy._geph_up, strikes=0, probe_ok=True,
                port=tproxy._geph_port, conflict=False,
            )
            assert tproxy._geph_up is True and strikes == 0
        payload_b = await request(host_b)
        assert all(writer.closed for writer in upstreams)
        if cause == "circuit_rejected":
            assert (first_state, payload_b, calls, recoveries) == (
                (True, 0.0), response, [host_b], [],
            )
        elif cause == "initially_unready":
            assert (first_state, payload_b, calls, recoveries) == (
                (False, 0.0), response, [host_b], [],
            )
            assert tproxy._geph_backend_hold_until == 0.0
        else:
            assert first_state == (False, 100.0 + tproxy.GEPH_BACKEND_FAILURE_HOLD)
            assert tproxy._geph_backend_hold_until == first_state[1]
            assert payload_b == b"" and calls == [host_a] and recoveries == [host_a]
            assert tproxy._geph_last_failure["reason"] == "remote closed without response"

    asyncio.run(sequence())

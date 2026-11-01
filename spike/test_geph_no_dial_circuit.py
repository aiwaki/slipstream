"""Pre-dispatch admission must not create or consume route-circuit state."""
import asyncio
from collections import deque
from dataclasses import asdict
import json

import pytest
import tproxy
from test_traffic_contracts import CaptureWriter, ScriptedReader, isolate_runtime_state, tls_client


@pytest.mark.parametrize("admission", ["unready", "draining_open"])
def test_no_dial_admission_must_not_delay_healthy_group(monkeypatch, admission):
    health_event = tproxy.route_health_event
    isolate_runtime_state(monkeypatch)
    monkeypatch.setattr(tproxy, "route_health_event", health_event)
    for name in ("_route_health", "_route_failure_windows", "_geph_fail_log"):
        monkeypatch.setattr(tproxy, name, {})
    monkeypatch.setattr(tproxy, "_geph_restart_failures", deque())
    monkeypatch.setattr(tproxy, "_geph_restart_hint", dict(tproxy._geph_restart_hint))
    monkeypatch.setattr(tproxy, "_geph_last_failure", {"host": "", "reason": "", "ts": 0.0})
    monkeypatch.setattr(tproxy, "_connection_tasks", set())
    monkeypatch.setattr(tproxy, "_conn_count", 0)
    monkeypatch.setattr(tproxy, "_active_route_policy_manifest", None)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_geph_up", admission == "draining_open")
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_route_intent", (None, True))
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.19", 443))
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    clock_ms = [100000]
    monkeypatch.setattr(tproxy.time, "time", lambda: clock_ms[0] / 1000)
    monkeypatch.setattr(tproxy, "_runtime_route_circuit_now_ms", lambda: clock_ms[0])
    registry = tproxy.route_circuit_registry.RouteCircuitRegistry(
        tproxy.RUNTIME_ROUTE_CIRCUIT_CONFIG,
        tproxy.RUNTIME_ROUTE_CIRCUIT_REGISTRY_CONFIG,
    )
    monkeypatch.setattr(tproxy, "_runtime_route_circuits", registry)
    host_a, host_b = "ws.chatgpt.com", "store.steampowered.com"
    assert tproxy.route_policy(host_a)["service_group"] != tproxy.route_policy(host_b)["service_group"]
    assert tproxy.RUNTIME_ROUTE_CIRCUIT_CONFIG.failure_threshold == 2
    assert tproxy.RUNTIME_ROUTE_CIRCUIT_CONFIG.open_duration_ms == 1000

    def forbidden(*_args, **_kwargs):
        raise AssertionError("fixture attempted external I/O")

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
    monkeypatch.setattr(tproxy.asyncio, "open_connection", forbidden)

    calls, upstreams, observations = [], [], []
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nready"

    async def geph(host, port, _first_flight):
        assert port == 443 and tproxy.geph_active_session_count() == 1
        calls.append({"host": host, "now_ms": clock_ms[0]})
        writer = CaptureWriter()
        upstreams.append(writer)
        return ScriptedReader(stream=(response,)), writer

    async def recovery(_host):
        raise AssertionError("admission denial must not invoke recovery")

    monkeypatch.setattr(tproxy, "dial_via_geph", geph)
    monkeypatch.setattr(tproxy, "_coalesced_owned_geph_recovery_for_replay", recovery)
    if admission == "draining_open":
        policy_a = tproxy.route_policy(host_a)
        for now_ms in (0, 1):
            tproxy.runtime_route_circuit_record_result(
                policy_a, tproxy.GEO_BACKEND_GEPH, False, now_ms=now_ms,
            )
        assert registry.snapshot()[0].state.phase == tproxy.route_circuit.PHASE_OPEN
        assert tproxy._begin_geph_restart_drain()

    async def request(host):
        reader, _ = tls_client(host, block_after_hello=False)
        writer = CaptureWriter()
        await asyncio.wait_for(tproxy.handle(reader, writer), 1)
        assert writer.closed and tproxy.geph_active_session_count() == 0
        assert tproxy._conn_count == 0 and not tproxy._connection_tasks
        return bytes(writer.payload)

    async def sequence():
        # Unready requests must not create a circuit. A drain must neither
        # take a half-open permit nor renew an existing circuit's activity.
        before_admission = registry.snapshot()
        refusal_times = (100000, 100100) if admission == "unready" else (1001,)
        ready_at = refusal_times[-1] + 100
        for now_ms in refusal_times:
            clock_ms[0] = now_ms
            assert await request(host_a) == b""
            assert not calls
            assert tproxy._geph_backend_hold_until == 0.0
            observations.append({"now_ms": now_ms, "dial_count": len(calls),
                                 "circuits": [asdict(s) for s in registry.snapshot()]})
        after_admission = registry.snapshot()
        clock_ms[0] = ready_at
        if admission == "draining_open":
            tproxy._finish_geph_restart_drain(retry_pending=False)
        tproxy._geph_up, strikes = tproxy.reduce_geph_probe_state(
            previous_up=tproxy._geph_up, strikes=0, probe_ok=True,
            port=tproxy._geph_port, conflict=False,
        )
        assert tproxy._geph_up and strikes == 0
        assert tproxy.geo_exit_backend_ready() and not tproxy._geph_restart_draining
        first_healthy_payload = await request(host_a)
        first_healthy_calls = list(calls)
        independent_payload = await request(host_b)
        # Bound the observed suppression: it is not an endless cooldown.
        clock_ms[0] = refusal_times[-1] + 1001
        later_same_group_payload = await request(host_a)
        assert independent_payload == later_same_group_payload == response
        assert all(writer.closed for writer in upstreams)
        assert tproxy._geph_backend_hold_until == 0.0
        print(json.dumps({"admission": admission, "no_dial_observations": observations,
                          "recovery_at_ms": ready_at,
                          "before_admission": [asdict(s) for s in before_admission],
                          "after_admission": [asdict(s) for s in after_admission],
                          "first_healthy_payload_bytes": len(first_healthy_payload),
                          "first_healthy_dials": first_healthy_calls,
                          "independent_payload_bytes": len(independent_payload),
                          "same_group_after_existing_open_period_bytes": len(later_same_group_payload),
                          "all_dials": calls,
                          "final_circuits": [asdict(s) for s in registry.snapshot()]}, sort_keys=True))
        assert (after_admission, first_healthy_payload) == (before_admission, response), (
            "no-dial admission changed the circuit or blocked the ready same-group request"
        )

    asyncio.run(sequence())

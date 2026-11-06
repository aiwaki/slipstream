"""A liveness miss must not erase independently verified Geph ownership."""

import asyncio
from collections import deque
import json
import os
import socket
import subprocess
import threading
from types import SimpleNamespace

import pytest
import tproxy
from test_traffic_contracts import CaptureWriter, ScriptedReader, isolate_runtime_state, tls_client


HOST = "xpersonatoy.com"
PAYLOAD = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nready"


@pytest.fixture
def owned_probe(monkeypatch):
    isolate_runtime_state(monkeypatch)
    ownership = {
        "pid": 4242, "executable": "/fixture/geph5-client",
        "config": "/fixture/geph-active.yaml",
    }
    state = SimpleNamespace(
        pid=4242, command="/fixture/geph5-client --config /fixture/geph-active.yaml",
        rpc_sessions=1, strikes=0, commands=[], dials=[], upstreams=[], forbidden=[],
        during_liveness=None, ownership=ownership,
    )

    def forbidden(*_args, **_kwargs):
        state.forbidden.append("external effect")
        raise AssertionError("probe ownership fixture forbids external I/O")

    for owner, names in (
        (socket.socket, ("connect", "connect_ex", "bind", "listen")),
        (socket, ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
                  "gethostbyaddr", "create_connection")),
        (asyncio, ("open_connection", "start_server", "create_subprocess_exec",
                   "create_subprocess_shell")),
        (subprocess, ("Popen",)),
        (os, ("system", "fork", "posix_spawn", "posix_spawnp")),
        (threading.Thread, ("start",)),
        (tproxy._POOL, ("submit",)),
        (tproxy, ("dial_plain", "dial_strategy", "resolve_connection_ips",
                  "save_auto_geph", "save_strat_cache", "request_owned_geph_restart",
                  "execute_owned_geph_restart", "_coalesced_owned_geph_recovery_for_replay")),
        (tproxy.geph_backend, ("read_enabled", "read_ownership")),
    ):
        for name in names:
            if hasattr(owner, name):
                monkeypatch.setattr(owner, name, forbidden)

    monkeypatch.setattr(tproxy, "time", SimpleNamespace(
        time=lambda: 100.0, monotonic=lambda: 100.0, sleep=forbidden,
    ))
    monkeypatch.setattr(tproxy, "_shutdown_started", threading.Event())
    monkeypatch.setattr(tproxy, "_geph_session_lock", threading.Lock())
    monkeypatch.setattr(tproxy, "_geph_backend_hold_lock", threading.RLock())
    monkeypatch.setattr(tproxy, "_geph_backend_hold_generation", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_failures", deque())
    monkeypatch.setattr(tproxy, "_geph_restart_hint", dict(tproxy._geph_restart_hint))
    monkeypatch.setattr(tproxy, "_geph_last_failure", {"host": "", "reason": "", "ts": 0.0})
    monkeypatch.setattr(tproxy, "_connection_tasks", set())
    monkeypatch.setattr(tproxy, "_conn_count", 0)
    monkeypatch.setattr(tproxy, "_active_route_policy_manifest", None)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_env_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_route_intent", (None, True))
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.19", 443))
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "_retry_pending_auto_geph_confirmations_after_drain", lambda: False)
    monkeypatch.setattr(tproxy, "_read_geph_ownership", lambda *_args: dict(ownership))
    monkeypatch.setattr(tproxy, "_tcp_listener_present", lambda port:
                        port == tproxy.GEPH_OWNED_PORT and state.pid is not None)
    def conn_info(*_args):
        callback = state.during_liveness
        state.during_liveness = None
        if callback is not None:
            callback()
        return state.rpc_sessions

    monkeypatch.setattr(tproxy, "_geph_conn_info_sessions", conn_info)

    # Exercise the real listener_owned/state_matches logic. Only lsof/ps effects
    # are replaced; the current PID and exact command must match the saved owner.
    def command(*args):
        state.commands.append(args)
        if args == ("/usr/sbin/lsof", "-nP", f"-iTCP:{tproxy.GEPH_OWNED_PORT}",
                    "-sTCP:LISTEN", "-t"):
            return subprocess.CompletedProcess(args, 0 if state.pid is not None else 1,
                                               f"{state.pid}\n" if state.pid is not None else "", "")
        if args == ("/bin/ps", "-p", str(state.pid), "-o", "command="):
            return subprocess.CompletedProcess(args, 0, state.command, "")
        return forbidden(*args)

    monkeypatch.setattr(tproxy, "_run", command)

    async def geph(host, port, first_flight):
        assert tproxy.geph_active_session_count() == 1
        assert tproxy.geph_listener_owned(tproxy.GEPH_OWNED_PORT)
        assert port == 443 and tproxy.parse_sni(first_flight[5:]) == host == HOST
        state.dials.append((host, port))
        writer = CaptureWriter()
        state.upstreams.append(writer)
        return ScriptedReader(stream=(PAYLOAD,)), writer

    monkeypatch.setattr(tproxy, "dial_via_geph", geph)

    def tick():
        # These are the monitor's real producer and reducer in production order.
        probe_ok = tproxy.probe_geph()
        tproxy._geph_up, state.strikes = tproxy.reduce_geph_probe_state(
            previous_up=tproxy._geph_up, strikes=state.strikes, probe_ok=probe_ok,
            port=tproxy._geph_port, conflict=tproxy._geph_port_conflict,
        )
        return probe_ok

    async def request():
        reader, _ = tls_client(HOST, block_after_hello=False)
        writer = CaptureWriter()
        await asyncio.wait_for(tproxy.handle(reader, writer), 1)
        assert writer.closed and tproxy.geph_active_session_count() == 0
        assert not tproxy._connection_tasks and tproxy._conn_count == 0
        assert all(writer.closed for writer in state.upstreams)
        assert state.forbidden == []
        assert tproxy._geph_backend_hold_until == 0.0
        return bytes(writer.payload)

    state.tick, state.request = tick, request
    assert tproxy.route_policy(HOST)["route_class"] == tproxy.ROUTE_GEO_EXIT
    return state


@pytest.mark.parametrize("misses", [1, 2])
def test_liveness_misses_keep_verified_owned_admission(owned_probe, misses):
    state = owned_probe
    assert state.tick() and tproxy._geph_up and tproxy._geph_owned
    state.rpc_sessions = 0
    for _ in range(misses):
        assert state.tick() is False
    assert tproxy.geph_listener_owned(tproxy.GEPH_OWNED_PORT), "same PID and command still match"
    assert tproxy._geph_up and state.strikes == misses
    assert tproxy.geo_exit_backend_ready()
    payload = asyncio.run(state.request())
    print(json.dumps({
        "same_pid": state.pid, "ownership_check": True,
        "up_after_hysteresis": tproxy._geph_up, "strikes": state.strikes,
        "published_owned": tproxy._geph_owned, "dial_count": len(state.dials),
        "downstream_bytes": len(payload), "hold_until": tproxy._geph_backend_hold_until,
        "forbidden_effects": len(state.forbidden),
    }, sort_keys=True))
    assert (payload, state.dials) == (PAYLOAD, [(HOST, 443)]), (
        "verified ownership was discarded by liveness misses before the handler could dial"
    )


@pytest.mark.parametrize("identity", ["foreign_pid", "missing_pid", "foreign_command"])
@pytest.mark.parametrize("when", ["before_probe", "during_liveness"])
@pytest.mark.parametrize("rpc_sessions", [0, 1])
def test_changed_or_missing_owned_identity_stays_closed(owned_probe, identity, when, rpc_sessions):
    state = owned_probe
    assert state.tick() and tproxy._geph_up and tproxy._geph_owned
    state.rpc_sessions = rpc_sessions

    def change_identity():
        if identity == "foreign_pid":
            state.pid = 4243
        elif identity == "missing_pid":
            state.pid = None
        else:
            state.command = "/foreign/geph5-client --config /foreign/config.yaml"

    if when == "before_probe":
        change_identity()
    else:
        state.during_liveness = change_identity
    assert state.tick() is False
    assert not tproxy.geph_listener_owned(tproxy.GEPH_OWNED_PORT)
    assert not tproxy._geph_owned
    assert asyncio.run(state.request()) == b""
    assert state.dials == []


@pytest.mark.parametrize("rpc_sessions", [0, 1])
def test_new_owned_pid_during_probe_cannot_inherit_prior_up(owned_probe, rpc_sessions):
    state = owned_probe
    assert state.tick() and tproxy._geph_up and tproxy._geph_owned
    state.rpc_sessions = rpc_sessions

    def replace_owner():
        state.pid = 4243
        state.ownership["pid"] = 4243

    state.during_liveness = replace_owner
    assert state.tick() is False
    assert tproxy.geph_listener_owned(tproxy.GEPH_OWNED_PORT), "successor is owned, but not the sampled PID"
    assert not tproxy._geph_owned
    assert asyncio.run(state.request()) == b""
    assert state.dials == []


def test_three_liveness_misses_still_exhaust_hysteresis(owned_probe):
    state = owned_probe
    assert state.tick()
    state.rpc_sessions = 0
    for _ in range(3):
        assert state.tick() is False
    assert not tproxy._geph_up and state.strikes == 3
    assert asyncio.run(state.request()) == b""
    assert state.dials == []


def test_cold_start_miss_cannot_invent_admission(owned_probe):
    state = owned_probe
    state.rpc_sessions = 0
    assert not state.tick()
    assert not tproxy._geph_up
    assert asyncio.run(state.request()) == b""
    assert state.dials == []


def test_healthy_owned_probe_control_reaches_the_handler(owned_probe):
    state = owned_probe
    assert state.tick() and tproxy._geph_owned
    assert asyncio.run(state.request()) == PAYLOAD
    assert state.dials == [(HOST, 443)]


def test_explicit_external_port_keeps_its_existing_hysteresis(owned_probe, monkeypatch):
    state = owned_probe
    monkeypatch.setattr(tproxy, "_env_geph_port", str(tproxy.GEPH_EXTERNAL_PORT))
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_EXTERNAL_PORT])
    assert state.tick() and tproxy._geph_up
    assert tproxy._geph_port == tproxy.GEPH_EXTERNAL_PORT
    assert not tproxy._geph_owned and not tproxy.owned_geph_route_required()
    state.rpc_sessions = 0
    assert not state.tick() and tproxy._geph_up and state.strikes == 1
    assert tproxy._geph_port == tproxy.GEPH_EXTERNAL_PORT and not tproxy._geph_owned
    assert state.forbidden == []

"""A payload-qualified owned successor must admit the next new connection."""

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
from test_traffic_contracts import (
    CaptureWriter, ScriptedReader, isolate_runtime_state, run_handler, tls_client,
)


@pytest.fixture
def owned_recovery(monkeypatch):
    isolate_runtime_state(monkeypatch)
    state = SimpleNamespace(
        pid=100, owned=True, monotonic=100.0, outcome="ready",
        commands=[], payload_probes=[], release_holds=[], forbidden=[],
    )

    def forbidden(*_args, **_kwargs):
        state.forbidden.append("external effect")
        raise AssertionError("owned recovery hold fixture forbids external I/O")

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
        (tproxy, ("dial_plain", "dial_strategy",
                  "resolve_connection_ips", "save_auto_geph", "save_strat_cache",
                  "_coalesced_owned_geph_recovery_for_replay")),
        (tproxy.geph_backend, ("read_enabled", "read_ownership")),
    ):
        for name in names:
            if hasattr(owner, name):
                monkeypatch.setattr(owner, name, forbidden)

    # Replace only tproxy's clock object, leaving asyncio's real deadlines intact.
    monkeypatch.setattr(tproxy, "time", SimpleNamespace(
        time=lambda: 100.0,
        monotonic=lambda: state.monotonic,
        sleep=lambda delay: setattr(state, "monotonic", state.monotonic + delay),
    ))
    monkeypatch.setattr(tproxy, "_shutdown_started", threading.Event())
    monkeypatch.setattr(tproxy, "_geph_session_lock", threading.Lock())
    monkeypatch.setattr(tproxy, "_geph_backend_hold_generation", 0, raising=False)
    monkeypatch.setattr(tproxy, "_geph_restart_failures", deque())
    hint = dict(tproxy._geph_restart_hint)
    hint.update(recommended=False, last_requested_at=0.0, last_attempt_at=0.0)
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_rearm_state", dict(tproxy._rearm_state))
    monkeypatch.setattr(tproxy, "_geph_last_failure", {"host": "", "reason": "", "ts": 0.0})
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_route_intent", (None, True))
    monkeypatch.setattr(tproxy, "_active_route_policy_manifest", None)
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.19", 443))
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "geph_ownership_path", lambda: "/private-fixture/owned.json")
    monkeypatch.setattr(tproxy, "_read_geph_ownership", lambda _path: {
        "uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL,
    })
    monkeypatch.setattr(tproxy, "_ownership_file_uid", lambda _path: 502)
    monkeypatch.setattr(tproxy, "geph_listener_owned", lambda *args, listener_pid=None, **kwargs: (
        state.owned and (listener_pid is None or listener_pid == state.pid)
    ))
    monkeypatch.setattr(tproxy, "_probe_owned_geph_recovery_state", lambda pid, **kwargs: (
        "ready" if pid == state.pid and state.owned else "conflict"
    ))
    monkeypatch.setattr(tproxy, "_retry_pending_auto_geph_confirmations_after_drain", lambda: False)

    lsof = ["/usr/sbin/lsof", "-nP", f"-iTCP:{tproxy.GEPH_OWNED_PORT}",
            "-sTCP:LISTEN", "-t"]
    kickstart = ["/bin/launchctl", "kickstart", "-k", "gui/502/dev.slipstream.geph"]

    def command(command, **kwargs):
        state.commands.append(command)
        assert kwargs["capture_output"] and kwargs["text"]
        assert kwargs["timeout"] == tproxy.RUN_COMMAND_TIMEOUT_SECONDS
        assert tproxy._geph_restart_draining
        if command == lsof:
            return subprocess.CompletedProcess(command, 0, f"{state.pid}\n", "")
        if command == kickstart:
            assert state.pid == 100, "a recovery must not restart twice"
            assert tproxy._geph_backend_hold_until == 130.0
            assert not tproxy._geph_up
            state.pid = 101
            return subprocess.CompletedProcess(command, 0, "", "")
        return forbidden()

    monkeypatch.setattr(subprocess, "run", command)

    def payload(host, spec, *, timeout):
        assert state.pid == 101 and tproxy._geph_restart_draining
        assert tproxy._geph_backend_hold_until == 130.0
        assert not tproxy.geo_exit_backend_ready()
        state.payload_probes.append((host, timeout))
        if state.outcome == "payload_timeout":
            state.monotonic += tproxy.GEPH_RESTART_PAYLOAD_READY_GRACE
            return 0
        if state.outcome == "pid_drift":
            state.pid = 102
        elif state.outcome == "conflict":
            state.owned = False
        elif state.outcome == "shutdown":
            tproxy._shutdown_started.set()
            return 0
        elif state.outcome == "shutdown_after_payload":
            tproxy._shutdown_started.set()
        elif state.outcome == "new_hold_during_payload":
            # Same timestamp/reason/deadline: only the generation identifies
            # this newer failure. A healthy monitor probe is not payload proof.
            tproxy.suspend_geo_exit_backend("owned Geph restart in progress", now=100.0)
            tproxy._geph_up = True
        return tproxy._local_payload_min_bytes(spec)

    monkeypatch.setattr(tproxy, "_geph_payload_probe", payload)
    finish = tproxy._finish_geph_restart_drain

    def release(*, retry_pending=True):
        assert tproxy._geph_restart_draining
        state.release_holds.append(tproxy._geph_backend_hold_until)
        return finish(retry_pending=retry_pending)

    monkeypatch.setattr(tproxy, "_finish_geph_restart_drain", release)
    yield state
    assert not tproxy._geph_restart_draining
    assert tproxy.geph_active_session_count() == 0
    assert state.forbidden == []
    assert state.commands.count(kickstart) == 1


def test_payload_qualified_recovery_admits_next_owned_request(monkeypatch, owned_recovery):
    state = owned_recovery
    host = "store.steampowered.com"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nsteam"
    dials, upstreams = [], []

    async def owned_dial(actual_host, port, first_flight):
        assert actual_host == host and port == 443
        assert tproxy._geph_owned and tproxy._geph_port == tproxy.GEPH_OWNED_PORT
        assert tproxy.geph_active_session_count() == 1
        dials.append(first_flight)
        upstream = CaptureWriter()
        upstreams.append(upstream)
        return ScriptedReader(stream=(response,)), upstream

    monkeypatch.setattr(tproxy, "dial_via_geph", owned_dial)
    recovered = tproxy._recover_owned_geph_for_replay_blocking(host)
    ready_after_recovery = tproxy.geo_exit_backend_ready()
    reader, first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    asyncio.run(run_handler(reader, writer))
    observation = {
        "recovered": recovered,
        "hold_until": tproxy._geph_backend_hold_until,
        "ready_after_recovery": ready_after_recovery,
        "release_holds": state.release_holds,
        "new_owned_dials": len(dials),
        "client_bytes": len(writer.payload),
        "forbidden_io_calls": len(state.forbidden),
    }
    print("RECOVERY_HOLD_OBSERVATION=" + json.dumps(observation, sort_keys=True))
    assert recovered is True
    assert state.release_holds == [0.0], "verified payload left the restart hold active at drain release"
    assert ready_after_recovery and tproxy._geph_backend_hold_until == 0.0
    assert tproxy._geph_backend_hold_reason == ""
    assert dials == [first_flight]
    assert bytes(writer.payload) == response and writer.closed
    assert all(upstream.closed for upstream in upstreams)
    assert len(state.payload_probes) == 1


@pytest.mark.parametrize("outcome", [
    "payload_timeout", "pid_drift", "conflict", "shutdown",
    "shutdown_after_payload", "new_hold_during_payload",
])
def test_unverified_recovery_preserves_hold(owned_recovery, outcome):
    state = owned_recovery
    state.outcome = outcome
    assert not tproxy._recover_owned_geph_for_replay_blocking("store.steampowered.com")
    assert state.release_holds == [130.0]
    assert tproxy._geph_backend_hold_until == 130.0
    assert tproxy._geph_backend_hold_reason == "owned Geph restart in progress"
    assert not tproxy.geo_exit_backend_ready()
    assert len(state.payload_probes) == 1

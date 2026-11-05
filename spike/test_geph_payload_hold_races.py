"""Canary results commit only to the owned backend and hold they observed."""

import asyncio
from collections import deque
import os
import socket
import subprocess
import threading
from types import SimpleNamespace

import pytest
import tproxy


HOLD_REASON = "owned Geph restart in progress"


@pytest.fixture
def canary_backend(monkeypatch):
    state = SimpleNamespace(pid=101, owned=True, probes=[], restarts=[], forbidden=[])

    def forbidden(*_args, **_kwargs):
        state.forbidden.append("external effect")
        raise AssertionError("payload hold fixture forbids external I/O")

    for owner, names in (
        (socket.socket, ("connect", "connect_ex", "bind", "listen")),
        (socket, ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
                  "gethostbyaddr", "create_connection")),
        (asyncio, ("open_connection", "start_server", "create_subprocess_exec",
                   "create_subprocess_shell")),
        (subprocess, ("run", "Popen")),
        (os, ("system", "fork", "posix_spawn", "posix_spawnp")),
        (threading.Thread, ("start",)),
        (tproxy._POOL, ("submit",)),
        (tproxy, ("_run", "_console_user_home", "_geph_payload_probe",
                  "execute_owned_geph_restart", "request_owned_geph_restart",
                  "save_auto_geph", "save_strat_cache")),
        (tproxy.geph_backend, ("read_enabled", "read_ownership")),
    ):
        for name in names:
            if hasattr(owner, name):
                monkeypatch.setattr(owner, name, forbidden)

    monkeypatch.setattr(tproxy, "time", SimpleNamespace(
        time=lambda: 100.0, monotonic=lambda: 100.0, sleep=forbidden,
    ))
    monkeypatch.setattr(tproxy, "_shutdown_started", threading.Event())
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_reason", "")
    monkeypatch.setattr(tproxy, "_geph_backend_hold_generation", 0, raising=False)
    monkeypatch.setattr(tproxy, "_geph_last_failure", {
        "host": "fixture.invalid", "reason": "payload probe failed", "ts": 100.0,
    })
    hint = dict(tproxy._geph_restart_hint)
    hint.update(recommended=False, reason="", last_requested_at=0.0, last_attempt_at=0.0)
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_restart_failures", deque([
        (100.0, "fixture.invalid", "payload probe failed"),
    ]))
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: state.pid)
    monkeypatch.setattr(tproxy, "geph_listener_owned", lambda *args, listener_pid=None, **kwargs: (
        state.owned and (listener_pid is None or listener_pid == state.pid)
    ))
    monkeypatch.setattr(tproxy, "_request_owned_geph_restart_from_payload_failures", lambda failures: (
        state.restarts.append(tuple(failures)) or True
    ))
    tproxy.suspend_geo_exit_backend(HOLD_REASON, now=100.0)
    tproxy._geph_up = True  # The monitor has verified control/listener liveness.
    assert not tproxy.geo_exit_backend_ready()
    yield state
    assert state.forbidden == []


def run_canary_batch(monkeypatch, state, *, healthy, mutation=None):
    """Finish one result, mutate the backend, then finish the same gather."""
    specs = tuple(tproxy.OWNED_GEPH_PAYLOAD_CANARY_SPECS)
    assert len(specs) >= 2

    async def scenario():
        first_completed = asyncio.Event()
        finish_others = asyncio.Event()

        async def payload(host, spec):
            state.probes.append((host, spec["name"]))
            if spec["name"] == specs[0]["name"]:
                first_completed.set()
                return tproxy._local_payload_min_bytes(spec) if healthy else 0
            await finish_others.wait()
            return 0

        monkeypatch.setattr(tproxy, "_run_geph_payload_probe", payload)
        batch = asyncio.create_task(tproxy._run_owned_geph_payload_canaries())
        try:
            await first_completed.wait()
            if mutation is not None:
                mutation()
            hint_before_commit = dict(tproxy._geph_restart_hint)
            failures_before_commit = tuple(tproxy._geph_restart_failures)
            finish_others.set()
            return await batch, hint_before_commit, failures_before_commit
        finally:
            finish_others.set()
            if not batch.done():
                batch.cancel()
            await asyncio.gather(batch, return_exceptions=True)

    async def bounded():
        return await asyncio.wait_for(scenario(), timeout=1.0)

    result = asyncio.run(bounded())
    assert sorted(state.probes) == sorted((spec["host"], spec["name"]) for spec in specs)
    return result


def test_same_backend_canary_payload_clears_original_hold(monkeypatch, canary_backend):
    state = canary_backend
    result, _, _ = run_canary_batch(monkeypatch, state, healthy=True)
    assert result is True
    assert tproxy._geph_backend_hold_until == 0.0
    assert tproxy._geph_backend_hold_reason == ""
    assert tproxy.geo_exit_backend_ready()
    assert not tproxy._geph_restart_failures
    assert not tproxy._geph_restart_hint["recommended"]
    assert state.restarts == []


@pytest.mark.parametrize("healthy", [True, False], ids=["success", "failure"])
@pytest.mark.parametrize("change", ["pid_drift", "conflict", "shutdown", "new_hold"])
def test_stale_canary_result_cannot_clear_hold_or_request_restart(
    monkeypatch, canary_backend, healthy, change,
):
    state = canary_backend

    def mutate():
        if change == "pid_drift":
            state.pid = 102
        elif change == "conflict":
            state.owned = False
        elif change == "shutdown":
            tproxy._shutdown_started.set()
        else:
            # Deliberately preserve every old hold value except its generation.
            tproxy.suspend_geo_exit_backend(HOLD_REASON, now=100.0)
            tproxy._geph_up = True
            tproxy._geph_restart_hint.update(recommended=True, reason="new failure")

    result, hint, failures = run_canary_batch(
        monkeypatch, state, healthy=healthy, mutation=mutate,
    )
    assert result is None
    assert tproxy._geph_backend_hold_until == 130.0
    assert tproxy._geph_backend_hold_reason == HOLD_REASON
    assert not tproxy.geo_exit_backend_ready()
    assert tproxy._geph_restart_hint == hint
    assert tuple(tproxy._geph_restart_failures) == failures
    assert state.restarts == []


def test_current_failed_canaries_still_request_existing_recovery(monkeypatch, canary_backend):
    state = canary_backend
    result, _, _ = run_canary_batch(monkeypatch, state, healthy=False)
    assert result is False
    assert len(state.restarts) == 1
    assert len(state.restarts[0]) == len(tproxy.OWNED_GEPH_PAYLOAD_CANARY_SPECS)
    assert tproxy._geph_backend_hold_until == 130.0
    assert not tproxy.geo_exit_backend_ready()

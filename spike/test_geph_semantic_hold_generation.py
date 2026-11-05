"""A semantic payload proof cannot authorize a later backend-hold generation."""

from concurrent.futures import Future
import asyncio
import json
import os
import socket
import subprocess
import threading
from types import SimpleNamespace

import pytest
import tproxy
from test_traffic_contracts import isolate_runtime_state


PATHS = ("semantic", "incomplete", "stable", "preflight")
HOLD_REASON = "fixture payload unavailable"


@pytest.fixture
def semantic_backend(monkeypatch):
    isolate_runtime_state(monkeypatch)
    state = SimpleNamespace(
        host="semantic-generation.example", pid=101, probes=[], writes=[],
        forbidden=[], mutate_after=0, mutations=0,
    )
    state.retry_helper = tproxy._retry_semantic_geph_probe_after_owned_restart

    def forbidden(*_args, **_kwargs):
        state.forbidden.append("external effect")
        raise AssertionError("semantic hold fixture forbids external I/O and replacement")

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
        (tproxy, ("_run", "_console_user_home", "_atomic_write_json",
                  "execute_owned_geph_restart", "request_owned_geph_restart",
                  "_retry_semantic_geph_probe_after_owned_restart")),
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
    monkeypatch.setattr(tproxy, "_auto_geph_lock", threading.RLock())
    monkeypatch.setattr(tproxy, "_geph_backend_hold_lock", threading.RLock())
    monkeypatch.setattr(tproxy, "_geph_backend_hold_generation", 0)
    hint = dict(tproxy._geph_restart_hint)
    hint.update(recommended=False, last_requested_at=0.0, last_attempt_at=0.0)
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_route_preflight_lock", threading.RLock())
    monkeypatch.setattr(tproxy, "_route_preflight_inflight", {})
    monkeypatch.setattr(tproxy, "_auto_geph_last_status", dict(tproxy._auto_geph_last_status))
    monkeypatch.setattr(tproxy, "_active_route_policy_manifest", None)
    monkeypatch.setattr(tproxy, "AUTO_GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_network_wide_unknown_failure_visible", lambda *args: False)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: state.pid)
    monkeypatch.setattr(tproxy, "geph_listener_owned", lambda *args, listener_pid=None, **kwargs: (
        listener_pid is None or listener_pid == state.pid
    ))
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: state.writes.append(dict(tproxy._auto_geph)))

    def monitor_liveness():
        tproxy._geph_up, strikes = tproxy.reduce_geph_probe_state(
            previous_up=tproxy._geph_up, strikes=0, probe_ok=True,
            port=tproxy._geph_port, conflict=False,
        )
        assert tproxy._geph_up and strikes == 0

    def newer_hold():
        assert not tproxy._geph_backend_hold_lock._is_owned()
        before = tproxy._geph_backend_hold_generation
        tproxy.suspend_geo_exit_backend(HOLD_REASON, now=100.0)
        assert tproxy._geph_backend_hold_generation == before + 1
        monitor_liveness()
        state.mutations += 1
        # PID, reason, deadline and liveness are identical to the original hold.
        assert state.pid == 101 and tproxy._geph_backend_hold_until == 130.0
        assert not tproxy.geo_exit_backend_ready()

    def payload(candidate, **_kwargs):
        assert candidate == state.host
        state.probes.append(tproxy._geph_backend_hold_generation)
        payload_bytes = tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES
        if state.mutate_after and len(state.probes) == state.mutate_after:
            # The positive bytes belong to the old generation. Before the
            # caller receives that result, another failure and a monitor probe
            # have occurred; neither supplies a new target payload proof.
            state.payload_mutation()
        return payload_bytes

    for name in ("_semantic_geph_payload_probe", "_incomplete_response_geph_payload_probe",
                 "_auto_geph_payload_probe"):
        monkeypatch.setattr(tproxy, name, payload)
    tproxy.suspend_geo_exit_backend(HOLD_REASON, now=100.0)
    monitor_liveness()
    state.original_generation = tproxy._geph_backend_hold_generation
    state.newer_hold = newer_hold
    state.monitor_liveness = monitor_liveness
    state.payload_mutation = newer_hold
    state.owner = Future()
    tproxy._route_preflight_inflight[state.host] = state.owner
    state.job = tproxy.route_preflight.RoutePreflightJobV1(
        capability="a" * 32, host=state.host,
        candidate_routes=("system", "owned_geph"),
        issued_at_unix_ms=100_000, deadline_unix_ms=102_000,
    )

    def preflight_proof():
        return tproxy._prove_preflight_owned_geph_route(
            state.host, tproxy.SEMANTIC_OUTCOME_REGIONAL_DENIAL, 2.0,
            probe=payload, job=state.job, deadline_monotonic=102.0,
        )

    state.preflight_proof = preflight_proof
    yield state
    assert state.forbidden == []
    assert tproxy.geph_active_session_count() == 0
    assert not tproxy._geph_restart_draining


def confirm(path, state):
    if path == "semantic":
        return tproxy._confirm_semantic_geo_exit(state.host)
    if path == "incomplete":
        return tproxy._confirm_incomplete_response_geo_exit(state.host)
    if path == "stable":
        tproxy._auto_geph_candidates[state.host] = 160.0
        return tproxy._confirm_auto_geph(state.host)
    proof = state.preflight_proof()
    return proof is not None and tproxy._commit_preflight_owned_geph_proof(proof, state.owner)


def observe(path, state, selected):
    observation = {
        "path": path, "selected": selected,
        "hold_until": tproxy._geph_backend_hold_until,
        "admission_ready": tproxy.geo_exit_backend_ready(),
        "learned": state.host in tproxy._auto_geph,
        "storage_writes": len(state.writes), "payload_probes": len(state.probes),
        "generation_before_payload": state.original_generation,
        "current_generation": tproxy._geph_backend_hold_generation,
        "forbidden_io_calls": len(state.forbidden),
    }
    print("SEMANTIC_HOLD_OBSERVATION=" + json.dumps(observation, sort_keys=True))
    return observation


@pytest.mark.parametrize("path", PATHS)
def test_payload_from_old_generation_cannot_clear_or_learn(path, semantic_backend):
    state = semantic_backend
    state.mutate_after = tproxy.AUTO_GEPH_CONFIRM_STABLE_PROBES if path == "stable" else 1
    selected = confirm(path, state)
    value = observe(path, state, selected)
    assert state.mutations == 1
    assert state.probes == [state.original_generation] * state.mutate_after
    assert value["hold_until"] == 130.0, "old payload erased a newer backend hold"
    assert not value["admission_ready"]
    assert not selected and not value["learned"] and not state.writes


@pytest.mark.parametrize("path", PATHS)
def test_current_generation_payload_still_commits(path, semantic_backend):
    state = semantic_backend
    selected = confirm(path, state)
    value = observe(path, state, selected)
    assert selected and value["learned"] and value["admission_ready"]
    assert value["hold_until"] == 0.0 and tproxy._geph_backend_hold_reason == ""
    assert len(state.writes) == 1
    assert len(state.probes) == (tproxy.AUTO_GEPH_CONFIRM_STABLE_PROBES if path == "stable" else 1)


def test_preflight_proof_remains_bound_to_generation_at_payload(semantic_backend):
    state = semantic_backend
    proof = state.preflight_proof()
    assert proof is not None and not state.writes
    state.newer_hold()
    selected = tproxy._commit_preflight_owned_geph_proof(proof, state.owner)
    value = observe("preflight_delayed_commit", state, selected)
    assert value["hold_until"] == 130.0, "delayed proof erased a newer backend hold"
    assert not value["admission_ready"]
    assert not selected and not value["learned"] and not state.writes


@pytest.mark.parametrize("path", PATHS)
def test_new_hold_during_save_survives_already_committed_learning(
    monkeypatch, path, semantic_backend,
):
    state = semantic_backend

    def save():
        # Learning has linearized, and persistence must not hold the admission
        # lock. This later failure does not retroactively invalidate that learn.
        assert state.host in tproxy._auto_geph
        assert tproxy._geph_backend_hold_until == 0.0
        assert not tproxy._geph_backend_hold_lock._is_owned()
        state.newer_hold()
        state.writes.append(dict(tproxy._auto_geph))

    monkeypatch.setattr(tproxy, "save_auto_geph", save)
    selected = confirm(path, state)
    value = observe(path + "_during_save", state, selected)
    assert selected and value["learned"] and len(state.writes) == 1
    assert state.mutations == 1
    assert value["hold_until"] == 130.0 and not value["admission_ready"]
    assert tproxy._geph_backend_hold_reason == HOLD_REASON


@pytest.mark.parametrize("path", PATHS)
def test_shutdown_after_payload_prevents_learning_and_hold_clear(path, semantic_backend):
    state = semantic_backend

    def shutdown():
        assert not tproxy._geph_backend_hold_lock._is_owned()
        tproxy._shutdown_started.set()
        state.mutations += 1

    state.payload_mutation = shutdown
    state.mutate_after = tproxy.AUTO_GEPH_CONFIRM_STABLE_PROBES if path == "stable" else 1
    selected = confirm(path, state)
    value = observe(path + "_shutdown", state, selected)
    assert state.mutations == 1
    assert value["current_generation"] == state.original_generation
    assert value["hold_until"] == 130.0 and not value["admission_ready"]
    assert not selected and not value["learned"] and not state.writes


@pytest.mark.parametrize("path", ("semantic", "incomplete"))
@pytest.mark.parametrize("stale", (False, True), ids=("current_successor", "newer_hold"))
def test_retry_callback_carries_generation_from_before_target_payload(
    monkeypatch, path, stale, semantic_backend,
):
    state = semantic_backend
    state.pid = 100
    restarts = []
    requests = []

    def restart(*, now, active_sessions):
        assert active_sessions == 0 and tproxy._geph_restart_draining
        restarts.append(state.pid)
        assert state.pid == 100, "the bounded fixture permits one replacement"
        tproxy.suspend_geo_exit_backend(HOLD_REASON, now=now)
        state.pid = 101
        state.monitor_liveness()
        return "restarted"

    def payload(candidate, **_kwargs):
        assert candidate == state.host
        state.probes.append(tproxy._geph_backend_hold_generation)
        if len(state.probes) == 1:
            return 0  # The direct semantic attempt needs the existing retry.
        assert len(state.probes) == 2 and state.pid == 101
        if stale:
            state.newer_hold()
        return tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES

    monkeypatch.setattr(tproxy, "_retry_semantic_geph_probe_after_owned_restart", state.retry_helper)
    monkeypatch.setattr(tproxy, "request_owned_geph_restart", lambda *args, **kwargs: (
        requests.append(args) or True
    ))
    monkeypatch.setattr(tproxy, "execute_owned_geph_restart", restart)
    monkeypatch.setattr(tproxy, "_wait_for_owned_geph_payload_ready", lambda pid: (
        "ready" if pid == 101 else pytest.fail("wrong successor payload probe")
    ))
    for name in ("_semantic_geph_payload_probe", "_incomplete_response_geph_payload_probe"):
        monkeypatch.setattr(tproxy, name, payload)

    selected = confirm(path, state)
    value = observe(path + "_retry", state, selected)
    assert restarts == [100] and len(requests) == 1
    assert state.probes == [state.original_generation, state.original_generation + 1]
    if stale:
        assert value["hold_until"] == 130.0 and not value["admission_ready"]
        assert not selected and not value["learned"] and not state.writes
    else:
        assert selected and value["learned"] and value["admission_ready"]
        assert value["hold_until"] == 0.0 and len(state.writes) == 1

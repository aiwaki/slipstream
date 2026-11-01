"""Restart drain ownership survives errors and transfers only on success."""
import asyncio
import errno
import json
from collections import deque
import os
import socket
import subprocess
import threading

import pytest
import tproxy


def _exercise_successor_lsof_emfile(monkeypatch):
    forbidden_calls = []
    commands = []
    cooling = []
    ownership_checks = []

    def forbidden(*args, **kwargs):
        forbidden_calls.append("external effect")
        raise AssertionError("private drain fixture forbids external I/O")

    for owner, names in (
        (socket.socket, ("connect", "connect_ex", "bind", "listen")),
        (socket, ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
                  "gethostbyaddr", "create_connection")),
        (asyncio, ("open_connection", "start_server", "create_subprocess_exec",
                   "create_subprocess_shell")),
        (subprocess, ("Popen",)),
        (os, ("system", "fork", "posix_spawn", "posix_spawnp")),
        (tproxy, ("_console_user_home", "geph_ownership_path",
                  "_read_geph_ownership", "_ownership_file_uid",
                  "_wait_for_owned_geph_payload_ready", "note_runtime_rearm")),
        (tproxy.geph_backend, ("read_enabled", "read_ownership")),
    ):
        for name in names:
            if hasattr(owner, name):
                monkeypatch.setattr(owner, name, forbidden)

    monkeypatch.setattr(tproxy, "_shutdown_started", threading.Event())
    monkeypatch.setattr(tproxy, "_geph_session_lock", threading.Lock())
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    hint = dict(tproxy._geph_restart_hint)
    hint.update(recommended=True, last_attempt_at=0.0)
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)

    # Supply the same explicit verified fixture ownership as existing restart tests.
    # Actual ownership file reads and platform identity probes remain prohibited.
    def owned(port):
        ownership_checks.append(port)
        assert port == tproxy.GEPH_OWNED_PORT
        return True

    monkeypatch.setattr(tproxy, "geph_listener_owned", owned)
    lsof = ["/usr/sbin/lsof", "-nP", f"-iTCP:{tproxy.GEPH_OWNED_PORT}",
            "-sTCP:LISTEN", "-t"]
    kickstart = ["/bin/launchctl", "kickstart", "-k", "gui/502/dev.slipstream.geph"]

    def controlled_subprocess(command, **kwargs):
        commands.append(command)
        assert kwargs["capture_output"] is True and kwargs["text"] is True
        assert kwargs["timeout"] == tproxy.RUN_COMMAND_TIMEOUT_SECONDS
        assert tproxy._geph_restart_draining is True
        if len(commands) == 1 and command == lsof:
            return subprocess.CompletedProcess(command, 0, "100\n", "")
        if len(commands) == 2 and command == kickstart:
            return subprocess.CompletedProcess(command, 0, "", "")
        if len(commands) == 3 and command == lsof:
            # subprocess.run creates capture pipes/process resources before exec.
            # _run handles missing command/timeouts, but this resource error escapes.
            raise OSError(errno.EMFILE, "synthetic capture-pipe FD exhaustion")
        return forbidden()

    monkeypatch.setattr(subprocess, "run", controlled_subprocess)
    outcome = {"return_value": None, "exception": None, "errno": None}
    try:
        try:
            outcome["return_value"] = tproxy.execute_owned_geph_restart(
                now=100.0,
                ownership_path="/private-fixture/geph-owned.json",
                ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
                owner_uid=502,
                listener_owned=True,
                backend_suspender=lambda: cooling.append("cooled"),
            )
        except OSError as error:
            outcome["exception"] = type(error).__name__
            outcome["errno"] = error.errno
        outcome.update(
            draining_after_failure=tproxy._geph_restart_draining,
            fresh_session_admitted=tproxy._geph_session_started(),
            subprocess_calls=len(commands),
            forbidden_io_calls=len(forbidden_calls),
        )
        print("DRAIN_OBSERVATION=" + json.dumps(outcome, sort_keys=True))
        assert commands == [lsof, kickstart, lsof]
        assert cooling == ["cooled"] and ownership_checks == [tproxy.GEPH_OWNED_PORT]
        assert forbidden_calls == []
        assert (outcome["draining_after_failure"], outcome["fresh_session_admitted"]) == (False, True), (
            "successor process-spawn failure left the restart drain reserved and denied a fresh session"
        )
    finally:
        # Restore the private in-process state even when the causal assertion is RED.
        # Disable deferred retries so cleanup cannot schedule any recovery work.
        tproxy._geph_active_sessions = 0
        tproxy._finish_geph_restart_drain(retry_pending=False)
        cleanup = {"draining": tproxy._geph_restart_draining,
                   "active_sessions": tproxy._geph_active_sessions,
                   "forbidden_io_calls": len(forbidden_calls)}
        print("DRAIN_CLEANUP=" + json.dumps(cleanup, sort_keys=True))
        assert cleanup == {"draining": False, "active_sessions": 0, "forbidden_io_calls": 0}


@pytest.fixture
def guarded_restart(monkeypatch):
    state = {"forbidden": [], "commands": [], "releases": [], "rearm": [],
             "ready_probes": [], "deferred": [], "kickstart_code": 0}

    def forbidden(*args, **kwargs):
        state["forbidden"].append("external effect")
        raise AssertionError("private drain candidate forbids external I/O")

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
        (tproxy, ("_console_user_home", "geph_ownership_path",
                  "_read_geph_ownership", "_ownership_file_uid",
                  "_wait_for_owned_geph_payload_ready")),
        (tproxy.geph_backend, ("read_enabled", "read_ownership")),
    ):
        for name in names:
            if hasattr(owner, name):
                monkeypatch.setattr(owner, name, forbidden)
    monkeypatch.setattr(tproxy, "_shutdown_started", threading.Event())
    monkeypatch.setattr(tproxy, "_geph_session_lock", threading.Lock())
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_restart_failures", deque())
    hint = dict(tproxy._geph_restart_hint)
    hint.update(recommended=True, last_attempt_at=0.0)
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "geph_listener_owned", lambda *a, **kw: True)
    monkeypatch.setattr(tproxy, "note_runtime_rearm", lambda reason: state["rearm"].append(reason))
    monkeypatch.setattr(tproxy, "_retry_pending_auto_geph_confirmations_after_drain",
                        lambda: state["deferred"].append("retry callback") or False)

    real_finish = tproxy._finish_geph_restart_drain

    def finish(*, retry_pending=True):
        state["releases"].append(retry_pending)
        return real_finish(retry_pending=retry_pending)

    monkeypatch.setattr(tproxy, "_finish_geph_restart_drain", finish)

    def ready(pid, **kwargs):
        assert pid == 101
        state["ready_probes"].append((pid, tproxy._geph_restart_draining))
        return "ready"

    monkeypatch.setattr(tproxy, "_probe_owned_geph_recovery_state", ready)
    lsof = ["/usr/sbin/lsof", "-nP", f"-iTCP:{tproxy.GEPH_OWNED_PORT}",
            "-sTCP:LISTEN", "-t"]
    kickstart = ["/bin/launchctl", "kickstart", "-k", "gui/502/dev.slipstream.geph"]

    def subprocess_result(command, **kwargs):
        state["commands"].append(command)
        assert kwargs["capture_output"] is True and kwargs["text"] is True
        assert kwargs["timeout"] == tproxy.RUN_COMMAND_TIMEOUT_SECONDS
        assert tproxy._geph_restart_draining is True
        if len(state["commands"]) == 1 and command == lsof:
            return subprocess.CompletedProcess(command, 0, "100\n", "")
        if len(state["commands"]) == 2 and command == kickstart:
            return subprocess.CompletedProcess(command, state["kickstart_code"], "", "fixture command result")
        if len(state["commands"]) == 3 and command == lsof:
            return subprocess.CompletedProcess(command, 0, "101\n", "")
        return forbidden()

    monkeypatch.setattr(subprocess, "run", subprocess_result)
    state["kwargs"] = dict(now=100.0,
                           ownership_path="/private-fixture/geph-owned.json",
                           ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
                           owner_uid=502, listener_owned=True,
                           backend_suspender=lambda: None)
    try:
        yield state
    finally:
        tproxy._geph_active_sessions = 0
        real_finish(retry_pending=False)
        assert not tproxy._geph_restart_draining
        assert state["forbidden"] == []


def test_same_causal_red_postcondition_with_single_owned_release(monkeypatch, guarded_restart):
    # The causal helper body matches the retained original RED reproduction.
    _exercise_successor_lsof_emfile(monkeypatch)
    # First release belongs to execute; the second is the frozen fixture's cleanup.
    assert guarded_restart["releases"] == [True, False]
    assert guarded_restart["deferred"] == ["retry callback"]


def test_success_hands_managed_drain_to_payload_caller(guarded_restart):
    state = guarded_restart
    assert tproxy.execute_owned_geph_restart(**state["kwargs"]) == "restarted"
    assert state["ready_probes"] == [(101, True)]
    assert state["rearm"] == ["geph_restart"]
    assert state["releases"] == [] and state["deferred"] == []
    assert tproxy._geph_restart_draining
    assert not tproxy._geph_session_started()
    # The caller releases only after successor payload qualification in production.
    tproxy._finish_geph_restart_drain(retry_pending=False)
    assert state["releases"] == [False]
    assert not tproxy._geph_restart_draining
    assert tproxy._geph_session_started()


@pytest.mark.parametrize("returncode, expected", [(0, "restarted"), (1, "unavailable")])
def test_unmanaged_return_never_releases_an_existing_drain(guarded_restart, returncode, expected):
    state = guarded_restart
    tproxy._geph_restart_draining = True  # Owned by another caller; not this injected mode.
    state["kickstart_code"] = returncode
    assert tproxy.execute_owned_geph_restart(active_sessions=0, **state["kwargs"]) == expected
    assert state["releases"] == [] and state["deferred"] == []
    assert tproxy._geph_restart_draining
    assert not tproxy._geph_session_started()


def test_managed_command_rejection_releases_exactly_once(guarded_restart):
    state = guarded_restart
    state["kickstart_code"] = 1
    assert tproxy.execute_owned_geph_restart(**state["kwargs"]) == "unavailable"
    assert len(state["commands"]) == 2
    assert state["ready_probes"] == [] and state["rearm"] == []
    assert state["releases"] == [True]
    assert state["deferred"] == ["retry callback"]
    assert not tproxy._geph_restart_draining
    assert tproxy._geph_session_started()

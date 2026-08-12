import asyncio
import ast
import base64
import errno
import hashlib
import inspect
import json
import logging
import os
import plistlib
import re
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from collections import OrderedDict, deque

import pytest
import tproxy
from tproxy import _doh_request, _doh_ssl_context
from scripts import composed_pending_navigation_smoke as composed


_REAL_CLAIM_PF_LOOPBACK_SKIP = tproxy._claim_pf_loopback_skip
_REAL_RESTORE_PF_LOOPBACK_SKIP = tproxy._restore_pf_loopback_skip
_PROBE_LAUNCH_ONE = "1111111111111111"
_PROBE_LAUNCH_TWO = "2222222222222222"
_PENDING_NAVIGATION_PROBE_CONTRACT = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "contracts"
        / "pending-navigation-probe-v1.json"
    ).read_text()
)


@pytest.fixture(autouse=True)
def reset_smart_dns_state(monkeypatch, tmp_path):
    shutdown_started = tproxy._shutdown_started.is_set()
    pf_teardown_complete = tproxy._pf_teardown_complete.is_set()
    route_policy_trial_generation = tproxy._route_policy_trial_generation
    dns_cache = dict(tproxy._system_dns_cache)
    smart_ok = dict(tproxy._smart_dns_ok_until)
    smart_failure = dict(tproxy._smart_dns_last_failure)
    auto_fail = {host: list(values) for host, values in tproxy._auto_fail.items()}
    auto_geph = dict(tproxy._auto_geph)
    auto_confirming = dict(tproxy._auto_geph_confirming)
    auto_confirmation_tokens = dict(tproxy._auto_geph_confirmation_tokens)
    auto_last_probe = dict(tproxy._auto_geph_last_probe)
    auto_retry_after_drain = dict(tproxy._auto_geph_retry_after_drain)
    auto_runtime_failures = {
        host: list(values)
        for host, values in tproxy._auto_geph_runtime_failures.items()
    }
    auto_candidates = dict(tproxy._auto_geph_candidates)
    auto_noise_invalidated = set(tproxy._auto_geph_noise_invalidated)
    partial_stalls = {
        host: dict(values) for host, values in tproxy._local_partial_stalls.items()
    }
    zero_payload_failures = {
        host: dict(values)
        for host, values in tproxy._local_zero_payload_failures.items()
    }
    one_shot_consumed_at = dict(tproxy._auto_geph_one_shot_consumed_at)
    payload_idle_failures = {
        host: dict(values)
        for host, values in tproxy._local_payload_idle_failures.items()
    }
    active_pending_relays = {
        host: dict(values)
        for host, values in tproxy._active_pending_navigation_relays.items()
    }
    pending_navigation_probe_capabilities = OrderedDict(
        tproxy._pending_navigation_probe_capabilities
    )
    pending_navigation_probe_host_guards = OrderedDict(
        tproxy._pending_navigation_probe_host_guards
    )
    pending_navigation_probe_accepted_guards = OrderedDict(
        tproxy._pending_navigation_probe_accepted_guards
    )
    pending_navigation_probe_claimed_guards = OrderedDict(
        tproxy._pending_navigation_probe_claimed_guards
    )
    xbox_dns_candidates = dict(tproxy._xbox_dns_candidates)
    xbox_dns_attempts = dict(tproxy._xbox_dns_attempts)
    clean_eof_stalls = {
        host: deque(values) for host, values in tproxy._clean_eof_stalls.items()
    }
    server_first_closes = {
        key: deque(values) for key, values in tproxy._server_first_closes.items()
    }
    server_first_repeat_stages = dict(tproxy._server_first_repeat_stages)
    transport_confirming = dict(tproxy._transport_incomplete_confirming)
    transport_last_probe = dict(tproxy._transport_incomplete_last_probe)
    transport_plain_candidates = dict(
        tproxy._transport_incomplete_plain_candidates
    )
    transport_server_first_evidence = {
        host: dict(values)
        for host, values in (
            tproxy._transport_incomplete_server_first_evidence.items()
        )
    }
    transport_client_first_evidence = {
        host: deque(values)
        for host, values in (
            tproxy._transport_incomplete_client_first_evidence.items()
        )
    }
    semantic_plain_confirming = dict(tproxy._semantic_plain_confirming)
    semantic_plain_last_probe = dict(tproxy._semantic_plain_last_probe)
    semantic_plain_probe_window = deque(tproxy._semantic_plain_probe_window)
    auto_last_status = dict(tproxy._auto_geph_last_status)
    local_resweep_active = dict(tproxy._local_bypass_resweep_active)
    local_resweep_last = dict(tproxy._local_bypass_resweep_last)
    policy_remote = dict(tproxy._route_policy_remote)
    strat_scores = OrderedDict(
        (host, {name: dict(value) for name, value in per_host.items()})
        for host, per_host in tproxy._strat_scores.items()
    )
    canary_health = {key: dict(value) for key, value in tproxy._canary_health.items()}
    canary_windows = {
        key: deque(value) for key, value in tproxy._canary_failure_windows.items()
    }
    canary_state = dict(tproxy._canary_state)
    rearm_state = dict(tproxy._rearm_state)
    runtime_rearm_requests = list(tproxy._runtime_rearm_requests)
    fd_pressure = (
        tproxy._fd_pressure,
        tproxy._fd_pressure_reason,
        tproxy._fd_pressure_at,
    )
    baseline_guard = dict(tproxy._baseline_guard_state)
    baseline_candidate = tproxy.install_guard.BaselineCandidate(
        "example.com", "203.0.113.10", "/"
    )
    monkeypatch.setattr(
        tproxy,
        "_baseline_preflight",
        lambda: (
            tproxy.install_guard.QualificationResult(
                True, "ok", (baseline_candidate,)
            ),
            (501, 20, "/Users/fixture"),
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_baseline_postflight",
        lambda candidates, _identity: tproxy.install_guard.QualificationResult(
            True, "ok", tuple(candidates)
        ),
    )
    monkeypatch.setattr(tproxy, "_claim_pf_loopback_skip", lambda: True)
    monkeypatch.setattr(tproxy, "_restore_pf_loopback_skip", lambda: True)
    monkeypatch.setattr(tproxy, "_pf_loopback_skip_state", lambda: False)
    monkeypatch.setattr(tproxy, "_daemon_recovery_record", lambda: None)
    monkeypatch.setattr(tproxy, "PF_TOKEN_PATH", str(tmp_path / "pf.token"))
    monkeypatch.setattr(
        tproxy,
        "INSTALL_ATTESTATION_PATH",
        str(tmp_path / "install-attestation.json"),
    )
    monkeypatch.setattr(
        tproxy,
        "PF_SKIP_LEASE_PATH",
        str(tmp_path / "pf-skip.lease"),
    )
    try:
        tproxy._shutdown_started.clear()
        tproxy._pf_teardown_complete.clear()
        tproxy._route_policy_trial_generation = 0
        tproxy.reset_route_policy_manifest()
        tproxy._system_dns_cache.update({
            "ts": 0.0,
            "status": None,
            "resolution_ts": 0.0,
            "resolution_checks": None,
        })
        tproxy._smart_dns_ok_until.clear()
        tproxy._smart_dns_last_failure.update({"host": "", "reason": "", "ts": 0.0})
        tproxy._auto_fail.clear()
        tproxy._auto_geph.clear()
        tproxy._auto_geph_confirming.clear()
        tproxy._auto_geph_confirmation_tokens.clear()
        tproxy._auto_geph_last_probe.clear()
        tproxy._auto_geph_retry_after_drain.clear()
        tproxy._auto_geph_runtime_failures.clear()
        tproxy._auto_geph_candidates.clear()
        tproxy._auto_geph_noise_invalidated.clear()
        tproxy._local_partial_stalls.clear()
        tproxy._local_zero_payload_failures.clear()
        tproxy._auto_geph_one_shot_consumed_at.clear()
        tproxy._local_payload_idle_failures.clear()
        tproxy._active_pending_navigation_relays.clear()
        tproxy._pending_navigation_probe_capabilities.clear()
        tproxy._pending_navigation_probe_host_guards.clear()
        tproxy._pending_navigation_probe_accepted_guards.clear()
        tproxy._pending_navigation_probe_claimed_guards.clear()
        tproxy._xbox_dns_candidates.clear()
        tproxy._xbox_dns_attempts.clear()
        tproxy._clean_eof_stalls.clear()
        tproxy._server_first_closes.clear()
        tproxy._server_first_repeat_stages.clear()
        tproxy._transport_incomplete_confirming.clear()
        tproxy._transport_incomplete_last_probe.clear()
        tproxy._transport_incomplete_plain_candidates.clear()
        tproxy._transport_incomplete_server_first_evidence.clear()
        tproxy._transport_incomplete_client_first_evidence.clear()
        tproxy._semantic_plain_confirming.clear()
        tproxy._semantic_plain_last_probe.clear()
        tproxy._semantic_plain_probe_window.clear()
        tproxy._local_bypass_resweep_active.clear()
        tproxy._local_bypass_resweep_last.clear()
        tproxy._auto_geph_last_status.update({
            "state": "idle",
            "host": "",
            "reason": "",
            "ts": 0.0,
            "bytes": 0,
        })
        tproxy._strat_scores.clear()
        tproxy._canary_health.clear()
        tproxy._canary_failure_windows.clear()
        tproxy._canary_state.update({
            "running": False,
            "last_run": 0.0,
            "last_started": 0.0,
            "last_reason": "",
            "next_due": 0.0,
            "pending_reason": "",
            "total": 0,
            "ok": 0,
            "degraded": 0,
            "warnings": 0,
            "unknown": 0,
        })
        tproxy._rearm_state.update({
            "last_at": 0.0,
            "last_reason": "",
            "last_gap": 0.0,
            "last_iface": "",
            "count": 0,
        })
        tproxy._runtime_rearm_requests.clear()
        tproxy._fd_pressure = False
        tproxy._fd_pressure_reason = ""
        tproxy._fd_pressure_at = 0.0
        tproxy._baseline_guard_state.update({
            "state": "pending",
            "reason": "",
            "updated_at": 0.0,
            "retry_at": 0.0,
            "failures": 0,
        })
        yield
    finally:
        if shutdown_started:
            tproxy._shutdown_started.set()
        else:
            tproxy._shutdown_started.clear()
        if pf_teardown_complete:
            tproxy._pf_teardown_complete.set()
        else:
            tproxy._pf_teardown_complete.clear()
        tproxy._route_policy_trial_generation = route_policy_trial_generation
        tproxy.reset_route_policy_manifest()
        tproxy._system_dns_cache.clear()
        tproxy._system_dns_cache.update(dns_cache)
        tproxy._smart_dns_ok_until.clear()
        tproxy._smart_dns_ok_until.update(smart_ok)
        tproxy._smart_dns_last_failure.clear()
        tproxy._smart_dns_last_failure.update(smart_failure)
        tproxy._auto_fail.clear()
        tproxy._auto_fail.update(auto_fail)
        tproxy._auto_geph.clear()
        tproxy._auto_geph.update(auto_geph)
        tproxy._auto_geph_confirming.clear()
        tproxy._auto_geph_confirming.update(auto_confirming)
        tproxy._auto_geph_confirmation_tokens.clear()
        tproxy._auto_geph_confirmation_tokens.update(auto_confirmation_tokens)
        tproxy._auto_geph_last_probe.clear()
        tproxy._auto_geph_last_probe.update(auto_last_probe)
        tproxy._auto_geph_retry_after_drain.clear()
        tproxy._auto_geph_retry_after_drain.update(auto_retry_after_drain)
        tproxy._auto_geph_runtime_failures.clear()
        tproxy._auto_geph_runtime_failures.update(auto_runtime_failures)
        tproxy._auto_geph_candidates.clear()
        tproxy._auto_geph_candidates.update(auto_candidates)
        tproxy._auto_geph_noise_invalidated.clear()
        tproxy._auto_geph_noise_invalidated.update(auto_noise_invalidated)
        tproxy._local_partial_stalls.clear()
        tproxy._local_partial_stalls.update(partial_stalls)
        tproxy._local_zero_payload_failures.clear()
        tproxy._local_zero_payload_failures.update(zero_payload_failures)
        tproxy._auto_geph_one_shot_consumed_at.clear()
        tproxy._auto_geph_one_shot_consumed_at.update(one_shot_consumed_at)
        tproxy._local_payload_idle_failures.clear()
        tproxy._local_payload_idle_failures.update(payload_idle_failures)
        tproxy._active_pending_navigation_relays.clear()
        tproxy._active_pending_navigation_relays.update(active_pending_relays)
        tproxy._pending_navigation_probe_capabilities.clear()
        tproxy._pending_navigation_probe_capabilities.update(
            pending_navigation_probe_capabilities
        )
        tproxy._pending_navigation_probe_host_guards.clear()
        tproxy._pending_navigation_probe_host_guards.update(
            pending_navigation_probe_host_guards
        )
        tproxy._pending_navigation_probe_accepted_guards.clear()
        tproxy._pending_navigation_probe_accepted_guards.update(
            pending_navigation_probe_accepted_guards
        )
        tproxy._pending_navigation_probe_claimed_guards.clear()
        tproxy._pending_navigation_probe_claimed_guards.update(
            pending_navigation_probe_claimed_guards
        )
        tproxy._xbox_dns_candidates.clear()
        tproxy._xbox_dns_candidates.update(xbox_dns_candidates)
        tproxy._xbox_dns_attempts.clear()
        tproxy._xbox_dns_attempts.update(xbox_dns_attempts)
        tproxy._clean_eof_stalls.clear()
        tproxy._clean_eof_stalls.update(clean_eof_stalls)
        tproxy._server_first_closes.clear()
        tproxy._server_first_closes.update(server_first_closes)
        tproxy._server_first_repeat_stages.clear()
        tproxy._server_first_repeat_stages.update(server_first_repeat_stages)
        tproxy._transport_incomplete_confirming.clear()
        tproxy._transport_incomplete_confirming.update(transport_confirming)
        tproxy._transport_incomplete_last_probe.clear()
        tproxy._transport_incomplete_last_probe.update(transport_last_probe)
        tproxy._transport_incomplete_plain_candidates.clear()
        tproxy._transport_incomplete_plain_candidates.update(
            transport_plain_candidates
        )
        tproxy._transport_incomplete_server_first_evidence.clear()
        tproxy._transport_incomplete_server_first_evidence.update(
            transport_server_first_evidence
        )
        tproxy._transport_incomplete_client_first_evidence.clear()
        tproxy._transport_incomplete_client_first_evidence.update(
            transport_client_first_evidence
        )
        tproxy._semantic_plain_confirming.clear()
        tproxy._semantic_plain_confirming.update(semantic_plain_confirming)
        tproxy._semantic_plain_last_probe.clear()
        tproxy._semantic_plain_last_probe.update(semantic_plain_last_probe)
        tproxy._semantic_plain_probe_window.clear()
        tproxy._semantic_plain_probe_window.extend(semantic_plain_probe_window)
        tproxy._local_bypass_resweep_active.clear()
        tproxy._local_bypass_resweep_active.update(local_resweep_active)
        tproxy._local_bypass_resweep_last.clear()
        tproxy._local_bypass_resweep_last.update(local_resweep_last)
        tproxy._auto_geph_last_status.clear()
        tproxy._auto_geph_last_status.update(auto_last_status)
        tproxy._route_policy_remote.clear()
        tproxy._route_policy_remote.update(policy_remote)
        tproxy._strat_scores.clear()
        tproxy._strat_scores.update(strat_scores)
        tproxy._canary_health.clear()
        tproxy._canary_health.update(canary_health)
        tproxy._canary_failure_windows.clear()
        tproxy._canary_failure_windows.update(canary_windows)
        tproxy._canary_state.clear()
        tproxy._canary_state.update(canary_state)
        tproxy._rearm_state.clear()
        tproxy._rearm_state.update(rearm_state)
        tproxy._runtime_rearm_requests.clear()
        tproxy._runtime_rearm_requests.extend(runtime_rearm_requests)
        (
            tproxy._fd_pressure,
            tproxy._fd_pressure_reason,
            tproxy._fd_pressure_at,
        ) = fd_pressure
        tproxy._baseline_guard_state.clear()
        tproxy._baseline_guard_state.update(baseline_guard)


def test_doh_ssl_context_verifies_resolver_certificate():
    ctx = _doh_ssl_context()

    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_local_payload_ssl_context_prefers_certifi(monkeypatch):
    calls = []
    fake_certifi = SimpleNamespace(where=lambda: "/tmp/fake-ca.pem")

    monkeypatch.setitem(sys.modules, "certifi", fake_certifi)
    monkeypatch.setattr(
        tproxy.ssl,
        "create_default_context",
        lambda **kwargs: calls.append(kwargs) or object(),
    )

    tproxy._local_payload_ssl_context()

    assert calls == [{"cafile": "/tmp/fake-ca.pem"}]


def test_geph_payload_probe_uses_one_absolute_deadline(monkeypatch):
    clock = {"now": 0.0}
    timeouts = []

    class FakeSocket:
        def settimeout(self, timeout):
            timeouts.append(timeout)

        def sendall(self, _data):
            return None

        def recv(self, _size):
            return b"payload"

        def close(self):
            return None

    fake_socket = FakeSocket()

    def connect(_host, _port, timeout):
        assert timeout == pytest.approx(4.0)
        clock["now"] = 3.0
        return fake_socket

    def wrap_socket(sock, *, server_hostname):
        assert sock is fake_socket
        assert server_hostname == "ready.example"
        clock["now"] = 3.5
        return fake_socket

    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(tproxy, "_socks5_connect_blocking", connect)
    monkeypatch.setattr(
        tproxy,
        "_local_payload_ssl_context",
        lambda: SimpleNamespace(wrap_socket=wrap_socket),
    )
    monkeypatch.setattr(tproxy, "_local_payload_min_bytes", lambda _spec: 1)

    result = tproxy._geph_payload_probe("ready.example", timeout=4.0)

    assert result == len(b"payload")
    assert timeouts == pytest.approx([1.0, 0.5, 0.5])


def test_doh_request_percent_encodes_host():
    req = _doh_request("good.example\r\nX-Bad: yes", "dns.google")
    first_line = req.split(b"\r\n", 1)[0]

    assert first_line == (
        b"GET /dns-query?name=good.example%0D%0AX-Bad%3A+yes&type=A HTTP/1.1"
    )
    assert b"\r\nX-Bad:" not in req


def test_telegram_proxy_suggests_only_after_repeated_direct_failures(monkeypatch):
    clock = {"now": 1_000.0}
    monkeypatch.setattr(tproxy.time, "time", lambda: clock["now"])
    tproxy._tg_direct_failures.clear()
    tproxy._tg_proxy_suggest_until = 0.0

    tproxy.note_telegram_direct_failure("connect failed")
    tproxy.note_telegram_direct_failure("connect failed")

    assert clock["now"] >= tproxy._tg_proxy_suggest_until

    tproxy.note_telegram_direct_failure("connect failed")

    assert clock["now"] < tproxy._tg_proxy_suggest_until


def test_telegram_direct_success_clears_failure_window():
    tproxy._tg_direct_failures.clear()
    tproxy._tg_proxy_suggest_until = 0.0

    tproxy.note_telegram_direct_failure("connect failed")
    tproxy.note_telegram_direct_success()

    assert list(tproxy._tg_direct_failures) == []


def test_telegram_proxy_acceptance_clears_current_suggestion_once(monkeypatch, tmp_path):
    ack = tmp_path / "accepted"
    ack.write_text("1\n")
    monkeypatch.setattr(tproxy, "TGWS_ACCEPTED_PATH", str(ack))
    tproxy._tg_proxy_ack_seen = 0.0
    tproxy._tg_direct_failures.clear()
    tproxy._tg_direct_failures.append(100.0)
    tproxy._tg_proxy_suggest_until = 200.0

    assert tproxy.consume_telegram_proxy_acceptance()
    assert list(tproxy._tg_direct_failures) == []
    assert tproxy._tg_proxy_suggest_until == 0.0

    tproxy._tg_direct_failures.append(300.0)
    tproxy._tg_proxy_suggest_until = 400.0

    assert not tproxy.consume_telegram_proxy_acceptance()
    assert list(tproxy._tg_direct_failures) == [300.0]
    assert tproxy._tg_proxy_suggest_until == 400.0


def test_tgws_status_reports_ready_duration(monkeypatch):
    clock = {"now": 10_000.0}
    monkeypatch.setattr(tproxy.time, "time", lambda: clock["now"])

    tproxy.set_tgws_state("starting")
    tproxy.set_tgws_state("ready")
    clock["now"] = 10_007.0

    assert tproxy.tgws_status(clock["now"]) == {
        "telegram_proxy": "ready",
        "telegram_proxy_port": tproxy.TGWS_PORT,
        "telegram_proxy_error": "",
        "telegram_proxy_ready_for": 7,
    }


def test_tgws_status_reports_error_without_ready_duration():
    tproxy.set_tgws_state("error", "boom")

    assert tproxy.tgws_status(10_000.0) == {
        "telegram_proxy": "error",
        "telegram_proxy_port": tproxy.TGWS_PORT,
        "telegram_proxy_error": "boom",
        "telegram_proxy_ready_for": 0,
    }


def test_tgws_restart_closes_cancelled_event_loop_tasks():
    loop = asyncio.new_event_loop()
    task = loop.create_task(asyncio.sleep(60))

    tproxy._close_asyncio_loop(loop)

    assert loop.is_closed()
    assert task.cancelled()


def test_frozen_daemon_running_from_install_dir():
    assert tproxy.running_from_install_dir(
        file_path="/usr/local/slipstream/_internal/tproxy.py",
        executable="/usr/local/slipstream/slipstreamd",
        frozen=True,
    )


def test_repo_script_is_not_running_from_install_dir():
    assert not tproxy.running_from_install_dir(
        file_path="/Users/example/slipstream/spike/tproxy.py",
        executable="/usr/bin/python3",
        frozen=False,
    )


def test_system_command_runner_is_bounded_and_strips_malloc_debug_env(monkeypatch):
    observed = {}

    def timeout_run(args, **kwargs):
        observed.update(kwargs)
        raise tproxy.subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(tproxy.subprocess, "run", timeout_run)

    result = tproxy._run("scutil", "--proxy")

    assert result.returncode == 124
    assert "timed out after 5s" in result.stderr
    assert observed["timeout"] == tproxy.RUN_COMMAND_TIMEOUT_SECONDS
    assert not any(name.startswith("Malloc") for name in observed["env"])


def test_copy_file_resilient_skips_identical_and_replaces_changed_file(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.write_text("one")
    dst.write_text("one")
    dst.chmod(0o600)

    assert tproxy._copy_file_resilient(str(src), str(dst), mode=0o644) == "unchanged"
    assert dst.read_text() == "one"
    assert dst.stat().st_mode & 0o777 == 0o644

    src.write_text("two")

    assert tproxy._copy_file_resilient(str(src), str(dst), mode=0o600) == "copied"
    assert dst.read_text() == "two"
    assert dst.stat().st_mode & 0o777 == 0o600


def test_replace_tree_resilient_replaces_tree_without_stale_files(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "fresh.txt").write_text("fresh")
    (dst / "stale.txt").write_text("stale")

    assert tproxy._replace_tree_resilient(str(src), str(dst)) == "replaced"
    assert (dst / "fresh.txt").read_text() == "fresh"
    assert not (dst / "stale.txt").exists()


def test_replace_tree_resilient_keeps_existing_tree_when_copy_fails(tmp_path, monkeypatch):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "fresh.txt").write_text("fresh")
    (dst / "current.txt").write_text("current")

    def fail_copytree(_src, _dst):
        raise OSError("copy failed")

    monkeypatch.setattr(tproxy.shutil, "copytree", fail_copytree)

    with pytest.raises(OSError):
        tproxy._replace_tree_resilient(str(src), str(dst), attempts=1)

    assert (dst / "current.txt").read_text() == "current"
    assert not (dst / "fresh.txt").exists()


_SCRIPT_RUNTIME_FIXTURE = {
    "tproxy.py": "import connection_probe\nimport geph_backend\n",
    "requirements-runtime.txt": "certifi==2026.6.17 --hash=sha256:fixture\n",
    "address_attempts.py": "VALUE = 1\n",
    "connection_probe.py": "VALUE = 2\n",
    "connection_race.py": "VALUE = 3\n",
    "connection_race_io.py": "VALUE = 4\n",
    "geph_backend.py": "VALUE = 5\n",
    "http_response_completion.py": "VALUE = 20\n",
    "http2_response_probe.py": "VALUE = 21\n",
    "install_guard.py": "VALUE = 6\n",
    "pending_navigation_probe_runtime.py": "VALUE = 22\n",
    "pf_adapter.py": "VALUE = 7\n",
    "primes.py": "VALUE = 8\n",
    "route_circuit.py": "VALUE = 9\n",
    "route_circuit_registry.py": "VALUE = 10\n",
    "route_policy_activation.py": "VALUE = 11\n",
    "route_policy_activation_adapter.py": "VALUE = 12\n",
    "route_policy_bundle.py": "VALUE = 13\n",
    "route_policy_manifest.py": "VALUE = 14\n",
    "routing_policy.py": "VALUE = 15\n",
    "routing_recovery.py": "VALUE = 16\n",
    "semantic_route_signal.py": "VALUE = 17\n",
    "semantic_route_signal_runtime.py": "VALUE = 18\n",
    "xbox_dns.py": "VALUE = 19\n",
}


def _write_script_runtime_fixture(source, *, missing=()):
    for name, content in _SCRIPT_RUNTIME_FIXTURE.items():
        if name not in missing:
            (source / name).write_text(content)


def test_copy_script_runtime_includes_local_modules(tmp_path):
    source = tmp_path / "source"
    install = tmp_path / "install"
    source.mkdir()
    _write_script_runtime_fixture(source)

    tproxy._copy_script_runtime(source / "tproxy.py", install)

    for name, content in _SCRIPT_RUNTIME_FIXTURE.items():
        assert (install / name).read_text() == content


def test_script_runtime_payload_covers_transitive_local_imports():
    source_dir = Path(tproxy.__file__).parent
    payload = tproxy._script_runtime_payload(tproxy.__file__)
    payload_names = {name for _source, name in payload}

    for source, _name in payload:
        if Path(source).suffix != ".py":
            continue
        tree = ast.parse(Path(source).read_text())
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.partition(".")[0] for alias in node.names
                )
            elif (
                isinstance(node, ast.ImportFrom)
                and node.level == 0
                and node.module
            ):
                imported_roots.add(node.module.partition(".")[0])
        local_dependencies = {
            f"{module}.py"
            for module in imported_roots
            if (source_dir / f"{module}.py").is_file()
        }
        assert local_dependencies <= payload_names


def test_copy_script_runtime_fails_before_partial_install(tmp_path):
    source = tmp_path / "source"
    install = tmp_path / "install"
    source.mkdir()
    _write_script_runtime_fixture(source, missing={"primes.py"})

    with pytest.raises(FileNotFoundError, match="primes.py"):
        tproxy._copy_script_runtime(source / "tproxy.py", install)

    assert not install.exists()


def test_copy_script_runtime_requires_recovery_module_before_install(tmp_path):
    source = tmp_path / "source"
    install = tmp_path / "install"
    source.mkdir()
    _write_script_runtime_fixture(source, missing={"routing_recovery.py"})

    with pytest.raises(FileNotFoundError, match="routing_recovery.py"):
        tproxy._copy_script_runtime(source / "tproxy.py", install)

    assert not install.exists()


def test_copy_script_runtime_requires_policy_module_before_install(tmp_path):
    source = tmp_path / "source"
    install = tmp_path / "install"
    source.mkdir()
    _write_script_runtime_fixture(source, missing={"routing_policy.py"})

    with pytest.raises(FileNotFoundError, match="routing_policy.py"):
        tproxy._copy_script_runtime(source / "tproxy.py", install)

    assert not install.exists()


def test_copy_script_runtime_requires_semantic_signal_runtime_before_install(
    tmp_path,
):
    source = tmp_path / "source"
    install = tmp_path / "install"
    source.mkdir()
    _write_script_runtime_fixture(
        source,
        missing={"semantic_route_signal_runtime.py"},
    )

    with pytest.raises(FileNotFoundError, match="semantic_route_signal_runtime.py"):
        tproxy._copy_script_runtime(source / "tproxy.py", install)

    assert not install.exists()


def test_copy_script_runtime_requires_pending_navigation_probe_runtime(
    tmp_path,
):
    source = tmp_path / "source"
    install = tmp_path / "install"
    source.mkdir()
    _write_script_runtime_fixture(
        source,
        missing={"pending_navigation_probe_runtime.py"},
    )

    with pytest.raises(
        FileNotFoundError,
        match="pending_navigation_probe_runtime.py",
    ):
        tproxy._copy_script_runtime(source / "tproxy.py", install)

    assert not install.exists()


def test_copy_script_runtime_requires_http_completion_parser_before_install(
    tmp_path,
):
    source = tmp_path / "source"
    install = tmp_path / "install"
    source.mkdir()
    _write_script_runtime_fixture(
        source,
        missing={"http_response_completion.py"},
    )

    with pytest.raises(FileNotFoundError, match="http_response_completion.py"):
        tproxy._copy_script_runtime(source / "tproxy.py", install)

    assert not install.exists()


def test_copy_script_runtime_requires_pf_adapter_before_install(tmp_path):
    source = tmp_path / "source"
    install = tmp_path / "install"
    source.mkdir()
    _write_script_runtime_fixture(source, missing={"pf_adapter.py"})

    with pytest.raises(FileNotFoundError, match="pf_adapter.py"):
        tproxy._copy_script_runtime(source / "tproxy.py", install)

    assert not install.exists()


def test_copy_script_runtime_requires_geph_backend_before_install(tmp_path):
    source = tmp_path / "source"
    install = tmp_path / "install"
    source.mkdir()
    _write_script_runtime_fixture(source, missing={"geph_backend.py"})

    with pytest.raises(FileNotFoundError, match="geph_backend.py"):
        tproxy._copy_script_runtime(source / "tproxy.py", install)

    assert not install.exists()


@pytest.mark.parametrize(
    "missing",
    (
        "address_attempts.py",
        "connection_probe.py",
        "connection_race.py",
        "connection_race_io.py",
        "requirements-runtime.txt",
        "route_circuit.py",
        "route_circuit_registry.py",
        "route_policy_manifest.py",
    ),
)
def test_copy_script_runtime_requires_complete_payload_before_install(tmp_path, missing):
    source = tmp_path / "source"
    install = tmp_path / "install"
    source.mkdir()
    _write_script_runtime_fixture(source, missing={missing})

    with pytest.raises(FileNotFoundError, match=missing):
        tproxy._copy_script_runtime(source / "tproxy.py", install)

    assert not install.exists()


def test_uninstall_removes_runtime_artifacts(monkeypatch, tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    plist = tmp_path / "daemon.plist"
    status = tmp_path / "status"
    tgws_link = tmp_path / "tgws.link"
    strategy = tmp_path / "strategies.json"
    auto_geph = tmp_path / "auto-geph.json"
    for path in (plist, status, tgws_link, strategy, auto_geph):
        path.write_text("state")

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tgws_link))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(strategy))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(auto_geph))
    commands = []

    def fake_run(*args):
        commands.append(args)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "_bootout_installed_launchd_job", lambda: True)
    monkeypatch.setattr(tproxy, "_pf_flush", lambda: SimpleNamespace(returncode=0))
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: None,
    )
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda: None)
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)

    assert tproxy.do_uninstall()

    assert not install.exists()
    assert not plist.exists()
    assert not status.exists()
    assert not tgws_link.exists()
    assert not strategy.exists()
    assert not auto_geph.exists()
    assert (
        "/bin/launchctl",
        "disable",
        "system/dev.slipstream.tproxy",
    ) in commands


def test_owned_listener_pids_reject_unrelated_process(monkeypatch, tmp_path):
    install = tmp_path / "install"
    owned = install / "slipstreamd"
    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy.sys, "executable", "/bundle/slipstreamd")
    monkeypatch.setattr(tproxy, "_listener_pids", lambda _port: [101, 202])
    monkeypatch.setattr(
        tproxy,
        "_process_command_for_pid",
        lambda pid: (
            f"{owned} --port 1080"
            if pid == 101
            else "/usr/bin/python3 /tmp/unrelated.py"
        ),
    )

    assert tproxy._owned_listener_pids(1080) == [101]


def test_uninstall_stops_owned_listener_when_status_is_missing(monkeypatch, tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    plist = tmp_path / "daemon.plist"
    plist.write_text("plist")
    stopped = []

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "missing-status.json"))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tmp_path / "tgws.link"))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(tmp_path / "strategies.json"))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(tmp_path / "auto-geph.json"))
    monkeypatch.setattr(
        tproxy,
        "_run",
        lambda *_args: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(tproxy, "_bootout_installed_launchd_job", lambda: True)
    monkeypatch.setattr(tproxy, "_owned_listener_pids", lambda _port: [4242])
    monkeypatch.setattr(tproxy, "_process_command_for_pid", lambda _pid: "owned")
    monkeypatch.setattr(tproxy, "_installed_daemon_command_owned", lambda _cmd: True)
    monkeypatch.setattr(
        tproxy,
        "_stop_owned_daemon_pid",
        lambda pid: stopped.append(pid) or True,
    )
    monkeypatch.setattr(tproxy, "_pf_flush", lambda: SimpleNamespace(returncode=0))
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: None,
    )
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda: None)
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)

    assert tproxy.do_uninstall()
    assert stopped == [4242]


def test_uninstall_reports_owned_daemon_that_did_not_stop(monkeypatch, tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    plist = tmp_path / "daemon.plist"
    plist.write_text("plist")

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "missing-status.json"))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tmp_path / "tgws.link"))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(tmp_path / "strategies.json"))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(tmp_path / "auto-geph.json"))
    monkeypatch.setattr(
        tproxy,
        "_run",
        lambda *_args: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(tproxy, "_bootout_installed_launchd_job", lambda: True)
    stopped = []
    monkeypatch.setattr(tproxy, "_owned_listener_pids", lambda _port: [4242, 4343])
    monkeypatch.setattr(tproxy, "_process_command_for_pid", lambda _pid: "owned")
    monkeypatch.setattr(tproxy, "_installed_daemon_command_owned", lambda _cmd: True)
    monkeypatch.setattr(
        tproxy,
        "_stop_owned_daemon_pid",
        lambda pid: stopped.append(pid) or pid != 4242,
    )
    monkeypatch.setattr(tproxy, "_pf_flush", lambda: SimpleNamespace(returncode=0))
    monkeypatch.setattr(tproxy, "_pf_release_enable_token", lambda: None)
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)

    assert not tproxy.do_uninstall()
    assert stopped == [4242, 4343]


def test_uninstall_reports_incomplete_pf_token_release(monkeypatch, tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    plist = tmp_path / "daemon.plist"
    plist.write_text("plist")

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status.json"))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tmp_path / "tgws.link"))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(tmp_path / "strategies.json"))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(tmp_path / "auto-geph.json"))
    monkeypatch.setattr(
        tproxy,
        "_run",
        lambda *_args: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(tproxy, "_owned_listener_pids", lambda _port: [])
    monkeypatch.setattr(tproxy, "_pf_flush", lambda: SimpleNamespace(returncode=0))
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: SimpleNamespace(returncode=1),
    )
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)

    assert not tproxy.do_uninstall()


def test_uninstall_clears_pf_and_boots_out_before_stopping_survivor(
    monkeypatch, tmp_path
):
    install = tmp_path / "install"
    install.mkdir()
    plist = tmp_path / "daemon.plist"
    plist.write_text("plist")
    events = []

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status.json"))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tmp_path / "tgws.link"))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(tmp_path / "strategies.json"))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(tmp_path / "auto-geph.json"))
    monkeypatch.setattr(
        tproxy,
        "_daemon_status_record",
        lambda: {"state": "active", "pid": 4242},
    )

    booted_out = {"value": False}

    def fake_run(*args):
        if args[1:2] == ("disable",):
            events.append("disable")
        elif args[1:2] == ("bootout",):
            events.append("bootout")
            booted_out["value"] = True
        elif args[1:2] == ("print",) and booted_out["value"]:
            events.append("print")
            return SimpleNamespace(
                returncode=113,
                stdout="",
                stderr=(
                    'Could not find service "dev.slipstream.tproxy" '
                    "in domain for system"
                ),
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(
        tproxy,
        "_flush_private_pf_with_retry",
        lambda **_kwargs: events.append("pf_cleared") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_restore_pf_loopback_skip",
        lambda: events.append("skip_restored") or True,
    )
    monkeypatch.setattr(tproxy, "_owned_listener_pids", lambda _port: [4242])
    monkeypatch.setattr(tproxy, "_process_command_for_pid", lambda _pid: "owned")
    monkeypatch.setattr(tproxy, "_installed_daemon_command_owned", lambda _cmd: True)
    monkeypatch.setattr(
        tproxy,
        "_stop_owned_daemon_pid",
        lambda _pid: events.append("stopped") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: events.append("token_released") or None,
    )
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)

    assert tproxy.do_uninstall()
    assert events == [
        "disable",
        "pf_cleared",
        "skip_restored",
        "bootout",
        "print",
        "stopped",
        "pf_cleared",
        "skip_restored",
        "token_released",
    ]


def test_uninstall_never_signals_daemon_while_launchd_remains_loaded(
    monkeypatch, tmp_path
):
    install = tmp_path / "install"
    install.mkdir()
    plist = tmp_path / "daemon.plist"
    plist.write_text("plist")
    events = []

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status.json"))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tmp_path / "tgws.link"))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(tmp_path / "strategies.json"))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(tmp_path / "auto-geph.json"))
    monkeypatch.setattr(
        tproxy,
        "_daemon_status_record",
        lambda: {"state": "active", "pid": 4242},
    )

    def fake_run(*args):
        action = args[1] if len(args) > 1 else ""
        if action == "disable":
            events.append("disable")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if action == "bootout":
            events.append("bootout")
            return SimpleNamespace(returncode=1, stdout="", stderr="busy")
        if action == "print":
            events.append("print")
            return SimpleNamespace(returncode=0, stdout="loaded", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(
        tproxy,
        "_flush_private_pf_with_retry",
        lambda **_kwargs: events.append("pf_cleared") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_restore_pf_loopback_skip",
        lambda: events.append("skip_restored") or True,
    )
    monkeypatch.setattr(tproxy, "_owned_listener_pids", lambda _port: [4242])
    monkeypatch.setattr(tproxy, "_process_command_for_pid", lambda _pid: "owned")
    monkeypatch.setattr(tproxy, "_installed_daemon_command_owned", lambda _cmd: True)
    monkeypatch.setattr(
        tproxy,
        "_stop_owned_daemon_pid",
        lambda _pid: events.append("stopped") or True,
    )

    assert not tproxy.do_uninstall()
    assert events == [
        "disable",
        "pf_cleared",
        "skip_restored",
        "bootout",
        "print",
        "bootout",
        "print",
        "pf_cleared",
        "skip_restored",
        "print",
    ]


def test_uninstall_falls_back_to_plist_bootout_for_loaded_service(
    monkeypatch, tmp_path
):
    install = tmp_path / "install"
    install.mkdir()
    plist = tmp_path / "daemon.plist"
    plist.write_text("plist")
    loaded = {"value": True}
    events = []

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status.json"))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tmp_path / "tgws.link"))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(tmp_path / "strategies.json"))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(tmp_path / "auto-geph.json"))
    monkeypatch.setattr(tproxy, "_daemon_status_record", lambda: {})

    def fake_run(*args):
        action = args[1] if len(args) > 1 else ""
        if action == "disable":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if action == "bootout":
            events.append(args[2:])
            if args[2:] == ("system", str(plist)):
                loaded["value"] = False
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="busy")
        if action == "print":
            if loaded["value"]:
                return SimpleNamespace(returncode=0, stdout="loaded", stderr="")
            return SimpleNamespace(
                returncode=113,
                stdout="",
                stderr=(
                    'Could not find service "dev.slipstream.tproxy" '
                    "in domain for system"
                ),
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "_flush_private_pf_with_retry", lambda **_kwargs: True)
    monkeypatch.setattr(tproxy, "_restore_pf_loopback_skip", lambda: True)
    monkeypatch.setattr(tproxy, "_owned_listener_pids", lambda _port: [])
    monkeypatch.setattr(tproxy, "_pf_release_enable_token", lambda: None)
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)

    assert tproxy.do_uninstall()
    assert events == [
        ("system/dev.slipstream.tproxy",),
        ("system", str(plist)),
    ]


def test_launchd_absence_requires_exact_not_found_evidence():
    missing = SimpleNamespace(
        returncode=113,
        stdout="",
        stderr='Could not find service "dev.slipstream.tproxy" in domain for system',
    )
    indeterminate = SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="Operation not permitted",
    )
    loaded = SimpleNamespace(returncode=0, stdout="loaded", stderr="")

    assert tproxy._launchd_job_absent(missing)
    assert not tproxy._launchd_job_absent(indeterminate)
    assert not tproxy._launchd_job_absent(loaded)


def test_uninstall_accepts_daemon_exit_caused_by_bootout(monkeypatch, tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    plist = tmp_path / "daemon.plist"
    plist.write_text("plist")
    alive = {"value": True}

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status.json"))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tmp_path / "tgws.link"))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(tmp_path / "strategies.json"))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(tmp_path / "auto-geph.json"))
    monkeypatch.setattr(
        tproxy,
        "_daemon_status_record",
        lambda: {"state": "active", "pid": 4242},
    )

    def fake_run(*args):
        if args[1:2] == ("bootout",):
            alive["value"] = False
        if args[1:2] == ("print",) and not alive["value"]:
            return SimpleNamespace(
                returncode=113,
                stdout="",
                stderr=(
                    'Could not find service "dev.slipstream.tproxy" '
                    "in domain for system"
                ),
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(
        tproxy,
        "_flush_private_pf_with_retry",
        lambda **_kwargs: True,
    )
    monkeypatch.setattr(
        tproxy,
        "_owned_listener_pids",
        lambda _port: [4242] if alive["value"] else [],
    )
    monkeypatch.setattr(
        tproxy,
        "_process_command_for_pid",
        lambda _pid: "owned" if alive["value"] else None,
    )
    monkeypatch.setattr(tproxy, "_installed_daemon_command_owned", lambda cmd: bool(cmd))
    monkeypatch.setattr(
        tproxy,
        "_stop_owned_daemon_pid",
        lambda _pid: pytest.fail("bootout already stopped the daemon"),
    )
    monkeypatch.setattr(tproxy, "_pf_release_enable_token", lambda: None)
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)

    assert tproxy.do_uninstall()


def test_owned_network_recovery_restores_skip_before_releasing_token(
    monkeypatch,
    tmp_path,
):
    events = []
    status = tmp_path / "status.json"
    status.write_text("{}")
    (tmp_path / "status.json.tmp").write_text("{}")
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status))
    monkeypatch.setattr(
        tproxy,
        "_flush_private_pf_with_retry",
        lambda **_kwargs: events.append("anchor-cleared") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_restore_pf_loopback_skip",
        lambda: events.append("skip-restored") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: events.append("token-released") or SimpleNamespace(returncode=0),
    )

    assert tproxy.recover_owned_network_state()
    assert events == ["anchor-cleared", "skip-restored", "token-released"]
    assert not status.exists()
    assert not (tmp_path / "status.json.tmp").exists()


def test_install_bootstrap_failure_rolls_back_and_disables_label(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "slipstreamd"
    executable.write_text("binary")
    executable.chmod(0o755)
    install = tmp_path / "runtime" / "slipstream"
    plist = tmp_path / "daemon.plist"
    status = tmp_path / "status.json"
    commands = []

    def fake_run(*args):
        commands.append(args)
        if args[:3] == ("/bin/launchctl", "bootstrap", "system"):
            return SimpleNamespace(returncode=5, stdout="", stderr="bootstrap refused")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy.sys, "frozen", True, raising=False)
    monkeypatch.setattr(tproxy.sys, "executable", str(executable))
    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tmp_path / "tgws.link"))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(tmp_path / "strategies.json"))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(tmp_path / "auto-geph.json"))
    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "_bootout_installed_launchd_job", lambda: True)
    monkeypatch.setattr(tproxy, "ensure_private_log_files", lambda: None)
    monkeypatch.setattr(tproxy, "_harden_installed_identity", lambda *_args: None)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)
    monkeypatch.setattr(tproxy, "_pf_flush", lambda: SimpleNamespace(returncode=0))
    monkeypatch.setattr(tproxy, "_pf_release_enable_token", lambda: None)
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda: None)
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)

    assert not tproxy.do_install(1080)

    assert not install.exists()
    assert not plist.exists()
    assert (
        "/bin/launchctl",
        "disable",
        "system/dev.slipstream.tproxy",
    ) in commands
    assert not any(command[1:3] == ("load", "-w") for command in commands)


def test_reinstall_quiesces_owned_daemon_before_replacing_runtime(
    monkeypatch, tmp_path
):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "slipstreamd"
    executable.write_text("new binary")
    executable.chmod(0o755)
    install = tmp_path / "runtime" / "slipstream"
    install.mkdir(parents=True)
    (install / "old").write_text("old runtime")
    plist = tmp_path / "daemon.plist"
    plist.write_text("old plist")
    events = []
    original_replace = tproxy._replace_tree_resilient

    def quiesce(port, remove_runtime=True):
        events.append(("quiesce", port, remove_runtime))
        return True

    def replace(src, dst, *args, **kwargs):
        events.append(("replace", src, dst))
        return original_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(tproxy.sys, "frozen", True, raising=False)
    monkeypatch.setattr(tproxy.sys, "executable", str(executable))
    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status.json"))
    monkeypatch.setattr(tproxy, "_disable_and_cleanup_install", quiesce)
    monkeypatch.setattr(tproxy, "_replace_tree_resilient", replace)
    monkeypatch.setattr(tproxy, "ensure_private_log_files", lambda: None)
    monkeypatch.setattr(tproxy, "_harden_installed_identity", lambda *_args: None)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)
    monkeypatch.setattr(
        tproxy,
        "_run",
        lambda *_args: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(tproxy, "_wait_for_installed_daemon", lambda *_args: True)
    monkeypatch.setattr(tproxy, "_write_install_attestation", lambda *_args: None)

    assert tproxy.do_install(1080)
    assert events[:2] == [
        ("quiesce", 1080, False),
        ("replace", str(bundle), str(install)),
    ]


def test_install_never_replaces_runtime_when_quiescence_is_unproven(
    monkeypatch, tmp_path
):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "slipstreamd"
    executable.write_text("new binary")
    executable.chmod(0o755)
    install = tmp_path / "runtime" / "slipstream"
    install.mkdir(parents=True)
    marker = install / "old"
    marker.write_text("old runtime")
    calls = []

    def cleanup(_port, remove_runtime=True):
        calls.append(remove_runtime)
        return False

    monkeypatch.setattr(tproxy.sys, "frozen", True, raising=False)
    monkeypatch.setattr(tproxy.sys, "executable", str(executable))
    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status.json"))
    monkeypatch.setattr(tproxy, "_disable_and_cleanup_install", cleanup)
    monkeypatch.setattr(tproxy, "ensure_private_log_files", lambda: None)
    monkeypatch.setattr(
        tproxy,
        "_replace_tree_resilient",
        lambda *_args, **_kwargs: pytest.fail(
            "runtime replacement requires proven launchd quiescence"
        ),
    )

    assert not tproxy.do_install(1080)
    assert calls == [False, True]
    assert marker.read_text() == "old runtime"


def test_reinstall_quiescence_preserves_runtime_but_removes_stale_status(
    monkeypatch, tmp_path
):
    install = tmp_path / "install"
    install.mkdir()
    plist = tmp_path / "daemon.plist"
    plist.write_text("plist")
    status = tmp_path / "status.json"
    status.write_text("{}")
    events = []

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status))
    monkeypatch.setattr(
        tproxy,
        "_daemon_status_record",
        lambda: {"state": "active", "pid": 4242},
    )

    def fake_run(*args):
        events.append(args[1])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "_bootout_installed_launchd_job", lambda: True)
    monkeypatch.setattr(
        tproxy,
        "_flush_private_pf_with_retry",
        lambda **_kwargs: events.append("pf_cleared") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_restore_pf_loopback_skip",
        lambda: events.append("skip_restored") or True,
    )
    monkeypatch.setattr(tproxy, "_owned_listener_pids", lambda _port: [4242])
    monkeypatch.setattr(tproxy, "_process_command_for_pid", lambda _pid: "owned")
    monkeypatch.setattr(tproxy, "_installed_daemon_command_owned", lambda _cmd: True)
    monkeypatch.setattr(
        tproxy,
        "_stop_owned_daemon_pid",
        lambda _pid: events.append("stopped") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: events.append("token_released") or None,
    )
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)

    assert tproxy._disable_and_cleanup_install(1080, remove_runtime=False)
    assert install.exists()
    assert plist.exists()
    assert not status.exists()
    assert events == [
        "disable",
        "pf_cleared",
        "skip_restored",
        "stopped",
        "pf_cleared",
        "skip_restored",
        "token_released",
    ]


def test_incomplete_baseline_rollback_preserves_live_runtime_when_pf_will_not_clear(
    monkeypatch, tmp_path
):
    install = tmp_path / "runtime" / "slipstream"
    install.mkdir(parents=True)
    plist = tmp_path / "daemon.plist"
    plist.write_text("plist")
    commands = []

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(
        tproxy,
        "_daemon_status_record",
        lambda: {"state": "active", "pid": 4242},
    )
    monkeypatch.setattr(
        tproxy,
        "_daemon_recovery_record",
        lambda: {"reason": tproxy.BASELINE_GUARD_ROLLBACK_REASON},
    )
    monkeypatch.setattr(
        tproxy,
        "_run",
        lambda *args: (
            commands.append(args)
            or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_flush_private_pf_with_retry",
        lambda **_kwargs: False,
    )
    monkeypatch.setattr(
        tproxy,
        "_owned_listener_pids",
        lambda _port: pytest.fail("listener must remain alive"),
    )

    assert not tproxy._disable_and_cleanup_install(1080)
    assert install.exists()
    assert plist.exists()
    assert not any(command[1:2] == ("bootout",) for command in commands)


def test_force_stop_refuses_to_kill_listener_until_private_pf_is_clear(monkeypatch):
    signals = []
    monkeypatch.setattr(
        tproxy,
        "_process_command_for_pid",
        lambda _pid: "/usr/local/slipstream/slipstreamd --port 1080",
    )
    monkeypatch.setattr(tproxy, "_installed_daemon_command_owned", lambda _cmd: True)
    monkeypatch.setattr(
        tproxy.os,
        "kill",
        lambda _pid, sig: signals.append(sig),
    )
    monkeypatch.setattr(
        tproxy,
        "_flush_private_pf_with_retry",
        lambda **_kwargs: False,
    )

    assert not tproxy._stop_owned_daemon_pid(4242, timeout=0.0)
    assert signals == [signal.SIGTERM]


def test_install_reports_success_only_after_health_gate(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "slipstreamd"
    executable.write_text("binary")
    executable.chmod(0o755)
    install = tmp_path / "runtime" / "slipstream"
    plist = tmp_path / "daemon.plist"
    commands = []

    def fake_run(*args):
        commands.append(args)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy.sys, "frozen", True, raising=False)
    monkeypatch.setattr(tproxy.sys, "executable", str(executable))
    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status.json"))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tmp_path / "tgws.link"))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(tmp_path / "strategies.json"))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(tmp_path / "auto-geph.json"))
    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "_bootout_installed_launchd_job", lambda: True)
    monkeypatch.setattr(tproxy, "ensure_private_log_files", lambda: None)
    monkeypatch.setattr(tproxy, "_harden_installed_identity", lambda *_args: None)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "_wait_for_installed_daemon", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "_write_install_attestation", lambda *_args: None)

    assert tproxy.do_install(1080)

    assert install.exists()
    assert plist.exists()
    assert (
        "/bin/launchctl",
        "enable",
        "system/dev.slipstream.tproxy",
    ) in commands
    assert (
        "/bin/launchctl",
        "bootstrap",
        "system",
        str(plist),
    ) in commands


def test_install_attestation_is_bounded_and_hash_bound(monkeypatch, tmp_path):
    installed = tmp_path / "slipstreamd"
    installed.write_bytes(b"qualified daemon")
    installed.chmod(0o700)
    evidence_dir = tmp_path / "attestation"
    evidence = evidence_dir / "install-attestation.json"
    source_sha256 = hashlib.sha256(installed.read_bytes()).hexdigest()
    monkeypatch.setattr(
        tproxy,
        "_installed_daemon_readiness_snapshot",
        lambda _port: (
            True,
            "ready",
            {"state": "active", "pid": 4242},
            True,
        ),
    )

    record = tproxy._write_install_attestation(
        str(installed),
        source_sha256,
        0o700,
        1080,
        evidence_path=str(evidence),
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
    )

    assert record["daemon"]["sha256"] == source_sha256
    assert record["launchd"] == {
        "label": "dev.slipstream.tproxy",
        "pid": 4242,
    }
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o644
    assert json.loads(evidence.read_text()) == record
    witness = Path(record["witness"]["path"])
    assert witness == Path(f"{evidence}.daemon")
    assert witness.stat().st_ino == installed.stat().st_ino
    assert witness.stat().st_nlink >= 2

    installed.write_bytes(b"tampered daemon")
    with pytest.raises(RuntimeError, match="does not match"):
        tproxy._install_attestation_record(
            str(installed),
            source_sha256,
            0o700,
            1080,
            witness_path=str(witness),
            expected_uid=os.getuid(),
        )


def test_install_attestation_retries_a_dormant_to_active_transition(
    monkeypatch, tmp_path
):
    installed = tmp_path / "slipstreamd"
    installed.write_bytes(b"qualified daemon")
    installed.chmod(0o700)
    source_sha256 = hashlib.sha256(installed.read_bytes()).hexdigest()
    witness = tmp_path / "attestation-witness"
    os.link(installed, witness)
    snapshots = iter(
        (
            (False, "PF state does not match daemon state", None, True),
            (
                True,
                "ready",
                {"state": "active", "pid": 4242},
                True,
            ),
        )
    )
    monkeypatch.setattr(
        tproxy,
        "_installed_daemon_readiness_snapshot",
        lambda _port: next(snapshots),
    )
    monkeypatch.setattr(tproxy.time, "sleep", lambda _seconds: None)

    record = tproxy._install_attestation_record(
        str(installed),
        source_sha256,
        0o700,
        1080,
        witness_path=str(witness),
        expected_uid=os.getuid(),
    )

    assert record["state"] == "active"
    assert record["pf_active"] is True
    assert record["launchd"]["pid"] == 4242


def test_install_attestation_path_persists_across_reboot() -> None:
    assert not tproxy.INSTALL_ATTESTATION_DIR.startswith("/var/run/")
    assert not tproxy.INSTALL_ATTESTATION_DIR.startswith("/private/var/run/")
    assert tproxy.INSTALL_ATTESTATION_DIR.startswith(
        "/Library/Application Support/"
    )


def test_install_attestation_rejects_symlink_parent(tmp_path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    parent = tmp_path / "attestation"
    parent.symlink_to(target, target_is_directory=True)

    with pytest.raises(RuntimeError, match="not a directory"):
        tproxy._ensure_install_attestation_directory(
            str(parent),
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )


def test_install_attestation_cleanup_removes_witness_and_empty_parent(
    monkeypatch, tmp_path
) -> None:
    parent = tmp_path / "attestation"
    evidence = parent / "install-attestation.json"
    parent.mkdir()
    evidence.write_text("{}")
    Path(f"{evidence}.daemon").write_text("witness")
    Path(f"{evidence}.tmp.42").write_text("temporary")
    monkeypatch.setattr(tproxy, "INSTALL_ATTESTATION_PATH", str(evidence))

    assert tproxy._remove_install_attestation_artifacts()
    assert not parent.exists()


def test_install_attestation_failure_rolls_back_daemon_free(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "slipstreamd"
    executable.write_bytes(b"qualified daemon")
    executable.chmod(0o755)
    install = tmp_path / "runtime" / "slipstream"
    plist = tmp_path / "daemon.plist"
    cleanup_calls = []

    def cleanup(_port, remove_runtime=True):
        cleanup_calls.append(remove_runtime)
        if remove_runtime:
            shutil.rmtree(install, ignore_errors=True)
            plist.unlink(missing_ok=True)
        return True

    monkeypatch.setattr(tproxy.sys, "frozen", True, raising=False)
    monkeypatch.setattr(tproxy.sys, "executable", str(executable))
    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "_disable_and_cleanup_install", cleanup)
    monkeypatch.setattr(tproxy, "ensure_private_log_files", lambda: None)
    monkeypatch.setattr(
        tproxy,
        "_harden_installed_identity",
        lambda path, mode: os.chmod(path, mode),
    )
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)
    monkeypatch.setattr(
        tproxy,
        "_run",
        lambda *_args: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(tproxy, "_wait_for_installed_daemon", lambda *_args: True)
    monkeypatch.setattr(
        tproxy,
        "_write_install_attestation",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("attestation rejected")),
    )

    assert not tproxy.do_install(1080)
    assert cleanup_calls == [False, True]
    assert not install.exists()
    assert not plist.exists()


def test_installed_daemon_command_accepts_real_venv_interpreter(
    monkeypatch, tmp_path
):
    install = tmp_path / "runtime" / "slipstream"
    venv_bin = install / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    framework = tmp_path / "Python.framework" / "Versions" / "3.13"
    launcher = framework / "bin" / "python3.13"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("binary")
    process_python = (
        framework / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
    )
    process_python.parent.mkdir(parents=True)
    process_python.write_text("binary")
    venv_python = venv_bin / "python3"
    venv_python.symlink_to(launcher)
    script = install / "tproxy.py"
    script.write_text("pass")

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))

    assert tproxy._installed_daemon_command_owned(
        f"{process_python} {script} run --port 1080"
    )
    assert not tproxy._installed_daemon_command_owned(
        f"{tmp_path / 'unknown-python'} {script} run --port 1080"
    )


def test_scapy_mac_noise_filter_only_drops_broadcast_warning():
    filt = tproxy._ScapyMacNoiseFilter()
    noisy = logging.LogRecord(
        "scapy.runtime", logging.WARNING, __file__, 1,
        "MAC address to reach destination not found. Using broadcast.",
        (), None,
    )
    useful = logging.LogRecord(
        "scapy.runtime", logging.WARNING, __file__, 1,
        "other warning",
        (), None,
    )

    assert not filt.filter(noisy)
    assert filt.filter(useful)


def test_default_iface_tracks_interface(monkeypatch):
    class Result:
        stdout = """
           route to: default
        destination: default
            gateway: 192.168.1.1
          interface: en0
        """

    monkeypatch.setattr(tproxy, "_run", lambda *args: Result())

    assert tproxy.default_iface() == "en0"


def test_write_status_includes_core_runtime_state(monkeypatch, tmp_path):
    status_path = tmp_path / "slipstream.status"
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))

    def fake_run(*args):
        if args == ("scutil", "--proxy"):
            return type("Result", (), {"returncode": 0, "stdout": "HTTPEnable : 0\n", "stderr": ""})()
        if args == ("scutil", "--dns"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "nameserver[0] : 111.88.96.50\nnameserver[1] : 111.88.96.51\n",
                "stderr": "",
            })()
        return type("Result", (), {"returncode": 1, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(tproxy, "_run", fake_run)
    tproxy._strat_cache.clear()
    tproxy._strat_cache["example.com"] = "split64+fake"
    tproxy._record_strategy_result("discord.com", "split64+fake", True, now=100.0)
    tproxy.route_health_event(
        tproxy.SERVICE_DISCORD,
        tproxy.ROUTE_LOCAL_BYPASS,
        "discord.com",
        now=100.0,
    )
    tproxy._dead.clear()
    tproxy._dead["blocked.example"] = 999.0
    tproxy._system_dns_cache.update({
        "ts": 0.0,
        "status": None,
        "resolution_ts": 0.0,
        "resolution_checks": None,
    })
    monkeypatch.setattr(tproxy, "_geph_up", True)

    tproxy.write_status("active", "en0", "en0")

    status = json.loads(status_path.read_text())
    assert status["schema_version"] == tproxy.STATUS_SCHEMA_VERSION
    assert status["daemon"]["state"] == "active"
    assert status["daemon"]["version"] == tproxy.DAEMON_VERSION
    assert status["daemon"]["hosts_learned"] == 1
    assert status["daemon"]["dead_hosts"] == 1
    assert status["routes"][tproxy.ROUTE_LOCAL_BYPASS]["state"] == tproxy.HEALTH_OK
    assert status["backends"]["geph"]["state"] == "up"
    assert status["backends"]["geph"]["active_sessions"] == 0
    auto_geo_exit = status["backends"]["geph"]["auto_geo_exit"]
    assert auto_geo_exit["enabled"] is True
    assert auto_geo_exit["learned"] == 0
    assert auto_geo_exit["pending"] >= 0
    assert "last_host" not in auto_geo_exit
    assert "last_reason" not in auto_geo_exit
    assert status["backends"]["telegram"]["state"] in {"ready", "starting", "error"}
    assert status["environment"]["proxy"] == {
        "state": "off",
        "kind": "",
        "managed_by_slipstream": False,
    }
    assert status["environment"]["dns"] == {
        "state": "xbox_dns",
        "providers": "xbox_dns",
        "managed_by_slipstream": False,
        "resolution_state": "unknown",
    }
    assert status["environment"]["pf"] == {
        "state": "off",
        "applied": False,
        "enabled": False,
        "rules_loaded": False,
        "interceptor_conflict": False,
    }
    assert status["recovery"]["last_action"] == "none"
    assert status["recovery"]["count"] == 0
    assert "canaries" in status
    assert status_path.stat().st_mode & 0o777 == tproxy.STATUS_PUBLIC_MODE

    public_text = status_path.read_text()
    for private_value in (
        "example.com",
        "blocked.example",
        "discord.com",
        "111.88.96.50",
        "142.250.186.46",
        "split64+fake",
        "en0",
    ):
        assert private_value not in public_text


def test_auto_geo_exit_pending_counts_every_confirmation_phase(monkeypatch):
    monkeypatch.setattr(tproxy, "_auto_geph_confirming", {})
    monkeypatch.setattr(tproxy, "_transport_incomplete_confirming", {})
    monkeypatch.setattr(tproxy, "_semantic_plain_confirming", {})
    tproxy._auto_geph_confirming["auto.example"] = 1.0
    tproxy._transport_incomplete_confirming["transport.example"] = 2.0
    tproxy._semantic_plain_confirming["semantic.example"] = 3.0
    tproxy._semantic_plain_confirming["auto.example"] = 4.0

    snapshot = tproxy.auto_geo_exit_status_snapshot(now=0.0)

    assert snapshot["pending"] == 3


def test_write_startup_status_never_runs_external_probes(monkeypatch, tmp_path):
    status_path = tmp_path / "slipstream.status"
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))

    def unexpected(*_args, **_kwargs):
        raise AssertionError("startup status attempted external I/O")

    for name in (
        "status_v2_snapshot",
        "current_system_proxy_status",
        "current_system_dns_status",
        "pf_state_snapshot",
        "tgws_status",
        "probe_geph",
        "system_resolve",
        "_run",
    ):
        monkeypatch.setattr(tproxy, name, unexpected)

    tproxy.write_startup_status()

    status = json.loads(status_path.read_text())
    assert status["schema_version"] == tproxy.STATUS_SCHEMA_VERSION
    assert status["daemon"]["state"] == "dormant"
    assert status["daemon"]["pid"] == os.getpid()
    assert status["backends"]["local_engine"]["state"] == "inactive"
    assert status["environment"]["proxy"]["state"] == "unknown"
    assert status["environment"]["dns"]["state"] == "unknown"
    assert status["environment"]["pf"]["rules_loaded"] is False
    assert status_path.stat().st_mode & 0o777 == tproxy.STATUS_PUBLIC_MODE


def test_status_v2_reports_baseline_pause_without_target_details(monkeypatch):
    monkeypatch.setattr(tproxy, "route_health_snapshot", lambda _now: {})
    monkeypatch.setattr(
        tproxy,
        "pf_state_snapshot",
        lambda _port: {
            "applied": False,
            "enabled": False,
            "rules_loaded": False,
            "interceptor_conflicts": [],
        },
    )
    monkeypatch.setattr(
        tproxy,
        "current_system_proxy_status",
        lambda: {"state": "off", "kind": "", "managed_by_slipstream": False},
    )
    monkeypatch.setattr(
        tproxy,
        "current_system_dns_status",
        lambda: {"state": "custom", "providers": "custom"},
    )
    monkeypatch.setattr(
        tproxy,
        "canary_status_snapshot",
        lambda: {
            "running": False,
            "total": 0,
            "ok": 0,
            "warnings": 0,
            "degraded": 0,
            "unknown": 0,
            "next_due_in": 0,
        },
    )
    monkeypatch.setattr(tproxy, "rearm_status_snapshot", lambda _now: {
        "last_at": 0.0,
        "last_reason": "",
        "count": 0,
    })
    monkeypatch.setattr(tproxy, "geph_restart_hint_snapshot", lambda _now: {
        "recommended": False,
        "last_wake_at": 0.0,
        "last_failure_at": 0.0,
    })
    monkeypatch.setattr(tproxy, "geph_active_session_count", lambda: 0)
    monkeypatch.setattr(tproxy, "auto_geo_exit_status_snapshot", lambda _now: {
        "enabled": False,
        "learned": 0,
        "pending": 0,
        "last_state": "idle",
        "last_at": 0.0,
    })
    monkeypatch.setattr(
        tproxy,
        "tgws_status",
        lambda _now: {"telegram_proxy": "unknown"},
    )
    tproxy._set_baseline_guard(
        "blocked", tproxy.BASELINE_GUARD_BLOCK_REASON, now=100.0
    )

    status = tproxy.status_v2_snapshot("dormant", "en0", None, now=101.0)

    assert status["backends"]["local_engine"]["state"] == "paused"
    assert status["recovery"] == {
        "state": "paused",
        "last_action": "pause_private_pf",
        "reason": tproxy.BASELINE_GUARD_BLOCK_REASON,
        "updated_at": 100.0,
        "count": 0,
    }
    assert "example.com" not in json.dumps(status)

    monkeypatch.setattr(
        tproxy,
        "pf_state_snapshot",
        lambda _port: {
            "applied": True,
            "enabled": True,
            "rules_loaded": True,
            "interceptor_conflicts": [],
        },
    )
    tproxy._set_baseline_guard(
        "rollback_failed", tproxy.BASELINE_GUARD_ROLLBACK_REASON, now=102.0
    )

    recovering = tproxy.status_v2_snapshot("active", "en0", None, now=103.0)

    assert recovering["daemon"]["state"] == "dormant"
    assert recovering["backends"]["local_engine"]["state"] == "rollback"
    assert recovering["recovery"]["state"] == "recovering"
    assert recovering["recovery"]["reason"] == tproxy.BASELINE_GUARD_ROLLBACK_REASON


@pytest.mark.parametrize(
    "status",
    [
        {"state": "active", "ts": 1000.0},
        {
            "schema_version": 2,
            "daemon": {"state": "active", "updated_at": 1000.0},
        },
    ],
)
def test_status_command_accepts_fresh_v1_and_v2_status(monkeypatch, tmp_path, capsys, status):
    status_path = tmp_path / "slipstream.status"
    status_path.write_text(json.dumps(status))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))
    monkeypatch.setattr(tproxy.time, "time", lambda: 1010.0)
    monkeypatch.setattr(sys, "argv", ["tproxy.py", "--status"])

    tproxy.main()

    assert json.loads(capsys.readouterr().out) == status


def test_status_command_marks_stale_v2_status_off(monkeypatch, tmp_path, capsys):
    status_path = tmp_path / "slipstream.status"
    status_path.write_text(json.dumps({
        "schema_version": 2,
        "daemon": {"state": "active", "updated_at": 980.0},
    }))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))
    monkeypatch.setattr(tproxy.time, "time", lambda: 1000.0)
    monkeypatch.setattr(sys, "argv", ["tproxy.py", "--status"])

    tproxy.main()

    assert json.loads(capsys.readouterr().out) == {"state": "off"}


@pytest.mark.parametrize(
    "status",
    [
        {"state": "conflict", "ts": 900.0},
        {
            "schema_version": 2,
            "daemon": {"state": "conflict", "updated_at": 900.0},
        },
    ],
)
def test_status_command_preserves_stale_terminal_conflict(
    monkeypatch, tmp_path, capsys, status
):
    status_path = tmp_path / "slipstream.status"
    status_path.write_text(json.dumps(status))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))
    monkeypatch.setattr(tproxy.time, "time", lambda: 1000.0)
    monkeypatch.setattr(sys, "argv", ["tproxy.py", "--status"])

    tproxy.main()

    assert json.loads(capsys.readouterr().out) == status


def test_main_publishes_conflict_and_exits_on_legacy_global_pf(monkeypatch, capsys):
    status_calls = []
    reserve_released = []

    def raise_conflict():
        raise tproxy.LegacyGlobalPfConflict("legacy conflict")

    monkeypatch.setattr(sys, "argv", ["tproxy.py"])
    monkeypatch.setattr(tproxy.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tproxy.resource, "getrlimit", lambda _kind: (256, 256))
    monkeypatch.setattr(tproxy.resource, "setrlimit", lambda *_args: None)
    monkeypatch.setattr(tproxy, "_open_fd_reserve", lambda: None)
    monkeypatch.setattr(tproxy, "cleanup_stale", raise_conflict)
    monkeypatch.setattr(
        tproxy,
        "write_status",
        lambda state, iface, voice_iface: status_calls.append(
            (state, iface, voice_iface)
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_release_fd_reserve",
        lambda: reserve_released.append(True),
    )

    with pytest.raises(SystemExit) as exc:
        tproxy.main()

    assert exc.value.code == 1
    assert status_calls == [("conflict", "", "")]
    assert reserve_released == [True]
    assert "legacy conflict" in capsys.readouterr().err


def test_strategy_score_snapshot_is_aggregated_without_hostnames():
    tproxy._record_strategy_result("discord.com", "split64+fake", True, now=100.0)
    tproxy._record_strategy_result("cdn.discordapp.com", "split64+fake", False, now=110.0)
    tproxy._record_strategy_result("rr1---sn-test.googlevideo.com", "fake5", True, now=120.0)

    snapshot = tproxy.strategy_score_snapshot()

    assert snapshot["hosts"] == 3
    assert snapshot["groups"][tproxy.SERVICE_DISCORD]["hosts"] == 2
    assert snapshot["groups"][tproxy.SERVICE_DISCORD]["strategies"]["split64+fake"] == {
        "hosts": 2,
        "ok": 1,
        "fail": 1,
        "last_seen": 110.0,
    }
    assert snapshot["groups"][tproxy.SERVICE_YOUTUBE]["strategies"]["fake5"] == {
        "hosts": 1,
        "ok": 1,
        "fail": 0,
        "last_seen": 120.0,
    }
    serialized = json.dumps(snapshot)
    assert "discord.com" not in serialized
    assert "googlevideo.com" not in serialized


def test_pf_state_snapshot_reports_enabled_and_loaded_rules(monkeypatch):
    def fake_run(*args):
        if args == ("pfctl", "-s", "info"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "Status: Enabled\n",
                "stderr": "",
            })()
        if args == ("pfctl", "-sn"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": 'rdr-anchor "com.apple/*" all\n',
                "stderr": "",
            })()
        if args == ("pfctl", "-sr"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": 'anchor "com.apple/*" all\n',
                "stderr": "",
            })()
        if args == ("pfctl", "-a", tproxy.PF_ANCHOR, "-sn"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "rdr pass inet proto tcp to any port 443 -> 127.0.0.1 port 1080\n",
                "stderr": "",
            })()
        if args == ("pfctl", "-a", tproxy.PF_ANCHOR, "-sr"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "pass out route-to (lo0 127.0.0.1) inet proto tcp to any port 443\n",
                "stderr": "",
            })()
        raise AssertionError(args)

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "_pf_applied", True)

    assert tproxy.pf_state_snapshot(1080) == {
        "applied": True,
        "enabled": True,
        "anchor": tproxy.PF_ANCHOR,
        "parent_loaded": True,
        "interceptor_conflicts": [],
        "rules_loaded": True,
    }


def test_pf_detects_nested_https_interceptor_before_parent(monkeypatch):
    outputs = {
        ("pfctl", "-sn"): 'rdr-anchor "zapret" all\nrdr-anchor "com.apple/*" all\n',
        ("pfctl", "-sr"): 'anchor "zapret" all\nanchor "com.apple/*" all\n',
        ("pfctl", "-a", "zapret", "-sn"): 'rdr-anchor "/zapret-v4" inet\n',
        ("pfctl", "-a", "zapret-v4", "-sn"): (
            "rdr on lo0 inet proto tcp to any port = 443 -> 127.0.0.1 port 988\n"
        ),
        ("pfctl", "-a", "zapret", "-sr"): 'anchor "/zapret-v4" inet\n',
        ("pfctl", "-a", "zapret-v4", "-sr"): (
            "pass out route-to (lo0 127.0.0.1) inet proto tcp to any port = 443\n"
        ),
    }

    def fake_run(*args):
        return type("Result", (), {
            "returncode": 0,
            "stdout": outputs[args],
            "stderr": "",
        })()

    monkeypatch.setattr(tproxy, "_run", fake_run)

    assert tproxy.pf_preceding_https_interceptors() == ["zapret"]


def test_pf_ignores_empty_or_later_external_anchor(monkeypatch):
    outputs = {
        ("pfctl", "-sn"): 'rdr-anchor "com.apple/*" all\nrdr-anchor "later" all\n',
        ("pfctl", "-sr"): 'anchor "com.apple/*" all\nanchor "later" all\n',
    }

    def fake_run(*args):
        return type("Result", (), {
            "returncode": 0,
            "stdout": outputs[args],
            "stderr": "",
        })()

    monkeypatch.setattr(tproxy, "_run", fake_run)

    assert tproxy.pf_preceding_https_interceptors() == []


def test_pf_setup_pauses_without_mutating_prior_interceptor(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "pf_parent_anchor_available", lambda: True)
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(tproxy, "pf_preceding_https_interceptors", lambda: ["zapret"])
    monkeypatch.setattr(tproxy, "_pf_acquire_enable_token", lambda: calls.append("token"))
    monkeypatch.setattr(tproxy, "_pf_load", lambda _port: calls.append("load"))
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: calls.append("flush") or type("Result", (), {"returncode": 0})(),
    )
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_pf_interceptor_conflicts", [])

    assert not tproxy.pf_setup(1080)
    assert calls == ["flush"]
    assert not tproxy._pf_applied
    assert tproxy._pf_interceptor_conflicts == ["zapret"]


def test_pf_parent_anchor_requires_rdr_and_filter_declarations(tmp_path):
    config = tmp_path / "pf.conf"
    config.write_text(
        'rdr-anchor "com.apple/*"\n'
        'anchor "com.apple/*"\n'
        'anchor "zapret"\n'
    )

    assert tproxy.pf_parent_anchor_available(str(config))

    config.write_text('anchor "com.apple/*"\nanchor "zapret"\n')
    assert not tproxy.pf_parent_anchor_available(str(config))


def test_pf_token_file_is_private_and_token_parser_is_strict(tmp_path):
    token_path = tmp_path / "pf.token"
    result = type("Result", (), {
        "stdout": "pf enabled\nToken : 123456\n",
        "stderr": "",
    })()

    token = tproxy._pf_token_from_result(result)
    tproxy._write_pf_token(token, str(token_path))

    assert token == "123456"
    assert tproxy._read_pf_token(str(token_path)) == "123456"
    assert token_path.stat().st_mode & 0o777 == 0o600
    token_path.write_text("123;pfctl -d\n")
    assert tproxy._read_pf_token(str(token_path)) is None


def test_pf_loopback_claim_persists_lease_before_clearing_skip(monkeypatch):
    events = []
    monkeypatch.setattr(tproxy, "_read_pf_skip_lease", lambda path=None: None)
    monkeypatch.setattr(
        tproxy,
        "_write_pf_skip_lease",
        lambda path=None: events.append("lease-written"),
    )
    monkeypatch.setattr(tproxy, "_pf_loopback_skip_state", lambda: True)
    monkeypatch.setattr(
        tproxy.pf_adapter,
        "set_interface_skip",
        lambda _runner, interface, enabled: events.append(
            ("ioctl", interface, enabled)
        )
        or True,
    )

    assert _REAL_CLAIM_PF_LOOPBACK_SKIP()
    assert events == [
        "lease-written",
        ("ioctl", tproxy.PF_LOOPBACK_INTERFACE, False),
    ]


def test_pf_loopback_restore_removes_lease_only_after_readback(monkeypatch):
    events = []
    monkeypatch.setattr(
        tproxy,
        "_read_pf_skip_lease",
        lambda path=None: {
            "interface": "lo0",
            "owner_pid": 123,
            "restore_skip": True,
            "schema_version": 1,
        },
    )
    monkeypatch.setattr(tproxy, "_pf_loopback_skip_state", lambda: False)
    monkeypatch.setattr(
        tproxy.pf_adapter,
        "set_interface_skip",
        lambda _runner, interface, enabled: events.append(
            ("ioctl", interface, enabled)
        )
        or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_remove_pf_skip_lease",
        lambda path=None: events.append("lease-removed"),
    )

    assert _REAL_RESTORE_PF_LOOPBACK_SKIP()
    assert events == [
        ("ioctl", tproxy.PF_LOOPBACK_INTERFACE, True),
        "lease-removed",
    ]


def test_pf_load_targets_only_private_anchor(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        if args[:4] == ("pfctl", "-a", tproxy.PF_ANCHOR, "-f"):
            rules = open(args[4]).read()
            assert "rdr on lo0 inet proto tcp" in rules
            assert "to ! 127.0.0.0/8 port 443" in rules
            assert "pass out quick on ! lo0 route-to (lo0 127.0.0.1)" in rules
            assert "pass out quick on lo0" in rules
            assert "no state" in rules
            assert "pass in quick on lo0 reply-to (lo0 127.0.0.1)" in rules
            assert "proto udp" not in rules
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        raise AssertionError(args)

    monkeypatch.setattr(tproxy, "_run", fake_run)

    assert tproxy._pf_load(1080).returncode == 0
    assert len(calls) == 1


def test_pf_teardown_flushes_anchor_and_releases_own_token(monkeypatch, tmp_path):
    calls = []
    status_path = tmp_path / "status"
    status_path.write_text("{}")
    status_tmp_path = tmp_path / "status.tmp"
    status_tmp_path.write_text("{}")

    def fake_run(*args):
        calls.append(args)
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda path=None: None)
    monkeypatch.setattr(
        tproxy,
        "_restore_pf_loopback_skip",
        lambda: calls.append(("restore-loopback",)) or True,
    )
    monkeypatch.setattr(tproxy, "_pf_enable_token", "123456")
    monkeypatch.setattr(tproxy, "_pf_applied", True)

    tproxy.pf_teardown()

    assert ("pfctl", "-a", tproxy.PF_ANCHOR, "-F", "rules") in calls
    assert ("pfctl", "-a", tproxy.PF_ANCHOR, "-F", "nat") in calls
    assert ("pfctl", "-X", "123456") in calls
    assert calls.index(("restore-loopback",)) < calls.index(("pfctl", "-X", "123456"))
    assert not any("states" in args or "all" in args for args in calls)
    assert not any(args[:3] == ("pfctl", "-f", "/etc/pf.conf") for args in calls)
    assert not any(args[:2] == ("pfctl", "-d") for args in calls)
    assert not status_path.exists()
    assert not status_tmp_path.exists()
    assert tproxy._pf_teardown_complete.is_set()

    completed_calls = list(calls)
    tproxy.pf_teardown()
    assert calls == completed_calls


def test_pf_teardown_prevents_inflight_status_writer_from_resurrecting_file(
    monkeypatch,
    tmp_path,
):
    status_path = tmp_path / "status"
    writer_inside_lock = threading.Event()
    release_writer = threading.Event()
    real_chmod = tproxy.os.chmod

    def blocking_chmod(path, mode):
        writer_inside_lock.set()
        assert release_writer.wait(timeout=2)
        real_chmod(path, mode)

    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))
    monkeypatch.setattr(tproxy, "status_v2_snapshot", lambda *_: {"state": "active"})
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(tproxy, "_pf_release_enable_token", lambda: None)
    monkeypatch.setattr(tproxy.os, "chmod", blocking_chmod)

    writer = threading.Thread(
        target=tproxy.write_status,
        args=("active", "en0", None),
    )
    writer.start()
    assert writer_inside_lock.wait(timeout=2)

    teardown = threading.Thread(target=tproxy.pf_teardown)
    teardown.start()
    assert tproxy._shutdown_started.wait(timeout=2)
    assert teardown.is_alive()

    release_writer.set()
    writer.join(timeout=2)
    teardown.join(timeout=2)

    assert not writer.is_alive()
    assert not teardown.is_alive()
    assert not status_path.exists()
    assert not (tmp_path / "status.tmp").exists()

    tproxy.write_status("active", "en0", None)
    assert not status_path.exists()


def test_pf_teardown_wins_when_shutdown_arrives_during_pf_load(monkeypatch, tmp_path):
    load_started = threading.Event()
    release_load = threading.Event()
    calls = []
    arm_result = []

    def blocking_load(_port):
        calls.append("load")
        load_started.set()
        assert release_load.wait(timeout=2)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def flush():
        calls.append("flush")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status"))
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", False)
    monkeypatch.setattr(tproxy, "_pf_applied", False)
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(tproxy, "_pf_acquire_enable_token", lambda: True)
    monkeypatch.setattr(tproxy, "_pf_load", blocking_load)
    monkeypatch.setattr(tproxy, "_pf_flush", flush)
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: calls.append("release"),
    )

    arm = threading.Thread(
        target=lambda: arm_result.append(tproxy.arm_private_pf_if_ready(1080))
    )
    arm.start()
    assert load_started.wait(timeout=2)

    teardown = threading.Thread(target=tproxy.pf_teardown)
    teardown.start()
    assert tproxy._shutdown_started.wait(timeout=2)
    assert teardown.is_alive()

    release_load.set()
    arm.join(timeout=2)
    teardown.join(timeout=2)

    assert not arm.is_alive()
    assert not teardown.is_alive()
    assert arm_result == [False]
    assert calls == ["load", "flush", "release", "flush", "release"]
    assert not tproxy._pf_applied


def test_pf_teardown_retries_without_releasing_token_after_failed_flush(
    monkeypatch,
    tmp_path,
):
    results = iter(
        (
            SimpleNamespace(returncode=1, stdout="", stderr="busy"),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
        )
    )
    releases = []
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status"))
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_pf_flush", lambda: next(results))
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: releases.append(True),
    )

    assert not tproxy.pf_teardown()
    assert not tproxy._pf_teardown_complete.is_set()
    assert tproxy._pf_applied
    assert releases == []

    assert tproxy.pf_teardown()
    assert tproxy._pf_teardown_complete.is_set()
    assert not tproxy._pf_applied
    assert releases == [True]


def test_pf_teardown_retries_skip_restore_before_releasing_token(
    monkeypatch,
    tmp_path,
):
    restores = iter((False, True))
    releases = []
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status"))
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(tproxy, "_restore_pf_loopback_skip", lambda: next(restores))
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: releases.append(True),
    )

    assert not tproxy.pf_teardown()
    assert not tproxy._pf_teardown_complete.is_set()
    assert not tproxy._pf_applied
    assert releases == []

    assert tproxy.pf_teardown()
    assert tproxy._pf_teardown_complete.is_set()
    assert releases == [True]


def test_pf_teardown_stops_interception_when_token_release_is_deferred(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(tmp_path / "status"))
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: SimpleNamespace(returncode=1, stdout="", stderr="busy"),
    )

    assert tproxy.pf_teardown()
    assert tproxy._pf_teardown_complete.is_set()
    assert not tproxy._pf_applied


def test_pf_release_failure_preserves_token_for_recovery(monkeypatch):
    removed = []
    result = type("Result", (), {"returncode": 1, "stdout": "", "stderr": "busy"})()
    monkeypatch.setattr(tproxy, "_run", lambda *args: result)
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda path=None: removed.append(path))
    monkeypatch.setattr(tproxy, "_pf_enable_token", "123456")

    assert tproxy._pf_release_enable_token() is result
    assert tproxy._pf_enable_token == "123456"
    assert removed == []


def test_pf_acquire_requires_releasable_token(monkeypatch):
    result = type("Result", (), {
        "returncode": 0,
        "stdout": "pf enabled without token\n",
        "stderr": "",
    })()
    monkeypatch.setattr(tproxy, "_run", lambda *args: result)
    monkeypatch.setattr(tproxy, "_read_pf_token", lambda path=None: None)
    monkeypatch.setattr(tproxy, "_pf_enable_token", None)

    assert not tproxy._pf_acquire_enable_token()
    assert tproxy._pf_enable_token is None


def test_pf_acquire_replaces_stale_memory_token_after_owned_recovery(monkeypatch):
    calls = []
    writes = []

    def fake_run(*args):
        calls.append(args)
        if args == ("pfctl", "-s", "info"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "Status: Disabled\n",
                "stderr": "",
            })()
        if args == ("pfctl", "-E"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "Token: 789\n",
                "stderr": "",
            })()
        raise AssertionError(args)

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "_read_pf_token", lambda path=None: None)
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda path=None: None)
    monkeypatch.setattr(tproxy, "_write_pf_token", lambda token, path=None: writes.append(token))
    monkeypatch.setattr(tproxy, "_pf_enable_token", "456")

    assert tproxy._pf_acquire_enable_token()
    assert tproxy._pf_enable_token == "789"
    assert writes == ["789"]
    assert calls == [("pfctl", "-s", "info"), ("pfctl", "-E")]


def test_pf_acquire_keeps_memory_token_when_pf_is_still_enabled(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        if args == ("pfctl", "-s", "info"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "Status: Enabled\n",
                "stderr": "",
            })()
        if args == ("pfctl", "-X", "456"):
            return type("Result", (), {"returncode": 1, "stdout": "", "stderr": "busy"})()
        raise AssertionError(args)

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "_read_pf_token", lambda path=None: None)
    monkeypatch.setattr(tproxy, "_pf_enable_token", "456")

    assert not tproxy._pf_acquire_enable_token()
    assert tproxy._pf_enable_token == "456"
    assert calls == [("pfctl", "-s", "info"), ("pfctl", "-X", "456")]


def test_legacy_global_pf_detection_is_read_only(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        if args == ("pfctl", "-sn"):
            stdout = "rdr pass proto tcp to any port = 443 -> 127.0.0.1 port 1080\n"
        elif args == ("pfctl", "-sr"):
            stdout = "pass out route-to (lo0 127.0.0.1) proto tcp to any port = 443\n"
        else:
            stdout = ""
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    monkeypatch.setattr(tproxy, "_run", fake_run)

    assert tproxy._legacy_global_pf_conflict(1080)
    assert ("pfctl", "-sn") in calls
    assert ("pfctl", "-sr") in calls
    assert not any("-f" in args or "-d" in args for args in calls)


def test_legacy_global_pf_detection_ignores_unrelated_route_to_rule(monkeypatch):
    def fake_run(*args):
        if args == ("pfctl", "-sn"):
            stdout = "rdr pass proto tcp to any port = 80 -> 127.0.0.1 port 1080\n"
        elif args == ("pfctl", "-sr"):
            stdout = "pass out route-to (lo0 127.0.0.1) proto tcp to any port = 80\n"
        else:
            raise AssertionError(args)
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    monkeypatch.setattr(tproxy, "_run", fake_run)

    assert not tproxy._legacy_global_pf_conflict(1080)


def test_legacy_global_pf_detection_ignores_live_private_anchor(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        outputs = {
            ("pfctl", "-sn"): (
                'rdr-anchor "com.apple/*" all\n'
                "rdr pass proto tcp to any port = 443 -> 127.0.0.1 port 1080\n"
            ),
            ("pfctl", "-sr"): (
                'anchor "com.apple/*" all\n'
                "pass out route-to (lo0 127.0.0.1) proto tcp to any port = 443\n"
            ),
            ("pfctl", "-a", tproxy.PF_ANCHOR, "-sn"): (
                "rdr pass proto tcp to any port = 443 -> 127.0.0.1 port 1080\n"
            ),
            ("pfctl", "-a", tproxy.PF_ANCHOR, "-sr"): (
                "pass out route-to (lo0 127.0.0.1) proto tcp to any port = 443\n"
            ),
        }
        return SimpleNamespace(returncode=0, stdout=outputs.get(args, ""), stderr="")

    monkeypatch.setattr(tproxy, "_run", fake_run)

    assert not tproxy._legacy_global_pf_conflict(1080)
    assert not any("-f" in args or "-d" in args for args in calls)


def test_cleanup_stale_disables_owned_job_on_legacy_global_conflict(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        outputs = {
            ("pfctl", "-sn"): (
                "rdr pass proto tcp to any port = 443 -> 127.0.0.1 port 1080\n"
            ),
            ("pfctl", "-sr"): (
                "pass out route-to (lo0 127.0.0.1) proto tcp to any port = 443\n"
            ),
        }
        return SimpleNamespace(returncode=0, stdout=outputs.get(args, ""), stderr="")

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "running_from_install_dir", lambda: True)
    monkeypatch.setattr(tproxy, "_read_pf_token", lambda path=None: None)
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda path=None: None)

    with pytest.raises(tproxy.LegacyGlobalPfConflict, match="refusing to reload"):
        tproxy.cleanup_stale()

    assert ("launchctl", "disable", f"system/{tproxy.LAUNCHD_LABEL}") in calls
    assert ("pfctl", "-a", tproxy.PF_ANCHOR, "-F", "rules") in calls
    assert ("pfctl", "-a", tproxy.PF_ANCHOR, "-F", "nat") in calls
    assert not any("-f" in args or "-d" in args for args in calls)


def test_tproxy_source_forbids_global_pf_mutation_calls():
    tree = ast.parse(inspect.getsource(tproxy))
    forbidden = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "_run":
            continue
        args = [arg.value for arg in node.args if isinstance(arg, ast.Constant)]
        if len(args) >= 2 and args[0] == "pfctl" and args[1] in {"-f", "-d"}:
            forbidden.append((node.lineno, args[:3]))

    assert forbidden == []


def test_cleanup_stale_never_uses_process_pattern_or_global_pf_disable(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        if args in (("pfctl", "-sn"), ("pfctl", "-sr")):
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "running_from_install_dir", lambda: True)
    monkeypatch.setattr(tproxy, "_read_pf_token", lambda path=None: None)
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda path=None: None)

    tproxy.cleanup_stale()

    assert ("pfctl", "-a", tproxy.PF_ANCHOR, "-F", "rules") in calls
    assert ("pfctl", "-a", tproxy.PF_ANCHOR, "-F", "nat") in calls
    assert not any("states" in args or "all" in args for args in calls)
    assert not any(args[0] in {"pgrep", "pkill", "kill"} for args in calls)
    assert not any(args[:2] == ("pfctl", "-d") for args in calls)
    assert not any(args[:3] == ("pfctl", "-f", "/etc/pf.conf") for args in calls)


def test_foreground_start_quiesces_installed_daemon_before_stale_cleanup(
    monkeypatch,
):
    quiescence = []
    monkeypatch.setattr(tproxy, "running_from_install_dir", lambda: False)
    monkeypatch.setattr(tproxy, "_legacy_global_pf_conflict", lambda _port: False)
    monkeypatch.setattr(
        tproxy,
        "_disable_and_cleanup_install",
        lambda port, remove_runtime=True: quiescence.append(
            (port, remove_runtime)
        ) or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(tproxy, "_restore_pf_loopback_skip", lambda: True)
    monkeypatch.setattr(tproxy, "_pf_release_enable_token", lambda: None)

    tproxy.cleanup_stale(1080)

    assert quiescence == [(1080, False)]


def test_foreground_start_aborts_when_installed_daemon_is_not_quiescent(
    monkeypatch,
):
    monkeypatch.setattr(tproxy, "running_from_install_dir", lambda: False)
    monkeypatch.setattr(tproxy, "_legacy_global_pf_conflict", lambda _port: False)
    monkeypatch.setattr(
        tproxy,
        "_disable_and_cleanup_install",
        lambda _port, remove_runtime=True: False,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: pytest.fail("stale cleanup requires launchd quiescence first"),
    )

    with pytest.raises(tproxy.OwnedPfStateError, match="quiesced safely"):
        tproxy.cleanup_stale(1080)


def test_geph_ownership_requires_pid_executable_and_config_match():
    state = {
        "pid": 4242,
        "executable": "/Applications/Slipstream.app/Contents/MacOS/geph5-client",
        "config": "/Users/test/Library/Application Support/dev.slipstream.tray/geph-active.yaml",
    }
    command = (
        "/Applications/Slipstream.app/Contents/MacOS/geph5-client --config "
        "/Users/test/Library/Application Support/dev.slipstream.tray/geph-active.yaml"
    )

    assert tproxy._geph_state_matches(state, 4242, command)
    assert not tproxy._geph_state_matches(state, 4243, command)
    assert not tproxy._geph_state_matches(state, 4242, "/tmp/geph5-client --config /tmp/x")
    assert not tproxy._geph_state_matches(state, 4242, state["executable"])
    assert not tproxy._geph_state_matches(state, 4242, command + ".untrusted")


def test_probe_geph_rejects_unknown_owned_port_and_only_detects_external(monkeypatch):
    live_calls = []
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_env_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_owned", False)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_external_geph_detected", False)
    monkeypatch.setattr(tproxy, "geph_listener_owned", lambda _port: False)
    monkeypatch.setattr(
        tproxy,
        "_tcp_listener_present",
        lambda port: port in {tproxy.GEPH_OWNED_PORT, tproxy.GEPH_EXTERNAL_PORT},
    )
    monkeypatch.setattr(tproxy, "_geph_live", lambda port: live_calls.append(port) or True)

    assert not tproxy.probe_geph()
    assert live_calls == []
    assert tproxy._geph_port_conflict is True
    assert tproxy._external_geph_detected is True
    assert tproxy._geph_owned is False
    assert tproxy._geph_port is None


def test_probe_geph_disabled_clears_external_detection(monkeypatch):
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", False)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", True)
    monkeypatch.setattr(tproxy, "_external_geph_detected", True)

    assert not tproxy.probe_geph()
    assert tproxy._geph_port is None
    assert tproxy._geph_owned is False
    assert tproxy._geph_port_conflict is False
    assert tproxy._external_geph_detected is False


def test_probe_geph_accepts_verified_owned_listener(monkeypatch):
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_env_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_owned", False)
    monkeypatch.setattr(tproxy, "geph_listener_owned", lambda _port: True)
    monkeypatch.setattr(tproxy, "_tcp_listener_present", lambda _port: False)
    monkeypatch.setattr(tproxy, "_geph_live", lambda port: port == tproxy.GEPH_OWNED_PORT)

    assert tproxy.probe_geph()
    assert tproxy._geph_port == tproxy.GEPH_OWNED_PORT
    assert tproxy._geph_owned is True
    assert tproxy._geph_port_conflict is False


@pytest.mark.parametrize(
    ("listener_present", "listener_owned", "backend_live", "expected"),
    (
        (False, False, False, "down"),
        (True, False, False, "conflict"),
        (True, True, False, "down"),
        (True, True, True, "ready"),
    ),
)
def test_owned_geph_recovery_probe_is_bounded_and_owner_exact(
    monkeypatch,
    listener_present,
    listener_owned,
    backend_live,
    expected,
):
    calls = []
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 123)
    monkeypatch.setattr(
        tproxy,
        "_tcp_listener_present",
        lambda port, *, timeout: (
            calls.append(("listener", port, timeout)) or listener_present
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda port, *, listener_pid: (
            calls.append(("owned", port, listener_pid)) or listener_owned
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_geph_live",
        lambda port, *, timeout: (
            calls.append(("live", port, timeout)) or backend_live
        ),
    )

    assert tproxy._probe_owned_geph_recovery_state() == expected
    assert calls[0] == (
        "listener",
        tproxy.GEPH_OWNED_PORT,
        tproxy.AUTO_GEPH_RECOVERY_PROBE_TIMEOUT,
    )
    assert ("owned", tproxy.GEPH_OWNED_PORT, 123) in calls or not listener_present
    assert (
        "live",
        tproxy.GEPH_OWNED_PORT,
        tproxy.AUTO_GEPH_RECOVERY_PROBE_TIMEOUT,
    ) in calls or not (listener_present and listener_owned)


def test_owned_geph_successor_rejects_pid_changed_during_readiness(monkeypatch):
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_tcp_listener_present", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "_geph_live", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda _port, *, listener_pid: listener_pid == 101,
    )
    listener_pids = iter((101, 100))

    assert (
        tproxy._wait_for_owned_geph_successor(
            100,
            timeout=0.0,
            listener_pid=lambda _port: next(listener_pids),
        )
        == "timeout"
    )


def test_geph_probe_hysteresis_never_invents_cold_start_readiness():
    up, strikes = tproxy.reduce_geph_probe_state(
        previous_up=False,
        strikes=0,
        probe_ok=False,
        port=None,
        conflict=False,
    )

    assert up is False
    assert strikes == 1


def test_geph_probe_hysteresis_preserves_only_a_verified_sticky_port():
    up, strikes = tproxy.reduce_geph_probe_state(
        previous_up=True,
        strikes=0,
        probe_ok=False,
        port=tproxy.GEPH_OWNED_PORT,
        conflict=False,
    )

    assert up is True
    assert strikes == 1
    up, strikes = tproxy.reduce_geph_probe_state(
        previous_up=up,
        strikes=strikes,
        probe_ok=False,
        port=tproxy.GEPH_OWNED_PORT,
        conflict=False,
    )
    assert up is True
    assert strikes == 2
    up, strikes = tproxy.reduce_geph_probe_state(
        previous_up=up,
        strikes=strikes,
        probe_ok=False,
        port=tproxy.GEPH_OWNED_PORT,
        conflict=False,
    )
    assert up is False
    assert strikes == 3


def test_fd_pressure_reducer_uses_hysteresis_and_a_bounded_high_watermark():
    assert tproxy.fd_pressure_watermarks(65536) == (2048, 1024)
    assert not tproxy.reduce_fd_pressure(False, 2047, 65536)
    assert tproxy.reduce_fd_pressure(False, 2048, 65536)
    assert tproxy.reduce_fd_pressure(True, 1025, 65536)
    assert not tproxy.reduce_fd_pressure(True, 1024, 65536)


def test_asyncio_emfile_pauses_only_private_routing_once(monkeypatch):
    pauses = []

    class Loop:
        def __init__(self):
            self.default_contexts = []

        def default_exception_handler(self, context):
            self.default_contexts.append(context)

    loop = Loop()
    monkeypatch.setattr(tproxy, "_fd_pressure", False)
    monkeypatch.setattr(tproxy, "_fd_reserve", [])
    monkeypatch.setattr(tproxy, "pause_private_pf", lambda: pauses.append(True) or True)

    context = {"exception": OSError(errno.EMFILE, "Too many open files")}
    tproxy.asyncio_exception_handler(loop, context)
    tproxy.asyncio_exception_handler(loop, context)

    assert pauses == [True]
    assert loop.default_contexts == []
    assert tproxy._fd_pressure
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", False)
    assert not tproxy.geo_exit_backend_ready(now=100.0)


def test_fd_pressure_stays_dormant_until_usage_falls_below_low_watermark(monkeypatch):
    counts = iter((2200, 1024))
    pauses = []
    reserve_reopens = []
    monkeypatch.setattr(tproxy, "_fd_pressure", False)
    monkeypatch.setattr(tproxy, "_fd_reserve", [])
    monkeypatch.setattr(tproxy, "open_fd_count", lambda: next(counts))
    monkeypatch.setattr(
        tproxy.resource,
        "getrlimit",
        lambda _kind: (65536, 65536),
    )
    monkeypatch.setattr(tproxy, "pause_private_pf", lambda: pauses.append(True) or True)
    monkeypatch.setattr(tproxy, "_open_fd_reserve", lambda: reserve_reopens.append(True))

    assert tproxy.refresh_fd_pressure()
    assert not tproxy.refresh_fd_pressure()
    assert pauses == [True]
    assert reserve_reopens == [True]


def test_pf_startup_keeps_local_routing_active_without_geph(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "_fd_pressure", False)
    monkeypatch.setattr(tproxy, "pf_parent_anchor_available", lambda: True)
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(tproxy, "pf_preceding_https_interceptors", lambda: [])
    monkeypatch.setattr(
        tproxy,
        "arm_private_pf_if_ready",
        lambda port: calls.append(port) or True,
    )

    assert not tproxy.geo_exit_backend_ready(now=100.0)
    assert tproxy.pf_setup_if_ready(1080, now=100.0)
    assert calls == [1080]


def test_installed_daemon_readiness_uses_exact_listener_ownership(monkeypatch):
    now = tproxy.time.time()
    status = {"updated_at": now, "state": "active", "pid": 321}
    monkeypatch.setattr(tproxy, "_daemon_status_record", lambda: status)
    monkeypatch.setattr(tproxy, "_process_command_for_pid", lambda pid: f"owned:{pid}")
    monkeypatch.setattr(tproxy, "_installed_daemon_command_owned", lambda command: True)
    monkeypatch.setattr(tproxy, "_listener_pids", lambda _port: [321])
    monkeypatch.setattr(tproxy, "pf_state_snapshot", lambda _port: {"rules_loaded": True})
    monkeypatch.setattr(
        tproxy,
        "_tcp_listener_present",
        lambda _port: pytest.fail("readiness must not open a data-plane connection"),
    )

    assert tproxy._installed_daemon_readiness(1080) == (True, "ready")


def test_installed_daemon_readiness_rejects_foreign_or_shared_listener(monkeypatch):
    now = tproxy.time.time()
    status = {"updated_at": now, "state": "active", "pid": 321}
    monkeypatch.setattr(tproxy, "_daemon_status_record", lambda: status)
    monkeypatch.setattr(tproxy, "_process_command_for_pid", lambda pid: f"owned:{pid}")
    monkeypatch.setattr(tproxy, "_installed_daemon_command_owned", lambda command: True)
    monkeypatch.setattr(tproxy, "_listener_pids", lambda _port: [321, 654])

    ready, reason = tproxy._installed_daemon_readiness(1080)

    assert not ready
    assert reason == (
        "listener 127.0.0.1:1080 is not owned exclusively by the status pid"
    )


def test_installed_daemon_readiness_rejects_baseline_guard_rollback(monkeypatch):
    now = tproxy.time.time()
    monkeypatch.setattr(
        tproxy,
        "_daemon_status_record",
        lambda: {"updated_at": now, "state": "dormant", "pid": 321},
    )
    monkeypatch.setattr(
        tproxy,
        "_daemon_recovery_record",
        lambda: {
            "state": "paused",
            "last_action": "pause_private_pf",
            "reason": tproxy.BASELINE_GUARD_BLOCK_REASON,
        },
    )

    ready, reason = tproxy._installed_daemon_readiness(1080)

    assert not ready
    assert reason == "daemon rolled back after baseline HTTPS qualification failed"


def test_installed_daemon_readiness_waits_for_incomplete_pf_rollback(monkeypatch):
    now = tproxy.time.time()
    monkeypatch.setattr(
        tproxy,
        "_daemon_status_record",
        lambda: {"updated_at": now, "state": "active", "pid": 321},
    )
    monkeypatch.setattr(
        tproxy,
        "_daemon_recovery_record",
        lambda: {"reason": tproxy.BASELINE_GUARD_ROLLBACK_REASON},
    )

    ready, reason = tproxy._installed_daemon_readiness(1080)

    assert not ready
    assert reason == "daemon is still restoring the system HTTPS path"


def test_pf_arm_refuses_to_touch_pf_after_shutdown_starts(monkeypatch):
    calls = []
    tproxy._shutdown_started.set()
    monkeypatch.setattr(
        tproxy,
        "pf_parent_anchor_loaded",
        lambda: calls.append("parent") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_acquire_enable_token",
        lambda: calls.append("token") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_load",
        lambda _port: calls.append("load"),
    )

    assert not tproxy.arm_private_pf_if_ready(1080)
    assert not tproxy.pf_setup(1080)
    assert calls == []


def test_amain_uses_backend_gate_before_starting_monitor(monkeypatch):
    calls = []

    class Server:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def serve_forever(self):
            raise RuntimeError("stop test server")

    async def start_server(*_args, **_kwargs):
        return Server()

    monkeypatch.setattr(tproxy.asyncio, "start_server", start_server)
    monkeypatch.setattr(
        tproxy,
        "_start_network_monitor",
        lambda port, voice: calls.append(("monitor", port, voice)),
    )
    monkeypatch.setattr(tproxy, "probe_geph", lambda: False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_pf_applied", False)
    monkeypatch.setattr(tproxy, "_pf_interceptor_conflicts", [])
    monkeypatch.setattr(tproxy, "default_iface", lambda: "en0")
    monkeypatch.setattr(
        tproxy,
        "write_status",
        lambda state, iface, voice_iface: calls.append(
            ("status", state, iface, voice_iface)
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "write_startup_status",
        lambda: calls.append(("startup_status",)),
    )
    monkeypatch.setattr(
        tproxy,
        "pf_setup_if_ready",
        lambda port: calls.append(("pf_gate", port)) or False,
    )

    with pytest.raises(RuntimeError, match="stop test server"):
        asyncio.run(tproxy.amain(1080, voice=False))

    assert calls[0] == ("startup_status",)
    assert calls[1] == ("pf_gate", 1080)
    assert calls[2] == ("status", "dormant", "en0", None)
    assert ("monitor", 1080, False) in calls


def test_amain_never_arms_pf_while_user_full_tunnel_vpn_is_default(monkeypatch):
    calls = []

    class Server:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def serve_forever(self):
            raise RuntimeError("stop test server")

    async def start_server(*_args, **_kwargs):
        return Server()

    monkeypatch.setattr(tproxy.asyncio, "start_server", start_server)
    monkeypatch.setattr(tproxy, "probe_geph", lambda: False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_pf_applied", False)
    monkeypatch.setattr(tproxy, "_pf_interceptor_conflicts", [])
    monkeypatch.setattr(tproxy, "default_iface", lambda: "utun7")
    monkeypatch.setattr(
        tproxy,
        "pf_setup_if_ready",
        lambda _port: calls.append("pf_arm_attempt"),
    )
    monkeypatch.setattr(
        tproxy,
        "write_status",
        lambda state, iface, voice_iface: calls.append(
            ("status", state, iface, voice_iface)
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "write_startup_status",
        lambda: calls.append(("startup_status",)),
    )
    monkeypatch.setattr(tproxy, "_start_network_monitor", lambda *_args: None)

    with pytest.raises(RuntimeError, match="stop test server"):
        asyncio.run(tproxy.amain(1080, voice=False))

    assert "pf_arm_attempt" not in calls
    assert calls == [
        ("startup_status",),
        ("status", "dormant", "utun7", None),
    ]


def test_shutdown_clears_pf_before_draining_accepted_connections(monkeypatch):
    calls = []

    class Server:
        async def __aenter__(self):
            calls.append("enter")
            return self

        async def __aexit__(self, *_args):
            calls.append("exit")
            return False

        async def serve_forever(self):
            await asyncio.Future()

        def close(self):
            calls.append("listener_closed")

        async def wait_closed(self):
            calls.append("listener_waited")

    class AuxiliaryServer:
        async def close(self):
            calls.append("auxiliary_closed")

    async def wait_for_drain(timeout):
        calls.append(("drain", timeout))
        return False

    async def cancel_connections():
        calls.append("connections_closed")
        return 1

    async def exercise():
        shutdown = asyncio.Event()
        shutdown.set()
        return await tproxy.serve_until_shutdown(
            Server(),
            shutdown,
            drain_timeout=3.5,
            auxiliary_servers=(AuxiliaryServer(),),
        )

    monkeypatch.setattr(
        tproxy,
        "pf_teardown",
        lambda: calls.append("pf_cleared") or True,
    )
    monkeypatch.setattr(tproxy, "wait_for_connections_to_drain", wait_for_drain)
    monkeypatch.setattr(tproxy, "cancel_active_connections", cancel_connections)

    assert not asyncio.run(exercise())
    assert calls == [
        "enter",
        "auxiliary_closed",
        "pf_cleared",
        "listener_closed",
        "listener_waited",
        ("drain", 3.5),
        "connections_closed",
        "exit",
    ]


def test_shutdown_request_is_visible_before_async_drain_starts():
    async def exercise():
        shutdown = asyncio.Event()
        tproxy.request_daemon_shutdown(shutdown)
        return (
            shutdown.is_set(),
            tproxy._shutdown_started.is_set(),
            tproxy._pf_teardown_complete.is_set(),
        )

    assert asyncio.run(exercise()) == (True, True, False)


def test_connection_drain_is_bounded(monkeypatch):
    async def exercise():
        tproxy._conn_count = 1
        loop = asyncio.get_running_loop()
        loop.call_later(0.02, setattr, tproxy, "_conn_count", 0)
        return await tproxy.wait_for_connections_to_drain(timeout=0.2)

    try:
        assert asyncio.run(exercise())
        tproxy._conn_count = 1
        assert not asyncio.run(tproxy.wait_for_connections_to_drain(timeout=0.0))
    finally:
        tproxy._conn_count = 0


def test_connection_drain_waits_for_a_stable_zero_count():
    async def exercise():
        tproxy._conn_count = 0
        loop = asyncio.get_running_loop()
        loop.call_soon(setattr, tproxy, "_conn_count", 1)
        loop.call_later(0.02, setattr, tproxy, "_conn_count", 0)
        started = loop.time()
        drained = await tproxy.wait_for_connections_to_drain(timeout=0.3)
        return drained, loop.time() - started

    try:
        drained, elapsed = asyncio.run(exercise())
        assert drained
        assert elapsed >= tproxy.SHUTDOWN_DRAIN_QUIET_SECONDS
    finally:
        tproxy._conn_count = 0


def test_cancel_active_connections_awaits_only_owned_handler_tasks():
    async def exercise():
        cancelled = asyncio.Event()

        async def connection():
            task = asyncio.current_task()
            tproxy._connection_tasks.add(task)
            try:
                await asyncio.Future()
            finally:
                tproxy._connection_tasks.discard(task)
                cancelled.set()

        task = asyncio.create_task(connection())
        await asyncio.sleep(0)
        count = await tproxy.cancel_active_connections()
        await asyncio.gather(task, return_exceptions=True)
        return count, cancelled.is_set(), len(tproxy._connection_tasks)

    assert asyncio.run(exercise()) == (1, True, 0)


def test_geo_exit_backend_hold_requires_fresh_probe_after_cooldown(monkeypatch):
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 130.0)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_reason", "runtime miss")

    assert not tproxy.geo_exit_backend_ready(now=120.0)
    assert tproxy.geo_exit_backend_ready(now=131.0)
    assert tproxy._geph_backend_hold_until == 0.0
    assert tproxy._geph_backend_hold_reason == ""


def test_network_monitor_keeps_local_routing_active_when_geph_is_not_ready(monkeypatch):
    pauses = []
    arms = []
    states = []
    rearms = []

    def pause():
        pauses.append(True)
        tproxy._pf_applied = False
        return True

    def arm(pf_port):
        arms.append(pf_port)
        tproxy._pf_applied = True
        return True

    def write_status_and_stop(state, iface, voice_iface):
        states.append((state, iface, voice_iface))
        tproxy._shutdown_started.set()

    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_pf_interceptor_conflicts", [])
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "default_iface", lambda: "en0")
    monkeypatch.setattr(tproxy, "probe_geph", lambda: False)
    monkeypatch.setattr(tproxy, "pause_private_pf", pause)
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(tproxy, "arm_private_pf_if_ready", arm)
    monkeypatch.setattr(
        tproxy,
        "write_status",
        write_status_and_stop,
    )
    monkeypatch.setattr(tproxy, "start_canaries_if_due", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        tproxy,
        "note_runtime_rearm",
        lambda reason, **kwargs: rearms.append((reason, kwargs.get("iface"))),
    )
    monkeypatch.setattr(
        tproxy,
        "start_route_policy_remote_update_if_due",
        lambda *_args, **_kwargs: None,
    )
    tproxy._queue_runtime_rearm("network_change")

    tproxy.network_monitor(1080, voice=False)

    assert pauses == [True]
    assert arms == [1080]
    assert states == [("active", "en0", None)]
    assert rearms == [("network_change", "en0")]


def test_network_monitor_retries_pending_confirmation_on_owned_geph_recovery(
    monkeypatch,
):
    retries = []
    deferred_retries = []

    def write_status_and_stop(_state, _iface, _voice_iface):
        tproxy._shutdown_started.set()

    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_pf_interceptor_conflicts", [])
    monkeypatch.setattr(tproxy, "default_iface", lambda: "en0")
    monkeypatch.setattr(tproxy, "execute_owned_geph_restart", lambda **_kwargs: "idle")
    monkeypatch.setattr(tproxy, "probe_geph", lambda: True)
    monkeypatch.setattr(
        tproxy,
        "retry_pending_auto_geph_confirmations",
        lambda: retries.append(True),
    )
    monkeypatch.setattr(
        tproxy,
        "_retry_pending_auto_geph_confirmations_after_drain",
        lambda: deferred_retries.append(True),
    )
    monkeypatch.setattr(tproxy, "pf_preceding_https_interceptors", lambda: [])
    monkeypatch.setattr(tproxy, "refresh_fd_pressure", lambda: None)
    monkeypatch.setattr(tproxy, "transparent_routing_ready", lambda: True)
    monkeypatch.setattr(tproxy, "_pf_loopback_skip_state", lambda: False)
    monkeypatch.setattr(tproxy, "pf_has_rules", lambda _port: True)
    monkeypatch.setattr(tproxy, "write_status", write_status_and_stop)
    monkeypatch.setattr(tproxy, "start_canaries_if_due", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        tproxy,
        "start_route_policy_remote_update_if_due",
        lambda *_args, **_kwargs: None,
    )

    tproxy.network_monitor(1080, voice=False)

    assert retries == [True]
    assert deferred_retries == [True]


def test_network_monitor_yields_to_user_full_tunnel_vpn_without_geph(monkeypatch):
    pauses = []
    arms = []
    states = []

    def pause():
        pauses.append(tproxy.PF_ANCHOR)
        tproxy._pf_applied = False
        return True

    def write_status_and_stop(state, iface, voice_iface):
        states.append((state, iface, voice_iface))
        tproxy._shutdown_started.set()

    monkeypatch.setattr(tproxy, "GEPH_ENABLED", False)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_pf_interceptor_conflicts", [])
    monkeypatch.setattr(tproxy, "default_iface", lambda: "utun7")
    monkeypatch.setattr(tproxy, "probe_geph", lambda: False)
    monkeypatch.setattr(tproxy, "pause_private_pf", pause)
    monkeypatch.setattr(
        tproxy,
        "arm_private_pf_if_ready",
        lambda _port: arms.append(True) or True,
    )
    monkeypatch.setattr(tproxy, "execute_owned_geph_restart", lambda **_kwargs: "idle")
    monkeypatch.setattr(tproxy, "refresh_fd_pressure", lambda: False)
    monkeypatch.setattr(tproxy, "write_status", write_status_and_stop)
    monkeypatch.setattr(tproxy, "start_canaries_if_due", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        tproxy,
        "start_route_policy_remote_update_if_due",
        lambda *_args, **_kwargs: None,
    )

    tproxy.network_monitor(1080, voice=False)

    assert pauses == [tproxy.PF_ANCHOR]
    assert arms == []
    assert states == [("dormant", "utun7", None)]


def test_network_monitor_reclaims_reasserted_loopback_skip(monkeypatch):
    events = []
    states = []

    def pause():
        events.append("pause")
        tproxy._pf_applied = False
        return True

    def arm(port):
        events.append(("arm", port))
        tproxy._pf_applied = True
        return True

    def write_status_and_stop(state, iface, voice_iface):
        states.append((state, iface, voice_iface))
        tproxy._shutdown_started.set()

    monkeypatch.setattr(tproxy, "GEPH_ENABLED", False)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_pf_interceptor_conflicts", [])
    monkeypatch.setattr(tproxy, "default_iface", lambda: "en0")
    monkeypatch.setattr(tproxy, "probe_geph", lambda: False)
    monkeypatch.setattr(tproxy, "refresh_fd_pressure", lambda: False)
    monkeypatch.setattr(tproxy, "pf_preceding_https_interceptors", lambda: [])
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(tproxy, "pf_has_rules", lambda _port: True)
    monkeypatch.setattr(tproxy, "_pf_loopback_skip_state", lambda: True)
    monkeypatch.setattr(tproxy, "pause_private_pf", pause)
    monkeypatch.setattr(tproxy, "arm_private_pf_if_ready", arm)
    monkeypatch.setattr(tproxy, "write_status", write_status_and_stop)
    monkeypatch.setattr(tproxy, "start_canaries_if_due", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        tproxy,
        "start_route_policy_remote_update_if_due",
        lambda *_args, **_kwargs: None,
    )

    tproxy.network_monitor(1080, voice=False)

    assert events == ["pause", ("arm", 1080)]
    assert states == [("active", "en0", None)]


def test_network_monitor_does_not_rearm_after_shutdown_starts(monkeypatch):
    calls = []
    tproxy._shutdown_started.set()
    monkeypatch.setattr(
        tproxy,
        "default_iface",
        lambda: calls.append("default_iface"),
    )
    monkeypatch.setattr(
        tproxy,
        "arm_private_pf_if_ready",
        lambda _port: calls.append("arm_pf"),
    )
    monkeypatch.setattr(
        tproxy,
        "execute_owned_geph_restart",
        lambda **_kwargs: calls.append("restart_geph"),
    )

    tproxy.network_monitor(1080, voice=False)

    assert calls == []


def test_runtime_pf_arm_does_not_depend_on_geph_after_loading_rules(monkeypatch):
    calls = []

    def load(_port):
        calls.append("load")
        tproxy._geph_up = False
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_pf_applied", False)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(tproxy, "_pf_acquire_enable_token", lambda: True)
    monkeypatch.setattr(tproxy, "_pf_load", load)
    monkeypatch.setattr(
        tproxy,
        "_claim_pf_loopback_skip",
        lambda: calls.append("claim-loopback") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: calls.append("flush") or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: calls.append("release") or SimpleNamespace(returncode=0),
    )

    assert tproxy.arm_private_pf_if_ready(1080)
    assert calls == ["load", "claim-loopback"]
    assert tproxy._pf_applied is True


def test_pf_arm_rolls_back_if_loopback_skip_cannot_be_claimed(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy.time, "time", lambda: 100.0)
    monkeypatch.setattr(tproxy, "_pf_applied", False)
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(
        tproxy,
        "_pf_acquire_enable_token",
        lambda: calls.append("token") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_load",
        lambda _port: calls.append("load") or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        tproxy,
        "_claim_pf_loopback_skip",
        lambda: calls.append("claim-loopback") or False,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: calls.append("flush") or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        tproxy,
        "_restore_pf_loopback_skip",
        lambda: calls.append("restore-loopback") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: calls.append("release") or SimpleNamespace(returncode=0),
    )

    assert not tproxy.arm_private_pf_if_ready(1080)
    assert calls == [
        "token",
        "load",
        "claim-loopback",
        "flush",
        "restore-loopback",
        "release",
    ]
    assert not tproxy._pf_applied
    snapshot = tproxy.baseline_guard_snapshot(now=100.0)
    assert snapshot["state"] == "retry"
    assert snapshot["reason"] == tproxy.PF_LOOPBACK_UNAVAILABLE_REASON


def test_baseline_guard_rolls_back_private_pf_and_blocks_repeat_arm(monkeypatch):
    calls = []
    candidate = tproxy.install_guard.BaselineCandidate(
        "example.com", "203.0.113.10", "/"
    )
    monkeypatch.setattr(
        tproxy,
        "_baseline_preflight",
        lambda: (
            tproxy.install_guard.QualificationResult(True, "ok", (candidate,)),
            (501, 20, "/Users/fixture"),
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_baseline_postflight",
        lambda *_args: tproxy.install_guard.QualificationResult(
            False, tproxy.BASELINE_GUARD_BLOCK_REASON, (candidate,)
        ),
    )
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(
        tproxy,
        "_pf_acquire_enable_token",
        lambda: calls.append("token") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_load",
        lambda _port: calls.append("load") or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: calls.append("flush") or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: calls.append("release") or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        tproxy,
        "_restore_pf_loopback_skip",
        lambda: calls.append("restore-loopback") or True,
    )

    assert not tproxy.arm_private_pf_if_ready(1080)
    assert calls == ["token", "load", "flush", "restore-loopback", "release"]
    assert tproxy._pf_applied is False
    assert tproxy.baseline_guard_snapshot()["state"] == "blocked"
    assert not tproxy.transparent_routing_ready()

    assert not tproxy.arm_private_pf_if_ready(1080)
    assert calls == ["token", "load", "flush", "restore-loopback", "release"]


def test_baseline_probe_log_records_bounded_private_evidence(capsys):
    candidate = tproxy.install_guard.BaselineCandidate(
        "example.com", "203.0.113.10", "/"
    )
    result = tproxy.install_guard.ProbeResult(
        False,
        "x" * 120,
    )

    tproxy._log_baseline_probe_results("after PF", ((candidate, result),))

    line = capsys.readouterr().err.strip()
    assert line.startswith(
        ">> HTTPS baseline after PF: example.com (203.0.113.10) -> "
    )
    assert line.endswith("x" * 80)


def test_baseline_guard_keeps_listener_owned_until_pf_rollback_succeeds(monkeypatch):
    calls = []
    candidate = tproxy.install_guard.BaselineCandidate(
        "example.com", "203.0.113.10", "/"
    )
    monkeypatch.setattr(
        tproxy,
        "_baseline_preflight",
        lambda: (
            tproxy.install_guard.QualificationResult(True, "ok", (candidate,)),
            (501, 20, "/Users/fixture"),
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_baseline_postflight",
        lambda *_args: tproxy.install_guard.QualificationResult(
            False, tproxy.BASELINE_GUARD_BLOCK_REASON, (candidate,)
        ),
    )
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(
        tproxy,
        "_pf_acquire_enable_token",
        lambda: calls.append("token") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_load",
        lambda _port: calls.append("load") or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: calls.append("flush") or SimpleNamespace(returncode=1),
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_release_enable_token",
        lambda: calls.append("release") or None,
    )

    assert not tproxy.arm_private_pf_if_ready(1080)
    assert calls == ["token", "load", "flush", "flush", "flush"]
    assert tproxy._pf_applied is True
    snapshot = tproxy.baseline_guard_snapshot()
    assert snapshot["state"] == "rollback_failed"
    assert snapshot["reason"] == tproxy.BASELINE_GUARD_ROLLBACK_REASON

    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: calls.append("flush_ok") or SimpleNamespace(returncode=0),
    )
    assert tproxy.retry_baseline_rollback()
    assert calls[-2:] == ["flush_ok", "release"]
    assert tproxy._pf_applied is False
    assert tproxy.baseline_guard_snapshot()["state"] == "blocked"


def test_baseline_preflight_failure_never_loads_pf_and_retries_later(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy.time, "time", lambda: 100.0)
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(
        tproxy,
        "_baseline_preflight",
        lambda: (
            tproxy.install_guard.QualificationResult(
                False, "baseline_preflight_unavailable"
            ),
            (501, 20, "/Users/fixture"),
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_acquire_enable_token",
        lambda: calls.append("token") or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_pf_load",
        lambda _port: calls.append("load") or SimpleNamespace(returncode=0),
    )

    assert not tproxy.arm_private_pf_if_ready(1080)
    assert calls == []
    snapshot = tproxy.baseline_guard_snapshot(now=100.0)
    assert snapshot["state"] == "retry"
    assert snapshot["retry_at"] == 100.0 + tproxy.BASELINE_GUARD_RETRY_SECONDS
    assert not tproxy._baseline_guard_allows_attempt(now=129.99)
    assert tproxy._baseline_guard_allows_attempt(now=130.0)


def test_runtime_network_change_resets_a_blocked_baseline_guard(monkeypatch):
    tproxy._set_baseline_guard(
        "blocked", tproxy.BASELINE_GUARD_BLOCK_REASON, now=90.0
    )
    monkeypatch.setattr(tproxy, "note_runtime_rearm", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "start_canaries_if_due", lambda *_args, **_kwargs: None)

    tproxy._apply_runtime_rearm("network_change", now=100.0, iface="en0")

    assert tproxy.baseline_guard_snapshot(now=100.0)["state"] == "pending"
    assert tproxy.transparent_routing_ready()


def test_suspend_geo_exit_backend_keeps_private_anchor_active(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_reason", "")
    monkeypatch.setattr(
        tproxy, "pause_private_pf", lambda: calls.append("paused") or True
    )

    assert tproxy.suspend_geo_exit_backend("geo-exit tunnel down", now=100.0)
    assert calls == []
    assert tproxy._pf_applied is True
    assert tproxy._geph_up is False
    assert tproxy._geph_backend_hold_until == 100.0 + tproxy.GEPH_BACKEND_FAILURE_HOLD
    assert tproxy._geph_backend_hold_reason == "geo-exit tunnel down"


def test_suspend_geo_exit_backend_is_idempotent_when_already_down(monkeypatch):
    monkeypatch.setattr(tproxy, "_pf_applied", False)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)

    assert tproxy.suspend_geo_exit_backend("geo-exit tunnel down", now=100.0)
    assert tproxy._pf_applied is False


def test_pf_lifecycle_functions_are_not_shadowed_by_later_definitions():
    module = ast.parse(Path(tproxy.__file__).read_text())
    names = [node.name for node in module.body if isinstance(node, ast.FunctionDef)]

    for name in (
        "geo_exit_backend_ready",
        "transparent_routing_ready",
        "pause_private_pf",
        "suspend_geo_exit_backend",
        "pf_setup_if_ready",
    ):
        assert names.count(name) == 1, name


def test_explicit_local_only_mode_preserves_geo_policy_and_local_pf(monkeypatch):
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", False)
    monkeypatch.setattr(tproxy, "_fd_pressure", False)

    assert tproxy.is_geo_exit_route("chatgpt.com")
    assert not tproxy.geo_exit_backend_ready(now=100.0)
    assert tproxy.transparent_routing_ready()


def test_unavailable_geph_keeps_geo_policy_without_disarming_local_pf(monkeypatch):
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)

    assert tproxy.is_geo_exit_route("chatgpt.com")
    assert not tproxy.geo_exit_backend_ready(now=100.0)
    assert tproxy.route_policy("chatgpt.com")["route_class"] == tproxy.ROUTE_GEO_EXIT


def test_geo_exit_tunnel_down_cools_geph_but_keeps_private_pf(monkeypatch):
    class Reader:
        def __init__(self):
            self.parts = [b"\x16\x03\x01\x00\x01", b"x"]

        async def readexactly(self, _size):
            return self.parts.pop(0)

    class Writer:
        def __init__(self):
            self.closed = False

        def get_extra_info(self, _name):
            return object()

        def close(self):
            self.closed = True

    suspended = []
    writer = Writer()

    async def direct_miss(*_args, **_kwargs):
        return None

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.8", 443))
    monkeypatch.setattr(tproxy, "parse_sni", lambda _body: "chatgpt.com")
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "log_geph_route_failure", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "suspend_geo_exit_backend", suspended.append)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "dial_plain", direct_miss)

    asyncio.run(tproxy._handle_impl(Reader(), writer))

    assert suspended == ["geo-exit tunnel down"]
    assert writer.closed is True


def test_geph_runtime_first_payload_guard_closes_a_stalled_stream(monkeypatch):
    class UpReader:
        async def read(self, _size):
            await asyncio.Event().wait()

    class UpWriter:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

        async def wait_closed(self):
            return None

    up_writer = UpWriter()

    async def connected(*_args):
        return UpReader(), up_writer

    monkeypatch.setattr(tproxy, "dial_via_geph", connected)

    result, reason = asyncio.run(
        tproxy._dial_via_geph_first_payload(
            "store.steampowered.com",
            443,
            b"client-hello",
            timeout=0.01,
        )
    )

    assert result is None
    assert reason == "first payload timeout"
    assert up_writer.closed is True


def test_geo_exit_commits_geph_only_after_first_target_payload(monkeypatch):
    class Reader:
        def __init__(self):
            self.parts = [b"\x16\x03\x01\x00\x01", b"x"]

        async def readexactly(self, _size):
            return self.parts.pop(0)

    class Writer:
        def __init__(self):
            self.writes = []

        def get_extra_info(self, _name):
            return object()

        def write(self, data):
            self.writes.append(data)

        async def drain(self):
            return None

    async def geph_ready(*_args):
        return (object(), object(), b"server-first"), None

    relay_activity = []

    async def relay(*_args):
        relay_activity.append(_args[4])
        return 0, 0

    async def system_should_not_run(*_args):
        raise AssertionError("healthy Geph unexpectedly fell back to system route")

    failures = []
    cleared = []
    suspended = []
    circuit_results = []
    writer = Writer()
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.8", 443))
    monkeypatch.setattr(tproxy, "parse_sni", lambda _body: "chatgpt.com")
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "_dial_via_geph_first_payload", geph_ready)
    monkeypatch.setattr(tproxy, "relay_local_stream", relay)
    monkeypatch.setattr(tproxy, "_try_system_geo_connect", system_should_not_run)
    monkeypatch.setattr(tproxy, "geo_exit_backend_ready", lambda now=None: True)
    monkeypatch.setattr(tproxy, "_geph_session_started", lambda: True)
    monkeypatch.setattr(tproxy, "_geph_session_finished", lambda: None)
    monkeypatch.setattr(tproxy, "runtime_route_circuit_allows", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        tproxy,
        "runtime_route_circuit_record_result",
        lambda _policy, _backend, ok, **_kwargs: circuit_results.append(ok),
    )
    monkeypatch.setattr(
        tproxy,
        "log_geph_route_failure",
        lambda host, reason: failures.append((host, reason)),
    )
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: cleared.append(True))
    monkeypatch.setattr(tproxy, "suspend_geo_exit_backend", suspended.append)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    asyncio.run(tproxy._handle_impl(Reader(), writer))

    assert writer.writes == [b"server-first"]
    assert circuit_results == [True]
    assert cleared == [True]
    assert failures == []
    assert suspended == []
    assert len(relay_activity) == 1
    assert relay_activity[0].downstream_bytes == len(b"server-first")
    assert relay_activity[0].first_downstream_seen is True


def test_geo_exit_external_geph_preserves_streaming_relay(monkeypatch):
    class Reader:
        def __init__(self):
            self.parts = [b"\x16\x03\x01\x00\x01", b"x"]

        async def readexactly(self, _size):
            return self.parts.pop(0)

    class Writer:
        def get_extra_info(self, _name):
            return object()

    circuit_results = []
    relays = []
    cleared = []

    async def connected(*_args):
        return object(), object()

    async def owned_gate_must_not_run(*_args):
        raise AssertionError("external Geph entered the owned first-payload gate")

    async def relay(*_args):
        relays.append(_args[4])
        return 0, 1

    async def system_should_not_run(*_args):
        raise AssertionError("healthy external Geph unexpectedly used system route")

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.8", 443))
    monkeypatch.setattr(tproxy, "parse_sni", lambda _body: "chatgpt.com")
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "dial_via_geph", connected)
    monkeypatch.setattr(
        tproxy,
        "_dial_via_geph_first_payload",
        owned_gate_must_not_run,
    )
    monkeypatch.setattr(tproxy, "relay_local_stream", relay)
    monkeypatch.setattr(tproxy, "_try_system_geo_connect", system_should_not_run)
    monkeypatch.setattr(tproxy, "geo_exit_backend_ready", lambda now=None: True)
    monkeypatch.setattr(tproxy, "_geph_session_started", lambda: True)
    monkeypatch.setattr(tproxy, "_geph_session_finished", lambda: None)
    monkeypatch.setattr(
        tproxy, "runtime_route_circuit_allows", lambda *_args, **_kwargs: True
    )
    monkeypatch.setattr(
        tproxy,
        "runtime_route_circuit_record_result",
        lambda _policy, _backend, ok, **_kwargs: circuit_results.append(ok),
    )
    monkeypatch.setattr(
        tproxy,
        "clear_geph_route_failure",
        lambda: cleared.append(True),
    )
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", False)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_EXTERNAL_PORT)

    asyncio.run(tproxy._handle_impl(Reader(), Writer()))

    assert circuit_results == [True]
    assert cleared == [True]
    assert len(relays) == 1
    assert relays[0].on_first_downstream is not None


def test_geo_exit_cancellation_while_delivering_first_payload_closes_geph(
    monkeypatch,
):
    class Reader:
        def __init__(self):
            self.parts = [b"\x16\x03\x01\x00\x01", b"x"]

        async def readexactly(self, _size):
            return self.parts.pop(0)

    class ClientWriter:
        def get_extra_info(self, _name):
            return object()

        def write(self, _data):
            return None

        async def drain(self):
            await asyncio.Event().wait()

    class GephWriter:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

        async def wait_closed(self):
            return None

    geph_writer = GephWriter()

    async def geph_ready(*_args):
        return (object(), geph_writer, b"server-first"), None

    async def exercise():
        task = asyncio.create_task(tproxy._handle_impl(Reader(), ClientWriter()))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.8", 443))
    monkeypatch.setattr(tproxy, "parse_sni", lambda _body: "chatgpt.com")
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "_dial_via_geph_first_payload", geph_ready)
    monkeypatch.setattr(tproxy, "geo_exit_backend_ready", lambda now=None: True)
    monkeypatch.setattr(tproxy, "_geph_session_started", lambda: True)
    monkeypatch.setattr(tproxy, "_geph_session_finished", lambda: None)
    monkeypatch.setattr(
        tproxy, "runtime_route_circuit_allows", lambda *_args, **_kwargs: True
    )
    monkeypatch.setattr(
        tproxy,
        "runtime_route_circuit_record_result",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: None)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    asyncio.run(exercise())

    assert geph_writer.closed is True


def test_geo_exit_first_payload_timeout_falls_back_on_same_request(monkeypatch):
    class Reader:
        def __init__(self):
            self.parts = [b"\x16\x03\x01\x00\x01", b"x"]

        async def readexactly(self, _size):
            return self.parts.pop(0)

    class Writer:
        def get_extra_info(self, _name):
            return object()

    events = []
    circuit_results = []

    async def stalled_geph(*_args):
        return None, "first payload timeout"

    async def system_route(host, ip, port, first_flight, *_args):
        events.append(("system", host, ip, port, first_flight))
        return True

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.8", 443))
    monkeypatch.setattr(tproxy, "parse_sni", lambda _body: "chatgpt.com")
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "_dial_via_geph_first_payload", stalled_geph)
    monkeypatch.setattr(tproxy, "_try_system_geo_connect", system_route)
    monkeypatch.setattr(tproxy, "geo_exit_backend_ready", lambda now=None: True)
    monkeypatch.setattr(tproxy, "_geph_session_started", lambda: True)
    monkeypatch.setattr(tproxy, "_geph_session_finished", lambda: None)
    monkeypatch.setattr(tproxy, "runtime_route_circuit_allows", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        tproxy,
        "runtime_route_circuit_record_result",
        lambda _policy, _backend, ok, **_kwargs: circuit_results.append(ok),
    )
    def log_failure(host, reason):
        assert tproxy._geph_up is True
        events.append(("failure", host, reason))

    def suspend(reason):
        events.append(("suspend", reason))
        tproxy._geph_up = False

    monkeypatch.setattr(tproxy, "log_geph_route_failure", log_failure)
    monkeypatch.setattr(tproxy, "suspend_geo_exit_backend", suspend)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    asyncio.run(tproxy._handle_impl(Reader(), Writer()))

    assert circuit_results == [False]
    assert events == [
        ("failure", "chatgpt.com", "first payload timeout"),
        ("suspend", "geo-exit first payload unavailable"),
        (
            "system",
            "chatgpt.com",
            "203.0.113.8",
            443,
            b"\x16\x03\x01\x00\x01x",
        ),
    ]


def test_route_policy_classifies_service_groups():
    assert tproxy.route_policy("updates.discord.com") == {
        "host": "updates.discord.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_DISCORD,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert tproxy.route_policy("status.discordstatus.com") == {
        "host": "status.discordstatus.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_DISCORD,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert tproxy.route_policy("rr2---sn-ntq7yner.googlevideo.com") == {
        "host": "rr2---sn-ntq7yner.googlevideo.com",
        "route_class": tproxy.ROUTE_DIRECT_FIRST,
        "service_group": tproxy.SERVICE_YOUTUBE,
        "strategy_set": tproxy.STRATEGY_DIRECT_FIRST,
    }
    assert tproxy.route_policy("youtu.be")["service_group"] == tproxy.SERVICE_YOUTUBE
    assert tproxy.route_policy("yt3.ggpht.com")["service_group"] == tproxy.SERVICE_YOUTUBE
    assert tproxy.route_policy("billing.openai.com")["route_class"] == tproxy.ROUTE_GEO_EXIT
    assert tproxy.route_policy("claude.ai")["service_group"] == tproxy.SERVICE_ANTHROPIC
    assert tproxy.route_policy("t.me")["service_group"] == tproxy.SERVICE_TELEGRAM
    assert tproxy.route_policy("store.steampowered.com") == {
        "host": "store.steampowered.com",
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "service_group": tproxy.SERVICE_STEAM_STORE,
        "strategy_set": tproxy.STRATEGY_GEPH,
    }
    assert tproxy.route_policy("cdn.fastly.steamstatic.com")["service_group"] == (
        tproxy.SERVICE_STEAM_STORE
    )
    assert tproxy.route_policy("steamcdn-a.akamaihd.net")["service_group"] == (
        tproxy.SERVICE_STEAM_STORE
    )
    assert tproxy.route_policy("cmp1-fra1.steamserver.net")["route_class"] == (
        tproxy.ROUTE_UNKNOWN
    )
    assert tproxy.route_policy("github.com") == {
        "host": "github.com",
        "route_class": tproxy.ROUTE_DIRECT,
        "service_group": tproxy.SERVICE_GITHUB,
        "strategy_set": tproxy.STRATEGY_DIRECT,
    }
    assert tproxy.route_policy("objects.githubusercontent.com")["service_group"] == (
        tproxy.SERVICE_GITHUB
    )
    assert tproxy.route_policy("www.google.com") == {
        "host": "www.google.com",
        "route_class": tproxy.ROUTE_DIRECT_FIRST,
        "service_group": tproxy.SERVICE_GOOGLE,
        "strategy_set": tproxy.STRATEGY_DIRECT_FIRST,
    }
    assert tproxy.route_policy("gue1-spclient.spotify.com")["service_group"] == (
        tproxy.SERVICE_SPOTIFY
    )
    assert tproxy.route_policy("i.scdn.co")["route_class"] == tproxy.ROUTE_DIRECT_FIRST


def test_route_policy_tables_are_explicit_and_keep_boundaries():
    static = {
        (policy["service_group"], policy["route_class"], policy["strategy_set"])
        for policy in tproxy.ROUTE_POLICY_TABLE
    }
    geo = {
        policy["service_group"]
        for policy in tproxy.GEO_EXIT_POLICY_TABLE
    }

    assert (
        tproxy.SERVICE_DISCORD,
        tproxy.ROUTE_LOCAL_BYPASS,
        tproxy.STRATEGY_FAKE_ONLY,
    ) in static
    assert (
        tproxy.SERVICE_YOUTUBE,
        tproxy.ROUTE_LOCAL_BYPASS,
        tproxy.STRATEGY_FAKE_ONLY,
    ) in static
    assert (
        tproxy.SERVICE_TELEGRAM,
        tproxy.ROUTE_DIRECT,
        tproxy.STRATEGY_DIRECT,
    ) in static
    assert (
        tproxy.SERVICE_GITHUB,
        tproxy.ROUTE_DIRECT,
        tproxy.STRATEGY_DIRECT,
    ) in static
    assert (
        tproxy.SERVICE_GOOGLE,
        tproxy.ROUTE_DIRECT_FIRST,
        tproxy.STRATEGY_DIRECT_FIRST,
    ) in static
    assert (
        tproxy.SERVICE_SPOTIFY,
        tproxy.ROUTE_DIRECT_FIRST,
        tproxy.STRATEGY_DIRECT_FIRST,
    ) in static
    assert tproxy.SERVICE_DISCORD not in geo
    assert tproxy.SERVICE_YOUTUBE not in geo
    assert tproxy.SERVICE_OPENAI in geo
    assert tproxy.SERVICE_STEAM_STORE in geo
    assert "discord.com" not in tproxy.GEPH_HOSTS
    assert "youtube.com" not in tproxy.GEPH_HOSTS


def test_direct_and_direct_first_hosts_keep_plain_first():
    tproxy._strat_cache["www.google.com"] = "split64+fake"
    tproxy._strat_cache["api.spotify.com"] = "split64+fake"
    try:
        assert [s["name"] for s in tproxy.strategy_order("github.com")] == ["plain"]
        assert [s["name"] for s in tproxy.strategy_order("t.me")] == ["plain"]
        assert [s["name"] for s in tproxy.strategy_order("yandex.ru")] == ["plain"]
        assert [s["name"] for s in tproxy.strategy_order(
            "rr2---sn-ntq7yner.googlevideo.com"
        )][0] == "plain"
        assert [s["name"] for s in tproxy.strategy_order("www.google.com")][:2] == [
            "plain", "split64+fake",
        ]
        assert [s["name"] for s in tproxy.strategy_order("api.spotify.com")][:2] == [
            "plain", "split64+fake",
        ]
        assert [s["name"] for s in tproxy.strategy_order("i.scdn.co")][0] == "plain"
        assert not tproxy.is_geo_exit_route("www.google.com")
        assert not tproxy.is_geo_exit_route("api.spotify.com")
        assert not tproxy.is_geo_exit_route("i.scdn.co")
    finally:
        tproxy._strat_cache.clear()


def test_route_policy_manifest_has_stable_diagnostic_shape():
    manifest = tproxy.route_policy_manifest()
    status = tproxy.route_policy_status_snapshot()

    assert manifest["version"] == tproxy.ROUTE_POLICY_VERSION
    assert manifest["source"] == tproxy.ROUTE_POLICY_SOURCE
    assert status["version"] == tproxy.ROUTE_POLICY_VERSION
    assert status["source"] == tproxy.ROUTE_POLICY_SOURCE
    assert status["sha256"] == tproxy.route_policy_hash(manifest)
    assert len(status["sha256"]) == 64
    assert status["attempt_limits"]["default"] == tproxy.DEFAULT_IP_ATTEMPT_LIMIT
    assert status["attempt_limits"][tproxy.ROUTE_LOCAL_BYPASS] == (
        tproxy.LOCAL_BYPASS_IP_ATTEMPT_LIMIT
    )

    static_groups = {policy["service_group"] for policy in manifest["static_routes"]}
    geo_groups = {policy["service_group"] for policy in manifest["geo_exit_routes"]}
    assert tproxy.SERVICE_DISCORD in static_groups
    assert tproxy.SERVICE_YOUTUBE in static_groups
    assert tproxy.SERVICE_TELEGRAM in static_groups
    assert tproxy.SERVICE_GITHUB in static_groups
    assert tproxy.SERVICE_GOOGLE in static_groups
    assert tproxy.SERVICE_SPOTIFY in static_groups
    assert tproxy.SERVICE_OPENAI in geo_groups
    assert tproxy.SERVICE_ANTHROPIC in geo_groups
    assert tproxy.SERVICE_STEAM_STORE in geo_groups
    assert tproxy.SERVICE_DISCORD not in geo_groups
    assert tproxy.SERVICE_YOUTUBE not in geo_groups

    assert status["domains"][tproxy.ROUTE_DIRECT] == (
        len(tproxy.TELEGRAM_HOSTS)
        + len(tproxy.GITHUB_HOSTS)
    )
    assert status["domains"][tproxy.ROUTE_DIRECT_FIRST] == (
        len(tproxy.DIRECT_FIRST_HOSTS)
    )
    assert status["domains"][tproxy.ROUTE_LOCAL_BYPASS] == (
        len(tproxy.DISCORD_HOSTS) + len(tproxy.YOUTUBE_CONTROL_HOSTS)
    )
    assert status["domains"][tproxy.ROUTE_GEO_EXIT] == len(tproxy.GEPH_HOSTS)
    assert status["groups"][tproxy.SERVICE_DISCORD] == {
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
        "domains": len(tproxy.DISCORD_HOSTS),
    }
    assert status["groups"][tproxy.SERVICE_GITHUB] == {
        "route_class": tproxy.ROUTE_DIRECT,
        "strategy_set": tproxy.STRATEGY_DIRECT,
        "domains": len(tproxy.GITHUB_HOSTS),
    }
    assert status["groups"][tproxy.SERVICE_GOOGLE] == {
        "route_class": tproxy.ROUTE_DIRECT_FIRST,
        "strategy_set": tproxy.STRATEGY_DIRECT_FIRST,
        "domains": len(tproxy.GOOGLE_DIRECT_FIRST_HOSTS),
    }
    assert status["groups"][tproxy.SERVICE_SPOTIFY] == {
        "route_class": tproxy.ROUTE_DIRECT_FIRST,
        "strategy_set": tproxy.STRATEGY_DIRECT_FIRST,
        "domains": len(tproxy.SPOTIFY_DIRECT_FIRST_HOSTS),
    }
    assert status["groups"][tproxy.SERVICE_YOUTUBE] == {
        "route_class": "mixed",
        "strategy_set": "mixed",
        "domains": len(tproxy.YOUTUBE_MEDIA_HOSTS) + len(tproxy.YOUTUBE_CONTROL_HOSTS),
        "routes": [
            {
                "route_class": tproxy.ROUTE_DIRECT_FIRST,
                "strategy_set": tproxy.STRATEGY_DIRECT_FIRST,
                "domains": len(tproxy.YOUTUBE_MEDIA_HOSTS),
            },
            {
                "route_class": tproxy.ROUTE_LOCAL_BYPASS,
                "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
                "domains": len(tproxy.YOUTUBE_CONTROL_HOSTS),
            },
        ],
    }
    assert status["groups"][tproxy.SERVICE_OPENAI] == {
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
        "domains": len(tproxy.OPENAI_HOSTS) + 1,
    }


def test_route_policy_manifest_validator_preserves_bundled_manifest():
    manifest = tproxy.route_policy_manifest()
    normalized = tproxy.validate_route_policy_manifest(manifest)

    assert normalized == manifest
    assert tproxy.route_policy_canonical_bytes(manifest) == json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_route_policy_manifest_rejects_protected_group_geph_route():
    manifest = tproxy.route_policy_manifest()
    manifest["geo_exit_routes"].append({
        "domains": ["discord.com"],
        "service_group": tproxy.SERVICE_DISCORD,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })

    with pytest.raises(ValueError, match="discord.*local_bypass"):
        tproxy.validate_route_policy_manifest(manifest)


def test_classify_host_cli_is_read_only_and_does_not_require_root(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [
        "tproxy.py",
        "--classify-host",
        "RR1---SN-Test.GoogleVideo.Com.",
    ])
    monkeypatch.setattr(tproxy.os, "geteuid", lambda: 501)

    tproxy.main()

    assert json.loads(capsys.readouterr().out) == {
        "host": "rr1---sn-test.googlevideo.com",
        "route_class": tproxy.ROUTE_DIRECT_FIRST,
        "service_group": tproxy.SERVICE_YOUTUBE,
        "strategy_set": tproxy.STRATEGY_DIRECT_FIRST,
    }


def test_route_policy_manifest_requires_direct_first_for_google_and_spotify():
    manifest = tproxy.route_policy_manifest()
    google = next(
        entry for entry in manifest["static_routes"]
        if entry["service_group"] == tproxy.SERVICE_GOOGLE
    )
    google["route_class"] = tproxy.ROUTE_DIRECT
    google["strategy_set"] = tproxy.STRATEGY_DIRECT

    with pytest.raises(ValueError, match="protected direct-first domains missing"):
        tproxy.validate_route_policy_manifest(manifest)


def signed_test_policy_bundle(manifest, key_id="test"):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(tproxy.route_policy_canonical_bytes(manifest))
    return (
        {
            "schema": tproxy.ROUTE_POLICY_SCHEMA_VERSION,
            "key_id": key_id,
            "manifest": manifest,
            "signature": base64.b64encode(signature).decode("ascii"),
        },
        {key_id: base64.b64encode(public_key).decode("ascii")},
    )


def test_signed_route_policy_bundle_verifies_and_rejects_tampering():
    manifest = tproxy.route_policy_manifest()
    bundle, public_keys = signed_test_policy_bundle(manifest)

    assert tproxy.verify_signed_route_policy_bundle(bundle, public_keys) == manifest

    tampered = json.loads(json.dumps(bundle))
    tampered["manifest"]["geo_exit_routes"][0]["domains"].append("example.org")
    with pytest.raises(ValueError, match="signature verification failed"):
        tproxy.verify_signed_route_policy_bundle(tampered, public_keys)


def test_apply_route_policy_manifest_updates_lookup_status_and_reset():
    manifest = tproxy.route_policy_manifest()
    manifest["version"] += 1
    manifest["source"] = "signed:test"
    manifest["geo_exit_routes"].append({
        "domains": ["example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    manifest["attempt_limits"][tproxy.ROUTE_GEO_EXIT] = 3

    before = tproxy.route_policy("api.example.org")
    assert before["route_class"] == tproxy.ROUTE_UNKNOWN

    status = tproxy.apply_route_policy_manifest(manifest)

    policy = tproxy.route_policy("api.example.org")
    assert policy == {
        "host": "api.example.org",
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "service_group": tproxy.SERVICE_GENERIC,
        "strategy_set": tproxy.STRATEGY_GEPH,
    }
    assert tproxy.active_geph_hosts()[-1] == "example.org"
    assert tproxy.ip_attempt_limit("api.example.org") == 3
    assert status["source"] == "signed:test"
    assert status["version"] == tproxy.ROUTE_POLICY_VERSION + 1
    assert status["domains"][tproxy.ROUTE_GEO_EXIT] == len(tproxy.GEPH_HOSTS) + 1
    assert status["sha256"] == tproxy.route_policy_hash(manifest)

    reset_status = tproxy.reset_route_policy_manifest()
    assert tproxy.route_policy("api.example.org")["route_class"] == tproxy.ROUTE_UNKNOWN
    assert reset_status["source"] == tproxy.ROUTE_POLICY_SOURCE
    assert reset_status["domains"][tproxy.ROUTE_GEO_EXIT] == len(tproxy.GEPH_HOSTS)


def test_signed_route_policy_health_gate_activates_manifest(tmp_path):
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:test"
    manifest["geo_exit_routes"].append({
        "domains": ["payments.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    bundle, public_keys = signed_test_policy_bundle(manifest)

    status = tproxy.apply_signed_route_policy_bundle_with_health_gate(
        bundle,
        public_keys,
        lambda: True,
        policy_path=str(tmp_path / "route-policy.json"),
        previous_path=str(tmp_path / "route-policy.previous.json"),
        now=100.0,
    )

    assert status["source"] == "signed:test"
    assert tproxy.route_policy("payments.example.org")["route_class"] == (
        tproxy.ROUTE_GEO_EXIT
    )


def test_route_policy_health_evidence_rejects_non_integer_counters():
    evidence = tproxy._route_policy_health_evidence({"ok": 1.5})

    assert evidence.completed is False
    assert evidence.detail == "health gate returned invalid counters"


def test_persisted_route_policy_loads_and_rolls_back(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"

    first = tproxy.route_policy_manifest()
    first["source"] = "signed:first"
    first["geo_exit_routes"].append({
        "domains": ["alpha.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    first_bundle, public_keys = signed_test_policy_bundle(first)

    tproxy.apply_signed_route_policy_bundle_with_health_gate(
        first_bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )
    assert policy_path.exists()
    assert not previous_path.exists()
    assert json.loads(policy_path.read_text())["activation"] == {
        "contract": 1,
        "trial_generation": 1,
    }
    assert tproxy.route_policy("alpha.example.org")["route_class"] == (
        tproxy.ROUTE_GEO_EXIT
    )

    tproxy.reset_route_policy_manifest()
    assert tproxy.route_policy("alpha.example.org")["route_class"] == (
        tproxy.ROUTE_UNKNOWN
    )
    assert tproxy.load_persisted_route_policy(public_keys, policy_path=str(policy_path))
    assert tproxy.route_policy("alpha.example.org")["route_class"] == (
        tproxy.ROUTE_GEO_EXIT
    )
    assert tproxy.route_policy_storage_snapshot()["state"] == "loaded"

    second = tproxy.route_policy_manifest()
    second["source"] = "signed:second"
    second["geo_exit_routes"].append({
        "domains": ["beta.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    second_bundle, second_public_keys = signed_test_policy_bundle(second, key_id="test2")
    public_keys.update(second_public_keys)
    tproxy.apply_signed_route_policy_bundle_with_health_gate(
        second_bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=200.0,
    )

    assert previous_path.exists()
    assert json.loads(policy_path.read_text())["activation"]["trial_generation"] == 2
    assert tproxy.route_policy("beta.example.org")["route_class"] == (
        tproxy.ROUTE_GEO_EXIT
    )
    assert tproxy.rollback_route_policy(
        public_keys,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
    )
    assert tproxy.route_policy("alpha.example.org")["route_class"] == (
        tproxy.ROUTE_GEO_EXIT
    )
    assert tproxy.route_policy("beta.example.org")["route_class"] == tproxy.ROUTE_UNKNOWN
    assert tproxy.route_policy_storage_snapshot()["state"] == "rolled_back"
    assert not previous_path.exists()
    assert json.loads(policy_path.read_text())["activation"]["trial_generation"] == 2


def test_persisted_route_policy_without_activation_metadata_remains_readable(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:legacy"
    bundle, public_keys = signed_test_policy_bundle(manifest)
    state = tproxy.signed_route_policy_state(bundle, public_keys, now=100.0)
    state.pop("activation")
    policy_path.write_text(json.dumps(state))

    assert tproxy.load_persisted_route_policy(
        public_keys,
        policy_path=str(policy_path),
    )
    assert tproxy._route_policy_trial_generation == 0


def test_signed_bundled_content_keeps_signed_provenance_until_rollback(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    bundle, public_keys = signed_test_policy_bundle(
        tproxy.bundled_route_policy_manifest()
    )
    state = tproxy.signed_route_policy_state(
        bundle,
        public_keys,
        now=100.0,
        trial_generation=4,
    )
    policy_path.write_text(json.dumps(state))

    assert tproxy.load_persisted_route_policy(
        public_keys,
        policy_path=str(policy_path),
    )
    assert tproxy._active_route_policy_kind == (
        tproxy.route_policy_activation_contract.POLICY_SIGNED
    )
    assert tproxy.rollback_route_policy(
        public_keys,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
    )
    assert tproxy._active_route_policy_kind == (
        tproxy.route_policy_activation_contract.POLICY_BUNDLED
    )
    assert not policy_path.exists()
    assert not previous_path.exists()


def test_signed_bundled_content_candidate_is_a_contract_noop(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    activation_path = tmp_path / "route-policy.json.activation"
    bundle, public_keys = signed_test_policy_bundle(
        tproxy.bundled_route_policy_manifest()
    )

    status = tproxy.apply_signed_route_policy_bundle_with_health_gate(
        bundle,
        public_keys,
        lambda: (_ for _ in ()).throw(AssertionError("health repeated")),
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )

    assert status["source"] == tproxy.ROUTE_POLICY_SOURCE
    assert tproxy._active_route_policy_kind == (
        tproxy.route_policy_activation_contract.POLICY_BUNDLED
    )
    assert tproxy._route_policy_trial_generation == 0
    assert not policy_path.exists()
    assert not previous_path.exists()
    assert not activation_path.exists()


def test_rejected_trial_generation_survives_restart(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    activation_path = tmp_path / "route-policy.json.activation"
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:retry"
    manifest["geo_exit_routes"].append({
        "domains": ["retry.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    bundle, public_keys = signed_test_policy_bundle(manifest)

    assert tproxy.apply_signed_route_policy_bundle_with_health_gate(
        bundle,
        public_keys,
        lambda: {"ok": 0, "degraded": 1, "blocked": 0},
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    ) is None
    assert json.loads(activation_path.read_text()) == {
        "contract": 1,
        "trial_generation": 1,
    }
    assert activation_path.stat().st_mode & 0o777 == 0o600
    assert not policy_path.exists()

    tproxy._route_policy_trial_generation = 0
    tproxy.reset_route_policy_manifest()
    assert not tproxy.load_persisted_route_policy(
        public_keys,
        policy_path=str(policy_path),
    )
    assert tproxy._route_policy_trial_generation == 1

    assert tproxy.apply_signed_route_policy_bundle_with_health_gate(
        bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=200.0,
    )
    assert json.loads(activation_path.read_text())["trial_generation"] == 2
    assert json.loads(policy_path.read_text())["activation"][
        "trial_generation"
    ] == 2


def test_active_signed_policy_is_a_noop_without_repeating_health(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:same"
    bundle, public_keys = signed_test_policy_bundle(manifest)
    assert tproxy.apply_signed_route_policy_bundle_with_health_gate(
        bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )
    persisted = policy_path.read_bytes()

    status = tproxy.apply_signed_route_policy_bundle_with_health_gate(
        bundle,
        public_keys,
        lambda: (_ for _ in ()).throw(AssertionError("health repeated")),
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=200.0,
    )

    assert status["source"] == "signed:same"
    assert policy_path.read_bytes() == persisted
    assert not previous_path.exists()
    assert tproxy._route_policy_trial_generation == 1


def test_candidate_activation_failure_restores_bundled_policy(tmp_path, monkeypatch):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:cannot-activate"
    manifest["geo_exit_routes"].append({
        "domains": ["activation.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    bundle, public_keys = signed_test_policy_bundle(manifest)
    original_apply = tproxy.apply_route_policy_manifest

    def fail_candidate(value, *, kind=None):
        if value["source"] == "signed:cannot-activate":
            raise RuntimeError("activation refused")
        return original_apply(value, kind=kind)

    monkeypatch.setattr(tproxy, "apply_route_policy_manifest", fail_candidate)

    status = tproxy.apply_signed_route_policy_bundle_with_health_gate(
        bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )

    assert status is None
    assert not policy_path.exists()
    assert not previous_path.exists()
    assert tproxy.route_policy("activation.example.org")["route_class"] == (
        tproxy.ROUTE_UNKNOWN
    )
    storage = tproxy.route_policy_storage_snapshot()
    assert storage["state"] == "rejected"
    assert "activate_trial effect failed: activation refused" in storage["last_error"]


def test_candidate_commit_failure_restores_files_and_active_policy(
    tmp_path,
    monkeypatch,
):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    first = tproxy.route_policy_manifest()
    first["source"] = "signed:first"
    first["geo_exit_routes"].append({
        "domains": ["first.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    first_bundle, public_keys = signed_test_policy_bundle(first)
    assert tproxy.apply_signed_route_policy_bundle_with_health_gate(
        first_bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )
    previous_path.write_bytes(b"pre-existing rollback slot\n")
    policy_before = policy_path.read_bytes()
    previous_before = previous_path.read_bytes()

    second = tproxy.route_policy_manifest()
    second["source"] = "signed:second"
    second["geo_exit_routes"].append({
        "domains": ["second.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    second_bundle, second_keys = signed_test_policy_bundle(second, key_id="second")
    public_keys.update(second_keys)
    original_write = tproxy._atomic_write_json

    def fail_candidate_write(path, data, *, mode=0o600):
        if str(path) == str(policy_path) and data.get("source") == "signed:second":
            raise OSError("disk full")
        return original_write(path, data, mode=mode)

    monkeypatch.setattr(tproxy, "_atomic_write_json", fail_candidate_write)

    status = tproxy.apply_signed_route_policy_bundle_with_health_gate(
        second_bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=200.0,
    )

    assert status is None
    assert policy_path.read_bytes() == policy_before
    assert previous_path.read_bytes() == previous_before
    assert tproxy.route_policy("first.example.org")["route_class"] == (
        tproxy.ROUTE_GEO_EXIT
    )
    assert tproxy.route_policy("second.example.org")["route_class"] == (
        tproxy.ROUTE_UNKNOWN
    )
    storage = tproxy.route_policy_storage_snapshot()
    assert storage["state"] == "rejected"
    assert "commit_candidate effect failed: disk full" in storage["last_error"]


def test_corrupt_rollback_slot_does_not_replace_active_policy(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    first = tproxy.route_policy_manifest()
    first["source"] = "signed:first"
    first_bundle, public_keys = signed_test_policy_bundle(first)
    assert tproxy.apply_signed_route_policy_bundle_with_health_gate(
        first_bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )
    second = tproxy.route_policy_manifest()
    second["source"] = "signed:second"
    second_bundle, second_keys = signed_test_policy_bundle(second, key_id="second")
    public_keys.update(second_keys)
    assert tproxy.apply_signed_route_policy_bundle_with_health_gate(
        second_bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=200.0,
    )
    previous_path.write_text("not json")
    policy_before = policy_path.read_bytes()
    previous_before = previous_path.read_bytes()

    assert not tproxy.rollback_route_policy(
        public_keys,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
    )
    assert policy_path.read_bytes() == policy_before
    assert previous_path.read_bytes() == previous_before
    assert tproxy.route_policy_status_snapshot()["source"] == "signed:second"
    assert tproxy.route_policy_storage_snapshot()["state"] == "rollback_error"


def test_rollback_activation_failure_restores_files_and_active_policy(
    tmp_path,
    monkeypatch,
):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    first = tproxy.route_policy_manifest()
    first["source"] = "signed:first"
    first_bundle, public_keys = signed_test_policy_bundle(first)
    assert tproxy.apply_signed_route_policy_bundle_with_health_gate(
        first_bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )
    second = tproxy.route_policy_manifest()
    second["source"] = "signed:second"
    second_bundle, second_keys = signed_test_policy_bundle(second, key_id="second")
    public_keys.update(second_keys)
    assert tproxy.apply_signed_route_policy_bundle_with_health_gate(
        second_bundle,
        public_keys,
        lambda: True,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=200.0,
    )
    policy_before = policy_path.read_bytes()
    previous_before = previous_path.read_bytes()
    original_apply = tproxy.apply_route_policy_manifest
    failed = {"value": False}

    def fail_first_target_once(manifest, *, kind=None):
        if manifest["source"] == "signed:first" and not failed["value"]:
            failed["value"] = True
            raise RuntimeError("runtime apply refused")
        return original_apply(manifest, kind=kind)

    monkeypatch.setattr(tproxy, "apply_route_policy_manifest", fail_first_target_once)

    assert not tproxy.rollback_route_policy(
        public_keys,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
    )
    assert policy_path.read_bytes() == policy_before
    assert previous_path.read_bytes() == previous_before
    assert tproxy.route_policy_status_snapshot()["source"] == "signed:second"
    storage = tproxy.route_policy_storage_snapshot()
    assert storage["state"] == "rollback_error"
    assert "runtime apply refused" in storage["last_error"]


def test_persisted_route_policy_hash_mismatch_falls_back_to_bundled(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:test"
    manifest["geo_exit_routes"].append({
        "domains": ["gamma.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    bundle, public_keys = signed_test_policy_bundle(manifest)
    state = tproxy.signed_route_policy_state(bundle, public_keys, now=100.0)
    state["sha256"] = "0" * 64
    policy_path.write_text(json.dumps(state))

    assert not tproxy.load_persisted_route_policy(public_keys, policy_path=str(policy_path))
    assert tproxy.route_policy("gamma.example.org")["route_class"] == tproxy.ROUTE_UNKNOWN
    storage = tproxy.route_policy_storage_snapshot()
    assert storage["state"] == "invalid"
    assert "hash mismatch" in storage["last_error"]


def test_atomic_write_json_accepts_bare_filename(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    tproxy._atomic_write_json("route-policy.json", {"ok": True})

    assert json.loads((tmp_path / "route-policy.json").read_text()) == {"ok": True}


def test_trusted_route_policy_keys_load_from_file_and_validate(tmp_path):
    key = base64.b64encode(b"\x01" * 32).decode("ascii")
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"keys": {"test": key}}))

    assert tproxy.load_trusted_route_policy_keys(path=str(path)) == {"test": key}

    path.write_text(json.dumps({"keys": {"bad": base64.b64encode(b"short").decode("ascii")}}))
    with pytest.raises(ValueError, match="Ed25519"):
        tproxy.load_trusted_route_policy_keys(path=str(path))


def test_trusted_route_policy_keys_merge_embedded_bundled_and_override(tmp_path):
    embedded_key = base64.b64encode(b"\x01" * 32).decode("ascii")
    bundled_key = base64.b64encode(b"\x02" * 32).decode("ascii")
    override_key = base64.b64encode(b"\x03" * 32).decode("ascii")
    bundled_path = tmp_path / "bundled-keys.json"
    override_path = tmp_path / "override-keys.json"
    bundled_path.write_text(json.dumps({"keys": {"prod": bundled_key}}))
    override_path.write_text(json.dumps({"keys": {"prod": override_key}}))

    assert tproxy.load_trusted_route_policy_keys(
        path=str(override_path),
        bundled_path=str(bundled_path),
        embedded_keys={"prod": embedded_key},
    ) == {"prod": override_key}

    assert tproxy.load_trusted_route_policy_keys(
        path="",
        bundled_path=str(bundled_path),
        embedded_keys={"prod": embedded_key},
    ) == {"prod": bundled_key}


def test_remote_route_policy_url_must_be_https():
    with pytest.raises(ValueError, match="https"):
        tproxy.validate_route_policy_remote_url("http://example.org/policy.json")

    assert tproxy.validate_route_policy_remote_url(
        "https://example.org/policy.json"
    ) == "https://example.org/policy.json"


def test_remote_route_policy_update_disabled_without_url(monkeypatch):
    monkeypatch.delenv(tproxy.ROUTE_POLICY_REMOTE_URL_ENV, raising=False)

    assert not tproxy.update_route_policy_from_remote(now=100.0)
    remote = tproxy.route_policy_remote_snapshot()
    assert remote["state"] == "disabled"
    assert remote["last_checked"] == 100.0


def test_remote_route_policy_scheduler_disabled_without_url(monkeypatch):
    monkeypatch.delenv(tproxy.ROUTE_POLICY_REMOTE_URL_ENV, raising=False)

    assert not tproxy.start_route_policy_remote_update_if_due("periodic", now=100.0)
    remote = tproxy.route_policy_remote_snapshot()
    assert remote["state"] == "disabled"
    assert remote["next_due"] == 0.0
    assert remote["failures"] == 0
    assert remote["running"] is False


def test_remote_route_policy_scheduler_success_sets_next_due(monkeypatch):
    monkeypatch.setenv(
        tproxy.ROUTE_POLICY_REMOTE_URL_ENV,
        "https://policy.example.org/route-policy.json",
    )
    monkeypatch.setattr(tproxy, "ROUTE_POLICY_REMOTE_INTERVAL", 60.0)
    monkeypatch.setattr(tproxy, "ROUTE_POLICY_REMOTE_JITTER", 1.0)
    calls = []

    assert tproxy.start_route_policy_remote_update_if_due(
        "periodic",
        now=100.0,
        runner=lambda reason, url: calls.append((reason, url)) or True,
    )

    remote = tproxy.route_policy_remote_snapshot()
    assert calls == [("periodic", "https://policy.example.org/route-policy.json")]
    assert remote["running"] is False
    assert remote["failures"] == 0
    assert remote["next_due"] == 160.0
    assert not tproxy.start_route_policy_remote_update_if_due(
        "periodic",
        now=159.0,
        runner=lambda _reason, _url: True,
    )


def test_remote_route_policy_scheduler_failure_backs_off(monkeypatch):
    monkeypatch.setenv(
        tproxy.ROUTE_POLICY_REMOTE_URL_ENV,
        "https://policy.example.org/route-policy.json",
    )
    monkeypatch.setattr(tproxy, "ROUTE_POLICY_REMOTE_RETRY_BASE", 10.0)
    monkeypatch.setattr(tproxy, "ROUTE_POLICY_REMOTE_RETRY_MAX", 60.0)
    monkeypatch.setattr(tproxy, "ROUTE_POLICY_REMOTE_JITTER", 1.0)
    calls = []

    assert not tproxy.start_route_policy_remote_update_if_due(
        "periodic",
        now=100.0,
        runner=lambda reason, url: calls.append((reason, url)) or False,
    )
    remote = tproxy.route_policy_remote_snapshot()
    assert remote["failures"] == 1
    assert remote["next_due"] == 110.0
    assert calls == [("periodic", "https://policy.example.org/route-policy.json")]

    assert not tproxy.start_route_policy_remote_update_if_due(
        "periodic",
        now=109.0,
        runner=lambda reason, url: calls.append((reason, url)) or True,
    )
    assert calls == [("periodic", "https://policy.example.org/route-policy.json")]


def test_remote_route_policy_scheduler_waits_for_running_canaries(monkeypatch):
    monkeypatch.setenv(
        tproxy.ROUTE_POLICY_REMOTE_URL_ENV,
        "https://policy.example.org/route-policy.json",
    )
    tproxy._canary_state["running"] = True
    try:
        assert not tproxy.start_route_policy_remote_update_if_due(
            "periodic",
            now=100.0,
            runner=lambda _reason, _url: True,
        )
        assert tproxy.route_policy_remote_snapshot()["running"] is False
    finally:
        tproxy._canary_state["running"] = False


def test_remote_route_policy_scheduler_rejects_non_https_url(monkeypatch):
    monkeypatch.setenv(tproxy.ROUTE_POLICY_REMOTE_URL_ENV, "http://example.org/policy")
    monkeypatch.setattr(tproxy, "ROUTE_POLICY_REMOTE_RETRY_BASE", 10.0)
    monkeypatch.setattr(tproxy, "ROUTE_POLICY_REMOTE_JITTER", 1.0)

    assert not tproxy.start_route_policy_remote_update_if_due("periodic", now=100.0)
    remote = tproxy.route_policy_remote_snapshot()
    assert remote["state"] == "error"
    assert "https" in remote["last_error"]
    assert remote["failures"] == 1
    assert remote["next_due"] == 110.0


def test_remote_route_policy_rejects_without_health_gate(tmp_path):
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:remote"
    bundle, public_keys = signed_test_policy_bundle(manifest)

    assert not tproxy.update_route_policy_from_remote(
        url="https://policy.example.org/route-policy.json",
        public_keys=public_keys,
        fetcher=lambda _url: bundle,
        policy_path=str(tmp_path / "route-policy.json"),
        now=100.0,
    )
    remote = tproxy.route_policy_remote_snapshot()
    assert remote["state"] == "error"
    assert "health gate" in remote["last_error"]


def test_signed_route_policy_health_gate_rolls_back_failed_candidate(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:remote"
    manifest["geo_exit_routes"].append({
        "domains": ["reject.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    bundle, public_keys = signed_test_policy_bundle(manifest)

    status = tproxy.apply_signed_route_policy_bundle_with_health_gate(
        bundle,
        public_keys,
        lambda: (0, 1),
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )

    assert status is None
    assert not policy_path.exists()
    assert tproxy.route_policy("reject.example.org")["route_class"] == (
        tproxy.ROUTE_UNKNOWN
    )
    storage = tproxy.route_policy_storage_snapshot()
    assert storage["state"] == "rejected"
    assert "health gate degraded=1" in storage["last_error"]


def test_remote_route_policy_fetch_applies_after_health_gate(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:remote"
    manifest["geo_exit_routes"].append({
        "domains": ["remote.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    bundle, public_keys = signed_test_policy_bundle(manifest)

    assert tproxy.update_route_policy_from_remote(
        url="https://policy.example.org/route-policy.json",
        public_keys=public_keys,
        fetcher=lambda _url: bundle,
        health_runner=lambda: (5, 0),
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )

    assert policy_path.exists()
    assert tproxy.route_policy("remote.example.org")["route_class"] == (
        tproxy.ROUTE_GEO_EXIT
    )
    storage = tproxy.route_policy_storage_snapshot()
    assert storage["state"] == "saved"
    remote = tproxy.route_policy_remote_snapshot()
    assert remote["state"] == "applied"
    assert remote["last_source"] == "signed:remote"
    assert len(remote["last_sha256"]) == 64


def test_remote_route_policy_fetch_accepts_channel_index(tmp_path):
    policy_path = tmp_path / "route-policy.json"
    previous_path = tmp_path / "route-policy.previous.json"
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:channel"
    manifest["geo_exit_routes"].append({
        "domains": ["channel.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    bundle, public_keys = signed_test_policy_bundle(manifest)
    bundle_bytes = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
    channel = {
        "kind": tproxy.ROUTE_POLICY_CHANNEL_KIND,
        "schema": tproxy.ROUTE_POLICY_CHANNEL_SCHEMA_VERSION,
        "bundle_url": "https://policy.example.org/channel/route-policy.json",
        "sha256": hashlib.sha256(bundle_bytes).hexdigest(),
    }
    calls = []

    def fetcher(url):
        calls.append(url)
        if url.endswith("latest.json"):
            return json.dumps(channel).encode()
        return bundle_bytes

    assert tproxy.update_route_policy_from_remote(
        url="https://policy.example.org/channel/latest.json",
        public_keys=public_keys,
        fetcher=fetcher,
        health_runner=lambda: (5, 0),
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )

    assert calls == [
        "https://policy.example.org/channel/latest.json",
        "https://policy.example.org/channel/route-policy.json",
    ]
    assert tproxy.route_policy("channel.example.org")["route_class"] == (
        tproxy.ROUTE_GEO_EXIT
    )


def test_ip_attempt_limits_follow_route_policy():
    assert tproxy.IP_ATTEMPT_LIMIT_BY_ROUTE == {
        tproxy.ROUTE_LOCAL_BYPASS: tproxy.LOCAL_BYPASS_IP_ATTEMPT_LIMIT,
    }
    assert tproxy.ip_attempt_limit("updates.discord.com") == (
        tproxy.LOCAL_BYPASS_IP_ATTEMPT_LIMIT
    )
    assert tproxy.ip_attempt_limit("rr2---sn-ntq7yner.googlevideo.com") == (
        tproxy.DEFAULT_IP_ATTEMPT_LIMIT
    )
    assert tproxy.ip_attempt_limit("chatgpt.com") == tproxy.DEFAULT_IP_ATTEMPT_LIMIT
    assert tproxy.ip_attempt_limit("example.net") == tproxy.DEFAULT_IP_ATTEMPT_LIMIT


def test_local_payload_canary_request_supports_discord_gateway_websocket():
    spec = {"payload_probe": "websocket_upgrade"}
    req = tproxy._local_payload_canary_request(
        "gateway.discord.gg",
        spec,
    )
    req2 = tproxy._local_payload_canary_request("gateway.discord.gg", spec)

    assert req.startswith(b"GET /?v=10&encoding=json HTTP/1.1\r\n")
    assert b"Host: gateway.discord.gg\r\n" in req
    assert b"Upgrade: websocket\r\n" in req
    assert b"Sec-WebSocket-Version: 13\r\n" in req
    key = re.search(rb"Sec-WebSocket-Key: ([^\r]+)", req).group(1)
    key2 = re.search(rb"Sec-WebSocket-Key: ([^\r]+)", req2).group(1)
    decoded = base64.b64decode(key)
    decoded2 = base64.b64decode(key2)
    assert len(decoded) == 16
    assert len(decoded2) == 16
    assert decoded != b"the sample nonce"
    assert key2 != key


def test_local_payload_canary_request_supports_specific_http_path():
    req = tproxy._local_payload_canary_request(
        "cdn.discordapp.com",
        {"payload_path": "/embed/avatars/0.png"},
    )

    assert req.startswith(b"HEAD /embed/avatars/0.png HTTP/1.1\r\n")
    assert b"Host: cdn.discordapp.com\r\n" in req


def test_discord_api_canary_uses_gateway_api_path():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_api")
    req = tproxy._local_payload_canary_request(spec["host"], spec)

    assert spec["payload_path"] == "/api/v10/gateway"
    assert req.startswith(b"HEAD /api/v10/gateway HTTP/1.1\r\n")
    assert b"Host: discord.com\r\n" in req


def test_discord_cdn_canary_uses_get_and_throughput_threshold():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_cdn")
    req = tproxy._local_payload_canary_request(spec["host"], spec)

    assert spec["payload_path"] == "/embed/avatars/0.png"
    assert spec["payload_method"] == "GET"
    assert tproxy._local_payload_min_bytes(spec) == 512
    assert req.startswith(b"GET /embed/avatars/0.png HTTP/1.1\r\n")
    assert b"Host: cdn.discordapp.com\r\n" in req


def test_youtube_web_canary_uses_generate_204_path():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_web")
    req = tproxy._local_payload_canary_request(spec["host"], spec)

    assert spec["payload_path"] == "/generate_204"
    assert req.startswith(b"HEAD /generate_204 HTTP/1.1\r\n")
    assert b"Host: www.youtube.com\r\n" in req


def test_quic_version_negotiation_probe_packet_is_padded_initial():
    pkt = tproxy._quic_version_negotiation_probe_packet(
        dcid=b"12345678",
        scid=b"abcdefgh",
    )

    assert len(pkt) == tproxy.QUIC_MIN_INITIAL_SIZE
    assert pkt[:5] == b"\xc0" + tproxy.QUIC_UNSUPPORTED_VERSION
    assert pkt[5] == 8
    assert pkt[6:14] == b"12345678"
    assert pkt[14] == 8
    assert pkt[15:23] == b"abcdefgh"


def test_quic_version_negotiation_response_detection():
    assert tproxy._is_quic_version_negotiation_response(b"\xc0\x00\x00\x00\x00rest")

    assert not tproxy._is_quic_version_negotiation_response(b"\xc0\x00\x00\x00\x01rest")
    assert not tproxy._is_quic_version_negotiation_response(b"\x40\x00\x00\x00\x00rest")


def test_discord_cdn_canary_stays_local_bypass_and_fake_only():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_cdn")

    assert tproxy.route_policy(spec["host"]) == {
        "host": "cdn.discordapp.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_DISCORD,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert not tproxy.is_geo_exit_route(spec["host"])
    assert [s["name"] for s in tproxy.strategy_order(spec["host"])] == [
        "split64+fake",
        "split16+fake",
        "fake5",
    ]


def test_discord_api_canary_stays_local_bypass_and_fake_only():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_api")

    assert tproxy.route_policy(spec["host"]) == {
        "host": "discord.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_DISCORD,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert not tproxy.is_geo_exit_route(spec["host"])
    assert [s["name"] for s in tproxy.strategy_order(spec["host"])] == [
        "split64+fake",
        "split16+fake",
        "fake5",
    ]


def test_youtube_redirector_canary_uses_direct_first():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_video")
    host = spec["fallback_host"]

    assert tproxy.route_policy(host) == {
        "host": "redirector.googlevideo.com",
        "route_class": tproxy.ROUTE_DIRECT_FIRST,
        "service_group": tproxy.SERVICE_YOUTUBE,
        "strategy_set": tproxy.STRATEGY_DIRECT_FIRST,
    }
    assert not tproxy.is_geo_exit_route(host)
    assert [s["name"] for s in tproxy.strategy_order(host)][0] == "plain"


def test_youtube_web_canary_stays_local_bypass_and_fake_only():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_web")

    assert spec["soft"] is True
    assert tproxy.route_policy(spec["host"]) == {
        "host": "www.youtube.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_YOUTUBE,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert not tproxy.is_geo_exit_route(spec["host"])
    assert [s["name"] for s in tproxy.strategy_order(spec["host"])] == [
        "split64+fake",
        "split16+fake",
        "fake5",
    ]


def test_system_proxy_status_from_scutil_reports_kind_without_mutating():
    raw = """
HTTPEnable : 1
HTTPSEnable : 1
SOCKSEnable : 0
ProxyAutoConfigEnable : 1
"""

    assert tproxy.system_proxy_status_from_scutil(raw) == {
        "state": "active",
        "kind": "http,https,pac",
        "exceptions_count": 0,
        "exceptions_sample": [],
        "stale_exceptions": False,
    }
    assert tproxy.system_proxy_status_from_scutil("HTTPEnable : 0\n") == {
        "state": "off",
        "kind": "",
        "exceptions_count": 0,
        "exceptions_sample": [],
        "stale_exceptions": False,
    }


def test_system_proxy_status_reports_disabled_external_proxy_exceptions():
    raw = """
<dictionary> {
  ExceptionsList : <array> {
    0 : *.googlevideo.com
    1 : *.youtube.com
    2 : youtube.com
    3 : youtu.be
  }
  HTTPEnable : 0
  HTTPSEnable : 0
  SOCKSEnable : 0
  ProxyAutoConfigEnable : 0
  ProxyAutoDiscoveryEnable : 0
}
"""

    assert tproxy.system_proxy_status_from_scutil(raw) == {
        "state": "off",
        "kind": "",
        "exceptions_count": 4,
        "exceptions_sample": ["*.googlevideo.com", "*.youtube.com", "youtube.com"],
        "stale_exceptions": True,
    }


def test_rearm_status_tracks_wake_and_network_rearms():
    original = dict(tproxy._rearm_state)
    try:
        tproxy._rearm_state.update({
            "last_at": 0.0,
            "last_reason": "",
            "last_gap": 0.0,
            "last_iface": "",
            "count": 0,
        })

        tproxy.note_runtime_rearm("wake", gap=903.4, iface="en0", now=1000.0)
        snapshot = tproxy.rearm_status_snapshot(now=1010.0)

        assert snapshot == {
            "last_at": 1000.0,
            "last_reason": "wake",
            "last_gap": 903,
            "last_iface": "en0",
            "count": 1,
            "seconds_since": 10,
        }

        tproxy.note_runtime_rearm("network_change", iface="en1", now=1020.0)
        snapshot = tproxy.rearm_status_snapshot(now=1025.0)

        assert snapshot["last_reason"] == "network_change"
        assert snapshot["last_gap"] == 0
        assert snapshot["last_iface"] == "en1"
        assert snapshot["count"] == 2
        assert snapshot["seconds_since"] == 5
    finally:
        tproxy._rearm_state.clear()
        tproxy._rearm_state.update(original)


def test_runtime_rearm_queue_is_bounded_validated_and_deduplicated():
    for index in range(12):
        reason = "wake" if index % 2 else "network_change"
        tproxy._queue_runtime_rearm(reason)

    assert len(tproxy._runtime_rearm_requests) == 8
    assert tproxy._drain_runtime_rearms() == ["network_change", "wake"]
    assert tproxy._drain_runtime_rearms() == []
    with pytest.raises(ValueError, match="unsupported runtime rearm reason"):
        tproxy._queue_runtime_rearm("restart_everything")


def test_runtime_rearm_signal_only_queues_network_change():
    tproxy._runtime_rearm_signal_handler(tproxy._RUNTIME_REARM_SIGNAL, None)
    tproxy._runtime_rearm_signal_handler(signal.SIGTERM, None)

    assert tproxy._drain_runtime_rearms() == ["network_change"]


def test_runtime_rearm_helper_keeps_wake_and_network_side_effects_scoped(monkeypatch):
    events = []
    monkeypatch.setattr(
        tproxy,
        "note_runtime_rearm",
        lambda reason, **kwargs: events.append(("status", reason, kwargs)),
    )
    monkeypatch.setattr(
        tproxy,
        "note_geph_wake",
        lambda now: events.append(("geph_wake", now)),
    )
    monkeypatch.setattr(
        tproxy,
        "start_canaries_if_due",
        lambda reason, **kwargs: events.append(("canary", reason, kwargs)),
    )

    tproxy._apply_runtime_rearm("wake", now=100.0, iface="en0", gap=31.0)
    tproxy._apply_runtime_rearm("network_change", now=110.0, iface="en1")

    assert events == [
        ("status", "wake", {"gap": 31.0, "iface": "en0", "now": 100.0}),
        ("geph_wake", 100.0),
        ("canary", "wake", {"force": True}),
        ("status", "network_change", {"gap": 0.0, "iface": "en1", "now": 110.0}),
        ("canary", "network_change", {"force": True}),
    ]


def test_system_dns_status_detects_xbox_dns_without_mutating():
    raw = """
DNS configuration

resolver #1
  nameserver[0] : 111.88.96.50
  nameserver[1] : 111.88.96.51

DNS configuration (for scoped queries)
resolver #1
  nameserver[0] : 111.88.96.50
"""

    assert tproxy.system_dns_status_from_scutil(raw) == {
        "state": "xbox_dns",
        "providers": "xbox_dns",
        "servers": ["111.88.96.50", "111.88.96.51"],
        "managed_by_slipstream": False,
    }
    assert tproxy.system_dns_status_from_scutil("nameserver[0] : 1.1.1.1\n") == {
        "state": "configured",
        "providers": "",
        "servers": ["1.1.1.1"],
        "managed_by_slipstream": False,
    }


def test_system_dns_resolution_checks_flag_null_private_and_stub_answers():
    answers = {
        "updates.discord.com": ["0.0.0.0"],
        "gateway.discord.gg": ["10.0.0.42"],
        "www.youtube.com": ["142.250.186.46"],
        "redirector.googlevideo.com": ["87.228.47.11"],
    }

    status = tproxy.system_dns_resolution_checks(lambda host: answers.get(host, []))
    checks = {item["host"]: item for item in status["checks"]}

    assert status["state"] == "suspicious"
    assert checks["updates.discord.com"]["state"] == "suspicious"
    assert checks["gateway.discord.gg"]["suspicious_ips"] == ["10.0.0.42"]
    assert checks["www.youtube.com"]["state"] == "ok"
    assert checks["redirector.googlevideo.com"]["suspicious_ips"] == ["87.228.47.11"]


def test_system_dns_resolution_checks_report_unknown_without_mutating():
    status = tproxy.system_dns_resolution_checks(lambda host: [])

    assert status["state"] == "unknown"
    assert all(item["state"] == "unknown" for item in status["checks"])


def test_current_system_dns_status_is_cached(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        return type("Result", (), {
            "returncode": 0,
            "stdout": "nameserver[0] : 111.88.96.50\n",
            "stderr": "",
        })()

    original = dict(tproxy._system_dns_cache)
    try:
        tproxy._system_dns_cache.update({
            "ts": 0.0,
            "status": None,
            "resolution_ts": 100.0,
            "resolution_checks": {"state": "ok", "checks": []},
        })
        monkeypatch.setattr(tproxy, "_run", fake_run)
        monkeypatch.setattr(
            tproxy,
            "system_resolve",
            lambda _host: pytest.fail("status publication attempted DNS"),
        )

        first = tproxy.current_system_dns_status(now=100.0)
        second = tproxy.current_system_dns_status(now=110.0)

        assert first["state"] == "xbox_dns"
        assert first["resolution_checks"]["state"] == "ok"
        assert second["state"] == "xbox_dns"
        assert calls == [("scutil", "--dns")]
    finally:
        tproxy._system_dns_cache.clear()
        tproxy._system_dns_cache.update(original)


def test_current_system_dns_status_reports_unknown_until_background_refresh(
    monkeypatch,
):
    original = dict(tproxy._system_dns_cache)
    try:
        tproxy._system_dns_cache.update({
            "ts": 0.0,
            "status": None,
            "resolution_ts": 0.0,
            "resolution_checks": None,
        })
        monkeypatch.setattr(
            tproxy,
            "_run",
            lambda *_args: type("Result", (), {
                "returncode": 0,
                "stdout": "nameserver[0] : 1.1.1.1\n",
                "stderr": "",
            })(),
        )
        monkeypatch.setattr(
            tproxy,
            "system_resolve",
            lambda _host: pytest.fail("status publication attempted DNS"),
        )

        status = tproxy.current_system_dns_status(now=100.0)

        assert status["resolution_checks"] == {"state": "unknown", "checks": []}
    finally:
        tproxy._system_dns_cache.clear()
        tproxy._system_dns_cache.update(original)


def test_smart_dns_route_gate_requires_geo_exit_and_fresh_canary(monkeypatch):
    monkeypatch.setattr(
        tproxy,
        "current_system_dns_status",
        lambda now=None: {
            "state": "xbox_dns",
            "providers": "xbox_dns",
            "servers": ["111.88.96.50"],
            "managed_by_slipstream": False,
        },
    )
    tproxy._smart_dns_ok_until[tproxy.SERVICE_OPENAI] = 200.0

    assert tproxy.smart_dns_route_enabled("chatgpt.com", now=100.0)
    assert not tproxy.smart_dns_route_enabled("chatgpt.com", now=201.0)
    assert not tproxy.smart_dns_route_enabled("gateway.discord.gg", now=100.0)
    assert not tproxy.smart_dns_route_enabled("rr2---sn-ntq7yner.googlevideo.com", now=100.0)
    tproxy._smart_dns_ok_until[tproxy.SERVICE_STEAM_STORE] = 200.0
    assert not tproxy.smart_dns_route_enabled("store.steampowered.com", now=100.0)


def test_canary_scheduler_runs_on_forced_and_periodic_triggers(monkeypatch):
    calls = []
    tproxy._canary_state.update({
        "running": False,
        "last_run": 0.0,
        "last_started": 0.0,
        "next_due": 0.0,
        "last_reason": "",
        "total": 0,
        "ok": 0,
        "degraded": 0,
    })
    monkeypatch.setattr(tproxy, "CANARY_INTERVAL", 10.0)
    monkeypatch.setattr(tproxy, "CANARY_JITTER", 1.0)

    assert tproxy.start_canaries_if_due("startup", force=True, now=100.0, runner=calls.append)
    assert calls == ["startup"]
    assert not tproxy._canary_state["running"]
    assert tproxy._canary_state["next_due"] == 110.0

    assert not tproxy.start_canaries_if_due("periodic", now=105.0, runner=calls.append)
    assert tproxy.start_canaries_if_due("periodic", now=111.0, runner=calls.append)
    assert calls == ["startup", "periodic"]


def test_canary_scheduler_preserves_forced_recheck_while_running(monkeypatch):
    calls = []
    tproxy._canary_state.update({
        "running": True,
        "last_run": 0.0,
        "last_started": 100.0,
        "next_due": 999.0,
        "last_reason": "wake",
        "total": 0,
        "ok": 0,
        "degraded": 0,
        "warnings": 0,
        "unknown": 0,
    })
    monkeypatch.setattr(tproxy, "CANARY_INTERVAL", 10.0)
    monkeypatch.setattr(tproxy, "CANARY_JITTER", 1.0)
    monkeypatch.setattr(tproxy, "CANARY_FORCE_RETRY_DELAY", 5.0)

    assert not tproxy.start_canaries_if_due("geph_up", force=True, now=105.0, runner=calls.append)
    assert tproxy._canary_state["pending_reason"] == "geph_up"
    assert tproxy._canary_state["next_due"] == 110.0

    tproxy.finish_canaries(now=106.0)
    assert not tproxy._canary_state["running"]
    assert tproxy._canary_state["next_due"] == 110.0

    assert not tproxy.start_canaries_if_due("periodic", now=109.0, runner=calls.append)
    assert tproxy.start_canaries_if_due("periodic", now=111.0, runner=calls.append)
    assert calls == ["geph_up"]


def test_local_bypass_canary_failure_decays_only_local_strategy_cache(monkeypatch):
    async def no_ips(host, fallback_ip):
        return []

    monkeypatch.setattr(tproxy, "resolve_connection_ips", no_ips)
    tproxy._strat_cache.clear()
    tproxy._strat_cache["updates.discord.com"] = "split64+fake"
    tproxy._strat_cache["billing.openai.com"] = "split64+fake"

    try:
        spec = {"group": tproxy.SERVICE_DISCORD, "host": "updates.discord.com"}
        assert not asyncio.run(tproxy._run_local_bypass_canary(spec))

        assert "updates.discord.com" not in tproxy._strat_cache
        assert tproxy._strat_cache["billing.openai.com"] == "split64+fake"
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_failure"] == "dns failed"
    finally:
        tproxy._strat_cache.clear()


def test_local_bypass_runtime_failure_decays_cache_and_forces_canary(monkeypatch):
    host = "updates.discord.com"
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])
    original_canary_state = dict(tproxy._canary_state)
    calls = []
    resweeps = []

    try:
        monkeypatch.setattr(tproxy, "save_strat_cache", lambda: None)
        monkeypatch.setattr(
            tproxy,
            "schedule_local_bypass_resweep",
            lambda candidate: resweeps.append(candidate) or True,
            raising=False,
        )
        tproxy._route_failure_windows[tproxy.SERVICE_DISCORD].clear()
        tproxy._canary_state.update({
            "running": False,
            "last_run": 0.0,
            "last_started": 0.0,
            "next_due": 0.0,
            "last_reason": "",
            "total": 0,
            "ok": 0,
            "degraded": 0,
            "warnings": 0,
            "unknown": 0,
        })
        tproxy.route_health_event(
            tproxy.SERVICE_DISCORD,
            tproxy.ROUTE_LOCAL_BYPASS,
            host,
            ok=True,
            now=90.0,
        )
        tproxy._strat_cache.clear()
        tproxy._strat_cache[host] = "split64+fake"
        tproxy._strat_cache["gateway.discord.gg"] = "split16+fake"
        tproxy._strat_cache["billing.openai.com"] = "split64+fake"

        first = tproxy.note_local_bypass_runtime_result(
            host,
            False,
            "runtime strategy probe failed",
            now=100.0,
            canary_now=200.0,
            canary_runner=calls.append,
        )

        assert first["state"] == tproxy.HEALTH_OK
        assert first["last_warning"] == "runtime strategy probe failed"
        assert host not in tproxy._strat_cache
        assert "gateway.discord.gg" not in tproxy._strat_cache
        assert tproxy._strat_cache["billing.openai.com"] == "split64+fake"
        assert calls == [f"runtime:{tproxy.SERVICE_DISCORD}"]
        assert resweeps == [host]

        for offset in range(1, tproxy.LOCAL_BYPASS_RUNTIME_DEGRADE_AFTER):
            tproxy.note_local_bypass_runtime_result(
                host,
                False,
                "runtime strategy probe failed",
                now=100.0 + offset,
                canary_now=200.0 + offset,
                canary_runner=calls.append,
            )

        health = tproxy.route_health_snapshot(now=110.0)[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_failure"] == "runtime strategy probe failed"
        assert calls == [f"runtime:{tproxy.SERVICE_DISCORD}"]
        assert resweeps == [host] * tproxy.LOCAL_BYPASS_RUNTIME_DEGRADE_AFTER
        assert not tproxy.is_geo_exit_route(host)
    finally:
        tproxy._strat_cache.clear()
        tproxy._canary_state.clear()
        tproxy._canary_state.update(original_canary_state)
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_youtube_direct_first_runtime_failure_uses_protected_local_recovery(
    monkeypatch,
):
    host = "rr5---sn-test.googlevideo.com"
    invalidations = []
    scores = []
    resweeps = []
    canaries = []
    health = []
    monkeypatch.setattr(
        tproxy,
        "clear_route_strategy_cache",
        lambda **kwargs: invalidations.append(kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "_record_strategy_result",
        lambda *args: scores.append(args),
    )
    monkeypatch.setattr(
        tproxy,
        "schedule_local_bypass_resweep",
        lambda candidate: resweeps.append(candidate) or True,
    )
    monkeypatch.setattr(
        tproxy,
        "start_canaries_if_due",
        lambda reason, **kwargs: canaries.append((reason, kwargs)),
    )
    monkeypatch.setattr(
        tproxy,
        "route_health_event",
        lambda *args, **kwargs: health.append((args, kwargs)) or {"state": "ok"},
    )

    result = tproxy.note_local_bypass_runtime_result(
        host,
        False,
        "protected local TLS stream closed before completion",
        failed_strategy="plain",
    )

    assert result == {"state": "ok"}
    assert invalidations == [{"group": tproxy.SERVICE_YOUTUBE}]
    assert scores == [(host, "plain", False)]
    assert resweeps == [host]
    assert canaries[0][0] == f"runtime:{tproxy.SERVICE_YOUTUBE}"
    assert health[0][0][:3] == (
        tproxy.SERVICE_YOUTUBE,
        tproxy.ROUTE_DIRECT_FIRST,
        host,
    )
    assert not tproxy.is_geo_exit_route(host)


def test_local_bypass_resweep_scheduler_deduplicates_and_rejects_other_routes():
    calls = []

    assert tproxy.schedule_local_bypass_resweep(
        "updates.discord.com",
        now=100.0,
        runner=calls.append,
    )
    assert calls == ["updates.discord.com"]
    assert not tproxy.schedule_local_bypass_resweep(
        "updates.discord.com",
        now=101.0,
        runner=calls.append,
    )
    assert tproxy.schedule_local_bypass_resweep(
        "rr5---sn-test.googlevideo.com",
        now=200.0,
        runner=calls.append,
    )
    assert not tproxy.schedule_local_bypass_resweep(
        "chatgpt.com",
        now=200.0,
        runner=calls.append,
    )
    assert not tproxy.schedule_local_bypass_resweep(
        "payments.example.com",
        now=200.0,
        runner=calls.append,
    )
    assert calls == [
        "updates.discord.com",
        "rr5---sn-test.googlevideo.com",
    ]


def test_local_bypass_resweep_scheduler_starts_group_named_thread(monkeypatch):
    threads = []

    class DummyThread:
        def __init__(self, *, target, daemon, name):
            threads.append({"target": target, "daemon": daemon, "name": name})

        def start(self):
            threads[-1]["started"] = True

    monkeypatch.setattr(tproxy.threading, "Thread", DummyThread)

    assert tproxy.schedule_local_bypass_resweep("updates.discord.com", now=100.0)
    assert len(threads) == 1
    assert threads[0]["daemon"] is True
    assert threads[0]["name"] == "local-bypass-resweep-discord"
    assert threads[0]["started"] is True


def test_local_bypass_resweep_caches_exact_host_winner(monkeypatch):
    host = "updates.discord.com"
    attempts = []

    async def resolve(_host, _fallback_ip):
        return ["203.0.113.10"]

    async def dial(ip, port, head, body, candidate, strategy):
        attempts.append((candidate, strategy["name"], strategy["fake"]))
        if strategy["name"] == "split16+fake":
            return object()
        return None

    monkeypatch.setattr(tproxy, "resolve_connection_ips", resolve)
    monkeypatch.setattr(tproxy, "dial_strategy", dial)
    monkeypatch.setattr(tproxy, "_close_probe_result", lambda result: None)
    monkeypatch.setattr(tproxy, "save_strat_cache", lambda: None)
    tproxy._strat_cache.clear()
    tproxy._strat_scores.clear()
    tproxy._dead[host] = 999.0

    try:
        assert asyncio.run(tproxy._resweep_local_bypass_host(host))

        assert attempts == [
            (host, "split64+fake", True),
            (host, "split16+fake", True),
        ]
        assert tproxy._strat_cache[host] == "split16+fake"
        assert host not in tproxy._dead
        assert not tproxy.is_geo_exit_route(host)
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()
        tproxy._dead.pop(host, None)


def test_local_bypass_resweep_contains_background_probe_errors(monkeypatch):
    async def broken(_host):
        raise OSError("probe unavailable")

    monkeypatch.setattr(tproxy, "_resweep_local_bypass_host", broken)
    monkeypatch.setattr(tproxy, "VERBOSE", False)

    assert not tproxy._run_local_bypass_resweep("updates.discord.com")


def test_local_bypass_runtime_success_marks_route_ok():
    host = "gateway.discord.gg"
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_DISCORD].clear()

        item = tproxy.note_local_bypass_runtime_result(host, True, now=100.0)

        assert item["state"] == tproxy.HEALTH_OK
        assert item["last_failure"] == ""
        assert item["last_host"] == host
        assert item["last_route_class"] == tproxy.ROUTE_LOCAL_BYPASS
    finally:
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_local_bypass_canary_uses_modern_payload_probe_without_synthetic_preflight(monkeypatch):
    host = "updates.discord.com"
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])
    payload_calls = []

    async def ips(_host, _fallback_ip):
        return ["203.0.113.10"]

    async def unexpected_synthetic_preflight(*_args, **_kwargs):
        raise AssertionError("local canary must use the modern payload probe directly")

    async def payload(ip, sni, strat, spec):
        payload_calls.append((ip, sni, strat["name"], spec["name"]))
        return tproxy.LOCAL_PAYLOAD_CANARY_MIN_BYTES

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_DISCORD].clear()
        tproxy._strat_cache.clear()
        monkeypatch.setattr(tproxy, "resolve_connection_ips", ips)
        monkeypatch.setattr(
            tproxy,
            "strategy_order",
            lambda _host: [tproxy.STRAT_BY_NAME["split64+fake"]],
        )
        monkeypatch.setattr(tproxy, "dial_strategy", unexpected_synthetic_preflight)
        monkeypatch.setattr(tproxy, "_run_local_payload_probe", payload)

        spec = {"name": "discord_update", "group": tproxy.SERVICE_DISCORD, "host": host}
        assert asyncio.run(tproxy._run_local_bypass_canary(spec))

        assert payload_calls == [("203.0.113.10", host, "split64+fake", "discord_update")]
        assert tproxy._strat_cache[host] == "split64+fake"
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_failure"] == ""
        assert health["last_host"] == host
    finally:
        tproxy._strat_cache.clear()
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_youtube_media_canary_probes_plain_before_local_fallback(monkeypatch):
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_video")
    host = spec["fallback_host"]
    original = dict(tproxy._route_health[tproxy.SERVICE_YOUTUBE])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE])
    payload_calls = []

    async def ips(_host, _fallback_ip):
        return ["203.0.113.10"]

    async def payload(ip, sni, strat, received_spec):
        payload_calls.append((ip, sni, strat["name"], received_spec["name"]))
        return tproxy.LOCAL_PAYLOAD_CANARY_MIN_BYTES

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE].clear()
        tproxy._strat_cache.clear()
        monkeypatch.setattr(tproxy, "resolve_connection_ips", ips)
        monkeypatch.setattr(tproxy, "_run_local_payload_probe", payload)

        assert asyncio.run(tproxy._run_local_bypass_canary(spec))

        assert payload_calls == [
            ("203.0.113.10", host, "plain", "youtube_video")
        ]
        assert tproxy._strat_cache[host] == "plain"
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_YOUTUBE]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_route_class"] == tproxy.ROUTE_DIRECT_FIRST
        assert health["last_failure"] == ""
    finally:
        tproxy._strat_cache.clear()
        tproxy._route_health[tproxy.SERVICE_YOUTUBE] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE]
        q.clear()
        q.extend(original_window)


def test_local_bypass_canary_payload_failure_warns_before_degraded(monkeypatch):
    host = "updates.discord.com"
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])

    async def ips(_host, _fallback_ip):
        return ["203.0.113.10"]

    async def no_payload(ip, sni, strat, spec):
        return 0

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_DISCORD].clear()
        tproxy.route_health_event(
            tproxy.SERVICE_DISCORD,
            tproxy.ROUTE_LOCAL_BYPASS,
            host,
            ok=True,
            now=100.0,
        )
        tproxy._strat_cache.clear()
        tproxy._strat_cache[host] = "split64+fake"
        tproxy._strat_cache["billing.openai.com"] = "split64+fake"
        monkeypatch.setattr(tproxy, "resolve_connection_ips", ips)
        monkeypatch.setattr(
            tproxy,
            "strategy_order",
            lambda _host: [tproxy.STRAT_BY_NAME["split64+fake"]],
        )
        monkeypatch.setattr(tproxy, "_run_local_payload_probe", no_payload)

        spec = {"name": "discord_update", "group": tproxy.SERVICE_DISCORD, "host": host}
        assert asyncio.run(tproxy._run_local_bypass_canary(spec)) == "warning"

        assert host not in tproxy._strat_cache
        assert tproxy._strat_cache["billing.openai.com"] == "split64+fake"
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_failure"] == ""
        assert health["last_warning"] == "payload probe failed"

        for _ in range(max(0, tproxy.LOCAL_PAYLOAD_DEGRADE_AFTER - 2)):
            assert asyncio.run(tproxy._run_local_bypass_canary(spec)) == "warning"
        assert not asyncio.run(tproxy._run_local_bypass_canary(spec))
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_failure"] == "payload probe failed"
    finally:
        tproxy._strat_cache.clear()
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_local_bypass_canary_short_cdn_payload_warns_before_degraded(monkeypatch):
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_cdn")
    host = spec["host"]
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])

    async def ips(_host, _fallback_ip):
        return ["203.0.113.10"]

    async def short_payload(ip, sni, strat, probe_spec):
        assert probe_spec["payload_min_bytes"] == 512
        return 128

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_DISCORD].clear()
        monkeypatch.setattr(tproxy, "resolve_connection_ips", ips)
        monkeypatch.setattr(
            tproxy,
            "strategy_order",
            lambda _host: [tproxy.STRAT_BY_NAME["split64+fake"]],
        )
        monkeypatch.setattr(tproxy, "_run_local_payload_probe", short_payload)

        assert asyncio.run(tproxy._run_local_bypass_canary(spec)) == "warning"

        check = tproxy.canary_health_snapshot()["discord_cdn"]
        assert check["last_warning"] == "payload throughput below threshold"
        assert check["last_warning_host"] == host
        assert check["state"] != tproxy.HEALTH_DEGRADED

        for _ in range(1, tproxy.LOCAL_PAYLOAD_DEGRADE_AFTER):
            asyncio.run(tproxy._run_local_bypass_canary(spec))
        check = tproxy.canary_health_snapshot()["discord_cdn"]
        assert check["state"] == tproxy.HEALTH_DEGRADED
        assert check["last_failure"] == "payload throughput below threshold"
    finally:
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_canary_health_keeps_endpoint_failure_visible_after_sibling_ok():
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])
    gateway = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_gateway")
    cdn = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_cdn")
    now = tproxy.time.time()

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_DISCORD].clear()
        tproxy.canary_health_event(
            gateway,
            tproxy.ROUTE_LOCAL_BYPASS,
            "gateway.discord.gg",
            ok=False,
            reason="websocket upgrade failed",
            now=now,
        )
        tproxy.canary_health_event(
            cdn,
            tproxy.ROUTE_LOCAL_BYPASS,
            "cdn.discordapp.com",
            ok=True,
            now=now + 10.0,
        )

        checks = tproxy.canary_status_snapshot()["checks"]
        assert checks["discord_gateway"]["state"] == tproxy.HEALTH_DEGRADED
        assert checks["discord_gateway"]["last_failure"] == "websocket upgrade failed"
        assert checks["discord_cdn"]["state"] == tproxy.HEALTH_OK

        health = tproxy.route_health_snapshot(now=now + 10.0)[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_host"] == "gateway.discord.gg"
        assert health["last_failure"] == "websocket upgrade failed"
        assert health["failures_5m"] == 1
    finally:
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_canary_status_keeps_legacy_summary_fields_with_check_details():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_update")
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])

    try:
        tproxy.canary_health_event(
            spec,
            tproxy.ROUTE_LOCAL_BYPASS,
            "updates.discord.com",
            ok=True,
            now=tproxy.time.time(),
        )

        snapshot = tproxy.canary_status_snapshot()

        for key in ("running", "last_run", "total", "ok", "degraded", "warnings", "unknown"):
            assert key in snapshot
        assert snapshot["checks"]["discord_update"]["group"] == tproxy.SERVICE_DISCORD
        assert snapshot["checks"]["discord_update"]["last_host"] == "updates.discord.com"
    finally:
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_youtube_canary_prefers_observed_video_host_then_redirector_fallback():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_video")
    tproxy._strat_cache.clear()

    try:
        assert tproxy._canary_host(spec) == "redirector.googlevideo.com"

        tproxy._strat_cache["www.youtube.com"] = "fake5"
        assert tproxy._canary_host(spec) == "redirector.googlevideo.com"

        tproxy._strat_cache["rr2---sn-ntq7yner.googlevideo.com"] = "fake5"

        assert tproxy._canary_host(spec) == "rr2---sn-ntq7yner.googlevideo.com"
    finally:
        tproxy._strat_cache.clear()


def test_youtube_web_canary_failure_is_warning_only(monkeypatch):
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_web")
    original = dict(tproxy._route_health[tproxy.SERVICE_YOUTUBE])
    original_window = deque(tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE])

    async def fake_resolve(host, fallback_ip):
        return ["203.0.113.10"]

    async def no_payload(ip, host, strat, probe_spec):
        return 0

    try:
        monkeypatch.setattr(tproxy, "resolve_connection_ips", fake_resolve)
        monkeypatch.setattr(tproxy, "_run_local_payload_probe", no_payload)

        assert asyncio.run(tproxy._run_local_bypass_canary(spec)) == "warning"

        check = tproxy.canary_health_snapshot()["youtube_web"]
        assert check["state"] == tproxy.HEALTH_UNKNOWN
        assert check["last_warning"] == "payload probe failed"
        assert check["failures_5m"] == 0
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_YOUTUBE]
        assert health["state"] != tproxy.HEALTH_DEGRADED
    finally:
        tproxy._route_health[tproxy.SERVICE_YOUTUBE] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE]
        q.clear()
        q.extend(original_window)


def test_geo_exit_canary_failure_does_not_promote_to_local_bypass(monkeypatch):
    monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
    monkeypatch.setattr(tproxy, "_geph_up", False)

    spec = {"group": tproxy.SERVICE_OPENAI, "host": "billing.openai.com"}
    assert not asyncio.run(tproxy._run_geo_exit_canary(spec))

    assert tproxy.is_geo_exit_route("billing.openai.com")
    health = tproxy.route_health_snapshot()[tproxy.SERVICE_OPENAI]
    assert health["state"] == tproxy.HEALTH_BLOCKED
    assert health["last_route_class"] == tproxy.ROUTE_GEO_EXIT


def test_geo_exit_canary_success_clears_stale_geph_failure(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])
    original_failure = dict(tproxy._geph_last_failure)

    class DummyWriter:
        def close(self):
            pass

    async def connected(host, port, first_flight):
        return object(), DummyWriter()

    try:
        monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
        monkeypatch.setattr(tproxy, "_geph_up", True)
        monkeypatch.setattr(tproxy, "dial_via_geph", connected)
        tproxy._geph_last_failure.update({
            "host": "chatgpt.com",
            "reason": "tunnel down",
            "ts": 100.0,
        })

        spec = {"group": tproxy.SERVICE_OPENAI, "host": "chatgpt.com"}
        assert asyncio.run(tproxy._run_geo_exit_canary(spec))

        assert tproxy._geph_last_failure == {"host": "", "reason": "", "ts": 0.0}
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original
        tproxy._geph_last_failure.update(original_failure)


def test_geo_exit_canary_uses_smart_dns_before_geph(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])

    class DummyWriter:
        def close(self):
            pass

    async def system_ips(host):
        assert host == "chatgpt.com"
        return ["203.0.113.10"]

    async def smart_probe(ip, port, first_flight, probe_timeout=3.0):
        assert (ip, port) == ("203.0.113.10", 443)
        return object(), DummyWriter(), b"\x16\x03\x03"

    async def geph_should_not_run(host, port, first_flight):
        raise AssertionError("Geph should not run after Smart DNS succeeds")

    try:
        monkeypatch.setattr(
            tproxy,
            "current_system_dns_status",
            lambda now=None: {
                "state": "xbox_dns",
                "providers": "xbox_dns",
                "servers": ["111.88.96.50"],
                "managed_by_slipstream": False,
            },
        )
        monkeypatch.setattr(tproxy, "system_resolve_async", system_ips)
        monkeypatch.setattr(tproxy, "dial_and_probe", smart_probe)
        monkeypatch.setattr(tproxy, "dial_via_geph", geph_should_not_run)
        monkeypatch.setattr(tproxy, "_geph_up", False)

        spec = {"group": tproxy.SERVICE_OPENAI, "host": "chatgpt.com"}
        assert asyncio.run(tproxy._run_geo_exit_canary(spec))

        assert tproxy._smart_dns_ok_until[tproxy.SERVICE_OPENAI] > 0
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_backend"] == tproxy.GEO_BACKEND_SMART_DNS
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original


def test_geo_exit_canary_falls_back_to_geph_when_smart_dns_fails(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])

    class DummyWriter:
        def close(self):
            pass

    async def system_ips(host):
        return ["203.0.113.10"]

    async def smart_probe(ip, port, first_flight, probe_timeout=3.0):
        return None

    async def geph_connect(host, port, first_flight):
        return object(), DummyWriter()

    try:
        monkeypatch.setattr(
            tproxy,
            "current_system_dns_status",
            lambda now=None: {
                "state": "xbox_dns",
                "providers": "xbox_dns",
                "servers": ["111.88.96.50"],
                "managed_by_slipstream": False,
            },
        )
        monkeypatch.setattr(tproxy, "system_resolve_async", system_ips)
        monkeypatch.setattr(tproxy, "dial_and_probe", smart_probe)
        monkeypatch.setattr(tproxy, "dial_via_geph", geph_connect)
        monkeypatch.setattr(tproxy, "_geph_up", True)

        spec = {"group": tproxy.SERVICE_OPENAI, "host": "chatgpt.com"}
        assert asyncio.run(tproxy._run_geo_exit_canary(spec))

        assert tproxy.SERVICE_OPENAI not in tproxy._smart_dns_ok_until
        assert tproxy._smart_dns_last_failure["host"] == "chatgpt.com"
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_backend"] == tproxy.GEO_BACKEND_GEPH
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original


def test_steam_store_canary_skips_smart_dns_and_uses_geph(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_STEAM_STORE])

    async def smart_should_not_run(spec):
        raise AssertionError("Steam Store should not use Smart DNS")

    async def geph_payload_probe(host, spec):
        assert host == "store.steampowered.com"
        assert spec["payload_probe"] == "https_payload"
        return spec["payload_min_bytes"]

    try:
        monkeypatch.setattr(tproxy, "smart_dns_available", lambda: True)
        monkeypatch.setattr(tproxy, "_run_smart_dns_geo_canary", smart_should_not_run)
        monkeypatch.setattr(tproxy, "_run_geph_payload_probe", geph_payload_probe)
        monkeypatch.setattr(tproxy, "_geph_up", True)

        spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "steam_store")
        assert asyncio.run(tproxy._run_geo_exit_canary(spec))

        health = tproxy.route_health_snapshot()[tproxy.SERVICE_STEAM_STORE]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_backend"] == tproxy.GEO_BACKEND_GEPH
    finally:
        tproxy._route_health[tproxy.SERVICE_STEAM_STORE] = original


def test_steam_store_canary_spec_requires_payload_probe():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "steam_store")

    assert spec["payload_probe"] == "https_payload"
    assert spec["payload_method"] == "GET"
    assert spec["payload_path"] == "/"
    assert spec["payload_min_bytes"] >= 1024
    assert spec["degrade_after"] == tproxy.GEO_EXIT_RUNTIME_DEGRADE_AFTER


def test_owned_geph_backend_canaries_require_three_distinct_payload_hosts():
    specs = tproxy.OWNED_GEPH_PAYLOAD_CANARY_SPECS

    assert len(specs) >= tproxy.GEPH_RESTART_FAILURE_THRESHOLD
    assert len({item["host"] for item in specs}) >= tproxy.GEPH_RESTART_MIN_HOSTS
    assert all(item["payload_method"] == "GET" for item in specs)
    assert all(item["payload_min_bytes"] > 0 for item in specs)


def test_owned_geph_backend_canaries_restart_only_after_all_payloads_fail(
    monkeypatch,
):
    original_geph_up = tproxy._geph_up
    original_geph_owned = tproxy._geph_owned
    original_geph_port = tproxy._geph_port
    original_hint = dict(tproxy._geph_restart_hint)
    tproxy._geph_restart_failures.clear()
    tproxy._geph_restart_hint.update({
        "recommended": False,
        "last_wake_at": 0.0,
        "last_requested_at": 0.0,
    })

    async def no_payload(_host, _spec):
        return 0

    try:
        tproxy._geph_up = True
        tproxy._geph_owned = True
        tproxy._geph_port = tproxy.GEPH_OWNED_PORT
        monkeypatch.setattr(tproxy, "_run_geph_payload_probe", no_payload)

        assert not asyncio.run(tproxy._run_owned_geph_payload_canaries())

        hint = tproxy.geph_restart_hint_snapshot()
        assert hint["recommended"] is True
        assert hint["reason"] == "owned geo-exit tunnel payload unhealthy"
        assert hint["failures_5m"] == len(tproxy.OWNED_GEPH_PAYLOAD_CANARY_SPECS)
        assert hint["hosts_5m"] == len(tproxy.OWNED_GEPH_PAYLOAD_CANARY_SPECS)
    finally:
        tproxy._geph_up = original_geph_up
        tproxy._geph_owned = original_geph_owned
        tproxy._geph_port = original_geph_port
        tproxy._geph_restart_failures.clear()
        tproxy._geph_restart_hint.clear()
        tproxy._geph_restart_hint.update(original_hint)


def test_owned_geph_backend_canary_success_clears_failed_batch(monkeypatch):
    original_geph_up = tproxy._geph_up
    original_geph_owned = tproxy._geph_owned
    original_geph_port = tproxy._geph_port
    original_hint = dict(tproxy._geph_restart_hint)
    tproxy._geph_restart_failures.clear()

    async def one_healthy_payload(host, spec):
        if host == "claude.ai":
            return spec["payload_min_bytes"]
        return 0

    try:
        tproxy._geph_up = True
        tproxy._geph_owned = True
        tproxy._geph_port = tproxy.GEPH_OWNED_PORT
        monkeypatch.setattr(
            tproxy,
            "_run_geph_payload_probe",
            one_healthy_payload,
        )

        assert asyncio.run(tproxy._run_owned_geph_payload_canaries())
        assert not tproxy._geph_restart_failures
        assert not tproxy.geph_restart_hint_snapshot()["recommended"]
    finally:
        tproxy._geph_up = original_geph_up
        tproxy._geph_owned = original_geph_owned
        tproxy._geph_port = original_geph_port
        tproxy._geph_restart_failures.clear()
        tproxy._geph_restart_hint.clear()
        tproxy._geph_restart_hint.update(original_hint)


def test_geo_exit_payload_canary_warns_on_short_payload(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_STEAM_STORE])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_STEAM_STORE])

    async def payload_probe(host, spec):
        assert host == "store.steampowered.com"
        assert spec["payload_probe"] == "https_payload"
        return spec["payload_min_bytes"] - 1

    async def basic_connect_should_not_hide_payload_failure(host, port, first_flight):
        raise AssertionError("payload canary should not stop at SOCKS/TLS connect")

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_STEAM_STORE].clear()
        monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
        monkeypatch.setattr(tproxy, "_geph_up", True)
        monkeypatch.setattr(tproxy, "_run_geph_payload_probe", payload_probe, raising=False)
        monkeypatch.setattr(tproxy, "dial_via_geph", basic_connect_should_not_hide_payload_failure)

        spec = {
            "name": "steam_store",
            "group": tproxy.SERVICE_STEAM_STORE,
            "host": "store.steampowered.com",
            "smart_dns": False,
            "payload_probe": "https_payload",
            "payload_method": "GET",
            "payload_path": "/",
            "payload_min_bytes": 2048,
            "degrade_after": tproxy.GEO_EXIT_RUNTIME_DEGRADE_AFTER,
        }

        assert asyncio.run(tproxy._run_geo_exit_canary(spec)) == "warning"

        health = tproxy.canary_health_snapshot()["steam_store"]
        assert health["state"] == tproxy.HEALTH_UNKNOWN
        assert health["last_warning"] == "payload throughput below threshold"
        assert health["last_warning_host"] == "store.steampowered.com"
    finally:
        tproxy._route_health[tproxy.SERVICE_STEAM_STORE] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_STEAM_STORE]
        q.clear()
        q.extend(original_window)


def test_secondary_geo_exit_canary_failure_does_not_override_core_ok():
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_OPENAI])

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_OPENAI].clear()
        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "chatgpt.com",
            ok=True,
            now=100.0,
        )
        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "billing.openai.com",
            ok=False,
            reason="SOCKS connect failed",
            soft=True,
            now=110.0,
        )

        health = tproxy.route_health_snapshot(now=110.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_failure"] == ""
        assert health["last_warning"] == "SOCKS connect failed"
        assert health["last_warning_host"] == "billing.openai.com"
        assert health["failures_5m"] == 0
        assert health["last_host"] == "chatgpt.com"

        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "chatgpt.com",
            ok=False,
            reason="SOCKS connect failed",
            now=115.0,
        )
        health = tproxy.route_health_snapshot(now=115.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_failure"] == "SOCKS connect failed"

        health = tproxy.route_health_snapshot(now=500.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_UNKNOWN
        assert health["last_failure"] == ""
        assert health["failures_5m"] == 0

        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "chatgpt.com",
            ok=False,
            reason="tunnel down",
            state=tproxy.HEALTH_BLOCKED,
            now=120.0,
        )
        health = tproxy.route_health_snapshot(now=120.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_BLOCKED
        assert health["last_failure"] == "tunnel down"
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_OPENAI]
        q.clear()
        q.extend(original_window)


def test_billing_stays_geo_exit_without_becoming_a_health_canary():
    assert tproxy.route_policy("billing.openai.com")["route_class"] == tproxy.ROUTE_GEO_EXIT
    assert "openai_billing" not in {item["name"] for item in tproxy.CANARY_SPECS}


def test_geo_exit_canary_warns_before_degrade_threshold(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_OPENAI])
    original_state = dict(tproxy._canary_state)

    async def no_connect(host, port, first_flight):
        return None

    try:
        monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
        tproxy._route_health[tproxy.SERVICE_OPENAI] = tproxy._route_health_default(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
        )
        tproxy._route_failure_windows[tproxy.SERVICE_OPENAI].clear()
        monkeypatch.setattr(tproxy, "_geph_up", True)
        monkeypatch.setattr(tproxy, "dial_via_geph", no_connect)
        monkeypatch.setattr(tproxy, "CANARY_SPECS", (
            {
                "name": "openai_secondary",
                "group": tproxy.SERVICE_OPENAI,
                "host": "chatgpt.com",
                "degrade_after": tproxy.GEO_EXIT_RUNTIME_DEGRADE_AFTER,
            },
        ))

        ok, degraded = asyncio.run(tproxy.run_route_canaries("test"))

        assert (ok, degraded) == (0, 0)
        assert tproxy._canary_state["degraded"] == 0
        assert tproxy._canary_state["warnings"] == 1
        assert tproxy.canary_status_snapshot()["warnings"] == 1
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_UNKNOWN
        assert health["last_warning"] == "SOCKS connect failed"
        assert health["failures_5m"] == 1

        for _ in range(1, tproxy.GEO_EXIT_RUNTIME_DEGRADE_AFTER):
            ok, degraded = asyncio.run(tproxy.run_route_canaries("test"))

        assert (ok, degraded) == (0, 1)
        assert tproxy._canary_state["degraded"] == 1
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_failure"] == "SOCKS connect failed"
        assert health["last_host"] == "chatgpt.com"
    finally:
        tproxy._canary_state.clear()
        tproxy._canary_state.update(original_state)
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_OPENAI]
        q.clear()
        q.extend(original_window)


def test_socks_only_geo_canary_never_contributes_payload_restart_evidence(
    monkeypatch,
):
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])
    original_geph_up = tproxy._geph_up
    original_geph_owned = tproxy._geph_owned
    original_geph_port = tproxy._geph_port
    tproxy._geph_restart_failures.clear()

    async def no_connect(_host, _port, _first_flight):
        return None

    try:
        tproxy._geph_up = True
        tproxy._geph_owned = True
        tproxy._geph_port = tproxy.GEPH_OWNED_PORT
        monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
        monkeypatch.setattr(tproxy, "dial_via_geph", no_connect)
        spec = {
            "name": "openai_socks_only",
            "group": tproxy.SERVICE_OPENAI,
            "host": "chatgpt.com",
        }

        assert not asyncio.run(tproxy._run_geo_exit_canary(spec))
        assert not tproxy._geph_restart_failures
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original
        tproxy._geph_up = original_geph_up
        tproxy._geph_owned = original_geph_owned
        tproxy._geph_port = original_geph_port
        tproxy._geph_restart_failures.clear()


def test_runtime_geo_exit_failures_require_repeated_signal():
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_OPENAI])

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_OPENAI].clear()
        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "chatgpt.com",
            ok=True,
            now=100.0,
        )

        for i, now in enumerate((110.0, 120.0), start=1):
            tproxy.route_health_event(
                tproxy.SERVICE_OPENAI,
                tproxy.ROUTE_GEO_EXIT,
                "persistent.oaistatic.com",
                ok=False,
                reason="remote closed without response",
                degrade_after=tproxy.GEO_EXIT_RUNTIME_DEGRADE_AFTER,
                now=now,
            )
            health = tproxy.route_health_snapshot(now=now)[tproxy.SERVICE_OPENAI]
            assert health["state"] == tproxy.HEALTH_OK
            assert health["last_failure"] == ""
            assert health["last_warning"] == "remote closed without response"
            assert health["last_warning_host"] == "persistent.oaistatic.com"
            assert health["failures_5m"] == i
            assert health["last_host"] == "chatgpt.com"

        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "persistent.oaistatic.com",
            ok=False,
            reason="remote closed without response",
            degrade_after=tproxy.GEO_EXIT_RUNTIME_DEGRADE_AFTER,
            now=130.0,
        )
        health = tproxy.route_health_snapshot(now=130.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_failure"] == "remote closed without response"
        assert health["failures_5m"] == tproxy.GEO_EXIT_RUNTIME_DEGRADE_AFTER
        assert health["last_host"] == "persistent.oaistatic.com"
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_OPENAI]
        q.clear()
        q.extend(original_window)


def test_pf_rules_leave_quic_unblocked():
    assert "slipstream_quic_block" not in tproxy.PF_RULES
    assert "proto udp" not in tproxy.PF_RULES
    assert "block return quick inet proto udp from any to any port 443" not in tproxy.PF_RULES


def test_youtube_media_hosts_try_plain_before_cached_local_fallback():
    host = "rr2---sn-ntq7yner.googlevideo.com"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64"

    try:
        names = [s["name"] for s in tproxy.strategy_order(host)]

        assert names[:2] == ["plain", "split64"]
    finally:
        tproxy._strat_cache.clear()


def test_local_strategy_score_demotes_failed_cached_fake_strategy():
    host = "gateway.discord.gg"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64+fake"

    try:
        tproxy._record_strategy_result(host, "split64+fake", False, now=100.0)
        names = [s["name"] for s in tproxy.strategy_order(host)]

        assert names == ["split16+fake", "fake5", "split64+fake"]
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()


def test_local_strategy_score_keeps_successful_cached_fake_strategy_first():
    host = "gateway.discord.gg"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64+fake"

    try:
        tproxy._record_strategy_result(host, "split64+fake", True, now=100.0)
        names = [s["name"] for s in tproxy.strategy_order(host)]

        assert names == ["split64+fake", "split16+fake", "fake5"]
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()


def test_clear_route_strategy_cache_removes_strategy_scores():
    host = "gateway.discord.gg"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64+fake"
    tproxy._record_strategy_result(host, "split64+fake", False, now=100.0)

    try:
        assert tproxy.clear_route_strategy_cache(host=host) == 1

        assert host not in tproxy._strat_cache
        assert host not in tproxy._strat_scores
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()


def test_discord_hosts_use_fake_only_local_bypass_strategy():
    host = "gateway.discord.gg"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64"

    try:
        names = [s["name"] for s in tproxy.strategy_order(host)]

        assert names == ["split64+fake", "split16+fake", "fake5"]
    finally:
        tproxy._strat_cache.clear()


def test_discord_hosts_do_not_route_via_geph():
    assert not tproxy.is_geo_exit_route("updates.discord.com")
    assert not tproxy.is_geo_exit_route("gateway.discord.gg")
    assert not tproxy.is_geo_exit_route("discord.com")
    assert not tproxy.is_geo_exit_route("status.discordstatus.com")
    assert not tproxy.is_geo_exit_route("cdn.discordapp.com")
    assert not tproxy.is_geo_exit_route("discord-activities.com")


def test_geph_route_failure_log_is_rate_limited(capsys):
    tproxy._geph_fail_log.clear()

    try:
        tproxy.log_geph_route_failure("billing.openai.com", "SOCKS connect failed", now=10.0)
        tproxy.log_geph_route_failure("billing.openai.com", "SOCKS connect failed", now=20.0)
        tproxy.log_geph_route_failure(
            "billing.openai.com", "remote closed without response", now=30.0
        )
        tproxy.log_geph_route_failure("billing.openai.com", "SOCKS connect failed", now=71.0)

        err = capsys.readouterr().err
        assert err.count("billing.openai.com") == 3
        assert "geph route retry for billing.openai.com" in err
        assert "geph route failed" not in err
        assert "SOCKS connect failed" in err
        assert "remote closed without response" in err
    finally:
        tproxy._geph_fail_log.clear()


def test_transient_runtime_logs_avoid_failed_wording():
    root = Path(__file__).resolve().parents[1]
    sources = [
        root / "spike" / "tproxy.py",
        root / "vendor" / "tg-ws-proxy" / "proxy" / "tg_ws_proxy.py",
        root / "vendor" / "tg-ws-proxy" / "proxy" / "bridge.py",
        root / "vendor" / "tg-ws-proxy" / "proxy" / "config.py",
    ]
    text = "\n".join(path.read_text() for path in sources)

    for alarming in [
        "geph route failed",
        "route canaries failed",
        "voice sniffer failed",
        "fronting failed",
        "WS connect failed",
        "CF proxy failed",
        "CF worker %s failed",
        "TCP fallback to %s:%d failed",
        "Failed to fetch CF proxy domain list",
        "CF proxy domain refresh failed",
    ]:
        assert alarming not in text


def test_geo_exit_failures_after_wake_recommend_owned_geph_restart(capsys):
    original_geph_up = tproxy._geph_up
    original_geph_owned = tproxy._geph_owned
    original_geph_port = tproxy._geph_port
    original_hint = dict(tproxy._geph_restart_hint)
    tproxy._geph_fail_log.clear()
    tproxy._geph_restart_failures.clear()

    try:
        tproxy._geph_up = True
        tproxy._geph_owned = True
        tproxy._geph_port = tproxy.GEPH_OWNED_PORT
        tproxy.note_geph_wake(1000.0)

        tproxy.log_geph_route_failure("chatgpt.com", "first payload timeout", now=1001.0)
        assert not tproxy.geph_restart_hint_snapshot(now=1001.0)["recommended"]

        tproxy.log_geph_route_failure(
            "persistent.oaistatic.com",
            "remote closed without response",
            now=1002.0,
        )
        tproxy.log_geph_route_failure("api.anthropic.com", "SOCKS connect failed", now=1003.0)

        hint = tproxy.geph_restart_hint_snapshot(now=1003.0)
        assert hint["recommended"] is True
        assert hint["reason"] == "geo-exit tunnel stale after wake"
        assert hint["failures_5m"] == 3
        assert hint["hosts_5m"] == 3
        assert hint["last_failure_host"] == "api.anthropic.com"
    finally:
        capsys.readouterr()
        tproxy._geph_up = original_geph_up
        tproxy._geph_owned = original_geph_owned
        tproxy._geph_port = original_geph_port
        tproxy._geph_fail_log.clear()
        tproxy._geph_restart_failures.clear()
        tproxy._geph_restart_hint.clear()
        tproxy._geph_restart_hint.update(original_hint)


def test_hard_geo_canaries_restart_owned_backend_after_cross_host_payload_loss(
    monkeypatch,
    capsys,
):
    original_hint = dict(tproxy._geph_restart_hint)
    tproxy._geph_fail_log.clear()
    tproxy._geph_restart_failures.clear()
    tproxy._geph_restart_hint.update({
        "recommended": False,
        "last_wake_at": 0.0,
        "last_requested_at": 0.0,
    })

    async def no_payload(_host, _spec):
        return 0

    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
    monkeypatch.setattr(tproxy, "_run_geph_payload_probe", no_payload)
    specs = (
        {
            "name": "owned_backend_openai",
            "group": tproxy.SERVICE_OPENAI,
            "host": "chatgpt.com",
            "smart_dns": False,
            "payload_probe": "https_payload",
        },
        {
            "name": "owned_backend_anthropic",
            "group": tproxy.SERVICE_ANTHROPIC,
            "host": "claude.ai",
            "smart_dns": False,
            "payload_probe": "https_payload",
        },
        {
            "name": "owned_backend_steam",
            "group": tproxy.SERVICE_STEAM_STORE,
            "host": "store.steampowered.com",
            "smart_dns": False,
            "payload_probe": "https_payload",
        },
    )

    try:
        for spec in specs:
            assert not asyncio.run(tproxy._run_geo_exit_canary(spec))

        hint = tproxy.geph_restart_hint_snapshot()
        assert hint["recommended"] is True
        assert hint["reason"] == "owned geo-exit tunnel payload unhealthy"
        assert hint["failures_5m"] == 3
        assert hint["hosts_5m"] == 3
        assert hint["last_failure_host"] == "store.steampowered.com"
    finally:
        capsys.readouterr()
        tproxy._geph_fail_log.clear()
        tproxy._geph_restart_failures.clear()
        tproxy._geph_restart_hint.clear()
        tproxy._geph_restart_hint.update(original_hint)


def test_soft_geo_canary_never_requests_owned_backend_restart(monkeypatch):
    tproxy._geph_restart_failures.clear()

    async def no_payload(_host, _spec):
        return 0

    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
    monkeypatch.setattr(tproxy, "_run_geph_payload_probe", no_payload)
    spec = {
        "name": "optional_geo_endpoint",
        "group": tproxy.SERVICE_OPENAI,
        "host": "chatgpt.com",
        "smart_dns": False,
        "payload_probe": "https_payload",
        "soft": True,
    }

    assert asyncio.run(tproxy._run_geo_exit_canary(spec)) == "warning"
    assert not tproxy._geph_restart_failures


def test_geo_exit_failures_never_request_unowned_geph_restart(capsys):
    original_geph_up = tproxy._geph_up
    original_geph_owned = tproxy._geph_owned
    original_geph_port = tproxy._geph_port
    original_hint = dict(tproxy._geph_restart_hint)
    tproxy._geph_fail_log.clear()
    tproxy._geph_restart_failures.clear()

    try:
        tproxy._geph_up = True
        tproxy._geph_owned = False
        tproxy._geph_port = 9909
        tproxy.note_geph_wake(1000.0)

        for offset, host in enumerate(
            ("chatgpt.com", "persistent.oaistatic.com", "api.anthropic.com"),
            start=1,
        ):
            tproxy.log_geph_route_failure(
                host,
                "SOCKS connect failed",
                now=1000.0 + offset,
            )

        hint = tproxy.geph_restart_hint_snapshot(now=1003.0)
        assert hint["recommended"] is False
        assert hint["failures_5m"] == 0
        assert not tproxy.request_owned_geph_restart(
            "chatgpt.com",
            "SOCKS connect failed",
            now=1004.0,
        )
    finally:
        capsys.readouterr()
        tproxy._geph_up = original_geph_up
        tproxy._geph_owned = original_geph_owned
        tproxy._geph_port = original_geph_port
        tproxy._geph_fail_log.clear()
        tproxy._geph_restart_failures.clear()
        tproxy._geph_restart_hint.clear()
        tproxy._geph_restart_hint.update(original_hint)


def test_owned_geph_launch_target_requires_exact_user_claim():
    state = {"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL}

    assert tproxy._owned_geph_launch_target(state, 502) == (
        "gui/502/dev.slipstream.geph"
    )
    assert tproxy._owned_geph_launch_target(state, 503) is None
    assert tproxy._owned_geph_launch_target(
        {"uid": 502, "launchd_label": "com.example.geph"},
        502,
    ) is None
    assert tproxy._owned_geph_launch_target(
        {"uid": 0, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        0,
    ) is None
    assert tproxy._owned_geph_launch_target(
        {"uid": True, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        1,
    ) is None


def test_owned_geph_restart_rejects_symlinked_ownership_file(monkeypatch, tmp_path):
    target = tmp_path / "claim-target.json"
    target.write_text("{}")
    claim = tmp_path / "geph-owned.json"
    claim.symlink_to(target)
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    calls = []

    result = tproxy.execute_owned_geph_restart(
        now=100.0,
        active_sessions=0,
        ownership_path=str(claim),
        ownership_state={
            "uid": target.stat().st_uid,
            "launchd_label": tproxy.GEPH_LAUNCHD_LABEL,
        },
        listener_owned=True,
        runner=lambda *args: calls.append(args),
        backend_suspender=lambda: calls.append(("cool",)),
    )

    assert result == "unverified"
    assert calls == []


def test_owned_geph_restart_waits_for_active_tunnel(monkeypatch):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    calls = []

    result = tproxy.execute_owned_geph_restart(
        now=100.0,
        active_sessions=1,
        ownership_path="/tmp/geph-owned.json",
        ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        owner_uid=502,
        listener_owned=True,
        runner=lambda *args: calls.append(args),
        backend_suspender=lambda: calls.append(("cool",)),
    )

    assert result == "busy"
    assert calls == []
    assert hint["recommended"] is True


def test_owned_geph_restart_does_nothing_during_shutdown(monkeypatch):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    tproxy._shutdown_started.set()
    calls = []

    result = tproxy.execute_owned_geph_restart(
        now=100.0,
        active_sessions=0,
        ownership_path="/tmp/geph-owned.json",
        ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        owner_uid=502,
        listener_owned=True,
        runner=lambda *args: calls.append(("run", args)),
        backend_suspender=lambda: calls.append(("cool",)),
    )

    assert result == "shutdown"
    assert calls == []
    assert hint["last_attempt_at"] == 0.0


def test_owned_geph_restart_does_not_kickstart_if_shutdown_begins_while_cooling(
    monkeypatch,
):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    calls = []

    def cool_and_shutdown():
        calls.append("cool")
        tproxy._shutdown_started.set()

    result = tproxy.execute_owned_geph_restart(
        now=100.0,
        active_sessions=0,
        ownership_path="/tmp/geph-owned.json",
        ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        owner_uid=502,
        listener_owned=True,
        runner=lambda *args: calls.append(("run", args)),
        backend_suspender=cool_and_shutdown,
    )

    assert result == "shutdown"
    assert calls == ["cool"]


def test_owned_geph_restart_cools_backend_and_kickstarts_exact_launchagent(monkeypatch):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_restart_failures", deque([(99.0, "chatgpt.com", "stale")]))
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    listener_pids = iter((100, 101))
    monkeypatch.setattr(
        tproxy,
        "_geph_listener_pid",
        lambda _port: next(listener_pids),
    )
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        lambda _pid=None, **_kwargs: "ready",
    )
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    events = []

    def run(*args):
        events.append(("run",) + args)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        tproxy,
        "note_runtime_rearm",
        lambda reason, **_kwargs: events.append(("rearm", reason)),
    )
    monkeypatch.setattr(
        tproxy,
        "suspend_geo_exit_backend",
        lambda reason, now=None: events.append(("cool", reason, now)),
    )
    result = tproxy.execute_owned_geph_restart(
        now=100.0,
        ownership_path="/tmp/geph-owned.json",
        ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        owner_uid=502,
        listener_owned=True,
        runner=run,
    )

    assert result == "restarted"
    assert events == [
        ("cool", "owned Geph restart in progress", 100.0),
        ("run", "/bin/launchctl", "kickstart", "-k", "gui/502/dev.slipstream.geph"),
        ("rearm", "geph_restart"),
    ]
    assert hint["recommended"] is False
    assert tproxy._geph_restart_draining is True
    tproxy._finish_geph_restart_drain()
    assert tproxy._geph_restart_draining is False


def test_owned_geph_restart_adopts_delayed_successor_after_command_timeout(
    monkeypatch,
    capsys,
):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    listener_pids = iter((100, 101))
    monkeypatch.setattr(
        tproxy,
        "_geph_listener_pid",
        lambda _port: next(listener_pids),
    )

    def recovery_probe(successor_pid, **_kwargs):
        assert tproxy._geph_restart_draining is True
        assert successor_pid == 101
        return "ready"

    monkeypatch.setattr(tproxy, "_probe_owned_geph_recovery_state", recovery_probe)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    calls = []

    def timed_out(*args):
        calls.append(args)
        return SimpleNamespace(
            returncode=124,
            stdout="",
            stderr="timed out after 5s",
        )

    result = tproxy.execute_owned_geph_restart(
        now=100.0,
        ownership_path="/tmp/geph-owned.json",
        ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        owner_uid=502,
        listener_owned=True,
        runner=timed_out,
        backend_suspender=lambda: None,
    )

    assert result == "restarted"
    assert len(calls) == 1
    assert hint["recommended"] is False
    assert tproxy._geph_restart_draining is True
    stderr = capsys.readouterr().err
    assert "completion was indeterminate" in stderr
    assert "recovery unavailable" not in stderr
    tproxy._finish_geph_restart_drain()


def test_owned_geph_restart_preserves_timeout_diagnostics(monkeypatch, capsys):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "GEPH_RESTART_SUCCESSOR_GRACE", 0.0)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        lambda _pid=None, **_kwargs: "down",
    )
    monkeypatch.setattr(tproxy, "geph_listener_owned", lambda *args, **kwargs: True)

    def timed_out(*_args):
        raise subprocess.TimeoutExpired(
            cmd="launchctl kickstart",
            timeout=5,
            output=b"launch still active",
            stderr=b"delayed successor",
        )

    result = tproxy.execute_owned_geph_restart(
        now=100.0,
        ownership_path="/tmp/geph-owned.json",
        ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        owner_uid=502,
        listener_owned=True,
        runner=timed_out,
        backend_suspender=lambda: None,
    )

    assert result == "unavailable"
    assert "delayed successor" in capsys.readouterr().err


def test_owned_geph_restart_shutdown_while_waiting_is_quiet(monkeypatch, capsys):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(tproxy, "geph_listener_owned", lambda *args, **kwargs: True)
    monkeypatch.setattr(tproxy, "_wait_for_owned_geph_successor", lambda _pid: "shutdown")

    result = tproxy.execute_owned_geph_restart(
        now=100.0,
        ownership_path="/tmp/geph-owned.json",
        ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        owner_uid=502,
        listener_owned=True,
        runner=lambda *_args: SimpleNamespace(returncode=0, stdout="", stderr=""),
        backend_suspender=lambda: None,
    )

    assert result == "shutdown"
    assert tproxy._geph_restart_draining is False
    assert "recovery unavailable" not in capsys.readouterr().err


def test_owned_geph_restart_timeout_without_successor_fails_closed(monkeypatch, capsys):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "GEPH_RESTART_SUCCESSOR_GRACE", 0.0)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        lambda _pid=None, **_kwargs: "down",
    )
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    calls = []

    def timed_out(*args):
        calls.append(args)
        return SimpleNamespace(returncode=124, stdout="", stderr="timed out after 5s")

    kwargs = {
        "ownership_path": "/tmp/geph-owned.json",
        "ownership_state": {"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        "owner_uid": 502,
        "listener_owned": True,
        "runner": timed_out,
        "backend_suspender": lambda: None,
    }
    assert tproxy.execute_owned_geph_restart(now=100.0, **kwargs) == "unavailable"
    assert tproxy.execute_owned_geph_restart(now=101.0, **kwargs) == "cooldown"
    assert len(calls) == 1
    assert hint["recommended"] is True
    assert tproxy._geph_restart_draining is False
    assert "no verified owned successor appeared (timeout)" in capsys.readouterr().err


def test_owned_geph_restart_rejects_unowned_successor_after_timeout(monkeypatch):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    listener_pids = iter((100, 999))
    monkeypatch.setattr(
        tproxy,
        "_geph_listener_pid",
        lambda _port: next(listener_pids),
    )
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        lambda _pid=None, **_kwargs: "conflict",
    )
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    calls = []

    def timed_out(*args):
        calls.append(args)
        return SimpleNamespace(returncode=124, stdout="", stderr="timed out after 5s")

    result = tproxy.execute_owned_geph_restart(
        now=100.0,
        ownership_path="/tmp/geph-owned.json",
        ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        owner_uid=502,
        listener_owned=True,
        runner=timed_out,
        backend_suspender=lambda: None,
    )

    assert result == "unavailable"
    assert len(calls) == 1
    assert hint["recommended"] is True
    assert tproxy._geph_restart_draining is False
    assert tproxy._geph_port_conflict is True
    assert tproxy._geph_port is None
    assert tproxy._geph_owned is False
    assert tproxy._geph_up is False


def test_owned_geph_restart_never_touches_unverified_listener(monkeypatch):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    calls = []

    result = tproxy.execute_owned_geph_restart(
        now=100.0,
        active_sessions=0,
        ownership_path="/tmp/geph-owned.json",
        ownership_state={"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        owner_uid=502,
        listener_owned=False,
        runner=lambda *args: calls.append(args),
        backend_suspender=lambda: calls.append(("cool",)),
    )

    assert result == "unverified"
    assert calls == []
    assert hint["recommended"] is True


def test_owned_geph_restart_rate_limits_launchctl_retry(monkeypatch, capsys):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    calls = []

    def unavailable(*args):
        calls.append(args)
        return SimpleNamespace(returncode=1, stdout="", stderr="job unavailable")

    kwargs = {
        "active_sessions": 0,
        "ownership_path": "/tmp/geph-owned.json",
        "ownership_state": {"uid": 502, "launchd_label": tproxy.GEPH_LAUNCHD_LABEL},
        "owner_uid": 502,
        "listener_owned": True,
        "runner": unavailable,
        "backend_suspender": lambda: None,
    }
    assert tproxy.execute_owned_geph_restart(now=100.0, **kwargs) == "unavailable"
    assert tproxy.execute_owned_geph_restart(now=101.0, **kwargs) == "cooldown"
    assert len(calls) == 1
    assert hint["recommended"] is True
    capsys.readouterr()


def test_geph_active_session_counter_never_underflows(monkeypatch):
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)

    assert tproxy._geph_session_started()
    assert tproxy._geph_session_started()
    assert tproxy.geph_active_session_count() == 2
    tproxy._geph_session_finished()
    tproxy._geph_session_finished()
    tproxy._geph_session_finished()
    assert tproxy.geph_active_session_count() == 0


def test_geph_restart_drain_blocks_new_sessions(monkeypatch):
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)

    assert tproxy._begin_geph_restart_drain()
    assert not tproxy._geph_session_started()
    assert tproxy.geph_active_session_count() == 0
    tproxy._finish_geph_restart_drain()
    assert tproxy._geph_session_started()
    tproxy._geph_session_finished()


def test_learned_auto_geph_cache_never_overrides_explicit_policy(monkeypatch):
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    tproxy._auto_geph.clear()
    tproxy._auto_geph["updates.discord.com"] = tproxy.time.time() + 3600
    tproxy._auto_geph["rr2---sn-ntq7yner.googlevideo.com"] = tproxy.time.time() + 3600
    tproxy._auto_geph["www.google.com"] = tproxy.time.time() + 3600
    tproxy._auto_geph["api.spotify.com"] = tproxy.time.time() + 3600
    tproxy._auto_geph["payments.example.com"] = tproxy.time.time() + 3600

    try:
        assert not tproxy.is_geo_exit_route("updates.discord.com")
        assert not tproxy.is_geo_exit_route("rr2---sn-ntq7yner.googlevideo.com")
        assert not tproxy.is_geo_exit_route("www.google.com")
        assert not tproxy.is_geo_exit_route("api.spotify.com")
        assert not tproxy.is_geo_exit_route("payments.example.com")
        assert tproxy.is_geo_exit_route("chatgpt.com")
        assert (
            tproxy.runtime_route_policy("payments.example.com")["route_class"]
            == tproxy.ROUTE_GEO_EXIT
        )
        assert tproxy.runtime_route_policy(
            "www.google.com"
        ) == tproxy.route_policy("www.google.com")
        assert tproxy.runtime_route_policy(
            "updates.discord.com"
        ) == tproxy.route_policy("updates.discord.com")
    finally:
        tproxy._auto_geph.clear()


def test_learned_auto_geph_policy_survives_without_current_owned_listener(
    monkeypatch,
):
    host = "payments.example.com"
    tproxy._auto_geph[host] = tproxy.time.time() + 3600
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_EXTERNAL_PORT)
    monkeypatch.setattr(tproxy, "_geph_owned", False)

    try:
        policy = tproxy.runtime_route_policy(host)
        assert policy["route_class"] == tproxy.ROUTE_GEO_EXIT
        assert policy["strategy_set"] == tproxy.STRATEGY_GEPH
        assert policy["runtime_learned"] is True
        assert tproxy._auto_geph_learned_exact_host(host)
    finally:
        tproxy._auto_geph.clear()


def test_auto_geph_candidate_requires_owned_backend_and_exact_local_evidence(
    monkeypatch,
):
    host = "payments.example.com"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    assert not tproxy._auto_geph_candidate_proven(host, now=100.0)
    assert not tproxy._auto_geph_candidate_allowed(host, now=100.0)
    tproxy._auto_geph_candidates[host] = 200.0
    assert tproxy._auto_geph_candidate_proven(host, now=100.0)
    assert tproxy._auto_geph_candidate_allowed(host, now=100.0)

    for protected in (
        "updates.discord.com",
        "rr2---sn-ntq7yner.googlevideo.com",
        "t.me",
        "www.google.com",
        "api.spotify.com",
        "chatgpt.com",
    ):
        tproxy._auto_geph_candidates[protected] = 200.0
        assert not tproxy._auto_geph_candidate_proven(protected, now=100.0)
        assert not tproxy._auto_geph_candidate_allowed(protected, now=100.0)

    monkeypatch.setattr(tproxy, "_geph_owned", False)
    assert tproxy._auto_geph_candidate_proven(host, now=100.0)
    assert not tproxy._auto_geph_candidate_allowed(host, now=100.0)


def test_semantic_signal_schedules_only_exact_unknown_host_confirmation(
    monkeypatch,
):
    host = "regional-denial.example"
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    assert tproxy._request_semantic_geo_exit_confirmation(
        host,
        now=100.0,
        confirmation_runner=confirmations.append,
    )

    assert confirmations == [host]
    assert not tproxy._auto_geph_candidate_allowed(host, now=100.0)
    assert host not in tproxy._auto_geph_candidates
    assert tproxy.route_policy(host)["route_class"] == tproxy.ROUTE_UNKNOWN
    assert not tproxy.is_geo_exit_route(host)
    assert not tproxy._auto_geph
    assert tproxy._auto_geph_last_status["reason"] == "regional denial observed"


def test_semantic_signal_never_authorizes_protected_routes(monkeypatch):
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for host in (
        "updates.discord.com",
        "rr2---sn-ntq7yner.googlevideo.com",
        "www.google.com",
        "api.spotify.com",
        "chatgpt.com",
    ):
        assert not tproxy._request_semantic_geo_exit_confirmation(
            host,
            now=100.0,
            confirmation_runner=confirmations.append,
        )
        assert host not in tproxy._auto_geph_candidates

    assert confirmations == []


def test_semantic_signal_requires_owned_geph(monkeypatch):
    host = "regional-denial.example"
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", False)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_EXTERNAL_PORT)

    assert not tproxy._request_semantic_geo_exit_confirmation(
        host,
        now=100.0,
        confirmation_runner=confirmations.append,
    )

    assert confirmations == []
    assert host not in tproxy._auto_geph_candidates


def test_semantic_geph_response_requires_usable_non_denial_http():
    assert tproxy._semantic_geph_response_usable(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        b"<html><main>Weather forecast</main></html>"
    )
    assert not tproxy._semantic_geph_response_usable(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        b"This content is no longer available in your area"
    )
    assert not tproxy._semantic_geph_response_usable(
        b"HTTP/1.1 451 Unavailable For Legal Reasons\r\n\r\n"
    )
    assert not tproxy._semantic_geph_response_usable(
        b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\n\r\n"
        b"local_rate_limited"
    )
    assert not tproxy._semantic_geph_response_usable(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        b"local_rate_limited"
    )
    assert not tproxy._semantic_geph_response_usable(
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n"
        b"\x1f\x8bopaque"
    )


def test_plain_semantic_response_recognizes_only_regional_denial():
    denial = b"This content is no longer available in your area"
    assert tproxy._semantic_plain_response_is_regional_denial(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + denial
    )
    assert tproxy._semantic_plain_response_is_regional_denial(
        b"HTTP/1.1 451 Unavailable For Legal Reasons\r\n\r\n" + denial
    )
    assert not tproxy._semantic_plain_response_is_regional_denial(
        b"HTTP/1.1 200 OK\r\n\r\nOrdinary page"
    )
    assert not tproxy._semantic_plain_response_is_regional_denial(
        b"HTTP/1.1 429 Too Many Requests\r\n\r\nlocal_rate_limited"
    )
    assert not tproxy._semantic_plain_response_is_regional_denial(
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n" + denial
    )
    first = b"This content is no l"
    second = b"onger available in your area"
    chunked = (
        b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n"
        + f"{len(first):x}\r\n".encode()
        + first
        + b"\r\n"
        + f"{len(second):x}\r\n".encode()
        + second
        + b"\r\n0\r\n\r\n"
    )
    assert tproxy._semantic_plain_response_is_regional_denial(
        chunked,
        stream_closed=False,
    )


@pytest.mark.parametrize("complete", (True, False))
def test_plain_semantic_probe_requires_complete_exact_ip_response(
    monkeypatch,
    complete,
):
    body = b"This content is no longer available in your area"
    declared = len(body) if complete else len(body) + 50
    response = (
        b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
        + f"Content-Length: {declared}\r\n\r\n".encode()
        + body
    )

    class FakeTlsSocket:
        def __init__(self):
            self.chunks = deque((response, b""))
            self.request = b""
            self.closed = False

        def settimeout(self, _timeout):
            return None

        def sendall(self, payload):
            self.request += payload

        def recv(self, _size):
            return self.chunks.popleft()

        def close(self):
            self.closed = True

    tls_socket = FakeTlsSocket()
    connections = []
    server_names = []
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(
        tproxy.socket,
        "create_connection",
        lambda address, timeout: (
            connections.append((address, timeout)) or tls_socket
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_local_payload_ssl_context",
        lambda: SimpleNamespace(
            wrap_socket=lambda _sock, server_hostname: (
                server_names.append(server_hostname) or tls_socket
            )
        ),
    )

    assert tproxy._semantic_plain_denial_probe(
        "1.1.1.1",
        "regional-denial.example",
    ) is complete
    assert connections == [(('1.1.1.1', 443), 6.0)]
    assert server_names == ["regional-denial.example"]
    assert b"Accept-Encoding: identity\r\n" in tls_socket.request
    assert b"Range: bytes=0-131071\r\n" in tls_socket.request
    assert tls_socket.closed


def test_plain_semantic_probe_schedules_exact_host_confirmation(monkeypatch):
    host = "regional-denial.example"
    direct_probes = []
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    assert tproxy._schedule_semantic_plain_denial_probe(
        host,
        "1.1.1.1",
        "plain",
        now=100.0,
        runner=lambda ip, candidate: (
            direct_probes.append((ip, candidate)) or True
        ),
        confirmation_runner=lambda candidate: (
            confirmations.append(candidate) or True
        ),
    )
    assert direct_probes == [("1.1.1.1", host)]
    assert confirmations == [host]
    assert host not in tproxy._semantic_plain_confirming
    assert tproxy._semantic_plain_last_probe[host] == 100.0
    assert not tproxy._schedule_semantic_plain_denial_probe(
        host,
        "1.1.1.1",
        "plain",
        now=101.0,
        runner=lambda _ip, _host: True,
    )


def test_plain_semantic_probe_excludes_protected_and_unowned_routes(monkeypatch):
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    for host in (
        "updates.discord.com",
        "rr2---sn-ntq7yner.googlevideo.com",
        "www.google.com",
    ):
        assert not tproxy._schedule_semantic_plain_denial_probe(
            host,
            "1.1.1.1",
            "plain",
            now=100.0,
            runner=lambda _ip, _host: True,
        )
    assert not tproxy._schedule_semantic_plain_denial_probe(
        "regional-denial.example",
        "127.0.0.1",
        "plain",
        now=100.0,
        runner=lambda _ip, _host: True,
    )


def test_plain_semantic_probe_has_a_small_network_wide_budget(monkeypatch):
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    tproxy._semantic_plain_probe_window.extend(
        [100.0] * tproxy.SEMANTIC_PLAIN_PROBE_WINDOW_MAX
    )

    assert not tproxy._schedule_semantic_plain_denial_probe(
        "budgeted-regional-denial.example",
        "1.1.1.1",
        "plain",
        now=100.1,
        runner=lambda _ip, _host: True,
    )
    assert tproxy._schedule_semantic_plain_denial_probe(
        "budgeted-regional-denial.example",
        "1.1.1.1",
        "plain",
        now=161.0,
        runner=lambda _ip, _host: False,
    )
    monkeypatch.setattr(tproxy, "_geph_owned", False)
    assert not tproxy._schedule_semantic_plain_denial_probe(
        "regional-denial.example",
        "1.1.1.1",
        "plain",
        now=100.0,
        runner=lambda _ip, _host: True,
    )


def test_plain_semantic_probe_respects_concurrency_cap(monkeypatch):
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    tproxy._semantic_plain_confirming.update(
        {
            "first.example": 100.0,
            "second.example": 100.0,
        }
    )

    assert not tproxy._schedule_semantic_plain_denial_probe(
        "third.example",
        "1.1.1.1",
        "plain",
        now=101.0,
        runner=lambda _ip, _host: True,
    )


def test_plain_semantic_probe_thread_failure_releases_its_slot(monkeypatch):
    host = "thread-failure.example"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    class UnavailableThread:
        def __init__(self, *, target, daemon):
            assert callable(target)
            assert daemon

        def start(self):
            raise RuntimeError("thread unavailable")

    monkeypatch.setattr(tproxy.threading, "Thread", UnavailableThread)

    assert not tproxy._schedule_semantic_plain_denial_probe(
        host,
        "1.1.1.1",
        "plain",
        now=100.0,
    )
    assert host not in tproxy._semantic_plain_confirming
    assert host not in tproxy._semantic_plain_last_probe
    assert not tproxy._semantic_plain_probe_window


def test_semantic_confirmation_learns_only_after_denial_clears_through_owned_geph(
    monkeypatch,
    tmp_path,
):
    host = "regional-denial.example"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: 4242)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda pid: pid == 4242,
    )
    monkeypatch.setattr(
        tproxy,
        "_AUTO_GEPH_PATH",
        str(tmp_path / "autogeph.json"),
    )
    monkeypatch.setattr(
        tproxy,
        "_semantic_geph_payload_probe",
        lambda candidate: 512 if candidate == host else 0,
    )

    assert tproxy._confirm_semantic_geo_exit(host)
    assert tproxy._auto_geph_learned_exact_host(host)
    assert host not in tproxy._auto_geph_candidates
    assert (
        tproxy._auto_geph_last_status["reason"]
        == "regional denial cleared through owned Geph"
    )


@pytest.mark.parametrize(
    ("confirmation_name", "probe_name"),
    (
        ("_confirm_semantic_geo_exit", "_semantic_geph_payload_probe"),
        (
            "_confirm_incomplete_response_geo_exit",
            "_incomplete_response_geph_payload_probe",
        ),
    ),
)
def test_semantic_confirmation_cannot_persist_after_network_noise(
    monkeypatch,
    confirmation_name,
    probe_name,
):
    host = "noise-invalidated-semantic.example"
    token = object()
    tproxy._auto_geph_confirming[host] = tproxy.time.monotonic()
    tproxy._auto_geph_confirmation_tokens[host] = token
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: 4242)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda pid: pid == 4242,
    )

    def payload_then_noise(candidate):
        assert candidate == host
        now = tproxy.time.monotonic()
        for index in range(tproxy.AUTO_GEPH_NET_BAD):
            tproxy._local_zero_payload_failures[
                f"semantic-noise-{index}.example"
            ] = {tproxy.AUTO_GEPH_STAGE_SYSTEM: now}
        assert tproxy._network_wide_unknown_failure_visible(now)
        tproxy._local_zero_payload_failures.clear()
        return 4096

    monkeypatch.setattr(tproxy, probe_name, payload_then_noise)

    assert not getattr(tproxy, confirmation_name)(host)
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert host in tproxy._auto_geph_noise_invalidated
    assert (
        tproxy._auto_geph_last_status["reason"]
        == "route changed or noise visible"
    )


@pytest.mark.parametrize(
    ("confirmation_name", "probe_name"),
    (
        ("_confirm_semantic_geo_exit", "_semantic_geph_payload_probe"),
        (
            "_confirm_incomplete_response_geo_exit",
            "_incomplete_response_geph_payload_probe",
        ),
    ),
)
def test_noise_producer_serializes_before_semantic_route_commit(
    monkeypatch,
    confirmation_name,
    probe_name,
):
    host = "serialized-noise-confirmation.example"
    token = object()
    before_commit = threading.Event()
    release_commit = threading.Event()
    result = []
    match_calls = 0
    now = tproxy.time.monotonic()
    tproxy._auto_geph_confirming[host] = now
    tproxy._auto_geph_confirmation_tokens[host] = token
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: 4242)
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: None)
    monkeypatch.setattr(tproxy, probe_name, lambda candidate: 4096)

    def pause_before_commit(pid):
        nonlocal match_calls
        assert pid == 4242
        match_calls += 1
        if match_calls == 2:
            before_commit.set()
            assert release_commit.wait(timeout=2)
        return True

    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        pause_before_commit,
    )
    worker = threading.Thread(
        target=lambda: result.append(getattr(tproxy, confirmation_name)(host)),
    )
    worker.start()
    try:
        assert before_commit.wait(timeout=2)
        stages = (
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
            f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake",
            f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake",
        )
        for index in range(tproxy.AUTO_GEPH_NET_BAD):
            noisy_host = f"serialized-noise-{index}.example"
            for offset, stage in enumerate(stages):
                tproxy.note_zero_payload_route_failure(
                    noisy_host,
                    stage,
                    now=now + offset / 1000,
                )
        assert host in tproxy._auto_geph_noise_invalidated
        with tproxy._auto_geph_lock:
            tproxy._local_zero_payload_failures.clear()
    finally:
        release_commit.set()
        worker.join(timeout=2)

    assert not worker.is_alive()
    assert result == [False]
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert (
        tproxy._auto_geph_last_status["reason"]
        == "route changed or noise visible"
    )


def test_semantic_confirmation_rejects_same_denial_response(monkeypatch):
    host = "regional-denial.example"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_semantic_geph_payload_probe", lambda _host: 0)

    assert not tproxy._confirm_semantic_geo_exit(host)
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert host not in tproxy._auto_geph_candidates
    assert (
        tproxy._auto_geph_last_status["reason"]
        == "owned Geph did not clear regional denial"
    )


def test_semantic_confirmation_does_not_learn_after_owned_pid_drift(
    monkeypatch,
):
    host = "pid-drift-denial.example"
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 100.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy.time, "time", lambda: 100.0)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: 4242)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda _pid: False,
    )
    monkeypatch.setattr(
        tproxy,
        "_semantic_geph_payload_probe",
        lambda _host: tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES,
    )

    assert not tproxy._confirm_semantic_geo_exit(host)
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_incomplete_response_confirmation_requires_complete_owned_geph_payload(
    monkeypatch,
    tmp_path,
):
    host = "partial-response.example"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: 4242)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda pid: pid == 4242,
    )
    monkeypatch.setattr(
        tproxy,
        "_AUTO_GEPH_PATH",
        str(tmp_path / "autogeph.json"),
    )
    monkeypatch.setattr(
        tproxy,
        "_incomplete_response_geph_payload_probe",
        lambda candidate: 4096 if candidate == host else 0,
    )

    assert tproxy._confirm_incomplete_response_geo_exit(host)
    assert tproxy._auto_geph_learned_exact_host(host)
    assert (
        tproxy._auto_geph_last_status["reason"]
        == "complete response confirmed through owned Geph"
    )


def test_incomplete_response_confirmation_rejects_unproven_payload(monkeypatch):
    host = "partial-response.example"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: None)
    monkeypatch.setattr(
        tproxy,
        "_incomplete_response_geph_payload_probe",
        lambda _host: 0,
    )

    assert not tproxy._confirm_incomplete_response_geo_exit(host)
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert (
        tproxy._auto_geph_last_status["reason"]
        == "owned Geph response was not proven complete"
    )


def test_incomplete_response_confirmation_restarts_owned_geph_once(
    monkeypatch,
    tmp_path,
):
    host = "rate-limited-exit.example"
    probes = iter([0, 4096])
    listener_pid = {"value": 100}
    events = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(
        tproxy,
        "_begin_geph_restart_drain",
        lambda: events.append(("begin",)) or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_AUTO_GEPH_PATH",
        str(tmp_path / "autogeph.json"),
    )
    monkeypatch.setattr(
        tproxy,
        "_incomplete_response_geph_payload_probe",
        lambda candidate: next(probes) if candidate == host else 0,
    )
    monkeypatch.setattr(
        tproxy,
        "_geph_listener_pid",
        lambda _port: listener_pid["value"],
    )
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda _port, **kwargs: kwargs.get(
            "listener_pid",
            listener_pid["value"],
        )
        == listener_pid["value"],
    )
    monkeypatch.setattr(
        tproxy,
        "request_owned_geph_restart",
        lambda candidate, reason, **_kwargs: (
            events.append(("request", candidate, reason)) or True
        ),
    )
    def restart(**kwargs):
        events.append(("restart", kwargs.get("active_sessions")))
        listener_pid["value"] += 1
        return "restarted"

    monkeypatch.setattr(tproxy, "execute_owned_geph_restart", restart)
    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_payload_ready",
        lambda _expected_pid=None: "ready",
    )
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        lambda: "ready",
    )
    monkeypatch.setattr(
        tproxy,
        "_finish_geph_restart_drain",
        lambda: events.append(("finish",)),
    )

    assert tproxy._confirm_incomplete_response_geo_exit(host)
    assert tproxy._auto_geph_learned_exact_host(host)
    assert events == [
        ("begin",),
        ("request", host, "payload probe failed"),
        ("restart", 0),
        ("finish",),
    ]


def test_semantic_confirmation_does_not_restart_unverified_listener(monkeypatch):
    host = "unverified-listener.example"
    calls = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_semantic_geph_payload_probe", lambda _host: 0)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda _port, **_kwargs: False,
    )
    monkeypatch.setattr(
        tproxy,
        "execute_owned_geph_restart",
        lambda **_kwargs: calls.append("restart") or "restarted",
    )

    assert not tproxy._confirm_semantic_geo_exit(host)
    assert calls == []
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_semantic_confirmation_restart_is_globally_rate_limited(monkeypatch):
    host = "cooldown.example"
    calls = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 99.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy.time, "time", lambda: 100.0)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_semantic_geph_payload_probe", lambda _host: 0)
    monkeypatch.setattr(
        tproxy,
        "request_owned_geph_restart",
        lambda *_args, **_kwargs: calls.append("request") or True,
    )

    assert not tproxy._confirm_semantic_geo_exit(host)
    assert calls == []
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_semantic_confirmation_uses_second_bounded_owned_geph_replacement(
    monkeypatch,
    tmp_path,
):
    host = "second-exit-works.example"
    probes = iter([0, 0, 4096])
    listener_pid = {"value": 100}
    events = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(
        tproxy,
        "_AUTO_GEPH_PATH",
        str(tmp_path / "autogeph.json"),
    )
    monkeypatch.setattr(
        tproxy,
        "_semantic_geph_payload_probe",
        lambda candidate: next(probes) if candidate == host else 0,
    )
    monkeypatch.setattr(
        tproxy,
        "_geph_listener_pid",
        lambda _port: listener_pid["value"],
    )
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda _port, **kwargs: kwargs.get(
            "listener_pid",
            listener_pid["value"],
        )
        == listener_pid["value"],
    )
    monkeypatch.setattr(
        tproxy,
        "_begin_geph_restart_drain",
        lambda: events.append(("begin",)) or True,
    )
    monkeypatch.setattr(
        tproxy,
        "request_owned_geph_restart",
        lambda candidate, reason, **_kwargs: (
            events.append(("request", candidate, reason)) or True
        ),
    )
    def restart(**kwargs):
        events.append(("restart", kwargs.get("active_sessions")))
        listener_pid["value"] += 1
        return "restarted"

    monkeypatch.setattr(tproxy, "execute_owned_geph_restart", restart)
    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_payload_ready",
        lambda _expected_pid=None: "ready",
    )
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        lambda: "ready",
    )
    monkeypatch.setattr(
        tproxy,
        "_finish_geph_restart_drain",
        lambda: events.append(("finish",)),
    )

    assert tproxy._confirm_semantic_geo_exit(host)
    assert tproxy._auto_geph_learned_exact_host(host)
    assert events == [
        ("begin",),
        ("request", host, "payload probe failed"),
        ("restart", 0),
        ("request", host, "payload probe failed"),
        ("restart", 0),
        ("finish",),
    ]


def test_semantic_confirmation_stops_after_two_owned_geph_replacements(monkeypatch):
    host = "still-unusable.example"
    probes = iter([0, 0, 0])
    listener_pid = {"value": 100}
    events = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_semantic_geph_payload_probe",
        lambda candidate: next(probes) if candidate == host else 0,
    )
    monkeypatch.setattr(
        tproxy,
        "_geph_listener_pid",
        lambda _port: listener_pid["value"],
    )
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda _port, **kwargs: kwargs.get(
            "listener_pid",
            listener_pid["value"],
        )
        == listener_pid["value"],
    )
    monkeypatch.setattr(
        tproxy,
        "_begin_geph_restart_drain",
        lambda: events.append(("begin",)) or True,
    )
    monkeypatch.setattr(
        tproxy,
        "request_owned_geph_restart",
        lambda *_args, **_kwargs: events.append(("request",)) or True,
    )
    def restart(**kwargs):
        events.append(("restart", kwargs.get("active_sessions")))
        listener_pid["value"] += 1
        return "restarted"

    monkeypatch.setattr(tproxy, "execute_owned_geph_restart", restart)
    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_payload_ready",
        lambda _expected_pid=None: "ready",
    )
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        lambda: "ready",
    )
    monkeypatch.setattr(
        tproxy,
        "_finish_geph_restart_drain",
        lambda: events.append(("finish",)),
    )

    assert not tproxy._confirm_semantic_geo_exit(host)
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert events == [
        ("begin",),
        ("request",),
        ("restart", 0),
        ("request",),
        ("restart", 0),
        ("finish",),
    ]
    with pytest.raises(StopIteration):
        next(probes)


@pytest.mark.parametrize(
    ("response_chunks", "expected_positive"),
    [
        (
            [
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: 93\r\n\r\n<html>",
                b"x" * 80 + b"</html>",
            ],
            True,
        ),
        (
            [
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: 200\r\n\r\n<html>",
                b"x" * 80 + b"</html>",
            ],
            False,
        ),
        (
            [
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n",
                b"5d\r\n<html>" + b"x" * 80 + b"</html>\r\n0\r\n\r\n",
            ],
            True,
        ),
        (
            [
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Encoding: gzip\r\nContent-Length: 93\r\n\r\n",
                b"\x1f\x8b" + b"x" * 91,
            ],
            False,
        ),
        (
            [
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                b"X-Fill: " + b"x" * 100 + b"\r\n\r\n",
            ],
            False,
        ),
        (
            [
                b"HTTP/1.1 204 No Content\r\n"
                b"X-Fill: " + b"x" * 100 + b"\r\n\r\n",
            ],
            False,
        ),
    ],
)
def test_incomplete_response_probe_requires_complete_http_response(
    monkeypatch,
    response_chunks,
    expected_positive,
):
    class FakeTlsSocket:
        def __init__(self, chunks):
            self.chunks = deque(chunks + [b""])
            self.closed = False
            self.request = b""

        def settimeout(self, _timeout):
            return None

        def sendall(self, request):
            self.request = request

        def recv(self, _size):
            return self.chunks.popleft()

        def close(self):
            self.closed = True

    class FakeContext:
        def __init__(self, tls_socket):
            self.tls_socket = tls_socket

        def wrap_socket(self, _sock, server_hostname):
            assert server_hostname == "partial-response.example"
            return self.tls_socket

    tls_socket = FakeTlsSocket(response_chunks)
    monkeypatch.setattr(
        tproxy,
        "_socks5_connect_blocking",
        lambda host, port, timeout: tls_socket,
    )
    monkeypatch.setattr(
        tproxy,
        "_local_payload_ssl_context",
        lambda: FakeContext(tls_socket),
    )

    result = tproxy._incomplete_response_geph_payload_probe(
        "partial-response.example"
    )

    assert (result > 0) is expected_positive
    assert b"Range: bytes=0-262143\r\n" in tls_socket.request
    assert b"Accept-Encoding: identity\r\n" in tls_socket.request
    assert tls_socket.closed


@pytest.mark.parametrize(
    ("response_chunks", "expected_incomplete"),
    [
        (
            [
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: 200\r\n\r\n<html>",
                b"x" * 80 + b"</html>",
                b"",
            ],
            True,
        ),
        (
            [
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: 93\r\n\r\n<html>",
                b"x" * 80 + b"</html>",
            ],
            False,
        ),
        (
            [
                b"HTTP/1.1 429 Too Many Requests\r\n"
                b"Content-Length: 18\r\n\r\nlocal",
                b"",
            ],
            False,
        ),
    ],
)
def test_plain_transport_probe_requires_a_proven_body_shortfall(
    monkeypatch,
    response_chunks,
    expected_incomplete,
):
    class FakeTlsSocket:
        def __init__(self, chunks):
            self.chunks = deque(chunks)
            self.closed = False
            self.request = b""

        def settimeout(self, _timeout):
            return None

        def sendall(self, request):
            self.request = request

        def recv(self, _size):
            return self.chunks.popleft()

        def close(self):
            self.closed = True

    class FakeContext:
        def __init__(self, tls_socket):
            self.tls_socket = tls_socket

        def wrap_socket(self, _sock, server_hostname):
            assert server_hostname == "partial-response.example"
            return self.tls_socket

    tls_socket = FakeTlsSocket(response_chunks)
    addresses = []
    monkeypatch.setattr(
        tproxy.socket,
        "create_connection",
        lambda address, timeout: (
            addresses.append((address, timeout)) or tls_socket
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_local_payload_ssl_context",
        lambda: FakeContext(tls_socket),
    )

    result = tproxy._incomplete_response_plain_payload_probe(
        "1.1.1.1",
        "partial-response.example",
    )

    assert result is expected_incomplete
    assert addresses and addresses[0][0] == ("1.1.1.1", 443)
    assert b"Range:" not in tls_socket.request
    assert b"Accept-Encoding: identity\r\n" in tls_socket.request
    assert tls_socket.closed


def test_plain_transport_probe_uses_http2_completion_when_negotiated(monkeypatch):
    class FakeTlsSocket:
        def __init__(self):
            self.closed = False

        def settimeout(self, _timeout):
            return None

        def selected_alpn_protocol(self):
            return "h2"

        def close(self):
            self.closed = True

    class FakeContext:
        def __init__(self, tls_socket):
            self.tls_socket = tls_socket
            self.protocols = None

        def set_alpn_protocols(self, protocols):
            self.protocols = protocols

        def wrap_socket(self, _sock, server_hostname):
            assert server_hostname == "partial-response.example"
            return self.tls_socket

    tls_socket = FakeTlsSocket()
    context = FakeContext(tls_socket)
    calls = []
    monkeypatch.setattr(
        tproxy.socket,
        "create_connection",
        lambda _address, timeout: tls_socket,
    )
    monkeypatch.setattr(tproxy, "_local_payload_ssl_context", lambda: context)
    monkeypatch.setattr(
        tproxy,
        "probe_http2_response",
        lambda sock, host, **kwargs: (
            calls.append((sock, host, kwargs))
            or SimpleNamespace(incomplete=True)
        ),
    )

    assert tproxy._incomplete_response_plain_payload_probe(
        "1.1.1.1",
        "partial-response.example",
    )
    assert context.protocols == ["h2", "http/1.1"]
    assert calls[0][0] is tls_socket
    assert calls[0][1] == "partial-response.example"
    assert calls[0][2]["bounded_range"] is False
    assert tls_socket.closed


@pytest.mark.parametrize(
    ("status", "complete", "protocol_error", "identity", "body", "expected"),
    [
        (200, True, False, True, b"x" * 4096, 4096),
        (200, True, True, True, b"x" * 4096, 0),
        (204, True, False, True, b"invalid body", 0),
        (205, True, False, True, b"invalid body", 0),
        (304, True, False, True, b"invalid body", 0),
        (429, True, False, True, b"local_rate_limited", 0),
        (200, False, False, True, b"x" * 4096, 0),
        (200, True, False, False, b"x" * 4096, 0),
    ],
)
def test_geph_transport_probe_requires_usable_complete_http2(
    monkeypatch,
    status,
    complete,
    protocol_error,
    identity,
    body,
    expected,
):
    class FakeTlsSocket:
        def __init__(self):
            self.closed = False

        def settimeout(self, _timeout):
            return None

        def selected_alpn_protocol(self):
            return "h2"

        def close(self):
            self.closed = True

    class FakeContext:
        def set_alpn_protocols(self, protocols):
            assert protocols == ["h2", "http/1.1"]

        def wrap_socket(self, sock, server_hostname):
            assert server_hostname == "partial-response.example"
            return sock

    tls_socket = FakeTlsSocket()
    monkeypatch.setattr(
        tproxy,
        "_socks5_connect_blocking",
        lambda host, port, timeout: tls_socket,
    )
    monkeypatch.setattr(
        tproxy,
        "_local_payload_ssl_context",
        FakeContext,
    )
    monkeypatch.setattr(
        tproxy,
        "probe_http2_response",
        lambda sock, host, **kwargs: SimpleNamespace(
            status=status,
            complete=complete,
            protocol_error=protocol_error,
            content_encoding_is_identity=identity,
            body=body,
            body_length=len(body),
        ),
    )

    assert (
        tproxy._incomplete_response_geph_payload_probe(
            "partial-response.example"
        )
        == expected
    )
    assert tls_socket.closed


def test_plain_transport_probe_accepts_a_framed_body_stall(monkeypatch):
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n"
        + b"x" * 80
    )

    class FakeTlsSocket:
        def __init__(self):
            self.responses = deque([response, tproxy.socket.timeout()])

        def settimeout(self, _timeout):
            return None

        def sendall(self, _request):
            return None

        def recv(self, _size):
            result = self.responses.popleft()
            if isinstance(result, BaseException):
                raise result
            return result

        def close(self):
            return None

    tls_socket = FakeTlsSocket()
    monkeypatch.setattr(
        tproxy.socket,
        "create_connection",
        lambda _address, timeout: tls_socket,
    )
    monkeypatch.setattr(
        tproxy,
        "_local_payload_ssl_context",
        lambda: SimpleNamespace(
            wrap_socket=lambda _sock, server_hostname: tls_socket
        ),
    )

    assert tproxy._incomplete_response_plain_payload_probe(
        "1.1.1.1",
        "partial-response.example",
    )


def test_plain_transport_probe_rejects_nonclosure_read_errors(monkeypatch):
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\nshort"

    class FakeTlsSocket:
        def __init__(self, error):
            self.responses = deque([response, error])

        def settimeout(self, _timeout):
            return None

        def sendall(self, _request):
            return None

        def recv(self, _size):
            result = self.responses.popleft()
            if isinstance(result, BaseException):
                raise result
            return result

        def close(self):
            return None

    for error in (
        ssl.SSLError("bad TLS record"),
        OSError("local socket failure"),
    ):
        tls_socket = FakeTlsSocket(error)
        monkeypatch.setattr(
            tproxy.socket,
            "create_connection",
            lambda _address, timeout: tls_socket,
        )
        monkeypatch.setattr(
            tproxy,
            "_local_payload_ssl_context",
            lambda: SimpleNamespace(
                wrap_socket=lambda _sock, server_hostname: tls_socket
            ),
        )

        assert not tproxy._incomplete_response_plain_payload_probe(
            "1.1.1.1",
            "partial-response.example",
        )


def test_socks5_connect_uses_one_total_deadline(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.timeouts = []
            self.responses = deque(
                [
                    b"\x05\x00",
                    b"\x05\x00\x00\x01",
                    b"\x7f\x00\x00\x01",
                    b"\x26\xe2",
                ]
            )
            self.closed = False

        def settimeout(self, timeout):
            self.timeouts.append(timeout)

        def sendall(self, _payload):
            return None

        def recv(self, _size):
            return self.responses.popleft()

        def close(self):
            self.closed = True

    sock = FakeSocket()
    clock = iter([0.0, 0.0, 1.0, 2.0, 3.0, 4.0, 4.5, 4.75])
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(
        tproxy.socket,
        "create_connection",
        lambda _address, timeout: sock,
    )

    assert tproxy._socks5_connect_blocking("example.com", 443, timeout=5.0) is sock
    assert sock.timeouts == pytest.approx([4.0, 3.0, 2.0, 1.0, 0.5, 0.25])
    assert not sock.closed


def test_socks5_connect_fails_when_total_deadline_expires(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.closed = False

        def settimeout(self, _timeout):
            raise AssertionError("expired socket must not receive a new timeout")

        def close(self):
            self.closed = True

    sock = FakeSocket()
    clock = iter([0.0, 0.0, 6.0])
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(
        tproxy.socket,
        "create_connection",
        lambda _address, timeout: sock,
    )

    assert tproxy._socks5_connect_blocking("example.com", 443, timeout=5.0) is None
    assert sock.closed


def test_incomplete_response_probe_shares_deadline_across_socks_tls_and_http(
    monkeypatch,
):
    class FakeSocket:
        def __init__(self):
            self.closed = False
            self.recv_called = False

        def settimeout(self, _timeout):
            return None

        def sendall(self, _payload):
            return None

        def recv(self, _size):
            self.recv_called = True
            return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

        def close(self):
            self.closed = True

    class FakeContext:
        def __init__(self, tls_socket):
            self.tls_socket = tls_socket

        def wrap_socket(self, _sock, server_hostname):
            assert server_hostname == "partial-response.example"
            return self.tls_socket

    tls_socket = FakeSocket()
    clock = iter([0.0, 0.0, 1.0, 2.0, 7.0])
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(
        tproxy,
        "_socks5_connect_blocking",
        lambda host, port, timeout: tls_socket,
    )
    monkeypatch.setattr(
        tproxy,
        "_local_payload_ssl_context",
        lambda: FakeContext(tls_socket),
    )

    assert (
        tproxy._incomplete_response_geph_payload_probe(
            "partial-response.example",
            timeout=6.0,
        )
        == 0
    )
    assert not tls_socket.recv_called
    assert tls_socket.closed


def test_semantic_geph_probe_shares_deadline_across_socks_tls_and_http(
    monkeypatch,
):
    class FakeSocket:
        def __init__(self):
            self.closed = False
            self.recv_called = False

        def settimeout(self, _timeout):
            return None

        def sendall(self, _payload):
            return None

        def recv(self, _size):
            self.recv_called = True
            return (
                b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\n\r\n"
                + b"x" * 128
            )

        def close(self):
            self.closed = True

    class FakeContext:
        def __init__(self, tls_socket):
            self.tls_socket = tls_socket

        def wrap_socket(self, _sock, server_hostname):
            assert server_hostname == "slow-response.example"
            return self.tls_socket

    tls_socket = FakeSocket()
    clock = iter([0.0, 0.0, 1.0, 2.0, 7.0])
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(
        tproxy,
        "_socks5_connect_blocking",
        lambda host, port, timeout: tls_socket,
    )
    monkeypatch.setattr(
        tproxy,
        "_local_payload_ssl_context",
        lambda: FakeContext(tls_socket),
    )

    assert (
        tproxy._semantic_geph_payload_probe(
            "slow-response.example",
            timeout=6.0,
        )
        == 0
    )
    assert not tls_socket.recv_called
    assert tls_socket.closed


@pytest.mark.parametrize(
    ("response_chunks", "expected_positive"),
    [
        (
            [
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: 128\r\n\r\n",
                b"x" * 128,
            ],
            True,
        ),
        (
            [
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: 256\r\n\r\n",
                b"x" * 128,
            ],
            False,
        ),
    ],
)
def test_semantic_geph_probe_requires_complete_http_response(
    monkeypatch,
    response_chunks,
    expected_positive,
):
    class FakeTlsSocket:
        def __init__(self, chunks):
            self.chunks = deque(chunks + [b""])
            self.closed = False
            self.request = b""

        def settimeout(self, _timeout):
            return None

        def sendall(self, payload):
            self.request += payload

        def recv(self, _size):
            return self.chunks.popleft()

        def close(self):
            self.closed = True

    tls_socket = FakeTlsSocket(response_chunks)
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(
        tproxy,
        "_socks5_connect_blocking",
        lambda host, port, timeout: tls_socket,
    )
    monkeypatch.setattr(
        tproxy,
        "_local_payload_ssl_context",
        lambda: SimpleNamespace(
            wrap_socket=lambda _sock, server_hostname: tls_socket
        ),
    )

    result = tproxy._semantic_geph_payload_probe("complete-response.example")

    assert (result > 0) is expected_positive
    assert b"Range: bytes=0-262143\r\n" in tls_socket.request
    assert tls_socket.closed


def test_semantic_geph_probe_accepts_complete_large_response(monkeypatch):
    body = b"x" * 1_100_000
    response_chunks = [
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode(),
        body,
    ]

    class FakeTlsSocket:
        def __init__(self):
            self.chunks = deque(response_chunks + [b""])
            self.closed = False
            self.request = b""

        def settimeout(self, _timeout):
            return None

        def sendall(self, payload):
            self.request += payload

        def recv(self, _size):
            return self.chunks.popleft()

        def close(self):
            self.closed = True

    tls_socket = FakeTlsSocket()
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(
        tproxy,
        "_socks5_connect_blocking",
        lambda host, port, timeout: tls_socket,
    )
    monkeypatch.setattr(
        tproxy,
        "_local_payload_ssl_context",
        lambda: SimpleNamespace(
            wrap_socket=lambda _sock, server_hostname: tls_socket
        ),
    )

    result = tproxy._semantic_geph_payload_probe("large-response.example")

    assert result == len(body)
    assert b"Range: bytes=0-262143\r\n" in tls_socket.request
    assert tls_socket.closed


def test_semantic_recovery_performs_two_successful_in_incident_replacements(
    monkeypatch,
):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    listener_pid = {"value": 100}
    probe_results = iter([0, 512])
    launchctl_calls = []
    blocked_callbacks = []
    success_observations = []

    monkeypatch.setattr(
        tproxy,
        "_geph_listener_pid",
        lambda _port: listener_pid["value"],
    )
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(tproxy, "geph_ownership_path", lambda: "/tmp/owned.json")
    monkeypatch.setattr(
        tproxy,
        "_read_geph_ownership",
        lambda _path: {
            "uid": 502,
            "launchd_label": tproxy.GEPH_LAUNCHD_LABEL,
        },
    )
    monkeypatch.setattr(tproxy, "_ownership_file_uid", lambda _path: 502)

    def run(*args):
        launchctl_calls.append(args)
        listener_pid["value"] += 1
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy, "_run", run)
    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_successor",
        lambda previous_pid: (
            "ready" if listener_pid["value"] != previous_pid else "timeout"
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "suspend_geo_exit_backend",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(tproxy, "note_runtime_rearm", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        lambda _pid=None, **_kwargs: "ready",
    )
    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_payload_ready",
        lambda _expected_pid=None: "ready",
    )

    result = tproxy._retry_semantic_geph_probe_after_owned_restart(
        "two-replacements.example",
        lambda _host: next(probe_results),
        on_drain_blocked=lambda: blocked_callbacks.append(True),
        on_success=lambda bytes_read, pinned_pid: success_observations.append(
            (bytes_read, pinned_pid, tproxy._geph_restart_draining)
        ),
    )

    assert result == 512
    assert len(launchctl_calls) == 2
    assert blocked_callbacks == []
    assert success_observations == [(512, 102, True)]
    assert not tproxy._geph_restart_draining
    with pytest.raises(StopIteration):
        next(probe_results)


def test_owned_geph_payload_readiness_waits_for_same_pid_payload(monkeypatch):
    clock = {"now": 0.0}
    probe_results = iter([0, 512])
    probes = []

    def payload_probe(host, spec, *, timeout):
        probes.append((host, spec["name"], timeout))
        return next(probe_results)

    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda _port, *, listener_pid=None: listener_pid == 101,
    )

    result = tproxy._wait_for_owned_geph_payload_ready(
        expected_pid=101,
        timeout=2.0,
        payload_probe=payload_probe,
        listener_pid=lambda _port: 101,
        monotonic=lambda: clock["now"],
        sleeper=lambda delay: clock.__setitem__("now", clock["now"] + delay),
    )

    assert result == "ready"
    assert [probe[1] for probe in probes] == [
        "owned_geph_openai_payload",
        "owned_geph_anthropic_payload",
    ]


def test_owned_geph_payload_readiness_rejects_pid_change_after_payload(
    monkeypatch,
):
    listener_pids = iter([101, 102])
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda _port, *, listener_pid=None: listener_pid == 101,
    )

    result = tproxy._wait_for_owned_geph_payload_ready(
        expected_pid=101,
        timeout=1.0,
        payload_probe=lambda _host, _spec, *, timeout: 4096,
        listener_pid=lambda _port: next(listener_pids),
        monotonic=lambda: 0.0,
        sleeper=lambda _delay: None,
    )

    assert result == "replaced"


def test_semantic_recovery_does_not_probe_target_before_payload_readiness(
    monkeypatch,
):
    readiness = iter(["timeout", "timeout"])
    events = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(tproxy, "_begin_geph_restart_drain", lambda: True)
    monkeypatch.setattr(
        tproxy,
        "request_owned_geph_restart",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        tproxy,
        "execute_owned_geph_restart",
        lambda **_kwargs: events.append("restart") or "restarted",
    )
    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_payload_ready",
        lambda _expected_pid=None: (
            events.append("readiness") or next(readiness)
        ),
    )
    monkeypatch.setattr(tproxy, "_finish_geph_restart_drain", lambda: None)

    result = tproxy._retry_semantic_geph_probe_after_owned_restart(
        "not-ready.example",
        lambda _host: pytest.fail("target probe must wait for payload readiness"),
    )

    assert result == 0
    assert events == ["restart", "readiness", "restart", "readiness"]


def test_semantic_recovery_rejects_target_payload_after_successor_pid_changes(
    monkeypatch,
):
    matches = iter([True, False])
    unavailable = []
    successes = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(tproxy, "_begin_geph_restart_drain", lambda: True)
    monkeypatch.setattr(
        tproxy,
        "request_owned_geph_restart",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        tproxy,
        "execute_owned_geph_restart",
        lambda **_kwargs: "restarted",
    )
    monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: 101)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda pid: pid == 101 and next(matches),
    )
    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_payload_ready",
        lambda expected_pid: "ready" if expected_pid == 101 else "unverified",
    )
    monkeypatch.setattr(tproxy, "_finish_geph_restart_drain", lambda: None)

    result = tproxy._retry_semantic_geph_probe_after_owned_restart(
        "pid-drift.example",
        lambda _host: tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES,
        on_backend_unavailable=lambda: unavailable.append(True),
        on_success=lambda *_args: successes.append(True),
    )

    assert result == 0
    assert unavailable == [True]
    assert successes == []


def test_stable_owned_geph_probe_blocks_replacement_between_responses(
    monkeypatch,
):
    observations = []
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_ready_for_semantic_confirmation",
        lambda: True,
    )
    monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: 4242)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda pid: pid == 4242,
    )

    def probe(_host):
        observations.append(
            (tproxy.geph_active_session_count(), tproxy._geph_restart_draining)
        )
        assert not tproxy._begin_geph_restart_drain()
        return tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES + len(observations)

    assert tproxy._stable_owned_geph_payload_probe(
        "serialized-stable-proof.example",
        probe,
    ) == tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES + 1
    assert observations == [(1, False), (1, False)]
    assert tproxy.geph_active_session_count() == 0
    assert not tproxy._geph_restart_draining


def test_stable_owned_geph_probe_reuses_reserved_drain(monkeypatch):
    observations = []
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", True)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_ready_for_semantic_confirmation",
        lambda: True,
    )
    monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: 4242)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda pid: pid == 4242,
    )

    def probe(_host):
        observations.append(
            (tproxy.geph_active_session_count(), tproxy._geph_restart_draining)
        )
        return tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES

    assert tproxy._stable_owned_geph_payload_probe(
        "reserved-stable-proof.example",
        probe,
        drain_reserved=True,
    ) == tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES
    assert observations == [(0, True), (0, True)]
    assert tproxy.geph_active_session_count() == 0
    assert tproxy._geph_restart_draining


def test_stable_owned_geph_probe_rejects_listener_pid_drift(monkeypatch):
    current_pid = {"value": 4242}
    probes = []
    commits = []
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_ready_for_semantic_confirmation",
        lambda: True,
    )
    monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: 4242)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda pid: current_pid["value"] == pid,
    )

    def probe(_host):
        probes.append(current_pid["value"])
        current_pid["value"] = 4343
        return tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES

    assert not tproxy._stable_owned_geph_payload_probe(
        "keepalive-drift.example",
        probe,
        on_success=lambda *args: commits.append(args),
    )
    assert probes == [4242]
    assert commits == []
    assert tproxy.geph_active_session_count() == 0


def test_auto_geph_learns_before_releasing_stable_session(monkeypatch):
    host = "learn-under-stable-session.example"
    observations = []
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_candidate_allowed",
        lambda actual_host, _now=None: actual_host == host,
    )
    def stable_probe(_host, _probe, **kwargs):
        bytes_read = tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES
        kwargs["on_success"](bytes_read, 4242)
        return bytes_read

    monkeypatch.setattr(tproxy, "_stable_owned_geph_payload_probe", stable_probe)

    def remember(actual_host, bytes_read, _reason, **_kwargs):
        observations.append(
            (
                actual_host,
                bytes_read,
                tproxy.geph_active_session_count(),
                tproxy._begin_geph_restart_drain(),
            )
        )
        return True

    monkeypatch.setattr(tproxy, "_remember_auto_geph_host", remember)

    assert tproxy._confirm_auto_geph(host)
    assert observations == [
        (host, tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES, 1, False)
    ]
    assert tproxy.geph_active_session_count() == 0
    assert not tproxy._geph_restart_draining


def test_auto_geph_route_commit_rejects_changed_owned_pid(monkeypatch):
    host = "commit-pid-drift.example"
    statuses = []
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_candidate_allowed",
        lambda actual_host, _now=None: actual_host == host,
    )
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda _pid: False,
    )
    monkeypatch.setattr(
        tproxy,
        "_set_auto_geph_status",
        lambda state, actual_host, reason, *_args: statuses.append(
            (state, actual_host, reason)
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "save_auto_geph",
        lambda: pytest.fail("PID drift must prevent route persistence"),
    )

    assert not tproxy._remember_auto_geph_host(
        host,
        tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES,
        "stable Geph payload confirmed",
        expected_geph_pid=4242,
    )
    assert host not in tproxy._auto_geph
    assert statuses[-1] == ("skipped", host, "owned Geph changed")


def test_semantic_recovery_reports_only_a_blocked_session_drain(monkeypatch):
    blocked = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(tproxy, "_begin_geph_restart_drain", lambda: False)

    assert not tproxy._retry_semantic_geph_probe_after_owned_restart(
        "blocked-recovery-drain.example",
        lambda _host: pytest.fail("blocked drain must prevent probing"),
        on_drain_blocked=lambda: blocked.append(True),
    )
    assert blocked == [True]


def test_semantic_recovery_reports_missing_owned_backend(monkeypatch):
    unavailable = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: None)
    monkeypatch.setattr(
        tproxy,
        "_begin_geph_restart_drain",
        lambda: pytest.fail("missing backend must not reserve drain"),
    )

    assert not tproxy._retry_semantic_geph_probe_after_owned_restart(
        "missing-recovery-backend.example",
        lambda _host: pytest.fail("missing backend must prevent probing"),
        on_backend_unavailable=lambda: unavailable.append(True),
    )
    assert unavailable == [True]


def test_semantic_recovery_reports_unowned_backend(monkeypatch):
    unavailable = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: False,
    )
    monkeypatch.setattr(
        tproxy,
        "_begin_geph_restart_drain",
        lambda: pytest.fail("unowned backend must not reserve drain"),
    )

    assert not tproxy._retry_semantic_geph_probe_after_owned_restart(
        "unowned-recovery-backend.example",
        lambda _host: pytest.fail("unowned backend must prevent probing"),
        on_backend_unavailable=lambda: unavailable.append(True),
    )
    assert unavailable == [True]


def test_semantic_recovery_reports_unavailable_restart(monkeypatch):
    unavailable = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        tproxy,
        "request_owned_geph_restart",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        tproxy,
        "execute_owned_geph_restart",
        lambda **_kwargs: "unavailable",
    )

    assert not tproxy._retry_semantic_geph_probe_after_owned_restart(
        "unavailable-restart.example",
        lambda _host: pytest.fail("unavailable restart must prevent probing"),
        drain_reserved=True,
        on_backend_unavailable=lambda: unavailable.append(True),
    )
    assert unavailable == [True]


def test_semantic_recovery_reports_replacement_timeout(monkeypatch):
    unavailable = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "AUTO_GEPH_RECOVERY_GRACE", 0.0)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        tproxy,
        "request_owned_geph_restart",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        tproxy,
        "execute_owned_geph_restart",
        lambda **_kwargs: "unavailable",
    )

    assert not tproxy._retry_semantic_geph_probe_after_owned_restart(
        "replacement-timeout.example",
        lambda _host: pytest.fail("timed-out replacement must prevent probing"),
        drain_reserved=True,
        on_backend_unavailable=lambda: unavailable.append(True),
    )
    assert unavailable == [True]


def test_semantic_runtime_reclassifies_against_current_policy(monkeypatch):
    confirmations = []
    route_class = {"value": tproxy.ROUTE_UNKNOWN}
    monkeypatch.setattr(tproxy, "_semantic_route_signal_runtime", None)
    monkeypatch.setattr(
        tproxy,
        "route_policy",
        lambda _host: {"route_class": route_class["value"]},
    )
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_ready_for_semantic_confirmation",
        lambda: True,
    )
    monkeypatch.setattr(
        tproxy,
        "_request_semantic_geo_exit_confirmation",
        lambda host: confirmations.append(host) or True,
    )
    monkeypatch.setattr(
        tproxy.semantic_route_signal_runtime.time,
        "time",
        lambda: 1_050.0,
    )
    runtime = tproxy._get_semantic_route_signal_runtime()
    signal = {
        "schema_version": 1,
        "signal_id": "0123456789abcdef0123456789abcdef",
        "source": "browser_extension",
        "host": "regional-denial.example",
        "category": "regional_access_denied",
        "confidence_bps": 9500,
        "observed_at_unix_ms": 1_000_000,
        "top_level": True,
    }

    assert runtime.handle(json.dumps(signal).encode())["accepted"] is True
    route_class["value"] = tproxy.ROUTE_DIRECT
    signal["signal_id"] = "fedcba9876543210fedcba9876543210"
    response = runtime.handle(json.dumps(signal).encode())

    assert response["accepted"] is False
    assert response["reason"] == "protected_route"
    assert confirmations == ["regional-denial.example"]


def test_incomplete_response_runtime_uses_distinct_confirmation(monkeypatch):
    regional = []
    incomplete = []
    monkeypatch.setattr(tproxy, "_semantic_route_signal_runtime", None)
    monkeypatch.setattr(
        tproxy,
        "route_policy",
        lambda _host: {"route_class": tproxy.ROUTE_UNKNOWN},
    )
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_ready_for_semantic_confirmation",
        lambda: True,
    )
    monkeypatch.setattr(
        tproxy,
        "_request_semantic_geo_exit_confirmation",
        lambda host: regional.append(host) or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_request_incomplete_response_geo_exit_confirmation",
        lambda host: incomplete.append(host) or True,
    )
    monkeypatch.setattr(
        tproxy.semantic_route_signal_runtime.time,
        "time",
        lambda: 1_050.0,
    )
    runtime = tproxy._get_semantic_route_signal_runtime()
    signal = {
        "schema_version": 2,
        "signal_id": "0123456789abcdef0123456789abcdef",
        "source": "browser_extension",
        "host": "partial-response.example",
        "category": "incomplete_response",
        "confidence_bps": 10000,
        "observed_at_unix_ms": 1_000_000,
        "top_level": True,
    }

    assert runtime.handle(json.dumps(signal).encode())["accepted"] is True
    assert regional == []
    assert incomplete == ["partial-response.example"]


def test_one_shot_watermark_pruning_uses_auto_geph_lock(monkeypatch):
    host = "serialized-watermark-prune.example"
    started = threading.Event()
    finished = threading.Event()
    now = tproxy.time.monotonic()
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_one_shot_consumed_at",
        {host: now - tproxy.AUTO_GEPH_ZERO_PAYLOAD_WINDOW - 1},
    )

    def prune():
        started.set()
        tproxy._prune_local_zero_payload_failures(now)
        finished.set()

    with tproxy._auto_geph_lock:
        worker = threading.Thread(target=prune)
        worker.start()
        assert started.wait(timeout=2)
        assert not finished.wait(timeout=0.1)
        assert host in tproxy._auto_geph_one_shot_consumed_at

    worker.join(timeout=2)
    assert not worker.is_alive()
    assert finished.is_set()
    assert host not in tproxy._auto_geph_one_shot_consumed_at


def test_auto_geph_confirmation_cooldown_state_is_bounded(monkeypatch):
    monkeypatch.setattr(tproxy, "AUTO_GEPH_STATE_MAX", 2)
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_candidate_allowed",
        lambda _host, _now: True,
    )
    monkeypatch.setattr(tproxy, "_set_auto_geph_status", lambda *_args: None)
    tproxy._auto_geph_last_probe.clear()
    tproxy._auto_geph_confirming.clear()
    tproxy._auto_geph_confirmation_tokens.clear()

    try:
        for host, now in (
            ("one.example", 100.0),
            ("two.example", 101.0),
            ("three.example", 102.0),
        ):
            assert tproxy._schedule_auto_geph_confirmation(
                host,
                now=now,
                runner=lambda _host: None,
            )
        assert set(tproxy._auto_geph_last_probe) == {
            "two.example",
            "three.example",
        }
        assert not tproxy._schedule_auto_geph_confirmation(
            "two.example",
            now=103.0,
            runner=lambda _host: None,
        )

        assert tproxy._schedule_auto_geph_confirmation(
            "four.example",
            now=500.0,
            runner=lambda _host: None,
        )
        assert tproxy._auto_geph_last_probe == {"four.example": 500.0}
    finally:
        tproxy._auto_geph_last_probe.clear()
        tproxy._auto_geph_confirming.clear()
        tproxy._auto_geph_confirmation_tokens.clear()


def test_live_auto_geph_confirmation_is_not_time_pruned(monkeypatch):
    host = "long-confirmation.example"
    entered = threading.Event()
    release = threading.Event()
    completed = threading.Event()

    def long_confirmation(actual_host):
        assert actual_host == host
        entered.set()
        assert release.wait(1.0)
        return False

    monkeypatch.setattr(
        tproxy,
        "_auto_geph_candidate_allowed",
        lambda _host, _now=None: True,
    )
    monkeypatch.setattr(tproxy, "_confirm_auto_geph", long_confirmation)
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_confirmation_completed",
        lambda _host, _succeeded: completed.set(),
    )
    monkeypatch.setattr(tproxy, "_set_auto_geph_status", lambda *_args: None)

    assert tproxy._schedule_auto_geph_confirmation(host, now=100.0)
    assert entered.wait(1.0)
    token = tproxy._auto_geph_confirmation_tokens[host]

    tproxy._prune_auto_geph_confirmation_state(10_000.0)

    assert tproxy._auto_geph_confirming[host] == 100.0
    assert tproxy._auto_geph_confirmation_tokens[host] is token
    assert not tproxy._schedule_auto_geph_confirmation(
        host,
        now=10_001.0,
        runner=lambda _host: True,
    )

    release.set()
    assert completed.wait(1.0)
    assert host not in tproxy._auto_geph_confirming
    assert host not in tproxy._auto_geph_confirmation_tokens


def test_auto_geph_confirmation_token_prevents_stale_worker_cleanup():
    host = "token-owner.example"
    stale_token = object()
    live_token = object()
    tproxy._auto_geph_confirming[host] = 200.0
    tproxy._auto_geph_confirmation_tokens[host] = live_token

    assert not tproxy._finish_auto_geph_confirmation(host, stale_token)
    assert tproxy._auto_geph_confirming[host] == 200.0
    assert tproxy._auto_geph_confirmation_tokens[host] is live_token

    assert tproxy._finish_auto_geph_confirmation(host, live_token)
    assert host not in tproxy._auto_geph_confirming
    assert host not in tproxy._auto_geph_confirmation_tokens


def test_auto_geph_confirmation_thread_start_failure_releases_token(
    monkeypatch,
):
    host = "thread-start-failure.example"
    statuses = []

    class BrokenThread:
        def __init__(self, *, target, daemon):
            assert callable(target)
            assert daemon

        def start(self):
            raise RuntimeError("thread capacity unavailable")

    monkeypatch.setattr(
        tproxy,
        "_auto_geph_candidate_allowed",
        lambda actual_host, _now=None: actual_host == host,
    )
    monkeypatch.setattr(tproxy.threading, "Thread", BrokenThread)
    monkeypatch.setattr(
        tproxy,
        "_set_auto_geph_status",
        lambda state, actual_host, reason, *_args: statuses.append(
            (state, actual_host, reason)
        ),
    )

    assert not tproxy._schedule_auto_geph_confirmation(host, now=100.0)
    assert host not in tproxy._auto_geph_confirming
    assert host not in tproxy._auto_geph_confirmation_tokens
    assert host not in tproxy._auto_geph_last_probe
    assert statuses[-1] == (
        "deferred",
        host,
        "confirmation worker unavailable",
    )


def test_post_drain_authorization_evicts_oldest_at_state_bound(monkeypatch):
    monkeypatch.setattr(tproxy, "AUTO_GEPH_STATE_MAX", 2)
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_base_host_allowed",
        lambda _host: True,
    )
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_learned_exact_host",
        lambda _host: False,
    )

    assert tproxy._retain_auto_geph_retry_after_drain_locked("old.example", 1.0)
    assert tproxy._retain_auto_geph_retry_after_drain_locked("mid.example", 2.0)
    assert tproxy._retain_auto_geph_retry_after_drain_locked("new.example", 3.0)

    assert list(tproxy._auto_geph_retry_after_drain) == [
        "mid.example",
        "new.example",
    ]


def test_post_drain_authorization_prunes_learned_and_invalid_hosts(monkeypatch):
    tproxy._auto_geph_retry_after_drain.update({
        "learned.example": 1.0,
        "invalid.example": 2.0,
        "valid.example": 3.0,
    })
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_learned_exact_host",
        lambda host: host == "learned.example",
    )
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_base_host_allowed",
        lambda host: host != "invalid.example",
    )

    tproxy._prune_auto_geph_retry_after_drain_locked()

    assert tproxy._auto_geph_retry_after_drain == {"valid.example": 3.0}
    assert not tproxy._retain_auto_geph_retry_after_drain_locked(
        "learned.example"
    )
    assert not tproxy._retain_auto_geph_retry_after_drain_locked(
        "invalid.example"
    )


def test_network_noise_discards_preexisting_learning_authorizations(
    monkeypatch,
):
    host = "pre-noise-candidate.example"
    pending_host = "pre-noise-pending.example"
    now = tproxy.time.monotonic()
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    tproxy._auto_geph_candidates.update({
        host: now + 60.0,
        pending_host: now + 60.0,
    })
    assert tproxy._retain_auto_geph_retry_after_drain_locked(host, now)
    assert tproxy._retain_auto_geph_retry_after_drain_locked(pending_host, now)

    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        tproxy._local_zero_payload_failures[
            f"authorization-noise-{index}.example"
        ] = {tproxy.AUTO_GEPH_STAGE_SYSTEM: now}

    assert not tproxy._auto_geph_deferred_candidate_allowed(host)
    assert tproxy._auto_geph_candidates == {}
    assert tproxy._auto_geph_retry_after_drain == {}
    assert not tproxy._retain_auto_geph_retry_after_drain_locked(host, now)

    tproxy._local_zero_payload_failures.clear()
    for offset, stage in enumerate((
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake",
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake",
    )):
        created = tproxy.note_zero_payload_route_failure(
            host,
            stage,
            now=now + 1.0 + offset,
        )

    assert created
    assert host not in tproxy._auto_geph_noise_invalidated
    assert tproxy._auto_geph_candidate_allowed(host, now=now + 5.0)
    assert not tproxy._auto_geph_deferred_candidate_allowed(pending_host)


def test_network_noise_invalidates_an_active_confirmation_commit(monkeypatch):
    host = "pre-noise-active-confirmation.example"
    now = tproxy.time.monotonic()
    token = object()
    statuses = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: None)
    monkeypatch.setattr(
        tproxy,
        "_set_auto_geph_status",
        lambda *args: statuses.append(args),
    )
    tproxy._auto_geph_candidates[host] = now + 60.0
    assert tproxy._retain_auto_geph_retry_after_drain_locked(host, now)
    tproxy._auto_geph_confirming[host] = now
    tproxy._auto_geph_confirmation_tokens[host] = token

    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        tproxy._local_zero_payload_failures[
            f"active-confirmation-noise-{index}.example"
        ] = {tproxy.AUTO_GEPH_STAGE_SYSTEM: now}
    assert tproxy._network_wide_unknown_failure_visible(now)

    tproxy._local_zero_payload_failures.clear()
    assert not tproxy._remember_auto_geph_host(
        host,
        tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES,
        "stale pre-noise proof",
        candidate_authorized=True,
    )
    assert host not in tproxy._auto_geph
    assert statuses[-1][:3] == ("skipped", host, "route changed")
    assert tproxy._finish_auto_geph_confirmation(host, token)
    assert host not in tproxy._auto_geph_noise_invalidated


def test_bounded_confirmation_checks_eligibility_under_authority_lock(
    monkeypatch,
):
    class ObservedLock:
        def __init__(self):
            self.held = False

        def __enter__(self):
            assert not self.held
            self.held = True
            return self

        def __exit__(self, _exc_type, _exc, _traceback):
            self.held = False

    lock = ObservedLock()
    eligibility_checks = []
    monkeypatch.setattr(tproxy, "_auto_geph_lock", lock)

    def eligible(_host, _now):
        eligibility_checks.append(lock.held)
        return False

    assert not tproxy._schedule_bounded_geph_confirmation(
        "atomic-browser-confirmation.example",
        now=100.0,
        runner=lambda _host: pytest.fail("ineligible route must not run"),
        confirmation=lambda _host: pytest.fail("ineligible route must not run"),
        eligible=eligible,
        evidence_reason="test",
    )
    assert eligibility_checks == [True]


@pytest.mark.parametrize(
    ("registry_name", "request_name"),
    (
        (
            "_semantic_plain_confirming",
            "_request_semantic_geo_exit_confirmation",
        ),
        (
            "_transport_incomplete_confirming",
            "_request_incomplete_response_geo_exit_confirmation",
        ),
    ),
)
def test_network_noise_revokes_active_precursor_confirmation(
    monkeypatch,
    registry_name,
    request_name,
):
    host = f"revoked-{registry_name.removeprefix('_')}.example"
    now = tproxy.time.monotonic()
    registry = getattr(tproxy, registry_name)
    registry[host] = now
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    tproxy._discard_auto_geph_learning_authorizations_for_noise()

    assert host in tproxy._auto_geph_noise_invalidated
    assert not getattr(tproxy, request_name)(
        host,
        now=now + 1.0,
        confirmation_runner=lambda _host: pytest.fail(
            "a revoked precursor must not reach owned Geph"
        ),
    )


@pytest.mark.parametrize(
    "precursor_name",
    ("_semantic_plain_confirming", "_transport_incomplete_confirming"),
)
def test_confirmation_cleanup_keeps_revocation_until_precursor_exits(
    precursor_name,
):
    host = f"confirmation-before-{precursor_name.removeprefix('_')}.example"
    token = object()
    tproxy._auto_geph_confirming[host] = 100.0
    tproxy._auto_geph_confirmation_tokens[host] = token
    getattr(tproxy, precursor_name)[host] = 101.0
    tproxy._auto_geph_noise_invalidated.add(host)

    assert tproxy._finish_auto_geph_confirmation(host, token)
    assert host in tproxy._auto_geph_noise_invalidated


@pytest.mark.parametrize("scheduler_name", ("semantic", "transport"))
def test_fresh_precursor_cannot_revive_active_revoked_confirmation(
    monkeypatch,
    scheduler_name,
):
    host = f"revoked-token-{scheduler_name}.example"
    token = object()
    tproxy._auto_geph_confirming[host] = 100.0
    tproxy._auto_geph_confirmation_tokens[host] = token
    tproxy._auto_geph_noise_invalidated.add(host)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    if scheduler_name == "semantic":
        scheduled = tproxy._schedule_semantic_plain_denial_probe(
            host,
            "1.1.1.1",
            tproxy.PLAIN_STRATEGY,
            now=101.0,
            runner=lambda *_args: pytest.fail("revoked host must not probe"),
        )
    else:
        scheduled = tproxy._schedule_transport_incomplete_response_confirmation(
            host,
            "1.1.1.1",
            tproxy.PLAIN_STRATEGY,
            now=101.0,
            runner=lambda *_args: pytest.fail("revoked host must not probe"),
        )

    assert not scheduled
    assert tproxy._auto_geph_confirmation_tokens[host] is token
    assert host in tproxy._auto_geph_noise_invalidated


def test_post_drain_retry_reserves_backend_before_consuming_marker(monkeypatch):
    host = "atomic-post-drain.example"
    observations = []
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_candidate_allowed",
        lambda actual_host, _now=None: actual_host == host,
    )
    monkeypatch.setattr(tproxy, "_set_auto_geph_status", lambda *_args: None)
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() + 60.0
    assert tproxy._retain_auto_geph_retry_after_drain_locked(host)

    def confirmation(actual_host):
        observations.append({
            "host": actual_host,
            "draining": tproxy._geph_restart_draining,
            "pending": actual_host in tproxy._auto_geph_retry_after_drain,
            "new_session_allowed": tproxy._geph_session_started(),
        })
        return False

    assert tproxy._retry_auto_geph_confirmation_after_drain(
        host,
        runner=confirmation,
    )
    assert observations == [{
        "host": host,
        "draining": True,
        "pending": False,
        "new_session_allowed": False,
    }]
    assert host not in tproxy._auto_geph_retry_after_drain
    assert not tproxy._geph_restart_draining
    assert tproxy._geph_session_started()
    tproxy._geph_session_finished()


def test_post_drain_retry_preserves_authorization_after_candidate_expires(
    monkeypatch,
):
    host = "expired-post-drain.example"
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_set_auto_geph_status", lambda *_args: None)
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() - 1.0
    assert tproxy._retain_auto_geph_retry_after_drain_locked(host)

    assert tproxy._retry_auto_geph_confirmation_after_drain(
        host,
        runner=lambda actual_host: confirmations.append(actual_host) or False,
    )
    assert confirmations == [host]
    assert host not in tproxy._auto_geph_retry_after_drain
    assert not tproxy._geph_restart_draining


def test_post_drain_retry_waits_for_owned_backend_recovery(monkeypatch):
    host = "backend-recovery-post-drain.example"
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_set_auto_geph_status", lambda *_args: None)
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() - 1.0
    assert tproxy._retain_auto_geph_retry_after_drain_locked(host)

    assert not tproxy._retry_auto_geph_confirmation_after_drain(
        host,
        runner=lambda _host: pytest.fail("down backend must not consume marker"),
    )
    assert host in tproxy._auto_geph_retry_after_drain
    assert not tproxy._geph_restart_draining

    tproxy._geph_up = True
    assert tproxy._retry_auto_geph_confirmation_after_drain(
        host,
        runner=lambda actual_host: confirmations.append(actual_host) or False,
    )
    assert confirmations == [host]
    assert host not in tproxy._auto_geph_retry_after_drain


def test_post_drain_unavailable_backend_does_not_immediately_reconsume_marker(
    monkeypatch,
):
    host = "unavailable-post-drain.example"
    confirmations = []
    drain_attempts = []
    original_begin = tproxy._begin_geph_restart_drain
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_reason", "")
    monkeypatch.setattr(tproxy, "_set_auto_geph_status", lambda *_args: None)
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() - 1.0
    assert tproxy._retain_auto_geph_retry_after_drain_locked(host)

    def begin():
        drain_attempts.append(True)
        return original_begin()

    def confirmation(actual_host):
        confirmations.append(actual_host)
        tproxy.suspend_geo_exit_backend("fixture backend unavailable")
        tproxy._restore_auto_geph_retry_after_drain(actual_host)
        return False

    monkeypatch.setattr(tproxy, "_begin_geph_restart_drain", begin)

    assert tproxy._retry_auto_geph_confirmation_after_drain(
        host,
        runner=confirmation,
    )
    assert confirmations == [host]
    assert drain_attempts == [True]
    assert host in tproxy._auto_geph_retry_after_drain
    assert not tproxy._geph_up
    assert not tproxy._geph_restart_draining


def test_post_drain_thread_start_failure_restores_authorized_retry(monkeypatch):
    host = "post-drain-thread-failure.example"

    class BrokenThread:
        def __init__(self, *, target, daemon):
            assert callable(target)
            assert daemon

        def start(self):
            raise OSError("thread capacity unavailable")

    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy.threading, "Thread", BrokenThread)
    monkeypatch.setattr(tproxy, "_set_auto_geph_status", lambda *_args: None)
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() - 1.0
    assert tproxy._retain_auto_geph_retry_after_drain_locked(host)

    assert not tproxy._retry_auto_geph_confirmation_after_drain(host)
    assert host in tproxy._auto_geph_retry_after_drain
    assert host not in tproxy._auto_geph_confirming
    assert host not in tproxy._auto_geph_confirmation_tokens
    assert host not in tproxy._auto_geph_last_probe
    assert not tproxy._geph_restart_draining


def test_authorized_post_drain_confirmation_can_learn_after_candidate_expires(
    monkeypatch,
):
    host = "expired-authorized-confirmation.example"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    def stable_probe(_host, _probe, **kwargs):
        bytes_read = tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES
        kwargs["on_success"](bytes_read, 4242)
        return bytes_read

    monkeypatch.setattr(tproxy, "_stable_owned_geph_payload_probe", stable_probe)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda pid: pid == 4242,
    )
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: None)
    monkeypatch.setattr(
        tproxy,
        "_clear_owned_geph_backend_hold_after_payload",
        lambda: None,
    )
    monkeypatch.setattr(tproxy, "_set_auto_geph_status", lambda *_args: None)
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() - 1.0
    tproxy._auto_geph_confirming[host] = tproxy.time.monotonic()
    tproxy._auto_geph_confirmation_tokens[host] = object()

    assert not tproxy._confirm_auto_geph(host, drain_reserved=True)
    assert tproxy._confirm_auto_geph(
        host,
        drain_reserved=True,
        candidate_authorized=True,
    )
    assert tproxy._auto_geph_learned_exact_host(host)


def test_authorized_post_drain_confirmation_restores_retry_if_backend_drops(
    monkeypatch,
):
    host = "post-drain-backend-drop.example"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    def drop_backend(_host, _probe, **_kwargs):
        tproxy._geph_up = False
        return 0

    monkeypatch.setattr(
        tproxy,
        "_stable_owned_geph_payload_probe",
        drop_backend,
    )
    monkeypatch.setattr(
        tproxy,
        "_retry_semantic_geph_probe_after_owned_restart",
        lambda *_args, **_kwargs: pytest.fail(
            "unavailable backend must defer before recovery"
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_remember_auto_geph_host",
        lambda _host, _bytes, _reason, **_kwargs: False,
    )
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() - 1.0
    tproxy._auto_geph_confirming[host] = tproxy.time.monotonic()
    tproxy._auto_geph_confirmation_tokens[host] = object()

    assert not tproxy._confirm_auto_geph(
        host,
        drain_reserved=True,
        candidate_authorized=True,
    )
    assert host in tproxy._auto_geph_retry_after_drain


def test_authorized_post_drain_confirmation_restores_retry_if_ownership_is_lost(
    monkeypatch,
):
    host = "post-drain-ownership-loss.example"
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_reason", "")
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 100)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: False,
    )
    monkeypatch.setattr(
        tproxy,
        "_remember_auto_geph_host",
        lambda _host, _bytes, _reason, **_kwargs: False,
    )
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() - 1.0
    tproxy._auto_geph_confirming[host] = tproxy.time.monotonic()
    tproxy._auto_geph_confirmation_tokens[host] = object()

    assert not tproxy._confirm_auto_geph(
        host,
        drain_reserved=True,
        candidate_authorized=True,
    )
    assert host in tproxy._auto_geph_retry_after_drain


def test_early_confirmation_restores_taken_retry_if_backend_drops(monkeypatch):
    host = "early-backend-drop.example"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_candidate_allowed",
        lambda actual_host, _now=None: actual_host == host,
    )

    def drop_backend(_host, _probe, **_kwargs):
        tproxy._geph_up = False
        return 0

    monkeypatch.setattr(
        tproxy,
        "_stable_owned_geph_payload_probe",
        drop_backend,
    )
    monkeypatch.setattr(
        tproxy,
        "_retry_semantic_geph_probe_after_owned_restart",
        lambda *_args, **_kwargs: pytest.fail(
            "unavailable backend must defer before recovery"
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_remember_auto_geph_host",
        lambda _host, _bytes, _reason, **_kwargs: False,
    )
    assert tproxy._retain_auto_geph_retry_after_drain_locked(host)
    tproxy._auto_geph_confirming[host] = tproxy.time.monotonic()
    tproxy._auto_geph_confirmation_tokens[host] = object()

    assert not tproxy._confirm_auto_geph(host)
    assert host in tproxy._auto_geph_retry_after_drain


def test_early_confirmation_consumes_retry_after_acquiring_drain(monkeypatch):
    host = "early-worker-owned-drain.example"
    recovery_attempts = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_candidate_allowed",
        lambda actual_host, _now=None: actual_host == host,
    )
    monkeypatch.setattr(
        tproxy,
        "_stable_owned_geph_payload_probe",
        lambda _host, _probe, **_kwargs: 0,
    )

    def failed_recovery(
        actual_host,
        _probe,
        *,
        drain_reserved=False,
        on_drain_blocked=None,
        on_backend_unavailable=None,
        on_success=None,
    ):
        assert actual_host == host
        assert not drain_reserved
        assert on_drain_blocked is not None
        assert on_backend_unavailable is not None
        assert actual_host not in tproxy._auto_geph_retry_after_drain
        recovery_attempts.append(actual_host)
        return 0

    monkeypatch.setattr(
        tproxy,
        "_retry_semantic_geph_probe_after_owned_restart",
        failed_recovery,
    )
    monkeypatch.setattr(
        tproxy,
        "_remember_auto_geph_host",
        lambda _host, _bytes, _reason, **_kwargs: False,
    )
    assert tproxy._retain_auto_geph_retry_after_drain_locked(host)
    tproxy._auto_geph_confirming[host] = tproxy.time.monotonic()
    tproxy._auto_geph_confirmation_tokens[host] = object()

    assert not tproxy._confirm_auto_geph(host)
    assert recovery_attempts == [host]
    assert host not in tproxy._auto_geph_retry_after_drain


def test_early_confirmation_restores_retry_only_when_drain_is_blocked(
    monkeypatch,
):
    host = "early-worker-blocked-drain.example"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_candidate_allowed",
        lambda actual_host, _now=None: actual_host == host,
    )
    monkeypatch.setattr(
        tproxy,
        "_stable_owned_geph_payload_probe",
        lambda _host, _probe, **_kwargs: 0,
    )

    def blocked_recovery(
        actual_host,
        _probe,
        *,
        drain_reserved=False,
        on_drain_blocked=None,
        on_backend_unavailable=None,
        on_success=None,
    ):
        assert actual_host == host
        assert not drain_reserved
        assert on_drain_blocked is not None
        assert on_backend_unavailable is not None
        assert actual_host not in tproxy._auto_geph_retry_after_drain
        on_drain_blocked()
        return 0

    monkeypatch.setattr(
        tproxy,
        "_retry_semantic_geph_probe_after_owned_restart",
        blocked_recovery,
    )
    monkeypatch.setattr(
        tproxy,
        "_remember_auto_geph_host",
        lambda _host, _bytes, _reason, **_kwargs: False,
    )
    assert tproxy._retain_auto_geph_retry_after_drain_locked(host)

    assert not tproxy._confirm_auto_geph(host)
    assert host in tproxy._auto_geph_retry_after_drain


def test_reserved_auto_geph_confirmation_reuses_held_drain(monkeypatch):
    host = "reserved-confirmation.example"
    recovery = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_candidate_allowed",
        lambda actual_host, _now=None: actual_host == host,
    )
    monkeypatch.setattr(
        tproxy,
        "_stable_owned_geph_payload_probe",
        lambda _host, _probe, **_kwargs: 0,
    )
    monkeypatch.setattr(
        tproxy,
        "_retry_semantic_geph_probe_after_owned_restart",
        lambda actual_host, _probe, *, drain_reserved=False, **_kwargs: (
            recovery.append((actual_host, drain_reserved)) or 0
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "_remember_auto_geph_host",
        lambda _host, _bytes, _reason, **_kwargs: False,
    )
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() + 60.0
    tproxy._auto_geph_confirming[host] = tproxy.time.monotonic()
    tproxy._auto_geph_confirmation_tokens[host] = object()

    assert not tproxy._confirm_auto_geph(host, drain_reserved=True)
    assert recovery == [(host, True)]


def test_owned_geph_recovery_retries_pending_exact_host_confirmation(monkeypatch):
    host = "payments.example.com"
    protected = "updates.discord.com"
    confirmations = []
    original_candidates = dict(tproxy._auto_geph_candidates)
    original_last_probe = dict(tproxy._auto_geph_last_probe)
    original_confirming = dict(tproxy._auto_geph_confirming)
    original_tokens = dict(tproxy._auto_geph_confirmation_tokens)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    tproxy._auto_geph_candidates.clear()
    tproxy._auto_geph_candidates.update({
        host: 200.0,
        protected: 200.0,
    })
    tproxy._auto_geph_last_probe.clear()
    tproxy._auto_geph_last_probe.update({
        host: 99.0,
        protected: 99.0,
    })
    tproxy._auto_geph_confirming.clear()
    tproxy._auto_geph_confirmation_tokens.clear()

    try:
        assert not tproxy.retry_pending_auto_geph_confirmations(
            now=100.0,
            runner=confirmations.append,
        )

        monkeypatch.setattr(tproxy, "_geph_up", True)
        assert tproxy.retry_pending_auto_geph_confirmations(
            now=101.0,
            runner=confirmations.append,
        ) == 1
        assert confirmations == [host]
        assert tproxy._auto_geph_last_probe[host] == 101.0
        assert tproxy._auto_geph_last_probe[protected] == 99.0
    finally:
        tproxy._auto_geph_candidates.clear()
        tproxy._auto_geph_candidates.update(original_candidates)
        tproxy._auto_geph_last_probe.clear()
        tproxy._auto_geph_last_probe.update(original_last_probe)
        tproxy._auto_geph_confirming.clear()
        tproxy._auto_geph_confirming.update(original_confirming)
        tproxy._auto_geph_confirmation_tokens.clear()
        tproxy._auto_geph_confirmation_tokens.update(original_tokens)


def test_local_stream_stall_requires_abnormal_client_abort_after_downstream_idle():
    activity = tproxy._RelayActivity(
        last_downstream_at=100.0,
        client_end_at=130.0,
        server_end_at=130.1,
    )

    assert not tproxy._local_stream_stalled(activity, now=130.1)

    activity.client_read_failed = True
    assert tproxy._local_stream_stalled(activity, now=130.1)

    activity.client_read_failed = False
    activity.downstream_write_failed = True
    assert tproxy._local_stream_stalled(activity, now=130.1)

    activity.downstream_write_failed = False
    activity.last_downstream_at = 120.0
    assert not tproxy._local_stream_stalled(activity, now=130.1)


def test_clean_eof_stream_stall_requires_client_first_idle_close():
    activity = tproxy._RelayActivity(
        last_downstream_at=100.0,
        client_end_at=130.0,
        server_end_at=130.1,
        client_eof=True,
        client_ended_first=True,
    )

    assert tproxy._clean_eof_stream_stalled(activity, now=130.1)

    activity.client_ended_first = False
    assert not tproxy._clean_eof_stream_stalled(activity, now=130.1)

    activity.client_ended_first = True
    activity.server_ended_first = True
    assert not tproxy._clean_eof_stream_stalled(activity, now=130.1)

    activity.server_ended_first = False
    activity.last_downstream_at = 120.0
    assert not tproxy._clean_eof_stream_stalled(activity, now=130.1)


def test_pump_records_transport_error_but_not_orderly_eof():
    class EofReader:
        async def read(self, _size):
            return b""

    class ResetReader:
        async def read(self, _size):
            raise ConnectionResetError("client reset")

    class Writer:
        def close(self):
            pass

    orderly = tproxy._RelayActivity(last_downstream_at=100.0)
    assert asyncio.run(tproxy.pump(EofReader(), Writer(), orderly)) == 0
    assert orderly.client_end_at
    assert orderly.client_eof
    assert not orderly.client_read_failed

    aborted = tproxy._RelayActivity(last_downstream_at=100.0)
    assert asyncio.run(tproxy.pump(ResetReader(), Writer(), aborted)) == 0
    assert aborted.client_end_at
    assert not aborted.client_eof
    assert aborted.client_read_failed


def test_handle_always_closes_client_writer_after_handler_failure(monkeypatch):
    class Writer:
        def __init__(self):
            self.closed = 0
            self.waited = 0

        def close(self):
            self.closed += 1

        async def wait_closed(self):
            self.waited += 1

    async def fail(_reader, _writer):
        raise RuntimeError("relay failed")

    writer = Writer()
    monkeypatch.setattr(tproxy, "_handle_impl", fail)
    monkeypatch.setattr(tproxy, "_conn_count", 0)

    with pytest.raises(RuntimeError, match="relay failed"):
        asyncio.run(tproxy.handle(object(), writer))

    assert writer.closed == 1
    assert writer.waited == 1
    assert tproxy._conn_count == 0


def test_every_transparent_backend_uses_the_bounded_relay_lifecycle():
    source = inspect.getsource(tproxy._handle_impl)

    assert "asyncio.gather(pump" not in source
    assert source.count("relay_local_stream(") == 5


def test_relay_closes_and_waits_for_both_stream_writers():
    class EofReader:
        async def read(self, _size):
            return b""

    class Writer:
        def __init__(self):
            self.closed = 0
            self.waited = 0

        def close(self):
            self.closed += 1

        async def wait_closed(self):
            self.waited += 1

    upstream = Writer()
    downstream = Writer()

    assert asyncio.run(
        tproxy.relay_local_stream(
            EofReader(), upstream, EofReader(), downstream
        )
    ) == (0, 0)
    assert (upstream.closed, upstream.waited) == (1, 1)
    assert (downstream.closed, downstream.waited) == (1, 1)


def test_failed_async_dials_close_and_wait_for_the_open_writer(monkeypatch):
    class Reader:
        async def read(self, _size):
            return b""

    class Socket:
        def getsockname(self):
            return "127.0.0.1", 50000

    class Writer:
        def __init__(self):
            self.closed = 0
            self.waited = 0

        def get_extra_info(self, _name):
            return Socket()

        def write(self, _data):
            pass

        async def drain(self):
            raise OSError("write failed")

        def close(self):
            self.closed += 1

        async def wait_closed(self):
            self.waited += 1

    writers = []

    async def open_connection(*_args, **_kwargs):
        writer = Writer()
        writers.append(writer)
        return Reader(), writer

    monkeypatch.setattr(tproxy.asyncio, "open_connection", open_connection)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "inject_fake_for_host", lambda *_args: None)

    async def exercise():
        assert await tproxy.dial_via_geph("example.com", 443, b"hello") is None
        assert await tproxy.dial_plain("127.0.0.1", 443, b"hello") is None
        assert await tproxy.dial_and_probe("127.0.0.1", 443, b"hello") is None
        assert await tproxy.dial_and_probe_fake(
            "127.0.0.1", 443, b"hello", host="example.com"
        ) is None

    asyncio.run(exercise())

    assert len(writers) == 4
    assert all((writer.closed, writer.waited) == (1, 1) for writer in writers)


def test_route_probe_distinguishes_confirmed_eof_from_timeout(monkeypatch):
    class Reader:
        def __init__(self, blocks):
            self.blocks = blocks

        async def read(self, _size):
            if self.blocks:
                await asyncio.Event().wait()
            return b""

    class Writer:
        def __init__(self):
            self.closed = 0
            self.waited = 0

        def write(self, _data):
            pass

        async def drain(self):
            pass

        def close(self):
            self.closed += 1

        async def wait_closed(self):
            self.waited += 1

    readers = [Reader(False), Reader(True)]
    writers = []

    async def open_connection(*_args, **_kwargs):
        writer = Writer()
        writers.append(writer)
        return readers.pop(0), writer

    monkeypatch.setattr(tproxy.asyncio, "open_connection", open_connection)

    async def probe(block_timeout):
        outcomes = []
        token = tproxy._ROUTE_PROBE_OUTCOME_SINK.set(outcomes.append)
        try:
            assert await tproxy.dial_and_probe(
                "127.0.0.1",
                443,
                b"hello",
                probe_timeout=0.01 if block_timeout else 1.0,
            ) is None
        finally:
            tproxy._ROUTE_PROBE_OUTCOME_SINK.reset(token)
        return outcomes

    assert asyncio.run(probe(False)) == [tproxy.ROUTE_PROBE_CLOSED]
    assert asyncio.run(probe(True)) == [tproxy.ROUTE_PROBE_TIMEOUT]
    assert all((writer.closed, writer.waited) == (1, 1) for writer in writers)


def test_relay_soak_leaves_no_half_open_tasks():
    class EofReader:
        async def read(self, _size):
            return b""

    class BlockingReader:
        async def read(self, _size):
            await asyncio.Event().wait()

    class Writer:
        def close(self):
            pass

    async def exercise():
        current = asyncio.current_task()
        for _ in range(200):
            assert await tproxy.relay_local_stream(
                EofReader(), Writer(), BlockingReader(), Writer()
            ) == (0, 0)
        assert asyncio.all_tasks() == {current}

    asyncio.run(exercise())


def test_relay_local_stream_stops_waiting_when_client_ends_first():
    class EofReader:
        async def read(self, _size):
            return b""

    class BlockingReader:
        async def read(self, _size):
            await asyncio.Event().wait()

    class Writer:
        def close(self):
            pass

    activity = tproxy._RelayActivity(last_downstream_at=100.0)
    result = asyncio.run(asyncio.wait_for(
        tproxy.relay_local_stream(
            EofReader(),
            Writer(),
            BlockingReader(),
            Writer(),
            activity,
        ),
        timeout=0.2,
    ))

    assert result == (0, 0)
    assert activity.client_eof
    assert activity.client_ended_first
    assert not activity.server_ended_first
    assert activity.client_end_at
    assert activity.server_end_at


def test_relay_client_first_after_framed_payload_is_completion_candidate():
    payload = b"x" * 9000
    record = b"\x17\x03\x03" + len(payload).to_bytes(2, "big") + payload

    class DelayedEofReader:
        async def read(self, _size):
            await asyncio.sleep(0.02)
            return b""

    class RecordThenBlockingReader:
        def __init__(self):
            self.sent = False

        async def read(self, _size):
            if not self.sent:
                self.sent = True
                return record
            await asyncio.Event().wait()

    class Writer:
        def write(self, _data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    activity = tproxy._RelayActivity(
        last_downstream_at=tproxy.time.monotonic(),
        track_tls_records=True,
    )
    result = asyncio.run(asyncio.wait_for(
        tproxy.relay_local_stream(
            DelayedEofReader(),
            Writer(),
            RecordThenBlockingReader(),
            Writer(),
            activity,
        ),
        timeout=0.2,
    ))

    # The pending server task is cancelled when the client closes first, so
    # its return value is zero even though RelayActivity retains the payload.
    assert result == (0, 0)
    assert activity.downstream_bytes == len(record)
    assert activity.client_ended_first
    assert not activity.server_ended_first
    assert activity.tls_complete_records == 1
    assert tproxy._ambiguous_client_first_response_abort(activity, 0.1)


def test_relay_local_stream_preserves_orderly_client_half_close(monkeypatch):
    response = b"delayed response"

    class EofReader:
        async def read(self, _size):
            return b""

    class DelayedResponseReader:
        def __init__(self):
            self.reads = 0

        async def read(self, _size):
            self.reads += 1
            if self.reads == 1:
                await asyncio.sleep(0.01)
                return response
            return b""

    class HalfCloseWriter:
        def __init__(self):
            self.eof = 0
            self.closed = 0

        def can_write_eof(self):
            return True

        def write_eof(self):
            self.eof += 1

        async def drain(self):
            pass

        def close(self):
            self.closed += 1

        async def wait_closed(self):
            pass

    class CaptureWriter(HalfCloseWriter):
        def __init__(self):
            super().__init__()
            self.payload = bytearray()

        def write(self, data):
            self.payload.extend(data)

    upstream = HalfCloseWriter()
    downstream = CaptureWriter()
    activity = tproxy._RelayActivity(last_downstream_at=100.0)
    monkeypatch.setattr(tproxy, "LOCAL_STREAM_IDLE", 0.1)

    result = asyncio.run(
        tproxy.relay_local_stream(
            EofReader(),
            upstream,
            DelayedResponseReader(),
            downstream,
            activity,
        )
    )

    assert result == (0, len(response))
    assert upstream.eof == 1
    assert upstream.closed == 1
    assert bytes(downstream.payload) == response
    assert activity.client_eof
    assert activity.client_ended_first
    assert activity.first_downstream_seen


def test_relay_local_stream_server_first_does_not_become_clean_eof_stall():
    class EofReader:
        async def read(self, _size):
            return b""

    class BlockingReader:
        async def read(self, _size):
            await asyncio.Event().wait()

    class Writer:
        def close(self):
            pass

    activity = tproxy._RelayActivity(last_downstream_at=100.0)
    result = asyncio.run(asyncio.wait_for(
        tproxy.relay_local_stream(
            BlockingReader(),
            Writer(),
            EofReader(),
            Writer(),
            activity,
        ),
        timeout=0.2,
    ))

    assert result == (0, 0)
    assert activity.server_ended_first
    assert not activity.client_ended_first
    assert not activity.client_eof
    assert not tproxy._clean_eof_stream_stalled(activity, now=130.0)


def test_real_loopback_upstream_eof_preserves_server_first_order():
    async def run():
        async def upstream_handler(_reader, writer):
            writer.write(b"server payload")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        upstream = await asyncio.start_server(
            upstream_handler,
            "127.0.0.1",
            0,
        )
        upstream_port = upstream.sockets[0].getsockname()[1]
        relay_done = asyncio.get_running_loop().create_future()

        async def relay_handler(client_reader, client_writer):
            try:
                upstream_reader, upstream_writer = await asyncio.open_connection(
                    "127.0.0.1",
                    upstream_port,
                )
                activity = tproxy._RelayActivity(
                    last_downstream_at=tproxy.time.monotonic()
                )
                result = await tproxy.relay_local_stream(
                    client_reader,
                    upstream_writer,
                    upstream_reader,
                    client_writer,
                    activity,
                )
                relay_done.set_result((result, activity))
            except BaseException as exc:
                if not relay_done.done():
                    relay_done.set_exception(exc)

        relay = await asyncio.start_server(relay_handler, "127.0.0.1", 0)
        relay_port = relay.sockets[0].getsockname()[1]
        browser_reader, browser_writer = await asyncio.open_connection(
            "127.0.0.1",
            relay_port,
        )
        try:
            payload = await asyncio.wait_for(browser_reader.read(), timeout=1.0)
            result, activity = await asyncio.wait_for(relay_done, timeout=1.0)
        finally:
            browser_writer.close()
            await browser_writer.wait_closed()
            relay.close()
            await relay.wait_closed()
            upstream.close()
            await upstream.wait_closed()
        return payload, result, activity

    payload, result, activity = asyncio.run(run())

    assert payload == b"server payload"
    assert result == (0, len(payload))
    assert activity.server_ended_first
    assert not activity.client_ended_first
    assert activity.server_end_at < activity.client_end_at


def test_relay_detects_incomplete_tls_record_then_idle_without_client_abort(
    monkeypatch,
):
    class BlockingReader:
        async def read(self, _size):
            await asyncio.Event().wait()

    complete_record = b"\x17\x03\x03\x00\x08" + b"a" * 8
    partial_record = b"\x17\x03\x03\x40\x11" + b"b" * 128
    framed_prefix = complete_record + partial_record

    class IncompleteRecordThenBlock:
        def __init__(self):
            self.sent = False

        async def read(self, _size):
            if not self.sent:
                self.sent = True
                return framed_prefix
            await asyncio.Event().wait()

    class Writer:
        def __init__(self):
            self.payload = bytearray()

        def write(self, data):
            self.payload.extend(data)

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    monkeypatch.setattr(tproxy, "PARTIAL_TLS_RECORD_IDLE", 0.01)
    downstream = Writer()
    activity = tproxy._RelayActivity(last_downstream_at=tproxy.time.monotonic())

    result = asyncio.run(asyncio.wait_for(
        tproxy.relay_local_stream(
            BlockingReader(),
            Writer(),
            IncompleteRecordThenBlock(),
            downstream,
            activity,
            detect_partial_tls_stall=True,
        ),
        timeout=0.2,
    ))

    assert result == (0, 0)
    assert bytes(downstream.payload) == framed_prefix
    assert activity.downstream_bytes == len(framed_prefix)
    assert activity.tls_complete_records == 1
    assert activity.tls_record_expected == 5 + 0x4011
    assert activity.partial_tls_record_stalled
    assert tproxy._local_stream_stalled(activity)


def test_complete_quiet_tls_record_is_not_a_partial_stall():
    record = b"\x17\x03\x03\x40\x11" + b"x" * 0x4011
    activity = tproxy._RelayActivity(
        last_downstream_at=tproxy.time.monotonic(),
        first_downstream_seen=True,
    )
    tproxy._track_tls_records(activity, record)

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(asyncio.wait_for(
            tproxy._watch_partial_tls_record(activity, 0.01),
            timeout=0.04,
        ))

    assert activity.tls_complete_records == 1
    assert activity.tls_record_expected == 0
    assert not activity.partial_tls_record_stalled


def test_downstream_idle_requires_one_complete_valid_tls_record():
    observations = []
    cases = (
        tproxy._RelayActivity(
            last_downstream_at=tproxy.time.monotonic() - 1.0,
            first_downstream_seen=True,
            track_tls_records=True,
            tls_framing_valid=True,
            tls_complete_records=0,
            on_downstream_idle=lambda: observations.append("incomplete"),
        ),
        tproxy._RelayActivity(
            last_downstream_at=tproxy.time.monotonic() - 1.0,
            first_downstream_seen=True,
            track_tls_records=True,
            tls_framing_valid=False,
            tls_complete_records=1,
            on_downstream_idle=lambda: observations.append("invalid"),
        ),
        tproxy._RelayActivity(
            last_downstream_at=tproxy.time.monotonic() - 1.0,
            first_downstream_seen=True,
            track_tls_records=False,
            tls_framing_valid=True,
            tls_complete_records=1,
            on_downstream_idle=lambda: observations.append("untracked"),
        ),
    )

    for activity in cases:
        asyncio.run(tproxy._watch_downstream_idle(activity, 0.0))
        assert not activity.downstream_idle_observed

    assert observations == []


def test_relay_observer_without_retry_permission_does_not_cancel_stream(
    monkeypatch,
):
    record = b"\x17\x03\x03\x00\x08" + b"x" * 8
    observations = []

    class DelayedEofReader:
        async def read(self, _size):
            await asyncio.sleep(0.04)
            return b""

    class RecordThenBlock:
        def __init__(self):
            self.sent = False

        async def read(self, _size):
            if not self.sent:
                self.sent = True
                return record
            await asyncio.Event().wait()

    class Writer:
        def __init__(self):
            self.payload = bytearray()

        def write(self, data):
            self.payload.extend(data)

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    monkeypatch.setattr(tproxy, "UNKNOWN_PRE_RESPONSE_IDLE", 0.01)
    downstream = Writer()
    activity = tproxy._RelayActivity(
        last_downstream_at=tproxy.time.monotonic(),
        on_downstream_idle=lambda: observations.append("idle"),
    )

    result = asyncio.run(asyncio.wait_for(
        tproxy.relay_local_stream(
            DelayedEofReader(),
            Writer(),
            RecordThenBlock(),
            downstream,
            activity,
            detect_partial_tls_stall=True,
        ),
        timeout=0.2,
    ))

    assert result == (0, 0)
    assert bytes(downstream.payload) == record
    assert observations == ["idle"]
    assert activity.downstream_idle_observed
    assert activity.client_ended_first
    assert not activity.partial_tls_record_stalled


def test_relay_closes_handshake_only_idle_when_observer_requests_retry(
    monkeypatch,
):
    record = b"\x17\x03\x03\x00\x08" + b"x" * 8

    class BlockingReader:
        async def read(self, _size):
            await asyncio.Event().wait()

    class RecordThenBlock:
        def __init__(self):
            self.sent = False

        async def read(self, _size):
            if not self.sent:
                self.sent = True
                return record
            await asyncio.Event().wait()

    class Writer:
        def __init__(self):
            self.payload = bytearray()

        def write(self, data):
            self.payload.extend(data)

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    monkeypatch.setattr(tproxy, "UNKNOWN_PRE_RESPONSE_IDLE", 0.01)
    downstream = Writer()
    activity = tproxy._RelayActivity(
        last_downstream_at=tproxy.time.monotonic(),
    )
    activity.on_downstream_idle = lambda: (
        tproxy._request_transport_idle_retry(activity)
    )

    result = asyncio.run(asyncio.wait_for(
        tproxy.relay_local_stream(
            BlockingReader(),
            Writer(),
            RecordThenBlock(),
            downstream,
            activity,
            detect_partial_tls_stall=True,
        ),
        timeout=0.2,
    ))

    assert result == (0, 0)
    assert bytes(downstream.payload) == record
    assert activity.downstream_idle_observed
    assert activity.downstream_idle_retry
    assert not activity.client_ended_first
    assert not activity.server_ended_first


def test_late_idle_confirmation_cannot_mutate_a_closed_relay():
    prepared = []
    activity = tproxy._RelayActivity(
        last_downstream_at=100.0,
        retry_closed=True,
    )

    assert not tproxy._request_transport_idle_retry(
        activity,
        prepare=lambda: prepared.append(True) or True,
    )
    assert prepared == []
    assert not activity.downstream_idle_retry


def _eligible_pending_navigation_activity(started_at_unix_ms=1_000_000):
    return tproxy._RelayActivity(
        last_downstream_at=90.0,
        downstream_bytes=64,
        first_downstream_seen=True,
        track_tls_records=True,
        tls_framing_valid=True,
        tls_complete_records=1,
        pending_navigation_started_at_unix_ms=started_at_unix_ms,
    )


def _pending_navigation_probe_result(job, **overrides):
    return {
        "schema_version": 1,
        "capability": job["capability"],
        "host": job["host"],
        "request_started_at_unix_ms": job[
            "request_started_at_unix_ms"
        ],
        "observed_at_unix_ms": job["issued_at_unix_ms"] + 8_001,
        "outcome": tproxy.PENDING_NAVIGATION_PROBE_OUTCOME_PENDING,
        **overrides,
    }


def test_pending_navigation_probe_contract_matches_runtime_bounds_and_shape():
    contract = _PENDING_NAVIGATION_PROBE_CONTRACT
    bounds = contract["bounds"]
    assert bounds == {
        "capability_bits": 128,
        "capability_ttl_ms": int(tproxy.PENDING_NAVIGATION_PROBE_TTL * 1000),
        "max_live_capabilities": tproxy.PENDING_NAVIGATION_PROBE_STATE_MAX,
        "max_capabilities_and_guards": (
            tproxy.PENDING_NAVIGATION_PROBE_STATE_MAX
        ),
        "min_pending_observation_ms": int(
            tproxy.UNKNOWN_PRE_RESPONSE_IDLE * 1000
        ),
    }
    assert set(contract["privacy"]["job_fields"]) == set(
        contract["job_defaults"]
    )
    assert set(contract["privacy"]["result_fields"]) == set(
        contract["result_defaults"]
    )
    assert contract["result_defaults"]["outcome"] == (
        tproxy.PENDING_NAVIGATION_PROBE_OUTCOME_PENDING
    )
    assert contract["worker_lifecycle"][
        "accepted_result_guard_until_worker_cleanup"
    ] is True
    assert contract["worker_lifecycle"][
        "claimed_job_guard_until_worker_cleanup"
    ] is True
    assert contract["worker_lifecycle"][
        "ambiguous_cleanup_failure_retains_guard"
    ] is True
    assert contract["worker_lifecycle"][
        "worker_cleanup_failure_retains_guard"
    ] is True
    assert contract["worker_lifecycle"][
        "cleanup_releases_exact_launch_only"
    ] is True
    assert contract["worker_lifecycle"][
        "unclaimed_rejected_result_guard_until_expiry"
    ] is True
    assert contract["worker_lifecycle"][
        "unclaimed_live_capability_guard_until_expiry"
    ] is True
    assert contract["worker_lifecycle"]["unstarted_job_guard_ms"] == 0
    assert contract["worker_lifecycle"][
        "unstarted_discard_uses_worker_lock"
    ] is True
    assert contract["worker_lifecycle"]["submit_before_cleanup"] is True
    assert contract["worker_lifecycle"]["cleanup_before_worker_exit"] is True
    assert contract["browser_surface"] == {
        "launchservices_hidden": True,
        "visible_window": False,
        "unified_headless": False,
        "sandbox_enabled": True,
        "private_profile": True,
        "extensions_disabled": True,
        "quic_disabled": True,
    }
    assert contract["invariants"]["production_runtime_composition"] is True
    assert contract["invariants"][
        "disposable_fixture_jobs_exact_endpoint_only"
    ] is True


def test_pending_navigation_probe_disposable_fixture_rejects_noise_jobs(
    monkeypatch,
):
    monkeypatch.setattr(
        tproxy,
        "_PENDING_NAVIGATION_FIXTURE_ENVIRONMENT",
        {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_DISPOSABLE_CI": "1",
            "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_HOST": (
                composed.FIXTURE_HOST
            ),
            "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_IP": (
                composed.FIXTURE_PUBLIC_IP
            ),
            "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_PORT": "8443",
        },
    )
    exact = _eligible_pending_navigation_activity()
    assert tproxy._register_pending_navigation_relay(
        exact,
        composed.FIXTURE_HOST,
        composed.FIXTURE_PUBLIC_IP,
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
    )
    exact_job = tproxy._issue_pending_navigation_probe(
        exact,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "1" * 32,
    )
    assert exact_job is not None
    tproxy._revoke_pending_navigation_probe_capability(
        exact,
        now=100.0,
        guard_possible_worker=False,
    )

    noise = _eligible_pending_navigation_activity()
    assert tproxy._register_pending_navigation_relay(
        noise,
        "noise.example",
        "1.1.1.1",
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
    )
    assert tproxy._issue_pending_navigation_probe(
        noise,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "2" * 32,
    ) is None


def test_pending_navigation_probe_capability_is_exact_one_shot_and_expires():
    activity = _eligible_pending_navigation_activity()
    assert tproxy._register_pending_navigation_relay(
        activity,
        "unknown.example",
        "1.1.1.1",
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        scheduler=lambda *args, **kwargs: False,
    )

    job = tproxy._issue_pending_navigation_probe(
        activity,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "1" * 32,
    )
    assert job == {
        "schema_version": 1,
        "capability": "1" * 32,
        "host": "unknown.example",
        "request_started_at_unix_ms": 1_000_000,
        "issued_at_unix_ms": 1_010_000,
        "expires_at_unix_ms": 1_040_000,
    }
    assert not tproxy._submit_pending_navigation_probe_result(
        _pending_navigation_probe_result(
            job,
            capability="2" * 32,
        ),
        now=108.001,
    )
    assert job["capability"] in tproxy._pending_navigation_probe_capabilities
    assert not tproxy._submit_pending_navigation_probe_result(
        _pending_navigation_probe_result(job, host="other.example"),
        now=108.001,
    )
    assert not tproxy._pending_navigation_probe_capabilities
    assert not activity.downstream_idle_retry
    assert tproxy._pending_navigation_probe_host_guards[
        "unknown.example"
    ] == 130.0
    tproxy._pending_navigation_probe_host_guards.clear()

    malformed_job = tproxy._issue_pending_navigation_probe(
        activity,
        now=111.0,
        now_unix_ms=1_021_000,
        token_factory=lambda: "a" * 32,
    )
    malformed = _pending_navigation_probe_result(malformed_job)
    malformed["unexpected"] = True
    assert not tproxy._submit_pending_navigation_probe_result(
        malformed,
        now=119.001,
    )
    assert not tproxy._pending_navigation_probe_capabilities
    assert tproxy._pending_navigation_probe_host_guards[
        "unknown.example"
    ] == 141.0
    tproxy._pending_navigation_probe_host_guards.clear()

    early_job = tproxy._issue_pending_navigation_probe(
        activity,
        now=122.0,
        now_unix_ms=1_032_000,
        token_factory=lambda: "3" * 32,
    )
    assert not tproxy._submit_pending_navigation_probe_result(
        _pending_navigation_probe_result(
            early_job,
            observed_at_unix_ms=1_039_999,
        ),
        now=129.999,
    )
    assert not activity.downstream_idle_retry
    assert tproxy._pending_navigation_probe_host_guards[
        "unknown.example"
    ] == 152.0
    tproxy._pending_navigation_probe_host_guards.clear()

    rebound_job = tproxy._issue_pending_navigation_probe(
        activity,
        now=133.0,
        now_unix_ms=1_043_000,
        token_factory=lambda: "b" * 32,
    )
    activity.pending_navigation_stage = tproxy.AUTO_GEPH_STAGE_XBOX_DNS
    assert not tproxy._submit_pending_navigation_probe_result(
        _pending_navigation_probe_result(rebound_job),
        now=141.001,
    )
    activity.pending_navigation_stage = tproxy.AUTO_GEPH_STAGE_SYSTEM
    assert not activity.downstream_idle_retry
    assert tproxy._pending_navigation_probe_host_guards[
        "unknown.example"
    ] == 163.0
    tproxy._pending_navigation_probe_host_guards.clear()

    accepted_job = tproxy._issue_pending_navigation_probe(
        activity,
        now=144.0,
        now_unix_ms=1_054_000,
        token_factory=lambda: "4" * 32,
    )
    assert tproxy._pending_navigation_probe_worker_claimed(
        accepted_job,
        _PROBE_LAUNCH_ONE,
        now=144.0,
    )
    accepted = _pending_navigation_probe_result(accepted_job)
    assert tproxy._submit_pending_navigation_probe_result(
        accepted,
        _PROBE_LAUNCH_ONE,
        now=152.001,
    )
    assert activity.downstream_idle_retry
    assert not tproxy._submit_pending_navigation_probe_result(
        accepted,
        now=152.002,
    )
    assert tproxy._pending_navigation_probe_host_guards[
        "unknown.example"
    ] == float("inf")
    assert tproxy._pending_navigation_probe_accepted_guards[
        (accepted_job["capability"], _PROBE_LAUNCH_ONE)
    ] == ("unknown.example", 174.0)
    tproxy._pending_navigation_probe_worker_completed(
        _PROBE_LAUNCH_ONE,
        now=152.002,
    )
    assert not tproxy._pending_navigation_probe_host_guards
    assert not tproxy._pending_navigation_probe_accepted_guards

    expired_job = tproxy._issue_pending_navigation_probe(
        activity,
        now=200.0,
        now_unix_ms=2_000_000,
        token_factory=lambda: "5" * 32,
    )
    assert not tproxy._submit_pending_navigation_probe_result(
        _pending_navigation_probe_result(
            expired_job,
            observed_at_unix_ms=2_031_000,
        ),
        now=231.0,
    )
    assert not tproxy._pending_navigation_probe_capabilities


def test_pending_navigation_probe_completes_only_its_bound_original_relay():
    class BlockingReader:
        async def read(self, _size):
            await asyncio.Event().wait()

    class Writer:
        def write(self, _data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def scenario():
        first = _eligible_pending_navigation_activity()
        second = _eligible_pending_navigation_activity()
        for activity, address in (
            (first, "1.1.1.1"),
            (second, "8.8.8.8"),
        ):
            assert tproxy._register_pending_navigation_relay(
                activity,
                "unknown.example",
                address,
                tproxy.ROUTE_UNKNOWN,
                tproxy.AUTO_GEPH_STAGE_SYSTEM,
                scheduler=lambda *args, **kwargs: False,
            )

        first_relay = asyncio.create_task(tproxy.relay_local_stream(
            BlockingReader(),
            Writer(),
            BlockingReader(),
            Writer(),
            first,
        ))
        second_relay = asyncio.create_task(tproxy.relay_local_stream(
            BlockingReader(),
            Writer(),
            BlockingReader(),
            Writer(),
            second,
        ))
        await asyncio.sleep(0)

        job = tproxy._issue_pending_navigation_probe(
            first,
            now=100.0,
            now_unix_ms=1_010_000,
            token_factory=lambda: "6" * 32,
        )
        assert job is not None
        assert tproxy._submit_pending_navigation_probe_result(
            _pending_navigation_probe_result(job),
            now=108.001,
        )
        assert await asyncio.wait_for(first_relay, timeout=0.2) == (0, 0)
        assert first.downstream_idle_retry
        assert not second.downstream_idle_retry
        assert not second_relay.done()

        second_relay.cancel()
        await asyncio.gather(second_relay, return_exceptions=True)

    asyncio.run(scenario())


def test_claimed_rejected_probe_stays_guarded_until_worker_cleanup():
    activity = _eligible_pending_navigation_activity()
    assert tproxy._register_pending_navigation_relay(
        activity,
        "unknown.example",
        "1.1.1.1",
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
    )
    job = tproxy._issue_pending_navigation_probe(
        activity,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "1" * 32,
    )
    assert job is not None
    assert tproxy._pending_navigation_probe_worker_claimed(
        job,
        _PROBE_LAUNCH_ONE,
        now=100.0,
    )
    assert not tproxy._submit_pending_navigation_probe_result(
        _pending_navigation_probe_result(job, host="other.example"),
        _PROBE_LAUNCH_ONE,
        now=108.001,
    )
    assert tproxy._pending_navigation_probe_host_guards[
        "unknown.example"
    ] == float("inf")
    tproxy._pending_navigation_probe_worker_completed(
        _PROBE_LAUNCH_ONE,
        now=108.002,
    )
    assert not tproxy._pending_navigation_probe_host_guards
    assert not tproxy._pending_navigation_probe_claimed_guards


def test_pending_navigation_probe_capability_state_is_bounded_and_revoked():
    activities = []
    jobs = []
    for index in range(tproxy.PENDING_NAVIGATION_PROBE_STATE_MAX):
        activity = _eligible_pending_navigation_activity(1_000_000 + index)
        host = f"unknown-{index}.example"
        assert tproxy._register_pending_navigation_relay(
            activity,
            host,
            "1.1.1.1",
            tproxy.ROUTE_UNKNOWN,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
        )
        job = tproxy._issue_pending_navigation_probe(
            activity,
            now=100.0,
            now_unix_ms=1_010_000,
            token_factory=lambda index=index: f"{index + 1:032x}",
        )
        assert job is not None
        activities.append(activity)
        jobs.append(job)

    assert (
        len(tproxy._pending_navigation_probe_capabilities)
        == tproxy.PENDING_NAVIGATION_PROBE_STATE_MAX
    )
    overflow = _eligible_pending_navigation_activity(2_000_000)
    assert tproxy._register_pending_navigation_relay(
        overflow,
        "overflow.example",
        "8.8.4.4",
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
    )
    assert tproxy._issue_pending_navigation_probe(
        overflow,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "f" * 32,
    ) is None
    assert jobs[0]["capability"] in (
        tproxy._pending_navigation_probe_capabilities
    )
    assert jobs[-1]["capability"] in (
        tproxy._pending_navigation_probe_capabilities
    )

    tproxy._revoke_pending_navigation_probe_capability(
        activities[-1],
        now=100.0,
    )
    assert jobs[-1]["capability"] not in (
        tproxy._pending_navigation_probe_capabilities
    )
    assert tproxy._pending_navigation_probe_host_guards[
        f"unknown-{tproxy.PENDING_NAVIGATION_PROBE_STATE_MAX - 1}.example"
    ] == 130.0
    assert (
        len(tproxy._pending_navigation_probe_capabilities)
        + len(tproxy._pending_navigation_probe_host_guards)
        == tproxy.PENDING_NAVIGATION_PROBE_STATE_MAX
    )
    assert tproxy._issue_pending_navigation_probe(
        overflow,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "f" * 32,
    ) is None


def test_pending_navigation_probe_suppresses_same_host_worker_recursion():
    first = _eligible_pending_navigation_activity(1_000_000)
    second = _eligible_pending_navigation_activity(1_000_001)
    for activity, address in ((first, "1.1.1.1"), (second, "8.8.8.8")):
        assert tproxy._register_pending_navigation_relay(
            activity,
            "unknown.example",
            address,
            tproxy.ROUTE_UNKNOWN,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
        )

    first_job = tproxy._issue_pending_navigation_probe(
        first,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "1" * 32,
    )
    assert first_job is not None
    assert tproxy._issue_pending_navigation_probe(
        second,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "2" * 32,
    ) is None

    assert tproxy._pending_navigation_probe_worker_claimed(
        first_job,
        _PROBE_LAUNCH_ONE,
        now=100.0,
    )
    assert tproxy._submit_pending_navigation_probe_result(
        _pending_navigation_probe_result(first_job),
        _PROBE_LAUNCH_ONE,
        now=108.001,
    )
    assert tproxy._issue_pending_navigation_probe(
        second,
        now=108.001,
        now_unix_ms=1_018_001,
        token_factory=lambda: "2" * 32,
    ) is None
    assert tproxy._issue_pending_navigation_probe(
        second,
        now=130.001,
        now_unix_ms=1_040_001,
        token_factory=lambda: "2" * 32,
    ) is None
    tproxy._pending_navigation_probe_worker_completed(
        _PROBE_LAUNCH_ONE,
        now=130.001,
    )

    second_job = tproxy._issue_pending_navigation_probe(
        second,
        now=130.001,
        now_unix_ms=1_040_001,
        token_factory=lambda: "2" * 32,
    )
    assert second_job is not None
    assert second_job["capability"] == "2" * 32


def test_pending_navigation_probe_live_revoke_guards_until_expiry():
    first = _eligible_pending_navigation_activity(1_000_000)
    second = _eligible_pending_navigation_activity(1_000_001)
    for activity, address in ((first, "1.1.1.1"), (second, "8.8.8.8")):
        assert tproxy._register_pending_navigation_relay(
            activity,
            "unknown.example",
            address,
            tproxy.ROUTE_UNKNOWN,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
        )

    assert tproxy._issue_pending_navigation_probe(
        first,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "1" * 32,
    ) is not None
    first.retry_closed = True
    assert tproxy._issue_pending_navigation_probe(
        second,
        now=108.001,
        now_unix_ms=1_018_001,
        token_factory=lambda: "2" * 32,
    ) is None
    assert tproxy._pending_navigation_probe_host_guards[
        "unknown.example"
    ] == 130.0
    assert tproxy._issue_pending_navigation_probe(
        second,
        now=129.999,
        now_unix_ms=1_039_999,
        token_factory=lambda: "2" * 32,
    ) is None
    assert tproxy._issue_pending_navigation_probe(
        second,
        now=130.001,
        now_unix_ms=1_040_001,
        token_factory=lambda: "2" * 32,
    ) is not None


def test_claimed_probe_expiry_stays_guarded_until_worker_cleanup():
    first = _eligible_pending_navigation_activity(1_000_000)
    second = _eligible_pending_navigation_activity(1_000_001)
    for activity, address in ((first, "1.1.1.1"), (second, "8.8.8.8")):
        assert tproxy._register_pending_navigation_relay(
            activity,
            "unknown.example",
            address,
            tproxy.ROUTE_UNKNOWN,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
        )

    job = tproxy._issue_pending_navigation_probe(
        first,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "1" * 32,
    )
    assert job is not None
    assert tproxy._pending_navigation_probe_worker_claimed(
        job,
        _PROBE_LAUNCH_ONE,
        now=100.0,
    )
    assert (job["capability"], _PROBE_LAUNCH_ONE) in (
        tproxy._pending_navigation_probe_claimed_guards
    )

    assert tproxy._issue_pending_navigation_probe(
        second,
        now=130.001,
        now_unix_ms=1_040_001,
        token_factory=lambda: "2" * 32,
    ) is None
    assert job["capability"] not in (
        tproxy._pending_navigation_probe_capabilities
    )
    assert tproxy._pending_navigation_probe_host_guards[
        "unknown.example"
    ] == float("inf")

    tproxy._pending_navigation_probe_worker_completed(
        _PROBE_LAUNCH_ONE,
        now=130.001,
    )
    assert not tproxy._pending_navigation_probe_claimed_guards
    assert not tproxy._pending_navigation_probe_host_guards
    assert tproxy._issue_pending_navigation_probe(
        second,
        now=130.001,
        now_unix_ms=1_040_001,
        token_factory=lambda: "2" * 32,
    ) is not None


def test_later_worker_cleanup_does_not_release_ambiguous_prior_launch_guard():
    first = _eligible_pending_navigation_activity(1_000_000)
    second = _eligible_pending_navigation_activity(1_000_001)
    for activity, address in ((first, "1.1.1.1"), (second, "8.8.8.8")):
        assert tproxy._register_pending_navigation_relay(
            activity,
            "unknown.example",
            address,
            tproxy.ROUTE_UNKNOWN,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
        )

    job = tproxy._issue_pending_navigation_probe(
        first,
        now=100.0,
        now_unix_ms=1_010_000,
        token_factory=lambda: "1" * 32,
    )
    assert job is not None
    assert tproxy._pending_navigation_probe_worker_claimed(
        job,
        _PROBE_LAUNCH_ONE,
        now=100.0,
    )
    assert tproxy._pending_navigation_probe_worker_claimed(
        job,
        _PROBE_LAUNCH_TWO,
        now=105.001,
    )
    assert not tproxy._submit_pending_navigation_probe_result(
        _pending_navigation_probe_result(job),
        "3333333333333333",
        now=108.0,
    )
    assert job["capability"] in (
        tproxy._pending_navigation_probe_capabilities
    )
    assert tproxy._submit_pending_navigation_probe_result(
        _pending_navigation_probe_result(job),
        _PROBE_LAUNCH_TWO,
        now=108.001,
    )

    assert tproxy._pending_navigation_probe_worker_completed(
        _PROBE_LAUNCH_TWO,
        now=108.002,
    )
    assert (
        job["capability"],
        _PROBE_LAUNCH_ONE,
    ) in tproxy._pending_navigation_probe_claimed_guards
    assert tproxy._pending_navigation_probe_host_guards[
        "unknown.example"
    ] == float("inf")
    assert tproxy._issue_pending_navigation_probe(
        second,
        now=130.001,
        now_unix_ms=1_040_001,
        token_factory=lambda: "2" * 32,
    ) is None

    assert tproxy._pending_navigation_probe_worker_completed(
        _PROBE_LAUNCH_ONE,
        now=130.001,
    )
    assert not tproxy._pending_navigation_probe_claimed_guards
    assert not tproxy._pending_navigation_probe_host_guards
    assert tproxy._issue_pending_navigation_probe(
        second,
        now=130.001,
        now_unix_ms=1_040_001,
        token_factory=lambda: "2" * 32,
    ) is not None


def test_pending_navigation_idle_callback_queues_one_lazy_worker_job(
    monkeypatch,
):
    class Runtime:
        def __init__(self):
            self.jobs = []
            self.discarded = []

        def enqueue(self, job):
            self.jobs.append(job)
            return True

        def discard(self, capability):
            self.discarded.append(capability)
            return True

    class Worker:
        def __init__(self):
            self.notifications = 0

        def notify_job_ready(self):
            self.notifications += 1
            return True

        def active(self):
            return False

    runtime = Runtime()
    worker = Worker()
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_runtime", runtime)
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_worker", worker)
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_available", True)
    tproxy._shutdown_started.clear()
    activity = _eligible_pending_navigation_activity(
        int(tproxy.time.time() * 1000) - 9_000
    )
    activity.last_downstream_at = tproxy.time.monotonic() - 9.0
    assert tproxy._register_pending_navigation_relay(
        activity,
        "unknown.example",
        "1.1.1.1",
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        scheduler=lambda *args, **kwargs: False,
    )
    try:
        assert activity.on_downstream_idle() is True
        assert len(runtime.jobs) == 1
        assert runtime.jobs[0]["host"] == "unknown.example"
        assert worker.notifications == 1
        assert runtime.discarded == []
    finally:
        tproxy._unregister_pending_navigation_relay(activity)


def test_real_tls_handshake_idle_queues_the_lazy_worker(monkeypatch):
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("SLIPSTREAM_DISPOSABLE_CI", "1")

    class Runtime:
        def __init__(self):
            self.jobs = []
            self.ready = None

        def enqueue(self, job):
            self.jobs.append(job)
            self.ready.set()
            return True

        def discard(self, _capability):
            return True

    class Worker:
        def notify_job_ready(self):
            return True

        def active(self):
            return False

    activities = []
    original_register = tproxy._register_pending_navigation_relay

    def capture_registration(activity, *args, **kwargs):
        registered = original_register(activity, *args, **kwargs)
        activities.append(activity)
        return registered

    async def scenario(fixture):
        runtime.ready = asyncio.Event()
        proxy = await asyncio.start_server(
            tproxy.handle,
            "127.0.0.1",
            0,
        )
        port = int(proxy.sockets[0].getsockname()[1])
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        writer = None
        try:
            _reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                port,
                ssl=context,
                server_hostname=composed.FIXTURE_HOST,
            )
            writer.write(
                f"GET / HTTP/1.1\r\nHost: {composed.FIXTURE_HOST}\r\n"
                "Connection: close\r\n\r\n".encode("ascii")
            )
            await writer.drain()
            try:
                await asyncio.wait_for(runtime.ready.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pytest.fail(
                    f"pending job missing: records={fixture.records!r}; "
                    f"activities={activities!r}"
                )
        finally:
            fixture._release.set()
            if writer is not None:
                writer.close()
            proxy.close()
            await proxy.wait_closed()

    runtime = Runtime()
    worker = Worker()
    with composed.ComposedHttpsFixture() as fixture:
        environment = fixture.qualification_environment(Path(sys.executable))
        monkeypatch.setattr(
            tproxy,
            "_PENDING_NAVIGATION_FIXTURE_ENVIRONMENT",
            {
                name: environment[name]
                for name in tproxy._PENDING_NAVIGATION_FIXTURE_ENV_KEYS
            },
        )
        monkeypatch.setattr(tproxy, "UNKNOWN_PRE_RESPONSE_IDLE", 0.05)
        monkeypatch.setattr(
            tproxy,
            "_register_pending_navigation_relay",
            capture_registration,
        )
        monkeypatch.setattr(
            tproxy,
            "orig_dst",
            lambda _socket: (composed.FIXTURE_PUBLIC_IP, 443),
        )
        monkeypatch.setattr(tproxy, "_pending_navigation_probe_runtime", runtime)
        monkeypatch.setattr(tproxy, "_pending_navigation_probe_worker", worker)
        monkeypatch.setattr(tproxy, "_pending_navigation_probe_available", True)
        tproxy._shutdown_started.clear()
        asyncio.run(scenario(fixture))

    assert len(runtime.jobs) == 1
    assert runtime.jobs[0]["host"] == composed.FIXTURE_HOST


def test_pending_navigation_idle_callback_revokes_unstarted_job(monkeypatch):
    class Runtime:
        def __init__(self):
            self.job = None
            self.discarded = []

        def enqueue(self, job):
            self.job = job
            return True

        def discard(self, capability):
            self.discarded.append(capability)
            return True

    class Worker:
        def notify_job_ready(self):
            return False

        def discard_unstarted(self, discard):
            return discard()

    runtime = Runtime()
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_runtime", runtime)
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_worker", Worker())
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_available", True)
    tproxy._shutdown_started.clear()
    activity = _eligible_pending_navigation_activity(
        int(tproxy.time.time() * 1000) - 9_000
    )
    activity.last_downstream_at = tproxy.time.monotonic() - 9.0
    assert tproxy._register_pending_navigation_relay(
        activity,
        "unknown.example",
        "1.1.1.1",
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
    )
    try:
        assert activity.on_downstream_idle() is False
        assert runtime.discarded == [runtime.job["capability"]]
        assert not tproxy._pending_navigation_probe_capabilities
        assert not tproxy._pending_navigation_probe_host_guards
    finally:
        tproxy._unregister_pending_navigation_relay(activity)


def test_pending_navigation_rejected_enqueue_has_no_guard(monkeypatch):
    class Runtime:
        def enqueue(self, _job):
            return False

    monkeypatch.setattr(tproxy, "_pending_navigation_probe_runtime", Runtime())
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_available", True)
    tproxy._shutdown_started.clear()
    activity = _eligible_pending_navigation_activity(
        int(tproxy.time.time() * 1000) - 9_000
    )
    activity.last_downstream_at = tproxy.time.monotonic() - 9.0
    assert tproxy._register_pending_navigation_relay(
        activity,
        "unknown.example",
        "1.1.1.1",
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
    )
    try:
        assert activity.on_downstream_idle() is False
        assert not tproxy._pending_navigation_probe_capabilities
        assert not tproxy._pending_navigation_probe_host_guards
    finally:
        tproxy._unregister_pending_navigation_relay(activity)


def test_pending_navigation_signal_advances_only_the_exact_unknown_stage():
    system_activity = _eligible_pending_navigation_activity()
    assert tproxy._register_pending_navigation_relay(
        system_activity,
        "unknown.example",
        "1.1.1.1",
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        scheduler=lambda *args, **kwargs: False,
    )
    assert tproxy._request_pending_navigation_retry(
        "unknown.example",
        1_000_000,
        now=100.0,
    )
    assert system_activity.downstream_idle_retry
    assert tproxy._xbox_dns_candidate_active("unknown.example", now=100.0)
    tproxy._unregister_pending_navigation_relay(system_activity)

    xbox_activity = _eligible_pending_navigation_activity()
    assert tproxy._register_pending_navigation_relay(
        xbox_activity,
        "unknown.example",
        "8.8.8.8",
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        scheduler=lambda *args, **kwargs: False,
    )
    assert tproxy._request_pending_navigation_retry(
        "unknown.example",
        1_000_000,
        now=100.0,
    )
    assert xbox_activity.downstream_idle_retry
    assert tproxy._xbox_dns_attempted_recently("unknown.example", now=100.0)


def test_pending_navigation_strategy_moves_behind_untried_strategies():
    failed_name = tproxy.GENERAL_STRATS[0]
    stage = f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}{failed_name}"
    activity = _eligible_pending_navigation_activity()
    assert tproxy._register_pending_navigation_relay(
        activity,
        "unknown.example",
        "9.9.9.9",
        tproxy.ROUTE_UNKNOWN,
        stage,
        scheduler=lambda *args, **kwargs: False,
    )

    assert tproxy._request_pending_navigation_retry(
        "unknown.example",
        1_000_000,
        now=100.0,
    )
    ordered = tproxy._strategy_order_for_attempt("unknown.example")
    assert ordered[0]["name"] != failed_name
    assert ordered[-1]["name"] == failed_name


def test_pending_navigation_retries_only_after_confirmation_succeeds():
    host = "unknown.example"
    for stage, ip in (
        (tproxy.AUTO_GEPH_STAGE_SYSTEM, "1.1.1.1"),
        (tproxy.AUTO_GEPH_STAGE_XBOX_DNS, "8.8.8.8"),
        (f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64", "9.9.9.9"),
    ):
        tproxy._record_transport_incomplete_idle_evidence(
            host,
            ip,
            stage,
            now=100.0,
            scheduler=lambda *args, **kwargs: False,
        )

    callbacks = []

    def schedule(candidate, ip, strategy_name, *, now=None, on_complete=None):
        callbacks.append((candidate, ip, strategy_name, now))
        assert on_complete is not None
        on_complete(candidate, True)
        return True

    activity = _eligible_pending_navigation_activity()
    assert tproxy._register_pending_navigation_relay(
        activity,
        host,
        "9.9.9.10",
        tproxy.ROUTE_UNKNOWN,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}fake5",
        scheduler=schedule,
    )

    assert tproxy._request_pending_navigation_retry(
        host,
        1_000_000,
        now=100.0,
    )
    assert activity.downstream_idle_retry
    assert callbacks[0][:3] == (host, "1.1.1.1", "plain")


def test_final_pending_navigation_relay_stays_open_when_confirmation_refuses():
    host = "unknown.example"
    stages = (
        (tproxy.AUTO_GEPH_STAGE_SYSTEM, "1.1.1.1"),
        (tproxy.AUTO_GEPH_STAGE_XBOX_DNS, "8.8.8.8"),
        (f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64", "9.9.9.9"),
    )
    for stage, ip in stages:
        tproxy._record_transport_incomplete_idle_evidence(
            host,
            ip,
            stage,
            now=100.0,
            scheduler=lambda *args, **kwargs: False,
        )
    activity = _eligible_pending_navigation_activity()
    assert tproxy._register_pending_navigation_relay(
        activity,
        host,
        "9.9.9.10",
        tproxy.ROUTE_UNKNOWN,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}fake5",
        scheduler=lambda *args, **kwargs: False,
    )

    assert not tproxy._request_pending_navigation_retry(
        host,
        1_000_000,
        now=100.0,
    )
    assert not activity.downstream_idle_retry


def test_pending_navigation_requires_fresh_matching_browser_start_and_idle():
    activity = _eligible_pending_navigation_activity()
    assert tproxy._register_pending_navigation_relay(
        activity,
        "unknown.example",
        "1.1.1.1",
        tproxy.ROUTE_UNKNOWN,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
    )

    assert not tproxy._request_pending_navigation_retry(
        "unknown.example",
        900_000,
        now=100.0,
    )
    assert not tproxy._request_pending_navigation_retry(
        "other.example",
        1_000_000,
        now=100.0,
    )
    activity.last_downstream_at = 99.0
    assert not tproxy._request_pending_navigation_retry(
        "unknown.example",
        1_000_000,
        now=100.0,
    )
    assert not activity.downstream_idle_retry


def test_pending_navigation_registers_only_generic_public_local_routes():
    for host, ip, route_class, stage in (
        (
            "updates.discord.com",
            "1.1.1.1",
            tproxy.ROUTE_UNKNOWN,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
        ),
        (
            "rr2---sn-ntq7yner.googlevideo.com",
            "1.1.1.1",
            tproxy.ROUTE_UNKNOWN,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
        ),
        (
            "www.google.com",
            "1.1.1.1",
            tproxy.ROUTE_UNKNOWN,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
        ),
        (
            "unknown.example",
            "127.0.0.1",
            tproxy.ROUTE_UNKNOWN,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
        ),
        (
            "unknown.example",
            "1.1.1.1",
            tproxy.ROUTE_DIRECT,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
        ),
        ("unknown.example", "1.1.1.1", tproxy.ROUTE_UNKNOWN, None),
        ("unknown.example", "1.1.1.1", tproxy.ROUTE_UNKNOWN, "invalid"),
    ):
        rejected = _eligible_pending_navigation_activity()
        assert not tproxy._register_pending_navigation_relay(
            rejected,
            host,
            ip,
            route_class,
            stage,
        )
        assert not rejected.pending_navigation_eligible
    assert not tproxy._active_pending_navigation_relays


def test_splice_skips_tls_framing_when_partial_detector_is_disabled():
    record = b"\x17\x03\x03\x00\x08" + b"x" * 8

    class Reader:
        def __init__(self):
            self.payload = record

        async def read(self, _size):
            payload, self.payload = self.payload, b""
            return payload

    class Writer:
        def write(self, _data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    activity = tproxy._RelayActivity(last_downstream_at=tproxy.time.monotonic())
    assert asyncio.run(tproxy.splice(Reader(), Writer(), activity)) == len(record)
    assert activity.downstream_bytes == len(record)
    assert activity.tls_record_buffer is None
    assert activity.tls_complete_records == 0


def test_splice_records_upstream_transport_reset():
    class ResetReader:
        async def read(self, _size):
            raise ConnectionResetError("reset")

    class Writer:
        def write(self, _data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    activity = tproxy._RelayActivity(last_downstream_at=tproxy.time.monotonic())
    assert asyncio.run(tproxy.splice(ResetReader(), Writer(), activity)) == 0
    assert activity.server_read_failed
    assert activity.server_end_at > 0


def _short_server_first_activity(*, read_failed=False, downstream_bytes=16384):
    return tproxy._RelayActivity(
        last_downstream_at=100.1,
        downstream_bytes=downstream_bytes,
        server_end_at=100.2,
        server_ended_first=True,
        first_downstream_seen=True,
        server_read_failed=read_failed,
        tls_record_buffer=bytearray(),
        tls_complete_records=2,
    )


def _medium_server_first_activity(*, downstream_bytes=96 * 1024):
    return _short_server_first_activity(downstream_bytes=downstream_bytes)


def _client_first_response_abort_activity(*, downstream_bytes=16 * 1024):
    return tproxy._RelayActivity(
        last_downstream_at=100.1,
        downstream_bytes=downstream_bytes,
        client_end_at=100.2,
        server_end_at=100.3,
        client_eof=True,
        client_ended_first=True,
        first_downstream_seen=True,
        tls_record_buffer=bytearray(),
        tls_complete_records=2,
        track_tls_records=True,
    )


def _first_tls_record_cut_activity(*, read_failed=False):
    payload = bytearray(b"\x17\x03\x03\x00\x20partial")
    return tproxy._RelayActivity(
        last_downstream_at=100.1,
        downstream_bytes=len(payload),
        server_end_at=100.2,
        server_ended_first=True,
        first_downstream_seen=True,
        server_read_failed=read_failed,
        tls_record_buffer=payload,
        tls_record_expected=37,
        tls_complete_records=0,
    )


def test_protected_first_tls_record_cut_recovers_without_repeat(monkeypatch):
    host = "rr5---sn-test.googlevideo.com"
    runtime_results = []
    monkeypatch.setattr(tproxy, "_protected_local_server_first_closes", {})
    monkeypatch.setattr(tproxy, "_direct_first_local_fallback_until", {})
    monkeypatch.setattr(
        tproxy,
        "note_local_bypass_runtime_result",
        lambda *args, **kwargs: runtime_results.append((args, kwargs)),
    )

    recovered = tproxy.note_protected_local_server_first_close(
        host,
        "plain",
        _first_tls_record_cut_activity(),
        duration=0.2,
        now=100.0,
    )

    assert recovered
    assert len(runtime_results) == 1
    assert runtime_results[0][1]["failed_strategy"] == "plain"
    assert tproxy._direct_first_local_fallback_active(host, now=100.1)


def test_protected_reset_without_a_tls_record_is_not_recovery_evidence(
    monkeypatch,
):
    host = "rr5---sn-test.googlevideo.com"
    runtime_results = []
    activity = _first_tls_record_cut_activity(read_failed=True)
    activity.tls_record_buffer = bytearray(b"\x17\x03\x03\x00")
    activity.tls_record_expected = 0
    activity.downstream_bytes = len(activity.tls_record_buffer)
    monkeypatch.setattr(tproxy, "_protected_local_server_first_closes", {})
    monkeypatch.setattr(tproxy, "_direct_first_local_fallback_until", {})
    monkeypatch.setattr(
        tproxy,
        "note_local_bypass_runtime_result",
        lambda *args, **kwargs: runtime_results.append((args, kwargs)),
    )

    recovered = tproxy.note_protected_local_server_first_close(
        host,
        "plain",
        activity,
        duration=0.2,
        now=100.0,
    )

    assert not recovered
    assert not runtime_results


def test_protected_direct_first_close_requires_repeat_then_uses_local_fallback(
    monkeypatch,
):
    host = "rr5---sn-test.googlevideo.com"
    strategy_name = "plain"
    now = tproxy.time.monotonic()
    runtime_results = []
    monkeypatch.setattr(tproxy, "_protected_local_server_first_closes", {})
    monkeypatch.setattr(tproxy, "_direct_first_local_fallback_until", {})
    monkeypatch.setattr(
        tproxy,
        "note_local_bypass_runtime_result",
        lambda *args, **kwargs: runtime_results.append((args, kwargs)),
    )

    first = tproxy.note_protected_local_server_first_close(
        host,
        strategy_name,
        _short_server_first_activity(),
        duration=0.2,
        now=now,
    )
    second = tproxy.note_protected_local_server_first_close(
        host,
        strategy_name,
        _short_server_first_activity(),
        duration=0.2,
        now=now + 1.0,
    )

    assert not first
    assert second
    assert len(runtime_results) == 1
    args, kwargs = runtime_results[0]
    assert args[:2] == (host, False)
    assert kwargs["failed_strategy"] == strategy_name
    assert tproxy._direct_first_local_fallback_active(host, now=now + 1.1)
    order = tproxy.strategy_order(host)
    assert order
    assert all(strategy["name"] != "plain" for strategy in order)

    monkeypatch.setattr(
        tproxy.time,
        "monotonic",
        lambda: now + tproxy.DIRECT_FIRST_LOCAL_FALLBACK_TTL + 2.0,
    )
    assert tproxy.strategy_order(host)[0]["name"] == "plain"


def test_youtube_medium_server_close_requires_repeat_then_uses_local_fallback(
    monkeypatch,
):
    host = "rr5---sn-test.googlevideo.com"
    now = tproxy.time.monotonic()
    runtime_results = []
    monkeypatch.setattr(tproxy, "_protected_local_server_first_closes", {})
    monkeypatch.setattr(tproxy, "_direct_first_local_fallback_until", {})
    monkeypatch.setattr(
        tproxy,
        "note_local_bypass_runtime_result",
        lambda *args, **kwargs: runtime_results.append((args, kwargs)),
    )

    first = tproxy.note_protected_local_server_first_close(
        host,
        "plain",
        _medium_server_first_activity(),
        duration=2.0,
        now=now,
    )
    second = tproxy.note_protected_local_server_first_close(
        host,
        "plain",
        _medium_server_first_activity(),
        duration=2.0,
        now=now + 1.0,
    )

    assert not first
    assert second
    assert len(runtime_results) == 1
    assert runtime_results[0][1]["failed_strategy"] == "plain"
    assert tproxy._direct_first_local_fallback_active(host, now=now + 1.1)
    assert all(
        strategy["name"] != "plain" for strategy in tproxy.strategy_order(host)
    )


def test_youtube_medium_close_demotes_first_local_fallback_immediately(
    monkeypatch,
):
    host = "rr5---sn-test.googlevideo.com"
    now = tproxy.time.monotonic()
    runtime_results = []
    monkeypatch.setattr(tproxy, "_protected_local_server_first_closes", {})
    monkeypatch.setattr(
        tproxy,
        "_direct_first_local_fallback_until",
        {host: now + 30.0},
    )
    monkeypatch.setattr(
        tproxy,
        "note_local_bypass_runtime_result",
        lambda *args, **kwargs: runtime_results.append((args, kwargs)),
    )

    recovered = tproxy.note_protected_local_server_first_close(
        host,
        "split64+fake",
        _medium_server_first_activity(),
        duration=2.0,
        now=now,
    )

    assert recovered
    assert len(runtime_results) == 1
    assert runtime_results[0][1]["failed_strategy"] == "split64+fake"
    assert not tproxy.is_geo_exit_route(host)


def test_medium_server_close_does_not_broaden_other_protected_routes(
    monkeypatch,
):
    runtime_results = []
    monkeypatch.setattr(tproxy, "_protected_local_server_first_closes", {})
    monkeypatch.setattr(tproxy, "_direct_first_local_fallback_until", {})
    monkeypatch.setattr(
        tproxy,
        "note_local_bypass_runtime_result",
        lambda *args, **kwargs: runtime_results.append((args, kwargs)),
    )

    for host, strategy in (
        ("updates.discord.com", "split64+fake"),
        ("www.google.com", "plain"),
        ("api.spotify.com", "plain"),
    ):
        for observed_at in (100.0, 101.0):
            assert not tproxy.note_protected_local_server_first_close(
                host,
                strategy,
                _medium_server_first_activity(),
                duration=2.0,
                now=observed_at,
            )

    assert not runtime_results
    assert not tproxy._protected_local_server_first_closes


def test_youtube_server_close_above_probe_cap_remains_inert(monkeypatch):
    host = "rr5---sn-test.googlevideo.com"
    monkeypatch.setattr(tproxy, "_protected_local_server_first_closes", {})
    monkeypatch.setattr(tproxy, "_direct_first_local_fallback_until", {})

    for observed_at in (100.0, 101.0):
        assert not tproxy.note_protected_local_server_first_close(
            host,
            "plain",
            _medium_server_first_activity(
                downstream_bytes=tproxy.TRANSPORT_INCOMPLETE_PROBE_MAX_BYTES + 1,
            ),
            duration=2.0,
            now=observed_at,
        )

    assert not tproxy._protected_local_server_first_closes
    assert not tproxy._direct_first_local_fallback_active(host, now=101.1)


def test_protected_local_transport_reset_recovers_without_repeat(monkeypatch):
    host = "updates.discord.com"
    runtime_results = []
    monkeypatch.setattr(tproxy, "_protected_local_server_first_closes", {})
    monkeypatch.setattr(tproxy, "_direct_first_local_fallback_until", {})
    monkeypatch.setattr(
        tproxy,
        "note_local_bypass_runtime_result",
        lambda *args, **kwargs: runtime_results.append((args, kwargs)),
    )

    recovered = tproxy.note_protected_local_server_first_close(
        host,
        "split64+fake",
        _short_server_first_activity(read_failed=True),
        duration=0.2,
        now=100.0,
    )

    assert recovered
    assert len(runtime_results) == 1
    assert runtime_results[0][1]["failed_strategy"] == "split64+fake"
    assert not tproxy.is_geo_exit_route(host)


def test_repeated_short_server_first_closes_advance_exact_unknown_host():
    host = "large-transfer.example"
    activity = _short_server_first_activity()

    assert not tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        now=100.2,
    )
    assert not tproxy._xbox_dns_candidate_active(host, now=100.2)
    assert tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        now=100.3,
    )
    assert tproxy._xbox_dns_candidate_active(host, now=100.3)
    assert (
        tproxy.AUTO_GEPH_STAGE_SYSTEM
        in tproxy._transport_incomplete_server_first_evidence[host]
    )
    assert host not in tproxy._local_partial_stalls
    assert not tproxy.is_geo_exit_route(host)

    for protected in (
        "updates.discord.com",
        "rr2---sn-ntq7yner.googlevideo.com",
        "www.google.com",
    ):
        assert not tproxy.note_server_first_route_close(
            protected,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            activity,
            duration=0.2,
            now=100.4,
        )
        assert not tproxy._xbox_dns_candidate_active(protected, now=100.4)


def test_repeated_plain_server_close_schedules_exact_transport_confirmation(
    monkeypatch,
):
    host = "partial-body.example"
    activity = _short_server_first_activity()
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    def observe(stage, strategy_name, times):
        for now in times:
            tproxy.note_server_first_route_close(
                host,
                stage,
                activity,
                duration=0.2,
                now=now,
                probe_ip="1.1.1.1",
                strategy_name=strategy_name,
                transport_confirmation_runner=lambda candidate, ip: (
                    confirmations.append((candidate, ip)) or True
                ),
            )

    observe(tproxy.AUTO_GEPH_STAGE_SYSTEM, "plain", (100.2, 100.3))
    assert confirmations == [(host, "1.1.1.1")]
    assert set(tproxy._transport_incomplete_server_first_evidence[host]) == {
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
    }
    assert tproxy._transport_incomplete_plain_candidates[host] == (
        "1.1.1.1",
        100.3,
    )
    assert host not in tproxy._transport_incomplete_confirming
    assert tproxy._transport_incomplete_last_probe[host] == 100.3
    assert tproxy._xbox_dns_candidate_active(host, now=100.3)
    assert not tproxy.is_geo_exit_route(host)


def test_single_system_short_close_does_not_request_content_probe(
    monkeypatch,
):
    host = "system-only-partial.example"
    activity = _short_server_first_activity()
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        now=100.2,
        probe_ip="1.1.1.1",
        strategy_name="plain",
        transport_confirmation_runner=lambda candidate, ip: (
            confirmations.append((candidate, ip)) or True
        ),
    )

    assert confirmations == []
    assert host not in tproxy._transport_incomplete_last_probe
    assert not tproxy._xbox_dns_candidate_active(host, now=100.2)
    assert not tproxy.is_geo_exit_route(host)


def test_repeated_system_short_close_respects_network_wide_failure_guard(
    monkeypatch,
):
    host = "network-guarded-partial.example"
    activity = _short_server_first_activity()
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        tproxy._local_partial_stalls[f"network-wide-{index}.example"] = {
            tproxy.AUTO_GEPH_STAGE_SYSTEM: 100.0,
        }

    for now in (100.2, 100.3):
        tproxy.note_server_first_route_close(
            host,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            activity,
            duration=0.2,
            now=now,
            probe_ip="1.1.1.1",
            strategy_name="plain",
            transport_confirmation_runner=lambda candidate, ip: (
                confirmations.append((candidate, ip)) or True
            ),
        )

    assert confirmations == []
    assert host not in tproxy._transport_incomplete_last_probe
    assert tproxy._xbox_dns_candidate_active(host, now=100.3)
    assert not tproxy.is_geo_exit_route(host)


def test_repeated_large_system_close_uses_content_probe_without_advancing_ladder(
    monkeypatch,
):
    host = "large-partial-body.example"
    activity = _short_server_first_activity(downstream_bytes=128 * 1024)
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for now, probe_ip in (
        (100.2, "1.1.1.1"),
        (100.3, "8.8.8.8"),
    ):
        assert not tproxy.note_server_first_route_close(
            host,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            activity,
            duration=12.0,
            now=now,
            probe_ip=probe_ip,
            strategy_name="plain",
            transport_confirmation_runner=lambda candidate, ip: (
                confirmations.append((candidate, ip)) or True
            ),
        )

    assert confirmations == [(host, "1.1.1.1")]
    assert not tproxy._xbox_dns_candidate_active(host, now=100.3)
    assert host not in tproxy._transport_incomplete_server_first_evidence
    assert tproxy._transport_incomplete_last_probe[host] == 100.3
    assert not tproxy.is_geo_exit_route(host)


def test_repeated_large_complete_response_does_not_request_geph(monkeypatch):
    host = "large-complete-body.example"
    activity = _short_server_first_activity(downstream_bytes=128 * 1024)
    local_probes = []
    geph_requests = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_incomplete_response_plain_payload_probe",
        lambda ip, candidate: local_probes.append((ip, candidate)) or False,
    )
    monkeypatch.setattr(
        tproxy,
        "_request_incomplete_response_geo_exit_confirmation",
        lambda candidate: geph_requests.append(candidate) or True,
    )

    for now in (100.2, 100.3):
        assert not tproxy.note_server_first_route_close(
            host,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            activity,
            duration=12.0,
            now=now,
            probe_ip="1.1.1.1",
            strategy_name="plain",
            transport_confirmation_runner=(
                tproxy._confirm_transport_incomplete_response
            ),
        )

    assert local_probes == [("1.1.1.1", host)]
    assert geph_requests == []
    assert not tproxy._xbox_dns_candidate_active(host, now=100.3)
    assert not tproxy.is_geo_exit_route(host)


def test_repeated_large_close_requires_exact_public_system_ip(monkeypatch):
    host = "large-no-address.example"
    activity = _short_server_first_activity(downstream_bytes=128 * 1024)
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for now in (100.2, 100.3):
        assert not tproxy.note_server_first_route_close(
            host,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            activity,
            duration=12.0,
            now=now,
            strategy_name="plain",
            transport_confirmation_runner=lambda candidate, ip: (
                confirmations.append((candidate, ip)) or True
            ),
        )

    assert confirmations == []
    assert host not in tproxy._transport_incomplete_last_probe
    assert not tproxy._xbox_dns_candidate_active(host, now=100.3)
    assert not tproxy.is_geo_exit_route(host)


def test_repeated_client_first_abort_schedules_only_content_probe():
    host = "partial-http2-body.example"
    activity = _client_first_response_abort_activity()
    scheduled = []

    def schedule(candidate, ip, strategy, *, now):
        scheduled.append((candidate, ip, strategy, now))
        return True

    assert not tproxy.note_client_first_response_abort(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        probe_ip="1.1.1.1",
        strategy_name="plain",
        now=100.2,
        scheduler=schedule,
    )
    assert tproxy.note_client_first_response_abort(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        probe_ip="1.0.0.1",
        strategy_name="plain",
        now=100.3,
        scheduler=schedule,
    )

    assert scheduled == [(host, "1.0.0.1", "plain", 100.3)]
    assert not tproxy._xbox_dns_candidate_active(host, now=100.3)
    assert not tproxy.is_geo_exit_route(host)


def test_completed_response_breaks_client_first_abort_sequence():
    host = "ordinary-keepalive.example"
    activity = _client_first_response_abort_activity()
    scheduled = []

    assert not tproxy.note_client_first_response_abort(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        probe_ip="1.1.1.1",
        strategy_name="plain",
        now=100.2,
        scheduler=lambda *args, **kwargs: scheduled.append((args, kwargs)),
    )
    completed = _short_server_first_activity()
    assert not tproxy.note_client_first_response_abort(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        completed,
        duration=0.2,
        probe_ip="1.1.1.1",
        strategy_name="plain",
        now=100.3,
        scheduler=lambda *args, **kwargs: scheduled.append((args, kwargs)),
    )
    assert not tproxy.note_client_first_response_abort(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        probe_ip="1.1.1.1",
        strategy_name="plain",
        now=100.4,
        scheduler=lambda *args, **kwargs: scheduled.append((args, kwargs)),
    )

    assert scheduled == []
    assert len(tproxy._transport_incomplete_client_first_evidence[host]) == 1


def test_client_first_abort_excludes_non_system_and_protected_routes():
    activity = _client_first_response_abort_activity()
    scheduled = []

    for host, stage in (
        ("partial-local.example", tproxy.AUTO_GEPH_STAGE_XBOX_DNS),
        ("updates.discord.com", tproxy.AUTO_GEPH_STAGE_SYSTEM),
        ("rr2---sn-test.googlevideo.com", tproxy.AUTO_GEPH_STAGE_SYSTEM),
        ("www.google.com", tproxy.AUTO_GEPH_STAGE_SYSTEM),
    ):
        for now in (100.2, 100.3):
            assert not tproxy.note_client_first_response_abort(
                host,
                stage,
                activity,
                duration=0.2,
                probe_ip="1.1.1.1",
                strategy_name="plain",
                now=now,
                scheduler=lambda *args, **kwargs: scheduled.append((args, kwargs)),
            )

    assert scheduled == []
    assert not tproxy._transport_incomplete_client_first_evidence


def test_client_first_abort_is_bounded_before_content_probe():
    host = "bounded-client-abort.example"
    scheduled = []

    for activity, duration in (
        (_client_first_response_abort_activity(downstream_bytes=1024), 0.2),
        (
            _client_first_response_abort_activity(
                downstream_bytes=tproxy.TRANSPORT_INCOMPLETE_PROBE_MAX_BYTES + 1,
            ),
            0.2,
        ),
        (_client_first_response_abort_activity(), 31.0),
    ):
        assert not tproxy.note_client_first_response_abort(
            host,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            activity,
            duration=duration,
            probe_ip="1.1.1.1",
            strategy_name="plain",
            now=100.2,
            scheduler=lambda *args, **kwargs: scheduled.append((args, kwargs)),
        )

    assert scheduled == []
    assert host not in tproxy._transport_incomplete_client_first_evidence


def test_client_first_abort_respects_network_wide_guard():
    host = "guarded-client-abort.example"
    activity = _client_first_response_abort_activity()
    scheduled = []
    for index in range(tproxy.AUTO_GEPH_NET_BAD - 1):
        tproxy._transport_incomplete_client_first_evidence[
            f"peer-{index}.example"
        ] = deque(((100.1, "1.1.1.1"),))

    for now in (100.2, 100.3):
        assert not tproxy.note_client_first_response_abort(
            host,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            activity,
            duration=0.2,
            probe_ip="1.1.1.1",
            strategy_name="plain",
            now=now,
            scheduler=lambda *args, **kwargs: scheduled.append((args, kwargs)),
        )

    assert scheduled == []
    assert not tproxy.is_geo_exit_route(host)


def test_repeated_large_close_excludes_protected_routes(monkeypatch):
    activity = _short_server_first_activity(downstream_bytes=128 * 1024)
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for protected in (
        "updates.discord.com",
        "rr2---sn-ntq7yner.googlevideo.com",
        "www.google.com",
    ):
        for now in (100.2, 100.3):
            assert not tproxy.note_server_first_route_close(
                protected,
                tproxy.AUTO_GEPH_STAGE_SYSTEM,
                activity,
                duration=12.0,
                now=now,
                probe_ip="1.1.1.1",
                strategy_name="plain",
                transport_confirmation_runner=lambda candidate, ip: (
                    confirmations.append((candidate, ip)) or True
                ),
            )
        assert not tproxy._xbox_dns_candidate_active(protected, now=100.3)

    assert confirmations == []


def test_server_first_close_classes_do_not_complete_each_other(monkeypatch):
    host = "mixed-close-sizes.example"
    short = _short_server_first_activity()
    large = _short_server_first_activity(downstream_bytes=128 * 1024)
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for now, activity, duration in (
        (100.1, short, 0.2),
        (100.2, large, 12.0),
        (100.3, short, 0.2),
        (100.4, large, 12.0),
    ):
        assert not tproxy.note_server_first_route_close(
            host,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            activity,
            duration=duration,
            now=now,
            probe_ip="1.1.1.1",
            strategy_name="plain",
            transport_confirmation_runner=lambda candidate, ip: (
                confirmations.append((candidate, ip)) or True
            ),
        )

    assert confirmations == []
    assert not tproxy._xbox_dns_candidate_active(host, now=100.4)
    assert host not in tproxy._transport_incomplete_server_first_evidence
    assert not tproxy.is_geo_exit_route(host)


def test_short_repeat_claim_cannot_authorize_large_content_probe(monkeypatch):
    host = "claimed-mixed-close.example"
    large = _short_server_first_activity(downstream_bytes=128 * 1024)
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    assert not tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        large,
        duration=12.0,
        now=100.2,
        probe_ip="8.8.8.8",
        strategy_name="plain",
        repeat_claimed=True,
        repeat_probe_ip="1.1.1.1",
        transport_confirmation_runner=lambda candidate, ip: (
            confirmations.append((candidate, ip)) or True
        ),
    )

    assert confirmations == []
    assert not tproxy._xbox_dns_candidate_active(host, now=100.2)
    assert host not in tproxy._transport_incomplete_last_probe
    assert not tproxy.is_geo_exit_route(host)


def test_repeated_large_non_system_close_never_schedules_content_probe(monkeypatch):
    host = "large-local-response.example"
    activity = _short_server_first_activity(downstream_bytes=128 * 1024)
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for now in (100.2, 100.3):
        assert not tproxy.note_server_first_route_close(
            host,
            tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
            activity,
            duration=12.0,
            now=now,
            probe_ip="1.1.1.1",
            strategy_name="plain",
            transport_confirmation_runner=lambda candidate, ip: (
                confirmations.append((candidate, ip)) or True
            ),
        )

    assert confirmations == []
    assert host not in tproxy._transport_incomplete_last_probe
    assert not tproxy.is_geo_exit_route(host)


def test_server_first_evidence_does_not_mix_with_partial_record_stalls(
    monkeypatch,
):
    host = "mixed-evidence.example"
    activity = _short_server_first_activity()
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for stage in (
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake",
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake",
    ):
        assert not tproxy._record_partial_tls_stall_evidence(host, stage, 100.0)

    for now in (100.2, 100.3):
        tproxy.note_server_first_route_close(
            host,
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            activity,
            duration=0.2,
            now=now,
            probe_ip="1.1.1.1",
            strategy_name="plain",
            transport_confirmation_runner=lambda candidate, ip: (
                confirmations.append((candidate, ip)) or True
            ),
        )

    assert confirmations == [(host, "1.1.1.1")]
    assert set(tproxy._transport_incomplete_server_first_evidence[host]) == {
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
    }
    assert set(tproxy._local_partial_stalls[host]) == {
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake",
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake",
    }
    assert tproxy._transport_incomplete_last_probe[host] == 100.3


def test_transport_confirmation_rejects_non_plain_and_protected_routes(monkeypatch):
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    assert not tproxy._schedule_transport_incomplete_response_confirmation(
        "unknown.example",
        "1.1.1.1",
        "split64",
        now=100.0,
        runner=lambda host, ip: confirmations.append((host, ip)),
    )
    for protected in (
        "updates.discord.com",
        "rr2---sn-ntq7yner.googlevideo.com",
        "www.google.com",
    ):
        assert not tproxy._schedule_transport_incomplete_response_confirmation(
            protected,
            "1.1.1.1",
            "plain",
            now=100.0,
            runner=lambda host, ip: confirmations.append((host, ip)),
        )

    assert confirmations == []


def test_transport_confirmation_requires_local_proof_before_geph(monkeypatch):
    host = "partial-body.example"
    requested = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_request_incomplete_response_geo_exit_confirmation",
        lambda candidate: requested.append(candidate) or True,
    )
    monkeypatch.setattr(
        tproxy,
        "_incomplete_response_plain_payload_probe",
        lambda ip, candidate: False,
    )

    assert not tproxy._confirm_transport_incomplete_response(host, "1.1.1.1")
    assert requested == []

    monkeypatch.setattr(
        tproxy,
        "_incomplete_response_plain_payload_probe",
        lambda ip, candidate: ip == "1.1.1.1" and candidate == host,
    )
    assert tproxy._confirm_transport_incomplete_response(host, "1.1.1.1")
    assert requested == [host]


def test_transport_confirmation_is_rate_limited_per_exact_host(monkeypatch):
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for now in (100.0, 101.0):
        tproxy._schedule_transport_incomplete_response_confirmation(
            "partial-body.example",
            "1.1.1.1",
            "plain",
            now=now,
            runner=lambda host, ip: confirmations.append((host, ip)),
        )
    tproxy._schedule_transport_incomplete_response_confirmation(
        "other-partial.example",
        "8.8.8.8",
        "plain",
        now=101.0,
        runner=lambda host, ip: confirmations.append((host, ip)),
    )

    assert confirmations == [
        ("partial-body.example", "1.1.1.1"),
        ("other-partial.example", "8.8.8.8"),
    ]


def test_transport_confirmation_reports_runner_outcome_once(monkeypatch):
    completed = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    assert tproxy._schedule_transport_incomplete_response_confirmation(
        "partial-body.example",
        "1.1.1.1",
        "plain",
        now=100.0,
        runner=lambda _host, _ip: True,
        on_complete=lambda host, succeeded: completed.append(
            (host, succeeded)
        ),
    )

    assert completed == [("partial-body.example", True)]


def test_transport_confirmation_has_a_small_global_concurrency_cap(monkeypatch):
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    for index in range(tproxy.TRANSPORT_INCOMPLETE_CONFIRM_MAX):
        tproxy._transport_incomplete_confirming[f"active-{index}.example"] = 100.0

    assert not tproxy._schedule_transport_incomplete_response_confirmation(
        "another-partial.example",
        "1.1.1.1",
        "plain",
        now=101.0,
        runner=lambda host, ip: confirmations.append((host, ip)),
    )
    assert confirmations == []


def test_transport_confirmation_respects_network_wide_failure_guard(monkeypatch):
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_network_wide_unknown_failure_visible",
        lambda _now=None: True,
    )

    assert not tproxy._schedule_transport_incomplete_response_confirmation(
        "guarded-partial.example",
        "1.1.1.1",
        "plain",
        now=101.0,
        runner=lambda host, ip: confirmations.append((host, ip)),
    )
    assert confirmations == []
    assert "guarded-partial.example" not in tproxy._transport_incomplete_confirming


def test_payload_idle_evidence_participates_in_network_wide_failure_guard():
    scheduled = []
    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        assert (
            tproxy._record_transport_incomplete_idle_evidence(
            f"idle-{index}.example",
            f"1.1.1.{index + 1}",
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            now=100.0 + index,
            scheduler=lambda *args, **kwargs: scheduled.append((args, kwargs)),
            )
            == tproxy.TRANSPORT_IDLE_EVIDENCE_ADVANCE
        )

    assert tproxy._network_wide_unknown_failure_visible(now=110.0)
    guarded_host = "idle-0.example"
    for stage, expected in (
        (
            tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
            tproxy.TRANSPORT_IDLE_EVIDENCE_ADVANCE,
        ),
        (
            f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64",
            tproxy.TRANSPORT_IDLE_EVIDENCE_ADVANCE,
        ),
        (
            f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}fake5",
            tproxy.TRANSPORT_IDLE_EVIDENCE_HOLD,
        ),
    ):
        assert (
            tproxy._record_transport_incomplete_idle_evidence(
                guarded_host,
                "8.8.8.8",
                stage,
                now=110.0,
                scheduler=lambda *args, **kwargs: scheduled.append((args, kwargs)),
            )
            == expected
        )
    assert scheduled == []


def test_payload_idle_evidence_expires_from_network_wide_failure_guard():
    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        tproxy._record_transport_incomplete_idle_evidence(
            f"stale-idle-{index}.example",
            f"1.1.1.{index + 1}",
            tproxy.AUTO_GEPH_STAGE_SYSTEM,
            now=100.0,
            scheduler=lambda *args, **kwargs: True,
        )

    assert tproxy._network_wide_unknown_failure_visible(now=100.0)
    assert not tproxy._network_wide_unknown_failure_visible(
        now=101.0 + tproxy.AUTO_GEPH_PARTIAL_STALL_WINDOW
    )
    assert not tproxy._local_payload_idle_failures


def test_server_reset_advances_unknown_host_without_waiting_for_repeat():
    host = "reset-after-record.example"
    activity = _short_server_first_activity(read_failed=True)

    assert tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        now=100.2,
    )
    assert tproxy._xbox_dns_candidate_active(host, now=100.2)
    assert host not in tproxy._transport_incomplete_server_first_evidence
    assert (
        tproxy.unknown_recovery_stage(host, now=100.3)
        == tproxy.UNKNOWN_RECOVERY_XBOX_DNS
    )
    repeat_stage = tproxy._claim_server_first_repeat_stage(host, now=100.3)
    assert repeat_stage == (tproxy.AUTO_GEPH_STAGE_SYSTEM, None)
    assert (
        tproxy._unknown_recovery_stage_for_attempt(
            host,
            repeat_stage[0],
            now=100.3,
        )
        == tproxy.UNKNOWN_RECOVERY_SYSTEM
    )
    assert tproxy._claim_server_first_repeat_stage(host, now=100.3) is None

    assert tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        now=100.4,
        repeat_claimed=True,
    )
    assert set(tproxy._transport_incomplete_server_first_evidence[host]) == {
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
    }


def test_nonmatching_server_first_retry_discards_the_provisional_close():
    host = "nonmatching-reset-repeat.example"
    stage = tproxy.AUTO_GEPH_STAGE_SYSTEM
    activity = _short_server_first_activity(read_failed=True)

    assert tproxy.note_server_first_route_close(
        host,
        stage,
        activity,
        duration=0.2,
        now=100.0,
    )
    assert tproxy._claim_server_first_repeat_stage(host, now=100.1) == (
        stage,
        None,
    )
    assert (host, stage) not in tproxy._server_first_closes

    # The claimed attempt produced a different outcome. A later close is a new
    # first observation, not the missing matching retry.
    assert tproxy.note_server_first_route_close(
        host,
        stage,
        activity,
        duration=0.2,
        now=100.2,
    )
    assert host not in tproxy._transport_incomplete_server_first_evidence
    assert tproxy._claim_server_first_repeat_stage(host, now=100.3) == (
        stage,
        None,
    )


def test_server_first_repeat_stage_expires_inside_the_evidence_window():
    host = "expired-reset-repeat.example"
    activity = _short_server_first_activity(read_failed=True)

    assert tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        activity,
        duration=0.2,
        now=100.0,
    )
    assert (
        tproxy._claim_server_first_repeat_stage(
            host,
            now=100.0 + tproxy.SERVER_FIRST_CLOSE_WINDOW,
        )
        is None
    )


def test_server_first_repeat_restores_xbox_and_exact_strategy_once():
    activity = _short_server_first_activity(read_failed=True)
    xbox_host = "repeat-xbox.example"
    tproxy._mark_xbox_dns_candidate(xbox_host, now=100.0)

    assert tproxy.note_server_first_route_close(
        xbox_host,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        activity,
        duration=0.2,
        now=100.1,
    )
    assert (
        tproxy.unknown_recovery_stage(xbox_host, now=100.2)
        == tproxy.UNKNOWN_RECOVERY_LOCAL_LADDER
    )
    xbox_repeat = tproxy._claim_server_first_repeat_stage(xbox_host, now=100.2)
    assert xbox_repeat == (tproxy.AUTO_GEPH_STAGE_XBOX_DNS, None)
    assert (
        tproxy._unknown_recovery_stage_for_attempt(
            xbox_host,
            xbox_repeat[0],
            now=100.2,
        )
        == tproxy.UNKNOWN_RECOVERY_XBOX_DNS
    )

    strategy_host = "repeat-strategy.example"
    tproxy._mark_xbox_dns_exhausted(strategy_host, now=100.0)
    repeat_name = "plain"
    repeat_stage = f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}{repeat_name}"
    assert tproxy.note_server_first_route_close(
        strategy_host,
        repeat_stage,
        activity,
        duration=0.2,
        now=100.1,
        strategy_name=repeat_name,
    )
    claimed = tproxy._claim_server_first_repeat_stage(
        strategy_host,
        now=100.2,
    )
    assert claimed == (repeat_stage, None)
    assert (
        tproxy._strategy_order_for_attempt(strategy_host, claimed[0])[0]["name"]
        == repeat_name
    )


def test_system_repeat_preserves_the_first_selected_ip():
    activity = _short_server_first_activity(read_failed=True)
    host = "system-ip-changed.example"

    assert tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        now=100.0,
        probe_ip="1.1.1.1",
        strategy_name="plain",
    )
    claim = tproxy._claim_server_first_repeat_stage(host, now=100.1)
    assert claim == (tproxy.AUTO_GEPH_STAGE_SYSTEM, "1.1.1.1")

    assert tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        now=100.2,
        probe_ip="8.8.8.8",
        strategy_name="plain",
        repeat_claimed=True,
        repeat_probe_ip=claim[1],
    )
    assert tproxy._transport_incomplete_plain_candidates[host] == (
        "1.1.1.1",
        100.2,
    )

    natural_host = "system-ip-changed-without-claim.example"
    orderly = _short_server_first_activity()
    assert not tproxy.note_server_first_route_close(
        natural_host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        orderly,
        duration=0.2,
        now=101.0,
        probe_ip="1.0.0.1",
        strategy_name="plain",
    )
    assert tproxy.note_server_first_route_close(
        natural_host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        orderly,
        duration=0.2,
        now=101.1,
        probe_ip="8.8.4.4",
        strategy_name="plain",
    )
    assert tproxy._transport_incomplete_plain_candidates[natural_host] == (
        "1.0.0.1",
        101.1,
    )


def test_downstream_write_failure_is_not_server_close_evidence():
    host = "client-cancelled.example"
    activity = _short_server_first_activity()
    activity.downstream_write_failed = True

    assert not tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        now=100.2,
    )
    assert not tproxy._xbox_dns_candidate_active(host, now=100.2)
    assert not tproxy._server_first_closes


def test_late_server_reset_does_not_advance_unknown_host():
    host = "late-reset.example"
    activity = _short_server_first_activity(
        read_failed=True,
        downstream_bytes=tproxy.SERVER_FIRST_CLOSE_MAX_BYTES + 1,
    )

    assert not tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        activity,
        duration=0.2,
        now=100.2,
    )
    assert not tproxy._xbox_dns_candidate_active(host, now=100.2)
    assert tproxy._server_first_closes


def test_large_completed_server_close_clears_provisional_evidence():
    host = "short-close.example"
    short = _short_server_first_activity()
    large = _short_server_first_activity(
        downstream_bytes=tproxy.TRANSPORT_INCOMPLETE_PROBE_MAX_BYTES + 1
    )

    assert not tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        short,
        duration=0.2,
        now=100.2,
    )
    assert tproxy._server_first_closes
    assert not tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        large,
        duration=0.2,
        now=100.3,
    )
    assert not tproxy._server_first_closes
    assert not tproxy._xbox_dns_candidate_active(host, now=100.3)


def test_slow_large_server_close_clears_provisional_evidence():
    host = "slow-large-close.example"
    large = _short_server_first_activity(downstream_bytes=128 * 1024)

    assert not tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        large,
        duration=12.0,
        now=100.2,
        probe_ip="1.1.1.1",
        strategy_name="plain",
    )
    assert tproxy._server_first_closes
    assert not tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        large,
        duration=tproxy.TRANSPORT_INCOMPLETE_AMBIGUOUS_MAX_DURATION + 0.1,
        now=100.3,
        probe_ip="1.1.1.1",
        strategy_name="plain",
    )
    assert not tproxy._server_first_closes
    assert host not in tproxy._transport_incomplete_last_probe
    assert not tproxy._xbox_dns_candidate_active(host, now=100.3)


def test_repeated_xbox_server_closes_advance_to_local_ladder():
    host = "xbox-transfer.example"
    activity = _short_server_first_activity()
    tproxy._mark_xbox_dns_candidate(host, now=100.0)

    assert not tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        activity,
        duration=0.2,
        now=100.2,
    )
    assert tproxy.note_server_first_route_close(
        host,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        activity,
        duration=0.2,
        now=100.3,
    )
    assert (
        tproxy.unknown_recovery_stage(host, now=100.3)
        == tproxy.UNKNOWN_RECOVERY_LOCAL_LADDER
    )
    assert (
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS
        in tproxy._transport_incomplete_server_first_evidence[host]
    )
    assert host not in tproxy._local_partial_stalls
    assert not tproxy.is_geo_exit_route(host)


def test_partial_stream_stall_marks_exact_xbox_dns_candidate():
    host = "crystalidea.example"
    tproxy._strat_cache[host] = "split64+fake"

    try:
        assert tproxy.note_local_stream_stall(host, "split64+fake")
        assert host not in tproxy._strat_cache
        assert tproxy._xbox_dns_candidate_active(host)
        assert not tproxy.is_geo_exit_route(host)
        assert [strategy["name"] for strategy in tproxy.strategy_order(host)][0] == "split16+fake"

        tproxy._strat_cache["updates.discord.com"] = "split64+fake"
        assert not tproxy.note_local_stream_stall("updates.discord.com", "split64+fake")
        assert tproxy._strat_cache["updates.discord.com"] == "split64+fake"
        assert not tproxy._xbox_dns_candidate_active("updates.discord.com")
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()


def test_unknown_recovery_stage_progresses_without_foreign_exit():
    host = "crystalidea.example"

    assert (
        tproxy.unknown_recovery_stage(host, now=100.0)
        == tproxy.UNKNOWN_RECOVERY_SYSTEM
    )
    assert tproxy._mark_xbox_dns_candidate(host, now=100.0)
    assert (
        tproxy.unknown_recovery_stage(host, now=100.1)
        == tproxy.UNKNOWN_RECOVERY_XBOX_DNS
    )
    assert tproxy._mark_xbox_dns_exhausted(host, now=100.2)
    assert (
        tproxy.unknown_recovery_stage(host, now=100.3)
        == tproxy.UNKNOWN_RECOVERY_LOCAL_LADDER
    )
    assert not tproxy._xbox_dns_candidate_active(host, now=100.3)
    assert tproxy.note_local_stream_stall(host, "split64+fake", now=100.4)
    assert not tproxy._xbox_dns_candidate_active(host, now=100.4)
    assert (
        tproxy.unknown_recovery_stage(host, now=100.4)
        == tproxy.UNKNOWN_RECOVERY_LOCAL_LADDER
    )
    assert not tproxy.is_geo_exit_route(host)
    assert (
        tproxy.unknown_recovery_stage("updates.discord.com", now=100.3)
        == tproxy.UNKNOWN_RECOVERY_SYSTEM
    )
    assert (
        tproxy.unknown_recovery_stage(
            "rr2---sn-ntq7yner.googlevideo.com",
            now=100.3,
        )
        == tproxy.UNKNOWN_RECOVERY_SYSTEM
    )
    assert (
        tproxy.unknown_recovery_stage(
            host,
            now=100.2 + tproxy.XBOX_DNS_ATTEMPT_TTL + 0.1,
        )
        == tproxy.UNKNOWN_RECOVERY_SYSTEM
    )


def test_repeated_clean_eof_stalls_mark_only_exact_unknown_host_for_xbox_dns():
    host = "crystalidea.example"
    activity = tproxy._RelayActivity(
        last_downstream_at=100.0,
        client_end_at=130.0,
        server_end_at=130.1,
        client_eof=True,
        client_ended_first=True,
    )
    tproxy._strat_cache[host] = "split64+fake"

    try:
        assert not tproxy.note_clean_eof_stream_stall(
            host,
            "split64+fake",
            activity,
            now=130.1,
        )
        assert not tproxy._xbox_dns_candidate_active(host, now=130.1)
        assert tproxy.note_clean_eof_stream_stall(
            host,
            "split64+fake",
            activity,
            now=130.2,
        )
        assert host not in tproxy._strat_cache
        assert not tproxy._clean_eof_stalls
        assert tproxy._xbox_dns_candidate_active(host, now=130.2)
        assert not tproxy.is_geo_exit_route(host)

        for protected in (
            "updates.discord.com",
            "rr2---sn-ntq7yner.googlevideo.com",
        ):
            assert not tproxy.note_clean_eof_stream_stall(
                protected,
                "split64+fake",
                activity,
                now=130.3,
            )
            assert not tproxy._xbox_dns_candidate_active(protected, now=130.3)
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()


def test_clean_eof_stall_requires_repeat_before_clearing_xbox_dns_retry():
    host = "crystalidea.example"
    activity = tproxy._RelayActivity(
        last_downstream_at=100.0,
        client_end_at=130.0,
        server_end_at=130.1,
        client_eof=True,
        client_ended_first=True,
    )

    try:
        tproxy._mark_xbox_dns_candidate(host, now=130.0)
        assert not tproxy.note_clean_eof_stream_stall(
            host,
            "plain",
            activity,
            via_xbox_dns=True,
            now=130.1,
        )
        assert tproxy._xbox_dns_candidate_active(host, now=130.1)
        assert tproxy.note_clean_eof_stream_stall(
            host,
            "plain",
            activity,
            via_xbox_dns=True,
            now=130.2,
        )
        assert not tproxy._xbox_dns_candidate_active(host, now=130.2)
        assert tproxy._xbox_dns_attempted_recently(host, now=130.2)
        assert (
            tproxy.unknown_recovery_stage(host, now=130.2)
            == tproxy.UNKNOWN_RECOVERY_LOCAL_LADDER
        )
        assert not tproxy.is_geo_exit_route(host)
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()


def test_xbox_dns_fallback_uses_plain_tls_for_unknown_host(monkeypatch):
    calls = []

    async def resolve(host):
        assert host == "payments.example.com"
        return ["203.0.113.42"]

    async def dial(ip, port, head, body, host, strategy):
        calls.append((ip, port, host, strategy["name"], strategy["fake"]))
        return ("reader", "writer", b"server-first")

    monkeypatch.setattr(tproxy, "xbox_dns_resolve_async", resolve)
    monkeypatch.setattr(tproxy, "dial_strategy", dial)

    result = asyncio.run(
        tproxy._try_xbox_dns_local_connect(
            "payments.example.com",
            443,
            b"head",
            b"body",
        )
    )

    assert result == ("203.0.113.42", ("reader", "writer", b"server-first"))
    assert calls == [("203.0.113.42", 443, "payments.example.com", "plain", False)]
    assert not tproxy._xbox_dns_attempted_recently("payments.example.com")


def test_xbox_dns_fallback_excludes_discord_and_youtube(monkeypatch):
    calls = []

    async def resolve(host):
        calls.append(host)
        return ["203.0.113.42"]

    monkeypatch.setattr(tproxy, "xbox_dns_resolve_async", resolve)

    assert asyncio.run(
        tproxy._try_xbox_dns_local_connect("updates.discord.com", 443, b"head", b"body")
    ) is None
    assert asyncio.run(
        tproxy._try_xbox_dns_local_connect(
            "rr2---sn-ntq7yner.googlevideo.com", 443, b"head", b"body"
        )
    ) is None
    assert calls == []


def test_unknown_stalls_use_xbox_dns_without_foreign_exit():
    host = "payments.example.com"
    confirmations = []

    for index in range(tproxy.AUTO_GEPH_STORM):
        tproxy.note_local_result(
            host,
            down_bytes=100,
            duration=tproxy.AUTO_GEPH_HANG + 1,
            now=100.0 + index,
            confirmation_runner=lambda value: confirmations.append(value),
        )

    assert confirmations == []
    assert tproxy._xbox_dns_candidate_active(host, now=103.0)

    tproxy._xbox_dns_attempts[host] = 1_000.0
    tproxy.note_local_result(
        host,
        down_bytes=100,
        duration=tproxy.AUTO_GEPH_HANG + 1,
        now=103.0,
        confirmation_runner=lambda value: confirmations.append(value),
    )

    assert confirmations == []
    assert not tproxy.is_geo_exit_route(host)


def test_low_content_stall_schedules_xbox_dns_without_geph(monkeypatch):
    host = "payments.example.com"

    monkeypatch.setattr(tproxy, "_geph_up", False)
    for index in range(tproxy.AUTO_GEPH_STORM):
        tproxy.note_local_result(
            host,
            down_bytes=100,
            duration=tproxy.AUTO_GEPH_HANG + 1,
            now=100.0 + index,
        )

    assert tproxy._xbox_dns_candidate_active(host, now=103.0)
    assert not tproxy.is_geo_exit_route(host)


def test_distinct_local_partial_stalls_schedule_owned_geph_confirmation(monkeypatch):
    confirmations = []
    host = "payments.example.com"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    assert not tproxy.note_partial_tls_stall(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        now=100.0,
        confirmation_runner=confirmations.append,
    )
    assert not tproxy.note_partial_tls_stall(
        host,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        now=101.0,
        confirmation_runner=confirmations.append,
    )
    assert not tproxy.note_local_ladder_partial_stall(
        host,
        "split64+fake",
        now=102.0,
        confirmation_runner=confirmations.append,
    )
    assert tproxy.note_local_ladder_partial_stall(
        host,
        "split16+fake",
        now=103.0,
        confirmation_runner=confirmations.append,
    )

    assert confirmations == [host]
    assert not tproxy.is_geo_exit_route(host)
    assert not tproxy._auto_geph
    assert tproxy._auto_geph_candidates[host] > 101.0


def test_exact_system_partial_tls_stall_waits_for_full_local_ladder(
    monkeypatch,
):
    confirmations = []
    host = "partial-body.example.com"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    assert not tproxy.note_partial_tls_stall(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        now=100.0,
        probe_ip="1.1.1.1",
        strategy_name="plain",
        transport_confirmation_runner=(
            lambda candidate, ip: confirmations.append((candidate, ip))
        ),
    )

    assert confirmations == []
    assert tproxy._transport_incomplete_plain_candidates[host][0] == "1.1.1.1"
    assert not tproxy.note_partial_tls_stall(
        host,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        now=101.0,
        transport_confirmation_runner=(
            lambda candidate, ip: confirmations.append((candidate, ip))
        ),
    )
    assert not tproxy.note_partial_tls_stall(
        host,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake",
        now=102.0,
        transport_confirmation_runner=(
            lambda candidate, ip: confirmations.append((candidate, ip))
        ),
    )
    assert tproxy.note_partial_tls_stall(
        host,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake",
        now=103.0,
        transport_confirmation_runner=(
            lambda candidate, ip: confirmations.append((candidate, ip))
        ),
    )

    assert confirmations == [(host, "1.1.1.1")]
    assert not tproxy.is_geo_exit_route(host)
    assert host not in tproxy._auto_geph


def test_partial_tls_content_confirmation_excludes_non_system_routes(
    monkeypatch,
):
    confirmations = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for host, stage, strategy in (
        ("updates.discord.com", tproxy.AUTO_GEPH_STAGE_SYSTEM, "plain"),
        ("partial-body.example.com", tproxy.AUTO_GEPH_STAGE_XBOX_DNS, "plain"),
        ("partial-body.example.com", tproxy.AUTO_GEPH_STAGE_SYSTEM, "split16+fake"),
    ):
        assert not tproxy.note_partial_tls_stall(
            host,
            stage,
            now=100.0,
            probe_ip="1.1.1.1",
            strategy_name=strategy,
            transport_confirmation_runner=(
                lambda candidate, ip: confirmations.append((candidate, ip))
            ),
        )

    assert confirmations == []


def test_local_strategy_stalls_without_system_and_xbox_proof_do_not_confirm(
    monkeypatch,
):
    confirmations = []
    host = "payments.example.com"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    assert not tproxy.note_local_ladder_partial_stall(
        host,
        "split64+fake",
        now=100.0,
        confirmation_runner=confirmations.append,
    )
    assert not tproxy.note_local_ladder_partial_stall(
        host,
        "split16+fake",
        now=101.0,
        confirmation_runner=confirmations.append,
    )

    assert confirmations == []
    assert host not in tproxy._auto_geph_candidates


def test_zero_payload_route_exhaustion_requires_all_local_stages(monkeypatch):
    host = "foreign-exit-candidate.example"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    assert not tproxy.note_zero_payload_route_failure(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        now=100.0,
    )
    assert not tproxy.note_zero_payload_route_failure(
        host,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        now=101.0,
    )
    assert not tproxy.note_zero_payload_route_failure(
        host,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake",
        now=102.0,
    )
    assert tproxy.note_zero_payload_route_failure(
        host,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake",
        now=103.0,
    )
    assert tproxy._auto_geph_candidate_allowed(host, now=104.0)
    assert not tproxy._auto_geph_one_shot_request_proven(host, now=104.0)


def test_network_wide_zero_payload_failures_do_not_authorize_geph(monkeypatch):
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    stages = (
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake",
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake",
    )

    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        host = f"network-wide-{index}.example"
        for offset, stage in enumerate(stages):
            tproxy.note_zero_payload_route_failure(
                host,
                stage,
                now=100.0 + offset,
            )

    last_host = f"network-wide-{tproxy.AUTO_GEPH_NET_BAD - 1}.example"
    first_host = "network-wide-0.example"
    assert not tproxy._auto_geph_candidate_allowed(last_host, now=105.0)
    assert tproxy._auto_geph_one_shot_request_proven(last_host, now=105.0)
    assert first_host not in tproxy._auto_geph_candidates
    assert not tproxy._auto_geph_candidate_allowed(first_host, now=105.0)
    assert tproxy._auto_geph_one_shot_request_proven(first_host, now=105.0)


def test_one_shot_unknown_rescue_excludes_protected_local_hosts(monkeypatch):
    now = 100.0
    stages = {
        tproxy.AUTO_GEPH_STAGE_SYSTEM: now,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS: now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake": now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake": now,
    }
    protected_hosts = (
        "gateway.discord.gg",
        "www.youtube.com",
        "rr2---sn-test.googlevideo.com",
    )
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        tproxy._local_zero_payload_failures[
            f"network-noise-{index}.example"
        ] = {tproxy.AUTO_GEPH_STAGE_SYSTEM: now}
    for host in protected_hosts:
        tproxy._local_zero_payload_failures[host] = dict(stages)

    for host in protected_hosts:
        assert not tproxy._auto_geph_one_shot_request_proven(host, now=now)


def test_network_noise_blocks_background_geph_confirmation(monkeypatch):
    host = "candidate-before-noise.example"
    now = tproxy.time.monotonic()
    tproxy._auto_geph_candidates[host] = now + 60.0
    stages = (
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake",
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake",
    )

    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        noisy_host = f"background-noise-{index}.example"
        for offset, stage in enumerate(stages):
            tproxy.note_zero_payload_route_failure(
                noisy_host,
                stage,
                now=now + offset / 100.0,
            )

    monkeypatch.setattr(
        tproxy,
        "_auto_geph_payload_probe",
        lambda _host: pytest.fail("background confirmation must not probe"),
    )

    assert not tproxy._confirm_auto_geph(host)
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert tproxy._auto_geph_last_status["state"] == "skipped"


def test_one_shot_unknown_rescue_requires_a_full_fresh_proof_after_claim(
    monkeypatch,
):
    host = "fresh-proof-after-claim.example"
    stages = (
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake",
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake",
    )
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    for index in range(tproxy.AUTO_GEPH_NET_BAD - 1):
        tproxy._local_zero_payload_failures[
            f"claim-noise-{index}.example"
        ] = {tproxy.AUTO_GEPH_STAGE_SYSTEM: 100.0}
    tproxy._local_zero_payload_failures[host] = {
        stage: 100.0 + offset for offset, stage in enumerate(stages)
    }

    assert tproxy._claim_auto_geph_one_shot_request(host, now=104.0)
    assert not tproxy._claim_auto_geph_one_shot_request(host, now=104.0)
    for offset, stage in enumerate(stages[:-1]):
        tproxy._local_zero_payload_failures[host][stage] = 110.0 + offset
    assert not tproxy._auto_geph_one_shot_request_proven(host, now=113.0)
    tproxy._local_zero_payload_failures[host][stages[-1]] = 113.0
    assert tproxy._auto_geph_one_shot_request_proven(host, now=113.0)


def test_one_shot_consumption_watermarks_are_ttl_and_size_bounded():
    now = 100.0
    for index in range(tproxy.AUTO_GEPH_STATE_MAX + 1):
        tproxy._auto_geph_one_shot_consumed_at[
            f"bounded-watermark-{index}.example"
        ] = now

    tproxy._prune_local_zero_payload_failures(now)

    assert len(tproxy._auto_geph_one_shot_consumed_at) == tproxy.AUTO_GEPH_STATE_MAX
    assert "bounded-watermark-0.example" not in (
        tproxy._auto_geph_one_shot_consumed_at
    )

    tproxy._prune_local_zero_payload_failures(
        now + tproxy.AUTO_GEPH_ZERO_PAYLOAD_WINDOW + 1.0
    )
    assert tproxy._auto_geph_one_shot_consumed_at == {}


def test_auto_geph_confirmation_learns_only_proven_exact_unknown_host(
    monkeypatch,
    tmp_path,
):
    probes = []
    host = "payments.example.com"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: 4242)
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        tproxy,
        "_AUTO_GEPH_PATH",
        str(tmp_path / "autogeph.json"),
    )
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_payload_probe",
        lambda host: probes.append(host) or 128,
    )
    monkeypatch.setattr(
        tproxy,
        "_geph_backend_hold_until",
        tproxy.time.time() + 30.0,
    )
    monkeypatch.setattr(tproxy, "_geph_backend_hold_reason", "earlier payload miss")
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() + 60.0

    assert tproxy._confirm_auto_geph(host)
    assert probes == [host, host]
    assert tproxy._auto_geph_learned_exact_host(host)
    assert tproxy.runtime_route_policy(host)["route_class"] == tproxy.ROUTE_GEO_EXIT
    assert tproxy.route_policy(host)["route_class"] == tproxy.ROUTE_UNKNOWN
    snap = tproxy.auto_geo_exit_status_snapshot()
    assert snap["enabled"] is True
    assert snap["last_state"] == "learned"
    assert tproxy._auto_geph_last_status["reason"] == "stable Geph payload confirmed"
    assert snap["learned"] == 1
    assert tproxy._geph_backend_hold_until == 0.0
    assert tproxy._geph_backend_hold_reason == ""


def test_auto_geph_failed_payload_keeps_backend_hold(monkeypatch, tmp_path):
    host = "still-unhealthy.example.com"
    hold_until = tproxy.time.time() + 30.0
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", hold_until)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_reason", "payload miss")
    monkeypatch.setattr(
        tproxy,
        "_AUTO_GEPH_PATH",
        str(tmp_path / "autogeph.json"),
    )
    monkeypatch.setattr(tproxy, "_auto_geph_payload_probe", lambda _host: 0)
    monkeypatch.setattr(tproxy, "_geph_listener_pid", lambda _port: None)
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() + 60.0

    assert not tproxy._confirm_auto_geph(host)
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert tproxy._geph_backend_hold_until == hold_until
    assert tproxy._geph_backend_hold_reason == "payload miss"


def test_auto_geph_confirmation_replaces_owned_exit_when_second_probe_is_limited(
    monkeypatch,
    tmp_path,
):
    host = "unstable-exit.example.com"
    probes = iter([512, 0, 1024, 1024])
    listener_pid = {"value": 100}
    events = []
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"last_requested_at": 0.0, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(
        tproxy,
        "_AUTO_GEPH_PATH",
        str(tmp_path / "autogeph.json"),
    )
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_payload_probe",
        lambda candidate: next(probes) if candidate == host else 0,
    )
    monkeypatch.setattr(
        tproxy,
        "_geph_listener_pid",
        lambda _port: listener_pid["value"],
    )
    monkeypatch.setattr(
        tproxy,
        "geph_listener_owned",
        lambda _port, **kwargs: kwargs.get(
            "listener_pid",
            listener_pid["value"],
        )
        == listener_pid["value"],
    )
    monkeypatch.setattr(
        tproxy,
        "_begin_geph_restart_drain",
        lambda: events.append(("begin",)) or True,
    )
    monkeypatch.setattr(
        tproxy,
        "request_owned_geph_restart",
        lambda candidate, reason, **_kwargs: (
            events.append(("request", candidate, reason)) or True
        ),
    )
    def restart(**kwargs):
        events.append(("restart", kwargs.get("active_sessions")))
        listener_pid["value"] = 101
        return "restarted"

    monkeypatch.setattr(tproxy, "execute_owned_geph_restart", restart)
    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_payload_ready",
        lambda _expected_pid=None: "ready",
    )
    monkeypatch.setattr(tproxy, "_probe_owned_geph_recovery_state", lambda: "ready")
    monkeypatch.setattr(
        tproxy,
        "_finish_geph_restart_drain",
        lambda: events.append(("finish",)),
    )
    tproxy._auto_geph_candidates[host] = tproxy.time.monotonic() + 60.0
    tproxy._auto_geph_confirming[host] = tproxy.time.monotonic()
    tproxy._auto_geph_confirmation_tokens[host] = object()

    assert tproxy._confirm_auto_geph(host)
    assert tproxy._auto_geph_learned_exact_host(host)
    assert events == [
        ("begin",),
        ("request", host, "payload probe failed"),
        ("restart", 0),
        ("finish",),
    ]
    with pytest.raises(StopIteration):
        next(probes)


def test_load_auto_geph_keeps_only_fresh_unknown_exact_hosts(tmp_path, monkeypatch):
    path = tmp_path / "autogeph.json"
    path.write_text(json.dumps({
        "payments.example.com": tproxy.time.time() + 3600,
        "www.google.com": tproxy.time.time() + 3600,
        "expired.example.com": tproxy.time.time() - 1,
    }))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(path))
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    tproxy.load_auto_geph()

    assert set(tproxy._auto_geph) == {"payments.example.com"}
    assert set(json.loads(path.read_text())) == {"payments.example.com"}
    assert path.stat().st_mode & 0o777 == 0o600
    assert not tproxy.is_geo_exit_route("payments.example.com")
    assert (
        tproxy.runtime_route_policy("payments.example.com")["route_class"]
        == tproxy.ROUTE_GEO_EXIT
    )


def test_network_wide_unknown_stalls_do_not_schedule_foreign_exit(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "_geph_up", True)

    cutoff_base = 100.0
    for idx in range(tproxy.AUTO_GEPH_NET_BAD):
        tproxy._auto_fail[f"noisy-{idx}.example.com"] = [cutoff_base, cutoff_base + 1]

    for idx in range(tproxy.AUTO_GEPH_STORM):
        tproxy.note_local_result(
            "payments.example.com",
            down_bytes=100,
            duration=tproxy.AUTO_GEPH_HANG + 1,
            now=cutoff_base + 2 + idx,
            confirmation_runner=lambda host: calls.append(host),
        )

    assert calls == []
    assert not tproxy.is_geo_exit_route("payments.example.com")


def test_network_wide_partial_stalls_do_not_schedule_foreign_exit(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    now = 100.0

    for idx in range(tproxy.AUTO_GEPH_NET_BAD - 1):
        host = f"noisy-{idx}.example.com"
        tproxy._local_partial_stalls[host] = {
            tproxy.AUTO_GEPH_STAGE_SYSTEM: now,
            tproxy.AUTO_GEPH_STAGE_XBOX_DNS: now,
            f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake": now,
            f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake": now,
        }
    host = "payments.example.com"
    tproxy.note_partial_tls_stall(
        host,
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        now=now,
    )
    tproxy.note_partial_tls_stall(
        host,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        now=now,
    )
    tproxy.note_local_ladder_partial_stall(
        host,
        "split64+fake",
        now=now,
        confirmation_runner=calls.append,
    )
    assert not tproxy.note_local_ladder_partial_stall(
        host,
        "split16+fake",
        now=now + 1,
        confirmation_runner=calls.append,
    )

    assert calls == []
    assert host not in tproxy._auto_geph_candidates


def test_prune_auto_geph_keeps_fresh_unknown_exact_hosts(monkeypatch):
    saves = []
    tproxy._auto_geph["old.example.com"] = 100.0
    tproxy._auto_geph["fresh.example.com"] = 300.0
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: saves.append(True))

    snap = tproxy.auto_geo_exit_status_snapshot(now=200.0)

    assert tproxy._auto_geph == {"fresh.example.com": 300.0}
    assert snap["learned"] == 1
    assert saves


def test_local_bypass_resolution_uses_system_dns_when_doh_is_empty(monkeypatch):
    async def empty_doh(host):
        return []

    async def system(host):
        return ["162.159.136.232", "162.159.138.232"]

    monkeypatch.setattr(tproxy, "doh_resolve_async", empty_doh)
    monkeypatch.setattr(tproxy, "system_resolve_async", system)

    ips = asyncio.run(tproxy.resolve_connection_ips("updates.discord.com", "162.159.136.232"))

    assert ips == ["162.159.136.232", "162.159.138.232"]
    assert tproxy.ip_attempt_limit("updates.discord.com") == 4


def test_local_bypass_resolution_keeps_system_dns_even_when_doh_has_results(monkeypatch):
    async def doh(host):
        return ["162.159.128.233"]

    async def system(host):
        return ["162.159.136.232", "162.159.138.232"]

    monkeypatch.setattr(tproxy, "doh_resolve_async", doh)
    monkeypatch.setattr(tproxy, "system_resolve_async", system)

    ips = asyncio.run(tproxy.resolve_connection_ips("gateway.discord.gg", "162.159.136.232"))

    assert ips == ["162.159.128.233", "162.159.136.232", "162.159.138.232"]


def test_fake_injector_uses_discord_decoy_without_changing_video_poison(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "inject_fake_decoy", lambda *args: calls.append("decoy"))
    monkeypatch.setattr(tproxy, "inject_fake_poison", lambda *args: calls.append("poison"))

    tproxy.inject_fake_for_host("gateway.discord.gg", "127.0.0.1", 50000, "203.0.113.10", 443)
    tproxy.inject_fake_for_host("rr2---sn-ntq7yner.googlevideo.com", "127.0.0.1", 50001, "203.0.113.11", 443)

    assert calls == ["decoy", "poison"]


def test_voice_flow_observe_caps_count_and_keeps_recent_flow():
    flows = OrderedDict()
    key = ("10.0.0.2", 50000, "203.0.113.10", 50001)

    for index in range(tproxy.VOICE_CUTOFF):
        should_prime, count = tproxy.observe_voice_flow(flows, key, now=float(index))
        assert should_prime
        assert count == index

    should_prime, count = tproxy.observe_voice_flow(flows, key, now=99.0)

    assert not should_prime
    assert count == tproxy.VOICE_CUTOFF
    assert flows[key] == (tproxy.VOICE_CUTOFF, 99.0)


def test_voice_flow_prune_expires_idle_entries():
    flows = OrderedDict([
        ("old", (1, 0.0)),
        ("fresh", (1, 200.0)),
    ])

    tproxy.prune_voice_flows(flows, now=400.0, idle_ttl=250.0)

    assert list(flows) == ["fresh"]


def test_voice_flow_prune_evicts_lru_overflow_without_full_clear():
    flows = OrderedDict([
        ("oldest", (1, 100.0)),
        ("middle", (1, 101.0)),
        ("newest", (1, 102.0)),
    ])

    tproxy.prune_voice_flows(flows, now=110.0, max_flows=2, idle_ttl=999.0)

    assert list(flows) == ["middle", "newest"]


def test_voice_bpf_includes_discord_setup_and_primary_ranges():
    bpf = tproxy._voice_bpf("10.0.0.2")

    assert "dst portrange 19294-19344" in bpf
    assert "dst portrange 50000-65535" in bpf
    assert "(dst portrange 19294-19344 or dst portrange 50000-65535)" in bpf


def test_voice_payload_gate_preserves_existing_primary_range():
    assert tproxy.should_prime_voice_payload(50000, b"unclassified")
    assert tproxy.should_prime_voice_payload(65535, b"")


def test_voice_payload_gate_requires_known_setup_payload_on_setup_range():
    assert tproxy.should_prime_voice_payload(19294, tproxy._fake_stun())
    assert tproxy.should_prime_voice_payload(19344, b"\x80\x78" + (b"\x00" * 10))

    assert not tproxy.should_prime_voice_payload(19294, b"unclassified")
    assert not tproxy.should_prime_voice_payload(19345, tproxy._fake_stun())


def test_rotating_log_writer_keeps_bounded_archives(tmp_path):
    log = tmp_path / "slipstream.log"
    writer = tproxy.RotatingLogWriter(str(log), max_bytes=10, backups=2)

    writer.write("123456789\n")
    writer.write("abcdefghi\n")
    writer.write("XYZ\n")
    writer.flush()

    assert log.read_text() == "XYZ\n"
    assert (tmp_path / "slipstream.log.1").read_text() == "abcdefghi\n"
    assert (tmp_path / "slipstream.log.2").read_text() == "123456789\n"
    assert not (tmp_path / "slipstream.log.3").exists()
    assert log.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "slipstream.log.1").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "slipstream.log.2").stat().st_mode & 0o777 == 0o600


def test_rotating_log_writer_rotates_oversized_existing_log(tmp_path):
    log = tmp_path / "slipstream.log"
    log.write_text("already too large\n")

    writer = tproxy.RotatingLogWriter(str(log), max_bytes=10, backups=2)
    writer.write("fresh\n")
    writer.flush()

    assert log.read_text() == "fresh\n"
    assert (tmp_path / "slipstream.log.1").read_text() == "already too large\n"


def test_rotating_log_writer_migrates_existing_log_and_archives_to_owner_only(tmp_path):
    log = tmp_path / "slipstream.log"
    archive = tmp_path / "slipstream.log.1"
    log.write_text("current\n")
    archive.write_text("previous\n")
    log.chmod(0o644)
    archive.chmod(0o640)

    writer = tproxy.RotatingLogWriter(str(log), max_bytes=1024, backups=2)
    writer.flush()

    assert log.stat().st_mode & 0o777 == 0o600
    assert archive.stat().st_mode & 0o777 == 0o600


def test_rotating_log_writer_refuses_symlink_log_path(tmp_path):
    target = tmp_path / "target"
    target.write_text("leave me alone\n")
    target.chmod(0o644)
    log = tmp_path / "slipstream.log"
    log.symlink_to(target)

    with pytest.raises(OSError):
        tproxy.RotatingLogWriter(str(log), max_bytes=1024, backups=1)

    assert target.read_text() == "leave me alone\n"
    assert target.stat().st_mode & 0o777 == 0o644


def test_harden_existing_log_tolerates_archive_rotation_race(monkeypatch):
    monkeypatch.setattr(tproxy.os.path, "lexists", lambda _path: True)

    def vanished(_path, _flags):
        raise FileNotFoundError

    monkeypatch.setattr(tproxy.os, "open", vanished)

    assert not tproxy._harden_existing_log("/var/log/slipstream.log.1")


def test_rotating_log_writer_can_prefix_timestamps(tmp_path):
    log = tmp_path / "slipstream.log"
    writer = tproxy.RotatingLogWriter(
        str(log),
        max_bytes=1024,
        backups=1,
        timestamp=True,
        clock=lambda: 1783512000.0,
    )

    writer.write("alpha")
    writer.write("\n")
    writer.write("beta")
    writer.write(" continued\n")
    writer.flush()

    lines = log.read_text().splitlines()
    assert len(lines) == 2
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4} alpha$", lines[0])
    assert re.match(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4} beta continued$",
        lines[1],
    )


def test_remove_obsolete_newsyslog_config(monkeypatch, tmp_path):
    conf = tmp_path / "dev.slipstream.tproxy.conf"
    conf.write_text("obsolete\n")
    monkeypatch.setattr(tproxy, "OBSOLETE_NEWSYSLOG_CONFIG_PATH", str(conf))

    tproxy.remove_obsolete_newsyslog_config()
    tproxy.remove_obsolete_newsyslog_config()

    assert not conf.exists()


def test_launchd_delegates_raw_log_creation_to_private_writer():
    raw = tproxy.launchd_plist_text(
        ["/usr/local/slipstream/slipstreamd", "--port", "1080"],
        "/usr/local/slipstream",
    )
    plist = plistlib.loads(raw.encode())

    assert plist["StandardOutPath"] == "/dev/null"
    assert plist["StandardErrorPath"] == "/dev/null"
    assert plist["ProgramArguments"] == [
        "/usr/local/slipstream/slipstreamd",
        "--port",
        "1080",
    ]


def test_packaged_install_pins_its_exact_tray_worker_in_launchd(tmp_path):
    contents = tmp_path / "Slipstream & Test.app" / "Contents"
    daemon = contents / "Resources" / "slipstreamd" / "slipstreamd"
    worker = contents / "MacOS" / "slipstream"
    daemon.parent.mkdir(parents=True)
    worker.parent.mkdir(parents=True)
    daemon.write_bytes(b"daemon")
    worker.write_bytes(b"worker")
    daemon.chmod(0o755)
    worker.chmod(0o755)

    resolved = tproxy._packaged_browser_worker_executable(daemon)
    raw = tproxy.launchd_plist_text(
        ["/usr/local/slipstream/slipstreamd", "--port", "1080"],
        "/usr/local/slipstream",
        browser_worker=resolved,
    )
    plist = plistlib.loads(raw.encode())

    assert resolved == str(worker)
    assert plist["EnvironmentVariables"][
        "SLIPSTREAM_PENDING_NAVIGATION_BROWSER_WORKER"
    ] == str(worker)


def test_packaged_worker_resolver_rejects_writable_or_wrong_layout(tmp_path):
    worker = tmp_path / "Contents" / "MacOS" / "slipstream"
    worker.parent.mkdir(parents=True)
    worker.write_bytes(b"worker")
    worker.chmod(0o755)

    assert tproxy._packaged_browser_worker_executable(
        tmp_path / "Contents" / "Resources" / "wrong" / "slipstreamd"
    ) is None

    daemon = (
        tmp_path
        / "Contents"
        / "Resources"
        / "slipstreamd"
        / "slipstreamd"
    )
    daemon.parent.mkdir(parents=True)
    daemon.write_bytes(b"daemon")
    daemon.chmod(0o755)
    worker.chmod(0o777)
    assert tproxy._packaged_browser_worker_executable(daemon) is None


def test_uninstaller_recovers_only_root_owned_launchd_worker_pin(
    monkeypatch,
    tmp_path,
):
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    installed_daemon = install_dir / os.path.basename(sys.executable)
    worker = tmp_path / "Slipstream.app" / "Contents" / "MacOS" / "slipstream"
    worker.parent.mkdir(parents=True)
    launchd = tmp_path / "dev.slipstream.tproxy.plist"
    launchd.write_text(tproxy.launchd_plist_text(
        [str(installed_daemon), "--port", str(tproxy.PROXY_PORT)],
        install_dir,
        browser_worker=worker,
    ))
    launchd.chmod(0o644)
    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install_dir))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(launchd))

    assert tproxy._installed_browser_worker_from_launchd(
        expected_uid=os.getuid()
    ) == str(worker)

    malformed = plistlib.loads(launchd.read_bytes())
    malformed["ProgramArguments"].insert(1, "--unexpected")
    launchd.write_bytes(plistlib.dumps(malformed))
    assert tproxy._installed_browser_worker_from_launchd(
        expected_uid=os.getuid()
    ) is None

    malformed["ProgramArguments"].remove("--unexpected")
    malformed["WorkingDirectory"] = 7
    launchd.write_bytes(plistlib.dumps(malformed))
    assert tproxy._installed_browser_worker_from_launchd(
        expected_uid=os.getuid()
    ) is None

    launchd.write_text(tproxy.launchd_plist_text(
        [str(installed_daemon), "--port", str(tproxy.PROXY_PORT)],
        install_dir,
        browser_worker=worker,
    ))

    launchd.chmod(0o666)
    assert tproxy._installed_browser_worker_from_launchd(
        expected_uid=os.getuid()
    ) is None

    launchd.unlink()
    launchd.symlink_to(tmp_path / "missing")
    assert tproxy._installed_browser_worker_from_launchd(
        expected_uid=os.getuid()
    ) is None

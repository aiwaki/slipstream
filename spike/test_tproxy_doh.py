import asyncio
import ast
import base64
import errno
import hashlib
import inspect
import json
import logging
import plistlib
import re
import signal
import ssl
import sys
from pathlib import Path
from types import SimpleNamespace
from collections import OrderedDict, deque

import pytest
import tproxy
from tproxy import _doh_request, _doh_ssl_context


@pytest.fixture(autouse=True)
def reset_smart_dns_state():
    dns_cache = dict(tproxy._system_dns_cache)
    smart_ok = dict(tproxy._smart_dns_ok_until)
    smart_failure = dict(tproxy._smart_dns_last_failure)
    auto_fail = {host: list(values) for host, values in tproxy._auto_fail.items()}
    auto_geph = dict(tproxy._auto_geph)
    auto_confirming = dict(tproxy._auto_geph_confirming)
    auto_last_probe = dict(tproxy._auto_geph_last_probe)
    auto_runtime_failures = {
        host: list(values)
        for host, values in tproxy._auto_geph_runtime_failures.items()
    }
    xbox_dns_candidates = dict(tproxy._xbox_dns_candidates)
    xbox_dns_attempts = dict(tproxy._xbox_dns_attempts)
    clean_eof_stalls = {
        host: deque(values) for host, values in tproxy._clean_eof_stalls.items()
    }
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
    try:
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
        tproxy._auto_geph_last_probe.clear()
        tproxy._auto_geph_runtime_failures.clear()
        tproxy._xbox_dns_candidates.clear()
        tproxy._xbox_dns_attempts.clear()
        tproxy._clean_eof_stalls.clear()
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
        yield
    finally:
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
        tproxy._auto_geph_last_probe.clear()
        tproxy._auto_geph_last_probe.update(auto_last_probe)
        tproxy._auto_geph_runtime_failures.clear()
        tproxy._auto_geph_runtime_failures.update(auto_runtime_failures)
        tproxy._xbox_dns_candidates.clear()
        tproxy._xbox_dns_candidates.update(xbox_dns_candidates)
        tproxy._xbox_dns_attempts.clear()
        tproxy._xbox_dns_attempts.update(xbox_dns_attempts)
        tproxy._clean_eof_stalls.clear()
        tproxy._clean_eof_stalls.update(clean_eof_stalls)
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
    "address_attempts.py": "VALUE = 1\n",
    "connection_probe.py": "VALUE = 2\n",
    "connection_race.py": "VALUE = 3\n",
    "connection_race_io.py": "VALUE = 4\n",
    "geph_backend.py": "VALUE = 5\n",
    "pf_adapter.py": "VALUE = 6\n",
    "primes.py": "VALUE = 7\n",
    "route_circuit.py": "VALUE = 8\n",
    "routing_policy.py": "VALUE = 9\n",
    "routing_recovery.py": "VALUE = 10\n",
    "xbox_dns.py": "VALUE = 11\n",
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
        "route_circuit.py",
    ),
)
def test_copy_script_runtime_requires_connection_race_closure(tmp_path, missing):
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
    for path in (plist, status, tgws_link, strategy):
        path.write_text("state")

    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(install))
    monkeypatch.setattr(tproxy, "LAUNCHD_PLIST", str(plist))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status))
    monkeypatch.setattr(tproxy, "TGWS_LINK_PATH", str(tgws_link))
    monkeypatch.setattr(tproxy, "_STRAT_PATH", str(strategy))
    commands = []

    def fake_run(*args):
        commands.append(args)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "_pf_flush", lambda: SimpleNamespace(returncode=0))
    monkeypatch.setattr(tproxy, "_pf_release_enable_token", lambda: None)
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda: None)
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)

    assert tproxy.do_uninstall()

    assert not install.exists()
    assert not plist.exists()
    assert not status.exists()
    assert not tgws_link.exists()
    assert not strategy.exists()
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
    monkeypatch.setattr(
        tproxy,
        "_run",
        lambda *_args: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(tproxy, "_owned_listener_pids", lambda _port: [4242])
    monkeypatch.setattr(
        tproxy,
        "_stop_owned_daemon_pid",
        lambda pid: stopped.append(pid) or True,
    )
    monkeypatch.setattr(tproxy, "_pf_flush", lambda: SimpleNamespace(returncode=0))
    monkeypatch.setattr(tproxy, "_pf_release_enable_token", lambda: None)
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda: None)
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)

    assert tproxy.do_uninstall()
    assert stopped == [4242]


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
    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "ensure_private_log_files", lambda: None)
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
    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "ensure_private_log_files", lambda: None)
    monkeypatch.setattr(tproxy, "remove_obsolete_newsyslog_config", lambda: None)
    monkeypatch.setattr(tproxy, "_wait_for_listener_state", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(tproxy, "_wait_for_installed_daemon", lambda *_args, **_kwargs: True)

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
    monkeypatch.setattr(tproxy, "system_resolve", lambda host: ["142.250.186.46"])
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
    assert auto_geo_exit["enabled"] is False
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
        "resolution_state": "ok",
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
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_pf_interceptor_conflicts", [])

    assert not tproxy.pf_setup(1080)
    assert calls == []
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


def test_pf_load_targets_only_private_anchor(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        if args[:4] == ("pfctl", "-a", tproxy.PF_ANCHOR, "-f"):
            rules = open(args[4]).read()
            assert "proto tcp" in rules
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

    def fake_run(*args):
        calls.append(args)
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))
    monkeypatch.setattr(tproxy, "_remove_pf_token", lambda path=None: None)
    monkeypatch.setattr(tproxy, "_pf_enable_token", "123456")
    monkeypatch.setattr(tproxy, "_pf_applied", True)

    tproxy.pf_teardown()

    assert ("pfctl", "-a", tproxy.PF_ANCHOR, "-F", "rules") in calls
    assert ("pfctl", "-a", tproxy.PF_ANCHOR, "-F", "nat") in calls
    assert ("pfctl", "-X", "123456") in calls
    assert not any("states" in args or "all" in args for args in calls)
    assert not any(args[:3] == ("pfctl", "-f", "/etc/pf.conf") for args in calls)
    assert not any(args[:2] == ("pfctl", "-d") for args in calls)
    assert not status_path.exists()


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


def test_legacy_pf_restore_is_explicit_and_preserves_config_source(monkeypatch):
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

    assert tproxy._restore_legacy_pf_rules(1080)
    assert calls[-1] == ("pfctl", "-f", tproxy.PF_CONFIG_PATH)


def test_legacy_pf_restore_ignores_unrelated_route_to_rule(monkeypatch):
    def fake_run(*args):
        if args == ("pfctl", "-sn"):
            stdout = "rdr pass proto tcp to any port = 80 -> 127.0.0.1 port 1080\n"
        elif args == ("pfctl", "-sr"):
            stdout = "pass out route-to (lo0 127.0.0.1) proto tcp to any port = 80\n"
        else:
            raise AssertionError(args)
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    monkeypatch.setattr(tproxy, "_run", fake_run)

    assert not tproxy._restore_legacy_pf_rules(1080)


def test_legacy_pf_restore_never_reloads_over_live_private_anchor(monkeypatch):
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

    assert not tproxy._restore_legacy_pf_rules(1080)
    assert not any(args[:3] == ("pfctl", "-f", tproxy.PF_CONFIG_PATH) for args in calls)


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


def test_pf_startup_waits_for_enabled_geo_exit_backend(monkeypatch):
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_pf_backend_hold_until", 0.0)

    assert not tproxy.geo_exit_backend_ready(now=100.0)
    assert not tproxy.pf_setup_if_ready(1080, now=100.0)


def test_amain_uses_backend_gate_before_starting_monitor(monkeypatch):
    calls = []

    class Server:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def serve_forever(self):
            raise RuntimeError("stop test server")

    class Thread:
        def __init__(self, *args, **kwargs):
            calls.append(("thread", args, kwargs))

        def start(self):
            calls.append(("thread_start",))

    async def start_server(*_args, **_kwargs):
        return Server()

    monkeypatch.setattr(tproxy.asyncio, "start_server", start_server)
    monkeypatch.setattr(tproxy.threading, "Thread", Thread)
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
        "pf_setup_if_ready",
        lambda port: calls.append(("pf_gate", port)) or False,
    )

    with pytest.raises(RuntimeError, match="stop test server"):
        asyncio.run(tproxy.amain(1080, voice=False))

    assert calls[0] == ("pf_gate", 1080)
    assert calls[1] == ("status", "dormant", "en0", None)
    assert ("thread_start",) in calls


def test_geo_exit_backend_hold_requires_fresh_probe_after_cooldown(monkeypatch):
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_PORTS", [tproxy.GEPH_OWNED_PORT])
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_pf_backend_hold_until", 130.0)
    monkeypatch.setattr(tproxy, "_pf_backend_hold_reason", "runtime miss")

    assert not tproxy.geo_exit_backend_ready(now=120.0)
    assert tproxy.geo_exit_backend_ready(now=131.0)
    assert tproxy._pf_backend_hold_until == 0.0
    assert tproxy._pf_backend_hold_reason == ""


def test_network_monitor_pauses_pf_when_cold_start_geph_is_not_ready(monkeypatch):
    class StopMonitor(Exception):
        pass

    pauses = []
    states = []
    rearms = []

    def pause():
        pauses.append(True)
        tproxy._pf_applied = False
        return True

    def stop_sleep(_seconds):
        raise StopMonitor

    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_pf_interceptor_conflicts", [])
    monkeypatch.setattr(tproxy, "_pf_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "default_iface", lambda: "en0")
    monkeypatch.setattr(tproxy, "probe_geph", lambda: False)
    monkeypatch.setattr(tproxy, "pause_private_pf", pause)
    monkeypatch.setattr(
        tproxy,
        "write_status",
        lambda state, iface, voice_iface: states.append((state, iface, voice_iface)),
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
    monkeypatch.setattr(tproxy.time, "sleep", stop_sleep)
    tproxy._queue_runtime_rearm("network_change")

    with pytest.raises(StopMonitor):
        tproxy.network_monitor(1080, voice=False)

    assert pauses == [True]
    assert states == [("dormant", "en0", None)]
    assert rearms == [("network_change", "en0")]


def test_runtime_pf_arm_rechecks_backend_after_loading_rules(monkeypatch):
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
    monkeypatch.setattr(tproxy, "_pf_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "pf_parent_anchor_loaded", lambda: True)
    monkeypatch.setattr(tproxy, "_pf_acquire_enable_token", lambda: True)
    monkeypatch.setattr(tproxy, "_pf_load", load)
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

    assert not tproxy.arm_private_pf_if_ready(1080)
    assert calls == ["load", "flush", "release"]
    assert tproxy._pf_applied is False


def test_suspend_transparent_routing_flushes_only_private_anchor(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_pf_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "_pf_backend_hold_reason", "")
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: calls.append("private rulesets flushed") or SimpleNamespace(returncode=0),
    )

    assert tproxy.suspend_transparent_routing("geo-exit tunnel down", now=100.0)
    assert calls == ["private rulesets flushed"]
    assert tproxy._pf_applied is False
    assert tproxy._geph_up is False
    assert tproxy._pf_backend_hold_until == 100.0 + tproxy.PF_BACKEND_FAILURE_HOLD
    assert tproxy._pf_backend_hold_reason == "geo-exit tunnel down"


def test_suspend_transparent_routing_flushes_stale_anchor_when_flag_is_false(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "_pf_applied", False)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_pf_backend_hold_until", 0.0)
    monkeypatch.setattr(
        tproxy,
        "_pf_flush",
        lambda: calls.append(tproxy.PF_ANCHOR) or SimpleNamespace(returncode=0),
    )

    assert tproxy.suspend_transparent_routing("geo-exit tunnel down", now=100.0)
    assert calls == [tproxy.PF_ANCHOR]
    assert tproxy._pf_applied is False


def test_pf_lifecycle_functions_are_not_shadowed_by_later_definitions():
    module = ast.parse(Path(tproxy.__file__).read_text())
    names = [node.name for node in module.body if isinstance(node, ast.FunctionDef)]

    for name in (
        "geo_exit_backend_ready",
        "pause_private_pf",
        "suspend_transparent_routing",
        "pf_setup_if_ready",
    ):
        assert names.count(name) == 1, name


def test_explicit_local_only_mode_does_not_fail_close_geo_hosts(monkeypatch):
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", False)

    assert not tproxy.geph_route("chatgpt.com")
    assert tproxy.geo_exit_backend_ready(now=100.0)


def test_geo_exit_tunnel_down_suspends_private_pf_before_close(monkeypatch):
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
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.8", 443))
    monkeypatch.setattr(tproxy, "parse_sni", lambda _body: "chatgpt.com")
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "log_geph_route_failure", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "suspend_transparent_routing", suspended.append)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", False)

    asyncio.run(tproxy._handle_impl(Reader(), writer))

    assert suspended == ["geo-exit tunnel down"]
    assert writer.closed is True


@pytest.mark.parametrize(
    ("downstream_bytes", "expected_failure", "expected_suspend", "expected_clear"),
    [
        (
            0,
            [("chatgpt.com", "remote closed without response")],
            ["geo-exit remote close before payload"],
            [],
        ),
        (1, [], [], [True]),
    ],
)
def test_geo_exit_payload_result_controls_private_pf(
    monkeypatch,
    downstream_bytes,
    expected_failure,
    expected_suspend,
    expected_clear,
):
    class Reader:
        def __init__(self):
            self.parts = [b"\x16\x03\x01\x00\x01", b"x"]

        async def readexactly(self, _size):
            return self.parts.pop(0)

    class Writer:
        def get_extra_info(self, _name):
            return object()

    async def connected(*_args):
        return object(), object()

    async def empty_client_pump(*_args):
        return 0

    async def geph_response(*_args):
        return downstream_bytes

    failures = []
    cleared = []
    suspended = []
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.8", 443))
    monkeypatch.setattr(tproxy, "parse_sni", lambda _body: "chatgpt.com")
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "dial_via_geph", connected)
    monkeypatch.setattr(tproxy, "pump", empty_client_pump)
    monkeypatch.setattr(tproxy, "splice", geph_response)
    monkeypatch.setattr(
        tproxy,
        "log_geph_route_failure",
        lambda host, reason: failures.append((host, reason)),
    )
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: cleared.append(True))
    monkeypatch.setattr(tproxy, "suspend_transparent_routing", suspended.append)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)

    asyncio.run(tproxy._handle_impl(Reader(), Writer()))

    assert failures == expected_failure
    assert suspended == expected_suspend
    assert cleared == expected_clear


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
    assert tproxy.route_policy("rr2---sn-ntq7yner.googlevideo.com")["service_group"] == (
        tproxy.SERVICE_YOUTUBE
    )
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


def test_direct_passthrough_hosts_use_plain_strategy_only():
    tproxy._strat_cache["www.google.com"] = "split64+fake"
    tproxy._strat_cache["api.spotify.com"] = "split64+fake"
    try:
        assert [s["name"] for s in tproxy.strategy_order("github.com")] == ["plain"]
        assert [s["name"] for s in tproxy.strategy_order("t.me")] == ["plain"]
        assert [s["name"] for s in tproxy.strategy_order("yandex.ru")] == ["plain"]
        assert [s["name"] for s in tproxy.strategy_order("www.google.com")][:2] == [
            "plain", "split64+fake",
        ]
        assert [s["name"] for s in tproxy.strategy_order("api.spotify.com")][:2] == [
            "plain", "split64+fake",
        ]
        assert [s["name"] for s in tproxy.strategy_order("i.scdn.co")][0] == "plain"
        assert not tproxy.geph_route("www.google.com")
        assert not tproxy.geph_route("api.spotify.com")
        assert not tproxy.geph_route("i.scdn.co")
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
        len(tproxy.TELEGRAM_HOSTS) + len(tproxy.GITHUB_HOSTS)
    )
    assert status["domains"][tproxy.ROUTE_DIRECT_FIRST] == (
        len(tproxy.DIRECT_FIRST_HOSTS)
    )
    assert status["domains"][tproxy.ROUTE_LOCAL_BYPASS] == (
        len(tproxy.DISCORD_HOSTS) + len(tproxy.GOOGLE_VIDEO)
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


def test_apply_signed_route_policy_bundle_activates_manifest():
    manifest = tproxy.route_policy_manifest()
    manifest["source"] = "signed:test"
    manifest["geo_exit_routes"].append({
        "domains": ["payments.example.org"],
        "service_group": tproxy.SERVICE_GENERIC,
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "strategy_set": tproxy.STRATEGY_GEPH,
    })
    bundle, public_keys = signed_test_policy_bundle(manifest)

    status = tproxy.apply_signed_route_policy_bundle(bundle, public_keys)

    assert status["source"] == "signed:test"
    assert tproxy.route_policy("payments.example.org")["route_class"] == (
        tproxy.ROUTE_GEO_EXIT
    )


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

    tproxy.save_signed_route_policy_bundle(
        first_bundle,
        public_keys,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=100.0,
    )
    assert policy_path.exists()
    assert not previous_path.exists()
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
    tproxy.save_signed_route_policy_bundle(
        second_bundle,
        public_keys,
        policy_path=str(policy_path),
        previous_path=str(previous_path),
        now=200.0,
    )

    assert previous_path.exists()
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
        tproxy.LOCAL_BYPASS_IP_ATTEMPT_LIMIT
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
    assert not tproxy.geph_route(spec["host"])
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
    assert not tproxy.geph_route(spec["host"])
    assert [s["name"] for s in tproxy.strategy_order(spec["host"])] == [
        "split64+fake",
        "split16+fake",
        "fake5",
    ]


def test_youtube_redirector_canary_stays_local_bypass_and_fake_only():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_video")
    host = spec["fallback_host"]

    assert tproxy.route_policy(host) == {
        "host": "redirector.googlevideo.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_YOUTUBE,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert not tproxy.geph_route(host)
    assert [s["name"] for s in tproxy.strategy_order(host)] == [
        "split64+fake",
        "split16+fake",
        "fake5",
    ]


def test_youtube_web_canary_stays_local_bypass_and_fake_only():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_web")

    assert spec["soft"] is True
    assert tproxy.route_policy(spec["host"]) == {
        "host": "www.youtube.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_YOUTUBE,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert not tproxy.geph_route(spec["host"])
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
    resolves = []

    def fake_run(*args):
        calls.append(args)
        return type("Result", (), {
            "returncode": 0,
            "stdout": "nameserver[0] : 111.88.96.50\n",
            "stderr": "",
        })()

    def fake_resolve(host):
        resolves.append(host)
        return ["142.250.186.46"]

    original = dict(tproxy._system_dns_cache)
    try:
        tproxy._system_dns_cache.update({
            "ts": 0.0,
            "status": None,
            "resolution_ts": 0.0,
            "resolution_checks": None,
        })
        monkeypatch.setattr(tproxy, "_run", fake_run)
        monkeypatch.setattr(tproxy, "system_resolve", fake_resolve)

        first = tproxy.current_system_dns_status(now=100.0)
        second = tproxy.current_system_dns_status(now=110.0)

        assert first["state"] == "xbox_dns"
        assert first["resolution_checks"]["state"] == "ok"
        assert second["state"] == "xbox_dns"
        assert calls == [("scutil", "--dns")]
        assert resolves == [host for host, _group in tproxy.DNS_DIAGNOSTIC_HOSTS]
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
        assert not tproxy.geph_route(host)
    finally:
        tproxy._strat_cache.clear()
        tproxy._canary_state.clear()
        tproxy._canary_state.update(original_canary_state)
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


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
    assert calls == ["updates.discord.com"]


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
        assert not tproxy.geph_route(host)
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


def test_youtube_canary_uses_quic_transport_probe(monkeypatch):
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_video")
    original = dict(tproxy._route_health[tproxy.SERVICE_YOUTUBE])
    original_window = deque(tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE])
    tproxy._strat_cache.clear()
    calls = []

    async def fake_resolve(host, fallback_ip):
        calls.append(("resolve", host, fallback_ip))
        return ["203.0.113.10"]

    async def fake_quic(ips):
        calls.append(("quic", tuple(ips)))
        return True

    async def unexpected_dial_strategy(*args, **kwargs):
        raise AssertionError("YouTube canary should not use the TCP strategy probe")

    monkeypatch.setattr(tproxy, "resolve_connection_ips", fake_resolve)
    monkeypatch.setattr(tproxy, "_run_quic_version_negotiation_probe", fake_quic)
    monkeypatch.setattr(tproxy, "dial_strategy", unexpected_dial_strategy)

    try:
        assert asyncio.run(tproxy._run_local_bypass_canary(spec)) is True

        assert calls == [
            ("resolve", "redirector.googlevideo.com", None),
            ("quic", ("203.0.113.10",)),
        ]
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_YOUTUBE]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_host"] == "redirector.googlevideo.com"
    finally:
        tproxy._strat_cache.clear()
        tproxy._route_health[tproxy.SERVICE_YOUTUBE] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE]
        q.clear()
        q.extend(original_window)


def test_geo_exit_canary_failure_does_not_promote_to_local_bypass(monkeypatch):
    monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
    monkeypatch.setattr(tproxy, "_geph_up", False)

    spec = {"group": tproxy.SERVICE_OPENAI, "host": "billing.openai.com"}
    assert not asyncio.run(tproxy._run_geo_exit_canary(spec))

    assert tproxy.geph_route("billing.openai.com")
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


def test_youtube_video_hosts_ignore_stale_non_fake_strategy_cache():
    host = "rr2---sn-ntq7yner.googlevideo.com"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64"

    try:
        names = [s["name"] for s in tproxy.strategy_order(host)]

        assert names == ["split64+fake", "split16+fake", "fake5"]
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
    assert not tproxy.geph_route("updates.discord.com")
    assert not tproxy.geph_route("gateway.discord.gg")
    assert not tproxy.geph_route("discord.com")
    assert not tproxy.geph_route("status.discordstatus.com")
    assert not tproxy.geph_route("cdn.discordapp.com")
    assert not tproxy.geph_route("discord-activities.com")


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
    original_hint = dict(tproxy._geph_restart_hint)
    tproxy._geph_fail_log.clear()
    tproxy._geph_restart_failures.clear()

    try:
        tproxy._geph_up = True
        tproxy._geph_owned = True
        tproxy.note_geph_wake(1000.0)

        tproxy.log_geph_route_failure("chatgpt.com", "SOCKS connect failed", now=1001.0)
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
        tproxy._geph_fail_log.clear()
        tproxy._geph_restart_failures.clear()
        tproxy._geph_restart_hint.clear()
        tproxy._geph_restart_hint.update(original_hint)


def test_geo_exit_failures_never_request_unowned_geph_restart(capsys):
    original_geph_up = tproxy._geph_up
    original_geph_owned = tproxy._geph_owned
    original_hint = dict(tproxy._geph_restart_hint)
    tproxy._geph_fail_log.clear()
    tproxy._geph_restart_failures.clear()

    try:
        tproxy._geph_up = True
        tproxy._geph_owned = False
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
        assert hint["failures_5m"] == 3
        assert not tproxy.request_owned_geph_restart(
            "chatgpt.com",
            "SOCKS connect failed",
            now=1004.0,
        )
    finally:
        capsys.readouterr()
        tproxy._geph_up = original_geph_up
        tproxy._geph_owned = original_geph_owned
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
        pauser=lambda: calls.append(("pause",)),
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
        pauser=lambda: calls.append(("pause",)),
    )

    assert result == "busy"
    assert calls == []
    assert hint["recommended"] is True


def test_owned_geph_restart_pauses_pf_and_kickstarts_exact_launchagent(monkeypatch):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
    monkeypatch.setattr(tproxy, "_geph_restart_failures", deque([(99.0, "chatgpt.com", "stale")]))
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
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
        "suspend_transparent_routing",
        lambda reason, now=None: events.append(("pause", reason, now)),
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
        ("pause", "owned Geph restart in progress", 100.0),
        ("run", "/bin/launchctl", "kickstart", "-k", "gui/502/dev.slipstream.geph"),
        ("rearm", "geph_restart"),
    ]
    assert hint["recommended"] is False
    assert tproxy._geph_restart_draining is True
    tproxy._finish_geph_restart_drain()
    assert tproxy._geph_restart_draining is False


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
        pauser=lambda: calls.append(("pause",)),
    )

    assert result == "unverified"
    assert calls == []
    assert hint["recommended"] is True


def test_owned_geph_restart_rate_limits_launchctl_retry(monkeypatch, capsys):
    hint = dict(tproxy._geph_restart_hint)
    hint.update({"recommended": True, "last_attempt_at": 0.0})
    monkeypatch.setattr(tproxy, "_geph_restart_hint", hint)
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
        "pauser": lambda: None,
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


def test_stale_auto_geph_cache_never_overrides_explicit_policy():
    tproxy._auto_geph.clear()
    tproxy._auto_geph["updates.discord.com"] = tproxy.time.time() + 3600
    tproxy._auto_geph["rr2---sn-ntq7yner.googlevideo.com"] = tproxy.time.time() + 3600
    tproxy._auto_geph["www.google.com"] = tproxy.time.time() + 3600
    tproxy._auto_geph["api.spotify.com"] = tproxy.time.time() + 3600
    tproxy._auto_geph["payments.example.com"] = tproxy.time.time() + 3600

    try:
        assert not tproxy.geph_route("updates.discord.com")
        assert not tproxy.geph_route("rr2---sn-ntq7yner.googlevideo.com")
        assert not tproxy.geph_route("www.google.com")
        assert not tproxy.geph_route("api.spotify.com")
        assert not tproxy.geph_route("payments.example.com")
        assert tproxy.geph_route("chatgpt.com")
    finally:
        tproxy._auto_geph.clear()


def test_auto_geph_candidate_is_disabled_for_every_host():
    for host in (
        "payments.example.com",
        "updates.discord.com",
        "rr2---sn-ntq7yner.googlevideo.com",
        "t.me",
        "www.google.com",
        "api.spotify.com",
        "chatgpt.com",
    ):
        assert not tproxy._auto_geph_candidate_allowed(host)


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
    assert source.count("relay_local_stream(") == 4


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


def test_partial_stream_stall_marks_exact_xbox_dns_candidate():
    host = "crystalidea.example"
    tproxy._strat_cache[host] = "split64+fake"

    try:
        assert tproxy.note_local_stream_stall(host, "split64+fake")
        assert host not in tproxy._strat_cache
        assert tproxy._xbox_dns_candidate_active(host)
        assert not tproxy.geph_route(host)
        assert [strategy["name"] for strategy in tproxy.strategy_order(host)][0] == "split16+fake"

        tproxy._strat_cache["updates.discord.com"] = "split64+fake"
        assert not tproxy.note_local_stream_stall("updates.discord.com", "split64+fake")
        assert tproxy._strat_cache["updates.discord.com"] == "split64+fake"
        assert not tproxy._xbox_dns_candidate_active("updates.discord.com")
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()


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
        assert not tproxy.geph_route(host)

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
        assert not tproxy.geph_route(host)
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
    assert tproxy._xbox_dns_attempted_recently("payments.example.com")


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
    assert not tproxy.geph_route(host)


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
    assert not tproxy.geph_route(host)


def test_unknown_stalls_never_promote_to_geph_after_xbox_dns_attempt(monkeypatch):
    confirmations = []
    host = "payments.example.com"
    monkeypatch.setattr(tproxy, "_geph_up", True)
    tproxy._xbox_dns_attempts[host] = 1_000.0

    for idx in range(tproxy.AUTO_GEPH_STORM):
        tproxy.note_local_result(
            host,
            down_bytes=100,
            duration=tproxy.AUTO_GEPH_HANG + 1,
            now=100.0 + idx,
            confirmation_runner=lambda value: confirmations.append(value),
        )

    assert confirmations == []
    assert not tproxy.geph_route(host)
    assert not tproxy._auto_geph
    snap = tproxy.auto_geo_exit_status_snapshot()
    assert snap["enabled"] is False
    assert snap["learned"] == 0


def test_auto_geph_confirmation_never_dials_unknown_host(monkeypatch):
    probes = []
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_payload_probe",
        lambda host: probes.append(host) or 128,
    )

    assert not tproxy._confirm_auto_geph("payments.example.com")
    assert probes == []
    snap = tproxy.auto_geo_exit_status_snapshot()
    assert snap["last_state"] == "skipped"
    assert snap["last_reason"] == "not eligible"


def test_load_auto_geph_discards_legacy_learned_routes(tmp_path, monkeypatch):
    path = tmp_path / "autogeph.json"
    path.write_text(json.dumps({"www.google.com": tproxy.time.time() + 3600}))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(path))

    tproxy.load_auto_geph()

    assert tproxy._auto_geph == {}
    assert json.loads(path.read_text()) == {}
    assert not tproxy.geph_route("www.google.com")


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
    assert not tproxy.geph_route("payments.example.com")


def test_prune_auto_geph_discards_legacy_learned_hosts(monkeypatch):
    saves = []
    tproxy._auto_geph["old.example.com"] = 100.0
    tproxy._auto_geph["fresh.example.com"] = 300.0
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: saves.append(True))

    snap = tproxy.auto_geo_exit_status_snapshot(now=200.0)

    assert tproxy._auto_geph == {}
    assert snap["learned"] == 0
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

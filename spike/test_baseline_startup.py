import json
import os
import subprocess
import sys
import time

import pytest
import tproxy


def _identity(tmp_path):
    return os.getuid(), os.getgid(), str(tmp_path)


def test_baseline_resolver_timeout_kills_real_child(monkeypatch, tmp_path):
    pid_path = tmp_path / "resolver.pid"
    child = (
        "import os, pathlib, time; "
        f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); "
        "time.sleep(60)"
    )
    monkeypatch.setattr(
        tproxy,
        "_baseline_resolver_command",
        lambda _host: [sys.executable, "-c", child],
    )

    started = time.monotonic()
    answers = tproxy._run_baseline_resolver(
        "slow.example",
        443,
        _identity(tmp_path),
        timeout=0.5,
    )
    elapsed = time.monotonic() - started

    assert answers == ()
    assert elapsed < 2.0
    pid = int(pid_path.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_baseline_resolver_parses_bounded_child_output(monkeypatch, tmp_path):
    child = (
        "import json; "
        "print(json.dumps({'addresses': "
        "['203.0.113.10', '203.0.113.11', '203.0.113.12', "
        "'203.0.113.13', '203.0.113.14']}))"
    )
    monkeypatch.setattr(
        tproxy,
        "_baseline_resolver_command",
        lambda _host: [sys.executable, "-c", child],
    )

    answers = tproxy._run_baseline_resolver(
        "fast.example",
        443,
        _identity(tmp_path),
        timeout=1.0,
    )

    assert [answer[4] for answer in answers] == [
        ("203.0.113.10", 443),
        ("203.0.113.11", 443),
        ("203.0.113.12", 443),
        ("203.0.113.13", 443),
    ]


def test_baseline_resolve_cli_runs_without_root_or_network():
    result = subprocess.run(
        [
            sys.executable,
            tproxy.__file__,
            "--baseline-resolve",
            "--baseline-host",
            "localhost",
        ],
        capture_output=True,
        text=True,
        timeout=3.0,
        check=False,
    )

    assert result.returncode == 2
    assert json.loads(result.stdout) == {"addresses": []}


def test_baseline_preflight_has_one_total_budget(monkeypatch):
    identity = (501, 20, "/Users/fixture")
    observed_timeouts = []

    monkeypatch.setattr(tproxy, "_console_probe_identity", lambda: identity)
    monkeypatch.setattr(tproxy, "BASELINE_PREFLIGHT_BUDGET", 0.2)
    monkeypatch.setattr(tproxy, "BASELINE_RESOLVE_TIMEOUT", 5.0)

    def resolve(_host, _port, _identity, *, timeout):
        observed_timeouts.append(timeout)
        time.sleep(timeout)
        return ()

    monkeypatch.setattr(tproxy, "_run_baseline_resolver", resolve)

    started = time.monotonic()
    result, observed_identity = tproxy._baseline_preflight()
    elapsed = time.monotonic() - started

    assert not result.ok
    assert result.reason == "baseline_resolution_unavailable"
    assert observed_identity == identity
    assert elapsed < 0.6
    assert len(observed_timeouts) == len(tproxy.install_guard.DEFAULT_TARGETS)
    assert 0 < observed_timeouts[0] <= 0.2
    assert observed_timeouts[-1] == 0


def test_baseline_preflight_continues_after_resolver_timeout(monkeypatch):
    calls = []
    identity = (501, 20, "/Users/fixture")

    monkeypatch.setattr(tproxy, "_console_probe_identity", lambda: identity)

    def resolve(host, port, observed_identity, *, timeout):
        calls.append((host, timeout))
        assert port == 443
        assert observed_identity == identity
        if host != "www.microsoft.com":
            return ()
        return ((
            tproxy.socket.AF_INET,
            tproxy.socket.SOCK_STREAM,
            tproxy.socket.IPPROTO_TCP,
            "",
            ("203.0.113.20", 443),
        ),)

    monkeypatch.setattr(tproxy, "_run_baseline_resolver", resolve)
    monkeypatch.setattr(
        tproxy,
        "_run_baseline_probe_candidate",
        lambda candidate, observed_identity, *, timeout: (
            tproxy.install_guard.ProbeResult(True, "ok")
        ),
    )

    result, observed_identity = tproxy._baseline_preflight()

    assert result.ok
    assert observed_identity == identity
    assert result.candidates == (
        tproxy.install_guard.BaselineCandidate(
            "www.microsoft.com", "203.0.113.20", "/"
        ),
    )
    assert [host for host, _timeout in calls] == [
        "example.com",
        "www.apple.com",
        "www.microsoft.com",
    ]
    assert all(0 < timeout <= tproxy.BASELINE_RESOLVE_TIMEOUT for _, timeout in calls)


def test_background_dns_diagnostics_have_one_total_budget(monkeypatch):
    identity = (501, 20, "/Users/fixture")
    observed_timeouts = []
    monkeypatch.setattr(tproxy, "_console_probe_identity", lambda: identity)
    monkeypatch.setattr(tproxy, "SYSTEM_DNS_DIAGNOSTIC_BUDGET", 0.2)
    monkeypatch.setattr(tproxy, "BASELINE_RESOLVE_TIMEOUT", 5.0)
    monkeypatch.setattr(
        tproxy,
        "_system_dns_cache",
        {
            "ts": 0.0,
            "status": None,
            "resolution_ts": 0.0,
            "resolution_checks": None,
        },
    )

    def resolve(_host, _port, observed_identity, *, timeout):
        assert observed_identity == identity
        observed_timeouts.append(timeout)
        time.sleep(timeout)
        return ()

    monkeypatch.setattr(tproxy, "_run_baseline_resolver", resolve)

    started = time.monotonic()
    checks = tproxy._refresh_system_dns_resolution_checks()
    elapsed = time.monotonic() - started

    assert checks["state"] == "unknown"
    assert elapsed < 0.6
    assert len(observed_timeouts) == len(tproxy.DNS_DIAGNOSTIC_HOSTS)
    assert 0 < observed_timeouts[0] <= 0.2
    assert observed_timeouts[-1] == 0
    assert tproxy._system_dns_cache["resolution_checks"] == checks

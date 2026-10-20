"""Hermetic diagnostic guards and bounds; no native APIs or processes."""
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ci_macos_authorization_probe as probe


@pytest.fixture(autouse=True)
def no_native(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("native execution forbidden")
    monkeypatch.setattr(probe.subprocess, "Popen", forbidden)
    monkeypatch.setattr(probe.subprocess, "run", forbidden)
    monkeypatch.setattr(probe.C, "CDLL", forbidden)
    monkeypatch.setattr(probe.public_update_ui_preflight, "run", forbidden)
    monkeypatch.setattr(probe.signal, "alarm", lambda _seconds: None)
    monkeypatch.setattr(os, "kill", forbidden)


def guarded(monkeypatch):
    values = {"CI": "true", "GITHUB_ACTIONS": "true", "SLIPSTREAM_DISPOSABLE_CI": "1",
              "RUNNER_OS": "macOS", "GITHUB_REPOSITORY": "aiwaki/slipstream", "GITHUB_REF": probe.BRANCH,
              "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(probe.sys, "platform", "darwin")
    monkeypatch.setattr(probe.os, "getuid", lambda: 501)
    monkeypatch.setattr(probe.os, "geteuid", lambda: 501)
    old_stat = os.stat
    monkeypatch.setattr(probe.os, "stat", lambda path, *a, **k:
                        SimpleNamespace(st_uid=501) if str(path) == "/dev/console" else old_stat(path, *a, **k))


@pytest.mark.parametrize("key", ["CI", "GITHUB_ACTIONS", "SLIPSTREAM_DISPOSABLE_CI", "RUNNER_OS",
                               "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"])
def test_guard_rejects_wrong_runner_repository_branch_and_run(monkeypatch, key):
    guarded(monkeypatch)
    monkeypatch.setenv(key, "wrong")
    with pytest.raises(probe.Refused):
        probe.hosted_guard()


def test_guard_requires_exact_nonroot_console(monkeypatch):
    guarded(monkeypatch)
    assert probe.hosted_guard() == 501
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    with pytest.raises(probe.Refused, match="nonroot_console"):
        probe.hosted_guard()


def test_environment_has_no_tokens_or_privilege_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "SUDO_ASKPASS", "DYLD_INSERT_LIBRARIES", "PYTHONPATH"):
        monkeypatch.setenv(key, "must-not-be-inherited")
    assert probe.child_environment() == {"HOME": str(Path.home()), "TMPDIR": str(tmp_path),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"}


def test_output_is_private_exclusive_and_cannot_follow_symlink(monkeypatch, tmp_path):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    path = tmp_path / "probe.json"
    with probe.reserve_output(path) as output:
        output.write("{}")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        probe.reserve_output(path)
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    with pytest.raises(FileExistsError):
        probe.reserve_output(alias)
    assert path.read_text() == "{}"
    with pytest.raises(probe.Refused, match="private_output_location"):
        probe.reserve_output(tmp_path / "nested/probe.json")


@pytest.mark.parametrize("code,stdout,timed_out,expected", [
    (0, b"0\n", False, "passed"), (0, b"0", False, "refused"),
    (0, b"501\n", False, "refused"), (1, b"0\n", False, "refused"),
    (-9, b"", True, "timeout"), (0, b"0\n", True, "timeout")])
def test_only_exact_success_is_passed(code, stdout, timed_out, expected):
    assert probe.classify(code, stdout, 0, timed_out) == expected


@pytest.mark.parametrize("stdout,size", [(b"x" * 8193, 0), (b"0\n", 8193)])
def test_output_bounds(stdout, size):
    with pytest.raises(probe.Refused, match="output_bound"):
        probe.classify(0, stdout, size, False)


class FakeAX:
    def __init__(self, windows):
        self.app = {"AXWindows": windows}
        self.reads = []
        self.cf = SimpleNamespace(CFGetTypeID=lambda v: 1 if isinstance(v, list) else 2,
            CFArrayGetTypeID=lambda: 1, CFArrayGetCount=len, CFArrayGetValueAtIndex=lambda a, i: a[i],
            CFEqual=lambda a, b: a is b)
        self.ax = SimpleNamespace(AXUIElementGetTypeID=lambda: 2)

    def attribute(self, element, key):
        self.reads.append(key)
        return (0, element[key]) if key in element else (-1, None)

    def string(self, value):
        return value


def test_ax_reads_only_roles_and_subroles_never_values_text_or_actions():
    client = FakeAX([{"AXRole": "AXWindow", "AXTitle": "private title", "AXChildren": [
        {"AXRole": "AXTextField", "AXSubrole": "AXSecureTextField", "AXValue": "private password"}]}])
    result = probe.role_tree(client)
    assert result == [{"depth": 0, "role": "AXWindow", "subrole": None},
                      {"depth": 1, "role": "AXTextField", "subrole": "AXSecureTextField"}]
    assert set(client.reads) == {"AXWindows", "AXRole", "AXSubrole", "AXChildren"}
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize("kind", ["array", "nodes", "depth", "nested"])
def test_ax_hard_bounds(kind):
    node = {"AXRole": "AXWindow"}
    if kind == "array":
        windows = [node] * 33
    elif kind == "nodes":
        windows = [{"AXRole": "AXWindow", "AXChildren": [{"AXRole": "AXButton"} for _ in range(32)]}]
    elif kind == "depth":
        for _ in range(5):
            node = {"AXRole": "AXGroup", "AXChildren": [node]}
        windows = [node]
    else:
        windows = [[node]]
    with pytest.raises(probe.Refused, match="ax_"):
        probe.role_tree(FakeAX(windows))


@pytest.mark.parametrize("change", ["executable", "uid", "birth_drift"])
def test_system_process_identity_is_verified_before_ax(monkeypatch, change):
    paths = iter([probe.SECURITY_AGENT, "/other" if change == "birth_drift" else probe.SECURITY_AGENT])
    monkeypatch.setattr(probe, "executable_path",
                        lambda _pid: "/wrong" if change == "executable" else next(paths))
    monkeypatch.setattr(probe.subprocess, "run", lambda *_a, **_k: SimpleNamespace(
        returncode=0, stdout=f"{0 if change == 'uid' else 501} Tue Oct 20 12:00:00 2026 S\n".encode()))
    with pytest.raises(probe.Refused, match="process_"):
        probe.process_metadata(10, probe.SECURITY_AGENT, {501}, {}, deadline=probe.time.monotonic() + 5)


@pytest.mark.parametrize("delay,expected", [(0, "passed"), (2, "passed"), (100, "timeout"),
                                           (100, "overall_deadline")])
def test_fixed_request_is_once_bounded_and_reaps_only_owned_child(monkeypatch, tmp_path, delay, expected):
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(probe.time, "sleep", lambda seconds: setattr(clock, "now", clock.now + seconds))
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(probe.public_update_ui_preflight, "run",
                        lambda: {"status": "ready_for_owned_app_AX_probe"})
    identity = {"pid": 42, "uid": 501, "started": "fixed", "executable": "/usr/bin/osascript"}
    monkeypatch.setattr(probe, "process_metadata", lambda *_a, **_k: identity)
    def security_agents(*_args):
        if expected == "overall_deadline":
            raise probe.OverallDeadline("overall_deadline")
        return []
    monkeypatch.setattr(probe, "security_agents", security_agents)
    calls = []

    class Child:
        pid = 42
        killed = False
        def poll(self):
            return -9 if self.killed else 0 if clock.now >= delay else None
        def kill(self):
            self.killed = True
        def wait(self, timeout):
            assert timeout == 2 and self.poll() is not None
            return self.poll()

    child = Child()
    def start(argv, **kwargs):
        calls.append((argv, kwargs))
        kwargs["stdout"].write(b"0\n")
        return child
    monkeypatch.setattr(probe.subprocess, "Popen", start)
    report = {"authorization_requested": False, "owned_child_killed": False, "observations": []}
    if expected == "overall_deadline":
        with pytest.raises(probe.OverallDeadline, match="overall_deadline"):
            probe.probe(report, 501, tmp_path)
        assert child.killed and report["returncode"] == -9 and len(calls) == 1
        return
    probe.probe(report, 501, tmp_path)
    assert len(calls) == 1
    assert calls[0][0] == ["/usr/bin/osascript", "-e", probe.SCRIPT]
    assert probe.SCRIPT == 'do shell script "/usr/bin/id -u" with administrator privileges with prompt "Slipstream CI authorization capability"'
    assert calls[0][1]["env"] == probe.child_environment()
    assert report["status"] == expected and report["owned_child_killed"] == (expected == "timeout")
    assert len(report["observations"]) <= 3 and clock.now <= 25.2


def test_failed_preflight_never_requests_authorization(monkeypatch, tmp_path):
    monkeypatch.setattr(probe.public_update_ui_preflight, "run", lambda: {"status": "blocked"})
    with pytest.raises(probe.Refused, match="preflight"):
        probe.probe({}, 501, tmp_path)

"""No native commands: real-UI authorization protocol and cancellation boundaries."""
import copy
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import public_update_observer as public
import public_update_menu_smoke as menu
import public_update_ax as ax
from native_root_update import Refused


@pytest.fixture(autouse=True)
def no_native(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("native command or signal forbidden")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(public.native_ui, "auth_action", forbidden)


class Clock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now
    def sleep(self, seconds): self.now += seconds


def test_cancel_retries_only_preclick_then_once():
    clock, calls = Clock(), []
    responses = iter([{"state": "ax_error", "stage": "lookup", "code": -1728}, "absent", "cancelled"])
    def actor(prompt, **kwargs):
        calls.append((prompt, kwargs))
        return next(responses)
    assert public.cancel_dialog(actor, timeout=3, clock=clock, sleep=clock.sleep) == {
        "mode": "cancel", "cancelled": True, "cancel_clicks": 1}
    assert len(calls) == 3
    assert all(prompt == public.UPDATE_PROMPT and kw["cancel"] is True and kw["timeout"] <= 3 for prompt, kw in calls)
    assert all("username" not in kw and "password" not in kw for _, kw in calls)


@pytest.mark.parametrize("response", ["pending", "submitted", "rejected", {"state": "ax_error", "stage": "cancel", "code": -1728},
    {"state": "ax_error", "stage": "prompt_match", "code": -1728}, {"state": "ax_error", "stage": "lookup", "code": -999}])
def test_cancel_uncertain_action_never_replayed(response):
    calls = []
    with pytest.raises(Refused):
        public.cancel_dialog(lambda *_a, **_k: calls.append(1) or response, timeout=3)
    assert calls == [1]


def test_cancel_deadline_and_late_reply():
    clock = Clock()
    with pytest.raises(Refused, match="deadline"):
        public.cancel_dialog(lambda *_a, **_k: "absent", timeout=1, clock=clock, sleep=clock.sleep)
    assert clock.now == 1
    def late(*_a, **_k):
        clock.sleep(2)
        return "cancelled"
    with pytest.raises(Refused, match="arrived after"):
        public.cancel_dialog(late, timeout=1, clock=clock)


def configured():
    value = public.PublicObserver.__new__(public.PublicObserver)
    value.authorization = None
    value.authorization_mode = "confirm"
    value._authorization_credentials = ("ephemeral-user", "fixture-password-never-reported")
    value.authorization_children = [{"pid": 12, "uid": 501, "started": "birth"}]
    value.identity = {"nonce": "a" * 32, "prepare_deadline_unix": 12345}
    value.last_journal = {"phase": "prepared"}
    value.authorization_confirmed = False
    value.deadline = 720
    value.events = []
    value.record = lambda kind, evidence: value.events.append((kind, copy.deepcopy(evidence)))
    return value


def test_confirm_single_submit_then_readonly_and_separate_lease(monkeypatch):
    value, clock, calls = configured(), Clock(), []
    monkeypatch.setattr(public.native_ui.time, "monotonic", clock)
    monkeypatch.setattr(public.native_ui.time, "sleep", clock.sleep)
    def actor(prompt, **kwargs):
        calls.append((prompt, kwargs))
        return "submitted" if kwargs["submit"] else "absent"
    value.interact_authorization(actor=actor, clock=clock)
    value.interact_authorization(actor=lambda *_a, **_k: pytest.fail("replayed"), clock=clock)
    assert [kw["submit"] for _, kw in calls] == [True, False]
    assert all(prompt == public.UPDATE_PROMPT for prompt, _ in calls)
    assert value.authorization_confirmed and value._authorization_credentials is None
    assert value.deadline == 720 and value.identity["prepare_deadline_unix"] == 12345
    assert value.authorization["gui_budget_seconds"] == 90
    assert "fixture-password" not in repr(value.events) and "ephemeral-user" not in repr(value.events)
    assert value.authorization["scope"] == "native_submission_and_prompt_disappearance"


def test_confirm_uncertain_submission_is_not_replayed(monkeypatch):
    value, clock, calls = configured(), Clock(), []
    monkeypatch.setattr(public.native_ui.time, "monotonic", clock)
    monkeypatch.setattr(public.native_ui.time, "sleep", clock.sleep)
    def actor(*_a, **kwargs):
        calls.append(kwargs["submit"])
        return {"state": "ax_error", "stage": "confirm", "code": -1728} if kwargs["submit"] else "absent"
    with pytest.raises(public.native_ui.QualificationError):
        value.interact_authorization(actor=actor, clock=clock)
    value.interact_authorization(actor=actor, clock=clock)
    assert calls == [True, False] and not value.authorization_confirmed
    assert value._authorization_credentials is None


@pytest.mark.parametrize("change", ["unbound", "wrong_phase", "two_children"])
def test_auth_refuses_unbound_dialog(change):
    value = configured()
    if change == "unbound": value.identity = None
    if change == "wrong_phase": value.last_journal["phase"] = "successor_launched"
    if change == "two_children": value.authorization_children *= 2
    with pytest.raises(Refused):
        value.interact_authorization(actor=lambda *_a, **_k: pytest.fail("must not act"), clock=lambda: 0)


def proof(heartbeat=1):
    return {"process": {"uid": 0, "started": "daemon-birth", "command": "canonical daemon"},
            "proof": {"daemon_pid": 333, "daemon_sha256": "d" * 64, "heartbeat_seq": heartbeat},
            "current_tree_sha256": "c" * 64, "active_index_absent": True, "root_operation_absent": True}


@pytest.fixture
def cancelled(tmp_path):
    value = configured()
    value.authorization_mode = "cancel"
    value.authorization = {"cancelled": True}
    value.authorization_children = []
    value.root_status = value.ack = None
    value.cancel_log_offset = 0
    value.cancel_before = proof()
    value.cancel_runtime_proof = lambda _nonce=None: proof(2)
    value.original_exited = False
    value.original_process = SimpleNamespace(poll=lambda: None)
    value.initiator = {"pid": 111, "uid": os.getuid(), "started": "tray-birth", "command": "canonical tray", "state": "S"}
    value.uid = os.getuid()
    value.process_snapshot = lambda _pid: value.initiator
    value.observe_once = lambda: None
    value.target = tmp_path / "old.app"
    value.args = SimpleNamespace(output_dir=tmp_path)
    value.journal_path, value.ack_path, value.stage, value.agent = [tmp_path / name for name in ("journal", "ack", "stage", "agent")]
    value.last_journal["backup"] = str(tmp_path / "backup")
    value.expected = {"old": {"bundle_tree_sha256": "b" * 64}}
    value.tproxy = SimpleNamespace(_daemon_update_tree=lambda *_a, **_k: "b" * 64)
    value.retain_public_diagnostic = lambda: value.record("timeout", {})
    log = tmp_path / "normal-old-tray.log"
    log.write_text("update installation unavailable: update authorization cancelled\n")
    log.chmod(0o600)
    return value


def test_cancel_requires_clean_old_runtime_before_retry(cancelled):
    result = cancelled.wait_cancelled(clock=lambda: 0)
    assert result["native_cancel_qualified"] and result["local_preparation_removed"]
    assert result["nonce"] == cancelled.identity["nonce"]
    assert result["before"]["proof"]["heartbeat_seq"] < result["after"]["proof"]["heartbeat_seq"]
    reset = []
    cancelled.menu = SimpleNamespace(click_verified=True, reset_after_cancel=lambda: reset.append(1))
    cancelled.reset_after_cancel()
    assert reset == [1] and cancelled.identity is None and cancelled.last_journal is None
    assert cancelled.deadline == 720 and cancelled.initiator["pid"] == 111


@pytest.mark.parametrize("change", ["daemon_birth", "daemon_pid", "daemon_hash", "runtime_tree", "app_tree", "stage", "root_started", "tray_exit"])
def test_cancel_rejects_changed_or_pending_state(cancelled, change):
    after = proof(2)
    if change == "daemon_birth": after["process"]["started"] = "different"
    if change == "daemon_pid": after["proof"]["daemon_pid"] += 1
    if change == "daemon_hash": after["proof"]["daemon_sha256"] = "different"
    if change == "runtime_tree": after["current_tree_sha256"] = "different"
    cancelled.cancel_runtime_proof = lambda _nonce: after
    if change == "app_tree": cancelled.tproxy._daemon_update_tree = lambda *_a, **_k: "different"
    if change == "stage": cancelled.stage.mkdir()
    if change == "root_started": cancelled.root_status = {"phase": "prepared"}
    if change == "tray_exit": cancelled.original_process.poll = lambda: 0
    with pytest.raises(Refused): cancelled.wait_cancelled(clock=lambda: 0)
    assert not hasattr(cancelled, "cancelled_proof")


def test_cancel_requires_advancing_heartbeat_within_original_observation_budget(cancelled):
    clock = Clock()
    cancelled.deadline = 91
    cancelled.cancel_runtime_proof = lambda _nonce: proof()
    with pytest.raises(Refused, match="deadline"):
        cancelled.wait_cancelled(clock=clock, sleep=clock.sleep)
    assert clock.now == 1 and cancelled.events[-1][0] == "timeout"


def test_reset_cannot_clear_unproven_intent(cancelled):
    cancelled.cancelled_proof = None
    with pytest.raises(Refused, match="definitive"):
        cancelled.reset_after_cancel()
    assert cancelled.identity is not None


def test_cancel_late_runtime_proof_cannot_admit_retry(cancelled):
    clock = Clock()
    cancelled.deadline = 91
    def late(_nonce):
        clock.sleep(1)
        return proof(2)
    cancelled.cancel_runtime_proof = late
    with pytest.raises(Refused, match="arrived after"):
        cancelled.wait_cancelled(clock=clock, sleep=clock.sleep)
    assert not hasattr(cancelled, "cancelled_proof")


def test_readonly_cancel_proof_reuses_canonical_validator(monkeypatch, tmp_path):
    proxy = SimpleNamespace(_DAEMON_UPDATE_ROOT=str(tmp_path / "absent-root"), INSTALL_DIR="installed",
                            _daemon_update_tree=lambda p: "c" * 64 if p == "installed" else pytest.fail("unexpected tree"))
    calls = []
    monkeypatch.setattr(public, "readonly_runtime_proof", lambda p, h: calls.append((p, h)) or proof())
    value = public.readonly_cancel_proof(proxy, "d" * 64, "a" * 32)
    assert calls == [(proxy, "d" * 64)] and value["root_operation_absent"]
    assert value["nonce"] == "a" * 32


@pytest.mark.parametrize("present", ["active.json", "a" * 32, ".prepare-" + "a" * 32])
def test_readonly_cancel_refuses_root_operation_without_reading_runtime(monkeypatch, tmp_path, present):
    root = tmp_path / "root"
    root.mkdir()
    (root / present).touch()
    real_lstat = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda p: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
                        if p == root else real_lstat(p))
    proxy = SimpleNamespace(_DAEMON_UPDATE_ROOT=str(root))
    monkeypatch.setattr(public, "readonly_runtime_proof", lambda *_a: pytest.fail("runtime proof after pending root"))
    with pytest.raises(Refused): public.readonly_cancel_proof(proxy, "d" * 64, "a" * 32)


def test_retry_uses_one_actual_check_action_and_keeps_install_distinct():
    original = {"pid": 1, "uid": 501, "started": "birth"}
    exe = Path("/Applications/Slipstream.app/Contents/MacOS/slipstream")
    report = {"identity": {**original, "executable": str(exe), "executable_sha256": "a" * 64},
              "status": "check_pressed", "installation_attempted": False,
              "actions": [{"kind": "press_check", "attempted": True, "ax_error": 0, "title": "Check for Updates…"}]}
    menu.validate_ax(report, original, exe, "a" * 64, checked=True)
    with pytest.raises(Refused): menu.validate_ax(report, original, exe, "a" * 64, pressed=True)
    report["actions"] *= 2
    with pytest.raises(Refused): menu.validate_ax(report, original, exe, "a" * 64, checked=True)


def test_check_menu_cli_reports_success_exit(tmp_path, monkeypatch):
    output = tmp_path / "check.json"
    monkeypatch.setattr(sys, "argv", ["public_update_ax.py", "--pid", "111", "--uid", "501",
        "--executable", "/Applications/Slipstream.app/Contents/MacOS/slipstream",
        "--exe-sha256", "a" * 64, "--output", str(output), "--press-check"])
    monkeypatch.setattr(ax.signal, "signal", lambda *_a: None)
    monkeypatch.setattr(ax.signal, "alarm", lambda *_a: None)
    def observed(args, report):
        assert args.press_check and not args.press_update
        report["status"] = "check_pressed"
    monkeypatch.setattr(ax, "run", observed)
    assert ax.main() == 0

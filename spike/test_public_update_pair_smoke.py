"""Hermetic public-path admission, real-initiator binding and bounded UI fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import public_update_observer as public
import public_update_menu_smoke as menu
import public_update_pair_smoke as driver
from native_root_update import Refused
from test_packaged_update_observer import (journal, IDENTITY, EXPECTED, STATUSES, UID, START,
                                          private, ack_for, Clock, bare_observer)


@pytest.fixture(autouse=True)
def no_native(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("native command/signal forbidden in public fixture")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)


def original(target):
    return {"pid": 111, "uid": UID, "started": START, "state": "S",
            "command": str(target / "Contents/MacOS/slipstream")}


def public_backend(journal, tmp_path):
    value = public.PublicObserver.__new__(public.PublicObserver)
    value.__dict__.update(bare_observer(journal).__dict__)
    value.args = SimpleNamespace(output_dir=tmp_path, mode="commit")
    value.uid = UID
    value.target = Path(journal["target"])
    value.state = Path(journal["helper"]).parent.parent
    value.journal_path = value.state / "app-update-transaction-v1.json"
    value.ack_path = value.journal_path.with_suffix(".ack.json")
    value.root = tmp_path / "root"
    value.identity = value.manifest = value.initiator = value.last_journal = value.receipt = None
    value.events, value.last_event = [], {}
    value.expected = copy.deepcopy(EXPECTED)
    value.menu = SimpleNamespace(check_click=lambda: None)
    value.tproxy = SimpleNamespace(_daemon_update_identity=lambda item: item,
        _daemon_update_tree=lambda *_a, **_k: EXPECTED["old"]["bundle_tree_sha256"])
    (tmp_path / "normal-old-tray.log").touch()
    return value


def test_capture_binds_normal_app_and_schema2_without_trigger_receipt(journal, tmp_path, monkeypatch):
    value = public_backend(journal, tmp_path)
    process = original(value.target)
    value.process_snapshot = lambda _pid: process
    monkeypatch.setattr(public, "digest", lambda path: "9" * 64 if "watchdog" in path.name else EXPECTED["old"]["app_executable_sha256"])
    value.capture_original(SimpleNamespace(pid=111))
    assert value.initiator == process
    assert value.receipt is None
    value.bind(journal)
    assert value.last_journal == journal and value.identity == IDENTITY
    assert not hasattr(value.args, "trigger_dir")
    changed = copy.deepcopy(journal)
    changed["initiator_pid"] += 1
    with pytest.raises(Refused, match="initiator changed"):
        value.bind(changed)


@pytest.mark.parametrize("change", ["uid", "argv", "hash", "tree", "prior_journal"])
def test_capture_refuses_unproven_original(journal, tmp_path, monkeypatch, change):
    value = public_backend(journal, tmp_path)
    process = original(value.target)
    if change == "uid":
        process["uid"] += 1
    if change == "argv":
        process["command"] += " --prepare"
    if change == "prior_journal":
        private(value.journal_path, journal)
    if change == "tree":
        value.tproxy._daemon_update_tree = lambda *_a, **_k: "wrong"
    value.process_snapshot = lambda _pid: process
    monkeypatch.setattr(public, "digest", lambda _p: "wrong" if change == "hash" else EXPECTED["old"]["app_executable_sha256"])
    with pytest.raises(Refused):
        value.capture_original(SimpleNamespace(pid=111))


def exited_fixture(journal, tmp_path, code=0, current=None):
    value = public_backend(journal, tmp_path)
    value.initiator = original(value.target)
    value.identity = copy.deepcopy(IDENTITY)
    value.original_exited = False
    value.original_process = SimpleNamespace(poll=lambda: code)
    value.process_snapshot = lambda _pid: current
    value.observe_authorization = lambda: None
    return value


def test_normal_exit_uses_owned_waitpid_and_absence_not_synthetic_receipt(journal, tmp_path):
    value = exited_fixture(journal, tmp_path)
    value.read_receipt()
    assert value.original_exited and value.receipt is None
    event = value.events[-1]
    assert event["kind"] == "normal_old_exit" and event["value"]["returncode"] == 0
    assert event["value"]["signal_sent_by_driver"] is False


@pytest.mark.parametrize("code,current,identity", [(-15, None, True), (1, None, True),
    (0, {"pid": 111}, True), (0, None, False)])
def test_exit_rejects_signal_error_reused_pid_and_unobserved_transaction(journal, tmp_path, code, current, identity):
    value = exited_fixture(journal, tmp_path, code, current)
    if not identity:
        value.identity = None
    with pytest.raises(Refused):
        value.read_receipt()
    assert value.original_exited is False


def test_exit_between_waitpid_and_ps_is_observed_without_false_failure(journal, tmp_path):
    value = exited_fixture(journal, tmp_path)
    codes = iter([None, 0])
    value.original_process = SimpleNamespace(poll=lambda: next(codes))
    value.read_receipt()
    assert value.original_exited


@pytest.mark.parametrize("exited,ack,watchdog", [(False, True, True), (True, False, True), (True, True, False)])
def test_commit_does_not_infer_old_exit_ack_or_cleanup(journal, tmp_path, exited, ack, watchdog):
    value = exited_fixture(journal, tmp_path)
    value.original_exited = exited
    value.root_status = copy.deepcopy(STATUSES["committed"])
    value.ack = ack_for(journal) if ack else None
    value.observe_once = lambda: None
    value.status = lambda: value.root_status
    value.watchdog_finished = lambda: watchdog
    value.deadline = 90.1
    diagnostics = []
    value.retain_public_diagnostic = lambda: diagnostics.append(True)
    clock = Clock()
    with pytest.raises(Refused):
        value.wait_transaction(clock=clock, sleep=clock.sleep)
    if exited and not ack and watchdog:
        assert not diagnostics  # Missing ACK is immediately terminal.
    else:
        assert diagnostics == [True] and clock.now >= .1


def test_commit_accepts_complete_real_evidence(journal, tmp_path):
    value = exited_fixture(journal, tmp_path)
    value.original_exited = True
    value.root_status = copy.deepcopy(STATUSES["committed"])
    value.ack = ack_for(journal)
    value.observe_once = lambda: None
    value.status = lambda: value.root_status
    value.watchdog_finished = lambda: True
    value.deadline = 100
    assert value.wait_transaction(clock=lambda: 0)["decision"] == "commit"


def ax_report(process, executable, *, pressed=False):
    title = f"Install Slipstream {menu.VERSION}…"
    return {"status": "update_pressed" if pressed else "inspected",
        "identity": {"pid": process["pid"], "uid": process["uid"], "started": process["started"],
                     "executable": str(executable), "executable_sha256": "a" * 64},
        "actions": [{"kind": "press_update", "attempted": True, "ax_error": 0, "title": title}] if pressed else [],
        "installation_attempted": pressed,
        "update_items": [{"title": title, "enabled": True}]}


@pytest.mark.parametrize("change", [None, "pid", "birth", "hash", "version", "double_click", "ax_error"])
def test_exact_single_menu_action_binding(change, tmp_path):
    process = original(tmp_path)
    executable = tmp_path / "Contents/MacOS/slipstream"
    report = ax_report(process, executable, pressed=True)
    if change in {"pid", "birth", "hash"}:
        report["identity"][{"pid": "pid", "birth": "started", "hash": "executable_sha256"}[change]] = "wrong"
    if change == "version":
        report["actions"][0]["title"] = "Install Slipstream 0.1.9-preview.31…"
    if change == "double_click":
        report["actions"].append(copy.deepcopy(report["actions"][0]))
    if change == "ax_error":
        report["actions"][0]["ax_error"] = -1
    if change is None:
        menu.validate_ax(report, process, executable, "a" * 64, pressed=True)
    else:
        with pytest.raises(Refused):
            menu.validate_ax(report, process, executable, "a" * 64, pressed=True)


def test_helper_environment_never_carries_tokens_or_updater_overrides(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "not-a-real-token")
    monkeypatch.setenv("GITHUB_TOKEN", "not-a-real-token")
    monkeypatch.setenv("SLIPSTREAM_UPDATE_URL", "https://invalid.example")
    for key in ("GITHUB_ACTIONS", "SLIPSTREAM_DISPOSABLE_CI", "RUNNER_OS", "RUNNER_TEMP",
                "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CI", "true")
    env = menu.helper_environment(SimpleNamespace(env={"HOME": "/fixture", "PATH": "/usr/bin"}))
    assert env == {"HOME": "/fixture", "PATH": "/usr/bin", "CI": "true"}


def test_launch_is_ordinary_executable_with_no_flags_or_ci_env(journal, tmp_path):
    value = public_backend(journal, tmp_path)
    value.env = {"HOME": "/fixture", "PATH": "/usr/bin"}
    captured = []
    value.capture_original = lambda child: captured.append(child.pid)
    ui = menu.PublicMenu(value)
    calls = []
    def start(argv, **kwargs):
        calls.append((argv, kwargs["env"]))
        return SimpleNamespace(pid=111)
    (tmp_path / "normal-old-tray.log").unlink()
    ui.launch(start=start)
    ui.close()
    assert calls == [([str(value.target / "Contents/MacOS/slipstream")], value.env)]
    assert captured == [111]


def test_click_is_async_one_shot_and_outcome_required(journal, tmp_path):
    value = public_backend(journal, tmp_path)
    value.initiator = original(value.target)
    value.process_snapshot = lambda _pid: value.initiator
    value.click_attempted = False
    value.env = {}
    ui = menu.PublicMenu(value)
    child = SimpleNamespace(pid=999, poll=lambda: None)
    calls = []
    def start(argv, **kwargs):
        calls.append(argv)
        return child
    ui.press(start=start)
    assert value.click_attempted and len(calls) == 1 and "--press-update" in calls[0]
    assert not ui.click_verified
    with pytest.raises(Refused, match="only once"):
        ui.press(start=start)
    ui.close()


def test_unknown_postclick_cannot_use_preclick_cleanup():
    with pytest.raises(Refused, match="pending public action"):
        driver.cleanup_before_click(SimpleNamespace(click_attempted=True))


def test_public_bytes_binding_refuses_nonpublic_candidate(tmp_path):
    public_dir, candidate = tmp_path / "public", tmp_path / "candidate"
    public_dir.mkdir(); candidate.mkdir()
    names = ["Slipstream.app.tar.gz", "Slipstream.app.tar.gz.sig", "sbom", "audit", "zip", "dmg"]
    manifest = {"artifacts": [{"name": name} for name in names]}
    for folder in (public_dir, candidate):
        (folder / "release-candidate-manifest.json").write_text(json.dumps(manifest))
        for name in names:
            (folder / name).write_text("bytes")
    (candidate / names[0]).write_text("different")
    backend = SimpleNamespace(args=SimpleNamespace(repo=tmp_path, repository="aiwaki/slipstream",
        public_release_metadata=tmp_path / "release", public_tag_ref=tmp_path / "tag",
        public_dir=public_dir, new_candidate_dir=candidate), run=lambda *_a, **_k: SimpleNamespace(stdout=b'{}'))
    with pytest.raises(Refused, match="not the published payload"):
        driver.public_binding(backend)


def test_authorization_observation_records_no_script_argv(journal, tmp_path):
    value = exited_fixture(journal, tmp_path)
    value.last_authorization_poll = 0
    replies = iter([SimpleNamespace(returncode=0, stdout=b"432\n"),
        SimpleNamespace(returncode=0, stdout=f"432 111 {UID} {START} /usr/bin/osascript\n".encode())])
    value.run = lambda *_a, **_k: next(replies)
    public.PublicInitiator.observe_authorization(value, clock=lambda: 2)
    record = value.events[-1]["value"]
    assert record["dialog_interaction_qualified"] is False
    assert record["processes"] == [{"pid": 432, "ppid": 111, "uid": UID, "started": START, "executable": "/usr/bin/osascript"}]


def test_public_driver_order_reuses_real_menu_and_actual_transaction(monkeypatch):
    events = []
    backend = SimpleNamespace(transaction_observed=False, original_exited=True)
    class FakeMenu:
        def __init__(self, owner): assert owner is backend
        def launch(self): events.append("normal_launch")
        def discover(self): events.append("public_offer")
        def press(self): events.append("real_axpress")
        def finish_click(self): events.append("axpress_completed")
    class Visibility:
        def start(self): events.append("visibility_start")
        def set_phase(self, phase): events.append(phase)
    def qualify():
        assert events[-1] == "real_axpress"
        events.append("actual_transaction")
        return {"side": "new"}
    backend.qualify_app = qualify
    monkeypatch.setattr(driver, "install_old", lambda _backend: events.append("install_old"))
    monkeypatch.setattr(driver, "PublicMenu", FakeMenu)
    import public_update_visibility
    monkeypatch.setattr(public_update_visibility, "PublicUpdateVisibility", Visibility)
    report = driver.drive(backend)
    assert events == ["install_old", "visibility_start", "discovery", "normal_launch", "public_offer", "interaction",
                      "real_axpress", "actual_transaction", "axpress_completed", "terminal"]
    assert report["public_update_transaction_qualified"] and not report["public_pair_qualified"]
    assert not report["administrator_dialog_interaction_qualified"] and not report["notification_delivery_qualified"]


def test_background_discovery_is_readonly_until_interaction_before_menu_press(journal, tmp_path, monkeypatch):
    value = public_backend(journal, tmp_path)
    value.uid = os.getuid()
    value.initiator = original(value.target)
    value.original_process = SimpleNamespace(poll=lambda: None)
    value.process_snapshot = lambda _pid: value.initiator
    value.deadline = 720
    value.env = {}
    events = []
    value.visibility = SimpleNamespace(set_phase=lambda phase: events.append(phase))
    state = {"version": 1, "channel": "preview", "highest_seen_version": menu.VERSION, "last_notified_version": None}
    path = value.state / "app-update-state-v1.json"
    clock = Clock()
    def sleep(seconds):
        events.append("readonly_wait")
        private(path, state)
        clock.sleep(seconds)
    def run(command, **_kwargs):
        assert events[-1] == "interaction"
        assert "--open-menu" in command and "--press-update" not in command
        events.append("open_menu")
        output = Path(command[command.index("--output") + 1])
        report = ax_report(value.initiator, value.target / "Contents/MacOS/slipstream")
        report["identity"]["executable_sha256"] = value.expected["old"]["app_executable_sha256"]
        private(output, report)
        return SimpleNamespace(returncode=0)
    value.run = run
    ui = menu.PublicMenu(value)
    ui.discover(clock=clock, sleep=sleep)
    assert events == ["readonly_wait", "interaction", "open_menu"]
    assert value.events[-1]["kind"] == "public_discovery"


@pytest.mark.parametrize("reused", [False, True])
def test_zombie_exit_between_poll_and_ps_reaps_then_rechecks_identity(journal, tmp_path, reused):
    value = exited_fixture(journal, tmp_path)
    codes = iter([None, 0])
    value.original_process = SimpleNamespace(poll=lambda: next(codes))
    zombie = {**value.initiator, "state": "Z", "command": "(slipstream)"}
    replacement = {**value.initiator, "started": "Mon Oct 19 12:35:00 2026"} if reused else None
    snapshots = iter([zombie, replacement])
    value.process_snapshot = lambda _pid: next(snapshots)
    if reused:
        with pytest.raises(Refused, match="PID was reused"):
            value.read_receipt()
        assert not value.original_exited
    else:
        value.read_receipt()
        assert value.original_exited

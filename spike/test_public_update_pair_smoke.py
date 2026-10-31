"""Hermetic public-path admission, real-initiator binding and bounded UI fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
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
    python_process = SimpleNamespace(start=subprocess.Popen, kill=os.kill)
    def forbidden(*_args, **_kwargs):
        pytest.fail("native command/signal forbidden in public fixture")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    return python_process  # Only the explicit inert-Python launch regression uses this.


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
    (tmp_path / "normal-old-tray.log").chmod(0o600)
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


@pytest.mark.parametrize("exited,ack,watchdog,authorized", [(False, True, True, True), (True, False, True, True), (True, True, False, True), (True, True, True, False)])
def test_commit_does_not_infer_old_exit_ack_cleanup_or_authorization(journal, tmp_path, exited, ack, watchdog, authorized):
    value = exited_fixture(journal, tmp_path)
    value.original_exited = exited
    value.authorization_confirmed = authorized
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
    if exited and watchdog and (not ack or not authorized):
        assert not diagnostics  # Missing ACK/authorization is immediately terminal.
    else:
        assert diagnostics == [True] and clock.now >= .1


def test_commit_accepts_complete_real_evidence(journal, tmp_path):
    value = exited_fixture(journal, tmp_path)
    value.authorization_confirmed = True
    value.original_exited = True
    value.root_status = copy.deepcopy(STATUSES["committed"])
    value.ack = ack_for(journal)
    value.observe_once = lambda: None
    value.status = lambda: value.root_status
    value.watchdog_finished = lambda: True
    value.deadline = 100
    assert value.wait_transaction(clock=lambda: 0)["decision"] == "commit"


def test_no_journal_timeout_preserves_actual_failure_and_useful_diagnostic(journal, tmp_path):
    value = public_backend(journal, tmp_path)
    value.original_process = SimpleNamespace(poll=lambda: None)
    value.deadline = 90
    with pytest.raises(Refused, match="normal public update deadline exhausted"):
        value.wait_transaction(clock=lambda: 1)
    completion = next(event["value"] for event in value.events if event["kind"] == "completion_diagnostic")
    assert completion == {"journal_observed": False,
        "paths_present": {"journal": False, "ack": False}, "watchdog": "not_checked_before_journal"}
    assert value.events[-1]["kind"] == "public_completion"
    assert value.events[-1]["value"]["app_phase"] is None
    assert value.events[-1]["value"]["root_phase"] is None


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
        calls.append((argv, kwargs["env"], kwargs["umask"]))
        return SimpleNamespace(pid=111)
    (tmp_path / "normal-old-tray.log").unlink()
    ui.launch(start=start)
    ui.close()
    assert calls == [([str(value.target / "Contents/MacOS/slipstream")], value.env, 0o022)]
    assert captured == [111]


def test_normal_launch_child_permissions_do_not_inherit_private_driver_umask(tmp_path, no_native):
    # Isolate the private umask in an inert Python driver, not the pytest process.
    # It invokes the real PublicMenu.launch/Popen boundary with a Python fixture
    # executable at the expected relative path; no Slipstream payload is used.
    script = textwrap.dedent("""
        import json, os, stat, sys
        from pathlib import Path
        from types import SimpleNamespace
        sys.path.insert(0, sys.argv[1])
        from public_update_menu_smoke import PublicMenu
        root = Path(sys.argv[2])
        executable = root / "inert-python/Contents/MacOS/slipstream"
        executable.parent.mkdir(parents=True)
        executable.write_text("#!" + sys.executable + "\\n"
            "import os\\nfrom pathlib import Path\\n"
            "p = Path(os.environ['FIXTURE_ROOT']) / 'child-dir'\\np.mkdir()\\n"
            "(p / 'data').write_text('inert')\\n")
        executable.chmod(0o755)
        os.umask(0o077)
        backend = SimpleNamespace(target=root / "inert-python",
            args=SimpleNamespace(output_dir=root),
            env={"FIXTURE_ROOT": str(root)}, capture_original=lambda child: None)
        menu = PublicMenu(backend)
        child = menu.launch()
        try:
            assert child.wait(timeout=5) == 0
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            menu.close()
        parent_umask = os.umask(0o077)
        (root / "parent-report").write_text("private")
        modes = {name: stat.S_IMODE((root / name).stat().st_mode)
                 for name in ("child-dir", "child-dir/data", "normal-old-tray.log", "parent-report")}
        print(json.dumps({"parent_umask": parent_umask, "modes": modes}))
    """)
    child = no_native.start([sys.executable, "-c", script, str(REPO / "scripts"), str(tmp_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = child.communicate(timeout=15)
    finally:
        if child.poll() is None:
            no_native.kill(child.pid, 9)
            child.wait(timeout=5)
    assert child.returncode == 0, stderr.decode()
    assert json.loads(stdout) == {"parent_umask": 0o077, "modes": {
        "child-dir": 0o755, "child-dir/data": 0o644,
        "normal-old-tray.log": 0o600, "parent-report": 0o600}}


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


def published_pair(tmp_path, monkeypatch):
    import make_release_manifest
    specs = copy.deepcopy(driver.PUBLIC_RELEASES)
    public_root = tmp_path / "public"
    candidates = {}
    for side, spec in specs.items():
        folder = public_root / side
        assets = folder / "assets"
        candidate = tmp_path / (side + "-candidate")
        assets.mkdir(parents=True); candidate.mkdir()
        candidates[side] = candidate
        names = ["Slipstream-macos-arm64.zip", "Slipstream.app.tar.gz", "Slipstream.app.tar.gz.sig",
                 "Slipstream.spdx.json", "dependency-audit.json", f"Slipstream_{spec['version']}_aarch64.dmg"]
        for name in spec["assets"]:
            (assets / name).write_text(name + side)
        (assets / "release-candidate-manifest.json").write_text(json.dumps({"artifacts": [{"name": n} for n in names]}))
        (assets / "latest.json").write_text(json.dumps({"version": spec["version"], "platforms": {
            "darwin-aarch64": {"url": f"https://github.com/aiwaki/slipstream/releases/download/v{spec['version']}/Slipstream.app.tar.gz",
                                "signature": (assets / "Slipstream.app.tar.gz.sig").read_text()}}}))
        release_manifest = {
            "schema_version": make_release_manifest.MANIFEST_SCHEMA_VERSION,
            "generator": make_release_manifest.MANIFEST_GENERATOR,
            "product": "Slipstream", "repository": "aiwaki/slipstream",
            "version": spec["version"], "tag": "v" + spec["version"], "channel": "preview",
            "source": {"commit": driver.PAIR[side]["source_commit"]},
            "build": {"target": "aarch64-apple-darwin"},
            "artifacts": [{"name": name, "sha256": driver.digest(assets / name),
                           "size": (assets / name).stat().st_size}
                          for name in spec["assets"] if name != "artifact-manifest.json"],
        }
        (assets / "artifact-manifest.json").write_text(json.dumps(release_manifest))
        rows = []
        for name, (asset_id, _size, _sha) in spec["assets"].items():
            payload = (assets / name).read_bytes()
            spec["assets"][name] = [asset_id, len(payload), hashlib.sha256(payload).hexdigest()]
            rows.append({"name": name, "id": asset_id, "size": len(payload), "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                         "state": "uploaded", "browser_download_url": f"https://github.com/aiwaki/slipstream/releases/download/v{spec['version']}/{name}"})
        (folder / "release.json").write_text(json.dumps({"assets": rows, "id": spec["release_id"],
            "tag_name": "v" + spec["version"], "target_commitish": driver.PAIR[side]["source_commit"],
            "name": spec["release_name"], "draft": False, "prerelease": True,
            "published_at": "2026-10-30T10:47:09Z", "body": "Public fixture notes"}))
        (folder / "tag.json").write_text(json.dumps({"ref": "refs/tags/v" + spec["version"],
            "object": {"type": "commit", "sha": driver.PAIR[side]["source_commit"]}}))
        (folder / "tauri.conf.json").write_text(json.dumps({"version": spec["version"]}))
        spec["tauri_config_sha256"] = driver.digest(folder / "tauri.conf.json")
        for name in ["release-candidate-manifest.json", *names]:
            (candidate / name).write_bytes((assets / name).read_bytes())
    monkeypatch.setattr(driver, "PUBLIC_RELEASES", specs)
    commands = []
    def run(command, **_kwargs):
        commands.append([str(x) for x in command])
        return SimpleNamespace(returncode=0, stdout=b'{"verified":true}', stderr=b'')
    return SimpleNamespace(args=SimpleNamespace(repo=tmp_path, repository="aiwaki/slipstream",
        public_root=public_root, old_candidate_dir=candidates["old"], new_candidate_dir=candidates["new"]), run=run, env={"PATH": "/usr/bin:/bin"}), commands


def test_both_public_releases_use_frozen_inventory_and_source_specific_signature_config(tmp_path, monkeypatch):
    backend, commands = published_pair(tmp_path, monkeypatch)
    result = driver.public_binding(backend)
    assert set(result) == {"old", "new"} and all(v["origin"] == "published release" for v in result.values())
    assert len(commands) == 4
    for index, side in enumerate(("old", "new")):
        public, signature = commands[index * 2:index * 2 + 2]
        assert public[1].endswith("verify_published_release.py")
        assert public[public.index("--source-commit") + 1] == driver.PAIR[side]["source_commit"]
        assert public[public.index("--release-id") + 1] == str(driver.PUBLIC_RELEASES[side]["release_id"])
        assert signature[1].endswith("verify_updater_artifacts.py")
        assert signature[signature.index("--tauri-config") + 1] == str(backend.args.public_root / side / "tauri.conf.json")
    assert all("verify_release_artifacts.py" not in " ".join(command) for command in commands)


@pytest.mark.parametrize("side", ["old", "new"])
@pytest.mark.parametrize("mutation", ["candidate", "asset_id", "digest", "size", "url", "duplicate", "missing", "source_config", "extra_candidate"])
def test_public_binding_rejects_drift_on_either_published_side(tmp_path, monkeypatch, side, mutation):
    backend, _ = published_pair(tmp_path, monkeypatch)
    root = backend.args.public_root / side
    candidate = getattr(backend.args, side + "_candidate_dir")
    metadata = json.loads((root / "release.json").read_text())
    row = metadata["assets"][0]
    if mutation == "candidate": (candidate / "Slipstream.app.tar.gz").write_text("different")
    elif mutation == "source_config": (root / "tauri.conf.json").write_text("wrong version or key")
    elif mutation == "extra_candidate": (candidate / "latest.json").write_text("{}")
    elif mutation == "asset_id": row["id"] += 1
    elif mutation == "digest": row["digest"] = "sha256:" + "0" * 64
    elif mutation == "size": row["size"] = True
    elif mutation == "url": row["browser_download_url"] = "https://example.test/redirect"
    elif mutation == "duplicate": metadata["assets"][-1] = row
    elif mutation == "missing": metadata["assets"].pop()
    (root / "release.json").write_text(json.dumps(metadata))
    with pytest.raises(Refused): driver.public_binding(backend)


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


@pytest.mark.parametrize("mode", ["commit", "kill-successor-before-ack"])
def test_public_driver_order_reuses_real_menu_actual_authorization_and_transaction(monkeypatch, mode):
    from contextlib import contextmanager
    events = []
    backend = SimpleNamespace(args=SimpleNamespace(mode=mode), transaction_observed=False,
                              original_exited=True, authorization_confirmed=True)
    class FakeMenu:
        def __init__(self, owner): assert owner is backend
        def launch(self): events.append("normal_launch")
        def discover(self): events.append("public_offer")
        def press(self): events.append("real_axpress")
        def finish_click(self): events.append("axpress_completed")
    class Visibility:
        def start(self): events.append("visibility_start")
        def set_phase(self, phase): events.append(phase)
    @contextmanager
    def admin():
        assert "GH_TOKEN" not in os.environ and "GITHUB_TOKEN" not in os.environ
        events.append("admin_fixture")
        yield "fixture", "private-value"
        events.append("admin_removed")
    backend.configure_authorization = lambda username, password, mode: events.append("authorize_" + mode)
    backend.wait_cancelled = lambda: events.append("cancel_proven") or {"native_cancel_qualified": True}
    backend.reset_after_cancel = lambda: events.append("cancel_reset")
    def qualify():
        assert events[-2:] == ["authorize_confirm", "real_axpress"]
        events.append("actual_transaction")
        return {"side": "new" if mode == "commit" else "old"}
    backend.qualify_app = qualify
    monkeypatch.setattr(driver, "fixture_admin", admin)
    monkeypatch.setenv("GH_TOKEN", "fake-orchestration-token")
    monkeypatch.setattr(driver, "install_old", lambda _backend: events.append("install_old"))
    monkeypatch.setattr(driver, "PublicMenu", FakeMenu)
    import public_update_visibility
    monkeypatch.setattr(public_update_visibility, "PublicUpdateVisibility", Visibility)
    report = driver.drive(backend)
    expected = ["install_old", "visibility_start", "discovery", "normal_launch", "public_offer", "admin_fixture", "interaction"]
    if mode == "commit":
        expected += ["authorize_cancel", "real_axpress", "cancel_proven", "axpress_completed", "cancel_reset", "public_offer"]
    expected += ["authorize_confirm", "real_axpress", "actual_transaction", "axpress_completed", "admin_removed", "terminal"]
    assert events == expected
    assert os.environ["GH_TOKEN"] == "fake-orchestration-token"
    assert report["public_update_transaction_qualified"] and not report["public_pair_qualified"]
    assert report["administrator_dialog_interaction_qualified"] and not report["notification_delivery_qualified"]
    assert report["native_cancel"] == ({"native_cancel_qualified": True} if mode == "commit" else None)
    assert "private-value" not in json.dumps(report)


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


def cancel_rediscovery_fixture(journal, tmp_path, observed_state):
    value = public_backend(journal, tmp_path)
    value.uid = os.getuid()
    value.initiator = original(value.target)
    value.original_process = SimpleNamespace(poll=lambda: None)
    value.process_snapshot = lambda _pid: value.initiator
    value.deadline, value.env = 720, {}
    value.visibility = SimpleNamespace(set_phase=lambda _phase: None)
    private(value.state / "app-update-state-v1.json", {"version": 1, "channel": "preview",
        "highest_seen_version": menu.VERSION, "last_notified_version": menu.VERSION})
    clock, actions = Clock(), []
    def run(command, **_kwargs):
        kind = "check" if "--press-check" in command else "open" if "--open-menu" in command else "inspect"
        assert "--press-update" not in command, "discovery must never install"
        title, enabled = observed_state(clock, actions, kind)
        if kind == "open":
            assert enabled and title in {f"Install Slipstream {menu.VERSION}…", "Check for Updates…"}, \
                "must observe ready menu before opening after Cancel"
        actions.append(kind)
        report = ax_report(value.initiator, value.target / "Contents/MacOS/slipstream")
        report["identity"]["executable_sha256"] = value.expected["old"]["app_executable_sha256"]
        report["update_items"] = [{"title": title, "enabled": enabled}]
        if kind in {"open", "check"}:
            report["status"] = "menu_opened" if kind == "open" else "check_pressed"
            report["actions"] = [{"kind": "open_menu" if kind == "open" else "press_check",
                                  "attempted": True, "ax_error": 0, "title": "" if kind == "open" else title}]
        private(Path(command[command.index("--output") + 1]), report)
        return SimpleNamespace(returncode=0)
    value.run = run
    ui = menu.PublicMenu(value)
    ui.retry_discovery = True  # Only reset_after_cancel enables this production state.
    return value, ui, clock, actions


def test_cancel_rediscovery_accepts_automatic_offer_without_manual_check(journal, tmp_path):
    value, ui, clock, actions = cancel_rediscovery_fixture(journal, tmp_path,
        lambda *_a: (f"Install Slipstream {menu.VERSION}…", True))
    ui.discover(clock=clock, sleep=clock.sleep)
    assert actions == ["inspect", "open"]
    assert ui.retry_discovery is False
    assert value.events[-1]["value"]["method"] == "unmodified_normal_app_automatic_rediscovery_after_cancel"


def test_cancel_rediscovery_only_observes_disabled_install_and_busy_until_ready(journal, tmp_path):
    def state(clock, _actions, _kind):
        if clock.now < 3:
            return f"Install Slipstream {menu.VERSION}…", False
        if clock.now < 6:
            return "Updating…", False
        return f"Install Slipstream {menu.VERSION}…", True
    value, ui, clock, actions = cancel_rediscovery_fixture(journal, tmp_path, state)
    ui.discover(clock=clock, sleep=clock.sleep)
    assert actions == ["inspect", "inspect", "inspect", "open"]
    assert clock.now == 6 and value.events[-1]["kind"] == "public_discovery"


def test_cancel_rediscovery_manual_check_once_then_readonly_offer_wait(journal, tmp_path):
    def state(clock, actions, _kind):
        if "check" not in actions:
            return "Check for Updates…", True
        if clock.now < 6:
            return "Updating…", False
        return f"Install Slipstream {menu.VERSION}…", True
    value, ui, clock, actions = cancel_rediscovery_fixture(journal, tmp_path, state)
    ui.discover(clock=clock, sleep=clock.sleep)
    assert actions == ["inspect", "open", "check", "inspect", "inspect", "open"]
    assert actions.count("check") == 1
    assert value.events[-1]["value"]["method"] == "unmodified_normal_app_manual_rediscovery_after_cancel"


def test_cancel_rediscovery_disabled_menu_expires_without_open_or_check(journal, tmp_path):
    value, ui, clock, actions = cancel_rediscovery_fixture(journal, tmp_path,
        lambda *_a: (f"Install Slipstream {menu.VERSION}…", False))
    value.deadline = 429  # Keep the existing deadline-minus-420 reserve.
    with pytest.raises(Refused, match="discovery bound"):
        ui.discover(clock=clock, sleep=clock.sleep)
    assert actions == ["inspect"] * 3 and clock.now == 9


def test_cancel_rediscovery_refuses_late_readiness_before_any_action(journal, tmp_path):
    def late(clock, _actions, _kind):
        clock.sleep(121)
        return f"Install Slipstream {menu.VERSION}…", True
    _value, ui, clock, actions = cancel_rediscovery_fixture(journal, tmp_path, late)
    with pytest.raises(Refused, match="discovery bound"):
        ui.discover(clock=clock, sleep=clock.sleep)
    assert actions == ["inspect"]


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


class DiscoveryResponse:
    def __init__(self, status=403, headers=None, body=b'{"message":"API rate limit exceeded"}'):
        from email.message import Message
        self.status, self.body, self.read_sizes = status, body, []
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value
    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def read(self, size):
        self.read_sizes.append(size)
        return self.body[:size]


def diagnostic_opener(response):
    calls = []
    def opened(request, timeout):
        calls.append((request, timeout))
        return response
    return SimpleNamespace(open=opened), calls


def test_discovery_diagnostic_matches_public_request_without_auth_or_redirects(monkeypatch):
    response = DiscoveryResponse(headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Limit": "60",
        "X-RateLimit-Reset": "1792500000", "Retry-After": "10", "X-GitHub-Request-Id": "public-id",
        "Content-Type": "application/json", "Set-Cookie": "do-not-retain", "Authorization": "do-not-retain"})
    opener, calls = diagnostic_opener(response)
    handlers = []
    def build(*values):
        handlers.extend(values)
        return opener
    monkeypatch.setattr(menu.urllib.request, "build_opener", build)
    monkeypatch.setenv("GH_TOKEN", "not-a-real-token")
    monkeypatch.setenv("HTTPS_PROXY", "http://invalid.example")
    result = menu.discovery_http_diagnostic()
    assert len(calls) == 1
    request, timeout = calls[0]
    assert request.full_url == "https://api.github.com/repos/aiwaki/slipstream/releases?per_page=10&page=1"
    assert request.method == "GET" and timeout == 5
    assert {name.lower(): value for name, value in request.header_items()} == {
        "user-agent": "Slipstream-Updater/1", "accept": "application/vnd.github+json", "x-github-api-version": "2022-11-28"}
    assert handlers[0].proxies == {}
    assert isinstance(handlers[1], menu.NoRedirect)
    assert handlers[1].redirect_request(None, None, 302, None, {}, "https://invalid.example") is None
    assert set(result["headers"]) == set(menu.DIAGNOSTIC_HEADERS)
    assert result["rate_limit_indicated_by_probe"] is True
    assert result["original_page_unknown"] is True and result["authenticated"] is False
    assert result["attempts"] == 1 and response.read_sizes == [16385]


@pytest.mark.parametrize("status,headers,message,indicated", [
    (403, {}, "Forbidden", False), (403, {"X-RateLimit-Remaining": "59"}, "Forbidden", False),
    (429, {}, "secondary rate limit", True), (403, {"X-RateLimit-Remaining": "0"}, "Forbidden", True),
    (200, {"X-RateLimit-Remaining": "0"}, "API rate limit exceeded", False),
    (302, {"Location": "https://invalid.example"}, "Found", False)])
def test_discovery_diagnostic_does_not_call_every_403_rate_limit(status, headers, message, indicated):
    response = DiscoveryResponse(status, headers, json.dumps({"message": message}).encode())
    opener, calls = diagnostic_opener(response)
    result = menu.discovery_http_diagnostic(opener=opener)
    assert len(calls) == 1 and result["status"] == status
    assert result["rate_limit_indicated_by_probe"] is indicated
    assert "location" not in result["headers"]


def test_discovery_diagnostic_bounds_message_headers_and_body():
    response = DiscoveryResponse(headers={"X-GitHub-Request-Id": "x" * 400},
                                 body=json.dumps({"message": "m" * 900, "other": "omit"}).encode())
    opener, _ = diagnostic_opener(response)
    result = menu.discovery_http_diagnostic(opener=opener)
    assert len(result["message"]) == 512 and len(result["headers"]["x-github-request-id"]) == 256
    response = DiscoveryResponse(body=b"x" * 20000)
    opener, _ = diagnostic_opener(response)
    result = menu.discovery_http_diagnostic(opener=opener)
    assert result["body_truncated"] and result["message"] is None and response.read_sizes == [16385]


def test_discovery_diagnostic_transport_failure_is_fixed_and_not_retried():
    calls = []
    def opened(*_args, **_kwargs):
        calls.append(True)
        raise TimeoutError("freeform diagnostic must not be retained")
    result = menu.discovery_http_diagnostic(opener=SimpleNamespace(open=opened))
    assert calls == [True] and result["error_type"] == "TimeoutError" and result["status"] is None
    assert "freeform" not in json.dumps(result)


def test_logged_discovery_failure_probes_once_without_waiting_or_clicking(journal, tmp_path, monkeypatch):
    value = public_backend(journal, tmp_path)
    value.uid = os.getuid()
    value.initiator = original(value.target)
    value.original_process = SimpleNamespace(poll=lambda: None)
    value.process_snapshot = lambda _pid: value.initiator
    value.env = {"HOME": "/fixture", "PATH": "/usr/bin"}
    value.deadline = 720
    monkeypatch.setenv("GH_TOKEN", "not-a-real-token")
    (tmp_path / "normal-old-tray.log").write_text(
        "update discovery unavailable: preview discovery returned HTTP 403 Forbidden\n")
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout=b'{"kind":"after_failure_probe","status":200}')
    value.run = run
    ui = menu.PublicMenu(value)
    def no_sleep(_seconds): pytest.fail("known discovery failure must not wait")
    with pytest.raises(Refused, match="public discovery failed"):
        ui.discover(clock=lambda: 0, sleep=no_sleep)
    with pytest.raises(Refused, match="public discovery failed"):
        ui.refuse_logged_discovery_failure()
    assert len(calls) == 1
    assert calls[0][0][-1] == "--diagnose-discovery" and "--press-update" not in calls[0][0]
    assert calls[0][1] == {"timeout": 10, "env": value.env}
    assert "GH_TOKEN" not in calls[0][1]["env"]
    assert value.events[0]["value"]["http_status"] == 403
    assert value.events[-1]["value"]["status"] == 200  # Later success cannot turn original failure into pass.


@pytest.mark.parametrize("text", ["", "ordinary background startup\n",
    "other update discovery unavailable: injected text\n", "update discovery unavailable: partial line"])
def test_logged_discovery_diagnostic_requires_complete_owned_failure_line(journal, tmp_path, text):
    value = public_backend(journal, tmp_path)
    value.uid = os.getuid()
    (tmp_path / "normal-old-tray.log").write_text(text)
    value.run = lambda *_a, **_k: pytest.fail("no actual failure: no probe allowed")
    ui = menu.PublicMenu(value)
    ui.refuse_logged_discovery_failure()
    assert not ui.discovery_diagnosed


def test_logged_discovery_diagnostic_refuses_symlink_log_before_any_probe(journal, tmp_path):
    value = public_backend(journal, tmp_path)
    value.uid = os.getuid()
    log = tmp_path / "normal-old-tray.log"
    log.unlink()
    other = private(tmp_path / "other.log", b"update discovery unavailable: failure\n")
    log.symlink_to(other)
    value.run = lambda *_a, **_k: pytest.fail("unsafe log must not trigger probe")
    with pytest.raises(Refused):
        menu.PublicMenu(value).refuse_logged_discovery_failure()


def test_public_preparation_downloads_both_tags_and_keeps_candidate_subsets_only(tmp_path, monkeypatch):
    import shutil
    original, _ = published_pair(tmp_path, monkeypatch)
    destination = tmp_path / "downloaded"
    destination.mkdir()
    pair = tmp_path / "pair"
    pair.mkdir()
    commands = []
    args = SimpleNamespace(repo=tmp_path, repository="aiwaki/slipstream", public_root=destination,
                           gh="/opt/runner-tools/gh")
    def run(command, **kwargs):
        command = [str(x) for x in command]
        commands.append(command)
        if command[0] == args.gh:
            endpoint = command[-1]
            side = next(side for side in ("old", "new") if driver.PUBLIC_RELEASES[side]["version"] in endpoint
                        or driver.PAIR[side]["source_commit"] in endpoint)
            filename = "tauri.conf.json" if "/contents/" in endpoint else "tag.json" if "/git/ref/" in endpoint else "release.json"
            return SimpleNamespace(stdout=(original.args.public_root / side / filename).read_bytes())
        if command[1].endswith("download_github_release_assets.py"):
            version = command[command.index("--tag") + 1][1:]
            side = next(s for s in ("old", "new") if driver.PUBLIC_RELEASES[s]["version"] == version)
            assert kwargs["github"] is True
            assert kwargs["env"]["PATH"].startswith("/opt/runner-tools:")
            shutil.copytree(original.args.public_root / side / "assets", Path(command[command.index("--output") + 1]))
        if command[1].endswith("verify_published_release.py"):
            import verify_published_release
            def value(flag): return command[command.index(flag) + 1]
            try:
                proof = verify_published_release.verify_published_release(
                    release_metadata_path=Path(value("--release-metadata")), tag_ref_path=Path(value("--tag-ref")),
                    release_dir=Path(value("--release-dir")), repository=value("--repository"),
                    version=value("--version"), tag=value("--tag"), channel=value("--channel"),
                    release_name=value("--release-name"), source_commit=value("--source-commit"),
                    target=value("--target"), release_id=int(value("--release-id")), state=value("--state"))
            except ValueError as error:
                if kwargs.get("check", True):
                    raise Refused("real canonical verifier refused: " + str(error)) from error
                return SimpleNamespace(returncode=1, stdout=b"", stderr=("ValueError: " + str(error)).encode())
            return SimpleNamespace(returncode=0, stdout=json.dumps(proof).encode(), stderr=b"")
        return SimpleNamespace(returncode=0, stdout=b'{"verified":true}', stderr=b"")
    backend = SimpleNamespace(args=args, run=run, env={"PATH": "/usr/bin:/bin"})
    driver.prepare_public(backend, pair)
    for side in ("old", "new"):
        candidate = pair / (side + "-candidate")
        assert {p.name for p in candidate.iterdir()} == set(driver.candidate_names(candidate))
        assert len(list(candidate.iterdir())) == 7
        notes = destination / side / "assets" / "release-notes.md"
        assert notes.read_text() == "Public fixture notes\n"
        assert len(list(notes.parent.iterdir())) == 13
        assert len(json.loads((destination / side / "release.json").read_text())["assets"]) == 12
        assert all(driver.digest(p) == driver.digest(destination / side / "assets" / p.name) for p in candidate.iterdir())
    assert len([c for c in commands if c[1].endswith("download_github_release_assets.py")]) == 2
    assert all("actions/artifacts" not in " ".join(c) and "verify_release_artifacts.py" not in " ".join(c) for c in commands)


def test_public_workflow_pins_are_current_dispatch_only_public_assets_and_no_account_gate():
    import re
    import shlex
    source = (REPO / ".github/workflows/public-update-qualification.yml").read_text()
    assert "  push:" not in source and "  pull_request:" not in source and "  workflow_dispatch:" in source
    assert "github.event_name == 'workflow_dispatch'" in source and "github.ref == 'refs/heads/main'" in source
    assert "runs-on: macos-15" in source and 'python-version: "3.13.14"' in source
    assert "environment:" not in source and "secrets." not in source
    assert "old_download" not in source and "name: release-candidate-" not in source
    for side, pin in driver.PAIR.items():
        if side == "schema_version": continue
        for name, key in (("RUN_ID", "run_id"), ("RUN_ATTEMPT", "run_attempt"), ("SOURCE_SHA", "source_commit"), ("MANIFEST_SHA", "candidate_manifest_sha256")):
            assert f'{side.upper()}_{name}: "{pin[key]}"' in source
    assert f'ROOT_GATE_RUN_ID: "{driver.ROOT_GATE[0]}"' in source
    assert f'ROOT_GATE_ATTEMPT: "{driver.ROOT_GATE[1]}"' in source
    assert "qualified-source/scripts/materialize_pair.py" in source
    # Parse the actual executable invocation with the real driver parser. Shell
    # substitutions remain inert strings in this hermetic contract test.
    command = re.search(r'bin/python" scripts/public_update_pair_smoke.py \\\n(.*?)\n          # The driver', source, re.S).group(1)
    command = command.replace("$ROOT_GATE_RUN_ID", str(driver.ROOT_GATE[0])).replace("$ROOT_GATE_ATTEMPT", str(driver.ROOT_GATE[1])).replace("$CASE_MODE", "commit")
    parsed = driver.parse_args(shlex.split(command.replace("\\\n", " ")))
    assert parsed.public_root == Path("$RUNNER_TEMP/public-releases")
    assert parsed.old_candidate_dir == Path("$RUNNER_TEMP/public-update-pair/old-candidate")
    assert parsed.new_candidate_dir == Path("$RUNNER_TEMP/public-update-pair/new-candidate")
    assert source.index("id: public_download") < source.index("id: materialize") < source.index("id: qualify")
    assert "commit (Cancel then confirm) first" in source


@pytest.mark.parametrize("failure", ["cancel_raises", "cancel_unproven", "reset_refuses"])
def test_public_driver_never_retries_an_unproven_native_cancel(monkeypatch, failure):
    from contextlib import nullcontext
    events = []
    backend = SimpleNamespace(args=SimpleNamespace(mode="commit"), transaction_observed=False,
                              original_exited=False, authorization_confirmed=False)
    backend.configure_authorization = lambda _u, _p, mode: events.append(mode)
    def cancelled():
        if failure == "cancel_raises": raise Refused("cancel outcome unknown")
        return {"native_cancel_qualified": failure != "cancel_unproven"}
    backend.wait_cancelled = cancelled
    backend.reset_after_cancel = lambda: (_ for _ in ()).throw(Refused("cancel ownership changed"))
    backend.qualify_app = lambda: pytest.fail("an uncertain cancellation cannot authorize another update")
    class FakeMenu:
        def __init__(self, _owner): pass
        def launch(self): pass
        def discover(self): events.append("discover")
        def press(self): events.append("press")
        def finish_click(self): pass
    import public_update_visibility
    monkeypatch.setattr(public_update_visibility, "PublicUpdateVisibility", lambda: SimpleNamespace(start=lambda: None, set_phase=lambda _p: None))
    monkeypatch.setattr(driver, "PublicMenu", FakeMenu)
    monkeypatch.setattr(driver, "install_old", lambda _b: None)
    monkeypatch.setattr(driver, "fixture_admin", lambda: nullcontext(("fixture", "private-value")))
    monkeypatch.setenv("GH_TOKEN", "fake-token")
    with pytest.raises(Refused): driver.drive(backend)
    assert events == ["discover", "cancel", "press"]
    assert not backend.transaction_observed
    assert os.environ["GH_TOKEN"] == "fake-token"


def test_public_metadata_is_refetched_after_transaction_and_final_drift_is_refused(tmp_path, monkeypatch):
    backend, commands = published_pair(tmp_path, monkeypatch)
    backend.args.gh = "/usr/bin/gh"
    ordinary = backend.run
    def run(command, **kwargs):
        if command[0] == backend.args.gh:
            side = next(side for side, spec in driver.PUBLIC_RELEASES.items() if spec["version"] in command[-1])
            name = "tag.json" if "/git/ref/" in command[-1] else "release.json"
            return SimpleNamespace(stdout=(backend.args.public_root / side / name).read_bytes())
        return ordinary(command, **kwargs)
    backend.run = run
    result = driver.refresh_public_metadata(backend)
    assert set(result) == {"old", "new"}
    assert all(any(str(backend.args.public_root / side / "release.final.json") in command for command in commands) for side in result)
    for side in result:
        assert (backend.args.public_root / side / "release.json").exists()
        (backend.args.public_root / side / "release.final.json").unlink()
        (backend.args.public_root / side / "tag.final.json").unlink()
    metadata = json.loads((backend.args.public_root / "new" / "release.json").read_text())
    metadata["assets"][0]["id"] += 1
    (backend.args.public_root / "new" / "release.json").write_text(json.dumps(metadata))
    with pytest.raises(Refused, match="identity changed"):
        driver.refresh_public_metadata(backend)


def test_auth_helper_dependencies_are_bound_to_the_qualified_product_source():
    assert {"stop_quit_ui_smoke.py", "geph_owned_lifecycle_smoke.py"} <= set(driver.REUSED)
    source = Path(driver.__file__).read_text()
    assert source.index('result.update(drive(backend), status="passed")') < source.index('result["public_release_final"] = refresh_public_metadata(backend)')


@pytest.mark.parametrize("kind", ["publication", "updater-signature"])
def test_fixed_public_validator_failure_retains_bounded_stderr_without_tokens_or_argv(tmp_path, monkeypatch, kind):
    backend, _ = published_pair(tmp_path, monkeypatch)
    backend.env["GH_TOKEN"] = "private-env-token"
    backend.env["GITHUB_TOKEN"] = "another-private-token"
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        failed = str(command[1]).endswith("verify_published_release.py") if kind == "publication" else str(command[1]).endswith("verify_updater_artifacts.py")
        return SimpleNamespace(returncode=1 if failed else 0, stdout=b"private-stdout" if failed else b"{}",
                               stderr=b"Traceback:\n" + b"x" * 10000 + b"\nValueError: fixed public validation failed\n")
    backend.run = run
    with pytest.raises(Refused, match="bounded diagnostic retained"):
        driver.verify_public_side(backend, "old")
    record = json.loads((backend.args.public_root / "old" / (kind + "-failure.json")).read_text())
    assert record["returncode"] == 1 and record["validator"] == kind
    assert record["stderr"]["truncated"] is True
    assert record["stderr"]["text"].startswith("Traceback:")
    assert "ValueError: fixed public validation failed" in record["stderr"]["text"]
    assert len(record["stderr"]["text"]) < 4200 and record["stdout_omitted"] is True
    assert all(call[1]["check"] is False and "GH_TOKEN" not in call[1]["env"] and "GITHUB_TOKEN" not in call[1]["env"] for call in calls)
    assert all(secret not in json.dumps(record) for secret in ("private-env-token", "another-private-token", "private-stdout"))
    assert "argv" not in record and "env" not in record


def test_validator_diagnostics_cannot_be_enabled_for_an_unrelated_command(tmp_path, monkeypatch):
    backend, _ = published_pair(tmp_path, monkeypatch)
    backend.run = lambda *_a, **_k: pytest.fail("an unrelated command must never execute")
    with pytest.raises(Refused, match="fixed public validator"):
        driver.run_public_validator(backend, [sys.executable, tmp_path / "private.py"],
                                    public=tmp_path, kind="publication")

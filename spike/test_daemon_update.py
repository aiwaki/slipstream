"""Hermetic daemon-updater protocol tests: no launchd, PF or privileged CLI."""
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import tproxy


ROOT = Path(__file__).resolve().parents[1]
NONCE = "0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def no_native_effects(monkeypatch):
    monkeypatch.setattr(tproxy, "_run", lambda *a: pytest.fail("native command forbidden in updater unit tests"))


def identity():
    return {
        "schema_version": 1, "nonce": NONCE, "uid": 501,
        "old_version": "0.1.9-preview.24", "new_version": "0.1.9-preview.25",
        "old_app_executable_sha256": "1" * 64, "new_app_executable_sha256": "2" * 64,
        "old_daemon_sha256": "3" * 64, "new_daemon_sha256": "4" * 64,
        "old_bundle_tree_sha256": "5" * 64, "new_bundle_tree_sha256": "6" * 64,
        "archive_sha256": "7" * 64, "prepare_deadline_unix": 4102444800,
    }


def proof(sha):
    return {"daemon_pid": 100, "daemon_sha256": sha, "heartbeat_seq": 4,
            "install_attestation_sha256": "8" * 64}


def journal():
    value = {
        "identity": identity(), "phase": "prepared", "decision": None,
        "accepted_sequence": 0, "deadline_unix": 4102444800,
        "worker_pid": 0, "writer_quiescent": True, "error": None,
        "old_plist": {"ProgramArguments": ["/usr/local/slipstream/slipstreamd", "--port", "1080"]},
        "old_plist_sha256": "9" * 64, "old_payload_sha256": "a" * 64,
        "worker_runtime_sha256": "b" * 64, "old_runtime_sha256": None,
        "predecessor_nonce": None,
        "snapshot_ready": False, **proof(identity()["old_daemon_sha256"]),
    }
    value["manifest_sha256"] = tproxy._daemon_update_manifest(value)
    return value


@pytest.fixture
def machine(monkeypatch):
    events = []
    writes = []
    def publish(value, **changes):
        value.update(changes)
        events.append(("publish", value["phase"], value["decision"], value["writer_quiescent"]))
        writes.append(copy.deepcopy(value))
    monkeypatch.setattr(tproxy, "_daemon_update_publish", publish)
    monkeypatch.setattr(tproxy.time, "time", lambda: 4102444600)
    monkeypatch.setattr(tproxy, "_daemon_update_runtime_proof", lambda sha: proof(sha))
    monkeypatch.setattr(tproxy, "_daemon_update_tree", lambda *args, **kwargs: "a" * 64)
    def restore(value):
        events.append(("restore", value["decision"]))
        return proof(value["identity"]["old_daemon_sha256"])
    monkeypatch.setattr(tproxy, "_daemon_update_restore_old", restore)
    monkeypatch.setattr(tproxy, "_daemon_update_refresh_terminal", lambda _: events.append(("refresh",)))
    monkeypatch.setattr(tproxy, "_run", lambda *a: pytest.fail("native command forbidden"))
    monkeypatch.setattr(tproxy, "do_install", lambda *a, **k: pytest.fail("installer forbidden"))
    return events, writes


def requests(monkeypatch, actions):
    iterator = iter(enumerate(actions, 1))
    def next_request(_):
        sequence, action = next(iterator)
        return {"schema_version": 1, "nonce": NONCE, "sequence": sequence, "action": action}
    monkeypatch.setattr(tproxy, "_daemon_update_request", next_request)


def test_activated_success_commits_one_decision_after_ready(machine, monkeypatch):
    events, writes = machine
    requests(monkeypatch, ["activate", "commit"])
    def activate(value):
        events.append(("activate", value["accepted_sequence"]))
        tproxy._daemon_update_publish(value, phase="ready", writer_quiescent=True, snapshot_ready=True,
                                     **proof(identity()["new_daemon_sha256"]))
    monkeypatch.setattr(tproxy, "_daemon_update_activate", activate)
    value = journal()
    assert tproxy._daemon_update_worker_loop(value)
    assert value["decision"] == "commit" and value["phase"] == "committed"
    assert value["accepted_sequence"] == 2 and value["writer_quiescent"]
    assert not any(event[0] == "restore" for event in events)
    assert all(item["decision"] != "abort" for item in writes)
    assert writes[0]["worker_pid"] > 0 and writes[0]["writer_quiescent"]


def test_cancel_before_activation_does_not_restart_healthy_old_daemon(machine, monkeypatch):
    events, _ = machine
    requests(monkeypatch, ["abort"])
    value = journal()
    assert tproxy._daemon_update_worker_loop(value)
    assert (value["phase"], value["decision"], value["writer_quiescent"]) == ("aborted", "abort", True)
    assert not any(event[0] == "restore" for event in events)


def test_original_deadline_expiry_aborts_without_reading_late_commit(machine, monkeypatch):
    monkeypatch.setattr(tproxy, "_daemon_update_request", lambda _: pytest.fail("late request consumed"))
    value = journal()
    value.update(deadline_unix=4102444500, phase="ready", snapshot_ready=True)
    assert tproxy._daemon_update_worker_loop(value)
    assert value["decision"] == "abort" and value["phase"] == "aborted"


def test_worker_crash_before_commit_restores_old_and_does_not_reactivate(machine, monkeypatch):
    events, _ = machine
    monkeypatch.setattr(tproxy, "_daemon_update_request", lambda _: pytest.fail("replayed request after crash"))
    value = journal()
    value.update(worker_pid=999, phase="activating", snapshot_ready=True, activation_started=True)
    assert tproxy._daemon_update_worker_loop(value)
    assert ("restore", "abort") in events
    assert value["decision"] == "abort" and value["writer_quiescent"]


def test_lost_commit_reply_preserves_commit_across_worker_restart(machine, monkeypatch):
    events, writes = machine
    monkeypatch.setattr(tproxy, "_daemon_update_request", lambda _: pytest.fail("abort request cannot reverse commit"))
    value = journal()
    value.update(worker_pid=999, phase="committing", decision="commit", snapshot_ready=True)
    assert tproxy._daemon_update_worker_loop(value)
    assert value["phase"] == "committed"
    assert not any(event[0] == "restore" for event in events)
    assert not any(item["decision"] == "abort" for item in writes)


def test_abort_does_not_publish_quiescent_until_restoration_completes(machine, monkeypatch):
    _, writes = machine
    value = journal()
    value.update(phase="ready", snapshot_ready=True)
    requests(monkeypatch, ["abort"])
    def failed_restore(_):
        raise RuntimeError("owned process still running")
    monkeypatch.setattr(tproxy, "_daemon_update_restore_old", failed_restore)
    assert not tproxy._daemon_update_worker_loop(value)
    assert value["phase"] == "recovery_incomplete" and value["decision"] == "abort"
    assert not value["writer_quiescent"]
    assert not any(item["phase"] == "aborted" for item in writes)


def test_activation_failure_aborts_then_restores(machine, monkeypatch):
    events, _ = machine
    requests(monkeypatch, ["activate"])
    def fail(value):
        value["snapshot_ready"] = True
        raise RuntimeError("install failed after new launch")
    monkeypatch.setattr(tproxy, "_daemon_update_activate", fail)
    value = journal()
    assert tproxy._daemon_update_worker_loop(value)
    assert value["phase"] == "aborted" and ("restore", "abort") in events


def test_terminal_worker_never_reinstalls_or_consumes_request(machine, monkeypatch):
    monkeypatch.setattr(tproxy, "_daemon_update_request", lambda _: pytest.fail("terminal request read"))
    value = journal()
    value.update(phase="committed", decision="commit", writer_quiescent=True)
    assert tproxy._daemon_update_worker_loop(value)
    assert machine[0][0] == ("refresh",)


@pytest.mark.parametrize("phase,decision", [("committed", "commit"), ("aborted", "abort")])
def test_terminal_wake_unready_exits_success_without_keepalive_or_decision_replay(machine, monkeypatch, phase, decision):
    value = journal()
    value.update(phase=phase, decision=decision, writer_quiescent=True, accepted_sequence=2)
    before = copy.deepcopy(value)
    calls = []
    def unavailable(_):
        calls.append("refresh")
        raise RuntimeError("selected daemon is still starting")
    monkeypatch.setattr(tproxy, "_daemon_update_refresh_terminal", unavailable)
    monkeypatch.setattr(tproxy, "_daemon_update_request", lambda _: pytest.fail("late decision consumed"))
    monkeypatch.setattr(tproxy, "_daemon_update_resolve", lambda _: pytest.fail("terminal runtime reinstalled"))
    assert tproxy._daemon_update_worker_loop(value) is True
    assert calls == ["refresh"] and value == before and machine[1] == []


def test_snapshot_is_copied_only_after_quiescence_and_before_new_install(monkeypatch, tmp_path):
    events = []
    value = journal()
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_ROOT", str(tmp_path))
    monkeypatch.setattr(tproxy, "_daemon_update_read_plist", lambda: ({}, value["old_plist_sha256"]))
    monkeypatch.setattr(tproxy, "_daemon_update_require_enabled_intent", lambda: None)
    monkeypatch.setattr(tproxy, "_daemon_update_runtime_proof", lambda sha: proof(sha))
    monkeypatch.setattr(tproxy, "_daemon_update_verify_app", lambda *args: None)
    monkeypatch.setattr(tproxy, "_daemon_update_publish", lambda v, **changes: v.update(changes))
    def stop(*args, **kwargs):
        assert kwargs["remove_runtime"] is False
        events.append("quiesce")
        return True
    monkeypatch.setattr(tproxy, "_disable_and_cleanup_install", stop)
    def tree(*args, **kwargs):
        if kwargs.get("copy_to"):
            events.append("snapshot")
        return "a" * 64
    monkeypatch.setattr(tproxy, "_daemon_update_tree", tree)
    def install(*args, **kwargs):
        assert value["snapshot_ready"] and value["old_runtime_sha256"] == "a" * 64
        assert kwargs["frozen_source"].endswith("new.app/Contents/Resources/slipstreamd/slipstreamd")
        assert kwargs["browser_worker_override"].endswith("new.app/Contents/MacOS/slipstream-browser-probe")
        events.append("install")
        return True
    monkeypatch.setattr(tproxy, "do_install", install)
    tproxy._daemon_update_activate(value)
    assert events == ["quiesce", "snapshot", "install"]
    assert value["phase"] == "ready" and value["writer_quiescent"]


def test_real_status_unwrap_heartbeat_is_used(monkeypatch, tmp_path):
    status_path = tmp_path / "status.json"
    sha = "3" * 64
    daemon = {"state": "dormant", "pid": 100, "heartbeat_seq": 7, "updated_at": 1000}
    status_path.write_text(json.dumps({"schema_version": 2, "daemon": daemon}))
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))
    actual = tproxy._daemon_status_record()
    assert actual["heartbeat_seq"] == 7 and "daemon" not in actual
    monkeypatch.setattr(tproxy, "_installed_daemon_readiness_snapshot", lambda _: (True, "ready", actual, False))
    record = {"schema_version": tproxy.INSTALL_ATTESTATION_SCHEMA_VERSION, "source_sha256": sha,
              "daemon": {"sha256": sha}, "launchd": {"pid": 100}}
    monkeypatch.setattr(tproxy, "_update_read_json", lambda *a, **k: record)
    monkeypatch.setattr(tproxy, "_sha256_regular_file", lambda _: sha)
    monkeypatch.setattr(tproxy, "_install_attestation_record", lambda *a, **k: record)
    assert tproxy._daemon_update_runtime_proof(sha)["heartbeat_seq"] == 7


@pytest.mark.parametrize("vector", json.loads((ROOT / "contracts/update-bundle-tree-v1.json").read_text())["vectors"], ids=lambda v: v["name"])
def test_tree_shared_vectors_and_copied_identity(vector, tmp_path):
    source = tmp_path / "source.app"
    source.mkdir()
    for node in vector["nodes"]:
        path = source / node["path"]
        if node["kind"] == "directory":
            path.mkdir()
        elif node["kind"] == "symlink":
            path.symlink_to(node["target"])
            if hasattr(os, "lchmod"):
                os.lchmod(path, node["mode"])
        else:
            path.write_text(node["content"], encoding="utf-8")
        if node["kind"] != "symlink":
            path.chmod(node["mode"])
    destination = tmp_path / "copy.app"
    assert tproxy._daemon_update_tree(source, copy_to=str(destination), readable=True) == vector["expected_sha256"]
    assert tproxy._daemon_update_tree(destination, readable=True) == vector["expected_sha256"]


def test_chained_symlink_escape_rejected(tmp_path):
    app = tmp_path / "app"
    (app / "d").mkdir(parents=True)
    (app / "a").mkdir()
    (tmp_path / "outside").write_text("outside")
    (app / "d/link").symlink_to("../a")
    (app / "d/escape").symlink_to("link/../../outside")
    with pytest.raises(RuntimeError, match="alias"):
        tproxy._daemon_update_tree(app)


def test_mutable_secret_excluded_only_for_payload_identity(tmp_path):
    (tmp_path / "slipstreamd").write_text("binary")
    secret = tmp_path / "tgws-secret"
    secret.write_text("old local secret")
    payload = tproxy._daemon_update_tree(tmp_path, exclude_names=("tgws-secret",))
    whole = tproxy._daemon_update_tree(tmp_path)
    secret.write_text("changed local secret")
    assert tproxy._daemon_update_tree(tmp_path, exclude_names=("tgws-secret",)) == payload
    assert tproxy._daemon_update_tree(tmp_path) != whole


def test_manifest_binds_privileged_runtime_and_launch_intent():
    value = journal()
    original = tproxy._daemon_update_manifest(value)
    for key in ("old_plist_sha256", "old_payload_sha256", "worker_runtime_sha256"):
        changed = copy.deepcopy(value)
        changed[key] = "f" * 64
        assert tproxy._daemon_update_manifest(changed) != original


@pytest.mark.parametrize("key,bad", [("uid", True), ("prepare_deadline_unix", 0), ("prepare_deadline_unix", True), ("prepare_deadline_unix", 2**64), ("nonce", "../bad"), ("old_daemon_sha256", "G" * 64)])
def test_identity_rejects_invalid_authorization_fields(key, bad):
    value = identity()
    value[key] = bad
    with pytest.raises(RuntimeError):
        tproxy._daemon_update_identity(value)


def test_actual_public_status_projection_matches_rust_wire_vectors(monkeypatch):
    captured = []
    monkeypatch.setattr(tproxy, "_update_write_json", lambda path, value, mode=0o600: captured.append((path, copy.deepcopy(value), mode)))
    vectors = json.loads((ROOT / "contracts/update-daemon-status-v1.json").read_text())["vectors"]
    for vector in vectors:
        expected = vector["status"]
        value = journal()
        side = "new" if expected["phase"] in {"ready", "committed"} else "old"
        tproxy._daemon_update_publish(value, phase=expected["phase"], decision=expected["decision"],
                                     worker_pid=101, writer_quiescent=True,
                                     **proof(value["identity"][side + "_daemon_sha256"]))
        assert captured[-1][1] == expected and captured[-1][2] == 0o644
        assert captured[-2][0].endswith("/private/journal.json")
        assert "old_plist" not in expected and "snapshot_ready" not in expected


def test_commit_recovery_preserves_retained_secret_and_no_voice(machine, monkeypatch, tmp_path):
    value = journal()
    value.update(decision="commit", phase="committing", snapshot_ready=True)
    value["old_plist"]["ProgramArguments"].append("--no-voice")
    calls = []
    attempts = iter([False, True])
    def runtime(sha):
        if not next(attempts):
            raise RuntimeError("current runtime disappeared")
        return proof(sha)
    monkeypatch.setattr(tproxy, "_daemon_update_runtime_proof", runtime)
    monkeypatch.setattr(tproxy, "_daemon_update_verify_app", lambda *a: None)
    monkeypatch.setattr(tproxy, "_daemon_update_retained_secret", lambda _: "retained-secret")
    monkeypatch.setattr(tproxy, "do_install", lambda *a, **k: calls.append(k) or True)
    tproxy._daemon_update_resolve(value)
    assert value["phase"] == "committed" and value["decision"] == "commit"
    assert calls[0]["secret_backup"] == "retained-secret"
    assert calls[0]["program_tail"] == ["--port", "1080", "--no-voice"]
    assert value["selected_payload_sha256"] == "a" * 64


def test_predecessor_blocks_older_orphan_from_claiming_later_terminal_index(monkeypatch, tmp_path):
    path = tmp_path / "active.json"
    path.write_text("placeholder")
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_ROOT", str(tmp_path))
    monkeypatch.setattr(tproxy, "_update_read_json", lambda *a, **k: {"nonce": "f" * 32})
    with pytest.raises(RuntimeError, match="later daemon update"):
        tproxy._daemon_update_check_predecessor(journal())


def test_retired_pruning_retains_everything_when_probe_ownership_unknown(monkeypatch, tmp_path):
    retained = tmp_path / NONCE
    retained.mkdir()
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_ROOT", str(tmp_path))
    monkeypatch.setattr(tproxy, "_installed_browser_worker_from_launchd", lambda: None)
    tproxy._daemon_update_prune_retired("f" * 32)
    assert retained.is_dir()


def test_terminal_refresh_does_not_overwrite_later_payload(monkeypatch):
    value = journal()
    value.update(phase="committed", decision="commit", selected_payload_sha256="c" * 64)
    monkeypatch.setattr(tproxy, "_update_read_json", lambda *a, **k: {"nonce": NONCE})
    monkeypatch.setattr(tproxy, "_installed_daemon_readiness_snapshot", lambda _: (True, "ready", {}, False))
    monkeypatch.setattr(tproxy, "_daemon_update_tree", lambda *a, **k: "d" * 64)
    monkeypatch.setattr(tproxy, "_write_install_attestation", lambda *a, **k: pytest.fail("overwriting later manual install"))
    tproxy._daemon_update_refresh_terminal(value)


def test_terminal_refresh_checks_readiness_before_hashing_installed_tree(monkeypatch):
    value = journal()
    value.update(phase="committed", decision="commit", selected_payload_sha256="c" * 64)
    monkeypatch.setattr(tproxy, "_update_read_json", lambda *a, **k: {"nonce": NONCE})
    monkeypatch.setattr(tproxy, "_installed_daemon_readiness_snapshot", lambda _: (False, "starting", None, False))
    monkeypatch.setattr(tproxy, "_daemon_update_tree", lambda *a, **k: pytest.fail("unready daemon caused full tree hash"))
    with pytest.raises(RuntimeError, match="not ready"):
        tproxy._daemon_update_refresh_terminal(value)


def test_terminal_worker_entry_exits_unready_before_hashing_retained_trees(monkeypatch, tmp_path):
    from contextlib import nullcontext
    value = journal()
    value.update(phase="aborted", decision="abort", writer_quiescent=True)
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_ROOT", str(tmp_path))
    monkeypatch.setattr(tproxy.sys, "frozen", True, raising=False)
    monkeypatch.setattr(tproxy.sys, "executable", str(tmp_path / NONCE / "private/worker-runtime/slipstreamd"))
    monkeypatch.setattr(tproxy, "_installer_operation_lock", lambda *a, **k: nullcontext())
    monkeypatch.setattr(tproxy, "_update_read_json", lambda *a, **k: value)
    monkeypatch.setattr(tproxy, "_installed_daemon_readiness_snapshot", lambda _: (False, "starting", None, False))
    monkeypatch.setattr(tproxy, "_daemon_update_tree", lambda *a, **k: pytest.fail("unready daemon caused retained tree hash"))
    monkeypatch.setattr(tproxy, "_daemon_update_publish", lambda *a, **k: pytest.fail("unready terminal receipt changed"))
    assert tproxy.do_update_worker(NONCE) is True


@pytest.mark.parametrize("phase,decision,side", [("committed", "commit", "new"), ("aborted", "abort", "old")])
def test_terminal_wake_rebinds_same_payload_new_pid_without_reinstall(monkeypatch, phase, decision, side):
    value = journal()
    value.update(phase=phase, decision=decision, selected_payload_sha256="c" * 64, accepted_sequence=2)
    monkeypatch.setattr(tproxy, "_update_read_json", lambda *a, **k: {"nonce": NONCE})
    monkeypatch.setattr(tproxy, "_daemon_update_tree", lambda *a, **k: "c" * 64)
    monkeypatch.setattr(tproxy, "_installed_daemon_readiness_snapshot", lambda _: (True, "ready", {"pid": 202}, False))
    writes = []
    monkeypatch.setattr(tproxy, "_write_install_attestation", lambda *a, **k: writes.append(a))
    monkeypatch.setattr(tproxy, "_daemon_update_runtime_proof", lambda sha: {**proof(sha), "daemon_pid": 202})
    monkeypatch.setattr(tproxy, "_daemon_update_publish", lambda v, **k: v.update(k))
    monkeypatch.setattr(tproxy, "do_install", lambda *a, **k: pytest.fail("reinstall forbidden"))
    monkeypatch.setattr(tproxy, "_daemon_update_request", lambda _: pytest.fail("late decision consumed"))
    assert tproxy._daemon_update_worker_loop(value)
    assert value["daemon_pid"] == 202 and value["decision"] == decision and len(writes) == 1
    assert value["phase"] == phase and value["accepted_sequence"] == 2 and value["writer_quiescent"]
    assert value["daemon_sha256"] == identity()[side + "_daemon_sha256"]
    assert writes[0][1] == identity()[side + "_daemon_sha256"]


@pytest.mark.parametrize("absent", [True, False])
def test_uninstall_drains_update_job_before_removing_retained_slots(monkeypatch, tmp_path, absent):
    operation = tmp_path / NONCE
    operation.mkdir()
    (tmp_path / "active.json").write_text("active")
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_ROOT", str(tmp_path))
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_REQUESTS", str(tmp_path / "requests"))
    value = journal()
    value.update(phase="aborted", decision="abort", writer_quiescent=True)
    monkeypatch.setattr(tproxy, "_update_read_json", lambda *a, **k: value)
    def run(*args):
        assert operation.exists()
        return SimpleNamespace(returncode=113 if absent else 0, stdout="", stderr="Could not find service" if absent else "")
    monkeypatch.setattr(tproxy, "_run", run)
    monkeypatch.setattr(tproxy, "_daemon_update_worker_plist", lambda _: str(tmp_path / "worker.plist"))
    monkeypatch.setattr(tproxy, "_process_command_for_pid", lambda _: None)
    assert tproxy._daemon_update_remove_retained() is absent
    assert operation.exists() is not absent
    assert (tmp_path / "active.json").exists() is not absent


def test_disabled_launch_intent_is_never_enabled_by_prepare(monkeypatch):
    monkeypatch.setattr(tproxy, "_run", lambda *a: SimpleNamespace(returncode=0, stdout='disabled services = { "dev.slipstream.tproxy" => true }'))
    with pytest.raises(RuntimeError, match="deliberately disabled"):
        tproxy._daemon_update_require_enabled_intent()


@pytest.fixture
def prepared_filesystem(monkeypatch, tmp_path):
    from contextlib import contextmanager
    uid = os.getuid()
    root = tmp_path / "updater"
    root.mkdir()
    requests_root = tmp_path / "requests"
    installed = tmp_path / "installed"
    installed.mkdir(mode=0o700)
    (installed / "slipstreamd").write_text("old daemon")
    (installed / "slipstreamd").chmod(0o700)
    apps = tmp_path / "apps"
    apps.mkdir()
    old = apps / "Slipstream.app"
    new = apps / (".Slipstream.app.slipstream-stage-" + NONCE)
    value = identity()
    value["uid"] = uid
    for side, app in (("old", old), ("new", new)):
        binary = app / "Contents/Resources/slipstreamd/slipstreamd"
        binary.parent.mkdir(parents=True)
        binary.write_text(side + " daemon")
        binary.chmod(0o755)
        executable = app / "Contents/MacOS/slipstream"
        executable.parent.mkdir(parents=True)
        executable.write_text(side + " tray")
        executable.chmod(0o755)
        for path in [app, app / "Contents", binary.parent.parent, binary.parent, executable.parent]:
            path.chmod(0o755)
        value[side + "_bundle_tree_sha256"] = tproxy._daemon_update_tree(app, readable=True)
        value[side + "_daemon_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        value[side + "_app_executable_sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_ROOT", str(root))
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_REQUESTS", str(requests_root))
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_TARGET", str(old))
    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(installed))
    monkeypatch.setattr(tproxy.sys, "frozen", True, raising=False)
    monkeypatch.setattr(tproxy.sys, "executable", str(installed / "slipstreamd"))
    monkeypatch.setattr(tproxy, "_console_probe_identity", lambda: (uid, os.getgid(), str(tmp_path)))
    monkeypatch.setattr(tproxy.time, "time", lambda: 4102444600)
    monkeypatch.setattr(tproxy, "_daemon_update_runtime_proof", lambda sha: proof(sha))
    monkeypatch.setattr(tproxy, "_daemon_update_require_enabled_intent", lambda: None)
    monkeypatch.setattr(tproxy, "_daemon_update_verify_app", lambda *a: None)
    monkeypatch.setattr(tproxy, "_daemon_update_read_plist", lambda: ({"ProgramArguments": [str(installed / "slipstreamd"), "--port", "1080"]}, "9" * 64))
    monkeypatch.setattr(tproxy, "_daemon_update_prune_retired", lambda _: None)
    monkeypatch.setattr(tproxy, "_daemon_update_worker_plist", lambda n: str(tmp_path / (n + ".plist")))
    monkeypatch.setattr(tproxy.os, "fchown", lambda *a: None)
    real_read = tproxy._update_read_json
    monkeypatch.setattr(tproxy, "_update_read_json", lambda path, **kw: real_read(path, **{**kw, "owner": uid}))
    real_lstat = os.lstat
    def lstat(path, **kw):
        metadata = real_lstat(path, **kw)
        if os.fspath(path) == str(installed):
            fields = list(metadata)
            fields[4] = 0
            return os.stat_result(fields)
        return metadata
    monkeypatch.setattr(tproxy.os, "lstat", lstat)
    def directory(path, mode=0o700, owner=0):
        Path(path).mkdir(mode=mode, exist_ok=True)
        Path(path).chmod(mode)
    monkeypatch.setattr(tproxy, "_update_private_directory", directory)
    held = []
    bootstrapped = []
    @contextmanager
    def lock(*args, **kw):
        held.append(True)
        try:
            yield
        finally:
            held.pop()
            if bootstrapped:
                _, journal_path = tproxy._daemon_update_paths(NONCE)
                current = tproxy._update_read_json(journal_path)
                tproxy._daemon_update_publish(current, worker_pid=101)
    monkeypatch.setattr(tproxy, "_installer_operation_lock", lock)
    def bootstrap(nonce):
        assert held and json.loads((root / "active.json").read_text())["nonce"] == nonce
        path = root / nonce / "private/worker-runtime/slipstreamd"
        assert path.read_text() == "old daemon"
        bootstrapped.append(nonce)
    monkeypatch.setattr(tproxy, "_daemon_update_bootstrap", bootstrap)
    return value, root, bootstrapped, held


def test_prepare_seals_actual_installed_worker_before_index_and_releases_lock_before_reply(prepared_filesystem):
    value, root, boots, held = prepared_filesystem
    assert tproxy.do_update_prepare(json.dumps(value))
    private = json.loads((root / NONCE / "private/journal.json").read_text())
    assert private["deadline_unix"] == value["prepare_deadline_unix"]
    assert not private["snapshot_ready"] and private["old_runtime_sha256"] is None
    assert (root / NONCE / "old.app").is_dir() and (root / NONCE / "new.app").is_dir()
    assert private["worker_runtime_sha256"] == tproxy._daemon_update_tree(root / NONCE / "private/worker-runtime")
    assert boots == [NONCE] and not held
    assert tproxy.do_update_prepare(json.dumps(value))
    retried = json.loads((root / NONCE / "private/journal.json").read_text())
    assert retried["deadline_unix"] == private["deadline_unix"]
    assert retried["manifest_sha256"] == private["manifest_sha256"]


def test_prepare_persists_mailbox_wake_without_heartbeat_watch_or_periodic_worker(prepared_filesystem):
    import plistlib
    value, _, _, _ = prepared_filesystem
    assert tproxy.do_update_prepare(json.dumps(value))
    with open(tproxy._daemon_update_worker_plist(NONCE), "rb") as handle:
        worker = plistlib.load(handle)
    mailbox = os.path.join(tproxy._DAEMON_UPDATE_REQUESTS, f"{value['uid']}-{NONCE}")
    assert worker["WatchPaths"] == [mailbox]
    assert Path(mailbox).is_dir()
    assert worker["KeepAlive"] == {"SuccessfulExit": False}
    assert "StartInterval" not in worker and "QueueDirectories" not in worker
    assert tproxy.STATUS_PATH not in worker["WatchPaths"]


def test_expired_authorization_is_definitive_noop_before_staging(prepared_filesystem):
    value, root, boots, _ = prepared_filesystem
    value["prepare_deadline_unix"] = 4102444599
    with pytest.raises(tproxy.DaemonUpdateNoOperation):
        tproxy.do_update_prepare(json.dumps(value))
    assert not (root / NONCE).exists() and not (root / "active.json").exists() and not boots


def test_canonical_publication_before_worker_plist_recovers_on_identical_prepare(prepared_filesystem, monkeypatch):
    value, root, boots, _ = prepared_filesystem
    write = tproxy._daemon_update_write_worker_plist
    monkeypatch.setattr(tproxy, "_daemon_update_write_worker_plist", lambda *a: (_ for _ in ()).throw(OSError("interrupted")))
    with pytest.raises(OSError, match="interrupted"):
        tproxy.do_update_prepare(json.dumps(value))
    assert (root / NONCE / "private/journal.json").is_file()
    assert not (root / "active.json").exists() and not boots
    monkeypatch.setattr(tproxy, "_daemon_update_write_worker_plist", write)
    assert tproxy.do_update_prepare(json.dumps(value))
    assert json.loads((root / "active.json").read_text())["nonce"] == NONCE
    assert json.loads((root / NONCE / "status.json").read_text())["prepare_deadline_unix"] == value["prepare_deadline_unix"]


def test_persistent_worker_before_index_can_claim_untouched_operation(prepared_filesystem, monkeypatch):
    value, root, boots, _ = prepared_filesystem
    write = tproxy._update_write_json
    def interrupted(path, *args, **kwargs):
        if Path(path) == root / "active.json":
            raise OSError("index publication interrupted")
        return write(path, *args, **kwargs)
    monkeypatch.setattr(tproxy, "_update_write_json", interrupted)
    with pytest.raises(OSError, match="index publication"):
        tproxy.do_update_prepare(json.dumps(value))
    assert Path(tproxy._daemon_update_worker_plist(NONCE)).is_file()
    assert not (root / "active.json").exists() and not boots
    monkeypatch.setattr(tproxy, "_update_write_json", write)
    monkeypatch.setattr(tproxy.sys, "executable", str(root / NONCE / "private/worker-runtime/slipstreamd"))
    def recover(current):
        assert json.loads((root / "active.json").read_text())["nonce"] == NONCE
        assert current["phase"] == "prepared" and current["decision"] is None
        assert current["deadline_unix"] == value["prepare_deadline_unix"]
        return True
    monkeypatch.setattr(tproxy, "_daemon_update_worker_loop", recover)
    assert tproxy.do_update_worker(NONCE)


def test_expired_existing_prepare_indexes_before_selecting_abort(prepared_filesystem, monkeypatch):
    value, root, _, _ = prepared_filesystem
    assert tproxy.do_update_prepare(json.dumps(value))
    (root / "active.json").unlink()
    monkeypatch.setattr(tproxy.time, "time", lambda: value["prepare_deadline_unix"] + 1)
    publish = tproxy._daemon_update_publish
    selected = []
    def checked(current, **changes):
        if changes.get("decision") == "abort":
            assert json.loads((root / "active.json").read_text())["nonce"] == NONCE
            selected.append(True)
        return publish(current, **changes)
    monkeypatch.setattr(tproxy, "_daemon_update_publish", checked)
    assert tproxy.do_update_prepare(json.dumps(value))
    assert selected


def test_orphan_prepared_operation_cannot_overwrite_new_installed_payload(prepared_filesystem, monkeypatch):
    value, root, _, _ = prepared_filesystem
    assert tproxy.do_update_prepare(json.dumps(value))
    (root / "active.json").unlink()
    Path(tproxy.INSTALL_DIR, "slipstreamd").write_text("a later manual installation")
    with pytest.raises(RuntimeError, match="generation changed"):
        tproxy.do_update_prepare(json.dumps(value))
    assert not (root / "active.json").exists()


def test_uninstall_removes_only_root_owned_unpublished_slots(monkeypatch, tmp_path):
    root = tmp_path / "updater"
    root.mkdir()
    partial = root / (".prepare-" + NONCE)
    partial.mkdir()
    (partial / "old.app").mkdir()
    (root / "installer.lock").touch()
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_ROOT", str(root))
    real = os.lstat
    def owned(path, **kwargs):
        metadata = real(path, **kwargs)
        if Path(path) == partial:
            fields = list(metadata)
            fields[4] = 0
            return os.stat_result(fields)
        return metadata
    monkeypatch.setattr(tproxy.os, "lstat", owned)
    assert tproxy._daemon_update_remove_retained()
    assert not partial.exists() and (root / "installer.lock").exists()


def test_abort_restores_exact_runtime_symlinks_and_secret_before_readiness(monkeypatch, tmp_path):
    value = journal()
    operation = tmp_path / NONCE
    snapshot = operation / "private/old-runtime"
    snapshot.mkdir(parents=True)
    (snapshot / "slipstreamd").write_text("old daemon")
    (snapshot / "tgws-secret").write_text("retained secret")
    (snapshot / "runtime-alias").symlink_to("slipstreamd")
    installed = tmp_path / "installed"
    installed.mkdir()
    (installed / "slipstreamd").write_text("new daemon")
    value.update(snapshot_ready=True, old_runtime_sha256=tproxy._daemon_update_tree(snapshot))
    monkeypatch.setattr(tproxy, "_DAEMON_UPDATE_ROOT", str(tmp_path))
    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(installed))
    monkeypatch.setattr(tproxy, "_daemon_update_verify_app", lambda *a: None)
    monkeypatch.setattr(tproxy, "_disable_and_cleanup_install", lambda *a, **k: True)
    monkeypatch.setattr(tproxy, "_write_launchd_plist_atomic", lambda *a: None)
    monkeypatch.setattr(tproxy, "_require_command", lambda *a: None)
    monkeypatch.setattr(tproxy, "_write_install_attestation", lambda *a: None)
    def ready(_):
        assert tproxy._daemon_update_tree(installed) == value["old_runtime_sha256"]
        assert (installed / "runtime-alias").is_symlink()
        assert (installed / "tgws-secret").read_text() == "retained secret"
        return True
    monkeypatch.setattr(tproxy, "_wait_for_installed_daemon", ready)
    monkeypatch.setattr(tproxy, "_daemon_update_runtime_proof", lambda sha: proof(sha))
    assert tproxy._daemon_update_restore_old(value) == proof(identity()["old_daemon_sha256"])

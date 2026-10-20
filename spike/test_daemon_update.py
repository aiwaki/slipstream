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
REAL_READINESS_SNAPSHOT = tproxy._installed_daemon_readiness_snapshot


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
              "daemon": {"sha256": sha}, "launchd": {"pid": 100},
              "state": "dormant", "pf_active": False}
    monkeypatch.setattr(tproxy, "_update_read_json", lambda *a, **k: record)
    monkeypatch.setattr(tproxy, "_sha256_regular_file", lambda _: sha)
    def fresh_record(*args, **kwargs):
        kwargs["readiness_reader"](tproxy.PROXY_PORT, {
            k: v for k, v in record.items() if k not in {"state", "pf_active"}})
        return record
    monkeypatch.setattr(tproxy, "_install_attestation_record", fresh_record)
    monkeypatch.setattr(tproxy, "_run", lambda *a: SimpleNamespace(
        returncode=0, stdout=f"0 Mon Oct 19 12:34:56 2026 {tproxy.INSTALL_DIR}/slipstreamd\n"))
    assert tproxy._daemon_update_runtime_proof(sha)["heartbeat_seq"] == 7


@pytest.fixture
def attested_runtime(monkeypatch, tmp_path):
    """Real retained inode/hash proof; only native readiness is substituted."""
    installed = tmp_path / "slipstreamd"
    installed.write_bytes(b"one unchanged frozen daemon")
    installed.chmod(0o700)
    evidence = tmp_path / "install.json"
    witness = Path(tproxy._install_attestation_witness_path(str(evidence)))
    os.link(installed, witness)
    sha = tproxy._sha256_regular_file(str(installed))
    current = {"state": "dormant", "pid": 100, "heartbeat_seq": 7}
    monkeypatch.setattr(tproxy, "INSTALL_DIR", str(tmp_path))
    monkeypatch.setattr(tproxy, "INSTALL_ATTESTATION_PATH", str(evidence))
    monkeypatch.setattr(tproxy, "_installed_daemon_readiness_snapshot", lambda _: (
        True, "ready", dict(current), current["state"] == "active"))
    original_record = tproxy._install_attestation_record
    def record(*args, **kwargs):
        # A hermetic user-owned fixture retains all production inode, mode,
        # hash and listener-record validation without requiring root.
        return original_record(*args, **kwargs, expected_uid=os.getuid())
    monkeypatch.setattr(tproxy, "_install_attestation_record", record)
    stored = record(str(installed), sha, 0o700, tproxy.PROXY_PORT,
                    witness_path=str(witness))
    evidence.write_text(json.dumps(stored))
    monkeypatch.setattr(tproxy, "_update_read_json", lambda *a, **k: copy.deepcopy(stored))
    monkeypatch.setattr(tproxy, "_write_install_attestation", lambda *a, **k: pytest.fail("receipt rewritten"))
    monkeypatch.setattr(tproxy, "_run", lambda *a: SimpleNamespace(
        returncode=0, stdout=f"0 Mon Oct 19 12:34:56 2026 {installed} --port 1080\n"))
    return SimpleNamespace(sha=sha, stored=stored, current=current, evidence=evidence,
                           installed=installed, witness=witness)


@pytest.mark.parametrize("before,after", [("dormant", "active"), ("active", "dormant")])
def test_runtime_proof_accepts_healthy_state_change_on_same_process(attested_runtime, before, after):
    runtime = attested_runtime
    runtime.stored.update(state=before, pf_active=before == "active")
    runtime.current["state"] = after
    stored_before = copy.deepcopy(runtime.stored)
    evidence_before = runtime.evidence.read_bytes()
    result = tproxy._daemon_update_runtime_proof(runtime.sha)
    assert result["daemon_pid"] == 100 and result["heartbeat_seq"] == 7
    assert result["daemon_sha256"] == runtime.sha
    assert runtime.stored == stored_before and runtime.evidence.read_bytes() == evidence_before


@pytest.mark.parametrize("path,value", [
    (("schema_version",), 2), (("schema_version",), 3.0),
    (("source_sha256",), "f" * 64), (("unexpected",), True),
    (("daemon", "path"), "/another/slipstreamd"),
    (("daemon", "sha256"), "f" * 64), (("daemon", "uid"), -1),
    (("daemon", "gid"), -1), (("daemon", "mode"), 0o755),
    (("daemon", "unexpected"), True), (("witness", "ino"), -1),
    (("launchd", "pid"), 101), (("launchd", "label"), "another.job"),
    (("listener", "port"), 1081), (("listener", "hosts"), ["127.0.0.1"]),
])
def test_runtime_proof_rejects_identity_drift_despite_healthy_transition(attested_runtime, path, value):
    runtime = attested_runtime
    runtime.current["state"] = "active"
    target = runtime.stored
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(RuntimeError, match="identity mismatch|attestation drift"):
        tproxy._daemon_update_runtime_proof(runtime.sha)


@pytest.mark.parametrize("state,pf_active", [
    ("active", False), ("dormant", True), ("active", 1), ("dormant", 0),
    ("starting", False), (None, False), ("active", None),
])
@pytest.mark.parametrize("side", ["retained", "fresh"])
def test_identity_comparison_rejects_malformed_health(attested_runtime, state, pf_active, side):
    retained = copy.deepcopy(attested_runtime.stored)
    fresh = copy.deepcopy(retained)
    (retained if side == "retained" else fresh).update(state=state, pf_active=pf_active)
    assert not tproxy._install_attestation_identity_matches(retained, fresh)


def test_runtime_proof_rejects_current_readiness_failure(attested_runtime, monkeypatch):
    monkeypatch.setattr(tproxy, "_installed_daemon_readiness_snapshot", lambda _: (
        False, "listener or PF readiness failed", None, False))
    with pytest.raises(RuntimeError, match="readiness missing"):
        tproxy._daemon_update_runtime_proof(attested_runtime.sha)


@pytest.mark.parametrize("mutation", ["payload", "mode", "witness"])
def test_runtime_proof_rejects_actual_retained_file_change(attested_runtime, mutation):
    runtime = attested_runtime
    runtime.current["state"] = "active"
    if mutation == "payload":
        runtime.installed.write_bytes(b"different runtime")
    elif mutation == "mode":
        runtime.installed.chmod(0o600)
    else:
        runtime.witness.unlink()
        runtime.witness.write_bytes(runtime.installed.read_bytes())
        runtime.witness.chmod(0o700)
    with pytest.raises(RuntimeError, match="identity mismatch|rejected mode|witness"):
        tproxy._daemon_update_runtime_proof(runtime.sha)


@pytest.fixture
def runtime_health(attested_runtime, monkeypatch):
    """Exercise the real status/PF readiness reader with deterministic OS inputs."""
    runtime = attested_runtime
    health = SimpleNamespace(
        runtime=runtime, now=1000.0, sleeps=[], recovery={}, pf=True, listeners=[100],
        addresses={"127.0.0.1", "::1"}, uid="0", birth="Mon Oct 19 12:34:56 2026",
        command=str(runtime.installed) + " --port 1080", after_sleep=lambda: None,
    )
    # The ordinary fixture stubs this reader; retain its real implementation here.
    monkeypatch.setattr(tproxy, "_installed_daemon_readiness_snapshot", REAL_READINESS_SNAPSHOT)
    monkeypatch.setattr(tproxy.time, "time", lambda: health.now)
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: health.now)
    def sleep(seconds):
        health.sleeps.append(seconds)
        health.now += seconds
        health.after_sleep()
    monkeypatch.setattr(tproxy.time, "sleep", sleep)
    monkeypatch.setattr(tproxy, "_daemon_status_record", lambda: {
        **runtime.current, "updated_at": health.now})
    monkeypatch.setattr(tproxy, "_daemon_recovery_record", lambda: health.recovery)
    monkeypatch.setattr(tproxy, "_process_command_for_pid", lambda _: health.command)
    monkeypatch.setattr(tproxy, "_installed_daemon_command_owned",
                        lambda command: command.startswith(str(runtime.installed) + " "))
    monkeypatch.setattr(tproxy, "_listener_pids", lambda _: health.listeners)
    monkeypatch.setattr(tproxy, "_listener_bind_addresses", lambda *a: health.addresses)
    monkeypatch.setattr(tproxy, "pf_state_snapshot", lambda _: {"rules_loaded": health.pf})
    def run(*args):
        assert args == ("/bin/ps", "-ww", "-p", "100", "-o", "uid=,lstart=,command=")
        return SimpleNamespace(returncode=0, stdout=f"{health.uid} {health.birth} {health.command}\n")
    monkeypatch.setattr(tproxy, "_run", run)
    return health


def test_runtime_proof_waits_for_same_process_pf_status_convergence(runtime_health):
    health = runtime_health
    before = health.runtime.evidence.read_bytes()
    def converge():
        health.runtime.current.update(state="active", heartbeat_seq=8)
    health.after_sleep = converge
    result = tproxy._daemon_update_runtime_proof(health.runtime.sha)
    assert result["daemon_pid"] == 100 and result["heartbeat_seq"] == 8
    assert health.sleeps == [0.05]
    assert health.runtime.evidence.read_bytes() == before


def test_runtime_proof_permanent_pf_mismatch_is_bounded(runtime_health):
    health = runtime_health
    with pytest.raises(RuntimeError, match="readiness"):
        tproxy._daemon_update_runtime_proof(health.runtime.sha)
    assert 4.99 <= health.now - 1000.0 <= 5.001
    assert 1 <= len(health.sleeps) <= 101


@pytest.mark.parametrize("field,value", [
    ("birth", "Mon Oct 19 12:35:56 2026"), ("uid", "501"),
    ("command", "/unowned/slipstreamd --port 1080"),
])
def test_runtime_proof_rejects_process_change_during_pf_wait(runtime_health, field, value):
    health = runtime_health
    def change():
        setattr(health, field, value)
        health.runtime.current["state"] = "active"
    health.after_sleep = change
    with pytest.raises(RuntimeError, match="identity"):
        tproxy._daemon_update_runtime_proof(health.runtime.sha)
    assert health.sleeps == [0.05]


def test_runtime_proof_rejects_status_pid_change_during_pf_wait(runtime_health):
    health = runtime_health
    def change():
        health.runtime.current.update(pid=101, state="active")
        health.listeners = [101]
    health.after_sleep = change
    with pytest.raises(RuntimeError, match="identity"):
        tproxy._daemon_update_runtime_proof(health.runtime.sha)
    assert health.sleeps == [0.05]


@pytest.mark.parametrize("reason", [
    tproxy.BASELINE_GUARD_BLOCK_REASON, tproxy.BASELINE_GUARD_ROLLBACK_REASON,
    tproxy.PF_LOOPBACK_UNAVAILABLE_REASON,
])
def test_runtime_proof_recovery_refusal_never_waits(runtime_health, reason):
    runtime_health.recovery = {"reason": reason}
    with pytest.raises(RuntimeError, match="readiness"):
        tproxy._daemon_update_runtime_proof(runtime_health.runtime.sha)
    assert runtime_health.sleeps == []


def test_runtime_proof_late_ready_retry_does_not_extend_budget(runtime_health, monkeypatch):
    health = runtime_health
    samples = []
    def late_pf(_):
        samples.append(True)
        if len(samples) == 1:
            return {"rules_loaded": True}
        health.now += 5.01
        return {"rules_loaded": False}
    monkeypatch.setattr(tproxy, "pf_state_snapshot", late_pf)
    with pytest.raises(RuntimeError, match="readiness"):
        tproxy._daemon_update_runtime_proof(health.runtime.sha)
    assert health.sleeps == [0.05] and len(samples) == 2


def test_runtime_proof_accepts_slow_first_ready_snapshot(runtime_health, monkeypatch):
    health = runtime_health
    def late_pf(_):
        health.now += 5.01
        return {"rules_loaded": False}
    monkeypatch.setattr(tproxy, "pf_state_snapshot", late_pf)
    assert tproxy._daemon_update_runtime_proof(health.runtime.sha)["heartbeat_seq"] == 7
    assert health.sleeps == []


def test_default_attestation_keeps_its_slow_first_ready_snapshot(runtime_health, monkeypatch):
    health = runtime_health
    def late_pf(_):
        health.now += 5.01
        return {"rules_loaded": False}
    monkeypatch.setattr(tproxy, "pf_state_snapshot", late_pf)
    record = tproxy._install_attestation_record(
        str(health.runtime.installed), health.runtime.sha, 0o700, tproxy.PROXY_PORT,
        witness_path=str(health.runtime.witness))
    assert record["state"] == "dormant" and not record["pf_active"]
    assert health.sleeps == []


@pytest.mark.parametrize("mutation", ["payload", "mode", "witness", "receipt"])
def test_runtime_proof_identity_refusal_precedes_pf_wait(runtime_health, mutation):
    health = runtime_health
    runtime = health.runtime
    if mutation == "payload":
        runtime.installed.write_bytes(b"changed daemon")
    elif mutation == "mode":
        runtime.installed.chmod(0o600)
    elif mutation == "witness":
        runtime.witness.unlink()
        runtime.witness.write_bytes(runtime.installed.read_bytes())
        runtime.witness.chmod(0o700)
    else:
        runtime.stored["witness"]["ino"] += 1
    with pytest.raises(RuntimeError, match="identity|mode|witness|attestation drift"):
        tproxy._daemon_update_runtime_proof(runtime.sha)
    assert health.sleeps == []


def test_committed_resolve_transient_pf_mismatch_does_not_reinstall(runtime_health, monkeypatch):
    health = runtime_health
    health.after_sleep = lambda: health.runtime.current.update(state="active")
    value = journal()
    value["identity"]["new_daemon_sha256"] = health.runtime.sha
    value.update(decision="commit", phase="committing")
    monkeypatch.setattr(tproxy, "do_install", lambda *a, **k: pytest.fail("unneeded reinstall"))
    monkeypatch.setattr(tproxy, "_daemon_update_verify_app", lambda *a: None)
    monkeypatch.setattr(tproxy, "_daemon_update_retained_secret", lambda _: None)
    monkeypatch.setattr(tproxy, "_daemon_update_tree", lambda *a, **k: "a" * 64)
    monkeypatch.setattr(tproxy, "_daemon_update_publish", lambda v, **k: v.update(k))
    tproxy._daemon_update_resolve(value)
    assert value["phase"] == "committed" and value["decision"] == "commit"
    assert health.sleeps == [0.05]


@pytest.mark.parametrize("permanent", [False, True])
def test_commit_pf_observation_converges_or_aborts_without_extending_lease(
        runtime_health, monkeypatch, permanent):
    health = runtime_health
    if not permanent:
        health.after_sleep = lambda: health.runtime.current.update(state="active")
    value = journal()
    value["identity"]["new_daemon_sha256"] = health.runtime.sha
    value.update(phase="ready", snapshot_ready=True, deadline_unix=1100)
    original_deadline = value["deadline_unix"]
    requests(monkeypatch, ["commit"])
    writes, restores = [], []
    def publish(v, **changes):
        v.update(changes)
        writes.append(copy.deepcopy(v))
    monkeypatch.setattr(tproxy, "_daemon_update_publish", publish)
    monkeypatch.setattr(tproxy, "_daemon_update_tree", lambda *a, **k: "a" * 64)
    def restore(v):
        restores.append(v["decision"])
        return proof(v["identity"]["old_daemon_sha256"])
    monkeypatch.setattr(tproxy, "_daemon_update_restore_old", restore)
    monkeypatch.setattr(tproxy, "do_install", lambda *a, **k: pytest.fail("transaction retried"))
    assert tproxy._daemon_update_worker_loop(value)
    assert value["phase"] == ("aborted" if permanent else "committed")
    assert restores == (["abort"] if permanent else [])
    assert all(item["deadline_unix"] == original_deadline for item in writes)
    assert sum(health.sleeps) <= 5.001


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


@pytest.fixture
def starting_worker(prepared_filesystem, monkeypatch):
    """Delay the worker's validated receipt without waiting in real time."""
    from contextlib import contextmanager
    value, root, boots, held = prepared_filesystem
    clock = SimpleNamespace(elapsed=0.0, offset=0.0, rollback_at=None,
                            worker_at=None, worker_published=False, sealing_delay=0.0)
    monkeypatch.setattr(tproxy.time, "time", lambda: 4102444600 + clock.elapsed + clock.offset)
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: clock.elapsed)

    @contextmanager
    def lock(*args, **kwargs):
        held.append(True)
        try:
            yield
        finally:
            held.pop()
    monkeypatch.setattr(tproxy, "_installer_operation_lock", lock)
    bootstrap = tproxy._daemon_update_bootstrap

    def delayed_bootstrap(nonce):
        bootstrap(nonce)
        clock.elapsed += clock.sealing_delay
    monkeypatch.setattr(tproxy, "_daemon_update_bootstrap", delayed_bootstrap)

    def sleep(seconds):
        assert boots == [NONCE] and not held
        clock.elapsed = round(clock.elapsed + seconds, 9)
        if clock.rollback_at is not None and clock.elapsed >= clock.rollback_at:
            clock.offset = -3600
        if (not clock.worker_published and clock.worker_at is not None
                and clock.elapsed >= clock.worker_at):
            current = tproxy._update_read_json(root / NONCE / "private/journal.json")
            tproxy._daemon_update_publish(current, worker_pid=101)
            clock.worker_published = True
    monkeypatch.setattr(tproxy.time, "sleep", sleep)
    return value, root, clock


def test_prepare_waits_for_validated_worker_after_ten_seconds_within_original_lease(starting_worker):
    value, root, clock = starting_worker
    value["prepare_deadline_unix"] = 4102444630
    clock.worker_at = 15.5
    installed_before = Path(tproxy.INSTALL_DIR, "slipstreamd").read_bytes()
    assert tproxy.do_update_prepare(json.dumps(value))
    current = json.loads((root / NONCE / "private/journal.json").read_text())
    assert 15.5 <= clock.elapsed < 15.6
    assert current["worker_pid"] == 101 and current["phase"] == "prepared"
    assert current["decision"] is None and current["accepted_sequence"] == 0
    assert current["deadline_unix"] == value["prepare_deadline_unix"]
    assert Path(tproxy.INSTALL_DIR, "slipstreamd").read_bytes() == installed_before


@pytest.mark.parametrize("sealing_delay,rollback_at", [(0, None), (0, 1), (2.5, None)])
def test_prepare_worker_wait_expires_without_renewing_original_budget(
        starting_worker, sealing_delay, rollback_at):
    value, root, clock = starting_worker
    value["prepare_deadline_unix"] = 4102444603
    clock.sealing_delay = sealing_delay
    clock.rollback_at = rollback_at
    with pytest.raises(RuntimeError, match="update worker startup unconfirmed"):
        tproxy.do_update_prepare(json.dumps(value))
    assert clock.elapsed == pytest.approx(3.0)
    current = json.loads((root / NONCE / "private/journal.json").read_text())
    assert current["worker_pid"] == 0 and current["decision"] is None
    assert current["deadline_unix"] == value["prepare_deadline_unix"]
    assert (root / "active.json").is_file()


def test_prepare_does_not_accept_worker_first_observed_at_lease_expiry(starting_worker):
    value, root, clock = starting_worker
    value["prepare_deadline_unix"] = 4102444603
    clock.worker_at = 3.0
    with pytest.raises(RuntimeError, match="update worker startup unconfirmed"):
        tproxy.do_update_prepare(json.dumps(value))
    assert clock.elapsed == pytest.approx(3.0)
    assert json.loads((root / NONCE / "status.json").read_text())["worker_pid"] == 101


@pytest.mark.parametrize("phase,decision", [("committed", "commit"), ("aborted", "abort")])
def test_prepare_terminal_receipt_remains_idempotent_after_lease_expiry(
        starting_worker, phase, decision):
    value, root, clock = starting_worker
    clock.worker_at = 0
    assert tproxy.do_update_prepare(json.dumps(value))
    current = tproxy._update_read_json(root / NONCE / "private/journal.json")
    tproxy._daemon_update_publish(current, phase=phase, decision=decision, worker_pid=0)
    clock.elapsed = value["prepare_deadline_unix"] - 4102444600 + 1
    assert tproxy.do_update_prepare(json.dumps(value))
    retained = json.loads((root / NONCE / "private/journal.json").read_text())
    assert retained["phase"] == phase and retained["decision"] == decision
    assert retained["worker_pid"] == 0


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


@pytest.mark.parametrize("stage", [
    "lease", "runtime-proof", "launch-intent", "plist", "runtime-tree",
    "seal-old-app", "seal-new-app", "seal-worker", "publish",
])
def test_prepare_cli_rejection_reports_only_bounded_stage_and_preserves_noop(
        prepared_filesystem, monkeypatch, capsys, stage):
    value, root, boots, _ = prepared_filesystem
    secret = "private-exception /Users/private/credential identity=secret env=secret"
    def fail(*args, **kwargs):
        raise RuntimeError(secret)
    if stage == "lease":
        value["prepare_deadline_unix"] = 4102444599
    elif stage in {"runtime-proof", "launch-intent", "plist"}:
        symbol = {"runtime-proof": "_daemon_update_runtime_proof",
                  "launch-intent": "_daemon_update_require_enabled_intent",
                  "plist": "_daemon_update_read_plist"}[stage]
        monkeypatch.setattr(tproxy, symbol, fail)
    elif stage in {"runtime-tree", "seal-worker"}:
        original = tproxy._daemon_update_tree
        def tree(path, **kwargs):
            if ((stage == "runtime-tree" and os.fspath(path) == tproxy.INSTALL_DIR
                 and not kwargs.get("copy_to"))
                    or (stage == "seal-worker" and str(kwargs.get("copy_to", "")).endswith("worker-runtime"))):
                fail()
            return original(path, **kwargs)
        monkeypatch.setattr(tproxy, "_daemon_update_tree", tree)
    elif stage in {"seal-old-app", "seal-new-app"}:
        def verify(app, identity, side):
            if stage == "seal-" + side + "-app":
                fail()
        monkeypatch.setattr(tproxy, "_daemon_update_verify_app", verify)
    else:
        original_write = tproxy._update_write_json
        def write(path, *args, **kwargs):
            if str(path).endswith("/private/journal.json"):
                fail()
            return original_write(path, *args, **kwargs)
        monkeypatch.setattr(tproxy, "_update_write_json", write)
    installed_before = Path(tproxy.INSTALL_DIR, "slipstreamd").read_bytes()
    monkeypatch.setattr(tproxy.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tproxy.sys, "argv", ["slipstreamd", "--update-prepare", json.dumps(value)])
    with pytest.raises(SystemExit) as result:
        tproxy.main()
    assert result.value.code == 77
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == f"daemon_update_no_operation\ndaemon_update_stage={stage}\n"
    assert not (root / NONCE).exists() and not (root / "active.json").exists() and not boots
    assert not (root / (".prepare-" + NONCE)).exists()
    assert Path(tproxy.INSTALL_DIR, "slipstreamd").read_bytes() == installed_before


def test_noop_stage_rejects_arbitrary_exception_payload():
    with pytest.raises(ValueError, match="^invalid update rejection stage$"):
        tproxy.DaemonUpdateNoOperation("private exception /path/credential")


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
    with pytest.raises(RuntimeError, match="update worker startup unconfirmed"):
        tproxy.do_update_prepare(json.dumps(value))
    assert selected
    retained = json.loads((root / NONCE / "private/journal.json").read_text())
    assert retained["phase"] == "aborting" and retained["decision"] == "abort"


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

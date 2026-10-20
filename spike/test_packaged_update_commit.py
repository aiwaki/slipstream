"""Hermetic gate wiring: no native commands, candidate execution or network."""
import copy
import json
from pathlib import Path
import signal
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_packaged_update_commit as gate
from native_root_update import Refused


def fixture(tmp_path, *, old_version=30, new_version=31):
    def pin(char, run):
        return {"source_commit": char * 40, "candidate_manifest_sha256": char * 64, "run_id": run, "run_attempt": 1}
    pair = {"schema_version": 1, "old": pin("b", 102), "new": pin("c", 103)}
    root_pair = copy.deepcopy(pair)
    def artifact(version, char):
        return {"version": "0.1.9-preview." + str(version), "source_commit": char * 40,
                **{key: char * 64 for key in ("archive_sha256", "app_executable_sha256", "daemon_sha256", "bundle_tree_sha256")}}
    expected = {"old": artifact(old_version, "b"), "new": artifact(new_version, "c")}
    metadata = {"id": 200, "run_attempt": 2, "head_sha": pair["new"]["source_commit"], "head_branch": "main",
                "event": "workflow_dispatch", "path": ".github/workflows/native-root-update-qualification.yml",
                "status": "completed", "conclusion": "success"}
    for mode in gate.MODES:
        directory = tmp_path / f"native-root-update-{mode}-200-2"
        directory.mkdir()
        (directory / "pair.json").write_text(json.dumps(root_pair))
        outcome = {"source_sha": metadata["head_sha"], "run_id": "200", "run_attempt": "2", "mode": mode,
                   "job_status_before_upload": "success", "steps": {"qualify": "success"}}
        result = {"status": "passed", "mode": mode, "root_protocol_qualified": True,
                  "public_pair_qualified": False, "new_daemon_preinstalled": False, "cleanup_errors": [],
                  "identity": {"archive_sha256": expected["new"]["archive_sha256"],
                               **{side + "_" + field: expected[side][field] for side in ("old", "new")
                                  for field in ("version", "app_executable_sha256", "daemon_sha256", "bundle_tree_sha256")}},
                  "events": [{"kind": "artifact", "side": side, **expected[side]} for side in ("old", "new")]}
        (directory / "workflow-outcome.json").write_text(json.dumps(outcome))
        (directory / "result.json").write_text(json.dumps(result))
    return metadata, pair, expected


def test_requires_both_successful_root_cases_bound_to_same_complete_app_pair(tmp_path):
    metadata, pair, expected = fixture(tmp_path)
    proof = gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)
    assert set(proof["sha256"]) == set(gate.MODES)
    assert proof["pair"] == pair
    assert proof["run_attempt"] == 2


@pytest.mark.parametrize("field,value", [("head_sha", "a" * 40), ("head_sha", "b" * 40),
    ("id", 201), ("run_attempt", 1), ("head_branch", "feature"), ("status", "in_progress"),
    ("path", ".github/workflows/ci.yml"), ("conclusion", "failure"), ("event", "pull_request")])
def test_root_workflow_identity_cannot_be_replaced(tmp_path, field, value):
    metadata, pair, expected = fixture(tmp_path)
    metadata[field] = value
    with pytest.raises(Refused, match="exact NEW"):
        gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)


@pytest.mark.parametrize("name,field,value", [
    ("pair.json", "new", {"source_commit": "b" * 40, "candidate_manifest_sha256": "e" * 64, "run_id": 102, "run_attempt": 1}),
    ("workflow-outcome.json", "run_attempt", "1"), ("workflow-outcome.json", "job_status_before_upload", "failure"),
    ("workflow-outcome.json", "source_sha", "b" * 40),
    ("result.json", "root_protocol_qualified", False), ("result.json", "cleanup_errors", ["residue"]),
    ("result.json", "new_daemon_preinstalled", True), ("result.json", "events", []),
    ("result.json", "identity", {})])
def test_each_root_receipt_must_match_and_finish_cleanup(tmp_path, name, field, value):
    metadata, pair, expected = fixture(tmp_path)
    path = tmp_path / "native-root-update-crash-before-commit-200-2" / name
    changed = json.loads(path.read_text())
    changed[field] = value
    path.write_text(json.dumps(changed))
    with pytest.raises(Refused):
        gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)


@pytest.mark.parametrize("old_version,new_version", [(26, 27), (27, 28), (28, 29), (28, 30), (29, 30), (29, 31), (30, 32)])
def test_root_pass_cannot_qualify_unfixed_or_unreviewed_pair(tmp_path, old_version, new_version):
    metadata, pair, expected = fixture(tmp_path, old_version=old_version, new_version=new_version)
    with pytest.raises(Refused, match=r"\.30 -> \.31"):
        gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)


@pytest.mark.parametrize("side", ["old", "new"])
@pytest.mark.parametrize("field", ["source_commit", "candidate_manifest_sha256", "run_id", "run_attempt"])
def test_root_pair_rejects_each_changed_immutable_pin(tmp_path, side, field):
    metadata, pair, expected = fixture(tmp_path)
    path = tmp_path / "native-root-update-commit-200-2/pair.json"
    changed = json.loads(path.read_text())
    before = changed[side][field]
    changed[side][field] = before + 100 if isinstance(before, int) else "d" * len(before)
    path.write_text(json.dumps(changed))
    with pytest.raises(Refused, match="same exact candidate pair"):
        gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)


def test_previous_root_pair_cannot_authorize_app_origin_to_successor(tmp_path):
    metadata, pair, expected = fixture(tmp_path)
    path = tmp_path / "native-root-update-commit-200-2/pair.json"
    changed = {"schema_version": 1, "old": {"source_commit": "a" * 40,
        "candidate_manifest_sha256": "a" * 64, "run_id": 101, "run_attempt": 1}, "new": pair["old"]}
    path.write_text(json.dumps(changed))
    with pytest.raises(Refused, match="same exact candidate pair"):
        gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)


@pytest.mark.parametrize("side", ["old", "new"])
@pytest.mark.parametrize("field", ["version", "source_commit", "archive_sha256", "app_executable_sha256",
                                  "daemon_sha256", "bundle_tree_sha256"])
def test_full_root_artifact_records_must_match_both_authenticated_payloads(tmp_path, side, field):
    metadata, pair, expected = fixture(tmp_path)
    path = tmp_path / "native-root-update-commit-200-2/result.json"
    changed = json.loads(path.read_text())
    record = next(item for item in changed["events"] if item["side"] == side)
    record[field] = "other" if field == "version" else "d" * len(record[field])
    path.write_text(json.dumps(changed))
    with pytest.raises(Refused, match="root artifact differs"):
        gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)


@pytest.mark.parametrize("mode", gate.MODES)
@pytest.mark.parametrize("kind", ["duplicate", "missing", "duplicate-side", "malformed", "extra-field"])
def test_root_artifact_observations_are_exactly_one_complete_record_per_side(tmp_path, mode, kind):
    metadata, pair, expected = fixture(tmp_path)
    path = tmp_path / f"native-root-update-{mode}-200-2/result.json"
    changed = json.loads(path.read_text())
    events = changed["events"]
    if kind == "duplicate":
        events.append(copy.deepcopy(events[0]))
    elif kind == "missing":
        events.pop()
    elif kind == "duplicate-side":
        events[1] = copy.deepcopy(events[0])
    elif kind == "malformed":
        events.append(None)
    else:
        events[0]["unexpected"] = True
    path.write_text(json.dumps(changed))
    with pytest.raises(Refused):
        gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)


@pytest.mark.parametrize("field", ["archive_sha256"] + [side + "_" + key for side in ("old", "new")
    for key in ("version", "app_executable_sha256", "daemon_sha256", "bundle_tree_sha256")])
def test_root_identity_binds_both_versions_and_all_transaction_hashes(tmp_path, field):
    metadata, pair, expected = fixture(tmp_path)
    path = tmp_path / "native-root-update-crash-before-commit-200-2/result.json"
    changed = json.loads(path.read_text())
    changed["identity"][field] = "other" if field.endswith("version") else "d" * 64
    path.write_text(json.dumps(changed))
    with pytest.raises(Refused, match="root identity mismatch"):
        gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)


def test_driver_verifies_candidate_source_without_rebinding_root_source(tmp_path, monkeypatch):
    _, pair, _ = fixture(tmp_path)
    proof = {"harness_source_sha": "d" * 40, "candidate_new_source_sha": "c" * 40}
    calls = []
    def verify(repo, candidate):
        calls.append((repo, candidate))
        return proof
    monkeypatch.setattr(gate, "verify_source", verify)
    backend = SimpleNamespace(args=SimpleNamespace(repo=tmp_path))
    assert gate.verify_harness_source(backend, pair) is proof
    assert calls == [(tmp_path, pair["new"]["source_commit"])]


@pytest.mark.parametrize("mode", ["commit", "kill-successor-before-ack"])
@pytest.mark.parametrize("mismatch", ["initial", "before_install"])
def test_harness_source_mismatch_stops_main_before_artifact_or_install(tmp_path, monkeypatch, mismatch, mode):
    _, pair, _ = fixture(tmp_path)
    (tmp_path / "pair.json").write_text(json.dumps(pair))
    paths = {name: tmp_path / name for name in ("repo", "old-candidate-dir", "new-candidate-dir", "old-app",
                                               "new-app", "trigger-dir", "root-gate-dir")}
    for path in paths.values():
        path.mkdir()
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(gate, "guard", lambda: 501)
    monkeypatch.setattr(gate, "modules", lambda repo: (None, None))
    calls = []
    def verify(repo, candidate):
        calls.append(candidate)
        if mismatch == "initial":
            raise ValueError("harness checkout differs from workflow SHA")
        return {"harness_source_sha": ("c" if len(calls) == 1 else "d") * 40}
    monkeypatch.setattr(gate, "verify_source", verify)
    monkeypatch.setattr(gate, "prerequisite", lambda *args: {"source": "c" * 40})
    def artifact(*args):
        assert calls == ["c" * 40]
        return {}
    backend = SimpleNamespace(expected={}, events=[], identity=None,
        run=lambda argv, **kwargs: SimpleNamespace(stdout=b"{}"), artifact=artifact)
    def observer(args, *unused):
        backend.args = args
        return backend
    monkeypatch.setattr(gate, "Observer", observer)
    monkeypatch.setattr(gate, "PreAckObserver", observer)
    monkeypatch.setattr(gate, "drive", lambda b: pytest.fail("install before source proof"))
    cleaned = []
    monkeypatch.setattr(gate.Native, "teardown", lambda b: cleaned.append(b))
    argv = [value for name, path in paths.items() for value in ("--" + name, str(path))]
    output = tmp_path / "result.json"
    argv += ["--pair-manifest", str(tmp_path / "pair.json"), "--output", str(output),
             "--root-gate-run-id", "200", "--root-gate-attempt", "2", "--gh", "/unused/gh", "--mode", mode]
    assert gate.main(argv) == 2
    result = json.loads(output.read_text())
    assert ("workflow SHA" if mismatch == "initial" else "source changed before installation") in result["reason"]
    assert len(calls) == (1 if mismatch == "initial" else 2)
    assert result["cleanup_errors"] == []
    assert result["mode"] == mode
    assert not result["transaction_observed"] and cleaned == [backend]


@pytest.mark.parametrize("fail", [False, True])
def test_observer_ready_precedes_trigger_and_unknown_transaction_is_never_cleaned(tmp_path, monkeypatch, fail):
    events = []
    monkeypatch.setattr(gate, "install_old", lambda b: events.append("install-old"))
    for key in ("CI", "GITHUB_ACTIONS", "SLIPSTREAM_DISPOSABLE_CI", "RUNNER_OS", "RUNNER_TEMP"):
        monkeypatch.setenv(key, "fixture")
    monkeypatch.setenv("GH_TOKEN", "must-not-reach-native-child")
    def observe():
        events.append("observe-actual-ack")
        if fail:
            raise Refused("ACK not observed")
        return {"packaged_transaction_qualified": True}
    backend = SimpleNamespace(args=SimpleNamespace(trigger_dir=tmp_path), binary=tmp_path / "trigger",
        setup_observation=lambda: events.append("observer-ready"), qualify_app=observe,
        trigger_started=False, transaction_observed=False, env={"HOME": str(tmp_path)})
    def start(argv, **kwargs):
        assert argv == [str(backend.binary), "--prepare"]
        assert events == ["install-old", "observer-ready"]
        assert "GH_TOKEN" not in kwargs["env"] and kwargs["env"]["HOME"] == str(tmp_path)
        events.append("start")
        return SimpleNamespace(wait=lambda timeout: events.append("trigger-exited") or 0)
    if fail:
        with pytest.raises(Refused, match="ACK"):
            gate.drive(backend, start=start, cleanup=lambda b: pytest.fail("unknown outcome cleanup"))
        assert backend.trigger_started and not backend.transaction_observed
    else:
        assert gate.drive(backend, start=start, cleanup=lambda b: events.append("cleanup"))["packaged_transaction_qualified"]
        assert events[-2:] == ["trigger-exited", "cleanup"]
        assert backend.transaction_observed


def cleanup_backend():
    process = {"pid": 222, "uid": 501, "started": "Mon Oct 19 15:00:00 2026", "state": "S",
               "command": "/Applications/Slipstream.app/Contents/MacOS/slipstream"}
    journal = {"successor_pid": 222, "uid": 501, "successor_started": process["started"], "target": "/Applications/Slipstream.app"}
    return SimpleNamespace(tray=process, ack={"pid": 222}, last_journal=journal, deadline=1000)


@pytest.mark.parametrize("field,value", [("pid", 223), ("uid", 502), ("started", "Tue Oct 20 15:00:00 2026"),
                                         ("command", "/unrelated"), ("state", "T")])
def test_cleanup_never_signals_changed_successor(field, value):
    backend = cleanup_backend()
    current = copy.deepcopy(backend.tray)
    current[field] = value
    backend.process_snapshot = lambda pid: current
    with pytest.raises(Refused):
        gate.stop_acknowledged_successor(backend, send=lambda *a: pytest.fail("unowned signal"))


def test_successful_cleanup_sends_only_term_to_exact_acknowledged_successor():
    backend = cleanup_backend()
    values = iter([copy.deepcopy(backend.tray), None])
    backend.process_snapshot = lambda pid: next(values)
    signals = []
    gate.stop_acknowledged_successor(backend, send=lambda *args: signals.append(args), clock=lambda: 0)
    assert signals == [(222, signal.SIGTERM)]


def test_cleanup_timeout_never_escalates_to_kill():
    backend = cleanup_backend()
    backend.process_snapshot = lambda pid: copy.deepcopy(backend.tray)
    ticks = iter([0, 0, 16])
    signals = []
    with pytest.raises(Refused, match="no forced kill"):
        gate.stop_acknowledged_successor(backend, send=lambda *args: signals.append(args),
                                        clock=lambda: next(ticks), sleep=lambda seconds: None)
    assert signals == [(222, signal.SIGTERM)]


def test_cleanup_rejects_pending_root_before_any_signal(monkeypatch):
    backend = cleanup_backend()
    backend.final_app = lambda: None
    backend.status = lambda: {"phase": "ready", "decision": None, "writer_quiescent": True}
    monkeypatch.setattr(gate, "stop_acknowledged_successor", lambda b: pytest.fail("pending signal"))
    with pytest.raises(Refused, match="quiescent root commit"):
        gate.cleanup_committed(backend)


def test_workflow_uses_exact_pair_builder_and_observer_without_repair_hooks():
    source = (ROOT / ".github/workflows/packaged-update-commit-qualification.yml").read_text()
    assert source.count("        type: string") == 10
    assert "if: github.ref == 'refs/heads/main'" in source
    for script in ("materialize_pair.py", "build_packaged_update_trigger.py", "qualify_packaged_update_commit.py"):
        assert script in source
    assert "ref: ${{ inputs.old_source_sha }}" in source
    assert "native-root-update-*-${{ inputs.root_gate_run_id }}-${{ inputs.root_gate_attempt }}" in source
    assert "Successful exact NEW main root-gate run ID for the same .30 to .31 pair" in source
    assert "kickstart" not in source and "--update-prepare" not in source
    assert "if: always()" in source and "prepare-result.json" in source


def test_common_ci_compiles_adapter_without_executing_its_prepare():
    source = (ROOT / ".github/workflows/ci.yml").read_text()
    step = source.split("      - name: Compile and test disposable update adapter", 1)[1].split("      - name: Rust core tests", 1)[0]
    assert 'builder.verified_source(repo, manifest)' in step
    assert 'builder.write_crate' in step and '{"compile_only": True}' in step
    assert '"trigger::tests::"' in step and '"cargo", "test", "--locked"' in step
    assert "sudo" not in step and '"--prepare"' not in step

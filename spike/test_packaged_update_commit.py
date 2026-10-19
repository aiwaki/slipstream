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


def fixture(tmp_path):
    def pin(char, run):
        return {"source_commit": char * 40, "candidate_manifest_sha256": char * 64, "run_id": run, "run_attempt": 1}
    pair = {"schema_version": 1, "old": pin("b", 102), "new": pin("c", 103)}
    root_pair = {"schema_version": 1, "old": pin("a", 101), "new": pair["old"]}
    def artifact(version, char):
        return {"version": "0.1.9-preview." + str(version), "source_commit": char * 40,
                **{key: char * 64 for key in ("archive_sha256", "app_executable_sha256", "daemon_sha256", "bundle_tree_sha256")}}
    expected = {"old": artifact(27, "b"), "new": artifact(28, "c")}
    metadata = {"id": 200, "run_attempt": 2, "head_sha": pair["old"]["source_commit"], "head_branch": "main",
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
                  "identity": {"old_version": "0.1.9-preview.26", "new_version": "0.1.9-preview.27",
                               "new_app_executable_sha256": "b" * 64, "new_daemon_sha256": "b" * 64},
                  "events": [{"kind": "artifact", "side": "old", **artifact(26, "a")},
                             {"kind": "artifact", "side": "new", **expected["old"]}]}
        (directory / "workflow-outcome.json").write_text(json.dumps(outcome))
        (directory / "result.json").write_text(json.dumps(result))
    return metadata, pair, expected


def test_requires_both_successful_root_cases_bound_to_exact_app_origin(tmp_path):
    metadata, pair, expected = fixture(tmp_path)
    proof = gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)
    assert set(proof["sha256"]) == set(gate.MODES)
    assert proof["pair"]["new"] == pair["old"]
    assert proof["run_attempt"] == 2


@pytest.mark.parametrize("field,value", [("head_sha", "a" * 40), ("run_attempt", 1), ("head_branch", "feature"),
    ("path", ".github/workflows/ci.yml"), ("conclusion", "failure"), ("event", "pull_request")])
def test_root_workflow_identity_cannot_be_replaced(tmp_path, field, value):
    metadata, pair, expected = fixture(tmp_path)
    metadata[field] = value
    with pytest.raises(Refused, match="exact OLD"):
        gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)


@pytest.mark.parametrize("name,field,value", [
    ("pair.json", "new", {"source_commit": "b" * 40, "candidate_manifest_sha256": "e" * 64, "run_id": 102, "run_attempt": 1}),
    ("workflow-outcome.json", "run_attempt", "1"), ("workflow-outcome.json", "job_status_before_upload", "failure"),
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


def test_root_pass_cannot_qualify_unfixed_origin(tmp_path):
    metadata, pair, expected = fixture(tmp_path)
    expected["old"]["version"] = "0.1.9-preview.26"
    with pytest.raises(Refused, match=".27 -> .28"):
        gate.prerequisite(metadata, tmp_path, pair, expected, 200, 2)


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
    assert "kickstart" not in source and "--update-prepare" not in source
    assert "if: always()" in source and "prepare-result.json" in source


def test_common_ci_compiles_adapter_without_executing_its_prepare():
    source = (ROOT / ".github/workflows/ci.yml").read_text()
    step = source.split("      - name: Compile and test disposable update adapter", 1)[1].split("      - name: Rust core tests", 1)[0]
    assert 'builder.verified_source(repo, manifest)' in step
    assert 'builder.write_crate' in step and '{"compile_only": True}' in step
    assert '"trigger::tests::"' in step and '"cargo", "test", "--locked"' in step
    assert "sudo" not in step and '"--prepare"' not in step

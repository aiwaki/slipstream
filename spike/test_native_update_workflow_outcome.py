"""Execute only the stdlib evidence writer, never the native qualification."""
import json
from pathlib import Path
import textwrap

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/native-root-update-qualification.yml"
STAGES = ("CHECKOUT", "PYTHON", "DEPENDENCIES", "OLD_DOWNLOAD",
          "NEW_DOWNLOAD", "MATERIALIZE", "QUALIFY")


def evidence_script():
    text = WORKFLOW.read_text()
    step = text.split("      - name: Record outcome even when preparation failed\n", 1)[1]
    writer, upload = step.split("      - name: Retain exact candidate identity and outcome\n", 1)
    assert "        if: always()\n" in writer
    assert "        if: always()\n" in upload
    assert "          if-no-files-found: error\n" in upload
    source = writer.split("          /usr/bin/python3 - <<'PY'\n", 1)[1].split("          PY\n", 1)[0]
    return compile(textwrap.dedent(source), str(WORKFLOW), "exec")


@pytest.mark.parametrize("failed_stage", STAGES)
def test_early_failure_produces_evidence_without_checkout_or_dependencies(tmp_path, monkeypatch, failed_stage):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("OUTCOME_RUN_SHA", "a" * 40)
    monkeypatch.setenv("OUTCOME_RUN_ID", "123")
    monkeypatch.setenv("OUTCOME_RUN_ATTEMPT", "2")
    monkeypatch.setenv("OUTCOME_MODE", "crash-before-commit")
    monkeypatch.setenv("OUTCOME_JOB_STATUS", "failure")
    monkeypatch.setenv("GH_TOKEN", "secret-must-not-be-exported")
    monkeypatch.setenv("UNRELATED_PRIVATE_VALUE", "private-must-not-be-exported")
    for stage in STAGES:
        monkeypatch.setenv("OUTCOME_" + stage, "failure" if stage == failed_stage else "skipped")
    assert list(tmp_path.iterdir()) == []
    exec(evidence_script(), {})
    path = tmp_path / "root-update/workflow-outcome.json"
    raw = path.read_text()
    record = json.loads(raw)
    assert record["schema_version"] == 1
    assert record["source_sha"] == "a" * 40
    assert record["run_id"] == "123" and record["run_attempt"] == "2"
    assert record["mode"] == "crash-before-commit"
    assert record["job_status_before_upload"] == "failure"
    assert record["steps"][failed_stage.lower()] == "failure"
    assert "secret-must-not-be-exported" not in raw
    assert "private-must-not-be-exported" not in raw
    assert len(raw) < 2048


def test_outcome_context_is_bounded_and_json_escaped(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    malicious = '"\n\\' * 10000
    for name in ("RUN_SHA", "RUN_ID", "RUN_ATTEMPT", "MODE", "JOB_STATUS", *STAGES):
        monkeypatch.setenv("OUTCOME_" + name, malicious)
    exec(evidence_script(), {})
    raw = (tmp_path / "root-update/workflow-outcome.json").read_text()
    record = json.loads(raw)
    assert record["source_sha"] == malicious[:256]
    assert all(len(value) <= 256 for value in record["steps"].values())
    assert len(raw) < 8192

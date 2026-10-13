from __future__ import annotations

import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from test_build_config import ACTION_PINS, ROOT


SCANS = (
    ("dependency-audit.yml", "audit", "app", "dependency-audit-app-evidence"),
)
EVIDENCE_FILES = ("receipt.json", "input.spdx.json", "policy.json", "osv.json")


def job_steps(workflow: str, job: str) -> list[str]:
    match = re.search(rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [\w-]+:\n|\Z)", workflow)
    if match is None:
        raise AssertionError(f"missing workflow job {job}")
    return re.split(r"(?m)^      - ", match[1])[1:]


def evidence_steps(workflow: str, job: str, leaf: str, step_id: str) -> tuple[str, str, str]:
    steps = job_steps(workflow, job)
    scans = [s for s in steps if "scripts/dependency_audit.py scan" in s]
    probes = [s for s in steps if s.startswith(f"id: {step_id}\n")]
    uploads = [s for s in steps if f"steps.{step_id}.outputs.available" in s]
    if not (len(scans) == len(probes) == len(uploads) == 1):
        raise AssertionError(f"{job}: every scan needs one independent evidence probe and upload")
    scan, probe, upload = scans[0], probes[0], uploads[0]
    if f'--evidence-dir "$RUNNER_TEMP/dependency-audit-evidence/{leaf}"' not in scan:
        raise AssertionError(f"{job}: scan does not preserve explicit isolated evidence")
    if not steps.index(scan) < steps.index(probe) < steps.index(upload):
        raise AssertionError(f"{job}: evidence collection must follow the scan")
    return scan, probe, upload


class DependencyAuditWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflows = {
            filename: (ROOT / ".github/workflows" / filename).read_text()
            for filename, *_ in SCANS
        }

    def test_app_scan_has_independent_evidence(self) -> None:
        for filename, job, leaf, step_id in SCANS:
            evidence_steps(self.workflows[filename], job, leaf, step_id)

    def test_policy_or_report_failure_cannot_skip_evidence_upload(self) -> None:
        for filename, job, leaf, step_id in SCANS:
            with self.subTest(job=job):
                scan, probe, upload = evidence_steps(self.workflows[filename], job, leaf, step_id)
                self.assertIn("set -euo pipefail", scan)
                self.assertIn("scripts/dependency_audit.py verify", scan)
                self.assertRegex(probe, r"(?m)^        if: always\(\)$")
                self.assertIn(f"if: always() && steps.{step_id}.outputs.available == 'true'", upload)
                self.assertNotIn("continue-on-error", scan)
                self.assertNotIn("continue-on-error", upload)

    def test_uploads_are_pinned_separate_and_attempt_specific(self) -> None:
        names = set()
        for filename, job, leaf, step_id in SCANS:
            with self.subTest(job=job):
                _, _, upload = evidence_steps(self.workflows[filename], job, leaf, step_id)
                self.assertIn("actions/upload-artifact@" + ACTION_PINS["actions/upload-artifact"][0], upload)
                paths = re.search(r"(?ms)^          path: \|\n(.*?)(?=^          \S|\Z)", upload)[1]
                self.assertEqual(
                    [line.strip() for line in paths.splitlines() if line.strip()],
                    [f"${{{{ runner.temp }}}}/dependency-audit-evidence/{leaf}/{name}" for name in EVIDENCE_FILES],
                )
                self.assertIn("retention-days: 14", upload)
                self.assertIn("if-no-files-found: error", upload)
                name = re.search(r"(?m)^          name: (.+)$", upload)[1]
                self.assertIn("${{ github.sha }}", name)
                self.assertIn("${{ github.run_attempt }}", name)
                self.assertNotIn(name, names)
                names.add(name)
        for workflow in self.workflows.values():
            self.assertNotRegex(workflow, r"subject-path:.*dependency-audit-evidence")

    def _probe(self, filename: str, job: str, leaf: str, step_id: str, state: str) -> bool:
        _, probe, _ = evidence_steps(self.workflows[filename], job, leaf, step_id)
        run = re.search(r"(?ms)^        run: \|\n(.*)", probe)[1]
        script = textwrap.dedent(run).strip() + "\n"
        with tempfile.TemporaryDirectory(prefix="slipstream-evidence-workflow-") as tmp:
            root = Path(tmp)
            directory = root / "dependency-audit-evidence" / leaf
            output = root / "github-output"
            if state != "not-reached":
                directory.mkdir(parents=True)
            if state in {"policy-failure", "timeout", "success"}:
                (directory / "receipt.json").write_text('{"status":"' + state + '"}\n')
                (directory / "osv.json").write_bytes(b'{"partial":' if state == "timeout" else b'{}\n')
            if state in {"symlink-only", "mixed-symlink"}:
                private = root / "do-not-upload"
                private.write_text("fixture secret")
                (directory / "receipt.json").symlink_to(private)
                if state == "mixed-symlink":
                    (directory / "osv.json").write_text("{}\n")
            if state == "nonregular-file":
                (directory / "receipt.json").mkdir()
            if state == "unrelated-only":
                (directory / "private.log").write_text("fixture secret")
            if state == "directory-symlink":
                directory.rmdir()
                private = root / "unrelated"
                private.mkdir()
                (private / "receipt.json").write_text("fixture secret")
                directory.symlink_to(private, target_is_directory=True)
            env = {"PATH": "/usr/bin:/bin", "RUNNER_TEMP": str(root), "GITHUB_OUTPUT": str(output)}
            completed = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", script],
                                       env=env, capture_output=True, text=True, timeout=5, check=False)
            expected_exit = 1 if state in {"symlink-only", "mixed-symlink", "nonregular-file"} else 0
            self.assertEqual(completed.returncode, expected_exit, completed.stderr)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")
            value = output.read_text() if output.exists() else ""
            self.assertIn(value, ("", "available=true\n"))
            return value == "available=true\n"

    def test_actual_probe_skips_unreached_or_empty_scan(self) -> None:
        for config in SCANS:
            for state in ("not-reached", "empty", "unrelated-only"):
                with self.subTest(job=config[1], state=state):
                    self.assertFalse(self._probe(*config, state))

    def test_actual_probe_retains_success_policy_failure_and_partial_timeout(self) -> None:
        for config in SCANS:
            for state in ("success", "policy-failure", "timeout"):
                with self.subTest(job=config[1], state=state):
                    self.assertTrue(self._probe(*config, state))

    def test_actual_probe_never_uploads_linked_or_nonregular_evidence(self) -> None:
        for config in SCANS:
            for state in ("symlink-only", "mixed-symlink", "directory-symlink", "nonregular-file"):
                with self.subTest(job=config[1], state=state):
                    self.assertFalse(self._probe(*config, state))


if __name__ == "__main__":
    unittest.main()

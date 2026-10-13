from __future__ import annotations

import contextlib
import hashlib
import io
import json
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import dependency_audit
from test_dependency_audit import SOURCE_COMMIT, TARGET, osv_result, sbom_package


class DependencyAuditEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sbom = self.root / "original.spdx.json"
        self.policy = self.root / "original-policy.json"
        self.scanner = self.root / "scanner"
        self.output = self.root / "audit.json"
        self.evidence = self.root / "evidence"
        self.sbom_bytes = json.dumps({"packages": [sbom_package(
            ecosystem="cargo", name="serde", version="1",
        )]}, indent=2).encode() + b"\n"
        self.sbom.write_bytes(self.sbom_bytes)

    def _prepare(self, mode: str = "pass", *, scan_exit: int = 0) -> bytes:
        vulnerabilities = [{"id": "GHSA-test-blocking", "affected": []}] if mode == "blocking" else []
        payload = osv_result(({
            "ecosystem": "crates.io", "name": "serde",
            "version": "" if mode == "identity" else "1",
        }, vulnerabilities))
        if mode == "expired-policy":
            self.sbom_bytes = json.dumps({"packages": [sbom_package(
                ecosystem="generic", name="chromium-headless-shell", version="151.0.7922.77",
                sha256="ab" * 32,
            )]}, indent=2).encode() + b"\n"
            self.sbom.write_bytes(self.sbom_bytes)
            payload = osv_result(({
                "ecosystem": "", "name": "chromium-headless-shell", "version": "151.0.7922.77",
            }, []))
        payload["results"][0]["source"]["path"] = "input.spdx.json"
        raw = b"{malformed JSON\n" if mode == "malformed" else json.dumps(payload, indent=3).encode() + b"\n\n"
        # A real local process writes exactly the bytes a scanner would produce.
        self.scanner.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys, time\nfrom pathlib import Path\n"
            "print('PRIVATE_SCANNER_DIAGNOSTIC stdout', flush=True) if '--version' not in sys.argv else None\n"
            "print('PRIVATE_SCANNER_DIAGNOSTIC stderr', file=sys.stderr, flush=True) if '--version' not in sys.argv else None\n"
            f"mode = {mode!r}\n"
            "if '--version' in sys.argv:\n"
            "    if mode == 'mutate-originals':\n"
            f"        Path({str(self.sbom)!r}).write_text('{{\"packages\": []}}')\n"
            f"        Path({str(self.policy)!r}).write_text('{{}}')\n"
            f"        Path({str(self.scanner)!r}).write_text('#!/bin/sh\\nexit 99\\n')\n"
            "    print('osv-scanner version 2.3.0')\n    raise SystemExit(0)\n"
            "assert sys.argv[sys.argv.index('-L') + 1] == 'input.spdx.json'\n"
            "assert Path('input.spdx.json').is_file()\n"
            "receipt = json.loads(Path('receipt.json').read_text())\n"
            "assert receipt['status'] == 'started' and receipt['scan']['state'] == 'running'\n"
            "assert 'finished_at' not in receipt\n"
            "output = Path(sys.argv[sys.argv.index('--output-file') + 1])\n"
            "assert output.parent != Path.cwd()\n"
            "if mode == 'symlink':\n"
            f"    output.symlink_to({str(self.policy)!r})\n"
            "    raise SystemExit(0)\n"
            "if mode == 'fifo':\n    os.mkfifo(output)\n    raise SystemExit(0)\n"
            "if mode == 'directory':\n"
            "    output.mkdir()\n    (output / 'unexpected').write_text('not raw')\n"
            "    raise SystemExit(0)\n"
            "if mode != 'missing':\n"
            f"    output.write_bytes({raw!r})\n"
            "if mode == 'timeout':\n    time.sleep(60)\n"
            "if mode == 'mutate-snapshot':\n"
            "    Path('input.spdx.json').chmod(0o600)\n"
            "    Path('input.spdx.json').write_text('{\"packages\": []}')\n"
            f"raise SystemExit({scan_exit})\n",
            encoding="utf-8",
        )
        self.scanner.chmod(0o700)
        self.scanner_sha = dependency_audit.hash_file(self.scanner)
        policy = {
            "schema_version": 1,
            "rules": {"informational": "record", "unreviewed": "block"},
            "scanner": {"repository": "google/osv-scanner", "version": "2.3.0", "assets": {
                "darwin-arm64": {"name": "osv-scanner_darwin_arm64", "sha256": self.scanner_sha},
            }},
            "exceptions": [],
        }
        if mode == "expired-policy":
            policy["integrity_only"] = [{
                "name": "chromium-headless-shell", "version": "151.0.7922.77",
                "purl": "pkg:generic/chromium-headless-shell@151.0.7922.77",
                "sha256": "ab" * 32, "expires": "2026-09-30",
                "reason": "Expired fixture: preserve rejection and diagnostic evidence.",
            }]
        self.policy_bytes = json.dumps(policy, indent=2).encode() + b"\n"
        self.policy.write_bytes(self.policy_bytes)
        return raw

    def _run(self) -> tuple[int, dict]:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = dependency_audit.main([
                "scan", "--scanner", str(self.scanner), "--platform", "darwin-arm64",
                "--sbom", str(self.sbom), "--policy", str(self.policy),
                "--source-commit", SOURCE_COMMIT, "--target", TARGET,
                "--evaluation-date", "2026-10-11", "--output", str(self.output),
                "--evidence-dir", str(self.evidence),
            ])
        return code, json.loads(stdout.getvalue())

    def _receipt(self) -> dict:
        return json.loads((self.evidence / "receipt.json").read_text())

    def _assert_raw(self, raw: bytes, state: str) -> dict:
        self.assertEqual((self.evidence / "osv.json").read_bytes(), raw)
        receipt = self._receipt()
        self.assertEqual(receipt["raw"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(receipt["raw"]["size_bytes"], len(raw))
        self.assertEqual(receipt["raw"]["state"], state)
        self.assertNotIn(str(self.root), (self.evidence / "receipt.json").read_text())
        self.assertFalse((self.evidence / "scanner").exists())
        self.assertEqual({p.name for p in self.evidence.iterdir()},
                         {"input.spdx.json", "policy.json", "osv.json", "receipt.json"})
        for path in self.evidence.iterdir():
            self.assertNotIn(b"PRIVATE_SCANNER_DIAGNOSTIC", path.read_bytes())
        self.assertEqual(stat.S_IMODE(self.evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.evidence / "osv.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.evidence / "receipt.json").stat().st_mode), 0o600)
        return receipt

    def test_pass_keeps_exact_bytes_and_binds_both_inputs_and_report(self) -> None:
        raw = self._prepare()
        code, summary = self._run()
        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "pass")
        receipt = self._assert_raw(raw, "complete")
        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["scanner"]["sha256"], self.scanner_sha)
        self.assertEqual(receipt["evaluator_sha256"], dependency_audit.hash_file(Path(dependency_audit.__file__)))
        self.assertEqual(receipt["report"]["sha256"], dependency_audit.hash_file(self.output))
        self.assertIn("started_at", receipt)
        self.assertIn("finished_at", receipt)
        report = json.loads(self.output.read_text())
        for kind, raw_input, filename in (
            ("sbom", self.sbom_bytes, "input.spdx.json"),
            ("policy", self.policy_bytes, "policy.json"),
        ):
            self.assertEqual((self.evidence / filename).read_bytes(), raw_input)
            digest = hashlib.sha256(raw_input).hexdigest()
            self.assertEqual(receipt["inputs"][kind]["sha256"], digest)
            self.assertEqual(report["inputs"][f"{kind}_sha256"], digest)

    def test_scanner_exit_one_can_still_be_a_valid_audit_input(self) -> None:
        raw = self._prepare(scan_exit=1)
        self.assertEqual(self._run()[0], 0)
        self.assertEqual(self._assert_raw(raw, "complete")["scan"]["exit_code"], 1)

    def test_blocking_audit_keeps_raw_and_fail_report(self) -> None:
        raw = self._prepare("blocking", scan_exit=1)
        self.assertEqual(self._run()[0], 1)
        receipt = self._assert_raw(raw, "complete")
        self.assertEqual(receipt["status"], "fail")
        self.assertEqual(receipt["report"]["sha256"], dependency_audit.hash_file(self.output))

    def test_incomplete_coordinate_rejection_keeps_raw_but_no_report(self) -> None:
        raw = self._prepare("identity")
        self.assertEqual(self._run()[0], 1)
        receipt = self._assert_raw(raw, "complete")
        self.assertEqual(receipt["status"], "error")
        self.assertEqual(receipt["stage"], "audit")
        self.assertNotIn("report", receipt)
        self.assertFalse(self.output.exists())

    def test_expired_integrity_policy_keeps_raw_and_still_rejects_release(self) -> None:
        raw = self._prepare("expired-policy")
        code, summary = self._run()
        self.assertEqual(code, 1)
        self.assertEqual(summary, {"status": "error", "stage": "audit", "error_type": "ValueError"})
        receipt = self._assert_raw(raw, "complete")
        self.assertEqual(receipt["status"], "error")
        self.assertNotIn("report", receipt)
        self.assertFalse(self.output.exists())
        policy_snapshot = json.loads((self.evidence / "policy.json").read_text())
        self.assertEqual(policy_snapshot["integrity_only"][0]["expires"], "2026-09-30")
        with self.assertRaisesRegex(ValueError, "integrity-only policy is expired"):
            dependency_audit.build_audit_report(
                osv_result=json.loads(raw), policy=policy_snapshot,
                policy_path=self.evidence / "policy.json", sbom_path=self.evidence / "input.spdx.json",
                scanner=receipt["scanner"], source_commit=SOURCE_COMMIT, target=TARGET,
                evaluated_on=dependency_audit.date(2026, 10, 11),
            )

    def test_operational_failure_keeps_partial_bytes(self) -> None:
        raw = self._prepare(scan_exit=7)
        code, summary = self._run()
        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "error")
        receipt = self._assert_raw(raw, "partial")
        self.assertEqual(receipt["scan"]["exit_code"], 7)
        self.assertEqual(receipt["status"], "error")
        self.assertFalse(self.output.exists())

    def test_malformed_output_keeps_exact_invalid_bytes(self) -> None:
        raw = self._prepare("malformed")
        self.assertEqual(self._run()[0], 1)
        receipt = self._assert_raw(raw, "invalid")
        self.assertEqual(receipt["stage"], "parse")
        self.assertEqual(receipt["status"], "error")
        self.assertFalse(self.output.exists())

    def test_missing_output_is_explicit(self) -> None:
        self._prepare("missing")
        self.assertEqual(self._run()[0], 1)
        self.assertEqual(self._receipt()["raw"]["state"], "missing")
        self.assertFalse(self.output.exists())

    def test_timeout_keeps_partial_bytes_and_terminal_failure(self) -> None:
        raw = self._prepare("timeout")
        real_run = subprocess.run

        def timeout_after_output(command, **kwargs):
            if "--version" in command:
                return real_run(command, **kwargs)
            # Synchronize on the real child writing its output. A tiny timeout
            # measured from process launch is flaky under concurrent CI load.
            output = Path(command[command.index("--output-file") + 1])
            process = subprocess.Popen(
                command, cwd=kwargs["cwd"], stdout=kwargs["stdout"],
                stderr=kwargs["stderr"], shell=False,
            )
            try:
                deadline = time.monotonic() + 10
                while not output.exists() or output.read_bytes() != raw:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        self.fail("fake scanner did not write its partial output")
                    time.sleep(0.01)
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.wait(timeout=0.01)
            finally:
                process.kill()
                process.wait()
            raise subprocess.TimeoutExpired(command, 0.01)

        with patch.object(dependency_audit.subprocess, "run", side_effect=timeout_after_output):
            self.assertEqual(self._run()[0], 1)
        receipt = self._assert_raw(raw, "partial")
        self.assertEqual(receipt["scan"]["state"], "timeout")
        self.assertEqual(receipt["status"], "error")
        self.assertFalse(self.output.exists())

    def test_mutable_original_inputs_and_scanner_cannot_change_scan(self) -> None:
        raw = self._prepare("mutate-originals")
        self.assertEqual(self._run()[0], 0)
        self.assertNotEqual(self.sbom.read_bytes(), self.sbom_bytes)
        self.assertNotEqual(self.policy.read_bytes(), self.policy_bytes)
        self.assertNotEqual(dependency_audit.hash_file(self.scanner), self.scanner_sha)
        receipt = self._assert_raw(raw, "complete")
        self.assertEqual(receipt["scanner"]["sha256"], self.scanner_sha)
        dependency_audit.validate_audit_report_file(
            report_path=self.output, policy_path=self.evidence / "policy.json",
            sbom_path=self.evidence / "input.spdx.json", source_commit=SOURCE_COMMIT,
            target=TARGET,
        )

    def test_snapshot_mutation_is_rejected(self) -> None:
        raw = self._prepare("mutate-snapshot")
        self.assertEqual(self._run()[0], 1)
        receipt = self._assert_raw(raw, "complete")
        self.assertEqual(receipt["status"], "error")
        self.assertFalse(self.output.exists())

    def test_existing_evidence_directory_is_never_reused(self) -> None:
        self._prepare()
        self.evidence.mkdir()
        marker = self.evidence / "receipt.json"
        marker.write_text("previous evidence")
        self.assertEqual(self._run()[0], 1)
        self.assertEqual(marker.read_text(), "previous evidence")
        self.assertEqual(list(self.evidence.iterdir()), [marker])
        self.assertFalse(self.output.exists())

    def test_oversized_raw_is_explicitly_omitted_not_truncated(self) -> None:
        self._prepare()
        with patch.object(dependency_audit, "MAX_OSV_EVIDENCE_BYTES", 8):
            self.assertEqual(self._run()[0], 1)
        receipt = self._receipt()
        self.assertEqual(receipt["raw"]["state"], "oversized")
        self.assertGreater(receipt["raw"]["size_bytes"], 8)
        self.assertFalse((self.evidence / "osv.json").exists())
        self.assertFalse(self.output.exists())

    def test_non_regular_raw_never_enters_uploadable_evidence(self) -> None:
        for mode in ("symlink", "fifo", "directory"):
            with self.subTest(mode=mode):
                self.evidence = self.root / f"evidence-{mode}"
                self._prepare(mode)
                self.assertEqual(self._run()[0], 1)
                self.assertEqual(self._receipt()["raw"]["state"], "invalid_file")
                self.assertEqual(self.policy.read_bytes(), self.policy_bytes)
                self.assertEqual(
                    sorted(path.name for path in self.evidence.iterdir()),
                    ["input.spdx.json", "policy.json", "receipt.json"],
                )
                self.assertTrue(all(path.is_file() and not path.is_symlink() for path in self.evidence.iterdir()))
                self.assertFalse(self.output.exists())

    def test_failed_scan_does_not_bind_a_preexisting_report(self) -> None:
        self._prepare("identity")
        self.output.write_bytes(b"previous report\n")
        self.assertEqual(self._run()[0], 1)
        self.assertEqual(self.output.read_bytes(), b"previous report\n")
        self.assertNotIn("report", self._receipt())

    def test_report_cannot_replace_raw_or_receipt(self) -> None:
        self._prepare()
        self.output = self.evidence / "osv.json"
        self.assertEqual(self._run()[0], 1)
        self.assertFalse(self.evidence.exists())


if __name__ == "__main__":
    unittest.main()

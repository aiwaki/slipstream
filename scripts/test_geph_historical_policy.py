"""Execute the existing-release policy check with local, synthetic audit inputs."""

import copy
from datetime import date
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest

import dependency_audit


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "a" * 40


class HistoricalGephPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="geph historical ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "existing"
        self.assets.mkdir()
        (self.root / "security").mkdir()
        (self.root / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
        policy = dependency_audit.load_policy(ROOT / "security/geph-dependency-audit-policy.json")
        # This historical fixture models registry packages, not a source-owned lane.
        policy.pop("source_owned_review", None)
        policy["exceptions"] = [dict(
            id="fixture-allowance", ecosystem="crates.io", package="fixture", version="1.0.0",
            advisories=["CVE-2026-0001"], reason="Synthetic historical fixture", expires="2026-10-29",
        )]
        self.historical_policy = self.root / "historical.json"
        self.historical_policy.write_text(json.dumps(policy))
        current = copy.deepcopy(policy)
        current["exceptions"].append({**policy["exceptions"][0], "id": "later-reviewed-allowance", "package": "other"})
        self.current_policy = self.root / "security/geph-dependency-audit-policy.json"
        self.current_policy.write_text(json.dumps(current))
        self.sbom = self.assets / "geph5-client.spdx.json"
        self.sbom.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{
            "SPDXID": "SPDXRef-fixture", "name": "fixture", "versionInfo": "1.0.0",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": "pkg:cargo/fixture@1.0.0"}],
        }]}))
        report = dependency_audit.build_audit_report(
            osv_result={"results": [{"packages": [{
                "package": {"ecosystem": "crates.io", "name": "fixture", "version": "1.0.0"},
                "vulnerabilities": [{"id": "CVE-2026-0001", "aliases": [], "affected": []}],
            }]}]}, policy=policy, policy_path=self.historical_policy, sbom_path=self.sbom,
            scanner=dependency_audit.expected_scanner_metadata(policy, "linux-amd64"),
            source_commit=SOURCE, target="macos-universal", evaluated_on=date(2026, 10, 26),
            vendored_transitive_dependencies="full",
        )
        self.report = self.assets / "geph5-client-dependency-audit.json"
        self.report.write_text(json.dumps(report))
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "python3").symlink_to(sys.executable)
        (self.bin / "gh").write_text(
            f"#!{sys.executable}\nimport json, os, pathlib, sys\n"
            "pathlib.Path('gh-args.json').write_text(json.dumps(sys.argv[1:]))\n"
            f"expected = ['api', '-H', 'Accept: application/vnd.github.raw+json', "
            f"'repos/aiwaki/slipstream/contents/security/geph-dependency-audit-policy.json?ref={SOURCE}']\n"
            "if sys.argv[1:] != expected: raise SystemExit(9)\n"
            "mode = os.environ['FETCH_MODE']\n"
            "if mode == 'missing': raise SystemExit(8)\n"
            "if mode == 'empty': raise SystemExit(0)\n"
            "if mode == 'invalid': sys.stdout.write('{'); raise SystemExit(0)\n"
            "path = 'security/geph-dependency-audit-policy.json' if mode == 'wrong-policy' else 'historical.json'\n"
            "sys.stdout.buffer.write(pathlib.Path(path).read_bytes())\n"
        )
        (self.bin / "gh").chmod(0o755)

    def run_existing_check(self, mode="ok", source=SOURCE):
        workflow = (ROOT / ".github/workflows/build-geph.yml").read_text()
        decision = workflow.split("name: Decide whether review or build is required", 1)[1]
        decision = decision.split("\n  bump:", 1)[0]
        # Prior SOURCE/lock/tag/SPDX checks are unchanged. Execute the actual
        # following shell, not a reproduction of its policy-selection logic.
        body = decision.split("              --sbom /tmp/geph-existing/geph5-client.spdx.json\n", 1)[1]
        body = textwrap.dedent(body.split("\n          fi", 1)[0])
        body = body.replace("/tmp/geph-existing", shlex.quote(str(self.assets)))
        body = body.replace("${{ github.repository }}", "aiwaki/slipstream")
        return subprocess.run(
            ["/bin/bash", "-c", "set -euo pipefail\n" + body], cwd=self.root,
            env={"PATH": str(self.bin) + os.pathsep + "/usr/bin:/bin",
                 "RUNNER_TEMP": str(self.root), "tag_commit": SOURCE,
                 "vendor_commit": source, "source_owned": "false", "FETCH_MODE": mode},
            capture_output=True, text=True, timeout=10,
        )

    def test_existing_report_uses_immutable_tag_policy_when_current_policy_changes(self):
        original = (self.report.read_bytes(), self.sbom.read_bytes(), self.current_policy.read_bytes())
        result = self.run_existing_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["accepted_exceptions"], 1)
        self.assertEqual((self.report.read_bytes(), self.sbom.read_bytes(), self.current_policy.read_bytes()), original)
        self.assertIn("?ref=" + SOURCE, (self.root / "gh-args.json").read_text())

    def test_missing_empty_malformed_or_wrong_historical_policy_fails_closed(self):
        for mode in ("missing", "empty", "invalid", "wrong-policy"):
            with self.subTest(mode=mode):
                result = self.run_existing_check(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('"accepted_exceptions"', result.stdout)

    def test_tampered_sbom_or_source_cannot_pass_with_historical_policy(self):
        original = self.sbom.read_bytes()
        self.sbom.write_bytes(original + b"\n")
        result = self.run_existing_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("input hashes do not match", result.stderr)
        self.sbom.write_bytes(original)
        result = self.run_existing_check(source="b" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source", result.stderr)

    def test_historical_verification_does_not_extend_current_publication_admission(self):
        with self.assertRaisesRegex(ValueError, "exception is expired at admission"):
            dependency_audit.validate_audit_report_file(
                report_path=self.report, sbom_path=self.sbom, policy_path=self.historical_policy,
                source_commit=SOURCE, target="macos-universal",
                vendored_transitive_dependencies="full", admission_on=date(2026, 10, 30),
            )

    def test_tag_binding_and_new_build_current_policy_are_preserved(self):
        workflow = (ROOT / ".github/workflows/build-geph.yml").read_text()
        decision = workflow.split("name: Decide whether review or build is required", 1)[1].split("\n  bump:", 1)[0]
        self.assertIn('[ "$vendor_commit" = "$tag_commit" ]', decision)
        self.assertIn('cmp vendor/geph/SOURCE.json', decision)
        self.assertIn('cmp vendor/geph/Cargo.lock', decision)
        build = workflow.split("\n  build:", 1)[1]
        for operation in ("scan", "verify"):
            command = build.split("python3 scripts/dependency_audit.py " + operation, 1)[1]
            command = command.split("\n      - ", 1)[0]
            self.assertIn("--policy security/geph-dependency-audit-policy.json", command)
            self.assertNotIn("--policy \"$historical_policy\"", command)

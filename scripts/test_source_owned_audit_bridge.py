"""Audit orchestration tests; exact source/evidence checks have their own suite."""
import copy
import contextlib
import io
import json
from datetime import date
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import dependency_audit as audit
import test_dependency_audit as fixtures


class SourceOwnedAuditBridgeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.NativeAuditBridgeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        def native_review(policy, **kwargs):
            value = f._validate_review(policy, **kwargs)
            value["binding"]["source_sha256"] = audit.hash_file(kwargs["source_path"])
            return value
        sys.modules["geph_native_sqlite_advisories"].validate_native_review = native_review
        self.owned = [{"SPDXID": "SPDXRef-Owned-" + str(i), "name": "owned-" + str(i),
                       "versionInfo": "1"} for i in range(3)]
        self.ids = sorted(p["SPDXID"] for p in self.owned)
        self.evidence = f.root / "owned-evidence"
        self.evidence.mkdir()
        (self.evidence / "review.json").write_text("exact reviewed source evidence")
        f.packages.extend(self.owned)
        document = json.loads(f.sbom.read_text())
        document["packages"] = f.packages
        document["files"] = [{"SPDXID": "SPDXRef-OwnedFile"}]
        document["relationships"].append({"spdxElementId": self.ids[0],
            "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-OwnedFile"})
        f.sbom.write_text(json.dumps(document))
        f.policy["source_owned_review"] = {"fixture_outcome": "pass"}
        f._save_policy()
        helper = types.ModuleType("geph_source_owned_advisories")
        helper.validate_source_owned_review = self._review
        helper.retain_source_owned_review_evidence = self._retain
        patcher = patch.dict(sys.modules, {"geph_source_owned_advisories": helper})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _review(self, policy, **kwargs):
        self.assertEqual(kwargs["source_commit"], fixtures.SOURCE_COMMIT)
        self.assertEqual(kwargs["source_path"].read_text(), "reviewed SOURCE")
        self.assertEqual((kwargs["evidence_root"] / "review.json").read_text(), "exact reviewed source evidence")
        actual = [p for p in kwargs["sbom"]["packages"] if p["SPDXID"] in self.ids]
        if actual != self.owned:
            raise ValueError("source-owned inventory mismatch")
        outcome = policy["fixture_outcome"]
        return {"schema_version": 1, "package_ids": self.ids,
            "review_sha256": "a" * 64, "binding": {"source_sha256": audit.hash_file(kwargs["source_path"])},
            "packages": [{"outcome": outcome}], "summary": {"packages": 3,
                "unresolved": int(outcome != "pass"), "affected": int(outcome == "affected")},
            "status": "pass" if outcome == "pass" else "fail"}

    def _retain(self, policy, root, destination):
        destination.mkdir()
        audit._snapshot_audit_input(root / "review.json", destination / "review.json", 1024)
        return {"root": str(destination), "review_sha256": "a" * 64}

    def _build(self, **kwargs):
        return self.fixture._build(**({"source_owned_evidence": self.evidence} | kwargs))

    def _verify(self, report, **kwargs):
        return self.fixture._verify(report, **({"source_owned_evidence": self.evidence} | kwargs))

    def test_all_three_lanes_are_bound_and_projection_excludes_owned_files(self):
        report = self._build()
        self.assertEqual(report["schema_version"], 3)
        self.assertEqual(report["package_partition"], {"scanned": sorted(p["SPDXID"] for p in self.fixture.packages[:2]),
            "integrity_only": [], "native": [self.fixture.native["SPDXID"]], "source_owned": self.ids})
        summary = self._verify(report)
        self.assertEqual(summary["packages_source_owned"], 3)
        self.assertEqual(summary["packages_scanned"], 2)
        self.assertEqual(summary["packages_native"], 1)
        projection = json.loads(audit._reviewed_scanner_sbom(json.loads(self.fixture.sbom.read_text()),
            self.fixture.native["SPDXID"], self.ids))
        self.assertEqual(projection["packages"], self.fixture.packages[:2])
        self.assertEqual(projection["files"], [])
        self.assertEqual(projection["relationships"], [])

    def test_source_owned_does_not_require_native_policy_or_proof(self):
        f = self.fixture
        del f.policy["native_sqlite_review"]
        f._save_policy()
        document = json.loads(f.sbom.read_text())
        document["packages"].remove(f.native)
        f.sbom.write_text(json.dumps(document))
        report = self._build(native_receipt=None, native_artifacts_root=None, native_advisory_evidence=None)
        self.assertEqual(report["package_partition"]["native"], [])
        self.assertNotIn("native_sqlite_review", report)
        self.assertNotIn("packages_native", report["summary"])
        self._verify(report, native_receipt=None, native_artifacts_root=None)

    def test_unknown_and_affected_reviews_cannot_be_serialized_into_pass(self):
        for outcome in ("unknown", "affected"):
            with self.subTest(outcome=outcome):
                self.fixture.policy["source_owned_review"]["fixture_outcome"] = outcome
                self.fixture._save_policy()
                report = self._build()
                self.assertEqual(report["status"], "fail")
                report["status"] = "pass"
                report["source_owned_review"]["status"] = "pass"
                report["source_owned_review"]["summary"]["unresolved"] = 0
                with self.assertRaises(ValueError):
                    self._verify(report)

    def test_forged_partition_counts_review_and_projection_fail(self):
        original = self._build()
        mutations = (
            lambda r: r["package_partition"]["source_owned"].pop(),
            lambda r: r["package_partition"]["scanned"].append(self.ids[0]),
            lambda r: r["summary"].update(packages_source_owned=True),
            lambda r: r["summary"].update(source_owned_unresolved=True),
            lambda r: r["source_owned_review"].update(package_ids=[]),
            lambda r: r["inputs"].update(scanner_sbom_sha256="0" * 64),
            lambda r: r.pop("source_owned_review"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                mutation(report)
                with self.assertRaises(ValueError):
                    self._verify(report)

    def test_unreviewed_package_cannot_hide_in_source_owned_lane(self):
        document = json.loads(self.fixture.sbom.read_text())
        document["packages"].append({"SPDXID": "SPDXRef-Unreviewed", "name": "unknown", "versionInfo": "1"})
        self.fixture.sbom.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "purl"):
            self._build()

    def test_valid_reviews_for_different_source_snapshots_cannot_be_combined(self):
        report = self._build()
        mismatched = copy.deepcopy(report["source_owned_review"])
        mismatched["binding"]["source_sha256"] = "d" * 64
        with patch.object(audit, "_source_owned_review", return_value=mismatched):
            with self.assertRaisesRegex(ValueError, "different SOURCE"):
                self._build()
            with self.assertRaisesRegex(ValueError, "different SOURCE"):
                self._verify(report)

    def test_missing_paths_or_policy_rejected(self):
        report = self._build()
        for overrides in ({"source_path": None}, {"source_owned_evidence": None}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError): self._build(**overrides)
                with self.assertRaises(ValueError): self._verify(report, **overrides)
        del self.fixture.policy["source_owned_review"]
        self.fixture._save_policy()
        with self.assertRaises(ValueError): self._build()
        with self.assertRaises(ValueError): self._verify(report)

    def test_ancestor_or_local_rows_are_not_counted_as_registry_release_packages(self):
        for row in ({"ecosystem": "crates.io", "name": "mizaru2", "version": "0.2.21"},
                    {"ecosystem": "crates.io", "name": "owned-0", "version": "1"}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                self._build(rows=[*self.fixture.rows, row])

    def _scan_args(self, scanner, evidence, output):
        f = self.fixture
        return ["scan", "--scanner", str(scanner), "--platform", "darwin-arm64", "--sbom", str(f.sbom),
            "--policy", str(f.policy_path), "--source-commit", fixtures.SOURCE_COMMIT, "--target", fixtures.TARGET,
            "--evaluation-date", "2026-10-13", "--output", str(output), "--evidence-dir", str(evidence),
            "--source", str(f.source), "--native-receipt", str(f.receipt), "--native-artifacts-root", str(f.artifacts),
            "--native-advisory-evidence", str(f.advisories), "--source-owned-evidence", str(self.evidence),
            "--vendored-transitive-dependencies", "full"]

    def test_scan_freezes_source_owned_evidence_and_preserves_release_inventory(self):
        f = self.fixture
        scanner, evidence, output = f.root / "scanner", f.root / "scan", f.root / "report.json"
        raw = fixtures.osv_result(*((row, []) for row in f.rows))
        scanner.write_text(f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
            "if '--version' in sys.argv:\n    print('osv-scanner version 2.3.0'); raise SystemExit(0)\n"
            "projection=json.loads(Path(sys.argv[sys.argv.index('-L')+1]).read_text())\n"
            f"assert projection['packages'] == {f.packages[:2]!r}\n"
            "assert projection['files'] == []\n"
            "assert len(json.loads(Path('input.spdx.json').read_text())['packages']) == 6\n"
            f"Path({str(f.source)!r}).write_text('changed original')\n"
            f"Path({str(self.evidence / 'review.json')!r}).write_text('changed original')\n"
            f"Path(sys.argv[sys.argv.index('--output-file')+1]).write_text({json.dumps(raw)!r})\n")
        scanner.chmod(0o700)
        f.policy["scanner"]["version"] = "2.3.0"
        f.policy["scanner"]["assets"]["darwin-arm64"]["sha256"] = audit.hash_file(scanner)
        f._save_policy()
        with contextlib.redirect_stdout(io.StringIO()):
            result = audit.main(self._scan_args(scanner, evidence, output))
        self.assertEqual(result, 0, (evidence / "receipt.json").read_text())
        report = json.loads(output.read_text())
        receipt = json.loads((evidence / "receipt.json").read_text())
        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["inputs"]["scanner_sbom"]["sha256"], report["inputs"]["scanner_sbom_sha256"])
        self._verify(report, source_path=evidence / "source.json", source_owned_evidence=evidence / "source-owned")
        # Producer success does not replace consumer verification of the retained bytes.
        (evidence / "source-owned/review.json").unlink()
        with self.assertRaises(OSError):
            self._verify(report, source_path=evidence / "source.json", source_owned_evidence=evidence / "source-owned")

    def test_missing_source_owned_evidence_fails_before_any_scanner_execution(self):
        f = self.fixture
        (self.evidence / "review.json").unlink()
        evidence = f.root / "scan"
        with patch.object(audit, "verify_scanner", side_effect=AssertionError("must not run")), \
                contextlib.redirect_stdout(io.StringIO()):
            result = audit.main(self._scan_args(f.root / "absent-scanner", evidence, f.root / "report"))
        self.assertEqual(result, 1)
        receipt = json.loads((evidence / "receipt.json").read_text())
        self.assertEqual(receipt["stage"], "source_owned_evidence")
        self.assertEqual(receipt["scan"]["state"], "not_started")

    def test_cli_requires_owned_source_and_retention_without_requiring_native_inputs(self):
        f = self.fixture
        args = self._scan_args("unused", f.root / "unused", f.root / "unused-output")
        for flag in ("--native-receipt", "--native-artifacts-root", "--native-advisory-evidence"):
            index = args.index(flag)
            del args[index:index+2]
        parsed = audit.parse_args(args)
        self.assertEqual(parsed.source_owned_evidence, self.evidence)
        for flag in ("--source", "--evidence-dir"):
            changed = list(args)
            index = changed.index(flag)
            del changed[index:index+2]
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                audit.parse_args(changed)


class RealSourceOwnedAuditBridgeTests(unittest.TestCase):
    """Real validators and retained archives; only OSV execution is synthetic."""

    def setUp(self):
        from test_geph_source_owned_advisories import SourceOwnedReviewFixture
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.f = SourceOwnedReviewFixture(self.root)
        self.policy = audit.load_policy(fixtures.GEPH_POLICY_PATH)
        self.policy["exceptions"] = []
        self.policy["source_owned_review"] = self.f.policy
        self.policy_path = self.root / "policy.json"
        self.sbom_path = self.root / "input.spdx.json"
        self.policy_path.write_text(json.dumps(self.policy))
        self.sbom_path.write_text(json.dumps(self.f.sbom))
        self.raw = fixtures.osv_result(({"ecosystem": "crates.io", "name": "geph5-client", "version": "0.4.3"}, []))

    def verify(self, report, **overrides):
        return audit.validate_audit_report(report, **(dict(
            policy_path=self.policy_path, sbom_path=self.sbom_path,
            source_commit=self.f.source_commit, target=fixtures.TARGET,
            source_path=self.f.source_path, source_owned_evidence=self.f.evidence_root,
            vendored_transitive_dependencies="full") | overrides))

    def build(self):
        return audit.build_audit_report(osv_result=self.raw, policy=self.policy,
            policy_path=self.policy_path, sbom_path=self.sbom_path,
            scanner=fixtures.scanner_metadata(self.policy), source_commit=self.f.source_commit,
            target=fixtures.TARGET, evaluated_on=date.today(), source_path=self.f.source_path,
            source_owned_evidence=self.f.evidence_root, vendored_transitive_dependencies="full")

    def test_real_review_build_and_consumer_reject_changed_archive_and_open_finding(self):
        report = self.build()
        summary = self.verify(report)
        self.assertEqual((summary["packages_scanned"], summary["packages_source_owned"]), (1, 3))
        archive = next(e for e in self.f.review["evidence"] if e["kind"] == "archive")
        path = self.f.evidence_root / archive["path"]
        original = path.read_bytes()
        path.write_bytes(original + b"changed")
        with self.assertRaises(ValueError):
            self.verify(report)
        path.write_bytes(original)
        self.f.review["packages"][0]["manual_findings"] = [
            {"id": "LOCAL-OPEN", "disposition": "affected", "evidence": ["review-0"]}]
        self.f.save_review()
        self.policy_path.write_text(json.dumps(self.policy))
        failing = self.build()
        self.assertEqual(failing["status"], "fail")
        self.assertEqual(failing["summary"]["source_owned_affected"], 1)
        failing["status"] = "pass"
        with self.assertRaisesRegex(ValueError, "unresolved or affected"):
            self.verify(failing)

    def test_real_scan_and_retained_consumer_survive_original_inputs_changing(self):
        scanner = self.root / "synthetic-scanner"
        scanner.write_text(f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
            "if '--version' in sys.argv:\n    print('osv-scanner version 2.3.0'); raise SystemExit(0)\n"
            "projection=json.loads(Path(sys.argv[sys.argv.index('-L')+1]).read_text())\n"
            "assert [p['name'] for p in projection['packages']] == ['geph5-client']\n"
            "assert projection['files'] == []\n"
            "assert len(json.loads(Path('input.spdx.json').read_text())['packages']) == 4\n"
            f"Path({str(self.f.source_path)!r}).write_text('changed original')\n"
            f"Path({str(self.f.evidence_root / 'review.json')!r}).write_text('changed original')\n"
            f"Path(sys.argv[sys.argv.index('--output-file')+1]).write_text({json.dumps(self.raw)!r})\n")
        scanner.chmod(0o700)
        self.policy["scanner"]["version"] = "2.3.0"
        self.policy["scanner"]["assets"]["darwin-arm64"]["sha256"] = audit.hash_file(scanner)
        self.policy_path.write_text(json.dumps(self.policy))
        evidence, output = self.root / "scan", self.root / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            result = audit.main(["scan", "--scanner", str(scanner), "--platform", "darwin-arm64",
                "--sbom", str(self.sbom_path), "--policy", str(self.policy_path),
                "--source-commit", self.f.source_commit, "--target", fixtures.TARGET,
                "--evaluation-date", date.today().isoformat(),
                "--output", str(output), "--evidence-dir", str(evidence),
                "--source", str(self.f.source_path), "--source-owned-evidence", str(self.f.evidence_root),
                "--vendored-transitive-dependencies", "full"])
        self.assertEqual(result, 0, (evidence / "receipt.json").read_text())
        report = json.loads(output.read_text())
        self.verify(report, source_path=evidence / "source.json", source_owned_evidence=evidence / "source-owned")
        archive = next((evidence / "source-owned/archives").iterdir())
        archive.unlink()
        with self.assertRaises(OSError):
            self.verify(report, source_path=evidence / "source.json", source_owned_evidence=evidence / "source-owned")


if __name__ == "__main__":
    unittest.main()

"""Publication admission is current; the immutable audit remains historical."""
from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, date, datetime
from pathlib import Path
from unittest import mock

import dependency_audit
import make_release_manifest
import make_release_sbom
import release_candidate


SOURCE = "a" * 40
VERSION = "0.1.9"
REPOSITORY = "aiwaki/slipstream"
TARGET = "aarch64-apple-darwin"
EPOCH = 1_750_000_000
SCANNED = date(2026, 10, 26)
EXPIRES = date(2026, 10, 29)


class ReleaseAuditAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = self.root / "release"
        self.release.mkdir()
        self.policy_path = self.root / "policy.json"

    def fixture(self, kind, *, sbom_tag=None):
        policy = dependency_audit.load_policy(dependency_audit.DEFAULT_POLICY)
        integrity = copy.deepcopy(policy["integrity_only"][0])
        integrity.update(name="fixture-browser", version="1.0",
                         purl="pkg:generic/fixture-browser@1.0", sha256="ab" * 32,
                         expires=EXPIRES.isoformat())
        exception = dict(id="fixture-exception", ecosystem="crates.io",
                         package="fixture-library", version="1.0",
                         advisories=["RUSTSEC-2026-0001"], expires=EXPIRES.isoformat(),
                         reason="Deterministic release admission fixture.")
        unused = dict(exception, id="unused-expired", package="unused-library",
                      expires="2026-09-01")
        policy["exceptions"] = [exception, unused]
        policy["integrity_only"] = [integrity]
        self.policy_path.write_text(json.dumps(policy))
        components = []
        rows = [{"package": {"ecosystem": "GitHub Actions", "name": REPOSITORY,
                             "version": VERSION}, "vulnerabilities": []}]
        if kind == "integrity":
            components.append(make_release_sbom.Component(
                ecosystem="generic", name=integrity["name"], version="1.0",
                download_location="https://example.invalid/browser", purl=integrity["purl"],
                checksum_algorithm="SHA256", checksum_value=integrity["sha256"],
            ))
            rows.append({"package": {"ecosystem": "", "name": integrity["name"],
                                     "version": "1.0"}, "vulnerabilities": []})
        elif kind == "exception":
            components.append(make_release_sbom.Component(
                ecosystem="cargo", name=exception["package"], version="1.0",
                download_location="NOASSERTION", purl="pkg:cargo/fixture-library@1.0",
            ))
            rows.append({"package": {"ecosystem": "crates.io", "name": exception["package"],
                                     "version": "1.0"},
                         "vulnerabilities": [{"id": "RUSTSEC-2026-0001", "aliases": [],
                                              "affected": []}]})
        self.sbom_path = self.release / make_release_manifest.SBOM_NAME
        self.sbom_path.write_text(json.dumps(make_release_sbom.build_spdx_document(
            version=VERSION, tag=sbom_tag or "v0.1.9-preview.99", repository=REPOSITORY,
            source_commit=SOURCE, source_date_epoch=EPOCH, target=TARGET,
            components=components,
        )))
        self.report = dependency_audit.build_audit_report(
            osv_result={"results": [{"packages": rows}]}, policy=policy,
            policy_path=self.policy_path, sbom_path=self.sbom_path,
            scanner=dependency_audit.expected_scanner_metadata(policy, "darwin-arm64"),
            source_commit=SOURCE, target=TARGET, evaluated_on=SCANNED,
        )
        self.report_path = self.release / dependency_audit.REPORT_NAME
        self.report_path.write_text(json.dumps(self.report))
        for name in ("Slipstream-macos-arm64.zip", "Slipstream.app.tar.gz",
                     "Slipstream.app.tar.gz.sig", "latest.json"):
            (self.release / name).write_bytes(b"fixture")
        self.args = ["--release-dir", str(self.release), "--repository", REPOSITORY,
                     "--version", VERSION, "--tag", "v0.1.9-preview.99", "--channel", "preview",
                     "--source-commit", SOURCE, "--source-date-epoch", str(EPOCH), "--target", TARGET]

    def historical(self):
        return dependency_audit.validate_audit_report_file(
            report_path=self.report_path, policy_path=self.policy_path, sbom_path=self.sbom_path,
            source_commit=SOURCE, target=TARGET,
        )

    def publish(self, on):
        clock = mock.Mock()
        clock.now.return_value = datetime(on.year, on.month, on.day, 23, 59, tzinfo=UTC)
        with mock.patch.object(dependency_audit, "DEFAULT_POLICY", self.policy_path), \
             mock.patch.object(make_release_manifest, "datetime", clock, create=True), \
             redirect_stdout(io.StringIO()):
            result = make_release_manifest.main([*self.args, "--for-publication"])
        self.publication_clock = clock
        return result

    def test_publisher_rejects_historically_green_expired_integrity_only(self):
        self.fixture("integrity")
        self.assertEqual(self.historical()["packages_integrity_only"], 1)
        before = self.report_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "integrity-only.*expired.*admission"):
            self.publish(date(2026, 10, 30))
        self.assertEqual(self.report_path.read_bytes(), before)

    def test_publisher_rejects_historically_green_expired_accepted_exception(self):
        self.fixture("exception")
        self.assertEqual(self.historical()["accepted_exceptions"], 1)
        before = self.report_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "exception.*expired.*admission"):
            self.publish(date(2026, 10, 30))
        self.assertEqual(self.report_path.read_bytes(), before)

    def test_publication_expiry_is_inclusive_and_unused_expired_entries_do_not_block(self):
        for kind, on in (("integrity", EXPIRES), ("exception", EXPIRES),
                         ("unused", date(2026, 11, 30))):
            with self.subTest(kind=kind):
                self.fixture(kind)
                before = self.report_path.read_bytes()
                self.assertEqual(self.publish(on), 0)
                self.publication_clock.now.assert_called_once_with(UTC)
                self.assertEqual(self.report_path.read_bytes(), before)

    def test_admission_date_is_explicit_valid_and_not_before_scan(self):
        self.fixture("unused")
        for invalid in ("2026-10-30", True, datetime(2026, 10, 30), date(2026, 10, 25)):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "admission date"):
                dependency_audit.validate_audit_report_file(
                    report_path=self.report_path, policy_path=self.policy_path,
                    sbom_path=self.sbom_path, source_commit=SOURCE, target=TARGET,
                    admission_on=invalid,
                )

    def test_current_policy_hash_still_must_match_original_audit(self):
        self.fixture("integrity")
        policy = json.loads(self.policy_path.read_text())
        policy["integrity_only"][0]["expires"] = "2027-01-01"
        self.policy_path.write_text(json.dumps(policy))
        with self.assertRaisesRegex(ValueError, "input hashes"):
            self.publish(date(2026, 10, 30))

    def candidate(self, kind):
        self.fixture(kind, sbom_tag=f"release-candidate-{SOURCE}")
        (self.release / "latest.json").unlink()
        (self.release / "Slipstream_0.1.9_aarch64.dmg").write_bytes(b"fixture")
        app = self.root / "Slipstream.app"
        app.mkdir(exist_ok=True)
        (app / "binary").write_bytes(b"fixture")
        with mock.patch.object(dependency_audit, "DEFAULT_POLICY", self.policy_path):
            manifest = release_candidate.build_manifest(
                candidate_dir=self.release, repository=REPOSITORY, version=VERSION,
                source_commit=SOURCE, source_tree="b" * 40, source_archive_sha256="c" * 64,
                source_date_epoch=EPOCH, target=TARGET, workflow_run_id=42,
                workflow_run_attempt=1, app_tree=app,
            )
        manifest_path = self.release / release_candidate.MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest))
        args = ["verify", "--candidate-dir", str(self.release), "--repository", REPOSITORY,
                "--version", VERSION, "--source-commit", SOURCE, "--source-tree", "b" * 40,
                "--source-archive-sha256", "c" * 64, "--source-date-epoch", str(EPOCH),
                "--target", TARGET, "--expected-workflow-run-id", "42",
                "--expected-workflow-run-attempt", "1", "--app-tree", str(app)]
        return manifest_path, args

    def test_existing_candidate_is_historically_valid_but_publication_rechecks_today(self):
        for kind in ("integrity", "exception"):
            with self.subTest(kind=kind):
                manifest, args = self.candidate(kind)
                before = (manifest.read_bytes(), self.report_path.read_bytes())
                clock = mock.Mock()
                clock.now.return_value = datetime(2026, 10, 30, 0, 1, tzinfo=UTC)
                with mock.patch.object(dependency_audit, "DEFAULT_POLICY", self.policy_path), \
                     mock.patch.object(release_candidate, "datetime", clock), \
                     redirect_stdout(io.StringIO()):
                    self.assertEqual(release_candidate.main(args), 0)
                    clock.now.assert_not_called()
                    with self.assertRaisesRegex(ValueError, "expired at admission"):
                        release_candidate.main([*args, "--for-publication"])
                    clock.now.assert_called_once_with(UTC)
                    self.assertEqual(release_candidate.main(args), 0)
                self.assertEqual((manifest.read_bytes(), self.report_path.read_bytes()), before)

    def test_existing_candidate_is_admitted_on_the_expiry_day(self):
        _manifest, args = self.candidate("integrity")
        clock = mock.Mock()
        clock.now.return_value = datetime(2026, 10, 29, 23, 59, tzinfo=UTC)
        with mock.patch.object(dependency_audit, "DEFAULT_POLICY", self.policy_path), \
             mock.patch.object(release_candidate, "datetime", clock), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(release_candidate.main([*args, "--for-publication"]), 0)
        clock.now.assert_called_once_with(UTC)

    def test_publisher_workflow_requires_current_candidate_admission(self):
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/build-app.yml"
        text = workflow.read_text()
        command = text.split("python3 scripts/release_candidate.py verify \\\n", 1)[1]
        command = command.split("python3 scripts/release_candidate.py verify-proof", 1)[0]
        self.assertIn('"${publication_args[@]}"', command)
        prefix = text.split("      - name: Verify exact immutable candidate and qualification proof", 1)[1]
        prefix = prefix.split("python3 scripts/release_candidate.py verify", 1)[0]
        self.assertIn('[ -n "$RESUME_RELEASE_ID" ] || publication_args+=(--for-publication)', prefix)
        metadata = text.split("      - name: Create tag-specific release metadata without rebuilding", 1)[1]
        metadata = metadata.split("      - name:", 1)[0]
        self.assertIn('[ -n "$RESUME_RELEASE_ID" ] || publication_args+=(--for-publication)', metadata)
        self.assertIn('"${publication_args[@]}"', metadata)
        self.assertIn('artifact-ids: ${{ steps.runs.outputs.geph_audit_artifact_id }}', text)
        self.assertIn('digest-mismatch: error', text)

    def geph_fixture(self):
        policy = dependency_audit.load_policy(
            Path(__file__).resolve().parents[1] / "security/geph-dependency-audit-policy.json"
        )
        used = [x for x in policy["exceptions"] if x["package"] == "rsa" and x["version"] == "0.8.2"]
        for item in used:
            item["expires"] = "2026-10-30"
        self.geph_policy = self.root / "geph-policy.json"
        self.geph_policy.write_text(json.dumps(policy))
        package = {"SPDXID": "SPDXRef-rsa", "name": "rsa", "versionInfo": "0.8.2",
                   "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                     "referenceType": "purl", "referenceLocator": "pkg:cargo/rsa@0.8.2"}]}
        self.geph_sbom = self.root / "geph5-client.spdx.json"
        self.geph_sbom.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [package]}))
        rows = [{"package": {"ecosystem": "crates.io", "name": "rsa", "version": "0.8.2"},
                 "vulnerabilities": [{"id": x["advisories"][0], "aliases": [], "affected": []}
                                     for x in used]}]
        self.geph_report = self.root / "geph5-client-dependency-audit.json"
        report = dependency_audit.build_audit_report(
            osv_result={"results": [{"packages": rows}]}, policy=policy,
            policy_path=self.geph_policy, sbom_path=self.geph_sbom,
            scanner=dependency_audit.expected_scanner_metadata(policy, "linux-amd64"),
            source_commit=SOURCE, target="macos-universal", evaluated_on=SCANNED,
            vendored_transitive_dependencies="full",
        )
        self.geph_report.write_text(json.dumps(report))

    def final_publication_shell(self, utc_day="2026-10-31", gh_fails_first=False):
        import os
        import shutil
        import subprocess
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/build-app.yml"
        text = workflow.read_text().split("      - name: Publish only the verified exact release draft", 1)[1]
        text = text.split("      - name:", 1)[0].split("        run: |\n", 1)[1]
        shell = "\n".join(line[10:] for line in text.splitlines() if line.strip())
        shell = shell.replace("${{ github.repository }}", REPOSITORY)
        shell = shell.replace("${{ steps.ver.outputs.make_latest }}", "false")
        bin_dir = self.root / "bin"
        bin_dir.mkdir(exist_ok=True)
        scripts = Path(__file__).resolve().parent
        interpreter = Path(__import__("sys").executable)
        days = [utc_day] if isinstance(utc_day, str) else list(utc_day)
        (bin_dir / "python3").write_text(
            f"#!{interpreter}\nimport sys\nsys.path.insert(0, {str(scripts)!r})\n"
            "import dependency_audit\nfrom datetime import datetime, UTC\nfrom pathlib import Path\n"
            f"days = {days!r}\nlog = Path('admissions.log')\n"
            "old = log.read_text().splitlines() if log.exists() else []\n"
            "day = days[min(len(old), len(days) - 1)]\nlog.write_text('\\n'.join([*old, day]) + '\\n')\n"
            "class Clock:\n"
            "    @staticmethod\n    def now(tz): return datetime.fromisoformat(day).replace(tzinfo=UTC)\n"
            "dependency_audit.datetime = Clock\n"
            "raise SystemExit(dependency_audit.main(sys.argv[2:]))\n"
        )
        (bin_dir / "python3").chmod(0o755)
        (bin_dir / "gh").write_text(
            '#!/bin/sh\nprintf "PATCH\\n" >> "$PATCH_LOG"\n'
            + ('[ "$(wc -l < "$PATCH_LOG" | tr -d " ")" -gt 1 ]\n' if gh_fails_first else "exit 0\n")
        )
        (bin_dir / "gh").chmod(0o755)
        (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / "sleep").chmod(0o755)
        security = self.root / "security"
        security.mkdir(exist_ok=True)
        shutil.copyfile(self.policy_path, security / "dependency-audit-policy.json")
        shutil.copyfile(self.geph_policy, security / "geph-dependency-audit-policy.json")
        geph_dir = self.root / "dist-geph-audit"
        geph_dir.mkdir(exist_ok=True)
        for path in (self.geph_report, self.geph_sbom):
            shutil.copyfile(path, geph_dir / path.name)
        release_dir = self.root / "dist-release"
        if not release_dir.exists():
            release_dir.symlink_to(self.release, target_is_directory=True)
        marker = self.root / "patch.log"
        result = subprocess.run(
            ["/bin/bash", "-c", shell], cwd=self.root, capture_output=True, text=True,
            env={**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                 "SOURCE_COMMIT": SOURCE, "SLIPSTREAM_TAURI_TARGET": TARGET,
                 "RELEASE_ID": "123", "RUNNER_TEMP": str(self.root), "PATCH_LOG": str(marker)},
            timeout=15,
        )
        return result, marker

    def test_final_publication_refuses_expired_vendor_before_patch(self):
        self.fixture("unused")
        self.geph_fixture()
        result, marker = self.final_publication_shell()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(marker.exists(), "expired vendor allowance reached the irreversible PATCH")
        self.assertIn("exception is expired at admission", result.stderr)

    def admission_args(self):
        return dict(report_path=self.report_path, sbom_path=self.sbom_path,
                    policy_path=self.policy_path, geph_report_path=self.geph_report,
                    geph_sbom_path=self.geph_sbom, geph_policy_path=self.geph_policy,
                    source_commit=SOURCE, target=TARGET)

    def test_pair_refuses_utc_rollover_during_admission(self):
        self.fixture("unused")
        self.geph_fixture()
        before = (self.report_path.read_bytes(), self.geph_report.read_bytes())
        clock = mock.Mock()
        clock.now.side_effect = [datetime(2026, 10, 30, 23, 59, tzinfo=UTC),
                                 datetime(2026, 10, 31, 0, 0, tzinfo=UTC)]
        with mock.patch.object(dependency_audit, "datetime", clock), \
             self.assertRaisesRegex(ValueError, "UTC date changed"):
            dependency_audit.validate_release_admission(**self.admission_args())
        self.assertEqual(clock.now.call_args_list, [mock.call(UTC), mock.call(UTC)])
        self.assertEqual((self.report_path.read_bytes(), self.geph_report.read_bytes()), before)

    def test_pair_requires_full_geph_coverage_and_exact_source_target_and_inputs(self):
        self.fixture("unused")
        self.geph_fixture()
        original = self.geph_report.read_bytes()
        mutations = [
            ("coverage", {"sbom_packages": "all", "vendored_transitive_dependencies": "top-level-only"}),
            ("source", {"commit": "b" * 40, "target": "macos-universal"}),
            ("source", {"commit": SOURCE, "target": TARGET}),
            ("inputs", {"policy_sha256": "c" * 64, "sbom_sha256": "d" * 64}),
        ]
        clock = mock.Mock()
        clock.now.return_value = datetime(2026, 10, 30, tzinfo=UTC)
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                report = json.loads(original)
                report[key] = value
                self.geph_report.write_text(json.dumps(report))
                with mock.patch.object(dependency_audit, "datetime", clock), self.assertRaises(ValueError):
                    dependency_audit.validate_release_admission(**self.admission_args())
        self.geph_report.write_bytes(original)
        self.geph_report.unlink()
        with mock.patch.object(dependency_audit, "datetime", clock), self.assertRaises(FileNotFoundError):
            dependency_audit.validate_release_admission(**self.admission_args())

    def test_final_publication_rechecks_both_reports_before_each_patch_attempt(self):
        self.fixture("unused")
        self.geph_fixture()
        result, marker = self.final_publication_shell("2026-10-30", gh_fails_first=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(marker.read_text().splitlines(), ["PATCH", "PATCH"])
        self.assertEqual((self.root / "admissions.log").read_text().splitlines(),
                         ["2026-10-30", "2026-10-30"])

    def test_final_publication_stops_retry_when_utc_day_expires_vendor(self):
        self.fixture("unused")
        self.geph_fixture()
        result, marker = self.final_publication_shell(
            ("2026-10-30", "2026-10-31"), gh_fails_first=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text().splitlines(), ["PATCH"])
        self.assertIn("exception is expired at admission", result.stderr)

    def test_final_publication_rechecks_application_before_patch(self):
        self.fixture("integrity")
        self.geph_fixture()
        result, marker = self.final_publication_shell("2026-10-30")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertIn("integrity-only policy is expired at admission", result.stderr)

    def test_historical_metadata_finalization_does_not_need_current_admission(self):
        self.fixture("integrity")
        clock = mock.Mock()
        with mock.patch.object(dependency_audit, "DEFAULT_POLICY", self.policy_path), \
             mock.patch.object(make_release_manifest, "datetime", clock), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(make_release_manifest.main(self.args), 0)
        clock.now.assert_not_called()


class GephAuditArtifactSelectionTests(unittest.TestCase):
    def setUp(self):
        self.jobs = {"total_count": 1, "jobs": [dict(
            name="geph-vendor-audit", run_attempt=2, status="completed", conclusion="success",
            started_at="2026-10-30T10:00:00Z", completed_at="2026-10-30T10:05:00Z",
        )]}
        self.artifacts = {"total_count": 1, "artifacts": [dict(
            id=99, name=f"geph-vendor-dependency-audit-{SOURCE}", expired=False,
            created_at="2026-10-30T10:04:00Z", updated_at="2026-10-30T10:04:01Z",
            workflow_run=dict(id=42, repository_id=12, head_repository_id=12,
                              head_sha=SOURCE, head_branch="main"),
        )]}

    def select(self):
        return release_candidate.select_geph_audit_artifact(
            self.artifacts, self.jobs, source_commit=SOURCE, run_id=42,
            run_attempt=2, repository_id=12,
        )

    def test_accepts_only_exact_current_attempt_artifact(self):
        self.assertEqual(self.select(), 99)
        self.artifacts["artifacts"][0].update(
            created_at="2026-10-30T10:00:00+00:00", updated_at="2026-10-30T10:05:00Z",
        )
        self.assertEqual(self.select(), 99)

    def test_same_run_previous_attempt_and_missing_or_non_utc_timestamps_fail(self):
        artifact = self.artifacts["artifacts"][0]
        for field in ("created_at", "updated_at"):
            for value in (None, "2026-10-30T09:59:59Z", "2026-10-30T10:06:00Z",
                          "2026-10-30T10:04:00", "2026-10-30T10:04:00+05:00"):
                before = artifact[field]
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "timestamp|attempt"):
                    artifact[field] = value
                    self.select()
                artifact[field] = before
        self.jobs["jobs"][0]["started_at"] = None
        with self.assertRaisesRegex(ValueError, "timestamp"):
            self.select()

    def test_wrong_source_run_repository_job_or_artifact_identity_fails(self):
        for field, value in (("head_sha", "b" * 40), ("id", 41), ("repository_id", 13),
                             ("head_repository_id", 13), ("head_branch", "other")):
            workflow = self.artifacts["artifacts"][0]["workflow_run"]
            before = workflow[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                workflow[field] = value
                self.select()
            workflow[field] = before
        for field, value in (("run_attempt", 1), ("conclusion", "failure"), ("status", "in_progress")):
            job = self.jobs["jobs"][0]
            before = job[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                job[field] = value
                self.select()
            job[field] = before
        self.artifacts["artifacts"][0]["expired"] = True
        with self.assertRaises(ValueError):
            self.select()

    def test_missing_duplicate_and_partial_metadata_fail(self):
        for payload, key in ((self.artifacts, "artifacts"), (self.jobs, "jobs")):
            original = copy.deepcopy(payload)
            for values, count in (([], 0), (payload[key] * 2, 2), (payload[key], 2)):
                with self.subTest(key=key, count=count), self.assertRaises(ValueError):
                    payload[key], payload["total_count"] = values, count
                    self.select()
            payload.clear()
            payload.update(original)

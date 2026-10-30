"""Immutable candidate identity and current publication admission are separate."""
from __future__ import annotations

import inspect
import json
import unittest
from datetime import date
from unittest import mock

import dependency_audit
import release_candidate
import test_release_audit_admission as admission_fixtures
from test_release_audit_admission import (
    EPOCH, REPOSITORY, SOURCE, TARGET, VERSION,
)


class HistoricalCandidatePolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = admission_fixtures.ReleaseAuditAdmissionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.manifest, _ = self.fixture.candidate("integrity")
        self.old_policy = self.fixture.policy_path
        current = json.loads(self.old_policy.read_text())
        current["exceptions"][0]["reason"] += " Current policy revision."
        self.current_policy = self.fixture.root / "current-policy.json"
        self.current_policy.write_text(json.dumps(current))
        self.kwargs = dict(
            candidate_dir=self.fixture.release, repository=REPOSITORY, version=VERSION,
            source_commit=SOURCE, source_tree="b" * 40, source_archive_sha256="c" * 64,
            source_date_epoch=EPOCH, target=TARGET,
            expected_workflow_run_id=42, expected_workflow_run_attempt=1,
            app_tree=self.fixture.root / "Slipstream.app",
        )

    def verify(self, **kwargs):
        with mock.patch.object(dependency_audit, "DEFAULT_POLICY", self.current_policy):
            return release_candidate.validate_manifest(**self.kwargs, **kwargs)

    def test_attested_old_candidate_remains_verifiable_after_policy_revision(self):
        before = (self.manifest.read_bytes(), self.fixture.report_path.read_bytes())
        # Also runs against the old API to reproduce the real input-hash failure,
        # rather than failing merely because the new keyword did not exist.
        kwargs = {}
        if "historical_audit_policy" in inspect.signature(release_candidate.validate_manifest).parameters:
            kwargs["historical_audit_policy"] = self.old_policy
        result = self.verify(**kwargs)
        self.assertEqual(result["candidate_id"], f"release-candidate-{SOURCE}")
        self.assertEqual((self.manifest.read_bytes(), self.fixture.report_path.read_bytes()), before)

    def test_default_still_rejects_report_from_a_different_policy(self):
        with self.assertRaisesRegex(ValueError, "input hashes"):
            self.verify()

    def test_wrong_historical_policy_still_rejected(self):
        with self.assertRaisesRegex(ValueError, "input hashes"):
            self.verify(historical_audit_policy=self.current_policy)

    def test_current_admission_never_accepts_historical_policy_override(self):
        for on in (date(2026, 10, 29), date(2026, 10, 30)):
            with self.subTest(admission_on=on), self.assertRaisesRegex(
                ValueError, "historical.*publication"
            ):
                self.verify(historical_audit_policy=self.old_policy, admission_on=on)

    def test_historical_policy_does_not_weaken_candidate_artifact_integrity(self):
        (self.fixture.release / "Slipstream-macos-arm64.zip").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "artifact hashes"):
            self.verify(historical_audit_policy=self.old_policy)

    def test_missing_historical_policy_does_not_fall_back(self):
        self.old_policy.unlink()
        with self.assertRaises((OSError, ValueError)):
            self.verify(historical_audit_policy=self.old_policy)


if __name__ == "__main__":
    unittest.main()

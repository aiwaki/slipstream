"""Historical source review transport is separate from current admission."""
from datetime import UTC, date, datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import dependency_audit as audit
import geph_source_owned_advisories as review
import geph_source_owned_bundle as bundle
import test_geph_source_owned_advisories as fixtures


class SourceOwnedHistoricalTests(unittest.TestCase):
    def test_historical_review_uses_evaluation_date_not_wallclock(self):
        policy = {"schema_version": 1, "source_sha256": "a" * 64,
                  "review_sha256": "b" * 64, "expires": "2000-01-02"}
        review._policy(policy, date(2000, 1, 1))
        review._policy(policy, date(2000, 1, 2))
        with self.assertRaisesRegex(ValueError, "expired"):
            review._policy(policy, date(2000, 1, 3))

    def test_historical_archive_preserves_expired_policy_without_admitting_it(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            fixture = fixtures.SourceOwnedReviewFixture(root)
            fixture.policy["expires"] = "2000-01-02"
            archive = root / bundle.BUNDLE_NAME
            bundle.pack_bundle(evidence_root=fixture.evidence_root,
                               output_path=archive, policy_entry=fixture.policy)
            bundle.unpack_bundle(bundle_path=archive, output_root=root / "unpacked",
                                 policy_entry=fixture.policy)
            with self.assertRaisesRegex(ValueError, "expired"):
                review._policy(fixture.policy, date(2000, 1, 3))

    def real_report(self, root):
        fixture = fixtures.SourceOwnedReviewFixture(root)
        fixture.policy["expires"] = "2000-01-02"
        policy = audit.load_policy(audit.DEFAULT_POLICY)
        policy["exceptions"] = []
        policy["source_owned_review"] = fixture.policy
        policy_path, sbom_path = root / "policy.json", root / "sbom.json"
        policy_path.write_text(json.dumps(policy))
        sbom_path.write_text(json.dumps(fixture.sbom))
        reviewed = fixture.validate(evaluated_on=date(2000, 1, 1))
        identities, integrity, _ = audit._sbom_scan_identities(
            fixture.sbom["packages"], source_owned_package_ids=tuple(reviewed["package_ids"]))
        self.assertFalse(integrity)
        rows = [{"package": {"ecosystem": ecosystem, "name": name, "version": version},
                 "vulnerabilities": []} for ecosystem, name, version in identities]
        report = audit.build_audit_report(
            osv_result={"results": [{"packages": rows}]}, policy=policy, policy_path=policy_path,
            sbom_path=sbom_path, scanner=audit.expected_scanner_metadata(policy, "linux-amd64"),
            source_commit=fixture.source_commit, target="macos-universal",
            evaluated_on=date(2000, 1, 1), vendored_transitive_dependencies="full",
            source_path=fixture.source_path, source_owned_evidence=fixture.evidence_root)
        report_path = root / "report.json"
        report_path.write_text(json.dumps(report))
        return dict(report_path=report_path, policy_path=policy_path, sbom_path=sbom_path,
                    source_commit=fixture.source_commit, target="macos-universal",
                    vendored_transitive_dependencies="full", source_path=fixture.source_path,
                    source_owned_evidence=fixture.evidence_root)

    def test_real_historical_report_rechecks_expiry_only_for_current_admission(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.real_report(Path(temp).resolve())
            before = args["report_path"].read_bytes()
            audit.validate_audit_report_file(**args)
            audit.validate_audit_report_file(**args, admission_on=date(2000, 1, 2))
            with self.assertRaisesRegex(ValueError, "expired"):
                audit.validate_audit_report_file(**args, admission_on=date(2000, 1, 3))
            with self.assertRaisesRegex(ValueError, "precedes"):
                audit.validate_audit_report_file(**args, admission_on=date(1999, 12, 31))
            self.assertEqual(args["report_path"].read_bytes(), before)

    def test_publication_entrypoint_requires_exact_source_and_rechecks_same_report(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.real_report(Path(temp).resolve())
            original = audit.validate_audit_report_file
            app = Path("application-report")

            def validate(**kwargs):
                return {"status": "pass"} if kwargs["report_path"] == app else original(**kwargs)

            publication = dict(report_path=app, sbom_path=Path("app-sbom"), policy_path=Path("app-policy"),
                geph_report_path=args["report_path"], geph_sbom_path=args["sbom_path"],
                geph_policy_path=args["policy_path"], source_commit=args["source_commit"],
                target="aarch64-apple-darwin", geph_source_path=args["source_path"],
                geph_source_owned_evidence=args["source_owned_evidence"])
            with mock.patch.object(audit, "validate_audit_report_file", side_effect=validate), \
                    mock.patch.object(audit, "datetime") as clock:
                clock.now.return_value = datetime(2000, 1, 2, tzinfo=UTC)
                audit.validate_release_admission(**publication)
                with self.assertRaisesRegex(ValueError, "explicit SOURCE"):
                    audit.validate_release_admission(**(publication | {"geph_source_path": None}))
                clock.now.return_value = datetime(2000, 1, 3, tzinfo=UTC)
                with self.assertRaisesRegex(ValueError, "expired"):
                    audit.validate_release_admission(**publication)


if __name__ == "__main__":
    unittest.main()

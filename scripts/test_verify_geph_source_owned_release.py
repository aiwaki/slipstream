"""Exact conditional asset and transport gates, not semantic security approval.

Small real evidence catalogs exercise the actual transport verifiers. Attestation fixtures represent already-verified
statements; these tests do not perform cryptographic verification or scanning.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import geph_source_owned_bundle as bundle
from test_geph_source_owned_advisories import SourceOwnedReviewFixture
import test_verify_geph_release as legacy_fixture
import verify_geph_release as verifier


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


class SourceOwnedReleaseConsumerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.case = SourceOwnedReviewFixture(self.root)
        self.legacy = legacy_fixture.VerifyGephReleaseTests()
        self.release, self.refs = self.legacy._fixture(self.root)
        self.archive = self.release / bundle.BUNDLE_NAME
        self.policy_path = self.root / "audit-policy.json"
        self.output = self.root / "verified-source-review"
        self.publish_fixture()

    def publish_fixture(self):
        for key, path, name in (("source", self.case.source_path, "geph5-client.SOURCE.json"),
                                ("cargo_lock", self.case.lock_path, "geph5-client.Cargo.lock"),
                                ("version", self.case.version_path, "geph5-client.VERSION")):
            self.refs[key].write_bytes(path.read_bytes())
            (self.release / name).write_bytes(path.read_bytes())
        (self.release / "geph5-client.spdx.json").write_text(json.dumps(self.case.sbom))
        self.policy_path.write_text(json.dumps({"source_owned_review": self.case.policy}))
        if self.archive.exists():
            self.archive.unlink()
        bundle.pack_bundle(self.case.evidence_root, self.archive, self.case.policy)
        self.refresh_inventory()

    def refresh_inventory(self):
        (self.release / "SHA256SUMS").write_text("".join(
            f"{sha(path.read_bytes())}  {path.name}\n" for path in sorted(self.release.iterdir())
            if path.name != "SHA256SUMS"))
        self.refs["metadata_path"].write_text(json.dumps({
            "tag_name": self.refs["expected_tag"], "draft": False, "prerelease": True,
            "assets": [{"name": path.name, "state": "uploaded", "size": path.stat().st_size,
                        "digest": "sha256:" + sha(path.read_bytes())}
                       for path in sorted(self.release.iterdir())]}))

    def verify(self, **kwargs):
        return verifier.verify_release_assets(**(dict(release_dir=self.release,
            source_owned_policy=self.policy_path, source_owned_output_root=self.output) | self.refs | kwargs))

    def attestations(self):
        provenance, spdx = self.legacy._attestation_fixture(self.root, self.release)
        value = json.loads(provenance.read_text())
        subjects = value[0]["verificationResult"]["statement"]["subject"]
        for path in sorted(self.release.iterdir()):
            if path.name not in verifier.REQUIRED_ASSETS:
                subjects.append({"name": path.name, "digest": {"sha256": sha(path.read_bytes())}})
        provenance.write_text(json.dumps(value))
        return dict(release_dir=self.release, provenance_json=provenance,
                    spdx_json=spdx, source=self.refs["source"])

    def test_source_owned_exact_assets_metadata_and_attestations(self):
        result = self.verify()
        self.assertEqual(result["asset_count"], 9)
        proof = result["source_owned_evidence"]
        self.assertEqual(proof["root"], str(self.output))
        self.assertEqual(proof["bundle_sha256"], sha(self.archive.read_bytes()))
        self.assertEqual(self.case.validate(evidence_root=self.output)["status"], "pass")
        self.assertEqual(verifier.verify_attestation_results(**self.attestations())["provenance_subject_count"], 9)
        self.assertEqual(verifier.verify_release_metadata(metadata_path=self.refs["metadata_path"],
            expected_tag=self.refs["expected_tag"], source=self.refs["source"])["asset_count"], 9)

    def test_native_descriptor_cannot_activate_an_extra_release_lane(self):
        source = json.loads(self.refs["source"].read_text())
        source["native_sqlite"] = {}
        self.refs["source"].write_text(json.dumps(source))
        with self.assertRaisesRegex(ValueError, "native SQLite evidence is not enabled"):
            verifier.verify_release_metadata(metadata_path=self.refs["metadata_path"],
                expected_tag=self.refs["expected_tag"], source=self.refs["source"])

    def test_missing_extra_and_wrong_conditional_assets_fail(self):
        original = self.archive.read_bytes()
        for name in (None, "unexpected.tar", "geph5-client-native-sqlite-evidence.tar"):
            self.archive.unlink()
            if name:
                (self.release / name).write_bytes(original)
            self.refresh_inventory()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "asset set"):
                self.verify()
            if name:
                (self.release / name).unlink()
            self.archive.write_bytes(original)

    def test_source_less_contract_cannot_select_embedded_bundle(self):
        with self.assertRaisesRegex(ValueError, "asset set"):
            verifier.verify_release_metadata(metadata_path=self.refs["metadata_path"],
                expected_tag=self.refs["expected_tag"])
        attest = self.attestations()
        attest.pop("source")
        with self.assertRaisesRegex(ValueError, "asset set"):
            verifier.verify_attestation_results(**attest)
        self.archive.unlink()
        self.refresh_inventory()
        attest = self.attestations()
        attest.pop("source")
        with self.assertRaisesRegex(ValueError, "reviewed source"):
            verifier.verify_attestation_results(**attest)

    def test_policy_and_output_are_required_and_source_bound(self):
        for values in ({"source_owned_policy": None}, {"source_owned_output_root": None}):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, "trusted policy"):
                self.verify(**values)
        self.policy_path.write_text(json.dumps({"source_owned_review": self.case.policy | {"source_sha256": "0" * 64}}))
        with self.assertRaisesRegex(ValueError, "reviewed Geph source"):
            self.verify()
        self.assertFalse(self.output.exists())

    def test_rehashed_downloaded_source_cannot_select_own_contract(self):
        path = self.release / "geph5-client.SOURCE.json"
        source = json.loads(path.read_text())
        source.pop("embedded_packages")
        path.write_text(json.dumps(source))
        self.refresh_inventory()
        with self.assertRaisesRegex(ValueError, "reviewed source"):
            self.verify()
        with self.assertRaisesRegex(ValueError, "reviewed source"):
            verifier.verify_attestation_results(**self.attestations())

    def test_corrupt_bundle_with_coherent_checksum_and_api_fails(self):
        self.archive.write_bytes(b"invalid source-owned bundle")
        self.refresh_inventory()
        with self.assertRaises(ValueError):
            self.verify()
        self.assertFalse(self.output.exists())

    def test_bundle_must_be_in_checksum_and_provenance_subjects(self):
        checksums = self.release / "SHA256SUMS"
        checksums.write_text("".join(line + "\n" for line in checksums.read_text().splitlines()
                                    if bundle.BUNDLE_NAME not in line))
        with self.assertRaisesRegex(ValueError, "checksum|SHA256SUMS"):
            self.verify()
        self.refresh_inventory()
        attest = self.attestations()
        document = json.loads(attest["provenance_json"].read_text())
        document[0]["verificationResult"]["statement"]["subject"].pop()
        attest["provenance_json"].write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "exact release asset set"):
            verifier.verify_attestation_results(**attest)

    def test_changed_bundle_snapshot_proof_is_rejected(self):
        real = bundle.unpack_bundle
        for key, value in (("bundle_sha256", "0" * 64), ("size", 1),
                           ("source_sha256", "0" * 64), ("review_sha256", "0" * 64)):
            def changed(**kwargs):
                return real(**kwargs) | {key: value}
            with self.subTest(key=key), mock.patch.object(bundle, "unpack_bundle", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "changed during asset verification"):
                    self.verify(source_owned_output_root=self.root / ("verified-" + key))

    def test_legacy_does_not_require_or_accept_source_owned_assets(self):
        root = self.root / "legacy"
        root.mkdir()
        release, refs = self.legacy._fixture(root)
        self.assertEqual(verifier.verify_release_assets(release_dir=release, **refs)["asset_count"], 8)
        with self.assertRaisesRegex(ValueError, "without embedded"):
            verifier.verify_release_assets(release_dir=release, **refs, source_owned_policy=self.policy_path)
        (release / bundle.BUNDLE_NAME).write_bytes(self.archive.read_bytes())
        with self.assertRaisesRegex(ValueError, "asset set"):
            verifier.verify_release_assets(release_dir=release, **refs)

    def test_source_less_attestation_cannot_swap_source_after_hashing(self):
        self.archive.unlink()
        self.refresh_inventory()
        attest = self.attestations()
        attest.pop("source")
        path = self.release / "geph5-client.SOURCE.json"
        source = json.loads(path.read_text())
        source.pop("embedded_packages")
        original = verifier._read_json_regular
        def swap_before_read(target, **kwargs):
            if target == path:
                path.write_text(json.dumps(source))
            return original(target, **kwargs)
        with mock.patch.object(verifier, "_read_json_regular", side_effect=swap_before_read):
            with self.assertRaisesRegex(ValueError, "source changed"):
                verifier.verify_attestation_results(**attest)



if __name__ == "__main__":
    unittest.main()

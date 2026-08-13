from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import release_candidate


REPOSITORY = "aiwaki/slipstream"
VERSION = "0.1.9"
SOURCE_COMMIT = "1" * 40
SOURCE_TREE = "2" * 40
SOURCE_ARCHIVE_SHA256 = "3" * 64
SOURCE_DATE_EPOCH = 1_750_000_000
TARGET = "aarch64-apple-darwin"


class ReleaseCandidateTests(unittest.TestCase):
    def _candidate(self, root: Path) -> None:
        files = {
            "Slipstream-macos-arm64.zip": b"zip",
            "Slipstream.app.tar.gz": b"tar",
            "Slipstream.app.tar.gz.sig": b"signature",
            "Slipstream_0.1.9_aarch64.dmg": b"dmg",
            release_candidate.SBOM_NAME: b"{}\n",
            release_candidate.AUDIT_NAME: b"{}\n",
        }
        for name, body in files.items():
            (root / name).write_bytes(body)

    def _metadata_patches(self):
        return (
            mock.patch.object(
                release_candidate.make_release_sbom,
                "validate_spdx_document",
                return_value={"package_count": 4},
            ),
            mock.patch.object(
                release_candidate.dependency_audit,
                "validate_audit_report_file",
                return_value={"packages_scanned": 4},
            ),
        )

    def _create(self, root: Path) -> dict:
        app_tree = root.with_name(f"{root.name}-Slipstream.app")
        self.addCleanup(shutil.rmtree, app_tree, True)
        app_tree.mkdir(exist_ok=True)
        (app_tree / "binary").write_bytes(b"app")
        first, second = self._metadata_patches()
        with first, second:
            manifest = release_candidate.build_manifest(
                candidate_dir=root,
                repository=REPOSITORY,
                version=VERSION,
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                source_archive_sha256=SOURCE_ARCHIVE_SHA256,
                source_date_epoch=SOURCE_DATE_EPOCH,
                target=TARGET,
                workflow_run_id=42,
                workflow_run_attempt=2,
                app_tree=app_tree,
            )
        release_candidate._write_json(root / release_candidate.MANIFEST_NAME, manifest)
        return manifest

    def _validate(self, root: Path) -> dict:
        first, second = self._metadata_patches()
        with first, second:
            return release_candidate.validate_manifest(
                candidate_dir=root,
                repository=REPOSITORY,
                version=VERSION,
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                source_archive_sha256=SOURCE_ARCHIVE_SHA256,
                source_date_epoch=SOURCE_DATE_EPOCH,
                target=TARGET,
                expected_workflow_run_id=42,
                expected_workflow_run_attempt=2,
                app_tree=root.with_name(f"{root.name}-Slipstream.app"),
            )

    def test_manifest_binds_source_tree_archive_and_every_candidate_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            manifest = self._create(root)
            result = self._validate(root)

            self.assertEqual(manifest["source"]["tree"], SOURCE_TREE)
            self.assertEqual(
                manifest["source"]["archive_sha256"], SOURCE_ARCHIVE_SHA256
            )
            self.assertEqual(result["builder_run_id"], 42)
            self.assertEqual(result["builder_run_attempt"], 2)
            self.assertEqual(result["artifact_count"], 6)

    def test_manifest_rejects_a_different_builder_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            self._create(root)
            first, second = self._metadata_patches()
            with first, second, self.assertRaisesRegex(ValueError, "run attempt"):
                release_candidate.validate_manifest(
                    candidate_dir=root,
                    repository=REPOSITORY,
                    version=VERSION,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    source_archive_sha256=SOURCE_ARCHIVE_SHA256,
                    source_date_epoch=SOURCE_DATE_EPOCH,
                    target=TARGET,
                    expected_workflow_run_id=42,
                    expected_workflow_run_attempt=3,
                )

    def test_manifest_rejects_binary_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            self._create(root)
            (root / "Slipstream-macos-arm64.zip").write_bytes(b"changed")

            with self.assertRaisesRegex(ValueError, "hashes, sizes, or names"):
                self._validate(root)

    def test_manifest_rejects_a_different_unpacked_app_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            self._create(root)
            app_tree = root.with_name(f"{root.name}-Slipstream.app")
            (app_tree / "binary").write_bytes(b"different app")

            with self.assertRaisesRegex(ValueError, "app tree digest"):
                self._validate(root)

    def test_manifest_rejects_a_different_checked_out_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            self._create(root)
            first, second = self._metadata_patches()
            with first, second, self.assertRaisesRegex(ValueError, "tree, or archive"):
                release_candidate.validate_manifest(
                    candidate_dir=root,
                    repository=REPOSITORY,
                    version=VERSION,
                    source_commit=SOURCE_COMMIT,
                    source_tree="4" * 40,
                    source_archive_sha256=SOURCE_ARCHIVE_SHA256,
                    source_date_epoch=SOURCE_DATE_EPOCH,
                    target=TARGET,
                    app_tree=root.with_name(f"{root.name}-Slipstream.app"),
                )

    def test_proof_is_bound_to_exact_candidate_manifest_and_protected_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            self._create(root)
            first, second = self._metadata_patches()
            with first, second:
                proof = release_candidate.build_qualification_proof(
                    candidate_dir=root,
                    qualification_run_id=77,
                    qualification_run_attempt=1,
                    expected_candidate_run_attempt=2,
                    app_tree=root.with_name(f"{root.name}-Slipstream.app"),
                )
            proof_path = root / release_candidate.PROOF_NAME
            release_candidate._write_json(proof_path, proof)

            first, second = self._metadata_patches()
            with first, second:
                result = release_candidate.validate_qualification_proof(
                    candidate_dir=root,
                    proof_path=proof_path,
                    expected_qualification_run_id=77,
                    expected_qualification_run_attempt=1,
                    expected_candidate_run_attempt=2,
                )
            self.assertEqual(result["candidate_build_run_id"], 42)
            self.assertEqual(result["candidate_build_run_attempt"], 2)
            self.assertEqual(result["qualification_run_id"], 77)
            self.assertEqual(result["qualification_run_attempt"], 1)

            manifest = json.loads(
                (root / release_candidate.MANIFEST_NAME).read_text(encoding="utf-8")
            )
            manifest["builder"]["run_attempt"] = 3
            release_candidate._write_json(
                root / release_candidate.MANIFEST_NAME, manifest
            )
            first, second = self._metadata_patches()
            with first, second, self.assertRaisesRegex(ValueError, "exact candidate"):
                release_candidate.validate_qualification_proof(
                    candidate_dir=root,
                    proof_path=proof_path,
                    expected_qualification_run_id=77,
                )

    def test_proof_creation_rechecks_candidate_after_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            self._create(root)
            (root / "Slipstream.app.tar.gz").write_bytes(b"changed after gate")
            first, second = self._metadata_patches()
            with first, second, self.assertRaisesRegex(
                ValueError, "hashes, sizes, or names"
            ):
                release_candidate.build_qualification_proof(
                    candidate_dir=root,
                    qualification_run_id=77,
                    qualification_run_attempt=1,
                    expected_candidate_run_attempt=2,
                    app_tree=root.with_name(f"{root.name}-Slipstream.app"),
                )

    def test_proof_creation_rechecks_unpacked_app_after_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            self._create(root)
            app_tree = root.with_name(f"{root.name}-Slipstream.app")
            (app_tree / "binary").write_bytes(b"changed after gate")
            first, second = self._metadata_patches()
            with first, second, self.assertRaisesRegex(ValueError, "app tree digest"):
                release_candidate.build_qualification_proof(
                    candidate_dir=root,
                    qualification_run_id=77,
                    qualification_run_attempt=1,
                    expected_candidate_run_attempt=2,
                    app_tree=app_tree,
                )

    def test_proof_rejects_non_positive_workflow_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            self._create(root)
            first, second = self._metadata_patches()
            with first, second:
                proof = release_candidate.build_qualification_proof(
                    candidate_dir=root,
                    qualification_run_id=77,
                    qualification_run_attempt=1,
                    expected_candidate_run_attempt=2,
                    app_tree=root.with_name(f"{root.name}-Slipstream.app"),
                )
            proof["qualification"]["run_id"] = 0
            proof_path = root / release_candidate.PROOF_NAME
            release_candidate._write_json(proof_path, proof)
            first, second = self._metadata_patches()
            with first, second, self.assertRaisesRegex(ValueError, "run identity"):
                release_candidate.validate_qualification_proof(
                    candidate_dir=root,
                    proof_path=proof_path,
                )


if __name__ == "__main__":
    unittest.main()

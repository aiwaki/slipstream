from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts import verify_geph_release


class VerifyGephReleaseTests(unittest.TestCase):
    EXPECTED_TAG = "geph-vendor-0.3.9-r1"

    def _fixture(self, root: Path) -> tuple[Path, dict[str, object]]:
        release = root / "release"
        reviewed = root / "reviewed"
        release.mkdir()
        reviewed.mkdir()
        references = {
            "source": reviewed / "SOURCE.json",
            "cargo_lock": reviewed / "Cargo.lock",
            "version": reviewed / "VERSION",
            "license_file": reviewed / "LICENSE",
            "metadata_path": reviewed / "release.json",
            "expected_tag": self.EXPECTED_TAG,
        }
        references["source"].write_text('{"reviewed":true}\n', encoding="utf-8")
        references["cargo_lock"].write_text("version = 4\n", encoding="utf-8")
        references["version"].write_text("0.3.9\n", encoding="utf-8")
        references["license_file"].write_text("MPL-2.0\n", encoding="utf-8")
        payloads = {
            "geph5-client": b"universal-geph-binary",
            "geph5-client.Cargo.lock": references["cargo_lock"].read_bytes(),
            "geph5-client.LICENSE": references["license_file"].read_bytes(),
            "geph5-client.SOURCE.json": references["source"].read_bytes(),
            "geph5-client.VERSION": references["version"].read_bytes(),
            "geph5-client.spdx.json": b'{"spdxVersion":"SPDX-2.3"}\n',
            "geph5-client-dependency-audit.json": b'{"status":"pass"}\n',
        }
        for name, payload in payloads.items():
            (release / name).write_bytes(payload)
        self._write_checksums(release)
        self._write_metadata(release, references["metadata_path"])
        return release, references

    @staticmethod
    def _write_checksums(release: Path) -> None:
        lines = []
        for name in sorted(verify_geph_release.CHECKSUMMED_ASSETS):
            digest = hashlib.sha256((release / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}")
        (release / verify_geph_release.CHECKSUM_NAME).write_text(
            "\n".join(lines) + "\n",
            encoding="ascii",
        )

    @classmethod
    def _write_metadata(cls, release: Path, output: object) -> None:
        if not isinstance(output, Path):
            raise TypeError("release metadata output must be a path")
        assets = []
        for name in sorted(verify_geph_release.REQUIRED_ASSETS):
            payload = (release / name).read_bytes()
            assets.append(
                {
                    "name": name,
                    "size": len(payload),
                    "state": "uploaded",
                    "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
                }
            )
        output.write_text(
            json.dumps(
                {
                    "tag_name": cls.EXPECTED_TAG,
                    "draft": False,
                    "prerelease": True,
                    "assets": assets,
                }
            ),
            encoding="utf-8",
        )

    def _verify(
        self, release: Path, references: dict[str, object]
    ) -> dict[str, object]:
        return verify_geph_release.verify_release_assets(
            release_dir=release,
            source=references["source"],
            cargo_lock=references["cargo_lock"],
            version=references["version"],
            license_file=references["license_file"],
            metadata_path=references["metadata_path"],
            expected_tag=references["expected_tag"],
        )

    @staticmethod
    def _release_digests(release: Path) -> dict[str, str]:
        return {
            name: hashlib.sha256((release / name).read_bytes()).hexdigest()
            for name in sorted(verify_geph_release.REQUIRED_ASSETS)
        }

    def _attestation_fixture(self, root: Path, release: Path) -> tuple[Path, Path]:
        digests = self._release_digests(release)
        provenance = root / "provenance.json"
        spdx = root / "spdx-attestation.json"
        provenance.write_text(
            json.dumps(
                [
                    {
                        "verificationResult": {
                            "statement": {
                                "predicateType": verify_geph_release.SLSA_PREDICATE_TYPE,
                                "subject": [
                                    {
                                        "name": name,
                                        "digest": {"sha256": digest},
                                    }
                                    for name, digest in digests.items()
                                ],
                                "predicate": {"builder": "fixture"},
                            }
                        }
                    }
                ]
            ),
            encoding="utf-8",
        )
        spdx.write_text(
            json.dumps(
                [
                    {
                        "verificationResult": {
                            "statement": {
                                "predicateType": verify_geph_release.SPDX_PREDICATE_TYPE,
                                "subject": [
                                    {
                                        "name": verify_geph_release.BINARY_NAME,
                                        "digest": {
                                            "sha256": digests[
                                                verify_geph_release.BINARY_NAME
                                            ]
                                        },
                                    }
                                ],
                                "predicate": json.loads(
                                    (release / "geph5-client.spdx.json").read_text(
                                        encoding="utf-8"
                                    )
                                ),
                            }
                        }
                    }
                ]
            ),
            encoding="utf-8",
        )
        return provenance, spdx

    @staticmethod
    def _rewrite_json(path: Path, mutate: object) -> None:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not callable(mutate):
            raise TypeError("JSON fixture mutation must be callable")
        mutate(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_accepts_exact_attested_release_shape(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            release, references = self._fixture(Path(root_name))

            result = self._verify(release, references)

            self.assertEqual(result["asset_count"], 8)
            self.assertEqual(
                result["binary_sha256"],
                hashlib.sha256(b"universal-geph-binary").hexdigest(),
            )

    def test_rejects_tampered_binary(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            release, references = self._fixture(Path(root_name))
            (release / "geph5-client").write_bytes(b"replacement")

            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                self._verify(release, references)

    def test_rejects_forged_reviewed_contract_even_with_matching_checksums(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            release, references = self._fixture(Path(root_name))
            (release / "geph5-client.SOURCE.json").write_text(
                '{"reviewed":false}\n', encoding="utf-8"
            )
            self._write_checksums(release)
            self._write_metadata(release, references["metadata_path"])

            with self.assertRaisesRegex(ValueError, "reviewed source"):
                self._verify(release, references)

    def test_rejects_missing_or_unexpected_assets(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            release, references = self._fixture(Path(root_name))
            (release / "geph5-client.spdx.json").unlink()
            (release / "extra").write_text("unexpected", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "asset set"):
                self._verify(release, references)

    def test_rejects_noncanonical_checksum_names(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            release, references = self._fixture(Path(root_name))
            manifest = release / verify_geph_release.CHECKSUM_NAME
            lines = manifest.read_text(encoding="ascii").splitlines()
            lines[0] = f"{'0' * 64}  ../geph5-client"
            manifest.write_text("\n".join(lines) + "\n", encoding="ascii")

            with self.assertRaisesRegex(ValueError, "invalid line"):
                self._verify(release, references)

    def test_rejects_symlinked_asset(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            release, references = self._fixture(Path(root_name))
            source_asset = release / "geph5-client.SOURCE.json"
            source_asset.unlink()
            os.symlink(references["source"], source_asset)

            with self.assertRaisesRegex(ValueError, "cannot open.*safely"):
                self._verify(release, references)

    def test_rejects_empty_asset_even_when_manifest_matches(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            release, references = self._fixture(Path(root_name))
            (release / "geph5-client").write_bytes(b"")
            self._write_checksums(release)

            with self.assertRaisesRegex(ValueError, "non-empty regular file"):
                self._verify(release, references)

    def test_rejects_reviewed_license_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            release, references = self._fixture(Path(root_name))
            (release / "geph5-client.LICENSE").write_text(
                "different license\n", encoding="utf-8"
            )
            self._write_checksums(release)
            self._write_metadata(release, references["metadata_path"])

            with self.assertRaisesRegex(ValueError, "reviewed license"):
                self._verify(release, references)

    def test_accepts_exact_verified_provenance_and_spdx_predicate(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            release, _ = self._fixture(root)
            provenance, spdx = self._attestation_fixture(root, release)

            result = verify_geph_release.verify_attestation_results(
                release_dir=release,
                provenance_json=provenance,
                spdx_json=spdx,
            )

            self.assertEqual(result["provenance_subject_count"], 8)
            self.assertEqual(result["provenance_result_count"], 1)
            self.assertEqual(result["spdx_result_count"], 1)

    def test_rejects_incomplete_or_extra_provenance_subject_set(self) -> None:
        for mode in ("missing", "extra"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                release, _ = self._fixture(root)
                provenance, spdx = self._attestation_fixture(root, release)

                def mutate(value: object) -> None:
                    subjects = value[0]["verificationResult"]["statement"]["subject"]
                    if mode == "missing":
                        subjects.pop()
                    else:
                        subjects.append(
                            {"name": "extra", "digest": {"sha256": "a" * 64}}
                        )

                self._rewrite_json(provenance, mutate)
                with self.assertRaisesRegex(ValueError, "exact release asset set"):
                    verify_geph_release.verify_attestation_results(
                        release_dir=release,
                        provenance_json=provenance,
                        spdx_json=spdx,
                    )

    def test_rejects_wrong_or_duplicate_provenance_subject(self) -> None:
        for mode in ("wrong-digest", "duplicate"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                release, _ = self._fixture(root)
                provenance, spdx = self._attestation_fixture(root, release)

                def mutate(value: object) -> None:
                    subjects = value[0]["verificationResult"]["statement"]["subject"]
                    if mode == "wrong-digest":
                        subjects[0]["digest"]["sha256"] = "0" * 64
                    else:
                        subjects.append(dict(subjects[0]))

                self._rewrite_json(provenance, mutate)
                error = (
                    "exact release asset set"
                    if mode == "wrong-digest"
                    else "duplicated"
                )
                with self.assertRaisesRegex(ValueError, error):
                    verify_geph_release.verify_attestation_results(
                        release_dir=release,
                        provenance_json=provenance,
                        spdx_json=spdx,
                    )

    def test_rejects_spdx_predicate_or_binary_digest_mismatch(self) -> None:
        for mode in ("predicate", "binary-digest"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                release, _ = self._fixture(root)
                provenance, spdx = self._attestation_fixture(root, release)

                def mutate(value: object) -> None:
                    statement = value[0]["verificationResult"]["statement"]
                    if mode == "predicate":
                        statement["predicate"] = {"spdxVersion": "different"}
                    else:
                        statement["subject"][0]["digest"]["sha256"] = "0" * 64

                self._rewrite_json(spdx, mutate)
                with self.assertRaisesRegex(ValueError, "exact binary and SBOM"):
                    verify_geph_release.verify_attestation_results(
                        release_dir=release,
                        provenance_json=provenance,
                        spdx_json=spdx,
                    )

    def test_rejects_unsafe_or_unbounded_attestation_json(self) -> None:
        for mode in ("symlink", "oversized"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                release, _ = self._fixture(root)
                provenance, spdx = self._attestation_fixture(root, release)
                if mode == "symlink":
                    target = root / "provenance-target.json"
                    provenance.replace(target)
                    os.symlink(target, provenance)
                    error = "cannot open.*safely"
                else:
                    provenance.write_bytes(b"x")
                    with provenance.open("r+b") as handle:
                        handle.truncate(
                            verify_geph_release.MAX_PROVENANCE_JSON_BYTES + 1
                        )
                    error = "size limit"
                with self.assertRaisesRegex(ValueError, error):
                    verify_geph_release.verify_attestation_results(
                        release_dir=release,
                        provenance_json=provenance,
                        spdx_json=spdx,
                    )

    def test_accepts_exact_internal_release_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            metadata = Path(root_name) / "release.json"
            metadata.write_text(
                json.dumps(
                    {
                        "tag_name": "geph-vendor-0.3.9-r1",
                        "draft": False,
                        "prerelease": True,
                        "assets": [
                            {
                                "name": name,
                                "size": 1,
                                "state": "uploaded",
                                "digest": f"sha256:{'a' * 64}",
                            }
                            for name in sorted(verify_geph_release.REQUIRED_ASSETS)
                        ],
                        "unrelated_api_field": "allowed",
                    }
                ),
                encoding="utf-8",
            )

            result = verify_geph_release.verify_release_metadata(
                metadata_path=metadata,
                expected_tag="geph-vendor-0.3.9-r1",
            )

            self.assertEqual(result["tag"], "geph-vendor-0.3.9-r1")
            self.assertEqual(result["asset_count"], 8)

    def test_rejects_incomplete_release_metadata_asset_set(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            metadata = Path(root_name) / "release.json"
            metadata.write_text(
                json.dumps(
                    {
                        "tag_name": "geph-vendor-0.3.9-r1",
                        "draft": False,
                        "prerelease": True,
                        "assets": [
                            {
                                "name": "geph5-client",
                                "size": 1,
                                "state": "uploaded",
                                "digest": f"sha256:{'a' * 64}",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "asset set"):
                verify_geph_release.verify_release_metadata(
                    metadata_path=metadata,
                    expected_tag="geph-vendor-0.3.9-r1",
                )

    def test_rejects_extra_or_duplicate_release_metadata_assets(self) -> None:
        for mode in ("extra", "duplicate"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                release, references = self._fixture(root)
                metadata = references["metadata_path"]
                self.assertIsInstance(metadata, Path)
                payload = json.loads(metadata.read_text(encoding="utf-8"))
                if mode == "extra":
                    payload["assets"].append(
                        {
                            "name": "extra",
                            "size": 1,
                            "state": "uploaded",
                            "digest": f"sha256:{'a' * 64}",
                        }
                    )
                    error = "asset set"
                else:
                    payload["assets"].append(dict(payload["assets"][0]))
                    error = "invalid name"
                metadata.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, error):
                    self._verify(release, references)

    def test_rejects_bad_or_null_release_metadata_digest(self) -> None:
        for digest in (None, "sha256:short", f"sha512:{'a' * 64}"):
            with self.subTest(
                digest=digest
            ), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                release, references = self._fixture(root)
                metadata = references["metadata_path"]
                self.assertIsInstance(metadata, Path)
                payload = json.loads(metadata.read_text(encoding="utf-8"))
                payload["assets"][0]["digest"] = digest
                metadata.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "digest is invalid"):
                    self._verify(release, references)

    def test_rejects_downloaded_asset_size_or_digest_metadata_mismatch(self) -> None:
        for mode in ("size", "digest"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                release, references = self._fixture(root)
                metadata = references["metadata_path"]
                self.assertIsInstance(metadata, Path)
                payload = json.loads(metadata.read_text(encoding="utf-8"))
                if mode == "size":
                    payload["assets"][0]["size"] += 1
                else:
                    payload["assets"][0]["digest"] = f"sha256:{'0' * 64}"
                metadata.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "differ from release metadata"):
                    self._verify(release, references)

    def test_rejects_duplicate_release_metadata_json_key(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            metadata = Path(root_name) / "release.json"
            metadata.write_text(
                '{"tag_name":"geph-vendor-0.3.9-r1",'
                '"tag_name":"geph-vendor-0.3.9-r1",'
                '"draft":false,"prerelease":true,"assets":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
                verify_geph_release.verify_release_metadata(
                    metadata_path=metadata,
                    expected_tag=self.EXPECTED_TAG,
                )

    def test_rejects_wrong_release_state_or_tag(self) -> None:
        cases = (
            ({"tag_name": "other", "draft": False, "prerelease": True}, "tag"),
            (
                {
                    "tag_name": "geph-vendor-0.3.9-r1",
                    "draft": True,
                    "prerelease": True,
                },
                "must not be a draft",
            ),
            (
                {
                    "tag_name": "geph-vendor-0.3.9-r1",
                    "draft": False,
                    "prerelease": False,
                },
                "internal prerelease",
            ),
        )
        for payload, error in cases:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as root_name:
                metadata = Path(root_name) / "release.json"
                metadata.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, error):
                    verify_geph_release.verify_release_metadata(
                        metadata_path=metadata,
                        expected_tag="geph-vendor-0.3.9-r1",
                    )


if __name__ == "__main__":
    unittest.main()

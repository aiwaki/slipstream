from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import make_release_manifest
import make_release_sbom


VERSION = "0.1.8"
STABLE_TAG = "v0.1.8"
PREVIEW_TAG = "v0.1.8-preview.42"
REPOSITORY = "aiwaki/slipstream"
SOURCE_COMMIT = "a" * 40
SOURCE_DATE_EPOCH = 1_783_600_000
TARGET = "aarch64-apple-darwin"


class MakeReleaseManifestTests(unittest.TestCase):
    def _write_release_dir(
        self,
        root: Path,
        *,
        tag: str = STABLE_TAG,
        channel: str = "stable",
    ) -> None:
        files = {
            "Slipstream-macos-arm64.zip": b"zip",
            "Slipstream.app.tar.gz": b"archive",
            "Slipstream.app.tar.gz.sig": b"signature",
            "latest.json": b"{}\n",
        }
        if channel == "stable":
            files.update(
                {
                    "route-policy.json": b"{}\n",
                    "route-policy-latest.json": b"{}\n",
                    "route-policy-keys.json": b"{}\n",
                }
            )
        for name, payload in files.items():
            (root / name).write_bytes(payload)

        sbom = make_release_sbom.build_spdx_document(
            version=VERSION,
            tag=tag,
            repository=REPOSITORY,
            source_commit=SOURCE_COMMIT,
            source_date_epoch=SOURCE_DATE_EPOCH,
            target=TARGET,
            components=[],
        )
        make_release_sbom.write_json_atomic(
            root / make_release_manifest.SBOM_NAME,
            sbom,
        )

    def _write_manifest(
        self,
        root: Path,
        *,
        tag: str = STABLE_TAG,
        channel: str = "stable",
    ) -> dict:
        manifest = make_release_manifest.build_artifact_manifest(
            release_dir=root,
            repository=REPOSITORY,
            version=VERSION,
            tag=tag,
            channel=channel,
            source_commit=SOURCE_COMMIT,
            source_date_epoch=SOURCE_DATE_EPOCH,
            target=TARGET,
        )
        make_release_sbom.write_json_atomic(
            root / make_release_manifest.MANIFEST_NAME,
            manifest,
        )
        return manifest

    def test_manifest_is_deterministic_and_covers_every_publishable_asset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root)

            first = self._write_manifest(root)
            second = make_release_manifest.build_artifact_manifest(
                release_dir=root,
                repository=REPOSITORY,
                version=VERSION,
                tag=STABLE_TAG,
                channel="stable",
                source_commit=SOURCE_COMMIT,
                source_date_epoch=SOURCE_DATE_EPOCH,
                target=TARGET,
            )

            self.assertEqual(first, second)
            names = [artifact["name"] for artifact in first["artifacts"]]
            self.assertEqual(names, sorted(names))
            self.assertEqual(
                set(names),
                {
                    "Slipstream-macos-arm64.zip",
                    "Slipstream.app.tar.gz",
                    "Slipstream.app.tar.gz.sig",
                    "Slipstream.spdx.json",
                    "latest.json",
                    "route-policy-keys.json",
                    "route-policy-latest.json",
                    "route-policy.json",
                },
            )
            self.assertEqual(first["build"]["architecture"], "arm64")

    def test_validation_rehashes_assets_and_validates_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root)
            self._write_manifest(root)

            result = make_release_manifest.validate_artifact_manifest(
                release_dir=root,
                repository=REPOSITORY,
                version=VERSION,
                tag=STABLE_TAG,
                channel="stable",
                source_commit=SOURCE_COMMIT,
                target=TARGET,
            )

            self.assertEqual(result["artifact_count"], 8)
            self.assertEqual(result["sbom"]["format"], "SPDX-2.3")
            self.assertEqual(result["target"], TARGET)

    def test_validation_rejects_artifact_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root)
            self._write_manifest(root)
            (root / "Slipstream-macos-arm64.zip").write_bytes(b"tampered")

            with self.assertRaisesRegex(ValueError, "hashes, sizes, or files"):
                make_release_manifest.validate_artifact_manifest(
                    release_dir=root,
                    repository=REPOSITORY,
                    version=VERSION,
                    tag=STABLE_TAG,
                    channel="stable",
                    source_commit=SOURCE_COMMIT,
                    target=TARGET,
                )

    def test_rejects_unexpected_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root)
            (root / "debug.log").write_text("not publishable\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "unexpected release artifact"):
                make_release_manifest.build_artifact_manifest(
                    release_dir=root,
                    repository=REPOSITORY,
                    version=VERSION,
                    tag=STABLE_TAG,
                    channel="stable",
                    source_commit=SOURCE_COMMIT,
                    source_date_epoch=SOURCE_DATE_EPOCH,
                    target=TARGET,
                )

    def test_rejects_symlinked_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root)
            target = root / "Slipstream-macos-arm64.zip"
            target.unlink()
            os.symlink(root / "latest.json", target)

            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                make_release_manifest.build_artifact_manifest(
                    release_dir=root,
                    repository=REPOSITORY,
                    version=VERSION,
                    tag=STABLE_TAG,
                    channel="stable",
                    source_commit=SOURCE_COMMIT,
                    source_date_epoch=SOURCE_DATE_EPOCH,
                    target=TARGET,
                )

    def test_preview_rejects_remote_policy_assets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root, tag=PREVIEW_TAG, channel="preview")
            (root / "route-policy.json").write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "must not contain route policy"):
                make_release_manifest.build_artifact_manifest(
                    release_dir=root,
                    repository=REPOSITORY,
                    version=VERSION,
                    tag=PREVIEW_TAG,
                    channel="preview",
                    source_commit=SOURCE_COMMIT,
                    source_date_epoch=SOURCE_DATE_EPOCH,
                    target=TARGET,
                )

    def test_cli_writes_manifest_at_the_canonical_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root, tag=PREVIEW_TAG, channel="preview")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(
                    make_release_manifest.main(
                        [
                            "--release-dir",
                            str(root),
                            "--repository",
                            REPOSITORY,
                            "--version",
                            VERSION,
                            "--tag",
                            PREVIEW_TAG,
                            "--channel",
                            "preview",
                            "--source-commit",
                            SOURCE_COMMIT,
                            "--source-date-epoch",
                            str(SOURCE_DATE_EPOCH),
                            "--target",
                            TARGET,
                        ]
                    ),
                    0,
                )

            result = json.loads(stdout.getvalue())
            self.assertEqual(result["artifact_count"], 5)
            self.assertTrue((root / make_release_manifest.MANIFEST_NAME).is_file())


if __name__ == "__main__":
    unittest.main()

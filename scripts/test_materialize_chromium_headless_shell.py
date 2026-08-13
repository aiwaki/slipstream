from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import materialize_chromium_headless_shell as materialize


class ChromiumHeadlessShellMaterializationTests(unittest.TestCase):
    def _archive(self, path: Path, *, unsafe: bool = False) -> str:
        root = "chrome-headless-shell-mac-arm64/"
        with zipfile.ZipFile(path, "w") as bundle:
            bundle.writestr(root + "chrome-headless-shell", b"binary")
            bundle.writestr(root + "LICENSE.headless_shell", b"license")
            bundle.writestr(root + "ABOUT", b"about")
            if unsafe:
                bundle.writestr(root + "../escape", b"bad")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_repository_source_contract_is_exact_and_canonical(self) -> None:
        source = materialize.load_source()

        self.assertEqual(source["version"], "151.0.7922.77")
        self.assertEqual(source["platform"], "mac-arm64")
        self.assertEqual(source["archive"]["length"], 98_976_279)
        self.assertEqual(
            source["archive"]["sha256"],
            "44a2ab4206fc5d5d33974adbc3fd2a80966e7a88167914794f524fa29a3d8e8e",
        )

    def test_macos_download_context_uses_system_ca_without_disabling_tls(self) -> None:
        with (
            mock.patch.object(materialize.sys, "platform", "darwin"),
            mock.patch.object(materialize.Path, "is_file", return_value=True),
            mock.patch.object(
                materialize.ssl, "create_default_context", return_value=object()
            ) as create_context,
        ):
            context = materialize._download_tls_context()

        self.assertIsNotNone(context)
        create_context.assert_called_once_with(cafile="/etc/ssl/cert.pem")

    def test_materializes_verified_runtime_and_private_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "runtime.zip"
            digest = self._archive(archive)
            source = {
                "archive": {
                    "length": archive.stat().st_size,
                    "sha256": digest,
                    "url": "https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.77/mac-arm64/runtime.zip",
                },
                "component": "Chrome for Testing chrome-headless-shell",
                "license_path": "LICENSE.headless_shell",
                "platform": "mac-arm64",
                "version": "151.0.7922.77",
            }
            output = root / "output"
            with mock.patch.object(materialize, "load_source", return_value=source):
                result = materialize.materialize(output, archive)

            self.assertTrue((output / "chrome-headless-shell").is_file())
            self.assertTrue((output / "LICENSE.headless_shell").is_file())
            self.assertEqual(result["archive_sha256"], digest)
            self.assertEqual(
                json.loads((output / "manifest.json").read_text()), result
            )

    def test_rejects_archive_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "runtime.zip"
            self._archive(archive)
            source = {
                "archive": {
                    "length": archive.stat().st_size,
                    "sha256": "0" * 64,
                    "url": "https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.77/mac-arm64/runtime.zip",
                },
                "component": "Chrome for Testing chrome-headless-shell",
                "license_path": "LICENSE.headless_shell",
                "platform": "mac-arm64",
                "version": "151.0.7922.77",
            }
            with mock.patch.object(materialize, "load_source", return_value=source):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    materialize.materialize(root / "output", archive)

    def test_rejects_archive_length_mismatch_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "runtime.zip"
            digest = self._archive(archive)
            source = {
                "archive": {
                    "length": archive.stat().st_size + 1,
                    "sha256": digest,
                    "url": "https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.77/mac-arm64/runtime.zip",
                },
                "component": "Chrome for Testing chrome-headless-shell",
                "license_path": "LICENSE.headless_shell",
                "platform": "mac-arm64",
                "version": "151.0.7922.77",
            }
            with mock.patch.object(materialize, "load_source", return_value=source):
                with self.assertRaisesRegex(ValueError, "length mismatch"):
                    materialize.materialize(root / "output", archive)

    def test_rejects_archive_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "runtime.zip"
            digest = self._archive(archive, unsafe=True)
            source = {
                "archive": {
                    "length": archive.stat().st_size,
                    "sha256": digest,
                    "url": "https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.77/mac-arm64/runtime.zip",
                },
                "component": "Chrome for Testing chrome-headless-shell",
                "license_path": "LICENSE.headless_shell",
                "platform": "mac-arm64",
                "version": "151.0.7922.77",
            }
            with mock.patch.object(materialize, "load_source", return_value=source):
                with self.assertRaisesRegex(ValueError, "unsafe path"):
                    materialize.materialize(root / "output", archive)


if __name__ == "__main__":
    unittest.main()

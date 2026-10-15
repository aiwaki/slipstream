from __future__ import annotations

import hashlib
import io
import json
import os
import stat
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

        self.assertEqual(source["version"], "155.0.8059.79")
        self.assertEqual(source["platform"], "mac-arm64")
        self.assertEqual(source["archive"]["length"], 102_390_341)
        self.assertEqual(
            source["archive"]["sha256"],
            "5f51504ead3d41815111cd73e79c4979df3a4e6aedc7cf6fe2b042ae037363b5",
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

    def test_materialized_resources_survive_root_ownership_and_restrictive_umask(self) -> None:
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "runtime.zip"
                self._archive(archive)
                with zipfile.ZipFile(archive, "a") as bundle:
                    for name, system, mode, payload in (
                        ("helpers/observer", 3, 0o104777, b"#!/bin/sh\nexit 0\n"),
                        ("helpers/data", 3, 0o106666, b"resource"),
                        ("helpers/non-unix", 0, 0o100777, b"data"),
                    ):
                        entry = zipfile.ZipInfo("chrome-headless-shell-mac-arm64/" + name)
                        entry.create_system = system
                        entry.external_attr = mode << 16
                        bundle.writestr(entry, payload)
                source = materialize.load_source()
                source["archive"]["length"] = archive.stat().st_size
                source["archive"]["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
                output = root / "runtime"
                previous_umask = os.umask(mask)
                try:
                    with mock.patch.object(materialize, "load_source", return_value=source):
                        manifest = materialize.materialize(output, archive)
                finally:
                    os.umask(previous_umask)

                expected = {
                    ".": 0o755,
                    "chrome-headless-shell": 0o755,
                    "LICENSE.headless_shell": 0o644,
                    "ABOUT": 0o644,
                    "helpers": 0o755,
                    "helpers/observer": 0o755,
                    "helpers/data": 0o644,
                    "helpers/non-unix": 0o644,
                    "manifest.json": 0o644,
                }
                self.assertEqual(
                    {name: stat.S_IMODE((output / name).stat().st_mode) for name in expected},
                    expected,
                )
                self.assertEqual((output / "helpers/observer").read_bytes(), b"#!/bin/sh\nexit 0\n")
                self.assertEqual((output / "helpers/data").read_bytes(), b"resource")
                self.assertEqual(json.loads((output / "manifest.json").read_text()), manifest)

    def test_permission_verifier_rejects_cross_owner_and_unsafe_modes_without_repair(self) -> None:
        for name, mode in (
            (".", 0o700),
            ("chrome-headless-shell", 0o744),
            ("LICENSE.headless_shell", 0o600),
            ("helpers", 0o700),
            ("helpers/observer", 0o744),
            ("manifest.json", 0o600),
            ("chrome-headless-shell", 0o775),
            ("chrome-headless-shell", 0o4755),
        ):
            with self.subTest(path=name, mode=oct(mode)), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "runtime"
                (output / "helpers").mkdir(parents=True)
                for directory in (output, output / "helpers"):
                    directory.chmod(0o755)
                for filename in ("chrome-headless-shell", "LICENSE.headless_shell", "helpers/observer", "manifest.json"):
                    path = output / filename
                    path.write_bytes(b"fixture")
                    path.chmod(0o755 if filename in ("chrome-headless-shell", "helpers/observer") else 0o644)
                materialize._verify_runtime_permissions(output)
                target = output / name
                target.chmod(mode)
                if name == "chrome-headless-shell" and mode == 0o744:
                    self.assertTrue(os.access(target, os.X_OK))
                with self.assertRaisesRegex(ValueError, "unsafe permissions|after root ownership"):
                    materialize._verify_runtime_permissions(output)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)

    def test_permission_check_precedes_output_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "runtime.zip"
            digest = self._archive(archive)
            source = materialize.load_source()
            source["archive"].update(length=archive.stat().st_size, sha256=digest)
            output = root / "runtime"
            output.mkdir()
            (output / "retained").write_bytes(b"existing runtime")

            def reject_inaccessible_manifest(staged: Path) -> None:
                (staged / "manifest.json").chmod(0o600)
                verify_permissions(staged)

            verify_permissions = materialize._verify_runtime_permissions
            with (
                mock.patch.object(materialize, "load_source", return_value=source),
                mock.patch.object(materialize, "_verify_runtime_permissions", side_effect=reject_inaccessible_manifest),
                self.assertRaisesRegex(ValueError, "after root ownership: manifest.json"),
            ):
                materialize.materialize(output, archive)
            self.assertEqual((output / "retained").read_bytes(), b"existing runtime")
            self.assertEqual(list(output.iterdir()), [output / "retained"])

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

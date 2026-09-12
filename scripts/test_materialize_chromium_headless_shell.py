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

    def _verified_runtime(self, root: Path) -> tuple[Path, dict, dict]:
        archive = root / "runtime.zip"
        digest = self._archive(archive)
        source = materialize.load_source()
        source["archive"]["sha256"] = digest
        source["archive"]["length"] = archive.stat().st_size
        output = root / "runtime"
        with mock.patch.object(materialize, "load_source", return_value=source):
            manifest = materialize.materialize(output, archive)
        return output, source, manifest

    def test_verify_only_accepts_complete_runtime_without_writes_or_downloads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, source, manifest = self._verified_runtime(Path(temporary))

            def snapshot() -> dict:
                return {
                    path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                    for path in output.iterdir()
                }

            before = snapshot()
            with (
                mock.patch.object(materialize, "load_source", return_value=source),
                mock.patch.object(materialize, "materialize", side_effect=AssertionError("must not materialize")),
                mock.patch.object(materialize.urllib.request, "urlopen", side_effect=AssertionError("must not download")),
                mock.patch("sys.stdout", new_callable=io.StringIO) as printed,
            ):
                self.assertEqual(materialize.main(["--output", str(output), "--verify-only"]), 0)
            self.assertEqual(json.loads(printed.getvalue()), manifest)
            self.assertEqual(snapshot(), before)

    def test_verify_only_rejects_incomplete_or_unpinned_runtime(self) -> None:
        cases = (
            "missing_binary", "symlink_binary", "directory_binary", "non_executable",
            "changed_binary", "missing_license", "symlink_license", "missing_about",
            "symlink_runtime", "missing_manifest", "symlink_manifest", "nonobject_manifest",
            "oversized_manifest", "malformed_manifest", "invalid_digest",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, source, manifest = self._verified_runtime(root)
                executable = output / "chrome-headless-shell"
                metadata = output / "manifest.json"
                if case in {"missing_binary", "symlink_binary", "directory_binary"}:
                    executable.unlink()
                    if case == "symlink_binary":
                        executable.symlink_to(output / "ABOUT")
                    elif case == "directory_binary":
                        executable.mkdir()
                elif case == "non_executable":
                    executable.chmod(0o600)
                elif case == "changed_binary":
                    executable.write_bytes(b"changed")
                elif case in {"missing_license", "symlink_license", "missing_about"}:
                    path = output / ("ABOUT" if case == "missing_about" else "LICENSE.headless_shell")
                    path.unlink()
                    if case == "symlink_license":
                        path.symlink_to(output / "ABOUT")
                elif case == "symlink_runtime":
                    alias = root / "alias"
                    alias.symlink_to(output, target_is_directory=True)
                    output = alias
                elif case in {"missing_manifest", "symlink_manifest"}:
                    metadata.unlink()
                    if case == "symlink_manifest":
                        metadata.symlink_to(output / "ABOUT")
                elif case == "nonobject_manifest":
                    metadata.write_text("[]")
                elif case == "oversized_manifest":
                    metadata.write_text(" " * (16 * 1024 + 1))
                elif case == "malformed_manifest":
                    metadata.write_text("{")
                else:
                    manifest["executable_sha256"] = "invalid"
                    metadata.write_text(json.dumps(manifest))
                with mock.patch.object(materialize, "load_source", return_value=source):
                    with self.assertRaises((OSError, ValueError)):
                        materialize.verify_existing(output)

    def test_verify_only_rejects_permissions_hidden_by_build_user_ownership(self) -> None:
        cases = (
            ("chrome-headless-shell", 0o744),
            ("LICENSE.headless_shell", 0o600),
            (".", 0o700),
            ("chrome-headless-shell", 0o775),
            ("helpers/observer", 0o744),
            ("helpers", 0o700),
        )
        for relative, mode in cases:
            with self.subTest(relative=relative, mode=oct(mode)):
                with tempfile.TemporaryDirectory() as temporary:
                    output, source, _ = self._verified_runtime(Path(temporary))
                    helper = output / "helpers/observer"
                    helper.parent.mkdir(mode=0o755)
                    helper.write_bytes(b"helper")
                    helper.chmod(0o755)
                    changed = output / relative
                    changed.chmod(mode)
                    if relative == "chrome-headless-shell":
                        self.assertTrue(os.access(changed, os.X_OK))
                    before = changed.stat().st_mode
                    with mock.patch.object(materialize, "load_source", return_value=source):
                        with self.assertRaisesRegex(ValueError, "permissions|root ownership"):
                            materialize.verify_existing(output)
                    self.assertEqual(changed.stat().st_mode, before)

    def test_verify_only_requires_every_manifest_source_field_to_match(self) -> None:
        fields = (
            "schema_version", "component", "version", "platform", "archive_url",
            "archive_length", "archive_sha256", "license",
        )
        with tempfile.TemporaryDirectory() as temporary:
            output, source, manifest = self._verified_runtime(Path(temporary))
            for field in fields:
                with self.subTest(field=field):
                    changed = {**manifest, field: False if field == "schema_version" else "wrong"}
                    (output / "manifest.json").write_text(json.dumps(changed))
                    with mock.patch.object(materialize, "load_source", return_value=source):
                        with self.assertRaisesRegex(ValueError, "does not match pinned source"):
                            materialize.verify_existing(output)

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

    def test_materialized_resources_survive_root_ownership_and_restrictive_umask(self) -> None:
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "runtime.zip"
                self._archive(archive)
                with zipfile.ZipFile(archive, "a") as bundle:
                    for name, mode, payload in (
                        ("helpers/observer", 0o104777, b"#!/bin/sh\nexit 0\n"),
                        ("helpers/data", 0o100666, b"resource"),
                    ):
                        entry = zipfile.ZipInfo("chrome-headless-shell-mac-arm64/" + name)
                        entry.create_system = 3
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
                        self.assertEqual(materialize.verify_existing(output), manifest)
                finally:
                    os.umask(previous_umask)
                # World readability/traversal/execute is necessary for the
                # console UID after a root install; ownership itself is not
                # included in the app tree digest.
                expected = {
                    ".": 0o755,
                    "chrome-headless-shell": 0o755,
                    "LICENSE.headless_shell": 0o644,
                    "ABOUT": 0o644,
                    "helpers": 0o755,
                    "helpers/observer": 0o755,
                    "helpers/data": 0o644,
                    "manifest.json": 0o644,
                }
                self.assertEqual(
                    {name: stat.S_IMODE((output / name).stat().st_mode) for name in expected},
                    expected,
                )
                self.assertEqual((output / "helpers/observer").read_bytes(), b"#!/bin/sh\nexit 0\n")
                self.assertEqual((output / "helpers/data").read_bytes(), b"resource")

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

    def test_download_stops_at_reviewed_size_before_reading_unbounded_body(self) -> None:
        class CountingResponse(io.BytesIO):
            consumed = 0

            def read(self, size=-1):
                block = super().read(size)
                self.consumed += len(block)
                return block

        response = CountingResponse(b"x" * 4096)
        source = {
            "archive": {
                "url": "https://example.invalid/runtime.zip",
                "length": 64,
                "sha256": "0" * 64,
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            with (
                mock.patch.object(materialize, "load_source", return_value=source),
                mock.patch.object(materialize, "_download_tls_context"),
                mock.patch.object(
                    materialize.urllib.request, "urlopen", return_value=response
                ) as download,
            ):
                with self.assertRaisesRegex(ValueError, "length mismatch"):
                    materialize.materialize(output)
            self.assertEqual(response.consumed, 65)
            download.assert_called_once()
            self.assertFalse(output.exists())

    def test_download_accepts_exact_reviewed_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "runtime.zip"
            digest = self._archive(archive)
            source = {
                "archive": {
                    "url": "https://example.invalid/runtime.zip",
                    "length": archive.stat().st_size,
                    "sha256": digest,
                },
                "component": "headless-shell",
                "version": "fixture",
                "platform": "mac-arm64",
                "license_path": "LICENSE.headless_shell",
            }
            with (
                mock.patch.object(materialize, "load_source", return_value=source),
                mock.patch.object(materialize, "_download_tls_context"),
                mock.patch.object(
                    materialize.urllib.request, "urlopen",
                    return_value=io.BytesIO(archive.read_bytes()),
                ),
            ):
                result = materialize.materialize(root / "output")
            self.assertEqual(result["archive_sha256"], digest)

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

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

import package_chromium_companion as package


class PackageChromiumCompanionTests(unittest.TestCase):
    def test_package_is_deterministic_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = package.package_companion(
                source_dir=package.DEFAULT_SOURCE_DIR,
                native_host_source=package.DEFAULT_NATIVE_HOST_SOURCE,
                output_dir=root / "first",
            )
            second = package.package_companion(
                source_dir=package.DEFAULT_SOURCE_DIR,
                native_host_source=package.DEFAULT_NATIVE_HOST_SOURCE,
                output_dir=root / "second",
            )

            first_archive = first["archive_path"]
            second_archive = second["archive_path"]
            self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
            self.assertEqual(
                first["provenance_path"].read_bytes(),
                second["provenance_path"].read_bytes(),
            )

            with zipfile.ZipFile(first_archive) as archive:
                self.assertEqual(archive.namelist(), sorted(package.PACKAGE_PATHS))
                for info in archive.infolist():
                    self.assertEqual(info.date_time, package.FIXED_ZIP_TIMESTAMP)
                    self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                    self.assertEqual((info.external_attr >> 16) & 0o777, 0o644)
                packaged_manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(
                    package.chrome_extension_id(packaged_manifest["key"]),
                    package.EXPECTED_EXTENSION_ID,
                )
                self.assertNotIn("PRIVACY.md", archive.namelist())
                self.assertFalse(
                    any(name.startswith("tests/") for name in archive.namelist())
                )

            provenance = first["provenance"]
            self.assertEqual(provenance["schema_version"], 1)
            self.assertEqual(
                provenance["archive"]["sha256"],
                package.sha256_file(first_archive),
            )
            self.assertEqual(
                provenance["extension"]["id"],
                package.EXPECTED_EXTENSION_ID,
            )
            self.assertFalse(provenance["remote_code"])
            self.assertEqual(
                [entry["path"] for entry in provenance["files"]],
                sorted(package.PACKAGE_PATHS),
            )

    def test_unexpected_source_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            shutil.copytree(package.DEFAULT_SOURCE_DIR, source)
            (source / ".DS_Store").write_bytes(b"unexpected")
            with self.assertRaisesRegex(package.PackageError, "source tree drift"):
                package.package_companion(
                    source_dir=source,
                    native_host_source=package.DEFAULT_NATIVE_HOST_SOURCE,
                    output_dir=Path(temporary) / "output",
                )

    def test_remote_or_dynamic_code_markers_are_rejected(self) -> None:
        markers = (
            "eval('remote');",
            "new Function('return 1')();",
            "import('https://example.test/remote.js');",
            "fetch(chrome.runtime.getURL('payload'));",
            "new XMLHttpRequest();",
            "new WebSocket('wss://example.test');",
            "new EventSource('https://example.test');",
            "WebAssembly.compile(bytes);",
            "document.createElement('script');",
        )
        for marker in markers:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / "source"
                shutil.copytree(package.DEFAULT_SOURCE_DIR, source)
                worker = source / "service-worker.js"
                worker.write_text(
                    worker.read_text(encoding="utf-8") + f"\n{marker}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(package.PackageError, "code marker"):
                    package.package_companion(
                        source_dir=source,
                        native_host_source=package.DEFAULT_NATIVE_HOST_SOURCE,
                        output_dir=Path(temporary) / "output",
                    )

    def test_service_worker_remote_import_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            shutil.copytree(package.DEFAULT_SOURCE_DIR, source)
            worker = source / "service-worker.js"
            worker.write_text(
                worker.read_text(encoding="utf-8").replace(
                    'importScripts("service-worker-core.js")',
                    'importScripts("https://example.test/remote.js")',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(package.PackageError, "must import only local"):
                package.package_companion(
                    source_dir=source,
                    native_host_source=package.DEFAULT_NATIVE_HOST_SOURCE,
                    output_dir=Path(temporary) / "output",
                )

    def test_manifest_key_must_derive_native_host_extension_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            shutil.copytree(package.DEFAULT_SOURCE_DIR, source)
            manifest_path = source / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["key"] = "YW5vdGhlci1rZXk="
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(package.PackageError, "unexpected extension ID"):
                package.package_companion(
                    source_dir=source,
                    native_host_source=package.DEFAULT_NATIVE_HOST_SOURCE,
                    output_dir=Path(temporary) / "output",
                )

    def test_native_host_origin_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            native_host = Path(temporary) / "native_messaging.rs"
            source = package.DEFAULT_NATIVE_HOST_SOURCE.read_text(encoding="utf-8")
            source = source.replace(
                package.EXPECTED_EXTENSION_ORIGIN,
                "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
                1,
            )
            native_host.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(
                package.PackageError, "CHROMIUM_EXTENSION_ORIGIN mismatch"
            ):
                package.package_companion(
                    source_dir=package.DEFAULT_SOURCE_DIR,
                    native_host_source=native_host,
                    output_dir=Path(temporary) / "output",
                )


if __name__ == "__main__":
    unittest.main()

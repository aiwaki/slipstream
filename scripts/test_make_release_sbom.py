from __future__ import annotations

import base64
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import make_release_sbom


VERSION = "0.1.8"
TAG = "v0.1.8-preview.42"
REPOSITORY = "aiwaki/slipstream"
SOURCE_COMMIT = "a" * 40
SOURCE_DATE_EPOCH = 1_783_600_000
TARGET = "aarch64-apple-darwin"


class MakeReleaseSbomTests(unittest.TestCase):
    def _write_inputs(self, root: Path) -> dict[str, Path]:
        cargo_lock = root / "Cargo.lock"
        cargo_lock.write_text(
            """\
version = 3

[[package]]
name = "slipstream"
version = "0.1.8"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "gtk"
version = "0.18.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
""",
            encoding="utf-8",
        )
        root_id = "path+file:///repo#slipstream@0.1.8"
        serde_id = (
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228"
        )
        gtk_id = "registry+https://github.com/rust-lang/crates.io-index#gtk@0.18.2"
        cargo_metadata = root / "cargo-metadata.json"
        cargo_metadata.write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "id": root_id,
                            "name": "slipstream",
                            "version": VERSION,
                            "source": None,
                            "license": "MIT",
                        },
                        {
                            "id": serde_id,
                            "name": "serde",
                            "version": "1.0.228",
                            "source": (
                                "registry+https://github.com/"
                                "rust-lang/crates.io-index"
                            ),
                            "license": "MIT OR Apache-2.0",
                        },
                        {
                            "id": gtk_id,
                            "name": "gtk",
                            "version": "0.18.2",
                            "source": (
                                "registry+https://github.com/"
                                "rust-lang/crates.io-index"
                            ),
                            "license": "MIT",
                        },
                    ],
                    "resolve": {
                        "root": root_id,
                        "nodes": [
                            {
                                "id": root_id,
                                "dependencies": [serde_id, gtk_id],
                                "deps": [
                                    {
                                        "pkg": serde_id,
                                        "dep_kinds": [{"kind": None, "target": None}],
                                    },
                                    {
                                        "pkg": gtk_id,
                                        "dep_kinds": [{"kind": "dev", "target": None}],
                                    },
                                ],
                            },
                            {"id": serde_id, "dependencies": [], "deps": []},
                            {"id": gtk_id, "dependencies": [], "deps": []},
                        ],
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        npm_digest = base64.b64encode(bytes.fromhex("ab" * 64)).decode("ascii")
        npm_lock = root / "package-lock.json"
        npm_lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {
                            "name": "slipstream-tray",
                            "version": VERSION,
                        },
                        "node_modules/@tauri-apps/api": {
                            "name": "@tauri-apps/api",
                            "version": "2.11.1",
                            "resolved": (
                                "https://registry.npmjs.org/@tauri-apps/api/"
                                "-/api-2.11.1.tgz"
                            ),
                            "integrity": f"sha512-{npm_digest}",
                        },
                        "node_modules/vite": {
                            "name": "vite",
                            "version": "7.0.0",
                            "dev": True,
                        },
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        python_lock = root / "requirements-runtime.txt"
        python_lock.write_text(
            """\
certifi==2026.6.20 \\
    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
cryptography==46.0.5 \\
    --hash=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
""",
            encoding="utf-8",
        )
        geph_version = root / "geph.VERSION"
        geph_version.write_text("0.3.0\n", encoding="utf-8")
        tg_version = root / "tg-ws-proxy.VERSION"
        tg_version.write_text("1.8.1\n", encoding="utf-8")
        return {
            "cargo_lock": cargo_lock,
            "cargo_metadata": cargo_metadata,
            "npm_lock": npm_lock,
            "python_lock": python_lock,
            "geph_version_file": geph_version,
            "tg_ws_proxy_version_file": tg_version,
        }

    def _document(self, root: Path) -> dict:
        components = make_release_sbom.collect_components(**self._write_inputs(root))
        return make_release_sbom.build_spdx_document(
            version=VERSION,
            tag=TAG,
            repository=REPOSITORY,
            source_commit=SOURCE_COMMIT,
            source_date_epoch=SOURCE_DATE_EPOCH,
            target=TARGET,
            components=components,
        )

    def test_same_inputs_produce_identical_spdx_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = self._document(root)
            second = self._document(root)

            first_json = json.dumps(first, indent=2, sort_keys=True)
            second_json = json.dumps(second, indent=2, sort_keys=True)
            self.assertEqual(first_json, second_json)
            self.assertNotIn("2026-07-15", first_json)

    def test_collects_only_runtime_dependency_graphs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            components = make_release_sbom.collect_components(
                **self._write_inputs(Path(tmp))
            )

            identities = {(item.ecosystem, item.name) for item in components}
            self.assertIn(("cargo", "serde"), identities)
            self.assertIn(("npm", "@tauri-apps/api"), identities)
            self.assertIn(("pypi", "certifi"), identities)
            self.assertIn(("pypi", "cryptography"), identities)
            self.assertIn(("cargo", "geph5-client"), identities)
            self.assertIn(("github", "Flowseal/tg-ws-proxy"), identities)
            self.assertNotIn(("npm", "vite"), identities)
            self.assertNotIn(("cargo", "slipstream"), identities)
            self.assertNotIn(("cargo", "gtk"), identities)

            tg_proxy = next(item for item in components if item.ecosystem == "github")
            self.assertEqual(
                tg_proxy.purl,
                "pkg:github/Flowseal/tg-ws-proxy@1.8.1",
            )
            self.assertEqual(tg_proxy.purpose, "APPLICATION")

            npm = next(item for item in components if item.ecosystem == "npm")
            self.assertEqual(npm.checksum_algorithm, "SHA512")
            self.assertEqual(npm.checksum_value, "ab" * 64)

    def test_document_validates_against_release_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            document = self._document(Path(tmp))

            summary = make_release_sbom.validate_spdx_document(
                document,
                version=VERSION,
                tag=TAG,
                repository=REPOSITORY,
                source_commit=SOURCE_COMMIT,
                source_date_epoch=SOURCE_DATE_EPOCH,
                target=TARGET,
            )

            self.assertEqual(summary["format"], "SPDX-2.3")
            self.assertEqual(summary["dependency_count"], 6)
            self.assertEqual(
                document["creationInfo"]["created"],
                make_release_sbom.utc_timestamp(SOURCE_DATE_EPOCH),
            )

    def test_validation_rejects_wrong_source_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            document = self._document(Path(tmp))

            with self.assertRaisesRegex(ValueError, "documentNamespace"):
                make_release_sbom.validate_spdx_document(
                    document,
                    version=VERSION,
                    tag=TAG,
                    repository=REPOSITORY,
                    source_commit="b" * 40,
                    source_date_epoch=SOURCE_DATE_EPOCH,
                    target=TARGET,
                )

    def test_cli_writes_valid_deterministic_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = self._write_inputs(root)
            output = root / "Slipstream.spdx.json"
            arguments = [
                "--version",
                VERSION,
                "--tag",
                TAG,
                "--repository",
                REPOSITORY,
                "--source-commit",
                SOURCE_COMMIT,
                "--source-date-epoch",
                str(SOURCE_DATE_EPOCH),
                "--target",
                TARGET,
                "--cargo-lock",
                str(inputs["cargo_lock"]),
                "--cargo-metadata",
                str(inputs["cargo_metadata"]),
                "--npm-lock",
                str(inputs["npm_lock"]),
                "--python-lock",
                str(inputs["python_lock"]),
                "--geph-version-file",
                str(inputs["geph_version_file"]),
                "--tg-ws-proxy-version-file",
                str(inputs["tg_ws_proxy_version_file"]),
                "--output",
                str(output),
            ]

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(make_release_sbom.main(arguments), 0)

            result = json.loads(stdout.getvalue())
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["package_count"], 7)
            self.assertEqual(document["name"], f"Slipstream-{VERSION}-{TARGET}")
            first_payload = output.read_bytes()
            with redirect_stdout(io.StringIO()):
                self.assertEqual(make_release_sbom.main(arguments), 0)
            self.assertEqual(first_payload, output.read_bytes())


if __name__ == "__main__":
    unittest.main()

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
        geph_source = root / "geph.SOURCE.json"
        geph_source.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "crate": {
                        "name": "geph5-client",
                        "version": "0.3.0",
                        "url": "https://static.crates.io/crates/geph5-client/geph5-client-0.3.0.crate",
                        "sha256": "dd" * 32,
                    },
                    "features": ["aws_lambda"],
                    "targets": [
                        "aarch64-apple-darwin",
                        "x86_64-apple-darwin",
                    ],
                    "lock_sha256": "ee" * 32,
                    "release_revision": 1,
                }
            ),
            encoding="utf-8",
        )
        tg_version = root / "tg-ws-proxy.VERSION"
        tg_version.write_text("1.8.1\n", encoding="utf-8")
        chromium_source = root / "chromium-headless-shell.SOURCE.json"
        chromium_source.write_text(
            json.dumps(
                {
                    "archive": {
                        "length": 98976279,
                        "sha256": "ff" * 32,
                        "url": "https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.77/mac-arm64/chrome-headless-shell-mac-arm64.zip",
                    },
                    "component": "Chrome for Testing chrome-headless-shell",
                    "license_path": "LICENSE.headless_shell",
                    "platform": "mac-arm64",
                    "version": "151.0.7922.77",
                }
            ),
            encoding="utf-8",
        )
        return {
            "cargo_lock": cargo_lock,
            "cargo_metadata": cargo_metadata,
            "npm_lock": npm_lock,
            "python_lock": python_lock,
            "geph_version_file": geph_version,
            "geph_source_file": geph_source,
            "tg_ws_proxy_version_file": tg_version,
            "chromium_headless_shell_source_file": chromium_source,
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

            geph = next(
                item
                for item in components
                if item.ecosystem == "cargo" and item.name == "geph5-client"
            )
            self.assertEqual(geph.checksum_algorithm, "SHA256")
            self.assertEqual(geph.checksum_value, "dd" * 32)
            self.assertEqual(
                geph.download_location,
                "https://static.crates.io/crates/geph5-client/geph5-client-0.3.0.crate",
            )

            npm = next(item for item in components if item.ecosystem == "npm")
            self.assertEqual(npm.checksum_algorithm, "SHA512")
            self.assertEqual(npm.checksum_value, "ab" * 64)

            chromium = next(
                item
                for item in components
                if item.name == "chromium-headless-shell"
            )
            self.assertEqual(chromium.purpose, "APPLICATION")
            self.assertEqual(chromium.license_declared, "NOASSERTION")
            self.assertEqual(chromium.checksum_algorithm, "SHA256")
            self.assertEqual(chromium.checksum_value, "ff" * 32)

    def test_rejects_nonregistry_runtime_packages_instead_of_claiming_crates_io(self) -> None:
        sources = (
            None,  # A local fork can keep a published name and version.
            "git+https://example.invalid/serde#" + "b" * 40,
            "registry+https://example.invalid/crates.io-index",
            "unrecognized+https://example.invalid/index",
        )
        for source in sources:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                inputs = self._write_inputs(Path(tmp))
                metadata_path = inputs["cargo_metadata"]
                metadata = json.loads(metadata_path.read_text())
                dependency = metadata["packages"][1]
                old_id = dependency["id"]
                new_id = (source or "path+file:///local/serde") + "#serde@1.0.228"
                dependency.update(id=new_id, source=source)
                for node in metadata["resolve"]["nodes"]:
                    if node["id"] == old_id:
                        node["id"] = new_id
                    node["dependencies"] = [
                        new_id if item == old_id else item
                        for item in node["dependencies"]
                    ]
                    for edge in node["deps"]:
                        if edge["pkg"] == old_id:
                            edge["pkg"] = new_id
                metadata_path.write_text(json.dumps(metadata))

                with self.assertRaisesRegex(ValueError, "unsupported Cargo source"):
                    make_release_sbom.collect_components(**inputs)

    def test_rejects_runtime_registry_package_without_matching_locked_checksum(self) -> None:
        for change in ("missing-checksum", "different-source", "different-version"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                inputs = self._write_inputs(Path(tmp))
                lock_path = inputs["cargo_lock"]
                lock = lock_path.read_text()
                if change == "missing-checksum":
                    lock = lock.replace('checksum = "' + "a" * 64 + '"\n', "")
                elif change == "different-source":
                    lock = lock.replace(
                        "registry+https://github.com/rust-lang/crates.io-index",
                        "registry+https://example.invalid/index", 1,
                    )
                else:
                    lock = lock.replace('version = "1.0.228"', 'version = "1.0.227"', 1)
                lock_path.write_text(lock)
                with self.assertRaisesRegex(ValueError, "matching locked checksum"):
                    make_release_sbom.collect_components(**inputs)

    def test_local_dev_only_package_does_not_enter_runtime_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inputs = self._write_inputs(Path(tmp))
            metadata_path = inputs["cargo_metadata"]
            metadata = json.loads(metadata_path.read_text())
            metadata["packages"][2]["source"] = None
            metadata_path.write_text(json.dumps(metadata))
            components = make_release_sbom.collect_components(**inputs)
            self.assertIn("serde", [component.name for component in components])
            self.assertNotIn("gtk", [component.name for component in components])

    def _add_owned_core(self, repo: Path, inputs: dict) -> tuple[dict, Path, Path]:
        # Model the actual app -> core -> registry graph, not a name-only stub.
        repo = repo.resolve()
        app_manifest = repo / "app-tauri/src-tauri/Cargo.toml"
        core_manifest = repo / "crates/slipstream-core/Cargo.toml"
        app_manifest.parent.mkdir(parents=True)
        core_manifest.parent.mkdir(parents=True)
        app_manifest.write_text(
            '[package]\nname="slipstream"\nversion="' + VERSION + '"\n'
            '[dependencies]\nslipstream-core={path="../../crates/slipstream-core"}\n'
        )
        core_manifest.write_text(
            '[package]\nname="slipstream-core"\nversion="0.1.0"\n'
            'publish=false\nlicense="MIT"\n'
        )
        inputs["first_party_root"] = repo
        with inputs["cargo_lock"].open("a") as handle:
            handle.write('\n[[package]]\nname="slipstream-core"\nversion="0.1.0"\n')
        metadata = json.loads(inputs["cargo_metadata"].read_text())
        metadata["packages"][0]["manifest_path"] = str(app_manifest)
        core_id = core_manifest.parent.as_uri() + "#slipstream-core@0.1.0"
        metadata["packages"].append({
            "id": core_id, "name": "slipstream-core", "version": "0.1.0",
            "source": None, "manifest_path": str(core_manifest), "license": "MIT",
        })
        root = metadata["resolve"]["nodes"][0]
        serde_id = metadata["packages"][1]["id"]
        root["dependencies"][0] = core_id
        root["deps"][0]["pkg"] = core_id
        metadata["resolve"]["nodes"].append({
            "id": core_id, "dependencies": [serde_id],
            "deps": [{"pkg": serde_id, "dep_kinds": [{"kind": None, "target": None}]}],
        })
        inputs["cargo_metadata"].write_text(json.dumps(metadata))
        return metadata, app_manifest, core_manifest

    def test_owned_core_is_root_source_and_keeps_transitive_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inputs = self._write_inputs(Path(tmp))
            self._add_owned_core(Path(tmp), inputs)
            components = make_release_sbom.collect_components(**inputs)
            self.assertIn("serde", [item.name for item in components])
            self.assertNotIn("slipstream-core", [item.name for item in components])
            # Geph/shared callers have no implicit first-party exception.
            with self.assertRaisesRegex(ValueError, "unsupported Cargo source"):
                make_release_sbom._cargo_components(inputs["cargo_metadata"], inputs["cargo_lock"])

    def test_owned_core_requires_exact_source_binding(self) -> None:
        for change in (
            "foreign-core", "foreign-root", "version", "publish", "license",
            "path", "git", "lock-source", "lock-version", "lock-missing",
            "lock-duplicate", "symlink", "ancestor-symlink", "root-source",
            "root-name", "other-local",
        ):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                inputs = self._write_inputs(Path(tmp))
                metadata, app, core = self._add_owned_core(Path(tmp), inputs)
                if change == "foreign-core":
                    metadata["packages"][-1]["manifest_path"] = "/foreign/Cargo.toml"
                elif change == "foreign-root":
                    metadata["packages"][0]["manifest_path"] = "/foreign/Cargo.toml"
                elif change == "version":
                    metadata["packages"][-1]["version"] = "0.2.0"
                elif change == "publish":
                    core.write_text(core.read_text().replace("publish=false", "publish=true"))
                elif change == "license":
                    core.write_text(core.read_text().replace('license="MIT"', 'license="ISC"'))
                elif change == "path":
                    app.write_text(app.read_text().replace("../../crates/slipstream-core", "../../foreign"))
                elif change == "git":
                    app.write_text(app.read_text().replace('path="', 'git="https://example.invalid",path="'))
                elif change == "lock-source":
                    with inputs["cargo_lock"].open("a") as handle:
                        handle.write('source="registry+https://github.com/rust-lang/crates.io-index"\n')
                elif change == "lock-version":
                    lock = inputs["cargo_lock"]
                    lock.write_text(lock.read_text().replace('version="0.1.0"', 'version="0.2.0"'))
                elif change == "lock-missing":
                    lock = inputs["cargo_lock"]
                    lock.write_text(lock.read_text().replace('\n[[package]]\nname="slipstream-core"\nversion="0.1.0"\n', ""))
                elif change == "lock-duplicate":
                    with inputs["cargo_lock"].open("a") as handle:
                        handle.write('\n[[package]]\nname="slipstream-core"\nversion="0.1.0"\n')
                elif change == "symlink":
                    other = core.with_name("other.toml")
                    core.rename(other)
                    core.symlink_to(other)
                elif change == "ancestor-symlink":
                    directory = core.parent
                    other = directory.with_name("other")
                    directory.rename(other)
                    directory.symlink_to(other, target_is_directory=True)
                elif change == "root-source":
                    metadata["packages"][0]["source"] = make_release_sbom.CRATES_IO_SOURCE
                elif change == "root-name":
                    metadata["packages"][0]["name"] = "other-app"
                elif change == "other-local":
                    metadata["packages"][1]["source"] = None
                inputs["cargo_metadata"].write_text(json.dumps(metadata))
                with self.assertRaisesRegex(ValueError, "unsupported Cargo source"):
                    make_release_sbom.collect_components(**inputs)

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
            self.assertEqual(summary["dependency_count"], 7)
            root_package = next(item for item in document["packages"]
                                if item["SPDXID"] == make_release_sbom.ROOT_SPDX_ID)
            self.assertIn("first-party crates/slipstream-core", root_package["comment"])
            # Previously generated releases lack the explanatory comment.
            del root_package["comment"]
            make_release_sbom.validate_spdx_document(
                document, version=VERSION, tag=TAG, repository=REPOSITORY,
                source_commit=SOURCE_COMMIT, source_date_epoch=SOURCE_DATE_EPOCH,
                target=TARGET,
            )
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
                "--geph-source-file",
                str(inputs["geph_source_file"]),
                "--tg-ws-proxy-version-file",
                str(inputs["tg_ws_proxy_version_file"]),
                "--chromium-headless-shell-source-file",
                str(inputs["chromium_headless_shell_source_file"]),
                "--output",
                str(output),
            ]

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(make_release_sbom.main(arguments), 0)

            result = json.loads(stdout.getvalue())
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["package_count"], 8)
            self.assertEqual(document["name"], f"Slipstream-{VERSION}-{TARGET}")
            first_payload = output.read_bytes()
            with redirect_stdout(io.StringIO()):
                self.assertEqual(make_release_sbom.main(arguments), 0)
            self.assertEqual(first_payload, output.read_bytes())


if __name__ == "__main__":
    unittest.main()

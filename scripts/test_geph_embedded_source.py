from __future__ import annotations

import copy
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import geph_vendor_source as source


# Standard OSI template, not a recovered package-specific copyright notice.
ISC_STANDARD_TEXT = (Path(__file__).parent / "fixtures/isc-standard-license.txt").read_text()


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def bind(package: dict) -> None:
    for entry in package["files"]:
        entry["sha256"] = digest(entry["content"].encode())
    unsigned = {key: value for key, value in package.items() if key != "sha256"}
    package["sha256"] = digest(json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode())


class EmbeddedGephSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.contract_path = self.root / "SOURCE.json"
        self.version_path = self.root / "VERSION"
        self.lock_path = self.root / "Cargo.lock"
        self.crate_path = self.root / "geph.crate"
        self.version_path.write_text("0.4.3\n")
        self.lock_path.write_text('version = 3\n[[package]]\nname = "geph5-client"\nversion = "0.4.3"\n')
        self.manifest = ('[package]\nname = "geph5-client"\nversion = "0.4.3"\n'
                         '[dependencies.mizaru2]\npackage = "mizaru2-slipstream-client"\n'
                         'path = "slipstream-vendor/mizaru-client"\n'
                         '[patch.crates-io.geph5-broker-protocol]\n'
                         'path = "slipstream-vendor/geph5-broker-protocol"\n')
        self.make_archive()
        self.contract = {
            "schema_version": 1,
            "crate": {"name": "geph5-client", "version": "0.4.3",
                      "url": "https://static.crates.io/crates/geph5-client/geph5-client-0.4.3.crate",
                      "sha256": digest(self.crate_path.read_bytes())},
            "features": ["aws_lambda"],
            "targets": ["aarch64-apple-darwin", "x86_64-apple-darwin"],
            "release_revision": 1, "lock_sha256": digest(self.lock_path.read_bytes()),
            "embedded_packages": {"schema_version": 1, "packages": self.packages()},
        }
        self.save()

    def make_archive(self, extra: str | None = None, symlink: bool = False) -> None:
        with tarfile.open(self.crate_path, "w:gz") as archive:
            for path, content in {"Cargo.toml": self.manifest, "src/lib.rs": "// original\n"}.items():
                info = tarfile.TarInfo(f"geph5-client-0.4.3/{path}")
                payload = content.encode()
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            if extra:
                info = tarfile.TarInfo(f"geph5-client-0.4.3/{extra}")
                if symlink:
                    info.type = tarfile.SYMTYPE
                    info.linkname = "../../outside"
                archive.addfile(info, io.BytesIO(b""))

    def packages(self) -> list[dict]:
        specs = [
            ("mizaru-client", "mizaru2-slipstream-client", "0.1.0", "ISC", ("mizaru2", "0.2.21"),
             ["lib"], '[dependencies.backend]\npackage = "slipstream-rsa-client"\npath = "../aws-lc-backend"\n'),
            ("aws-lc-backend", "slipstream-rsa-client", "0.1.0", "MIT", None, ["lib", "owned"],
             '[dependencies]\naws-lc-sys = "=0.45.0"\n'),
            ("geph5-broker-protocol", "geph5-broker-protocol", "0.4.3", "ISC", ("geph5-broker-protocol", "0.4.3"),
             ["lib", "bridge", "exit", "mac", "puzzle", "route", "signed"],
             '[dependencies.mizaru2]\npackage = "mizaru2-slipstream-client"\npath = "../mizaru-client"\n'),
        ]
        packages = []
        for directory, name, version, license_id, upstream, modules, dependencies in specs:
            files = {f"src/{module}.rs": f"// synthetic {module}\n" for module in modules}
            files["Cargo.toml"] = (f'[package]\nname = "{name}"\nversion = "{version}"\n'
                                    f'license = "{license_id}"\npublish = false\n{dependencies}')
            if upstream:
                original = (f'[package]\nname = "{upstream[0]}"\nversion = "{upstream[1]}"\nlicense = "ISC"\n')
                files["provenance/Cargo.toml"] = original
                files["SOURCE-NOTICE.md"] = ("Synthetic fixture: the retained package declares ISC. "
                    "This is a source attribution/declaration, not a fabricated upstream copyright notice.\n")
                files["LICENSE-ISC.txt"] = ISC_STANDARD_TEXT
                provenance = {"kind": "derivative", "name": upstream[0], "version": upstream[1],
                              "url": f"https://static.crates.io/crates/{upstream[0]}/{upstream[0]}-{upstream[1]}.crate",
                              "sha256": digest(b"synthetic upstream archive"),
                              "original_files": {**{f"src/{module}.rs": digest(b"synthetic upstream source") for module in modules},
                                                 "Cargo.toml": digest(original.encode())}}
            else:
                files["LICENSE"] = (Path(__file__).resolve().parents[1] / "LICENSE").read_text()
                provenance = {"kind": "first-party", "repository": "https://github.com/aiwaki/slipstream"}
            package = {"path": f"slipstream-vendor/{directory}", "name": name, "version": version,
                       "license": license_id, "provenance": provenance,
                       "files": [{"path": path, "content": content, "sha256": digest(content.encode())}
                                 for path, content in sorted(files.items())]}
            bind(package)
            packages.append(package)
        return packages

    def save(self) -> None:
        self.contract_path.write_text(json.dumps(self.contract))

    def materialize(self, name: str = "out") -> Path:
        return source.materialize_source(source_path=self.contract_path, version_path=self.version_path,
            cargo_lock_path=self.lock_path, crate_path=self.crate_path, output=self.root / name)

    def entry(self, package: dict, path: str) -> dict:
        return next(entry for entry in package["files"] if entry["path"] == path)

    def test_materialization_is_self_contained_exact_and_preserves_root_edits(self) -> None:
        before, after = "// original\n", "// retained reviewed source edit\n"
        self.contract["source_edits"] = [{"path": "src/lib.rs", "before": before, "after": after,
            "before_sha256": digest(before.encode()), "after_sha256": digest(after.encode())}]
        self.save()
        first, second = self.materialize("a"), self.materialize("b")
        for package in self.contract["embedded_packages"]["packages"]:
            for entry in package["files"]:
                relative = Path(package["path"]) / entry["path"]
                self.assertEqual((first / relative).read_bytes(), entry["content"].encode())
                self.assertEqual((second / relative).read_bytes(), (first / relative).read_bytes())
        self.assertEqual((first / "src/lib.rs").read_text(), after)
        self.assertEqual((first / "Cargo.lock").read_bytes(), self.lock_path.read_bytes())
        self.assertEqual(first.stat().st_mode & 0o777, 0o700)
        summary = source.verify_source_contract(source_path=self.contract_path, version_path=self.version_path,
                                                cargo_lock_path=self.lock_path)
        self.assertEqual(summary["source_sha256"], digest(self.contract_path.read_bytes()))
        self.assertEqual(summary["embedded_packages"], {p["name"]: p["sha256"] for p in self.contract["embedded_packages"]["packages"]})

    def test_contract_rejects_unknown_identity_path_and_file_injection(self) -> None:
        mutations = [
            lambda p: p.update(name="mizaru2"), lambda p: p.update(version="0.0.0"),
            lambda p: p.update(license="MIT"), lambda p: p.update(path="slipstream-vendor/../escape"),
            lambda p: p.update(path="/tmp/escape"), lambda p: p.update(path="Slipstream-vendor/mizaru-client"),
            lambda p: p.update(extra=True),
        ]
        for replacement in ("build.rs", ".cargo/config.toml", "Cargo.lock", "../lib.rs", "/lib.rs", "src/../lib.rs", "src/Lib.rs"):
            mutations.append(lambda p, value=replacement: p["files"][0].update(path=value))
        original = copy.deepcopy(self.contract)
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.contract = copy.deepcopy(original)
                package = self.contract["embedded_packages"]["packages"][0]
                mutate(package)
                bind(package)
                self.save()
                with self.assertRaises(ValueError):
                    source.load_source_contract(self.contract_path)

    def test_contract_requires_each_isc_license_after_rebinding_hashes(self) -> None:
        original = copy.deepcopy(self.contract)
        # Removing both licenses also exercises the formerly accepted file set.
        for indices in ((0, 2), (0,), (2,)):
            with self.subTest(indices=indices):
                self.contract = copy.deepcopy(original)
                for index in indices:
                    package = self.contract["embedded_packages"]["packages"][index]
                    package["files"].remove(self.entry(package, "LICENSE-ISC.txt"))
                    bind(package)
                self.save()
                with self.assertRaisesRegex(ValueError, "file set"):
                    source.load_source_contract(self.contract_path)

    def test_contract_rejects_changed_isc_license_after_rebinding_hashes(self) -> None:
        original = copy.deepcopy(self.contract)
        mutations = (
            ISC_STANDARD_TEXT[:100],
            ISC_STANDARD_TEXT.replace("with or without fee", "without fee"),
            ISC_STANDARD_TEXT.replace("<YEAR> <OWNER>", "2026 Invented Copyright Holder"),
        )
        for index in (0, 2):
            for payload in mutations:
                with self.subTest(index=index, payload=payload[:100]):
                    self.contract = copy.deepcopy(original)
                    package = self.contract["embedded_packages"]["packages"][index]
                    self.entry(package, "LICENSE-ISC.txt")["content"] = payload
                    bind(package)
                    self.save()
                    with self.assertRaisesRegex(ValueError, "standard ISC license text"):
                        source.load_source_contract(self.contract_path)

    def test_contract_rejects_isc_license_path_substitution_and_mit_addition(self) -> None:
        original = copy.deepcopy(self.contract)
        for index in (0, 2):
            for path in ("LICENSE", "provenance/LICENSE-ISC.txt", "../LICENSE-ISC.txt"):
                with self.subTest(index=index, path=path):
                    self.contract = copy.deepcopy(original)
                    package = self.contract["embedded_packages"]["packages"][index]
                    self.entry(package, "LICENSE-ISC.txt")["path"] = path
                    bind(package)
                    self.save()
                    with self.assertRaisesRegex(ValueError, "file path"):
                        source.load_source_contract(self.contract_path)
        self.contract = copy.deepcopy(original)
        package = self.contract["embedded_packages"]["packages"][1]
        package["files"].append({"path": "LICENSE-ISC.txt", "content": ISC_STANDARD_TEXT})
        bind(package)
        self.save()
        with self.assertRaisesRegex(ValueError, "file set"):
            source.load_source_contract(self.contract_path)

    def test_contract_rejects_duplicate_missing_and_fourth_packages_or_files(self) -> None:
        original = copy.deepcopy(self.contract)
        for mutation in (
            lambda s: s["packages"].pop(),
            lambda s: s["packages"].append(copy.deepcopy(s["packages"][0])),
            lambda s: s["packages"].__setitem__(1, copy.deepcopy(s["packages"][0])),
            lambda s: s["packages"][0]["files"].pop(),
            lambda s: s["packages"][0]["files"].__setitem__(0, copy.deepcopy(s["packages"][0]["files"][1])),
        ):
            self.contract = copy.deepcopy(original)
            mutation(self.contract["embedded_packages"])
            for package in self.contract["embedded_packages"]["packages"]:
                bind(package)
            self.save()
            with self.assertRaises(ValueError):
                source.load_source_contract(self.contract_path)

    def test_contract_rejects_manifest_build_config_and_unreviewed_dependency_edges(self) -> None:
        original = copy.deepcopy(self.contract)
        for suffix in ('\n[build-dependencies]\nx = "1"\n', '\n[workspace]\n',
                       '\n[patch.crates-io]\nx = { path = "../../outside" }\n',
                       '\n[dependencies.extra]\npath = "../other"\n',
                       '\n[dependencies.extra]\ngit = "https://example.invalid/evil"\n',
                       '\n[lib]\npath = "../../outside.rs"\n',
                       '\n[lib]\nproc-macro = true\n'):
            with self.subTest(suffix=suffix):
                self.contract = copy.deepcopy(original)
                package = self.contract["embedded_packages"]["packages"][0]
                self.entry(package, "Cargo.toml")["content"] += suffix
                bind(package)
                self.save()
                with self.assertRaises(ValueError):
                    source.load_source_contract(self.contract_path)
        for before, after in (('publish = false', 'publish = true'),
                              ('publish = false', 'build = "build.rs"\npublish = false'),
                              ('../aws-lc-backend', '../../outside'),
                              ('slipstream-rsa-client', 'rsa')):
            self.contract = copy.deepcopy(original)
            package = self.contract["embedded_packages"]["packages"][0]
            entry = self.entry(package, "Cargo.toml")
            entry["content"] = entry["content"].replace(before, after)
            bind(package)
            self.save()
            with self.assertRaises(ValueError):
                source.load_source_contract(self.contract_path)

    def test_contract_rejects_tampered_content_hashes_provenance_and_licenses(self) -> None:
        original = copy.deepcopy(self.contract)
        mutations = [
            lambda p: p.update(sha256="0" * 64),
            lambda p: self.entry(p, "src/lib.rs").update(content="// unbound change\n"),
            lambda p: self.entry(p, "src/lib.rs").update(sha256="0" * 64),
            lambda p: p["provenance"].update(name="wrong"),
            lambda p: p["provenance"].update(url="https://example.invalid/archive"),
            lambda p: p["provenance"]["original_files"].update(**{"Cargo.toml": "0" * 64}),
            lambda p: self.entry(p, "provenance/Cargo.toml").update(content='[package]\nname="mizaru2"\nversion="0.2.21"\nlicense="MIT"\n'),
            lambda p: self.entry(p, "provenance/Cargo.toml").update(content='package = "not a table"\n'),
        ]
        for index, mutate in enumerate(mutations):
            self.contract = copy.deepcopy(original)
            package = self.contract["embedded_packages"]["packages"][0]
            mutate(package)
            if index >= 3:
                bind(package)
            self.save()
            with self.assertRaises(ValueError):
                source.load_source_contract(self.contract_path)
        self.contract = copy.deepcopy(original)
        package = self.contract["embedded_packages"]["packages"][1]
        self.entry(package, "LICENSE")["content"] = "Invented license\n"
        bind(package)
        self.save()
        with self.assertRaisesRegex(ValueError, "MIT license"):
            source.load_source_contract(self.contract_path)
        self.contract = copy.deepcopy(original)
        package = self.contract["embedded_packages"]["packages"][0]
        upstream = self.entry(package, "provenance/Cargo.toml")
        upstream["content"] = 'package = "not a table"\n'
        package["provenance"]["original_files"]["Cargo.toml"] = digest(upstream["content"].encode())
        bind(package)
        self.save()
        with self.assertRaisesRegex(ValueError, "upstream license declaration/identity"):
            source.load_source_contract(self.contract_path)

    def test_contract_rejects_duplicate_json_keys_invalid_schema_and_size(self) -> None:
        self.contract_path.write_text('{"schema_version": 1, "schema_version": 1}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            source.load_source_contract(self.contract_path)
        for version in (True, 2, "1"):
            self.contract["embedded_packages"]["schema_version"] = version
            self.save()
            with self.assertRaises(ValueError):
                source.load_source_contract(self.contract_path)
        self.contract["embedded_packages"]["schema_version"] = 1
        package = self.contract["embedded_packages"]["packages"][0]
        self.entry(package, "src/lib.rs")["content"] = "я" * (128 * 1024 + 1)
        bind(package)
        self.save()
        with self.assertRaisesRegex(ValueError, "size limit"):
            source.load_source_contract(self.contract_path)

    def test_materialization_rejects_preseeded_namespace_and_symlink(self) -> None:
        for index, (path, symlink) in enumerate((("slipstream-vendor/keep", False),
                                                ("Slipstream-Vendor/keep", False),
                                                ("slipstream-vendor", True))):
            self.make_archive(path, symlink)
            self.contract["crate"]["sha256"] = digest(self.crate_path.read_bytes())
            self.save()
            with self.assertRaises(ValueError):
                self.materialize(f"bad-{index}")
        outside = self.root / "outside"
        self.assertFalse(outside.exists())

    def test_materialization_rejects_wrong_root_edges_and_preserves_existing_root(self) -> None:
        original = self.manifest
        for index, changed in enumerate((original.replace("slipstream-vendor/mizaru-client", "../outside"),
                                        original.replace("mizaru2-slipstream-client", "mizaru2"),
                                        original + '\n[dependencies.extra]\npath = "../outside"\n',
                                        original + '\n[replace.extra]\npath = "../outside"\n',
                                        original.split("[patch.crates-io.")[0])):
            self.manifest = changed
            self.make_archive()
            self.contract["crate"]["sha256"] = digest(self.crate_path.read_bytes())
            self.save()
            with self.assertRaisesRegex(ValueError, "reviewed embedded"):
                self.materialize(f"bad-root-{index}")
        existing = self.root / "existing" / "geph5-client-0.4.3"
        existing.mkdir(parents=True)
        (existing / "sentinel").write_text("keep")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.materialize("existing")
        self.assertEqual((existing / "sentinel").read_text(), "keep")

    def test_materialization_uses_verified_source_snapshot_and_checks_copied_lock(self) -> None:
        extract = source.extract_crate
        original_source = copy.deepcopy(self.contract)

        def replace_source(**kwargs):
            root = extract(**kwargs)
            self.contract.pop("embedded_packages")
            self.save()
            return root

        with mock.patch.object(source, "extract_crate", side_effect=replace_source):
            materialized = self.materialize("source-change")
        self.assertTrue((materialized / "slipstream-vendor/mizaru-client/src/lib.rs").is_file())
        self.contract = original_source
        self.save()

        def replace_lock(**kwargs):
            root = extract(**kwargs)
            self.lock_path.write_text("changed after initial verification\n")
            return root

        with mock.patch.object(source, "extract_crate", side_effect=replace_lock):
            with self.assertRaisesRegex(ValueError, "materialized Geph Cargo.lock"):
                self.materialize("lock-change")

    def test_transition_requires_new_revision_and_binds_complete_embedded_source(self) -> None:
        previous_path = self.root / "previous.json"
        previous = copy.deepcopy(self.contract)
        previous.pop("embedded_packages")
        previous_path.write_text(json.dumps(previous))
        policy_path = self.root / "policy.json"
        policy_path.write_text('{"exceptions": [], "schema_version": 1}')

        def verify():
            return source.verify_source_transition(
                previous_source_path=previous_path, previous_version_path=self.version_path,
                previous_cargo_lock_path=self.lock_path, previous_policy_path=policy_path,
                current_source_path=self.contract_path, current_version_path=self.version_path,
                current_cargo_lock_path=self.lock_path, current_policy_path=policy_path,
            )

        with self.assertRaisesRegex(ValueError, "reused"):
            verify()
        self.contract["release_revision"] = 2
        self.save()
        result = verify()
        self.assertEqual(result["transition"], "revision")
        self.assertEqual(result["previous_source_sha256"], digest(previous_path.read_bytes()))
        self.assertEqual(result["current_source_sha256"], digest(self.contract_path.read_bytes()))
        previous_path.write_bytes(self.contract_path.read_bytes())
        package = self.contract["embedded_packages"]["packages"][0]
        self.entry(package, "src/lib.rs")["content"] += "// changed embedded bytes\n"
        bind(package)
        self.save()
        with self.assertRaisesRegex(ValueError, "reused"):
            verify()

    def test_source_total_and_json_size_limits_apply_before_materialization(self) -> None:
        for package in self.contract["embedded_packages"]["packages"]:
            for entry in package["files"]:
                if entry["path"].endswith(".rs"):
                    entry["content"] = "x" * (200 * 1024)
            bind(package)
        self.save()
        with self.assertRaisesRegex(ValueError, "size limit"):
            source.load_source_contract(self.contract_path)
        self.contract_path.write_bytes(b" " * (4 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "size limit"):
            source.load_source_contract(self.contract_path)

    def test_materialization_rejects_archive_swapped_after_initial_verification(self) -> None:
        verify = source._verify_source_contract_files

        def swap(**kwargs):
            result = verify(**kwargs)
            self.make_archive("src/unreviewed.rs")
            return result

        with mock.patch.object(source, "_verify_source_contract_files", side_effect=swap):
            with self.assertRaisesRegex(ValueError, "extracted crate does not match"):
                self.materialize()
        self.assertFalse((self.root / "out/geph5-client-0.4.3/src/unreviewed.rs").exists())

    def test_extraction_rejects_casefold_collisions_and_excessive_contents(self) -> None:
        self.make_archive("Src/lib.rs")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            source.extract_crate(crate_path=self.crate_path, version="0.4.3", output=self.root / "case")
        self.make_archive()
        with mock.patch.object(source, "MAX_CRATE_ENTRIES", 1):
            with self.assertRaisesRegex(ValueError, "size limit"):
                source.extract_crate(crate_path=self.crate_path, version="0.4.3", output=self.root / "count")
        with mock.patch.object(source, "MAX_CRATE_UNPACKED_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "size limit"):
                source.extract_crate(crate_path=self.crate_path, version="0.4.3", output=self.root / "size")
        with mock.patch.object(source, "MAX_CRATE_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "size limit"):
                source.extract_crate(crate_path=self.crate_path, version="0.4.3", output=self.root / "compressed")

    def test_extraction_cannot_overwrite_precreated_output_and_ignores_tar_root_mode(self) -> None:
        with tarfile.open(self.crate_path, "w:gz") as archive:
            root_info = tarfile.TarInfo("geph5-client-0.4.3")
            root_info.type = tarfile.DIRTYPE
            root_info.mode = 0o777
            archive.addfile(root_info)
            payload = self.manifest.encode()
            info = tarfile.TarInfo("geph5-client-0.4.3/Cargo.toml")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        extracted = source.extract_crate(crate_path=self.crate_path, version="0.4.3", output=self.root / "private")
        self.assertEqual(extracted.stat().st_mode & 0o777, 0o700)
        (extracted / "Cargo.toml").write_text("keep sentinel")
        with self.assertRaisesRegex(ValueError, "already exists"):
            source.extract_crate(crate_path=self.crate_path, version="0.4.3", output=self.root / "private")
        self.assertEqual((extracted / "Cargo.toml").read_text(), "keep sentinel")


if __name__ == "__main__":
    unittest.main()

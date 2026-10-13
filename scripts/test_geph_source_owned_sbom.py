from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest
from pathlib import Path

import make_geph_vendor_sbom as sbom
import test_geph_embedded_source as embedded_fixture


class SourceOwnedGephSbomTests(unittest.TestCase):
    def setUp(self):
        self.fixture = embedded_fixture.EmbeddedGephSourceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.source = self.fixture.contract
        self.lock = self.fixture.lock_path
        with self.lock.open("a") as handle:
            for package in self.source["embedded_packages"]["packages"]:
                handle.write(f'\n[[package]]\nname = "{package["name"]}"\nversion = "{package["version"]}"\n')
            for name in ("direct-registry", "local-transitive"):
                handle.write(f'\n[[package]]\nname = "{name}"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + 'a' * 64 + '"\n')
        self.source["lock_sha256"] = hashlib.sha256(self.lock.read_bytes()).hexdigest()
        self.fixture.save()
        self.root = self.fixture.materialize().resolve()
        self.source_hash = hashlib.sha256(self.fixture.contract_path.read_bytes()).hexdigest()
        self.metadata = []
        for index, target in enumerate(self.source["targets"]):
            path = self.fixture.root / f"metadata-{index}.json"
            path.write_text(json.dumps(self.graph()))
            self.metadata.append((target, path))

    def graph(self):
        packages = [{"id": "root", "name": "geph5-client", "version": "0.4.3", "license": "MPL-2.0", "source": None, "manifest_path": str(self.root / "Cargo.toml")}]
        for descriptor in self.source["embedded_packages"]["packages"]:
            packages.append({"id": descriptor["name"], "name": descriptor["name"], "version": descriptor["version"], "license": descriptor["license"], "source": None, "manifest_path": str(self.root / descriptor["path"] / "Cargo.toml")})
        for name in ("direct-registry", "local-transitive"):
            packages.append({"id": name, "name": name, "version": "1.0.0", "license": "MIT", "source": "registry+https://github.com/rust-lang/crates.io-index"})
        edges = {"root": [p["name"] for p in self.source["embedded_packages"]["packages"]] + ["direct-registry"], "slipstream-rsa-client": ["local-transitive"]}
        return {"packages": packages, "resolve": {"root": "root", "nodes": [{"id": p["id"], "deps": [{"pkg": dependency, "dep_kinds": [{"kind": None, "target": None}]} for dependency in edges.get(p["id"], [])]} for p in packages]}}

    def collect(self, **kwargs):
        options = dict(cargo_lock=self.lock, cargo_metadata=self.metadata, expected_targets=self.source["targets"], source=self.source, source_root=self.root)
        options.update(kwargs)
        return sbom.collect_components(**options)

    def document(self):
        return sbom.build_spdx_document(repository="aiwaki/slipstream", source_commit="a" * 40, source_date_epoch=1784159400, target="macos-universal", source=self.source, source_sha256=self.source_hash, components=self.collect())

    def verify(self, document, **kwargs):
        options = dict(repository="aiwaki/slipstream", source_commit="a" * 40, target="macos-universal", source=self.source, source_sha256=self.source_hash)
        options.update(kwargs)
        return sbom.validate_spdx_document(document, **options)

    def test_real_materialized_generation_retains_transitive_registry_and_exact_files(self):
        components = self.collect()
        self.assertEqual({item.name for item in components}, {"direct-registry", "local-transitive"})
        document = self.document()
        self.assertEqual(document, self.document())
        self.assertEqual(self.verify(document)["package_count"], 6)
        self.assertEqual(self.verify(json.loads(json.dumps(document, sort_keys=True)))["package_count"], 6)
        self.assertEqual(len(document["files"]), 20)
        owned = [p for p in document["packages"] if p["SPDXID"].startswith("SPDXRef-Package-source-")]
        self.assertEqual(len(owned), 3)
        for package in owned:
            descriptor = next(p for p in self.source["embedded_packages"]["packages"] if p["name"] == package["name"])
            self.assertNotIn("externalRefs", package)
            self.assertNotIn("checksums", package)
            self.assertEqual(package["downloadLocation"], "NOASSERTION")
            self.assertEqual(package["licenseConcluded"], "NOASSERTION")
            self.assertEqual(package["copyrightText"], "NOASSERTION")
            info = json.loads(package["sourceInfo"])
            self.assertEqual(info["descriptor_sha256"], descriptor["sha256"])
            self.assertEqual(info["source_sha256"], self.source_hash)
            values = sorted(hashlib.sha1(p["content"].encode()).hexdigest() for p in descriptor["files"])
            self.assertEqual(package["packageVerificationCode"], {"packageVerificationCodeValue": hashlib.sha1("".join(values).encode()).hexdigest()})
        for file in document["files"]:
            payload = (self.root / file["fileName"]).read_bytes()
            self.assertEqual(file["checksums"][1]["checksumValue"], hashlib.sha256(payload).hexdigest())

    def test_isc_standard_text_is_inventoried_and_tampering_fails_closed(self):
        document = self.document()
        license_files = [file for file in document["files"] if file["fileName"].endswith("/LICENSE-ISC.txt")]
        self.assertEqual({file["fileName"] for file in license_files}, {
            "./slipstream-vendor/mizaru-client/LICENSE-ISC.txt",
            "./slipstream-vendor/geph5-broker-protocol/LICENSE-ISC.txt",
        })
        for file in license_files:
            with self.subTest(path=file["fileName"]):
                path = self.root / file["fileName"]
                original = path.read_bytes()
                self.assertEqual(original, embedded_fixture.ISC_STANDARD_TEXT.encode())
                for payload in (None, original.replace(b"<OWNER>", b"Invented Owner")):
                    if payload is None:
                        path.unlink()
                    else:
                        path.write_bytes(payload)
                    with self.assertRaises(ValueError):
                        self.collect()
                    path.write_bytes(original)
                missing = copy.deepcopy(document)
                missing["files"] = [entry for entry in missing["files"] if entry["SPDXID"] != file["SPDXID"]]
                with self.assertRaises(ValueError):
                    self.verify(missing)
                changed = copy.deepcopy(document)
                entry = next(entry for entry in changed["files"] if entry["SPDXID"] == file["SPDXID"])
                entry["checksums"][1]["checksumValue"] = hashlib.sha256(b"changed license").hexdigest()
                with self.assertRaises(ValueError):
                    self.verify(changed)

    def test_materialized_root_is_required_and_symlinks_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "explicit"):
            self.collect(source_root=None)
        link = self.fixture.root / "linked-root"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "physical"):
            self.collect(source_root=link)
        target = self.root / self.source["embedded_packages"]["packages"][0]["path"] / "src/lib.rs"
        payload = target.read_bytes()
        target.unlink()
        outside = self.fixture.root / "outside.rs"
        outside.write_bytes(payload)
        target.symlink_to(outside)
        with self.assertRaises((ValueError, OSError)):
            self.collect()

    def test_nested_directory_symlink_and_special_file_are_rejected(self):
        directory = self.root / self.source["embedded_packages"]["packages"][0]["path"] / "src"
        moved = self.fixture.root / "moved-src"
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink or special"):
            self.collect()
        directory.unlink()
        moved.rename(directory)
        if hasattr(os, "mkfifo"):
            fifo = directory / "lib.rs"
            fifo.unlink()
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "symlink or special"):
                self.collect()

    def test_materialized_files_missing_extra_or_tampered_fail_closed(self):
        target = self.root / self.source["embedded_packages"]["packages"][0]["path"] / "src/lib.rs"
        original = target.read_bytes()
        for payload in (None, b"tampered\n"):
            with self.subTest(payload=payload):
                if payload is None:
                    target.unlink()
                else:
                    target.write_bytes(payload)
                with self.assertRaises(ValueError):
                    self.collect()
                target.write_bytes(original)
        for relative in ("mizaru-client/extra.rs", "unreviewed/Cargo.toml"):
            extra = self.root / "slipstream-vendor" / relative
            extra.parent.mkdir(exist_ok=True)
            extra.write_text("extra")
            with self.assertRaisesRegex(ValueError, "file set"):
                self.collect()
            extra.unlink()

    def test_materialized_root_manifest_edges_and_lock_must_match(self):
        for name in ("Cargo.toml", "Cargo.lock"):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original.replace(b"mizaru2-slipstream-client", b"unreviewed-client"))
            with self.assertRaises(ValueError):
                self.collect()
            path.write_bytes(original)

    def test_root_manifest_uses_final_hash_of_multiple_reviewed_edits(self):
        path = self.root / "Cargo.toml"
        original = path.read_text()
        middle, final = original + "# first\n", original + "# first\n# second\n"
        self.source["source_edits"] = [
            {"path": "Cargo.toml", "before": before, "after": after,
             "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
             "after_sha256": hashlib.sha256(after.encode()).hexdigest()}
            for before, after in ((original, middle), (middle, final))
        ]
        path.write_text(final)
        self.assertEqual(len(self.collect()), 2)
        path.write_text(middle)
        with self.assertRaisesRegex(ValueError, "final reviewed edit"):
            self.collect()

    def test_metadata_identity_path_source_and_target_disagreement_are_rejected(self):
        path = self.metadata[1][1]
        original = path.read_text()
        for field, value in (("manifest_path", "/tmp/foreign/Cargo.toml"), ("manifest_path", str(self.root / "slipstream-vendor/mizaru-client/../mizaru-client/Cargo.toml")), ("source", "registry+https://github.com/rust-lang/crates.io-index"), ("version", "9.0.0"), ("license", "GPL-3.0-only")):
            with self.subTest(field=field, value=value):
                metadata = json.loads(original)
                metadata["packages"][1][field] = value
                path.write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):
                    self.collect()
        path.write_text(original)
        with self.assertRaisesRegex(ValueError, "targets"):
            self.collect(cargo_metadata=list(reversed(self.metadata)))

    def test_missing_duplicate_and_unknown_local_metadata_packages_are_rejected(self):
        path = self.metadata[0][1]
        original = path.read_text()
        for mode in ("missing", "duplicate", "foreign", "duplicate-node"):
            metadata = json.loads(original)
            if mode == "missing":
                metadata["packages"].pop(1)
            elif mode == "duplicate":
                metadata["packages"].append(metadata["packages"][1])
            elif mode == "duplicate-node":
                metadata["resolve"]["nodes"].append(metadata["resolve"]["nodes"][1])
            else:
                metadata["packages"][-1]["source"] = None
            path.write_text(json.dumps(metadata))
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.collect()
        path.write_text(original)

    def test_unknown_git_registry_and_missing_checksum_remain_rejected(self):
        path = self.metadata[0][1]
        original = path.read_text()
        for field, value in (("source", "git+https://example.invalid/library"), ("source", "registry+https://example.invalid/index"), ("version", "2.0.0")):
            metadata = json.loads(original)
            metadata["packages"][-1][field] = value
            path.write_text(json.dumps(metadata))
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.collect()
        path.write_text(original)

    def test_verifier_binds_exact_source_owned_identity_content_and_relationships(self):
        original = self.document()
        for mode in ("package-removed", "package-duplicate", "file-removed", "file-extra", "file-hash", "purl", "checksum", "verification-code", "source-info", "relation-extra", "relation-missing", "foreign-source-package"):
            document = copy.deepcopy(original)
            owned = next(p for p in document["packages"] if p["SPDXID"].startswith("SPDXRef-Package-source-"))
            if mode == "package-removed": document["packages"].remove(owned)
            elif mode == "package-duplicate": document["packages"].append(owned)
            elif mode == "file-removed": document["files"].pop()
            elif mode == "file-extra": document["files"].append(document["files"][0])
            elif mode == "file-hash": document["files"][0]["checksums"][1]["checksumValue"] = "f" * 64
            elif mode == "purl": owned["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:cargo/geph5-broker-protocol@0.4.3"}]
            elif mode == "checksum": owned["checksums"] = [{"algorithm": "SHA256", "checksumValue": "a" * 64}]
            elif mode == "verification-code": owned["packageVerificationCode"]["packageVerificationCodeValue"] = "f" * 40
            elif mode == "source-info": owned["sourceInfo"] = "altered"
            elif mode == "relation-extra": document["relationships"].append(document["relationships"][0])
            elif mode == "relation-missing": document["relationships"].pop()
            else:
                document["packages"].append(dict(owned, SPDXID="SPDXRef-Package-source-unreviewed", name="foreign"))
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.verify(document)
        with self.assertRaisesRegex(ValueError, "SOURCE"):
            self.verify(original, source_sha256=None)
        with self.assertRaisesRegex(ValueError, "sourceInfo"):
            self.verify(original, source_sha256="f" * 64)


if __name__ == "__main__":
    unittest.main()

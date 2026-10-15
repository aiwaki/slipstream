"""Inventory contract tests with real verifiers over synthetic binary fixtures.

No verifier is mocked. These fixtures are not a production Geph build or release.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
from contextlib import redirect_stdout
import unittest
from unittest import mock

import geph_native_sqlite as native
import make_geph_vendor_sbom as sbom
import test_geph_native_sqlite_build as binary_fixture


class NativeSqliteSbomTests(unittest.TestCase):
    def setUp(self):
        wrapper = native.WRAPPER
        self.lock_bytes = (f'version = 3\n\n[[package]]\nname = "{wrapper["name"]}"\nversion = "{wrapper["version"]}"\n'
                           f'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "{wrapper["sha256"]}"\n').encode()
        self.source = {"schema_version": 1,
                       "crate": {"name": "geph5-client", "version": "0.4.3", "url": "https://static.crates.io/crates/geph5-client/geph5-client-0.4.3.crate", "sha256": "e" * 64},
                       "features": ["aws_lambda"], "targets": native.TARGETS[:], "lock_sha256": hashlib.sha256(self.lock_bytes).hexdigest(),
                       "release_revision": 1, "native_sqlite": binary_fixture.descriptor()}
        self.source_bytes = (json.dumps(self.source, sort_keys=True) + "\n").encode()
        self.source_sha = hashlib.sha256(self.source_bytes).hexdigest()
        case = binary_fixture.NativeBuildEvidenceTests()
        self.addCleanup(case.doCleanups)
        # Configure the fixture factory's input identities, not verification.
        with mock.patch.multiple(binary_fixture, SOURCE_SHA=self.source_sha, LOCK=self.lock_bytes, LOCK_SHA=self.source["lock_sha256"]):
            case.setUp()
            self.receipt = case.release()
        self.case = case
        self.root = case.root
        self.source_root = self.root / "source"
        for name, data in binary_fixture.source_contents().items():
            case.write(self.source_root / native.PATH / name, data)
        self.lock = case.write(self.source_root / "Cargo.lock", self.lock_bytes)
        root_id, wrapper_id = "geph-root", "sqlite-wrapper"
        metadata = {"packages": [{"id": root_id, "name": "geph5-client", "version": "0.4.3", "source": None},
                                 {"id": wrapper_id, "name": wrapper["name"], "version": wrapper["version"],
                                  "source": "registry+https://github.com/rust-lang/crates.io-index", "license": "MIT"}],
                    "resolve": {"root": root_id, "nodes": [
                        {"id": root_id, "dependencies": [wrapper_id], "deps": [{"pkg": wrapper_id, "dep_kinds": [{"kind": None, "target": None}]}]},
                        {"id": wrapper_id, "dependencies": [], "deps": []}]}}
        self.metadata = [(target, case.json(self.root / (target + "-sbom-metadata.json"), metadata)) for target in native.TARGETS]
        components = sbom.collect_components(cargo_lock=self.lock, cargo_metadata=self.metadata,
                                               expected_targets=native.TARGETS, source=self.source, source_root=self.source_root)
        self.component, = components
        self.args = dict(repository="aiwaki/slipstream", source_commit="a" * 40, source_date_epoch=1784159400,
                         target="macos-universal", source=self.source, source_sha256=self.source_sha,
                         source_root=self.source_root, cargo_lock=self.lock,
                         native_receipt=self.receipt, native_artifacts_root=self.root)

    def document(self, **override):
        return sbom.build_spdx_document(**(self.args | override), components=[self.component])

    def verify(self, document, **override):
        return sbom.validate_spdx_document(document, **(self.args | override))

    def test_distinct_native_inventory_and_genuine_wrapper_identity(self):
        doc = self.document()
        self.assertEqual(doc, self.document())
        self.assertEqual(self.verify(doc)["package_count"], 3)
        wrapper = next(item for item in doc["packages"] if item["name"] == "libsqlite3-sys")
        sqlite = next(item for item in doc["packages"] if item["name"] == "sqlite")
        self.assertEqual(wrapper["checksums"][0]["checksumValue"], native.WRAPPER["sha256"])
        self.assertNotIn("externalRefs", sqlite)
        self.assertEqual(sqlite["versionInfo"], "3.53.2")
        self.assertIn({"spdxElementId": wrapper["SPDXID"], "relationshipType": "STATIC_LINK", "relatedSpdxElement": sqlite["SPDXID"]}, doc["relationships"])
        identity = json.loads(sqlite["sourceInfo"])
        self.assertEqual(identity["source_sha256"], self.source_sha)
        self.assertEqual(identity["native_receipt_sha256"], hashlib.sha256(self.receipt.read_bytes()).hexdigest())
        self.assertIn(self.source_sha, doc["packages"][0]["sourceInfo"])
        self.assertEqual(len(doc["files"]), 2)

    def test_all_native_evidence_inputs_are_required(self):
        for field in ("source_sha256", "source_root", "cargo_lock", "native_receipt", "native_artifacts_root"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.document(**{field: None})

    def test_object_only_or_one_target_receipt_cannot_qualify_universal(self):
        for path in (self.case.native_paths[native.TARGETS[0]], self.case.linked_paths[native.TARGETS[0]]):
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                self.document(native_receipt=path)

    def test_native_spdx_tampering_is_rejected(self):
        original = self.document()
        mutations = [
            lambda d: d["packages"].pop(),
            lambda d: d["packages"][-1].update(versionInfo="3.46.0"),
            lambda d: d["packages"][-1].update(externalRefs=[{"referenceType": "purl", "referenceLocator": "pkg:cargo/sqlite@3.53.2"}]),
            lambda d: d["packages"][-1]["checksums"][0].update(checksumValue="0" * 64),
            lambda d: d["packages"][-1].update(sourceInfo="descriptor only"),
            lambda d: d["files"][0]["checksums"][1].update(checksumValue="f" * 64),
            lambda d: d.update(relationships=[r for r in d["relationships"] if r["relationshipType"] != "STATIC_LINK"]),
            lambda d: d["packages"][1]["checksums"][0].update(checksumValue=self.source["native_sqlite"]["archive"]["sha256"]),
        ]
        for change in mutations:
            with self.subTest(change=change):
                doc = copy.deepcopy(original)
                change(doc)
                with self.assertRaises(ValueError):
                    self.verify(doc)

    def test_changed_materialized_source_rejected_even_with_old_valid_receipt(self):
        doc = self.document()
        (self.source_root / native.PATH / "sqlite3.h").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "size/hash"):
            self.verify(doc)

    def test_wrong_raw_source_digest_and_materialized_lock_rejected(self):
        with self.assertRaisesRegex(ValueError, "input mismatch"):
            self.document(source_sha256="0" * 64)
        self.lock.write_bytes(self.lock_bytes + b"\n")
        with self.assertRaisesRegex(ValueError, "lock hash"):
            self.document()

    def test_changed_final_binary_cannot_pass_even_after_rehashing_receipt(self):
        value = json.loads(self.receipt.read_text())
        path = self.root / value["final_binary"]["path"]
        path.write_bytes(binary_fixture.fat({target: binary_fixture.macho(target, True, address=8192) for target in native.TARGETS}))
        value["final_binary"] = binary_fixture.build._record(self.root, path)
        self.case.json(self.receipt, value)
        with self.assertRaisesRegex(ValueError, "slice differs"):
            self.document()

    def test_cli_generate_verify_uses_same_required_materialized_and_universal_evidence(self):
        document_path = self.case.json(self.root / "sbom.json", self.document())
        source_path = self.case.write(self.root / "SOURCE.json", self.source_bytes)
        version_path = self.case.write(self.root / "VERSION", b"0.4.3\n")
        arguments = ["verify", "--source", str(source_path), "--version-file", str(version_path), "--cargo-lock", str(self.lock),
                     "--repository", "aiwaki/slipstream", "--source-commit", "a" * 40, "--source-root", str(self.source_root),
                     "--native-receipt", str(self.receipt), "--native-artifacts-root", str(self.root), "--sbom", str(document_path)]
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(sbom.main(arguments), 0)
        self.assertEqual(json.loads(output.getvalue())["package_count"], 3)
        generated = self.root / "generated.json"
        generation = ["generate", *arguments[1:-2], "--output", str(generated), "--source-date-epoch", "1784159400"]
        for target, path in self.metadata:
            generation.extend(["--cargo-metadata", f"{target}={path}"])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(sbom.main(generation), 0)
        self.assertEqual(json.loads(generated.read_text()), json.loads(document_path.read_text()))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
from datetime import date, timedelta
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import geph_source_owned_advisories as audit
import geph_vendor_source as vendor
import make_geph_vendor_sbom as sbom_module
import test_geph_embedded_source as embedded


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def archive_bytes(name, version, contents, extras=()):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for relative, payload in contents.items():
            entry = tarfile.TarInfo(f"{name}-{version}/{relative}")
            entry.size = len(payload)
            archive.addfile(entry, io.BytesIO(payload))
        for entry, payload in extras:
            archive.addfile(entry, io.BytesIO(payload))
    return stream.getvalue()


class SourceOwnedReviewFixture:
    """Reusable tiny real source/SPDX/review pipeline; all security reviews synthetic.

    Call SourceOwnedReviewFixture(physical_empty_directory), then .validate().
    Public inputs: source_path, lock_path, crate_path, version_path, source_commit,
    sbom, policy, evidence_root. .save_review() rebinds edited test reviews;
    .rebind_source() recreates SOURCE, exact SPDX and review binding without stubs.
    The caller owns directory cleanup. No compiler, network or scanner executes.
    """

    def __init__(self, root: Path, source_commit="a" * 40):
        self.root = Path(root).resolve()
        self.root.mkdir(exist_ok=True)
        self.source_commit = source_commit
        original = embedded.EmbeddedGephSourceTests()
        original.setUp()
        try:
            self.source = copy.deepcopy(original.contract)
            self.source_path = self.root / "SOURCE.json"
            self.lock_path = self.root / "Cargo.lock"
            self.crate_path = self.root / "geph.crate"
            self.version_path = self.root / "VERSION"
            for target, origin in ((self.lock_path, original.lock_path), (self.crate_path, original.crate_path), (self.version_path, original.version_path)):
                target.write_bytes(origin.read_bytes())
        finally:
            original.doCleanups()
        with self.lock_path.open("a") as stream:
            for package in self.source["embedded_packages"]["packages"]:
                stream.write(f'\n[[package]]\nname="{package["name"]}"\nversion="{package["version"]}"\n')
        self.source["lock_sha256"] = sha(self.lock_path.read_bytes())
        self.evidence_root = self.root / "review-evidence"
        self.evidence_root.mkdir()
        self.review = {"schema_version": 1, "binding": {}, "evidence": [], "ancestors": [], "osv_evidence": "ancestor-osv", "packages": []}
        self.raw = {"results": [{"source": {"type": "sbom", "path": "synthetic-ancestors.json"}, "packages": []}]}
        self.original_contents = {}
        self.policy = {"schema_version": 1, "source_sha256": "", "review_sha256": "", "expires": (date.today() + timedelta(days=7)).isoformat()}
        for index, package in enumerate(self.source["embedded_packages"]["packages"]):
            evidence_id = f"review-{index}"
            self.evidence(evidence_id, f"reviews/{index}.md", f"Synthetic source review for test package {index}; not a real security assessment.\n".encode(), "review")
            package_review = {"path": package["path"], "source_review": {"disposition": "reviewed", "files": sorted(f["path"] for f in package["files"]), "evidence": [evidence_id]}, "inherited_findings": [], "manual_findings": []}
            provenance = package["provenance"]
            if provenance["kind"] == "derivative":
                contents = {path: (next(f["content"].encode() for f in package["files"] if f["path"] == "provenance/Cargo.toml") if path == "Cargo.toml" else b"// synthetic retained upstream source\n") for path in provenance["original_files"]}
                self.original_contents[package["path"]] = contents
                self.replace_archive(package, contents)
                self.review["ancestors"].append({"name": provenance["name"], "version": provenance["version"], "archive_evidence": f"archive-{provenance['name']}"})
                vulnerability = {"id": f"RUSTSEC-TEST-{index}", "aliases": [f"CVE-TEST-{index}", f"GHSA-TEST-{index}"]}
                self.raw["results"][0]["packages"].append({"package": {"ecosystem": "crates.io", "name": provenance["name"], "version": provenance["version"]}, "vulnerabilities": [vulnerability]})
                package_review["inherited_findings"].append({**vulnerability, "disposition": "code_not_present", "evidence": [evidence_id]})
            self.review["packages"].append(package_review)
        self.save_raw()
        self.rebind_source()

    def evidence(self, identity, path, payload, kind):
        output = self.evidence_root / path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
        self.review["evidence"] = [entry for entry in self.review["evidence"] if entry["id"] != identity]
        self.review["evidence"].append({"id": identity, "path": path, "size": len(payload), "sha256": sha(payload), "kind": kind})

    def replace_archive(self, package, contents, extras=(), *, rebind_originals=True):
        provenance = package["provenance"]
        payload = archive_bytes(provenance["name"], provenance["version"], contents, extras)
        provenance["sha256"] = sha(payload)
        if rebind_originals:
            provenance["original_files"] = {path: sha(content) for path, content in contents.items()}
        self.evidence(f"archive-{provenance['name']}", f"archives/{provenance['name']}.crate", payload, "archive")

    def save_raw(self):
        self.evidence("ancestor-osv", "ancestors.osv.json", json.dumps(self.raw).encode(), "osv")

    def save_review(self):
        payload = json.dumps(self.review, sort_keys=True, ensure_ascii=False).encode()
        (self.evidence_root / "review.json").write_bytes(payload)
        self.policy["review_sha256"] = sha(payload)

    def rebind_source(self):
        for package in self.source["embedded_packages"]["packages"]:
            embedded.bind(package)
        payload = json.dumps(self.source, sort_keys=True, ensure_ascii=False).encode()
        self.source_path.write_bytes(payload)
        source_hash = sha(payload)
        self.policy["source_sha256"] = source_hash
        self.review["binding"] = {"source_sha256": source_hash, "lock_sha256": self.source["lock_sha256"], "packages": [
            {"path": p["path"], "descriptor_sha256": p["sha256"], "files": {f["path"]: f["sha256"] for f in p["files"]}}
            for p in sorted(self.source["embedded_packages"]["packages"], key=lambda p: p["path"])]}
        self.sbom = sbom_module.build_spdx_document(repository="aiwaki/slipstream", source_commit=self.source_commit, source_date_epoch=1784159400, target="macos-universal", source=self.source, source_sha256=source_hash, components=[])
        self.save_review()

    def validate(self, **kwargs):
        options = dict(sbom=self.sbom, source_path=self.source_path, evidence_root=self.evidence_root, evaluated_on=date.today(), source_commit=self.source_commit)
        options.update(kwargs)
        return audit.validate_source_owned_review(self.policy, **options)


class SourceOwnedAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = SourceOwnedReviewFixture(Path(self.temporary.name))
        self.f = self.fixture

    def test_exact_source_spdx_archive_and_review_roundtrip(self):
        first = self.f.validate()
        self.assertEqual(first, self.f.validate())
        self.assertEqual(first["status"], "pass")
        self.assertEqual(first["summary"], {"packages": 3, "unresolved": 0, "affected": 0})
        self.assertEqual(first["package_ids"], sorted(first["package_ids"]))
        self.assertEqual(len(first["package_ids"]), 3)
        self.assertEqual(first["binding"]["source_sha256"], sha(self.f.source_path.read_bytes()))
        root = vendor.materialize_source(source_path=self.f.source_path, version_path=self.f.version_path, cargo_lock_path=self.f.lock_path, crate_path=self.f.crate_path, output=self.f.root / "materialized")
        self.assertTrue((root / "slipstream-vendor/mizaru-client/LICENSE-ISC.txt").is_file())
        for package in first["packages"]:
            if package["ancestor"]:
                self.assertNotEqual(package["ancestor"]["name"], "mizaru2-slipstream-client")
                self.assertEqual(len(package["inherited_findings"][0]["aliases"]), 2)
            else:
                self.assertEqual(package["name"], "slipstream-rsa-client")
                self.assertEqual(package["inherited_findings"], [])

    def test_unknown_affected_and_firstparty_source_review_fail(self):
        self.f.review["packages"][0]["inherited_findings"][0]["disposition"] = "unknown"
        self.f.review["packages"][1]["source_review"]["disposition"] = "unresolved"
        self.f.review["packages"][1]["manual_findings"] = [{"id": "LOCAL-1", "disposition": "affected", "evidence": ["review-1"]}]
        self.f.save_review()
        result = self.f.validate()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["summary"], {"packages": 3, "unresolved": 2, "affected": 1})
        backend = next(p for p in result["packages"] if p["name"] == "slipstream-rsa-client")
        self.assertEqual(backend["manual_findings"][0]["id"], "LOCAL-1")

    def test_empty_vulnerability_lists_do_not_replace_explicit_source_review(self):
        for entry in self.f.raw["results"][0]["packages"]:
            entry["vulnerabilities"] = []
        for package in self.f.review["packages"]:
            package["inherited_findings"] = []
        self.f.save_raw()
        self.f.review["packages"][1]["source_review"]["disposition"] = "unresolved"
        self.f.save_review()
        self.assertEqual(self.f.validate()["status"], "fail")
        self.f.review["packages"][1]["source_review"]["disposition"] = "reviewed"
        self.f.save_review()
        self.assertEqual(self.f.validate()["status"], "pass")

    def test_policy_review_source_binding_and_expiry_fail_closed(self):
        original = copy.deepcopy(self.f.policy)
        for field, value in (("source_sha256", "f" * 64), ("review_sha256", "f" * 64), ("schema_version", True), ("expires", (date.today() - timedelta(days=4)).isoformat())):
            with self.subTest(field=field):
                self.f.policy = dict(original, **{field: value})
                with self.assertRaises(ValueError):
                    self.f.validate(evaluated_on=date.today() - timedelta(days=3))
        self.f.policy = original
        with self.assertRaises(ValueError):
            self.f.validate(evaluated_on=date.fromisoformat(original["expires"]) + timedelta(days=1))
        for key in ("source_sha256", "lock_sha256"):
            binding = copy.deepcopy(self.f.review["binding"])
            self.f.review["binding"][key] = "f" * 64
            self.f.save_review()
            with self.assertRaisesRegex(ValueError, "binding"):
                self.f.validate()
            self.f.review["binding"] = binding

    def test_spdx_owned_packages_files_and_contains_are_exact(self):
        original = copy.deepcopy(self.f.sbom)
        for mode in ("purl", "package-extra", "package-missing", "file-extra", "file-missing", "file-hash", "relation-extra", "relation-missing", "source-info", "commit"):
            self.f.sbom = copy.deepcopy(original)
            owned = next(p for p in self.f.sbom["packages"] if p["SPDXID"].startswith("SPDXRef-Package-source-"))
            if mode == "purl": owned["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:cargo/mizaru2@0.2.21"}]
            elif mode == "package-extra": self.f.sbom["packages"].append(dict(owned, SPDXID="SPDXRef-Package-source-extra"))
            elif mode == "package-missing": self.f.sbom["packages"].remove(owned)
            elif mode == "file-extra": self.f.sbom["files"].append(dict(self.f.sbom["files"][0], SPDXID="SPDXRef-File-extra"))
            elif mode == "file-missing": self.f.sbom["files"].pop()
            elif mode == "file-hash": self.f.sbom["files"][0]["checksums"][0]["checksumValue"] = "f" * 40
            elif mode == "relation-extra": self.f.sbom["relationships"].append(next(r for r in self.f.sbom["relationships"] if r["spdxElementId"] == owned["SPDXID"]))
            elif mode == "relation-missing": self.f.sbom["relationships"] = [r for r in self.f.sbom["relationships"] if r["spdxElementId"] != owned["SPDXID"]]
            elif mode == "source-info": owned["sourceInfo"] = "{}"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.f.validate(source_commit="b" * 40 if mode == "commit" else self.f.source_commit)

    def test_original_archive_bytes_and_source_are_independently_verified(self):
        package = self.f.source["embedded_packages"]["packages"][0]
        contents = dict(self.f.original_contents[package["path"]])
        contents["src/lib.rs"] = b"// changed upstream body\n"
        self.f.replace_archive(package, contents, rebind_originals=False)
        self.f.rebind_source()
        with self.assertRaisesRegex(ValueError, "original source hash"):
            self.f.validate()

    def test_ancestor_archive_hash_and_retained_original_manifest_are_independent(self):
        package = self.f.source["embedded_packages"]["packages"][0]
        provenance = package["provenance"]
        archive_hash = provenance["sha256"]
        provenance["sha256"] = "f" * 64
        self.f.rebind_source()
        with self.assertRaisesRegex(ValueError, "archive differs from provenance"):
            self.f.validate()
        provenance["sha256"] = archive_hash
        original = next(f for f in package["files"] if f["path"] == "provenance/Cargo.toml")
        original["content"] += 'authors=["Invented Author"]\n'
        provenance["original_files"]["Cargo.toml"] = sha(original["content"].encode())
        self.f.rebind_source()
        with self.assertRaisesRegex(ValueError, "original source hash"):
            self.f.validate()

    def test_spdx_package_file_id_collision_is_rejected(self):
        self.f.sbom["packages"].append({"SPDXID": self.f.sbom["files"][0]["SPDXID"], "name": "unrelated-registry"})
        with self.assertRaisesRegex(ValueError, "IDs overlap"):
            self.f.validate()

    def test_missing_original_manifest_and_archive_identity_are_rejected(self):
        package = self.f.source["embedded_packages"]["packages"][0]
        contents = dict(self.f.original_contents[package["path"]])
        del contents["Cargo.toml"]
        self.f.replace_archive(package, contents, rebind_originals=False)
        self.f.rebind_source()
        with self.assertRaisesRegex(ValueError, "original file inventory"):
            self.f.validate()

    def test_tar_traversal_symlink_duplicate_and_special_members_are_rejected(self):
        package = self.f.source["embedded_packages"]["packages"][0]
        for mode in ("traversal", "symlink", "duplicate", "fifo", "noncanonical"):
            info = tarfile.TarInfo("mizaru2-0.2.21/../escape" if mode == "traversal" else "mizaru2-0.2.21/extra")
            if mode == "symlink": info.type, info.linkname = tarfile.SYMTYPE, "/outside"
            elif mode == "duplicate": info.name = "mizaru2-0.2.21/Cargo.toml"
            elif mode == "fifo": info.type = tarfile.FIFOTYPE
            elif mode == "noncanonical": info.name = "mizaru2-0.2.21/./extra"
            self.f.replace_archive(package, self.f.original_contents[package["path"]], [(info, b"")])
            self.f.rebind_source()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.f.validate()

    def test_osv_two_ancestor_identity_inventory_cannot_be_suppressed(self):
        original = copy.deepcopy(self.f.raw)
        for mode in ("empty", "missing", "duplicate", "wrong-version", "local-name", "wrong-ecosystem", "error"):
            self.f.raw = copy.deepcopy(original)
            packages = self.f.raw["results"][0]["packages"]
            if mode == "empty": self.f.raw["results"] = []
            elif mode == "missing": packages.pop()
            elif mode == "duplicate": self.f.raw["results"].append(copy.deepcopy(self.f.raw["results"][0]))
            elif mode == "wrong-version": packages[0]["package"]["version"] = "99.0.0"
            elif mode == "local-name": packages[0]["package"]["name"] = "mizaru2-slipstream-client"
            elif mode == "wrong-ecosystem": packages[0]["package"]["ecosystem"] = "PyPI"
            else: self.f.raw["errors"] = ["scan incomplete"]
            self.f.save_raw()
            self.f.save_review()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.f.validate()

    def test_inherited_ids_aliases_and_ancestor_assignment_are_exact(self):
        original = copy.deepcopy(self.f.review)
        for mode in ("missing", "extra", "alias-missing", "alias-extra", "wrong-ancestor", "duplicate", "bad-disposition"):
            self.f.review = copy.deepcopy(original)
            findings = self.f.review["packages"][0]["inherited_findings"]
            if mode == "missing": findings.clear()
            elif mode == "extra": findings.append(dict(findings[0], id="unknown"))
            elif mode == "alias-missing": findings[0]["aliases"].pop()
            elif mode == "alias-extra": findings[0]["aliases"].append("CVE-FABRICATED")
            elif mode == "wrong-ancestor": self.f.review["packages"][0]["inherited_findings"] = copy.deepcopy(self.f.review["packages"][2]["inherited_findings"])
            elif mode == "duplicate": findings.append(copy.deepcopy(findings[0]))
            else: findings[0]["disposition"] = "excluded"
            self.f.save_review()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.f.validate()

    def test_all_source_paths_packages_and_review_evidence_are_required(self):
        original = copy.deepcopy(self.f.review)
        for mode in ("missing-package", "duplicate-package", "notice-unreviewed", "source-unreviewed", "duplicate-file", "empty-proof", "osv-as-proof", "ancestor-missing"):
            self.f.review = copy.deepcopy(original)
            package = self.f.review["packages"][0]
            if mode == "missing-package": self.f.review["packages"].pop()
            elif mode == "duplicate-package": self.f.review["packages"][1] = copy.deepcopy(package)
            elif mode == "notice-unreviewed": package["source_review"]["files"].remove("SOURCE-NOTICE.md")
            elif mode == "source-unreviewed": package["source_review"]["files"].remove("src/lib.rs")
            elif mode == "duplicate-file": package["source_review"]["files"].append("src/lib.rs")
            elif mode == "empty-proof": package["source_review"]["evidence"] = []
            elif mode == "osv-as-proof": package["source_review"]["evidence"] = ["ancestor-osv"]
            else: self.f.review["ancestors"].pop()
            self.f.save_review()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.f.validate()

    def test_catalog_traversal_duplicates_sizes_and_hashes_are_rejected(self):
        original = copy.deepcopy(self.f.review)
        for mode in ("traversal", "absolute", "duplicate-path", "duplicate-id", "review-path", "reserved-id", "size", "hash", "unreferenced"):
            self.f.review = copy.deepcopy(original)
            entries = self.f.review["evidence"]
            if mode == "traversal": entries[0]["path"] = "../outside"
            elif mode == "absolute": entries[0]["path"] = "/tmp/outside"
            elif mode == "duplicate-path": entries[1]["path"] = entries[0]["path"]
            elif mode == "duplicate-id": entries[1]["id"] = entries[0]["id"]
            elif mode == "review-path": entries[0]["path"] = "review.json"
            elif mode == "reserved-id": entries[0]["id"] = "review.json"
            elif mode == "size": entries[0]["size"] = audit.MAX_EVIDENCE_BYTES + 1
            elif mode == "hash": entries[0]["sha256"] = "f" * 64
            else: self.f.evidence("unused", "unused.md", b"not selected", "review")
            self.f.save_review()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.f.validate()

    def test_physical_files_reject_symlinks_and_fifo(self):
        linked_root = self.f.root / "linked-evidence"
        linked_root.symlink_to(self.f.evidence_root, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.f.validate(evidence_root=linked_root)
        path = self.f.evidence_root / "reviews/0.md"
        original = path.read_bytes()
        outside = self.f.root / "outside.md"
        outside.write_bytes(original)
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises((ValueError, OSError)):
            self.f.validate()
        path.unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                self.f.validate()

    def test_duplicate_and_nonfinite_json_are_rejected_even_when_hash_bound(self):
        original = (self.f.evidence_root / "review.json").read_bytes()
        for suffix in (b',"schema_version":1}', b',"extra":NaN}'):
            payload = original[:-1] + suffix
            (self.f.evidence_root / "review.json").write_bytes(payload)
            self.f.policy["review_sha256"] = sha(payload)
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.f.validate()

    def test_retention_rejects_wrong_policy_before_creating_output(self):
        self.f.policy["review_sha256"] = "f" * 64
        destination = self.f.root / "retained"
        with self.assertRaisesRegex(ValueError, "review SHA256"):
            audit.retain_source_owned_review_evidence(self.f.policy, self.f.evidence_root, destination)
        self.assertFalse(destination.exists())

    def test_retention_rechecks_hashes_and_copies_only_verified_snapshot(self):
        (self.f.evidence_root / "unlisted-private-file").write_text("must not be copied")
        expected = self.f.validate()
        destination = self.f.root / "retained"
        result = audit.retain_source_owned_review_evidence(self.f.policy, self.f.evidence_root, destination)
        self.assertEqual(result, {"root": str(destination), "review_sha256": self.f.policy["review_sha256"]})
        self.assertFalse((destination / "unlisted-private-file").exists())
        self.assertEqual(expected, self.f.validate(evidence_root=destination))
        with self.assertRaises(FileExistsError):
            audit.retain_source_owned_review_evidence(self.f.policy, self.f.evidence_root, destination)
        (self.f.evidence_root / "reviews/0.md").write_text("tampered")
        with self.assertRaises(ValueError):
            audit.retain_source_owned_review_evidence(self.f.policy, self.f.evidence_root, self.f.root / "rejected")
        self.assertFalse((self.f.root / "rejected").exists())

    def test_retention_does_not_reopen_original_after_verified_snapshot(self):
        original_read = audit.read_snapshot
        original = (self.f.evidence_root / "ancestors.osv.json").read_bytes()
        def read(path, limit):
            payload = original_read(path, limit)
            if Path(path) == self.f.evidence_root / "ancestors.osv.json":
                Path(path).write_bytes(b"changed after the verified read")
            return payload
        destination = self.f.root / "retained"
        with mock.patch.object(audit, "read_snapshot", side_effect=read):
            audit.retain_source_owned_review_evidence(self.f.policy, self.f.evidence_root, destination)
        self.assertEqual((destination / "ancestors.osv.json").read_bytes(), original)
        self.assertEqual(self.f.validate(evidence_root=destination)["status"], "pass")


if __name__ == "__main__":
    unittest.main()

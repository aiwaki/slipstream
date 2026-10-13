from __future__ import annotations

import copy
from datetime import date, timedelta
import json
import os
from pathlib import Path
import unittest
from unittest import mock

import geph_native_sqlite as native
import geph_native_sqlite_advisories as audit
import geph_native_sqlite_build as build
import make_geph_vendor_sbom as sbom_module
import test_geph_native_sqlite_build as fixtures


class NativeAdvisoryTests(unittest.TestCase):
    """Tiny genuine linkage fixtures, never a compiler/network/scanner process."""

    def setUp(self):
        self.fixture = fixtures.NativeBuildEvidenceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.source_root = self.root / "source"
        self.source_root.mkdir()
        lock = ('version = 3\n[[package]]\nname="libsqlite3-sys"\nversion="0.30.1"\n'
                'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                f'checksum="{native.WRAPPER["sha256"]}"\n').encode()
        self.lock = self.fixture.write(self.source_root / "Cargo.lock", lock)
        for name, payload in fixtures.source_contents().items():
            self.fixture.write(self.source_root / native.PATH / name, payload)
        self.contract = {"schema_version": 1, "crate": {"name": "geph5-client", "version": "0.4.3",
            "url": "https://static.crates.io/crates/geph5-client/geph5-client-0.4.3.crate", "sha256": "a" * 64},
            "lock_sha256": build.sha(lock), "features": ["aws_lambda"], "targets": native.TARGETS[:],
            "release_revision": 1, "native_sqlite": self.fixture.descriptor}
        self.source = self.fixture.json(self.root / "SOURCE.json", self.contract)
        source_hash = build.sha(self.source.read_bytes())
        with mock.patch.object(fixtures, "SOURCE_SHA", source_hash), mock.patch.object(fixtures, "LOCK_SHA", build.sha(lock)):
            for target in native.TARGETS:
                self.fixture.make_native(target)
                self.fixture.linked_paths[target].unlink()
                self.fixture.make_linked(target)
            self.receipt = self.fixture.release()
        descriptor = self.contract["native_sqlite"]
        proof = build.verify_release_evidence(descriptor, self.receipt, self.root, source_hash, self.contract["lock_sha256"])
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        wrapper = audit._cargo_registry_component({"name": "libsqlite3-sys", "version": "0.30.1", "source": registry},
            {("libsqlite3-sys", "0.30.1", registry): native.WRAPPER["sha256"]})
        packages = [sbom_module._component_package(wrapper), {"SPDXID": sbom_module.ROOT_SPDX_ID, "name": "geph5-client", "versionInfo": "0.4.3"}]
        native_packages, files, relationships = sbom_module._native_inventory(
            self.contract, packages, source_hash, source_root=self.source_root, cargo_lock=self.lock,
            native_receipt=self.receipt, native_artifacts_root=self.root)
        self.package_id = native_packages[0]["SPDXID"]
        relationships.append({"spdxElementId": sbom_module.ROOT_SPDX_ID, "relationshipType": "CONTAINS", "relatedSpdxElement": self.package_id})
        self.sbom = {"packages": packages + native_packages, "files": files, "relationships": relationships}
        self.review = {"schema_version": 1, "expires": "2026-10-14", "binding": {
            "source_sha256": source_hash, "descriptor_sha256": native.descriptor_sha256(descriptor),
            "version": descriptor["version"], "source_id": descriptor["source_id"],
            "archive_sha256": descriptor["archive"]["sha256"],
            "files": {i["path"]: i["sha256"] for i in descriptor["files"]},
            "targets": descriptor["targets"], "compile_definitions": descriptor["compile_definitions"],
            "native_receipt_sha256": proof["receipt_sha256"], "final_binary_sha256": proof["final_binary_sha256"]},
            "census": {"publication_cutoff": "2026-10-13T10:05:31Z", "census_ref": "census", "aliases_ref": "aliases", "receipt_ref": "receipt"},
            "evidence": [], "groups": []}
        self.evidence = self.root / "advisory-evidence"
        self.evidence.mkdir()
        for identity, role, target in (("primary", "primary", None), ("source", "exact_source", None),
                ("positive", "positive_control", None), ("arm", "target_exclusion", native.TARGETS[0]),
                ("intel", "target_exclusion", native.TARGETS[1])):
            self.add_evidence(identity, role, b"retained reviewed evidence\n", target)
        specs = [
            ("CVE-2026-1001", "native", "unknown", "code_fixed", "adjudicated", ["primary", "source"]),
            ("CVE-2026-1002", "native", "unknown", "code_not_present", "adjudicated", ["positive", "arm", "intel"]),
            ("CVE-2026-1003", "native", "unknown", "unknown", "census_only", ["census"]),
            ("CVE-2026-1004", "native", "cna_rejected_record", "rejected", "census_only", ["census"]),
            ("CVE-2026-1005", "excluded", "outside_native_component_scope", "excluded", "adjudicated", ["census"]),
        ]
        for identity, scope, old, decision, status, refs in specs:
            self.review["groups"].append({"id": identity, "aliases": [identity], "identity": scope,
                "census_verdict": old, "decision": decision, "review_status": status,
                "source_verdict": "source_not_fixed" if decision == "code_not_present" else old,
                "rationale": "Exact retained review, not a version/range inference.", "evidence": refs,
                "conflicts": [], "conflicts_resolved": False})
        self.seal_census()

    def add_evidence(self, identity, role, payload, target=None):
        path = identity + ".json"
        self.fixture.write(self.evidence / path, payload)
        record = {"id": identity, "path": path, "size": len(payload), "sha256": build.sha(payload), "role": role, "target": target}
        self.review["evidence"].append(record)

    def seal_census(self):
        groups = self.review["groups"]
        rows = [{"id": g["id"], "alias_group": g["id"], "identity_class": "other_product" if g["identity"] == "excluded" else "upstream_sqlite_candidate",
                 "exact_3_53_2_source_verdict": g["census_verdict"], "observations": g["conflicts"]} for g in groups]
        census = audit.canonical({"scope": {"publication_cutoff": self.review["census"]["publication_cutoff"]}, "records": rows})
        aliases = audit.canonical({"groups": [{"key": g["id"], "ids": g["aliases"], "census_cve_ids": [g["id"]],
                    "native_or_ambiguous_ids": [g["id"]] if g["identity"] == "native" else []} for g in groups]})
        receipt = audit.canonical({"bindings": [{"path": "retained/" + name, "bytes": len(payload), "sha256": build.sha(payload)}
                    for name, payload in (("census.json", census), ("aliases.json", aliases))]})
        self.review["evidence"] = [e for e in self.review["evidence"] if e["id"] not in {"census", "aliases", "receipt"}]
        for identity, payload in (("census", census), ("aliases", aliases), ("receipt", receipt)):
            self.add_evidence(identity, identity, payload)
        self.review["census"].update(groups_total=len(groups), native_groups=sum(g["identity"] == "native" for g in groups),
                                     groups_sha256=audit.group_identity_sha256(groups))

    def validate(self, *, review=None, sbom=None, source=None, evidence=True, **kwargs):
        options = {"evaluated_on": date(2026, 10, 13), "verification_on": date(2026, 10, 13)}
        options.update(kwargs)
        return audit.validate_native_review(self.review if review is None else review,
            sbom=self.sbom if sbom is None else sbom, source_path=source or self.source,
            native_receipt=self.receipt, native_artifacts_root=self.root,
            evidence_root=self.evidence if evidence else None, **options)

    def test_incomplete_review_is_fail_with_distinct_unknown_and_census_only(self):
        result = self.validate()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["package_id"], self.package_id)
        self.assertEqual(result["summary"], {"groups_total": 5, "native_groups": 4, "excluded_groups": 1,
            "adjudicated_not_affected": 2, "unknown": 1, "affected": 0, "census_only": 1, "unresolved": 2})
        self.assertEqual(result["decisions"][1]["source_verdict"], "source_not_fixed")

    def test_consumer_reconstructs_identical_result_without_advisory_files(self):
        expected = self.validate()
        self.assertEqual(self.validate(evidence=False), expected)

    def test_all_explicit_adjudications_can_pass_without_registry_waiver(self):
        for group in self.review["groups"][2:4]:
            group.update(decision="rejected", review_status="adjudicated", evidence=["primary"])
        result = self.validate()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["summary"]["unresolved"], 0)

    def test_affected_is_fail_and_never_renamed_unknown(self):
        self.review["groups"][2]["decision"] = "affected"
        result = self.validate()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["summary"]["affected"], 1)
        self.assertEqual(result["summary"]["unknown"], 0)

    def test_backdated_report_does_not_extend_expired_review(self):
        with self.assertRaisesRegex(ValueError, "expired"):
            self.validate(verification_on=date(2026, 10, 15))
        with self.assertRaises(ValueError):
            self.validate(evaluated_on=date(2026, 10, 12))

    def test_group_omission_duplicate_alias_collision_extra_and_stale_digest_reject(self):
        mutations = [lambda r: r["groups"].pop(), lambda r: r["groups"].append(copy.deepcopy(r["groups"][0])),
            lambda r: r["groups"][1]["aliases"].append(r["groups"][0]["id"]),
            lambda r: r["groups"][0]["aliases"].append("GHSA-new"), lambda r: r["census"].update(groups_total=6)]
        for mutate in mutations:
            review = copy.deepcopy(self.review); mutate(review)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.validate(review=review)

    def test_structurally_rehashed_policy_still_cannot_omit_retained_census_group(self):
        self.review["groups"].pop()
        self.review["census"]["groups_total"] -= 1
        self.review["census"]["groups_sha256"] = audit.group_identity_sha256(self.review["groups"])
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.validate()

    def test_alias_group_key_may_differ_from_single_census_cve(self):
        group = self.review["groups"][-1]
        row_id = group["id"]
        group["id"] = "CVE-2026-1000"
        group["aliases"] = sorted([group["id"], row_id])
        self.seal_census()
        census = json.loads((self.evidence / "census.json").read_bytes())
        census["records"][-1]["id"] = row_id
        aliases = json.loads((self.evidence / "aliases.json").read_bytes())
        aliases["groups"][-1]["census_cve_ids"] = [row_id]
        records = {i["id"]: i for i in self.review["evidence"]}
        for identity, value in (("census", census), ("aliases", aliases)):
            payload = audit.canonical(value)
            (self.evidence / records[identity]["path"]).write_bytes(payload)
            records[identity].update(size=len(payload), sha256=build.sha(payload))
        receipt = {"bindings": [{"bytes": records[k]["size"], "sha256": records[k]["sha256"]} for k in ("census", "aliases")]}
        payload = audit.canonical(receipt)
        (self.evidence / "receipt.json").write_bytes(payload)
        records["receipt"].update(size=len(payload), sha256=build.sha(payload))
        self.assertEqual(self.validate()["summary"]["excluded_groups"], 1)

    def test_identity_or_binary_binding_mismatch_rejects(self):
        for key in ("source_sha256", "descriptor_sha256", "source_id", "native_receipt_sha256", "final_binary_sha256", "targets", "compile_definitions"):
            review = copy.deepcopy(self.review); review["binding"][key] = "wrong"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "binding differs"):
                self.validate(review=review)

    def test_real_link_proof_tamper_rejects_before_clearance(self):
        binary = self.root / "geph-universal"
        binary.write_bytes(binary.read_bytes() + b"changed")
        with self.assertRaises(ValueError):
            self.validate()

    def test_source_duplicate_keys_and_symlink_reject(self):
        data = self.source.read_bytes()
        self.source.write_bytes(data.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1', 1))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.validate()
        self.source.write_bytes(data)
        alias = self.root / "SOURCE-alias.json"; alias.symlink_to(self.source)
        with self.assertRaises((ValueError, OSError)):
            self.validate(source=alias)

    def test_native_spdx_mutations_reject(self):
        changes = [lambda s: s["packages"][-1].update(name="wrapper"),
            lambda s: s["packages"][-1].update(sourceInfo="{}"),
            lambda s: s["packages"][-1].update(externalRefs=[]),
            lambda s: s["packages"][-1]["checksums"][0].update(checksumValue="0" * 64),
            lambda s: s["packages"][0]["externalRefs"][0].update(referenceLocator="pkg:cargo/wrong@0.30.1"),
            lambda s: s["files"][0]["checksums"][1].update(checksumValue="0" * 64),
            lambda s: s["relationships"].pop(),
            lambda s: s["relationships"].append(copy.deepcopy(s["relationships"][0]))]
        for change in changes:
            sbom = copy.deepcopy(self.sbom); change(sbom)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(sbom=sbom)

    def test_roles_need_exact_fix_or_positive_and_two_target_evidence(self):
        for index, refs in ((0, ["primary"]), (1, ["positive", "arm"]), (1, ["arm", "intel"])):
            review = copy.deepcopy(self.review); review["groups"][index]["evidence"] = refs
            with self.subTest(index=index, refs=refs), self.assertRaises(ValueError):
                self.validate(review=review)

    def test_unresolved_alias_conflict_cannot_be_adjudicated_away(self):
        group = self.review["groups"][3]
        group.update(conflicts=["CNA rejected but OSV active"], decision="rejected", review_status="adjudicated", evidence=["primary"])
        self.seal_census()
        with self.assertRaisesRegex(ValueError, "conflict"):
            self.validate()
        group["conflicts_resolved"] = True
        self.assertEqual(self.validate()["summary"]["unresolved"], 1)

    def test_evidence_tamper_missing_and_duplicate_inventory_fail(self):
        original = (self.evidence / "primary.json").read_bytes()
        (self.evidence / "primary.json").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "reviewed bytes"):
            self.validate()
        (self.evidence / "primary.json").write_bytes(original)
        self.review["evidence"].append(copy.deepcopy(self.review["evidence"][0]))
        with self.assertRaisesRegex(ValueError, "duplicated"):
            self.validate()

    def test_malformed_schema_is_value_error_not_accidental_type_error(self):
        changes = [lambda r: r.update(extra=True), lambda r: r.update(expires=None),
            lambda r: r["evidence"][0].update(role={}), lambda r: r["groups"][0].update(conflicts=[{}]),
            lambda r: r["census"].update(census_ref=[]), lambda r: r.update(groups=[None]),
            lambda r: r["groups"][0].update(review_status=True)]
        for change in changes:
            review = copy.deepcopy(self.review); change(review)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(review=review)

    def test_retained_census_receipt_cannot_be_a_free_success_claim(self):
        record = next(x for x in self.review["evidence"] if x["id"] == "receipt")
        payload = audit.canonical({"bindings": [{"sha256": "0" * 64, "bytes": 1}], "status": "pass"})
        (self.evidence / record["path"]).write_bytes(payload)
        record.update(size=len(payload), sha256=build.sha(payload))
        with self.assertRaisesRegex(ValueError, "does not bind"):
            self.validate()

    def test_bounded_snapshot_preserves_existing_output_and_ignores_unlisted_input(self):
        (self.evidence / "unlisted").write_text("not copied")
        out = self.root / "snapshot"
        result = audit.retain_native_review_evidence(self.review, self.evidence, out)
        self.assertEqual(len(result["files"]), len(self.review["evidence"]))
        self.assertFalse((out / "unlisted").exists())
        before = (out / "primary.json").read_bytes()
        with self.assertRaises(FileExistsError):
            audit.retain_native_review_evidence(self.review, self.evidence, out)
        self.assertEqual((out / "primary.json").read_bytes(), before)

    def test_snapshot_output_extra_entry_is_rejected_without_touching_it(self):
        out = self.root / "snapshot-extra"
        original = audit._snapshot_inventory
        def inject(fd, records):
            (out / "unexpected").write_text("retained")
            return original(fd, records)
        with mock.patch.object(audit, "_snapshot_inventory", side_effect=inject), self.assertRaisesRegex(ValueError, "unexpected"):
            audit.retain_native_review_evidence(self.review, self.evidence, out)
        self.assertEqual((out / "unexpected").read_text(), "retained")

    def test_bad_evidence_paths_symlink_fifo_and_size_bound_reject(self):
        for path in ("../escape", "/absolute", "a//b", "a/./b", "a\\b"):
            review = copy.deepcopy(self.review); review["evidence"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                audit.retain_native_review_evidence(review, self.evidence, self.root / "never-created")
        self.assertFalse((self.root / "never-created").exists())
        path = self.evidence / "primary.json"; original = path.read_bytes(); path.unlink()
        path.symlink_to(self.source)
        with self.assertRaises((OSError, ValueError)):
            self.validate()
        path.unlink(); os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "regular"):
            self.validate()
        path.unlink(); path.write_bytes(original)
        self.review["evidence"][0]["size"] = audit.MAX_EVIDENCE_BYTES + 1
        with self.assertRaisesRegex(ValueError, "size"):
            self.validate()


if __name__ == "__main__":
    unittest.main()

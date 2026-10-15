"""Transport checks over tiny real catalogs; fixture reviews are synthetic."""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
from datetime import date, timedelta
import gzip
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import geph_source_owned_bundle as bundle
from test_geph_source_owned_advisories import SourceOwnedReviewFixture


class SourceOwnedBundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.case = SourceOwnedReviewFixture(self.root)
        self.archive = self.root / bundle.BUNDLE_NAME
        self.output = self.root / "unpacked"

    def pack(self, **kwargs):
        return bundle.pack_bundle(**(dict(evidence_root=self.case.evidence_root,
            output_path=self.archive, policy_entry=self.case.policy) | kwargs))

    def unpack(self, **kwargs):
        return bundle.unpack_bundle(**(dict(bundle_path=self.archive,
            output_root=self.output, policy_entry=self.case.policy) | kwargs))

    def rewrite(self, mutate):
        files = bundle._decode(self.archive.read_bytes())
        files.pop(bundle.MANIFEST)
        mutate(files)
        self.archive.write_bytes(bundle._encode(files | {
            bundle.MANIFEST: bundle._manifest(files, self.case.policy)}))

    def test_deterministic_roundtrip_and_semantic_consumer(self):
        packed = self.pack()
        second = self.root / "second.tar"
        self.pack(output_path=second)
        self.assertEqual(self.archive.read_bytes(), second.read_bytes())
        result = self.unpack()
        self.assertEqual(result["bundle_sha256"], packed["bundle_sha256"])
        self.assertEqual(result["root"], str(self.output))
        self.assertEqual(result["source_sha256"], self.case.policy["source_sha256"])
        self.assertEqual(result["review_sha256"], self.case.policy["review_sha256"])
        self.assertEqual(result["file_count"], len(self.case.review["evidence"]) + 1)
        self.assertEqual(self.case.validate(evidence_root=self.output)["status"], "pass")

    def test_transport_does_not_claim_security_semantics(self):
        self.case.review["packages"][0]["source_review"]["disposition"] = "unresolved"
        self.case.save_review()
        self.pack()
        result = self.unpack()
        self.assertNotIn("status", result)
        self.assertEqual(self.case.validate(evidence_root=self.output)["status"], "fail")

    def test_cli_reads_full_trusted_audit_policy(self):
        policy = self.root / "audit-policy.json"
        policy.write_text(json.dumps({"source_owned_review": self.case.policy}))
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(bundle.main(["pack", "--policy", str(policy),
                "--evidence-root", str(self.case.evidence_root), "--output", str(self.archive)]), 0)
            self.assertEqual(bundle.main(["unpack", "--policy", str(policy),
                "--bundle", str(self.archive), "--output", str(self.output)]), 0)
        self.assertEqual(len(output.getvalue().splitlines()), 2)
        policy.write_text(json.dumps(self.case.policy))
        with self.assertRaises(ValueError):
            bundle.read_policy(policy)

    def test_wrong_policy_pins_and_expired_policy_rejected(self):
        self.pack()
        for key, value in (("source_sha256", "0" * 64), ("review_sha256", "0" * 64),
                           ("expires", (date.today() - timedelta(days=1)).isoformat())):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.unpack(policy_entry=self.case.policy | {key: value})
        self.assertFalse(self.output.exists())

    def test_source_binding_cannot_be_relabelled(self):
        self.case.review["binding"]["source_sha256"] = "0" * 64
        self.case.save_review()
        with self.assertRaisesRegex(ValueError, "SOURCE binding"):
            self.pack()

    def test_exact_catalog_rejects_changed_missing_extra_members(self):
        self.pack()
        original = self.archive.read_bytes()
        for mutate in (lambda files: files.update({"extra.txt": b"extra"}),
                       lambda files: files.pop("reviews/0.md"),
                       lambda files: files.update({"reviews/0.md": b"changed"})):
            with self.subTest(mutate=mutate):
                self.archive.write_bytes(original)
                self.rewrite(mutate)
                with self.assertRaises((OSError, ValueError)):
                    self.unpack()
                self.assertFalse(self.output.exists())

    def test_manifest_cannot_be_missing_changed_or_self_selected(self):
        self.pack()
        files = bundle._decode(self.archive.read_bytes())
        for payload in (b"{}", bundle._manifest({k: v for k, v in files.items() if k != bundle.MANIFEST},
                        self.case.policy | {"source_sha256": "0" * 64})):
            self.archive.write_bytes(bundle._encode(files | {bundle.MANIFEST: payload}))
            with self.assertRaises(ValueError):
                self.unpack()
        files.pop(bundle.MANIFEST)
        self.archive.write_bytes(bundle._encode(files))
        with self.assertRaises(ValueError):
            self.unpack()

    def test_pack_rejects_extra_files_and_empty_directories(self):
        for name, directory in (("extra.txt", False), ("empty", True)):
            extra = self.case.evidence_root / name
            extra.mkdir() if directory else extra.write_bytes(b"extra")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.pack()
            extra.rmdir() if directory else extra.unlink()
        self.assertFalse(self.archive.exists())

    def test_pack_rejects_symlink_hardlink_and_changed_bytes(self):
        target = self.case.evidence_root / "reviews/0.md"
        saved = self.root / "original"
        saved.write_bytes(target.read_bytes())
        for kind in ("symlink", "hardlink", "changed"):
            target.unlink()
            if kind == "symlink":
                target.symlink_to(saved)
            elif kind == "hardlink":
                os.link(saved, target)
            else:
                target.write_bytes(b"different")
            with self.subTest(kind=kind), self.assertRaises((OSError, ValueError)):
                self.pack()

    def test_input_and_output_ancestors_must_be_physical(self):
        self.pack()
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for options in ({"bundle_path": alias / self.archive.name}, {"output_root": alias / "new"}):
            with self.subTest(options=options), self.assertRaises((OSError, ValueError)):
                self.unpack(**options)
        with self.assertRaises((OSError, ValueError)):
            self.pack(evidence_root=alias / self.case.evidence_root.name, output_path=self.root / "new.tar")

    def test_never_overwrites_archive_or_existing_destination(self):
        self.pack()
        original = self.archive.read_bytes()
        with self.assertRaises(FileExistsError):
            self.pack()
        self.assertEqual(self.archive.read_bytes(), original)
        self.output.mkdir()
        (self.output / "keep").write_bytes(b"user data")
        with self.assertRaises(FileExistsError):
            self.unpack()
        self.assertEqual((self.output / "keep").read_bytes(), b"user data")

    def test_rejects_compression_truncation_padding_and_duplicate_members(self):
        self.pack()
        original = self.archive.read_bytes()
        files = bundle._decode(original)
        name, data = next(iter(files.items()))
        entry = bundle._header(name, len(data)) + data + b"\0" * (-len(data) % 512)
        bad_padding = bytearray(entry)
        bad_padding[512 + len(data)] = 1
        malformed = [gzip.compress(original), original[:-512], original + bundle.ZERO_BLOCK,
                     bytes(bad_padding) + bundle.ZERO_BLOCK * 2,
                     entry * 2 + bundle.ZERO_BLOCK * 2]
        for payload in malformed:
            with self.subTest(length=len(payload)), self.assertRaises(ValueError):
                bundle._decode(payload)

    def test_rejects_unsafe_paths_links_devices_and_noncanonical_headers(self):
        for name in ("../outside", "/absolute", "a/../b", "a//b", "a\\b", "./file"):
            item = tarfile.TarInfo(name)
            item.size = 1
            item.mode = 0o644
            with self.subTest(name=name), self.assertRaises(ValueError):
                bundle._decode(item.tobuf(tarfile.USTAR_FORMAT) + b"x" + b"\0" * 511 + bundle.ZERO_BLOCK * 2)
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE, tarfile.XHDTYPE, tarfile.GNUTYPE_SPARSE):
            item = tarfile.TarInfo("member")
            item.type = kind
            item.linkname = "../outside"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                bundle._decode(item.tobuf(tarfile.USTAR_FORMAT) + bundle.ZERO_BLOCK * 2)
        item = tarfile.TarInfo("member")
        item.size, item.mtime, item.mode = 1, 7, 0o644
        with self.assertRaises(ValueError):
            bundle._decode(item.tobuf(tarfile.USTAR_FORMAT) + b"x" + b"\0" * 511 + bundle.ZERO_BLOCK * 2)

    def test_rejects_size_and_member_bounds_without_large_allocations(self):
        item = tarfile.TarInfo("large")
        item.mode, item.size = 0o644, bundle.review.MAX_EVIDENCE_BYTES + 1
        with self.assertRaises(ValueError):
            bundle._decode(item.tobuf(tarfile.USTAR_FORMAT) + bundle.ZERO_BLOCK * 2)
        payload = bundle._encode({"a": b"a", "b": b"b"})
        with mock.patch.object(bundle, "MAX_MEMBERS", 1), self.assertRaises(ValueError):
            bundle._decode(payload)
        self.pack()
        with mock.patch.object(bundle, "MAX_BUNDLE_BYTES", 512), self.assertRaises(ValueError):
            self.unpack()

    def test_catalog_rebinding_does_not_allow_paths_outside_root(self):
        for path in ("../outside", "/absolute", "review.json", "reviews/0.md/child", bundle.MANIFEST):
            original = copy.deepcopy(self.case.review)
            self.case.review["evidence"][0]["path"] = path
            self.case.save_review()
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                self.pack()
            self.case.review = original
            self.case.save_review()

    def test_changed_input_snapshot_is_detected(self):
        real_snapshot = bundle.review._bundle
        def change_after_read(*args, **kwargs):
            value = real_snapshot(*args, **kwargs)
            (self.case.evidence_root / "reviews/0.md").write_bytes(b"changed")
            return value
        with mock.patch.object(bundle.review, "_bundle", side_effect=change_after_read), self.assertRaises(ValueError):
            self.pack()
        self.assertFalse(self.archive.exists())

    def test_changed_unpacked_bytes_and_replaced_root_are_rejected_and_retained(self):
        self.pack()
        real_write = bundle.transport._mkdir_and_write
        for kind in ("bytes", "root"):
            destination = self.root / ("unpacked-" + kind)
            def change_after_write(root, files):
                identity = real_write(root, files)
                if root == destination:
                    if kind == "bytes":
                        (root / "reviews/0.md").write_bytes(b"changed")
                    else:
                        root.rename(self.root / "original-destination")
                        real_write(root, files)
                return identity
            with self.subTest(kind=kind), mock.patch.object(bundle.transport, "_mkdir_and_write", side_effect=change_after_write):
                with self.assertRaises(ValueError) as failure:
                    self.unpack(output_root=destination)
            self.assertTrue(destination.is_dir())
            self.assertIn("use a fresh destination", " ".join(failure.exception.__notes__))
        self.assertTrue((self.root / "original-destination").is_dir())

    def test_changed_published_archive_is_rejected(self):
        real_read = bundle.review.read_snapshot
        def change_before_read(path, limit):
            if path == self.archive:
                path.write_bytes(b"changed archive")
            return real_read(path, limit)
        with mock.patch.object(bundle.review, "read_snapshot", side_effect=change_before_read):
            with self.assertRaisesRegex(ValueError, "changed during publication"):
                self.pack()
        self.assertEqual(self.archive.read_bytes(), b"changed archive")


if __name__ == "__main__":
    unittest.main()

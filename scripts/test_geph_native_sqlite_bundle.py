"""Transport contracts with synthetic Mach-O inputs and the real link verifier.

No production Geph build, account, network or installed-app claim is made.
"""
from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import geph_native_sqlite as native
import geph_native_sqlite_build as build
import geph_native_sqlite_bundle as bundle
import test_geph_native_sqlite_build as fixture


class NativeBundleTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.NativeBuildEvidenceTests()
        self.addCleanup(self.case.doCleanups)
        self.case.setUp()
        self.root = self.case.root
        self.receipt = self.case.release()
        self.descriptor = self.case.descriptor
        self.published = self.case.write(self.root / "independent-published", (self.root / "geph-universal").read_bytes())
        self.archive = self.root / bundle.BUNDLE_NAME
        self.output = self.root / "unpacked"
        self.retry = 0
        self.args = dict(descriptor=self.descriptor, source_sha256=fixture.SOURCE_SHA,
                         lock_sha256=fixture.LOCK_SHA, published_binary=self.published)

    def pack(self, path=None):
        return bundle.pack_bundle(self.receipt, self.root, path or self.archive, **self.args)

    def unpack(self, **override):
        return bundle.unpack_bundle(self.archive, self.output, **(self.args | override))

    def entries(self):
        return bundle._decode(self.archive.read_bytes())

    def assert_retained(self):
        self.assertTrue(self.output.is_dir())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.retry += 1
        self.output = self.root / f"retry-{self.retry}"

    def write_entries(self, entries, *, refresh_manifest=False):
        if refresh_manifest:
            entries.pop(bundle.MANIFEST, None)
            value = bundle._manifest(entries, "release.json", self.descriptor, fixture.SOURCE_SHA, fixture.LOCK_SHA)
            entries[bundle.MANIFEST] = bundle._json(value)
        self.archive.write_bytes(bundle._encode(entries))

    def test_roundtrip_complete_closure_and_deterministic_pack(self):
        first = self.pack()
        second_path = self.root / "second.tar"
        second = self.pack(second_path)
        self.assertEqual(self.archive.read_bytes(), second_path.read_bytes())
        self.assertEqual(first["bundle_sha256"], second["bundle_sha256"])
        self.assertEqual(first["file_count"], 24)
        result = self.unpack()
        self.assertEqual(result["final_binary_sha256"], build.sha(self.published.read_bytes()))
        self.assertEqual(result["receipt_sha256"], build.sha(self.receipt.read_bytes()))
        self.assertEqual(result["receipt_path"], str(self.output / "release.json"))
        self.assertEqual(result["artifacts_root"], str(self.output))
        actual = {str(p.relative_to(self.output)) for p in self.output.rglob("*") if p.is_file()}
        expected = set(self.entries()) - {bundle.MANIFEST}
        self.assertEqual(actual, expected)
        for target in native.TARGETS:
            self.assertTrue({f"{target}/sqlite3.o", f"{target}/sys.rlib", f"{target}/map", f"{target}/include/sqlite3.c"} <= actual)
        self.assertNotIn("independent-published", actual)
        self.assertNotIn(bundle.BUNDLE_NAME, actual)

    def test_unpack_never_uses_original_producer_files(self):
        self.pack()
        for target in native.TARGETS:
            (self.root / target / "sqlite3.o").unlink()
            (self.root / target / "sys.rlib").unlink()
        self.receipt.unlink()
        self.assertEqual(self.unpack()["file_count"], 24)

    def test_independent_binary_mismatch_retains_unverified_private_evidence(self):
        self.pack()
        self.published.write_bytes(self.published.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "independently published"):
            self.unpack()
        self.assert_retained()
        with self.assertRaisesRegex(ValueError, "independently published"):
            self.pack(self.root / "bad.tar")
        self.assertFalse((self.root / "bad.tar").exists())

    def test_missing_target_not_hidden_by_manifest_rehash(self):
        self.pack()
        entries = self.entries()
        release = json.loads(entries["release.json"])
        release["linked_receipts"].pop(native.TARGETS[1])
        entries["release.json"] = bundle._json(release)
        self.write_entries(entries, refresh_manifest=True)
        with self.assertRaises(ValueError):
            self.unpack()
        self.assert_retained()

    def test_native_object_mutation_not_hidden_by_manifest_rehash(self):
        self.pack()
        entries = self.entries()
        entries[f"{native.TARGETS[0]}/sqlite3.o"] += b"different"
        self.write_entries(entries, refresh_manifest=True)
        with self.assertRaisesRegex(ValueError, "hash/size"):
            self.unpack()
        self.assert_retained()

    def test_receipt_mutation_and_helper_identity_remain_strict(self):
        self.pack()
        original = self.entries()
        for field in ("source_sha256", "helper_sha256", "lock_sha256"):
            with self.subTest(field=field):
                entries = dict(original)
                name = f"{native.TARGETS[0]}/native-build.json"
                receipt = json.loads(entries[name])
                receipt[field] = "0" * 64
                entries[name] = bundle._json(receipt)
                # Update all parent hashes to reach the semantic identity check.
                linked_name = f"{native.TARGETS[0]}-linked.json"
                linked = json.loads(entries[linked_name])
                linked["native_receipt"].update(size=len(entries[name]), sha256=build.sha(entries[name]))
                entries[linked_name] = bundle._json(linked)
                release = json.loads(entries["release.json"])
                release["linked_receipts"][native.TARGETS[0]].update(size=len(entries[linked_name]), sha256=build.sha(entries[linked_name]))
                entries["release.json"] = bundle._json(release)
                self.write_entries(entries, refresh_manifest=True)
                with self.assertRaisesRegex(ValueError, "native receipt .* mismatch"):
                    self.unpack()
                self.assert_retained()

    def test_extra_member_rejected_even_in_rehashed_manifest(self):
        self.pack()
        entries = self.entries()
        entries["unreferenced.txt"] = b"not part of proof"
        self.write_entries(entries, refresh_manifest=True)
        with self.assertRaisesRegex(ValueError, "exact release evidence closure"):
            self.unpack()
        self.assert_retained()

    def test_missing_referenced_file_and_manifest_only_fail(self):
        self.pack()
        original = self.entries()
        for names in ([f"{native.TARGETS[1]}/map"], [name for name in original if name != bundle.MANIFEST]):
            entries = {key: value for key, value in original.items() if key not in names}
            self.write_entries(entries, refresh_manifest=True)
            with self.assertRaises((ValueError, FileNotFoundError)):
                self.unpack()
            self.assert_retained()

    def test_wrong_trusted_inputs_and_manifest_tampering_fail_before_extract(self):
        self.pack()
        for values in ({"source_sha256": "f" * 64}, {"lock_sha256": "f" * 64}):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, "manifest identity"):
                self.unpack(**values)
        entries = self.entries()
        manifest = json.loads(entries[bundle.MANIFEST])
        manifest["files"]["release.json"]["sha256"] = "0" * 64
        entries[bundle.MANIFEST] = bundle._json(manifest)
        self.write_entries(entries)
        with self.assertRaisesRegex(ValueError, "manifest identity"):
            self.unpack()
        self.assertFalse(self.output.exists())

    def test_unsafe_paths_links_extensions_devices_and_directories_rejected(self):
        for name in (".", "/absolute", "../escape", "a/../../escape", "./receipt", "a//receipt", "a\\receipt"):
            info = tarfile.TarInfo(name)
            info.mode, info.size = 0o644, 1
            payload = info.tobuf(tarfile.USTAR_FORMAT) + b"x" + b"\0" * 511 + b"\0" * 1024
            with self.subTest(name=name), self.assertRaises(ValueError):
                bundle._decode(payload)
        for typ in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE,
                    tarfile.DIRTYPE, tarfile.FIFOTYPE, tarfile.XHDTYPE, tarfile.XGLTYPE,
                    tarfile.GNUTYPE_SPARSE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            info = tarfile.TarInfo("member")
            info.mode, info.size, info.type = 0o644, 1, typ
            payload = info.tobuf(tarfile.USTAR_FORMAT) + b"x" + b"\0" * 511 + b"\0" * 1024
            with self.subTest(type=typ), self.assertRaises(ValueError):
                bundle._decode(payload)

    def test_duplicate_unordered_truncated_nonzero_padding_and_trailing_rejected(self):
        member = bundle._header("a", 1) + b"x" + b"\0" * 511
        valid = member + b"\0" * 1024
        bad = [member + member + b"\0" * 1024, valid[:-512], valid[:-1], valid + b"\0" * 512,
               valid + member, valid[:513] + b"y" + valid[514:], valid[:400], b"\0" * 1024,
               bundle._header("b", 1) + b"x" + b"\0" * 511 + member + b"\0" * 1024]
        for payload in bad:
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                bundle._decode(payload)

    def test_metadata_checksum_and_size_bounds_rejected(self):
        for size in (0, build.MAX_BYTES + 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                bundle._header("member", size)
        info = tarfile.TarInfo("member")
        info.size, info.mode, info.uid = 1, 0o644, 1
        payload = info.tobuf(tarfile.USTAR_FORMAT) + b"x" + b"\0" * 1535
        with self.assertRaisesRegex(ValueError, "canonical regular"):
            bundle._decode(payload)
        payload = bytearray(bundle._encode({"a": b"x"}))
        payload[148] = ord("7")
        with self.assertRaisesRegex(ValueError, "header"):
            bundle._decode(bytes(payload))
        with mock.patch.object(bundle, "MAX_MEMBERS", 1):
            with self.assertRaises(ValueError):
                bundle._encode({"a": b"x", "b": b"y"})
        with mock.patch.object(bundle, "MAX_BUNDLE_BYTES", 1024):
            with self.assertRaises(ValueError):
                bundle._encode({"a": b"x"})

    def test_existing_destination_and_symlink_parents_preserved(self):
        self.pack()
        self.output.mkdir()
        sentinel = self.case.write(self.output / "keep", b"user data")
        with self.assertRaises(FileExistsError):
            self.unpack()
        self.assertEqual(sentinel.read_bytes(), b"user data")
        link = self.root / "linked-parent"
        link.symlink_to(self.output, target_is_directory=True)
        with self.assertRaises(ValueError):
            bundle.unpack_bundle(self.archive, link / "fresh", **self.args)
        self.assertEqual(sentinel.read_bytes(), b"user data")
        self.assertFalse((self.output / "fresh").exists())

    def test_symlink_inputs_and_existing_output_not_overwritten(self):
        self.pack()
        with self.assertRaises(FileExistsError):
            self.pack()
        saved = self.archive.read_bytes()
        self.archive.unlink()
        target = self.case.write(self.root / "original.tar", saved)
        self.archive.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            self.unpack()
        self.assertFalse(self.output.exists())
        (self.root / native.TARGETS[0] / "sqlite3.o").unlink()
        (self.root / native.TARGETS[0] / "sqlite3.o").symlink_to(self.root / native.TARGETS[1] / "sqlite3.o")
        with self.assertRaises((ValueError, OSError)):
            self.pack(self.root / "another.tar")

    def test_archive_snapshot_is_immutable_before_extraction(self):
        self.pack()
        original = bundle._decode
        checksum = build.sha(self.archive.read_bytes())
        def change_source_after_read(data):
            self.archive.write_bytes(b"changed after bounded snapshot")
            return original(data)
        # The verifier is real; only mutate the source after its immutable read.
        with mock.patch.object(bundle, "_decode", side_effect=change_source_after_read):
            self.assertEqual(self.unpack()["bundle_sha256"], checksum)

    def test_pack_verifies_snapshot_after_original_files_change(self):
        original = bundle._verify_snapshot
        def change_producer_after_snapshot(*args, **kwargs):
            (self.root / native.TARGETS[0] / "sqlite3.o").write_bytes(b"producer changed")
            return original(*args, **kwargs)
        with mock.patch.object(bundle, "_verify_snapshot", side_effect=change_producer_after_snapshot):
            self.pack()
        self.assertEqual(self.unpack()["file_count"], 24)

    def test_duplicate_json_and_noncanonical_manifest_are_rejected(self):
        self.pack()
        original = self.entries()
        for manifest in (original[bundle.MANIFEST].replace(b'{"descriptor', b'{"scope":"duplicate","descriptor', 1),
                         b" " + original[bundle.MANIFEST]):
            entries = dict(original)
            entries[bundle.MANIFEST] = manifest
            self.write_entries(entries)
            with self.assertRaises(ValueError):
                self.unpack()
            self.assertFalse(self.output.exists())

    def test_member_path_collision_retains_unverified_tree_and_user_files(self):
        self.pack()
        entries = self.entries()
        entries["collision"] = b"file cannot also be directory"
        entries["collision/child"] = b"child"
        self.write_entries(entries, refresh_manifest=True)
        sentinel = self.case.write(self.root / "keep-user-file", b"kept")
        with self.assertRaises(OSError):
            self.unpack()
        self.assert_retained()
        self.assertEqual(sentinel.read_bytes(), b"kept")

    def test_replaced_output_directory_is_never_deleted_on_failure(self):
        self.pack()
        foreign = self.root / "foreign"
        foreign.mkdir()
        self.case.write(foreign / "keep-user-file", b"user data")
        moved_owned = self.root / "moved-owned"
        original = bundle._verify_snapshot
        def swap_before_real_verify(*args, **kwargs):
            self.output.rename(moved_owned)
            foreign.rename(self.output)
            return original(*args, **kwargs)
        with mock.patch.object(bundle, "_verify_snapshot", side_effect=swap_before_real_verify):
            with self.assertRaises((ValueError, FileNotFoundError)) as failure:
                self.unpack()
        self.assertEqual((self.output / "keep-user-file").read_bytes(), b"user data")
        self.assertTrue((moved_owned / "release.json").is_file())
        self.assertTrue(any(str(self.output) in note for note in failure.exception.__notes__))

    def test_nonempty_directory_swapped_after_mkdir_is_not_written_or_accepted(self):
        self.pack()
        foreign = self.root / "foreign"
        foreign.mkdir()
        self.case.write(foreign / "keep-user-file", b"user data")
        moved_owned = self.root / "moved-owned"
        original = os.mkdir
        def swap_after_real_mkdir(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == self.output.name:
                self.output.rename(moved_owned)
                foreign.rename(self.output)
            return result
        with mock.patch.object(bundle.os, "mkdir", side_effect=swap_after_real_mkdir):
            with self.assertRaisesRegex(ValueError, "replaced or is not empty"):
                self.unpack()
        self.assertEqual(list(self.output.iterdir()), [self.output / "keep-user-file"])
        self.assertEqual((self.output / "keep-user-file").read_bytes(), b"user data")
        self.assertEqual(list(moved_owned.iterdir()), [])

    def test_unreferenced_physical_entry_added_during_verify_is_rejected(self):
        self.pack()
        original = bundle._verify_snapshot
        for extra_directory in (False, True):
            with self.subTest(directory=extra_directory):
                def add_after_real_verify(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if extra_directory:
                        (self.output / "extra-directory").mkdir()
                    else:
                        (self.output / "extra-file").write_bytes(b"unexpected")
                    return result
                with mock.patch.object(bundle, "_verify_snapshot", side_effect=add_after_real_verify):
                    with self.assertRaisesRegex(ValueError, "unexpected"):
                        self.unpack()
                self.assert_retained()


class NativeBundleStandaloneTests(unittest.TestCase):
    def test_import_and_help_need_only_original_three_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for module in (native, build, bundle):
                original = Path(module.__file__)
                (root / original.name).write_bytes(original.read_bytes())
            entrypoints = {
                "import": "import geph_native_sqlite_bundle as bundle; assert callable(bundle.pack_bundle); assert callable(bundle.unpack_bundle)",
                "--help": "import runpy; sys.argv = ['geph_native_sqlite_bundle.py', '--help']; runpy.run_module('geph_native_sqlite_bundle', run_name='__main__')",
            }
            for name, entrypoint in entrypoints.items():
                with self.subTest(entrypoint=name):
                    code = "import sys; sys.path.insert(0, sys.argv[1]); " + entrypoint
                    result = subprocess.run([sys.executable, "-I", "-c", code, str(root)],
                                            cwd=root, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    if name == "--help":
                        self.assertIn("pack", result.stdout)
                    else:
                        self.assertEqual(result.stdout, "")


class NativeBundleCliTests(unittest.TestCase):
    def setUp(self):
        wrapper = native.WRAPPER
        self.lock_bytes = (f'version = 3\n\n[[package]]\nname = "{wrapper["name"]}"\n'
                           f'version = "{wrapper["version"]}"\n'
                           'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                           f'checksum = "{wrapper["sha256"]}"\n').encode()
        self.descriptor = fixture.descriptor() | {
            "schema_version": 2, "producer_helper_sha256": build.sha(Path(build.__file__).read_bytes()),
        }
        self.source = {"schema_version": 1,
                       "crate": {"name": "geph5-client", "version": "0.4.3",
                                 "url": "https://static.crates.io/crates/geph5-client/geph5-client-0.4.3.crate",
                                 "sha256": "e" * 64},
                       "features": ["aws_lambda"], "targets": native.TARGETS.copy(),
                       "lock_sha256": build.sha(self.lock_bytes), "release_revision": 1,
                       "native_sqlite": self.descriptor}
        self.source_bytes = (json.dumps(self.source, sort_keys=True) + "\n").encode()
        self.source_sha = build.sha(self.source_bytes)
        self.case = fixture.NativeBuildEvidenceTests()
        self.addCleanup(self.case.doCleanups)
        # Configure only the synthetic evidence factory, never the verifiers.
        with mock.patch.multiple(fixture, SOURCE_SHA=self.source_sha, LOCK=self.lock_bytes,
                                 LOCK_SHA=self.source["lock_sha256"]), \
                mock.patch.object(fixture, "descriptor", return_value=self.descriptor):
            self.case.setUp()
            self.receipt = self.case.release()
        self.root = self.case.root
        self.source_path = self.case.write(self.root / "SOURCE.json", self.source_bytes)
        self.lock = self.case.write(self.root / "Cargo.lock", self.lock_bytes)
        self.published = self.case.write(self.root / "independent-published",
                                         (self.root / "geph-universal").read_bytes())
        self.archive = self.root / bundle.BUNDLE_NAME
        self.argv = ["pack", "--source", str(self.source_path), "--cargo-lock", str(self.lock),
                     "--receipt", str(self.receipt), "--artifacts-root", str(self.root),
                     "--published-binary", str(self.published), "--output", str(self.archive)]

    def failure(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as failure:
            bundle.main(self.argv)
        self.assertEqual(failure.exception.code, 1)
        self.assertEqual(stdout.getvalue(), "")
        return stderr.getvalue()

    def test_cli_pack_emits_metadata_and_independently_unpackable_v2_bundle(self):
        result = subprocess.run([sys.executable, "-E", "-s", str(Path(bundle.__file__)), *self.argv],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual(report["scope"], bundle.SCOPE)
        self.assertEqual(report["bundle_path"], str(self.archive))
        self.assertEqual(report["bundle_sha256"], build.sha(self.archive.read_bytes()))
        self.assertEqual(report["size"], self.archive.stat().st_size)
        self.assertEqual(report["file_count"], 24)
        unpacked = bundle.unpack_bundle(self.archive, self.root / "unpacked", self.descriptor,
                                         self.source_sha, build.sha(self.lock_bytes), self.published)
        self.assertEqual(unpacked["receipt_sha256"], report["receipt_sha256"])
        self.assertEqual(unpacked["final_binary_sha256"], build.sha(self.published.read_bytes()))

    def test_cli_validates_full_source_before_delegating(self):
        invalid = [self.source | {"features": []}, self.source | {"targets": native.TARGETS[:1]},
                   self.source | {"unexpected": True},
                   self.source | {"crate": self.source["crate"] | {"url": "https://unreviewed.invalid/crate"}}]
        payloads = [json.dumps(source).encode() for source in invalid]
        payloads.append(self.source_bytes.replace(b'{', b'{"schema_version":1,', 1))
        for payload in payloads:
            with self.subTest(payload=payload[:100]), mock.patch.object(bundle, "pack_bundle") as pack:
                self.source_path.write_bytes(payload)
                self.failure()
                pack.assert_not_called()
                self.assertFalse(self.archive.exists())

    def test_cli_refuses_source_without_native_descriptor(self):
        source = dict(self.source)
        del source["native_sqlite"]
        self.source_path.write_text(json.dumps(source))
        with mock.patch.object(bundle, "pack_bundle") as pack:
            self.assertIn("reviewed native SQLite SOURCE is required", self.failure())
            pack.assert_not_called()
        self.assertFalse(self.archive.exists())

    def test_cli_checks_lock_hash_and_genuine_wrapper_before_delegating(self):
        self.lock.write_bytes(self.lock_bytes + b"# different\n")
        with mock.patch.object(bundle, "pack_bundle") as pack:
            self.assertIn("Cargo.lock hash mismatch", self.failure())
            pack.assert_not_called()
        wrong_wrapper = self.lock_bytes.replace(native.WRAPPER["sha256"].encode(), b"0" * 64)
        self.lock.write_bytes(wrong_wrapper)
        self.source_path.write_text(json.dumps(self.source | {"lock_sha256": build.sha(wrong_wrapper)}))
        with mock.patch.object(bundle, "pack_bundle") as pack:
            self.assertIn("wrapper identity/checksum", self.failure())
            pack.assert_not_called()
        self.assertFalse(self.archive.exists())

    def test_cli_cannot_reuse_proof_under_other_source_or_receipt_selected_pin(self):
        for field in ("release_revision", "producer_helper_sha256"):
            source = copy.deepcopy(self.source)
            if field == "release_revision":
                source[field] += 1
            else:
                source["native_sqlite"][field] = "0" * 64
            with self.subTest(field=field):
                self.source_path.write_text(json.dumps(source))
                self.assertIn("final native evidence input mismatch", self.failure())
                self.assertFalse(self.archive.exists())

    def test_cli_rejects_wrong_independent_binary_without_output(self):
        self.published.write_bytes(self.published.read_bytes() + b"different")
        self.assertIn("independently published binary", self.failure())
        self.assertFalse(self.archive.exists())

    def test_cli_preserves_existing_output(self):
        self.archive.write_bytes(b"existing user artifact")
        self.failure()
        self.assertEqual(self.archive.read_bytes(), b"existing user artifact")

    def test_cli_refuses_symlink_authority_inputs(self):
        for path in (self.source_path, self.lock):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                target = self.case.write(self.root / (path.name + ".original"), original)
                path.unlink()
                path.symlink_to(target)
                with mock.patch.object(bundle, "pack_bundle") as pack:
                    self.failure()
                    pack.assert_not_called()
                self.assertFalse(self.archive.exists())
                path.unlink()
                path.write_bytes(original)

    def test_cli_keeps_one_authoritative_source_and_lock_snapshot(self):
        real_pack = bundle.pack_bundle
        def replace_authority_after_read(*args, **kwargs):
            self.source_path.write_bytes(b"replaced SOURCE after snapshot")
            self.lock.write_bytes(b"replaced lock after snapshot")
            return real_pack(*args, **kwargs)
        stdout = io.StringIO()
        with redirect_stdout(stdout), mock.patch.object(bundle, "pack_bundle", side_effect=replace_authority_after_read):
            self.assertEqual(bundle.main(self.argv), 0)
        self.assertEqual(json.loads(stdout.getvalue())["bundle_sha256"], build.sha(self.archive.read_bytes()))
        result = bundle.unpack_bundle(self.archive, self.root / "unpacked", self.descriptor,
                                      self.source_sha, build.sha(self.lock_bytes), self.published)
        self.assertEqual(result["file_count"], 24)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

import geph_native_sqlite as native
import geph_vendor_source


def fixture(root: Path) -> tuple[dict, Path, bytes]:
    """Tiny source-contract fixture, never represented as real SQLite."""
    source_id = "2026-06-03 19:12:13 " + "a" * 64
    body = (b"/*\n" + native.NOTICE + b"\n*/\n"
            + b'#define SQLITE_VERSION "3.53.2"\n'
            + f'#define SQLITE_SOURCE_ID "{source_id}"\n'.encode())
    payloads = {"sqlite3.c": body + b"/* C fixture */\n", "sqlite3.h": body}
    archive = root / "sqlite.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        for name, payload in payloads.items():
            zipped.writestr("sqlite-amalgamation-3530200/" + name, payload)
    data = archive.read_bytes()
    descriptor = {
        "schema_version": 1, "version": "3.53.2", "source_id": source_id,
        "path": native.PATH, "linkage": "static", "targets": native.TARGETS[:],
        "wrapper": native.WRAPPER.copy(), "compile_definitions": native.COMPILE_DEFINITIONS[:],
        "archive": {"url": "https://sqlite.org/2026/sqlite-amalgamation-3530200.zip",
                    "root": "sqlite-amalgamation-3530200", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "files": [{"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()} for name, payload in payloads.items()],
    }
    lock = (f'version = 3\n\n[[package]]\nname = "libsqlite3-sys"\nversion = "0.30.1"\n'
            f'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "{native.WRAPPER["sha256"]}"\n').encode()
    return descriptor, archive, lock


class NativeSqliteSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.descriptor, self.archive, self.lock = fixture(self.root)
        self.source = self.root / "source"
        self.source.mkdir()

    def materialize(self):
        return native.materialize(self.descriptor, self.archive, self.source)

    def rewrite_archive(self, edit):
        with zipfile.ZipFile(self.archive) as zipped:
            entries = [(item, zipped.read(item)) for item in zipped.infolist()]
        entries = edit(entries)
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            for info, data in entries:
                zipped.writestr(info, data)
        raw = self.archive.read_bytes()
        self.descriptor["archive"].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    def test_source_roundtrip_retains_exact_header_notice(self):
        target = self.materialize()
        result = native.verify_materialized(self.descriptor, self.source)
        self.assertEqual(set(result), {"sqlite3.c", "sqlite3.h"})
        self.assertIn(native.NOTICE, result["sqlite3.h"])
        self.assertEqual(target, self.source / native.PATH)
        native.verify_wrapper_lock(self.descriptor, self.lock, hashlib.sha256(self.lock).hexdigest())

    def test_strict_descriptor_rejects_unreviewed_inputs(self):
        changes = [
            lambda d: d.update(extra=1), lambda d: d.update(schema_version=True),
            lambda d: d.update(path="../sqlite"), lambda d: d.update(linkage="dynamic"),
            lambda d: d.update(targets=d["targets"][:1]), lambda d: d["archive"].update(url="https://evil.example/sqlite.zip"),
            lambda d: d["archive"].update(size=True), lambda d: d["archive"].update(root="sqlite-amalgamation-3530100"),
            lambda d: d["wrapper"].update(sha256="b" * 64),
            lambda d: d["compile_definitions"].append("SQLITE_OMIT_MUTEX"),
            lambda d: d["files"][0].update(path="../../sqlite3.c"),
            lambda d: d["files"][0].update(size=native.MAX_FILE_BYTES + 1),
            lambda d: d["files"][0].update(sha256="A" * 64),
        ]
        for change in changes:
            with self.subTest(change=change):
                value = copy.deepcopy(self.descriptor)
                change(value)
                with self.assertRaises(ValueError):
                    native.validate_descriptor(value)

    def test_archive_bytes_and_length_must_match(self):
        self.archive.write_bytes(self.archive.read_bytes() + b"x")
        with self.assertRaisesRegex(ValueError, "archive size/hash"):
            self.materialize()
        self.assertFalse((self.source / "slipstream-native").exists())

    def test_archive_snapshot_resists_replacement_between_check_and_extract(self):
        original = zipfile.ZipFile
        def replace_then_open(*args, **kwargs):
            self.archive.write_bytes(b"unchecked replacement")
            return original(*args, **kwargs)
        with mock.patch.object(native.zipfile, "ZipFile", side_effect=replace_then_open):
            self.materialize()
        self.assertEqual(len(native.verify_materialized(self.descriptor, self.source)), 2)

    def test_archive_rejects_traversal_duplicate_symlink_and_bomb_claim(self):
        def symlink(entries):
            entry = zipfile.ZipInfo("sqlite-amalgamation-3530200/sqlite3ext.h")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            return entries + [(entry, b"/etc/passwd")]
        edits = [lambda e: e + [("../sqlite3.c", b"bad")], lambda e: e + [e[0]], symlink,
                 lambda e: e + [("sqlite-amalgamation-3530200/shell.c", b"0" * (native.MAX_UNPACKED_BYTES + 1))]]
        original = self.archive.read_bytes()
        for edit in edits:
            with self.subTest(edit=edit):
                self.archive.write_bytes(original)
                self.rewrite_archive(edit)
                with self.assertRaises(ValueError):
                    self.materialize()

    def test_native_header_identity_is_not_only_a_descriptor_claim(self):
        for field, value in (("version", "3.53.1"), ("source_id", "2026-06-03 19:12:13 " + "b" * 64)):
            changed = copy.deepcopy(self.descriptor)
            changed[field] = value
            # Testing bytes against a syntactically reviewed descriptor avoids
            # relying only on the archive filename/version cross-check.
            with zipfile.ZipFile(self.archive) as z:
                contents = {item["path"]: z.read(changed["archive"]["root"] + "/" + item["path"]) for item in changed["files"]}
            with self.assertRaisesRegex(ValueError, "version/source ID"):
                native._verify_bytes(changed, contents)

    def test_materialized_mutation_extra_and_symlink_rejected(self):
        target = self.materialize()
        header = target / "sqlite3.h"
        original = header.read_bytes()
        header.write_bytes(original + b"x")
        with self.assertRaisesRegex(ValueError, "size/hash"):
            native.verify_materialized(self.descriptor, self.source)
        header.unlink()
        outside = self.root / "outside.h"
        outside.write_bytes(original)
        header.symlink_to(outside)
        with self.assertRaises(OSError):
            native.verify_materialized(self.descriptor, self.source)
        header.unlink()
        header.write_bytes(original)
        (target / "extra.h").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "file set"):
            native.verify_materialized(self.descriptor, self.source)

    def test_symlink_archive_and_preexisting_namespace_rejected(self):
        link = self.root / "link.zip"
        link.symlink_to(self.archive)
        with self.assertRaises(OSError):
            native.materialize(self.descriptor, link, self.source)
        (self.source / "slipstream-native").mkdir()
        with self.assertRaises(FileExistsError):
            self.materialize()

    def test_wrapper_registry_checksum_cannot_be_relabelled_native(self):
        wrong = self.lock.replace(native.WRAPPER["sha256"].encode(), self.descriptor["archive"]["sha256"].encode())
        with self.assertRaisesRegex(ValueError, "registry wrapper"):
            native.verify_wrapper_lock(self.descriptor, wrong, hashlib.sha256(wrong).hexdigest())
        with self.assertRaisesRegex(ValueError, "lock hash"):
            native.verify_wrapper_lock(self.descriptor, self.lock, "f" * 64)

    def test_original_notice_must_survive_even_when_file_hashes_are_updated(self):
        with zipfile.ZipFile(self.archive) as archive:
            contents = {item["path"]: archive.read(self.descriptor["archive"]["root"] + "/" + item["path"]) for item in self.descriptor["files"]}
        contents["sqlite3.h"] = contents["sqlite3.h"].replace(native.NOTICE, b"removed notice")
        changed = copy.deepcopy(self.descriptor)
        changed["files"][1].update(size=len(contents["sqlite3.h"]), sha256=hashlib.sha256(contents["sqlite3.h"]).hexdigest())
        with self.assertRaisesRegex(ValueError, "notice"):
            native._verify_bytes(changed, contents)

    def test_read_regular_keeps_pinned_parent_during_symlink_swap(self):
        parent, moved, evil = (self.root / name for name in ("parent", "moved", "evil"))
        parent.mkdir()
        evil.mkdir()
        (parent / "artifact").write_bytes(b"reviewed inode")
        (evil / "artifact").write_bytes(b"unreviewed replacement")
        original_open = os.open
        swapped = False
        def racing_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == "artifact" and not swapped:
                parent.rename(moved)
                parent.symlink_to(evil, target_is_directory=True)
                swapped = True
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(native.os, "open", side_effect=racing_open):
            self.assertEqual(native.read_regular(parent / "artifact", 100), b"reviewed inode")
        self.assertTrue(swapped)
        with self.assertRaises(OSError):
            native.read_regular(parent / "artifact", 100)

    def test_source_contract_requires_explicit_archive_before_extract(self):
        source = {"schema_version": 1,
                  "crate": {"name": "geph5-client", "version": "0.4.3", "url": "https://static.crates.io/crates/geph5-client/geph5-client-0.4.3.crate", "sha256": "e" * 64},
                  "features": ["aws_lambda"], "targets": native.TARGETS[:], "lock_sha256": hashlib.sha256(self.lock).hexdigest(),
                  "release_revision": 1, "native_sqlite": self.descriptor}
        source_path = self.root / "SOURCE.json"
        source_path.write_text(json.dumps(source))
        geph_vendor_source.load_source_contract(source_path)
        with self.assertRaisesRegex(ValueError, "explicit archive"):
            geph_vendor_source.materialize_source(source_path=source_path, version_path=self.root / "VERSION",
                                                  cargo_lock_path=self.root / "Cargo.lock", crate_path=self.root / "geph.crate",
                                                  output=self.root / "output")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import geph_native_sqlite as native
import geph_vendor_source as vendor
import seal_geph_cargo_cache as seal


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class CargoCacheSealTests(unittest.TestCase):
    """Tiny synthetic archives: never a Cargo resolution or real build fixture."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.home, self.output = self.root / "fetched", self.root / "sealed"
        self.source_path, self.lock_path = self.root / "SOURCE.json", self.root / "Cargo.lock"
        self.namespace = "index.crates.io-0123456789abcdef"
        self.cache = self.home / "registry/cache" / self.namespace
        self.index = self.home / "registry/index" / self.namespace
        self.cache.mkdir(parents=True)
        self.index.mkdir(parents=True)
        self.config = self.index / "config.json"
        self.config.write_text(json.dumps(seal.REGISTRY_CONFIG))
        self.packages = [{"name": vendor.CRATE_NAME, "version": "0.4.3"}]
        for name, version in (("a", "1.0.0"), ("cc", "1.0.0"), ("log", "1.0.0"),
                              ("serde", "1.0.0"), ("serde", "2.0.0+fixture"),
                              (native.WRAPPER["name"], native.WRAPPER["version"])):
            payload = f"synthetic archive {name} {version}\n".encode()
            self.packages.append({"name": name, "version": version, "source": seal.REGISTRY,
                                  "checksum": sha(payload)})
            (self.cache / f"{name}-{version}.crate").write_bytes(payload)
            target = self.index / ".cache" / seal.index_path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            # NUL-delimited header, non-UTF8 bytes and unrelated versions must survive.
            target.write_bytes(b'\x03\x02\0\0\0etag: "fixture"\0\xff\xfe\0'
                               b'0.1.0\0{"vers":"0.1.0"}\0' + name.encode())
        descriptor = {
            "schema_version": 2, "producer_helper_sha256": "b" * 64,
            "version": "3.53.2", "source_id": "2026-06-03 19:12:13 " + "a" * 64,
            "path": native.PATH, "linkage": "static", "targets": native.TARGETS[:],
            "wrapper": native.WRAPPER.copy(), "compile_definitions": native.COMPILE_DEFINITIONS[:],
            "archive": {"url": "https://sqlite.org/2026/sqlite-amalgamation-3530200.zip",
                        "root": "sqlite-amalgamation-3530200", "size": 1, "sha256": "a" * 64},
            "files": [{"path": name, "size": 1, "sha256": "a" * 64}
                      for name in ("sqlite3.c", "sqlite3.h")],
        }
        self.source = {
            "schema_version": vendor.SCHEMA_VERSION,
            "crate": {"name": vendor.CRATE_NAME, "version": "0.4.3",
                      "url": vendor.CRATE_URL.format(name=vendor.CRATE_NAME, version="0.4.3"),
                      "sha256": "a" * 64},
            "features": list(vendor.FEATURES), "targets": list(vendor.TARGETS),
            "release_revision": 1, "native_sqlite": descriptor,
        }
        self.write_lock()

    def write_source(self):
        self.source_path.write_text(json.dumps(self.source))

    def write_lock(self):
        lines = ["version = 3"]
        for package in self.packages:
            lines.append("\n[[package]]")
            lines.extend(f"{key} = {json.dumps(value)}" for key, value in package.items())
        payload = ("\n".join(lines) + "\n").encode()
        self.lock_path.write_bytes(payload)
        self.source["lock_sha256"] = sha(payload)
        self.write_source()

    def run_seal(self, *, fixture_wrapper=True, **kwargs):
        args = dict(source_path=self.source_path, lock_path=self.lock_path,
                    fetched_cargo_home=self.home, output=self.output)
        args.update(kwargs)
        if not fixture_wrapper:
            return seal.seal_cache(**args)
        # Only the genuine wrapper's archive identity is unavailable in this tiny
        # fixture. SOURCE/native descriptor, lock hash and all archive checks stay real.
        with mock.patch.object(native, "verify_wrapper_lock") as wrapper_policy:
            result = seal.seal_cache(**args)
            wrapper_policy.assert_called_once()
            return result

    def assert_unsealed(self):
        self.assertFalse((self.output / seal.RECEIPT).exists())

    def test_full_lock_copy_is_minimal_and_sparse_files_are_opaque(self):
        ignored = [self.home / "credentials.toml", self.home / "config.toml",
                   self.home / "git/checkouts/private", self.home / "registry/src/source",
                   self.cache / "unselected-9.9.9.crate", self.index / ".cache/un/wa/unwanted"]
        for path in ignored:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"must not copy")
        result = self.run_seal()
        self.assertEqual(result["registry_package_count"], 6)
        self.assertEqual(result["index_name_count"], 5)
        self.assertEqual(result["source_sha256"], sha(self.source_path.read_bytes()))
        self.assertEqual(result["lock_sha256"], sha(self.lock_path.read_bytes()))
        self.assertEqual(result["native_descriptor_sha256"],
                         native.descriptor_sha256(self.source["native_sqlite"]))
        self.assertEqual(result["offline_cargo_resolution"], "not_performed")
        self.assertIn("not filtered or authenticated", result["index_assurance"])
        records = result["archives"] + result["index"] + [result["registry_config"]]
        for record in records:
            actual = (self.output / record["path"]).read_bytes()
            self.assertEqual(actual, (self.home / record["path"]).read_bytes())
            self.assertEqual((record["size"], record["sha256"]), (len(actual), sha(actual)))
        expected = {record["path"] for record in records} | {seal.RECEIPT}
        actual = {str(p.relative_to(self.output)) for p in self.output.rglob("*") if p.is_file()}
        self.assertEqual(actual, expected)
        self.assertEqual(json.loads((self.output / seal.RECEIPT).read_bytes()), result)
        self.assertTrue(all(path.read_bytes() == b"must not copy" for path in ignored))

    def test_index_path_mapping_lowercases_only_index_name(self):
        for name, expected in (("a", "1/a"), ("cc", "2/cc"), ("log", "3/l/log"),
                               ("serde", "se/rd/serde"), ("Serde", "se/rd/serde")):
            self.assertEqual(seal.index_path(name), expected)
        item = self.packages[1]
        old = self.cache / "a-1.0.0.crate"
        item["name"] = "A"
        old.rename(self.cache / "A-1.0.0.crate")
        self.write_lock()
        result = self.run_seal()
        self.assertTrue(any(p["path"].endswith("/A-1.0.0.crate") for p in result["archives"]))
        self.assertTrue(any(p["path"].endswith("/1/a") for p in result["index"]))

    def test_real_wrapper_policy_rejects_synthetic_identity_before_output(self):
        with self.assertRaisesRegex(ValueError, "wrapper identity/checksum"):
            self.run_seal(fixture_wrapper=False)
        self.assertFalse(self.output.exists())

    def test_real_wrapper_pin_does_not_authenticate_synthetic_archive(self):
        self.packages[-1]["checksum"] = native.WRAPPER["sha256"]
        self.write_lock()
        with self.assertRaisesRegex(ValueError, "archive checksum mismatch: libsqlite3-sys"):
            self.run_seal(fixture_wrapper=False)
        self.assert_unsealed()

    def test_complete_source_validation_cannot_be_bypassed_by_wrapper_fixture(self):
        original = copy.deepcopy(self.source)
        mutations = [lambda s: s.update(unknown=True), lambda s: s.update(features=[]),
                     lambda s: s.update(targets=[]), lambda s: s.update(release_revision=True),
                     lambda s: s.pop("native_sqlite"),
                     lambda s: s["native_sqlite"]["wrapper"].update(sha256="c" * 64),
                     lambda s: s["native_sqlite"].update(compile_definitions=[]),
                     lambda s: s["native_sqlite"].update(producer_helper_sha256="wrong")]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.source = copy.deepcopy(original)
                mutate(self.source)
                self.write_source()
                with self.assertRaises(ValueError):
                    self.run_seal()
                self.assertFalse(self.output.exists())

    def test_source_duplicate_fields_and_lock_hash_mismatch_reject(self):
        self.source_path.write_bytes(self.source_path.read_bytes()[:-1] + b',"schema_version":1}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_seal()
        self.write_source()
        self.lock_path.write_bytes(self.lock_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "lock hash"):
            self.run_seal()
        self.assertFalse(self.output.exists())

    def test_source_and_lock_remain_frozen_after_validation(self):
        expected_source, expected_lock = self.source_path.read_bytes(), self.lock_path.read_bytes()
        original = seal._namespace
        calls = 0
        def replace_authority(path):
            nonlocal calls
            calls += 1
            if calls == 1:
                self.source_path.write_bytes(b"not the validated SOURCE")
                self.lock_path.write_bytes(b"not the validated lock")
            return original(path)
        with mock.patch.object(seal, "_namespace", side_effect=replace_authority):
            result = self.run_seal()
        self.assertEqual(result["source_sha256"], sha(expected_source))
        self.assertEqual(result["lock_sha256"], sha(expected_lock))

    def test_all_lock_registry_archives_are_required_even_if_unused_by_target(self):
        # A platform/dev dependency still belongs to the full lock closure.
        self.packages.append({"name": "windows-only", "version": "1.2.3", "source": seal.REGISTRY,
                              "checksum": "a" * 64})
        self.write_lock()
        with self.assertRaises(FileNotFoundError):
            self.run_seal()
        self.assertFalse(self.output.exists())

    def test_missing_exact_archive_or_index_fails_before_output(self):
        paths = [self.cache / "a-1.0.0.crate", self.index / ".cache/1/a"]
        for path in paths:
            with self.subTest(path=path):
                saved = path.read_bytes()
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    self.run_seal()
                self.assertFalse(self.output.exists())
                path.write_bytes(saved)

    def test_bad_archive_checksum_leaves_inspectable_partial_without_receipt(self):
        archive = self.cache / "a-1.0.0.crate"
        archive.write_bytes(b"incorrect archive")
        with self.assertRaisesRegex(ValueError, "archive checksum mismatch"):
            self.run_seal()
        self.assert_unsealed()
        self.assertEqual(archive.read_bytes(), b"incorrect archive")
        self.assertEqual((self.output / archive.relative_to(self.home)).read_bytes(), b"incorrect archive")

    def test_unsafe_names_versions_sources_checksums_and_duplicates_reject(self):
        original = copy.deepcopy(self.packages)
        changes = [{"name": "../a"}, {"name": "a/b"}, {"name": "a\\b"}, {"name": "a\n"},
                   {"version": "../1.0.0"}, {"version": "1.0.0/x"}, {"version": "01.0.0"},
                   {"version": "1.0.0-01"}, {"source": "git+https://example.invalid/repo"},
                   {"source": "registry+https://example.invalid/index"},
                   {"checksum": "A" * 64}, {"checksum": "x"}, {"checksum": None}]
        for change in changes:
            with self.subTest(change=change):
                self.packages = copy.deepcopy(original)
                self.packages[1].update(change)
                if change.get("checksum", "present") is None:
                    del self.packages[1]["checksum"]
                self.write_lock()
                with self.assertRaises(ValueError):
                    self.run_seal()
                self.assertFalse(self.output.exists())
        for duplicate in (copy.deepcopy(original[1]), {**original[1], "name": "A"}):
            self.packages = copy.deepcopy(original) + [duplicate]
            self.write_lock()
            with self.assertRaisesRegex(ValueError, "duplicate"):
                self.run_seal()

    def test_only_reviewed_source_less_entries_are_accepted(self):
        self.packages.append({"name": "arbitrary-path-package", "version": "1.0.0"})
        self.write_lock()
        with self.assertRaisesRegex(ValueError, "unreviewed source-less"):
            self.run_seal()
        self.packages = self.packages[1:-1]
        self.write_lock()
        with self.assertRaisesRegex(ValueError, "missing the source-owned Geph root"):
            self.run_seal()
        self.assertFalse(self.output.exists())

    def test_lock_versions_and_package_count_are_bounded(self):
        original = self.lock_path.read_bytes()
        for version in (b"2", b"true", b'"3"'):
            self.lock_path.write_bytes(original.replace(b"version = 3", b"version = " + version, 1))
            self.source["lock_sha256"] = sha(self.lock_path.read_bytes())
            self.write_source()
            with self.assertRaises(ValueError):
                self.run_seal()
        self.write_lock()
        with mock.patch.object(seal, "MAX_PACKAGES", 2), self.assertRaises(ValueError):
            self.run_seal()
        with mock.patch.object(seal, "MAX_LOCK_BYTES", 10), self.assertRaises(ValueError):
            self.run_seal()
        self.assertFalse(self.output.exists())

    def test_registry_config_is_strict_and_bounded(self):
        invalid = [b'{}', b'[]', b'not JSON', b'{"dl": "x", "api": "https://crates.io"}',
                   json.dumps({**seal.REGISTRY_CONFIG, "auth-required": True}).encode(),
                   json.dumps({**seal.REGISTRY_CONFIG, "api": "https://crates.io/"}).encode(),
                   b'{"dl":"x","dl":"https://static.crates.io/crates","api":"https://crates.io"}',
                   b" " * (seal.MAX_CONFIG_BYTES + 1)]
        for payload in invalid:
            with self.subTest(payload=payload[:100]):
                self.config.write_bytes(payload)
                with self.assertRaises(ValueError):
                    self.run_seal()
                self.assertFalse(self.output.exists())

    def test_namespace_must_be_unique_matching_physical_directory(self):
        other = self.cache.parent / "index.crates.io-fedcba9876543210"
        other.mkdir()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.run_seal()
        other.rmdir()
        moved = self.index.with_name(other.name)
        self.index.rename(moved)
        with self.assertRaisesRegex(ValueError, "namespaces do not match"):
            self.run_seal()
        moved.rename(self.index)
        self.cache.rename(other)
        self.cache.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "physical directory"):
            self.run_seal()
        self.assertFalse(self.output.exists())

    def test_symlinks_in_all_input_boundaries_are_rejected(self):
        for path in (self.source_path, self.lock_path, self.config,
                     self.cache / "a-1.0.0.crate", self.index / ".cache/1/a",
                     self.home, self.index / ".cache"):
            with self.subTest(path=path):
                saved = path.with_name(path.name + ".physical")
                path.rename(saved)
                path.symlink_to(saved, target_is_directory=saved.is_dir())
                try:
                    with self.assertRaises(OSError):
                        self.run_seal()
                    self.assertFalse(self.output.exists())
                finally:
                    path.unlink()
                    saved.rename(path)

    def test_fifo_input_is_rejected_without_blocking(self):
        path = self.cache / "a-1.0.0.crate"
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "bounded regular"):
            self.run_seal()
        self.assertFalse(self.output.exists())

    def test_existing_output_is_never_cleaned_or_overwritten(self):
        self.output.mkdir()
        marker = self.output / "caller-data"
        marker.write_bytes(b"preserve me")
        with self.assertRaises(FileExistsError):
            self.run_seal()
        self.assertEqual(marker.read_bytes(), b"preserve me")
        self.assertEqual(list(self.output.iterdir()), [marker])

    def test_symlink_output_root_and_parent_are_rejected(self):
        actual = self.root / "actual"
        actual.mkdir()
        self.output.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.run_seal()
        with self.assertRaises(OSError):
            self.run_seal(output=self.output / "child")
        self.assertEqual(list(actual.iterdir()), [])

    def test_per_file_and_aggregate_limits_apply_before_copy(self):
        for name, cap in (("MAX_ARCHIVE_BYTES", 1), ("MAX_ARCHIVES_TOTAL", 1),
                          ("MAX_INDEX_BYTES", 1), ("MAX_INDEX_TOTAL", 1)):
            with self.subTest(limit=name), mock.patch.object(seal, name, cap):
                with self.assertRaises(ValueError):
                    self.run_seal()
                self.assertFalse(self.output.exists())

    def test_streaming_is_bounded_and_mutating_input_has_no_receipt(self):
        original = os.read
        calls = []
        def mutate_on_read(fd, count):
            calls.append(count)
            chunk = original(fd, count)
            if len(calls) == 1:
                with (self.cache / "a-1.0.0.crate").open("ab") as stream:
                    stream.write(b"changed")
            return chunk
        with mock.patch.object(seal, "CHUNK_BYTES", 7), mock.patch.object(os, "read", side_effect=mutate_on_read):
            with self.assertRaisesRegex(ValueError, "input changed"):
                self.run_seal()
        self.assertTrue(calls)
        self.assertLessEqual(max(calls), 7)
        self.assert_unsealed()

    def test_output_replacement_before_sealing_is_rejected(self):
        original = seal._same_root
        def swap_then_check(output, info):
            output.rename(output.with_name("retained-partial"))
            output.mkdir()
            return original(output, info)
        with mock.patch.object(seal, "_same_root", side_effect=swap_then_check):
            with self.assertRaisesRegex(ValueError, "output root changed"):
                self.run_seal()
        self.assert_unsealed()
        self.assertFalse((self.root / "retained-partial" / seal.RECEIPT).exists())

    def test_output_file_replacement_before_sealing_is_rejected(self):
        original = seal._same_root
        def replace_then_check(output, info):
            path = output / "registry/cache" / self.namespace / "a-1.0.0.crate"
            path.write_bytes(b"replacement")
            return original(output, info)
        with mock.patch.object(seal, "_same_root", side_effect=replace_then_check):
            with self.assertRaisesRegex(ValueError, "prepared cache file changed"):
                self.run_seal()
        self.assert_unsealed()

    def test_unexpected_output_entries_are_rejected_before_receipt(self):
        original = seal._same_root
        for number, relative in enumerate(("config.toml", "registry/src/untrusted",
                                            "registry/index/extra/config.json",
                                            f"registry/index/{self.namespace}/.cache/extra")):
            output = self.root / f"output-extra-{number}"
            def inject_then_check(root, info):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"unexpected")
                return original(root, info)
            with self.subTest(relative=relative), mock.patch.object(seal, "_same_root", side_effect=inject_then_check):
                with self.assertRaisesRegex(ValueError, "unexpected file or directory"):
                    self.run_seal(output=output)
                self.assertFalse((output / seal.RECEIPT).exists())
                self.assertEqual((output / relative).read_bytes(), b"unexpected")

    def test_cli_reports_only_after_success(self):
        argv = ["seal", "--source", str(self.source_path), "--cargo-lock", str(self.lock_path),
                "--fetched-cargo-home", str(self.home), "--output", str(self.output)]
        with mock.patch("sys.argv", argv), mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            with self.assertRaisesRegex(SystemExit, "wrapper identity/checksum"):
                seal.main()
            self.assertEqual(stdout.getvalue(), "")
        with mock.patch("sys.argv", argv), mock.patch.object(native, "verify_wrapper_lock"), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            seal.main()
            self.assertEqual(json.loads(stdout.getvalue())["registry_packages"], 6)
            self.assertTrue((self.output / seal.RECEIPT).is_file())


if __name__ == "__main__":
    unittest.main()

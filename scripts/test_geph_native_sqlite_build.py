from __future__ import annotations

import copy
import json
from pathlib import Path
import struct
import shutil
import subprocess
import sys
import tempfile
import unittest

import geph_native_sqlite as native
import geph_native_sqlite_build as build

SOURCE_SHA = "a" * 64
LOCK = b"test-only lock fixture\n"
LOCK_SHA = build.sha(LOCK)
VERSION = "3.53.2"
SOURCE_ID = "2026-06-03 19:12:13 " + "d" * 64


def source_contents():
    header = b"/*\n" + native.NOTICE + b"\n*/\n"
    identity = f'#define SQLITE_VERSION "{VERSION}"\n#define SQLITE_SOURCE_ID "{SOURCE_ID}"\n'.encode()
    return {"sqlite3.h": header + identity,
            "sqlite3.c": identity + b'const char *sqlite3_libversion(void) { return SQLITE_VERSION; }\nconst char *sqlite3_sourceid(void) { return SQLITE_SOURCE_ID; }\n'}


def descriptor():
    contents = source_contents()
    return {"schema_version": 1, "version": VERSION, "source_id": SOURCE_ID, "path": native.PATH,
            "archive": {"url": "https://sqlite.org/2026/sqlite-amalgamation-3530200.zip", "root": "sqlite-amalgamation-3530200", "size": 100, "sha256": "b" * 64},
            "files": [{"path": name, "size": len(contents[name]), "sha256": build.sha(contents[name])} for name in ("sqlite3.c", "sqlite3.h")],
            "compile_definitions": native.COMPILE_DEFINITIONS.copy(), "linkage": "static", "targets": native.TARGETS.copy(), "wrapper": native.WRAPPER.copy()}


def ar_member(name, data):
    header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
    assert len(header) == 60
    return header + data + (b"\n" if len(data) % 2 else b"")


def ar(data):
    return b"!<arch>\n" + ar_member("sqlite3.o", data)


def rlib(target, obj=None):
    return ar(macho(target) if obj is None else obj) + ar_member("lib.rmeta", b"fixture metadata") + ar_member("r.rcgu.o", macho(target))


def macho(target, executable=False, address=4096):
    cpu = build.TARGET_ARCH[target][1]
    if not executable:
        return struct.pack("<8I", 0xFEEDFACF, cpu, 0, 1, 0, 0, 0, 0)
    strings = b"\0_sqlite3_libversion\0_sqlite3_sourceid\0"
    first, second = 1, strings.index(b"_sqlite3_sourceid")
    header = struct.pack("<8I", 0xFEEDFACF, cpu, 0, 2, 1, 24, 0, 0)
    table = struct.pack("<6I", 2, 24, 56, 2, 88, len(strings))
    symbols = struct.pack("<IBBHQ", first, 0xF, 1, 0, address) + struct.pack("<IBBHQ", second, 0xF, 1, 0, address + 16)
    return header + table + symbols + strings + VERSION.encode() + b"\0" + SOURCE_ID.encode() + b"\0"


def fat(slices):
    offset = 48
    entries, data = [], b""
    for target in native.TARGETS:
        payload = slices[target]
        entries.append(struct.pack(">5I", build.TARGET_ARCH[target][1], 0, offset, len(payload), 0))
        data += payload
        offset += len(payload)
    return b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"".join(entries) + data


def metadata():
    names = [("sqlx", "sqlite-unbundled", "0.8.6"), ("sqlx-sqlite", "unbundled", "0.8.6"), ("libsqlite3-sys", "buildtime_bindgen", "0.30.1")]
    return {"packages": [{"id": name, "name": name, "version": version, "source": "registry+https://github.com/rust-lang/crates.io-index"} for name, _, version in names],
            "resolve": {"nodes": [{"id": name, "features": [feature]} for name, feature, _ in names]}}


class NativeBuildEvidenceTests(unittest.TestCase):
    """Synthetic binary/receipt fixtures test rejection rules, not production linkage."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.descriptor = descriptor()
        self.target = native.TARGETS[0]
        self.native_paths = {}
        self.linked_paths = {}
        for target in native.TARGETS:
            self.make_native(target)
            self.make_linked(target)

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def json(self, path, value):
        return self.write(path, (json.dumps(value, sort_keys=True) + "\n").encode())

    def make_native(self, target):
        directory = self.root / target
        for name, content in source_contents().items():
            self.write(directory / "include" / name, content)
        obj = macho(target)
        self.write(directory / "sqlite3.o", obj)
        self.write(directory / "libsqlite3.a", ar(obj))
        tools = {"clang": {"path": "/tool/clang", "size": 1, "sha256": "c" * 64}, "ar": {"path": "/tool/ar", "size": 1, "sha256": "d" * 64}, "sdk": {"path": "/SDK", "settings_sha256": "e" * 64}}
        proof = {"schema_version": 1, "scope": build.NATIVE_SCOPE, "target": target,
                 "descriptor_sha256": native.descriptor_sha256(self.descriptor), "source_sha256": SOURCE_SHA, "lock_sha256": LOCK_SHA,
                 "helper_sha256": build.sha(Path(build.__file__).read_bytes()), "tools": tools,
                 "commands": build._commands(self.descriptor, target, directory, tools), "build_directory": str(directory),
                 "environment": {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "ZERO_AR_DATE": "1", "TMPDIR": str(directory / "tmp")},
                 "files": {name: build._record(self.root, directory / name) for name in ("include/sqlite3.c", "include/sqlite3.h", "sqlite3.o", "libsqlite3.a")}}
        self.native_paths[target] = self.json(directory / "native-build.json", proof)

    def make_linked(self, target):
        directory = self.root / target
        self.write(directory / "sys.rlib", rlib(target))
        self.write(directory / "geph", macho(target, True))
        self.json(directory / "metadata.json", metadata())
        self.write(directory / "sys-output", f"cargo:rustc-link-lib=static=sqlite3\ncargo:rustc-link-search={directory}\n".encode())
        self.write(directory / "map", f"# Path: {directory}/geph\n# Arch: {build.TARGET_ARCH[target][0]}\n# Object files:\n[ 1] {directory}/sys.rlib(sqlite3.o)\n# Symbols:\n0x1000 0x10 [ 1] _sqlite3_libversion\n0x1010 0x10 [ 1] _sqlite3_sourceid\n".encode())
        path = self.root / (target + "-linked.json")
        files = {"rlib": directory / "sys.rlib", "binary": directory / "geph", "sys_build_output": directory / "sys-output", "link_map": directory / "map", "cargo_metadata": directory / "metadata.json"}
        build.seal_linked_target(self.descriptor, self.native_paths[target], self.root, SOURCE_SHA, LOCK_SHA, files, str(directory / "geph"), str(directory / "sys.rlib"), path)
        self.linked_paths[target] = path

    def verify(self):
        return build.verify_linked_target(self.descriptor, self.linked_paths[self.target], self.root, SOURCE_SHA, LOCK_SHA)

    def update_linked_file(self, name, content):
        path = self.linked_paths[self.target]
        proof = json.loads(path.read_text())
        artifact = self.root / proof["files"][name]["path"]
        artifact.write_bytes(content)
        proof["files"][name] = build._record(self.root, artifact)
        self.json(path, proof)

    def test_scopes_and_real_artifact_bindings(self):
        proof = self.verify()
        self.assertEqual(proof["scope"], build.LINKED_SCOPE)
        self.assertEqual(proof["identity"]["sqlite_identity_addresses"]["_sqlite3_sourceid"], 4112)
        with self.assertRaises(ValueError):
            build.verify_linked_target(self.descriptor, self.native_paths[self.target], self.root, SOURCE_SHA, LOCK_SHA)

    def test_wrong_source_lock_and_descriptor_fail(self):
        for source, lock in [("f" * 64, LOCK_SHA), (SOURCE_SHA, "f" * 64)]:
            with self.subTest(source=source, lock=lock), self.assertRaises(ValueError):
                build.verify_linked_target(self.descriptor, self.linked_paths[self.target], self.root, source, lock)

    def test_feature_closure_happy_and_wrong_edges(self):
        self.assertEqual(len(build.validate_feature_closure(metadata(), self.descriptor)), 3)
        for feature in ("bundled", "bundled-sqlcipher", "loadable_extension", "in_gecko", "sqlcipher"):
            value = metadata()
            value["resolve"]["nodes"][2]["features"].append(feature)
            with self.subTest(feature=feature), self.assertRaises(ValueError):
                build.validate_feature_closure(value, self.descriptor)
        value = metadata()
        value["resolve"]["nodes"][0]["features"].append("sqlite")
        with self.assertRaises(ValueError):
            build.validate_feature_closure(value, self.descriptor)
        for change in ("missing", "duplicate", "path"):
            value = metadata()
            if change == "missing": value["resolve"]["nodes"].pop()
            elif change == "duplicate": value["packages"].append(value["packages"][-1])
            else: value["packages"][-1]["source"] = None
            with self.subTest(change=change), self.assertRaises(ValueError):
                build.validate_feature_closure(value, self.descriptor)

    def test_changed_bytes_and_symlink_rejected(self):
        path = self.root / self.target / "sqlite3.o"
        original = path.read_bytes()
        path.write_bytes(original + b"changed")
        with self.assertRaises(ValueError): self.verify()
        path.unlink()
        other = self.write(self.root / "other.o", original)
        path.symlink_to(other)
        with self.assertRaises(ValueError): self.verify()

    def test_missing_archive_rejected_even_with_host_library_available(self):
        (self.root / self.target / "libsqlite3.a").unlink()
        with self.assertRaises((ValueError, FileNotFoundError)): self.verify()

    def test_extra_search_path_and_dynamic_link_rejected(self):
        for text in (f"cargo:rustc-link-lib=static=sqlite3\ncargo:rustc-link-search={self.root/self.target}\ncargo:rustc-link-search=/usr/lib\n",
                     f"cargo:rustc-link-lib=sqlite3\ncargo:rustc-link-search={self.root/self.target}\n"):
            self.update_linked_file("sys_build_output", text.encode())
            with self.assertRaises(ValueError): self.verify()

    def test_swapped_rlib_and_architecture_rejected(self):
        self.update_linked_file("rlib", rlib(self.target, macho(self.target) + b"different"))
        with self.assertRaises(ValueError): self.verify()
        self.update_linked_file("rlib", rlib(self.target))
        self.update_linked_file("binary", macho(native.TARGETS[1], True))
        with self.assertRaises(ValueError): self.verify()

    def test_mixed_link_map_binary_and_old_source_id_rejected(self):
        self.update_linked_file("binary", macho(self.target, True, address=8192))
        with self.assertRaisesRegex(ValueError, "address"): self.verify()
        self.update_linked_file("binary", macho(self.target, True).replace(SOURCE_ID.encode(), b"x" * len(SOURCE_ID)))
        with self.assertRaisesRegex(ValueError, "source ID"): self.verify()

    def test_map_cannot_use_dead_or_foreign_member(self):
        proof = json.loads(self.linked_paths[self.target].read_text())
        original = (self.root / proof["files"]["link_map"]["path"]).read_bytes()
        for bad in (original.replace(b"# Symbols:", b"# Dead Stripped Symbols:"), original.replace(b"sys.rlib(sqlite3.o)", b"other.rlib(sqlite3.o)")):
            self.update_linked_file("link_map", bad)
            with self.assertRaises(ValueError): self.verify()

    def test_unrecognized_map_member_preserves_exact_bounded_diagnostics(self):
        proof = json.loads(self.linked_paths[self.target].read_text())
        original = (self.root / proof["files"]["link_map"]["path"]).read_bytes()
        bad = original.replace(b"sys.rlib(sqlite3.o)", b"sys.rlib(unknown-sqlite3.o)")
        self.update_linked_file("link_map", bad)
        with self.assertRaises(ValueError) as failure:
            self.verify()
        detail = json.loads(str(failure.exception).split("once: ", 1)[1])
        self.assertEqual(detail["expected"], str(self.root / self.target / "sys.rlib") + "(sqlite3.o)")
        self.assertEqual(detail["matches"], 0)
        self.assertEqual(detail["relevant_rows"], [["1", str(self.root / self.target / "sys.rlib") + "(unknown-sqlite3.o)"]])

    def test_xcode15_map_archive_annotation_keeps_exact_linkage(self):
        # Captured from CI 38371930625: Apple ld-1053.12 adds [5] between
        # the exact archive path and member; ld-1267 omits that annotation.
        original = (self.root / self.target / "map").read_bytes()
        annotated = original.replace(b"sys.rlib(sqlite3.o)", b"sys.rlib[5](sqlite3.o)")
        self.update_linked_file("link_map", annotated)
        self.assertEqual(self.verify()["scope"], build.LINKED_SCOPE)
        # Annotation support must not bypass the existing actual-binary check.
        self.update_linked_file("binary", macho(self.target, True, address=8192))
        with self.assertRaisesRegex(ValueError, "address"):
            self.verify()

    def test_archive_annotation_cannot_hide_foreign_or_malformed_member(self):
        original = (self.root / self.target / "map").read_bytes()
        for spelling in (b"other.rlib[5](sqlite3.o)", b"sys.rlib[5](other.o)",
                         b"sys.rlib[](sqlite3.o)", b"sys.rlib[-5](sqlite3.o)",
                         b"sys.rlib[5x](sqlite3.o)", b"sys.rlib[5][5](sqlite3.o)",
                         b"sys.rlib[5](sqlite3.o).other", b"sys.rlib [5](sqlite3.o)",
                         b"sysXrlib[5](sqlite3.o)", b"sys.rlib[5.0](sqlite3.o)",
                         "sys.rlib[５](sqlite3.o)".encode()):
            with self.subTest(spelling=spelling):
                self.update_linked_file("link_map", original.replace(b"sys.rlib(sqlite3.o)", spelling))
                with self.assertRaisesRegex(ValueError, "exact sys rlib native member once"):
                    self.verify()

    def test_annotated_and_plain_member_duplicates_rejected(self):
        original = (self.root / self.target / "map").read_bytes()
        for index in (1, 2):
            with self.subTest(index=index):
                extra = f"[ {index}] {self.root / self.target}/sys.rlib[5](sqlite3.o)\n".encode()
                self.update_linked_file("link_map", original.replace(b"# Symbols:\n", extra + b"# Symbols:\n"))
                with self.assertRaisesRegex(ValueError, "exact sys rlib native member once"):
                    self.verify()

    def test_numeric_object_index_alias_duplicates_rejected(self):
        original = (self.root / self.target / "map").read_bytes()
        for index in ("01", "001"):
            with self.subTest(index=index):
                extra = f"[ {index}] {self.root / self.target}/foreign.rcgu.o\n".encode()
                self.update_linked_file("link_map", original.replace(b"# Symbols:\n", extra + b"# Symbols:\n"))
                with self.assertRaisesRegex(ValueError, "exact sys rlib native member once"):
                    self.verify()

    def test_environment_strips_inherited_native_overrides(self):
        env = build.cargo_environment(self.descriptor, self.native_paths[self.target], self.root, SOURCE_SHA, LOCK_SHA,
                                     {"HOME": "/home", "PKG_CONFIG_PATH": "/host", "CARGO_ENCODED_RUSTFLAGS": "bad", "CFLAGS": "bad", "DYLD_LIBRARY_PATH": "bad", "SQLITE3_LIB_DIR": "/host"})
        self.assertEqual(env["HOME"], "/home")
        self.assertEqual(env["SQLITE3_NO_PKG_CONFIG"], "1")
        self.assertEqual(env["SQLITE3_STATIC"], "1")
        self.assertEqual(env["SQLITE3_LIB_DIR"], str(self.root / self.target))
        self.assertFalse({"PKG_CONFIG_PATH", "CARGO_ENCODED_RUSTFLAGS", "CFLAGS", "DYLD_LIBRARY_PATH"} & env.keys())

    def release(self):
        binary = self.write(self.root / "geph-universal", fat({target: (self.root / target / "geph").read_bytes() for target in native.TARGETS}))
        proof = {"schema_version": 1, "scope": "linked-macos-universal", "source_sha256": SOURCE_SHA, "lock_sha256": LOCK_SHA,
                 "descriptor_sha256": native.descriptor_sha256(self.descriptor), "targets": native.TARGETS.copy(),
                 "linked_receipts": {target: build._record(self.root, path) for target, path in self.linked_paths.items()}, "final_binary": build._record(self.root, binary)}
        return self.json(self.root / "release.json", proof)

    def test_universal_requires_both_exact_proved_slices(self):
        path = self.release()
        proof = build.verify_release_evidence(self.descriptor, path, self.root, SOURCE_SHA, LOCK_SHA)
        self.assertEqual(proof["scope"], "linked-macos-universal")
        value = json.loads(path.read_text())
        binary = self.root / value["final_binary"]["path"]
        binary.write_bytes(fat({target: macho(target, True, address=8192) for target in native.TARGETS}))
        value["final_binary"] = build._record(self.root, binary)
        self.json(path, value)
        with self.assertRaisesRegex(ValueError, "slice differs"):
            build.verify_release_evidence(self.descriptor, path, self.root, SOURCE_SHA, LOCK_SHA)

    def test_malformed_archive_and_universal_fail(self):
        for payload in (b"!<arch>\nBAD", ar(macho(self.target)) + ar_member("sqlite3.o", b"duplicate"), ar(macho(self.target))[:-1]):
            with self.subTest(archive=len(payload)), self.assertRaises(ValueError): build.archive_members(payload)
        data = fat({target: macho(target, True) for target in native.TARGETS})
        for payload in (data + b"tail", data[:4] + struct.pack(">I", 1) + data[8:], data[:28] + struct.pack(">I", build.TARGET_ARCH[self.target][1]) + data[32:]):
            with self.subTest(universal=len(payload)), self.assertRaises(ValueError): build.universal_slices(payload)

    def test_gnu_ar_name_table_and_bsd_names(self):
        def raw_member(name, payload):
            header = f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(payload):<10}`\n".encode()
            return header + payload + (b"\n" if len(payload) % 2 else b"")
        payload = b"!<arch>\n" + raw_member("//", b"long-rust-file.rcgu.o/\n") + raw_member("/0", b"object")
        self.assertEqual(build.archive_members(payload), {"long-rust-file.rcgu.o": b"object"})
        name = b"sqlite3.o\0\0\0"
        payload = b"!<arch>\n" + raw_member("#1/12", name + b"object")
        self.assertEqual(build.archive_members(payload), {"sqlite3.o": b"object"})
        with self.assertRaises(ValueError): build.archive_members(b"!<arch>\n" + raw_member("/20", b"bad"))

    def test_duplicate_rust_locals_allowed_but_identity_ambiguous_rejected(self):
        original = macho(self.target, True)
        strsize = struct.unpack_from("<I", original, 52)[0]
        strings = original[88:88 + strsize] + b"repeated_local\0"
        header = original[:32]
        table = struct.pack("<6I", 2, 24, 56, 4, 120, len(strings))
        locals_ = struct.pack("<IBBHQ", strsize, 0xE, 1, 0, 5000) + struct.pack("<IBBHQ", strsize, 0xE, 1, 0, 6000)
        value = header + table + original[56:88] + locals_ + strings
        self.assertTrue(build.macho(value, self.target, executable=True)["sqlite_identity_symbols_defined"])
        duplicate = bytearray(value)
        struct.pack_into("<I", duplicate, 88, 1)
        duplicate[92] = 0xF
        with self.assertRaisesRegex(ValueError, "duplicate SQLite"):
            build.macho(bytes(duplicate), self.target, executable=True)
        local_identity = bytearray(value)
        local_identity[60] = 0xE
        with self.assertRaisesRegex(ValueError, "must be global"):
            build.macho(bytes(local_identity), self.target, executable=True)

    def test_plain_native_archive_cannot_masquerade_as_sys_rlib(self):
        self.update_linked_file("rlib", ar(macho(self.target)))
        with self.assertRaisesRegex(ValueError, "not a Rust rlib"): self.verify()

    @unittest.skipUnless(sys.platform == "darwin", "Apple native build boundary")
    def test_actual_clang_build_is_archived_and_stale_output_rejected(self):
        try:
            self._actual_native_fixture()
        except unittest.SkipTest:
            raise
        except Exception:
            # TemporaryDirectory cleanup must not erase the only failing
            # linker map. Persist this public toy fixture; log bounded facts
            # too, since an ephemeral CI runner may not upload its output/.
            base = Path(__file__).resolve().parents[1] / "output/sqlite-native-test-failures"
            base.mkdir(parents=True, exist_ok=True)
            retained = Path(tempfile.mkdtemp(prefix="apple-link-", dir=base))
            actual = self.root / "actual"
            if actual.is_dir():
                shutil.copytree(actual, retained / "actual")
            report = {"retained_fixture": str(retained), "toolchain": {}}
            for name, argv in (("clang", ["/usr/bin/xcrun", "clang", "--version"]),
                               ("ld", ["/usr/bin/xcrun", "ld", "-v"]),
                               ("rustc", [shutil.which("rustc") or "rustc", "-Vv"])):
                try:
                    proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
                    report["toolchain"][name] = (proc.stdout + proc.stderr)[:2048]
                except (OSError, subprocess.TimeoutExpired) as exc:
                    report["toolchain"][name] = str(exc)[:512]
            mp = actual / self.target / "map"
            if mp.is_file():
                report["map_excerpt"] = mp.read_text()[:8192]
            (retained / "diagnostics.json").write_text(json.dumps(report, indent=2) + "\n")
            print("Native SQLite linker fixture failure: " + json.dumps(report, sort_keys=True), file=sys.stderr)
            raise

    def _actual_native_fixture(self):
        # Tiny public fixture proves compiler/archiver plumbing only, not Geph.
        if not Path("/usr/bin/xcrun").is_file() or not shutil.which("rustc"):
            self.skipTest("Apple developer tools and rustc required")
        source = self.root / "source"
        for name, data in source_contents().items(): self.write(source / native.PATH / name, data)
        lock = self.write(source / "Cargo.lock", LOCK)
        out = self.root / "actual"
        out.mkdir()
        try:
            tools = {name: Path(subprocess.check_output(["/usr/bin/xcrun", "--find", name], text=True, stderr=subprocess.PIPE).strip()).resolve() for name in ("clang", "ar")}
            tools["sdk"] = Path(subprocess.check_output(["/usr/bin/xcrun", "--show-sdk-path"], text=True, stderr=subprocess.PIPE).strip()).resolve()
        except subprocess.CalledProcessError:
            self.skipTest("Apple compiler/SDK unavailable")
        result = build.build_native(self.descriptor, source, out, self.target, SOURCE_SHA, lock, tools)
        self.assertEqual(result["scope"], build.NATIVE_SCOPE)
        obj = (out / self.target / "sqlite3.o").read_bytes()
        self.assertEqual(build.archive_members((out / self.target / "libsqlite3.a").read_bytes())["sqlite3.o"], obj)
        with self.assertRaises(FileExistsError): build.build_native(self.descriptor, source, out, self.target, SOURCE_SHA, lock, tools)
        # Actual Apple linker map/Mach-O compatibility. The wrapper metadata and
        # sys stdout below are explicit fixtures; this is not a Cargo/Geph run.
        directory = out / self.target
        rlib = directory / "sys.rlib"
        rust_source = self.write(directory / "lib.rs", b'#[link(name="sqlite3", kind="static")] extern "C" { pub fn sqlite3_libversion() -> *const u8; } pub fn marker() -> u32 { 1 }\n')
        subprocess.run([shutil.which("rustc"), "--edition", "2021", "--crate-type", "rlib", "--crate-name", "libsqlite3_sys", "--target", self.target, "-L", "native=" + str(directory), str(rust_source), "-o", str(rlib)], check=True, capture_output=True, timeout=30)
        main = self.write(directory / "main.c", b'extern const char *sqlite3_libversion(void); extern const char *sqlite3_sourceid(void); int main(void) { return !*sqlite3_libversion() || !*sqlite3_sourceid(); }\n')
        binary, linkmap = directory / "geph", directory / "map"
        subprocess.run([str(tools["clang"]), "-arch", "arm64", "-isysroot", str(tools["sdk"]), "-mmacosx-version-min=11.0", str(main), str(rlib), "-Wl,-map," + str(linkmap), "-o", str(binary)], check=True, capture_output=True, timeout=30)
        files = {"rlib": rlib, "binary": binary, "link_map": linkmap,
                 "cargo_metadata": self.json(directory / "metadata.json", metadata()),
                 "sys_build_output": self.write(directory / "sys-output", f"cargo:rustc-link-lib=static=sqlite3\ncargo:rustc-link-search={directory}\n".encode())}
        build.seal_linked_target(self.descriptor, directory / "native-build.json", out, SOURCE_SHA, LOCK_SHA, files, str(binary), str(rlib), out / "linked.json")


if __name__ == "__main__":
    unittest.main()

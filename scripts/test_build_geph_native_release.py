"""Synthetic command-driver contracts; these do not compile or qualify Geph."""
from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import zipfile

import build_geph_native_release as producer
import geph_native_sqlite as native
import geph_native_sqlite_build as link
from test_geph_native_sqlite_build import descriptor, source_contents, macho, rlib, ar, fat, metadata

WRAPPER_ID = "registry+https://github.com/rust-lang/crates.io-index#libsqlite3-sys@0.30.1"


class ProducerCommandDriverTests(unittest.TestCase):
    """Real validators/materializer and synthetic compiler outputs, never real Geph."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.paths = {}
        for name in ("cargo", "rustc", "python", "clang", "ar", "lipo"):
            path = self.root / name
            path.write_bytes(b"synthetic command driver\n")
            path.chmod(0o755)
            self.paths[name] = path
        sdk = self.root / "SDK"
        sdk.mkdir()
        (sdk / "SDKSettings.json").write_text("{}")
        self.paths["sdk"] = sdk
        self.paths["libclang"] = self.root / "libclang.dylib"
        self.paths["libclang"].write_bytes(b"synthetic libclang")
        self.cargo_home = self.root / "cargo-cache"
        self.cargo_home.mkdir()
        self.native_zip = self.root / "sqlite.zip"
        self.descriptor = descriptor()
        with zipfile.ZipFile(self.native_zip, "w") as archive:
            for name, payload in source_contents().items():
                archive.writestr("sqlite-amalgamation-3530200/" + name, payload)
        raw = self.native_zip.read_bytes()
        self.descriptor["archive"].update(size=len(raw), sha256=link.sha(raw))
        self.lock = self.root / "Cargo.lock"
        self.lock.write_text('version = 3\n[[package]]\nname = "libsqlite3-sys"\nversion = "0.30.1"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{native.WRAPPER["sha256"]}"\n')
        self.crate = self.root / "geph.crate"
        with tarfile.open(self.crate, "w:gz") as archive:
            for name, contents in {"Cargo.toml": '[package]\nname="geph5-client"\nversion="0.4.3"\n',
                                   "src/main.rs": "fn main() {}\n"}.items():
                data = contents.encode()
                info = tarfile.TarInfo("geph5-client-0.4.3/" + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        self.source = {"schema_version": 1, "crate": {"name": "geph5-client", "version": "0.4.3",
            "url": "https://static.crates.io/crates/geph5-client/geph5-client-0.4.3.crate", "sha256": link.sha(self.crate.read_bytes())},
            "lock_sha256": link.sha(self.lock.read_bytes()), "features": ["aws_lambda"],
            "targets": native.TARGETS.copy(), "release_revision": 1, "native_sqlite": self.descriptor}
        self.source_path = self.root / "SOURCE.json"
        producer.write_json(self.source_path, self.source)
        self.version = self.root / "VERSION"
        self.version.write_text("0.4.3\n")
        self.output = self.root / "output"
        self.calls, self.mutate = [], lambda stage, value: None

    def write(self, path, payload):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def driver(self, command, *, cwd, env, prefix, timeout, stdout_limit=producer.MAX_LOG):
        self.calls.append((command, env.copy()))
        stage = "native" if "--source-root" in command else command[1]
        self.write(prefix.with_suffix(".stdout"), b"")
        self.write(prefix.with_suffix(".stderr"), b"synthetic compiler warning\n")
        producer.write_json(prefix.with_suffix(".json"), {"command": command, "environment": env})
        if stage == "native":
            target = command[command.index("--target") + 1]
            directory = self.output / "evidence" / target
            directory.mkdir()
            for name, data in source_contents().items():
                self.write(directory / "include" / name, data)
            self.write(directory / "sqlite3.o", macho(target))
            self.write(directory / "libsqlite3.a", ar(macho(target)))
            tools = {name: link._tool(self.paths[name]) for name in ("clang", "ar")}
            tools["sdk"] = {"path": str(self.paths["sdk"]), "settings_sha256": link.sha(b"{}")}
            proof = {"schema_version": 1, "scope": link.NATIVE_SCOPE, "target": target,
                "descriptor_sha256": native.descriptor_sha256(self.descriptor),
                "source_sha256": link.sha(Path(command[command.index("--source") + 1]).read_bytes()),
                "lock_sha256": self.source["lock_sha256"],
                "helper_sha256": link.sha(Path(link.__file__).read_bytes()), "tools": tools,
                "commands": link._commands(self.descriptor, target, directory, tools),
                "environment": {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "ZERO_AR_DATE": "1", "TMPDIR": str(directory / "tmp")},
                "build_directory": str(directory), "files": {name: link._record(self.output / "evidence", directory / name)
                    for name in ("include/sqlite3.c", "include/sqlite3.h", "sqlite3.o", "libsqlite3.a")}}
            producer.write_json(directory / "native-build.json", proof)
        elif stage == "metadata":
            value = metadata()
            source_root = Path(command[command.index("--manifest-path") + 1]).parent
            value["packages"][2]["id"] = value["resolve"]["nodes"][2]["id"] = WRAPPER_ID
            value["packages"].append({"id": "path+file://" + str(source_root) + "#0.4.3", "name": "geph5-client",
                "version": "0.4.3", "source": None, "manifest_path": str(source_root / "Cargo.toml")})
            value["resolve"]["root"] = value["packages"][-1]["id"]
            value["resolve"]["nodes"].append({"id": value["resolve"]["root"], "features": ["aws_lambda"]})
            self.mutate(stage, value)
            self.write(prefix.with_suffix(".stdout"), json.dumps(value).encode())
        elif stage == "rustc":
            target = command[command.index("--target") + 1]
            target_root = Path(env["CARGO_TARGET_DIR"])
            release = target_root / target / "release"
            archive = self.write(release / "deps/liblibsqlite3_sys-abc.rlib", rlib(target))
            hashed = self.write(release / "deps/geph5_client-abc", macho(target, True))
            binary = self.write(release / "geph5-client", hashed.read_bytes())
            out = release / "build/libsqlite3-sys-abc/out"
            out.mkdir(parents=True)
            self.write(out.parent / "output", ("cargo:rustc-link-lib=static=sqlite3\ncargo:rustc-link-search=" + env["SQLITE3_LIB_DIR"] + "\n").encode())
            link_map = self.write(target_root / "geph-link.map", (f"# Path: {hashed}\n# Arch: {link.TARGET_ARCH[target][0]}\n# Object files:\n[ 1] {archive}(sqlite3.o)\n# Symbols:\n0x1000 0x10 [ 1] _sqlite3_libversion\n0x1010 0x10 [ 1] _sqlite3_sourceid\n").encode())
            root_id = "path+file://" + str(Path(command[command.index("--manifest-path") + 1]).parent) + "#0.4.3"
            messages = [
                {"reason": "compiler-artifact", "package_id": WRAPPER_ID, "target": {"name": "libsqlite3_sys", "kind": ["lib"]}, "filenames": [str(archive)]},
                {"reason": "build-script-executed", "package_id": WRAPPER_ID, "out_dir": str(out)},
                {"reason": "compiler-artifact", "package_id": root_id, "target": {"name": "geph5-client", "kind": ["bin"]}, "profile": {"test": False}, "executable": str(binary)},
                {"reason": "build-finished", "success": True},
            ]
            self.mutate(stage, {"messages": messages, "hashed": hashed, "binary": binary,
                                "map": link_map, "archive": archive, "out": out})
            self.write(prefix.with_suffix(".stdout"), b"\n".join(json.dumps(m).encode() for m in messages) + b"\n")
        elif stage == "-create":
            slices = {target: Path(path).read_bytes() for target, path in zip(native.TARGETS, command[4:])}
            final = self.write(Path(command[3]), fat(slices))
            self.mutate("lipo", final)
        else:
            raise AssertionError(command)

    def build(self, **kwargs):
        with mock.patch.object(producer, "run", side_effect=self.driver):
            return producer.build_release(source_path=self.source_path, version_path=self.version,
                lock_path=self.lock, crate_path=self.crate, native_archive=self.native_zip,
                output=self.output, cargo_home=self.cargo_home, tools=self.paths, **kwargs)

    def use_v2(self, pin=None):
        self.descriptor.update(schema_version=2,
            producer_helper_sha256=pin or link.sha(Path(link.__file__).read_bytes()))
        self.source_path.write_text(json.dumps(self.source))

    def test_v2_synthetic_full_pipeline_uses_reviewed_current_helper(self):
        self.use_v2()
        self.assertEqual(self.build()["scope"], "linked-macos-universal")

    def test_v2_wrong_pin_stops_before_output_and_all_commands(self):
        self.use_v2("1" * 64)
        with self.assertRaisesRegex(ValueError, "producer helper"):
            self.build()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.calls)

    def test_v2_source_replacement_after_preflight_keeps_frozen_authority(self):
        self.use_v2()
        reviewed = self.source_path.read_bytes()
        replaced = json.loads(reviewed)
        replaced["native_sqlite"]["producer_helper_sha256"] = "0" * 64
        mkdir = Path.mkdir
        replacements = []
        def swap_after_preflight(path, *args, **kwargs):
            result = mkdir(path, *args, **kwargs)
            if path == self.output:
                self.source_path.write_text(json.dumps(replaced))
                replacements.append(path)
            return result
        with mock.patch.object(Path, "mkdir", swap_after_preflight):
            proof = self.build()
        self.assertEqual(replacements, [self.output])
        self.assertEqual((self.output / "inputs/SOURCE.json").read_bytes(), reviewed)
        self.assertEqual(proof["source_sha256"], link.sha(reviewed))

    def test_synthetic_both_targets_full_pipeline_and_sanitized_commands(self):
        with mock.patch.dict(os.environ, {"RUSTFLAGS": "-C link-arg=bad", "CARGO_BUILD_RUSTC_WRAPPER": "/bad",
                                          "SQLITE3_LIB_DIR": "/bad", "PYTHONPATH": "/bad", "TOKEN": "private"}):
            result = self.build()
        self.assertEqual(result["scope"], "linked-macos-universal")
        self.assertEqual(len(self.calls), 7)
        self.assertTrue((self.output / "producer.json").is_file())
        for command, env in self.calls:
            self.assertNotIn("TOKEN", env)
            self.assertNotIn("RUSTFLAGS", env)
            self.assertNotIn("PYTHONPATH", env)
            self.assertNotIn("CARGO_BUILD_RUSTC_WRAPPER", env)
            self.assertNotIn("/bad", env.values())
            self.assertNotIn("install", command)
            self.assertNotIn("test", command)
            if command[1] in ("metadata", "rustc"):
                self.assertIn("--offline", command)
                self.assertIn("--locked", command)
                self.assertEqual(env["RUSTC"], str(self.paths["rustc"]))
            if command[1] == "rustc":
                self.assertEqual(command[command.index("--jobs") + 1], "2")
                self.assertEqual(command[command.index("--"):command.index("--") + 2], ["--", "-C"])
                self.assertTrue(command[-1].startswith("link-arg=-Wl,-map,"))
            else:
                self.assertNotIn("--jobs", command)

    def test_synthetic_explicit_build_jobs_only_reaches_cargo_rustc(self):
        self.build(jobs=3)
        for command, _ in self.calls:
            if command[1] == "rustc":
                self.assertEqual(command.count("--jobs"), 1)
                self.assertEqual(command[command.index("--jobs") + 1], "3")
            else:
                self.assertNotIn("--jobs", command)

    def test_invalid_build_jobs_rejected_before_commands_or_output(self):
        for jobs in (True, False, 0, -1, 65, 2.0, "2", None):
            with self.subTest(jobs=jobs), self.assertRaisesRegex(ValueError, "build jobs"):
                self.build(jobs=jobs)
            self.assertFalse(self.calls)
            self.assertFalse(self.output.exists())

    def test_stale_output_is_refused_before_commands(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError): self.build()
        self.assertFalse(self.calls)

    def test_wrong_source_lock_or_native_archive_rejected_before_commands(self):
        self.lock.write_text("invalid changed lock")
        with self.assertRaisesRegex(ValueError, "Cargo.lock"): self.build()
        self.assertFalse(self.calls)

    def test_ambient_cargo_configuration_refused(self):
        (self.cargo_home / "config.toml").write_text('[build]\nrustc-wrapper="/bad"')
        with self.assertRaisesRegex(ValueError, "ambient Cargo"): self.build()
        self.assertFalse(self.calls)

    def test_wrong_native_archive_rejected_before_commands(self):
        self.native_zip.write_bytes(self.native_zip.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "archive size/hash"): self.build()
        self.assertFalse(self.calls)

    def test_symlink_tool_rejected_before_commands(self):
        alias = self.root / "cargo-alias"
        alias.symlink_to(self.paths["cargo"])
        self.paths["cargo"] = alias
        with self.assertRaisesRegex(ValueError, "physical paths"): self.build()
        self.assertFalse(self.calls)

    def test_wrong_geph_or_wrapper_metadata_rejected(self):
        def mutate(stage, value):
            if stage == "metadata": value["packages"][-1]["version"] = "0.4.4"
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "root identity"): self.build()

    def test_metadata_feature_closure_rejects_bundled_sqlite(self):
        def mutate(stage, value):
            if stage == "metadata": value["resolve"]["nodes"][2]["features"].append("bundled")
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "unsafe resolved"): self.build()

    def test_path_dependency_outside_materialized_source_rejected(self):
        def mutate(stage, value):
            if stage == "metadata": value["packages"].append({"name": "foreign", "source": None,
                                                               "manifest_path": str(self.version)})
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "escapes"): self.build()

    def test_mismatched_package_id_does_not_select_arbitrary_rlib(self):
        def mutate(stage, value):
            if stage == "rustc": value["messages"][0]["package_id"] = "lookalike"
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "package-matched"): self.build()

    def test_duplicate_matching_artifact_rejected(self):
        def mutate(stage, value):
            if stage == "rustc": value["messages"].insert(1, copy.deepcopy(value["messages"][0]))
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "package-matched"): self.build()

    def test_sys_build_output_must_be_from_exact_target(self):
        def mutate(stage, value):
            if stage == "rustc": value["messages"][1]["out_dir"] = str(self.root)
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "escapes"): self.build()

    def test_symlink_artifact_rejected(self):
        def mutate(stage, value):
            if stage == "rustc":
                original = value["archive"].read_bytes()
                value["archive"].unlink()
                other = self.write(self.root / "other.rlib", original)
                value["archive"].symlink_to(other)
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "escapes"): self.build()

    def test_failed_build_finished_rejected(self):
        def mutate(stage, value):
            if stage == "rustc": value["messages"][-1]["success"] = False
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "finish successfully"): self.build()

    def test_test_artifact_rejected(self):
        def mutate(stage, value):
            if stage == "rustc": value["messages"][2]["profile"]["test"] = True
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "test executable"): self.build()

    def test_link_map_hashed_binary_must_equal_cargo_binary(self):
        def mutate(stage, value):
            if stage == "rustc": value["hashed"].write_bytes(value["hashed"].read_bytes() + b"different")
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "differs from Cargo"): self.build()

    def test_map_binary_accepts_real_linker_opaque_literal_string_bytes(self):
        binary = self.write(self.root / "geph5-client", b"same executable")
        linked = self.write(self.root / "hashed-geph", binary.read_bytes())
        # Bounded line from the real production ARM linker map, 2026-10-13.
        literal = b"0x100BC7EC8\t0x00000004\t[  3] literal string: \x01-\xc0\n"
        path = self.write(self.root / "map", b"# Path: " + str(linked).encode() + b"\n# Symbols:\n" + literal)
        self.assertEqual(producer.map_binary(path, binary, self.root), linked)

    def test_synthetic_pipeline_retains_real_linker_opaque_literal_bytes(self):
        def mutate(stage, value):
            if stage == "rustc":
                with value["map"].open("ab") as handle:
                    handle.write(b"0x100BC7EC8\t0x00000004\t[  3] literal string: \x01-\xc0\n")
        self.mutate = mutate
        self.assertEqual(self.build()["scope"], "linked-macos-universal")

    def test_map_binary_rejects_invalid_utf8_path(self):
        binary = self.write(self.root / "geph5-client", b"same executable")
        path = self.write(self.root / "map", b"# Path: " + str(binary).encode() + b"\xc0\n")
        with self.assertRaises(UnicodeDecodeError):
            producer.map_binary(path, binary, self.root)

    def test_map_binary_rejects_duplicate_path(self):
        binary = self.write(self.root / "geph5-client", b"same executable")
        path = self.write(self.root / "map", (b"# Path: " + str(binary).encode() + b"\n") * 2)
        with self.assertRaisesRegex(ValueError, "exactly one binary"):
            producer.map_binary(path, binary, self.root)

    def test_link_map_path_outside_owned_release_rejected(self):
        def mutate(stage, value):
            if stage == "rustc":
                foreign = self.write(self.root / "foreign-geph", value["binary"].read_bytes())
                value["map"].write_text(value["map"].read_text().replace(str(value["hashed"]), str(foreign)))
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "escapes"): self.build()

    def test_sys_output_must_use_owned_native_archive(self):
        def mutate(stage, value):
            if stage == "rustc": (value["out"].parent / "output").write_text("cargo:rustc-link-lib=sqlite3\n")
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "unexpected linker"): self.build()

    def test_lipo_cannot_modify_proven_slice(self):
        def mutate(stage, value):
            if stage == "lipo":
                payload = value.read_bytes()
                value.write_bytes(payload[:-1] + b"x")
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "slice differs"): self.build()

    def test_source_mutation_during_build_rejected(self):
        def mutate(stage, value):
            if stage == "lipo":
                (self.output / "source/geph5-client-0.4.3/src/main.rs").write_text("modified")
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "source changed"): self.build()
        self.assertFalse((self.output / "evidence/native-release.json").exists())

    def test_input_snapshot_mutation_rejected_before_final_receipt(self):
        def mutate(stage, value):
            if stage == "lipo": (self.output / "inputs/Cargo.lock").write_text("changed")
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "snapshot changed"): self.build()
        self.assertFalse((self.output / "evidence/native-release.json").exists())

    def test_tool_mutation_during_build_rejected(self):
        def mutate(stage, value):
            if stage == "lipo": self.paths["cargo"].write_text("changed")
        self.mutate = mutate
        with self.assertRaisesRegex(ValueError, "tool changed"): self.build()


class ProcessDriverTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.python = str(Path(sys.executable).resolve())

    def run_python(self, code, timeout=5, limit=1024):
        return producer.run([self.python, "-c", code], cwd=self.root,
            env={"PATH": "/usr/bin:/bin"}, prefix=self.root / "command", timeout=timeout, stdout_limit=limit)

    def assert_child_stopped(self, pid):
        deadline = time.monotonic() + 3
        while True:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            # Linux containers may retain an adopted zombie until their init
            # reaps it. No executable process remains in that state.
            stat = Path(f"/proc/{pid}/stat")
            if stat.exists() and stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                return
            if time.monotonic() >= deadline:
                self.fail("owned build descendant is still running")
            time.sleep(0.05)

    def test_stderr_cannot_corrupt_machine_readable_stdout(self):
        self.run_python('import sys; print("{\\"ok\\": true}"); print("warning", file=sys.stderr)')
        self.assertEqual(json.loads((self.root / "command.stdout").read_text()), {"ok": True})
        self.assertEqual((self.root / "command.stderr").read_text().strip(), "warning")

    def test_nonzero_exit_retains_logs_and_receipt(self):
        with self.assertRaisesRegex(RuntimeError, "failed"):
            self.run_python('print("diagnostic"); raise SystemExit(3)')
        self.assertEqual(json.loads((self.root / "command.json").read_text())["returncode"], 3)
        self.assertIn("diagnostic", (self.root / "command.stdout").read_text())

    def test_excess_output_refused(self):
        with self.assertRaisesRegex(RuntimeError, "output limit"):
            self.run_python('print("x" * 2048)', limit=100)
        self.assertLessEqual((self.root / "command.stdout").stat().st_size, 100)

    def test_timeout_kills_owned_child_process(self):
        child = self.root / "child.pid"
        code = f'import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); open({str(child)!r},"w").write(str(p.pid)); time.sleep(60)'
        with self.assertRaisesRegex(RuntimeError, "timeout"):
            self.run_python(code, timeout=0.3)
        pid = int(child.read_text())
        self.assert_child_stopped(pid)

    def test_invalid_timeout_does_not_start_process(self):
        for timeout in (0, -1, float("nan"), float("inf"), 7201):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.run_python("raise Exception('must not run')", timeout=timeout)

    def test_successful_launcher_cannot_leave_child_running(self):
        child = self.root / "child.pid"
        code = f'import subprocess,sys; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); open({str(child)!r},"w").write(str(p.pid))'
        self.run_python(code)
        pid = int(child.read_text())
        self.assert_child_stopped(pid)


if __name__ == "__main__":
    unittest.main()

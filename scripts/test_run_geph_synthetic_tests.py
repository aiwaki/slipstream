from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import geph_native_sqlite as native
import geph_native_sqlite_build as link
import run_geph_synthetic_tests as runner
from test_geph_native_sqlite_build import descriptor, source_contents, macho, ar, metadata

ROOT = Path(__file__).resolve().parents[1]


class SyntheticRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        (self.source / "src").mkdir(parents=True)
        for name in ("lib", "session", "database"):
            (self.source / f"src/{name}.rs").write_text("// synthetic fixture\n")
        self.contract = self.root / "SOURCE.json"
        self.evidence = self.root / "evidence"
        self.configure("0.3.9")

    def configure(self, version):
        (self.source / "Cargo.toml").write_text(
            f'[package]\nname="geph5-client"\nversion="{version}"\n')
        (self.source / "Cargo.lock").write_text("synthetic lock\n")
        contract = json.loads((ROOT / "vendor/geph/SOURCE.json").read_text())
        contract["crate"]["version"] = version
        contract["crate"]["url"] = f"https://static.crates.io/crates/geph5-client/geph5-client-{version}.crate"
        contract["lock_sha256"] = runner.digest(self.source / "Cargo.lock")
        contract["source_edits"] = []
        self.contract.write_text(json.dumps(contract))

    def orchestration(self, version="0.3.9", fault=None):
        self.configure(version)
        self.commands = []
        expected = runner.ALLOWLIST.get(version, ())

        def fake_run(command, *, cwd, env, timeout, log, log_limit=1024 * 1024):
            self.commands.append(command)
            if "cargo" == command[0]:
                self.assertIn("--no-run", command)
                self.assertIn("--locked", command)
                self.assertIn("--lib", command)
                if fault == "compile-exit":
                    raise runner.QualificationError("synthetic compile failure")
                target = Path(command[command.index("--target-dir") + 1])
                self.executable = target / "geph5_client-fixture"
                self.executable.write_text("never executed\n")
                artifact = {"reason": "compiler-artifact", "profile": {"test": True},
                            "target": {"name": "geph5_client", "src_path": str(self.source / "src/lib.rs")},
                            "executable": str(self.executable)}
                if fault == "outside-binary":
                    artifact["executable"] = sys.executable
                log.write_text(json.dumps(artifact) + "\n")
            else:
                self.assertEqual(command[:1], [str(runner.SANDBOX)])
                self.assertNotIn("SLIPSTREAM_GEPH_ACCOUNT_SECRET", env)
                self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
                if "--list" in command:
                    tests = expected[:-1] if fault == "missing-case" else expected
                    log.write_text("\n".join(name + ": test" for name in tests) +
                                   "\ntests::test_clib: test\n")
                else:
                    self.assertEqual(command[3], str(self.executable))
                    name = command[4]
                    self.assertIn(name, expected)
                    self.assertEqual(command[5:], ["--exact", "--test-threads=1", "--nocapture"])
                    if fault == "case-exit":
                        raise runner.QualificationError("fixture failure")
                    count = 0 if fault == "zero-pass" else 1
                    log.write_text(f"running {count} test\ntest {name} ... ok\n"
                                   f"test result: ok. {count} passed; 0 failed; 0 ignored; "
                                   "0 measured; 20 filtered out; finished in 0.01s\n")
            return {"returncode": 0}

        with mock.patch.object(runner.sys, "platform", "darwin"), \
             mock.patch.object(runner, "SANDBOX", Path(sys.executable)), \
             mock.patch.object(runner, "sandbox_selftest") as probe, \
             mock.patch.object(runner, "run_command", side_effect=fake_run), \
             mock.patch.dict(os.environ, {"SLIPSTREAM_GEPH_ACCOUNT_SECRET": "must-not-propagate",
                                          "DYLD_INSERT_LIBRARIES": "must-not-propagate"}):
            if fault == "probe":
                probe.side_effect = runner.QualificationError("denial probe failed")
            return runner.qualify(self.source, self.contract, self.evidence)

    def test_workflow_never_executes_unfiltered_libtest(self):
        workflow = (ROOT / ".github/workflows/build-geph.yml").read_text()
        self.assertNotIn('cargo test --manifest-path "$source_root/Cargo.toml"', workflow)
        self.assertIn("python3 scripts/run_geph_synthetic_tests.py", workflow)
        self.assertIn('--source-root "$source_root"', workflow)

    def test_reviewed_versions_execute_exact_nine_and_nineteen_only(self):
        for version, count in (("0.3.9", 9), ("0.4.3", 19)):
            with self.subTest(version=version):
                self.evidence = self.root / version
                result = self.orchestration(version)
                self.assertEqual(result["status"], "passed")
                self.assertEqual(len(result["passed_tests"]), count)
                self.assertEqual(len(self.commands), count + 2)
                self.assertFalse(any("tests::test_clib" in cmd for cmd in self.commands))

    def test_failures_prevent_further_execution_and_retain_failed_status(self):
        for fault, calls in (("probe", 0), ("compile-exit", 1), ("outside-binary", 1), ("missing-case", 2),
                             ("case-exit", 3), ("zero-pass", 3)):
            with self.subTest(fault=fault):
                self.evidence = self.root / fault
                with self.assertRaises(runner.QualificationError):
                    self.orchestration(fault=fault)
                self.assertEqual(len(self.commands), calls)
                evidence = json.loads((self.evidence / "summary.json").read_text())
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(evidence["passed_tests"], [])

    def test_unknown_version_and_lock_mismatch_fail_before_execution(self):
        with self.assertRaisesRegex(runner.QualificationError, "no reviewed"):
            self.orchestration("0.5.0")
        self.assertEqual(self.commands, [])
        self.configure("0.3.9")
        (self.source / "Cargo.lock").write_text("different")
        with self.assertRaisesRegex(runner.QualificationError, "lock differs"):
            runner.reviewed_tests(self.source, self.contract)

    def test_unavailable_sandbox_fails_before_compilation(self):
        with mock.patch.object(runner.sys, "platform", "linux"), \
             mock.patch.object(runner, "run_command") as command:
            with self.assertRaisesRegex(runner.QualificationError, "sandbox-exec is required"):
                runner.qualify(self.source, self.contract, self.evidence)
            command.assert_not_called()

    def test_discovery_rejects_missing_ambiguous_and_symlink_escaped_artifacts(self):
        target = self.root / "target"
        target.mkdir()
        executable = target / "test-bin"
        executable.write_text("synthetic")
        artifact = {"reason": "compiler-artifact", "profile": {"test": True},
                    "target": {"name": "geph5_client", "src_path": str(self.source / "src/lib.rs")},
                    "executable": str(executable)}
        log = self.root / "compile.log"
        log.write_text("")
        with self.assertRaisesRegex(runner.QualificationError, "exactly one"):
            runner.compiled_binary(log, self.source, target)
        another = target / "second-bin"
        another.write_text("synthetic")
        log.write_text(json.dumps(artifact) + "\n" + json.dumps(dict(artifact, executable=str(another))))
        with self.assertRaisesRegex(runner.QualificationError, "exactly one"):
            runner.compiled_binary(log, self.source, target)
        executable.unlink()
        executable.symlink_to(sys.executable)
        log.write_text(json.dumps(artifact))
        with self.assertRaisesRegex(runner.QualificationError, "outside the owned target"):
            runner.compiled_binary(log, self.source, target)

    def test_positive_oracle_rejects_zero_ignored_wrong_name_or_failed_case(self):
        log = self.root / "case.log"
        for text in (
            "test expected ... ok\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 21 filtered out;",
            "test expected ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 20 filtered out;",
            "test other ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out;",
            "test expected ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 20 filtered out;",
        ):
            with self.subTest(text=text):
                log.write_text("running 1 test\n" + text)
                with self.assertRaises(runner.QualificationError):
                    runner.require_single_pass(log, "expected")

    def test_positive_oracle_rejects_duplicate_summaries(self):
        log = self.root / "case.log"
        single = ("running 1 test\ntest expected ... ok\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out;\n")
        log.write_text(single)
        runner.require_single_pass(log, "expected")
        log.write_text(single + single)
        with self.assertRaises(runner.QualificationError):
            runner.require_single_pass(log, "expected")


class NativeSyntheticRunnerTests(unittest.TestCase):
    """Actual validators and tiny command outputs; no Cargo/compiler execution."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source, self.evidence = self.root / "source", self.root / "evidence"
        (self.source / "src").mkdir(parents=True)
        for name in ("lib", "session", "database"):
            (self.source / f"src/{name}.rs").write_text("// fixture, never compiled\n")
        (self.source / "Cargo.toml").write_text('[package]\nname="geph5-client"\nversion="0.4.3"\n')
        (self.source / "Cargo.lock").write_text('version = 3\n[[package]]\nname = "libsqlite3-sys"\n'
            'version = "0.30.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{native.WRAPPER["sha256"]}"\n')
        self.descriptor = descriptor()
        self.descriptor.update(schema_version=2, producer_helper_sha256="4" * 64)
        for name, data in source_contents().items():
            self.write(self.source / native.PATH / name, data)
        self.contract_value = {"schema_version": 1, "crate": {"name": "geph5-client", "version": "0.4.3",
            "url": "https://static.crates.io/crates/geph5-client/geph5-client-0.4.3.crate", "sha256": "a" * 64},
            "lock_sha256": runner.digest(self.source / "Cargo.lock"), "features": ["aws_lambda"],
            "targets": native.TARGETS[:], "release_revision": 1, "native_sqlite": self.descriptor}
        self.contract = self.root / "SOURCE.json"
        self.contract.write_text(json.dumps(self.contract_value))
        self.tools = {}
        for name in ("cargo", "rustc", "clang", "ar", "cmake"):
            self.tools[name] = self.write(self.root / "tools" / name, f"fake {name}\n".encode())
            self.tools[name].chmod(0o755)
        self.tools["sdk"] = self.root / "SDK"
        self.write(self.tools["sdk"] / "SDKSettings.json", b"{}")
        self.tools["libclang"] = self.write(self.root / "libclang.dylib", b"fake libclang\n")
        self.cargo_home = self.root / "cargo-home"
        self.cargo_home.mkdir()
        self.artifacts = self.root / "native-artifacts"
        self.artifacts.mkdir()
        self.make_receipt(native.TARGETS[0])
        self.calls, self.fault = [], None

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def make_receipt(self, target):
        directory = self.artifacts / target
        for name, data in source_contents().items():
            self.write(directory / "include" / name, data)
        self.write(directory / "sqlite3.o", macho(target))
        self.write(directory / "libsqlite3.a", ar(macho(target)))
        tools = {name: link._tool(self.tools[name]) for name in ("clang", "ar")}
        tools["sdk"] = {"path": str(self.tools["sdk"]), "settings_sha256": link.sha(b"{}")}
        self.proof = {"schema_version": 1, "scope": link.NATIVE_SCOPE, "target": target,
            "descriptor_sha256": native.descriptor_sha256(self.descriptor),
            "source_sha256": runner.digest(self.contract), "lock_sha256": self.contract_value["lock_sha256"],
            "helper_sha256": self.descriptor["producer_helper_sha256"], "tools": tools,
            "commands": link._commands(self.descriptor, target, directory, tools),
            "environment": {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "ZERO_AR_DATE": "1", "TMPDIR": str(directory / "tmp")},
            "build_directory": str(directory), "files": {name: link._record(self.artifacts, directory / name)
                for name in ("include/sqlite3.c", "include/sqlite3.h", "sqlite3.o", "libsqlite3.a")}}
        self.receipt = directory / "native-build.json"
        self.receipt.write_text(json.dumps(self.proof))

    def cargo_driver(self, command, *, cwd, env, prefix, timeout, stdout_limit):
        self.assertEqual(command[:3], [str(runner.SANDBOX), "-p", runner.COMPILE_PROFILE])
        self.assertEqual(command[3], str(self.tools["cargo"]))
        stage = command[4]
        self.calls.append((stage, command, env.copy()))
        self.assertNotEqual(cwd, self.source)
        self.assertEqual(cwd, Path(env["HOME"]))
        self.assertEqual(env["PATH"], "/usr/bin:/bin")
        self.assertEqual(env["CARGO_HOME"], str(self.cargo_home))
        self.assertEqual(env["CARGO_NET_OFFLINE"], "true")
        for key in ("RUSTC_WRAPPER", "RUSTFLAGS", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "CFLAGS",
                    "CARGO_BUILD_JOBS", "HTTP_PROXY", "PYTHONPATH", "AWS_SECRET_ACCESS_KEY",
                    "SLIPSTREAM_GEPH_ACCOUNT_SECRET"):
            self.assertNotIn(key, env)
        self.assertEqual(env["RUSTC"], str(self.tools["rustc"]))
        self.assertEqual(env["CC"], str(self.tools["clang"]))
        self.assertEqual(env["AR"], str(self.tools["ar"]))
        self.assertEqual(env["SDKROOT"], str(self.tools["sdk"]))
        self.assertEqual(env["LIBCLANG_PATH"], str(self.tools["libclang"].parent))
        self.assertEqual(env["SQLITE3_STATIC"], "1")
        self.assertIn("--locked", command)
        self.assertIn("--offline", command)
        self.assertEqual(command[command.index("--features") + 1], "aws_lambda")
        self.write(prefix.with_suffix(".stderr"), b"warning: synthetic stderr does not corrupt JSON\n")
        if stage == "metadata":
            self.assertEqual(command[command.index("--filter-platform") + 1], self.proof["target"])
            value = metadata()
            value["packages"].append({"id": "geph-root", "name": "geph5-client", "version": "0.4.3",
                                      "source": None, "manifest_path": str(self.source / "Cargo.toml")})
            value["resolve"]["root"] = "geph-root"
            value["resolve"]["nodes"].append({"id": "geph-root", "features": ["aws_lambda"]})
            if self.fault == "bundled":
                value["resolve"]["nodes"][0]["features"].append("sqlite")
            elif self.fault == "root":
                value["packages"][-1]["manifest_path"] = str(self.root / "wrong/Cargo.toml")
            elif self.fault == "missing-feature":
                value["resolve"]["nodes"][-1]["features"] = []
            elif self.fault == "source-mutation":
                (self.source / "src/lib.rs").write_text("changed during metadata")
            elif self.fault == "tool-mutation":
                self.tools["cargo"].write_bytes(b"different executable")
            elif self.fault == "config-injection":
                self.write(cwd / ".cargo/config.toml", b"[build]\nrustc-wrapper='bad'\n")
            elif self.fault == "contract-swap":
                self.contract.write_bytes(b"invalid replacement SOURCE")
            self.write(prefix.with_suffix(".stdout"), json.dumps(value).encode())
        elif stage == "test":
            if self.fault == "compile-timeout":
                raise RuntimeError("build command failed: timeout")
            self.assertEqual(command[command.index("--jobs") + 1], "1")
            self.assertEqual(command[command.index("--target") + 1], self.proof["target"])
            self.assertIn("--no-run", command)
            self.assertIn("--lib", command)
            target = Path(env["CARGO_TARGET_DIR"])
            self.executable = self.write(target / self.proof["target"] / "debug/deps/geph5_client-fixture", b"fake libtest")
            artifact = {"reason": "compiler-artifact", "profile": {"test": True},
                "target": {"name": "geph5_client", "src_path": str(self.source / "src/lib.rs")},
                "executable": str(self.executable)}
            self.write(prefix.with_suffix(".stdout"), json.dumps(artifact).encode() + b"\n")
        else:
            self.fail(f"unexpected native command stage {stage}")

    def runtime_driver(self, command, *, cwd, env, timeout, log, log_limit=1024 * 1024):
        if "-c" in command:
            self.calls.append(("compile-probe", command, env.copy()))
            self.assertEqual(command[:3], [str(runner.SANDBOX), "-p", runner.COMPILE_PROFILE])
            value = {"network": 1, "child_network": "13" if self.fault == "compile-probe" else "1"}
            log.write_text(json.dumps(value))
        elif "--list" in command:
            self.calls.append(("list", command, env.copy()))
            self.assertEqual(command[3], str(self.executable))
            log.write_text("\n".join(name + ": test" for name in runner.ALLOWLIST["0.4.3"]) +
                           "\ntests::test_clib: test\n")
        else:
            self.calls.append(("case", command, env.copy()))
            name = command[4]
            self.assertIn(name, runner.ALLOWLIST["0.4.3"])
            self.assertEqual(command[5:], ["--exact", "--test-threads=1", "--nocapture"])
            log.write_text(f"running 1 test\ntest {name} ... ok\n"
                           "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out;\n")
        return {"returncode": 0}

    def run_native(self, *, fault=None, machine="arm64", **overrides):
        self.fault = fault
        options = {"native_receipt": self.receipt, "native_artifacts_root": self.artifacts,
                   "cargo_home": self.cargo_home, "native_tools": self.tools, "build_jobs": 1}
        options.update(overrides)
        with mock.patch.object(runner.sys, "platform", "darwin"), \
                mock.patch.object(runner.platform, "machine", return_value=machine), \
                mock.patch.object(runner, "SANDBOX", Path(sys.executable).resolve()), \
                mock.patch.object(runner, "sandbox_selftest"), \
                mock.patch.object(runner, "run_command", side_effect=self.runtime_driver), \
                mock.patch.object(runner.producer, "run", side_effect=self.cargo_driver):
            return runner.qualify(self.source, self.contract, self.evidence, **options)

    def test_native_host_receipt_runs_offline_metadata_then_exact_nineteen(self):
        result = self.run_native()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["passed_tests"], list(runner.ALLOWLIST["0.4.3"]))
        self.assertEqual([c[0] for c in self.calls[:4]], ["compile-probe", "metadata", "test", "list"])
        self.assertEqual(len(self.calls), 23)
        self.assertEqual(result["native_compile"]["target"], native.TARGETS[0])
        self.assertEqual((self.evidence / "compile.sb").read_text(), runner.COMPILE_PROFILE)

    def test_intel_host_and_optional_cmake_are_supported(self):
        self.make_receipt(native.TARGETS[1])
        selected = {name: value for name, value in self.tools.items() if name != "cmake"}
        result = self.run_native(machine="x86_64", native_tools=selected)
        self.assertEqual(result["native_compile"]["target"], native.TARGETS[1])
        self.assertNotIn("CMAKE", self.calls[1][2])

    def test_minimal_compile_environment_discards_ambient_overrides_and_secrets(self):
        poison = {key: "must-not-propagate" for key in (
            "RUSTC_WRAPPER", "RUSTFLAGS", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "CFLAGS",
            "CARGO_BUILD_JOBS", "HTTP_PROXY", "PYTHONPATH", "AWS_SECRET_ACCESS_KEY", "SLIPSTREAM_GEPH_ACCOUNT_SECRET")}
        with mock.patch.dict(os.environ, poison):
            self.run_native()

    def test_missing_native_arguments_and_nonserial_jobs_fail_before_commands(self):
        for key in ("native_receipt", "native_artifacts_root", "cargo_home", "native_tools", "build_jobs"):
            with self.subTest(key=key), self.assertRaisesRegex(runner.QualificationError, "requires explicit"):
                self.run_native(**{key: None})
        for jobs in (0, 2, True):
            with self.subTest(jobs=jobs), self.assertRaisesRegex(runner.QualificationError, "set to 1"):
                self.run_native(build_jobs=jobs)
        for missing in runner.NATIVE_TOOLS:
            with self.subTest(tool=missing), self.assertRaisesRegex(runner.QualificationError, "explicit tool"):
                self.run_native(native_tools={k: v for k, v in self.tools.items() if k != missing})
        self.assertEqual(self.calls, [])
        self.assertFalse(self.evidence.exists())

    def test_native_arguments_cannot_change_legacy_compile_path(self):
        self.contract_value.pop("native_sqlite")
        self.contract.write_text(json.dumps(self.contract_value))
        with self.assertRaisesRegex(runner.QualificationError, "require native SOURCE"):
            self.run_native()
        self.assertEqual(self.calls, [])

    def test_wrong_host_or_unknown_architecture_fails_before_commands(self):
        for machine in ("x86_64", "unsupported"):
            with self.subTest(machine=machine), self.assertRaises(runner.QualificationError):
                self.run_native(machine=machine)
        self.assertEqual(self.calls, [])

    def test_lock_materialized_c_and_receipt_hash_reject_before_commands(self):
        for path in (self.source / "Cargo.lock", self.source / native.PATH / "sqlite3.c", self.receipt):
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.run_native()
            path.write_bytes(original)
        self.assertEqual(self.calls, [])

    def test_receipt_cannot_select_executables(self):
        self.proof["tools"]["clang"]["path"] = "/untrusted/receipt-selected-clang"
        self.proof["commands"] = link._commands(self.descriptor, self.proof["target"],
                                                 Path(self.proof["build_directory"]), self.proof["tools"])
        self.receipt.write_text(json.dumps(self.proof))
        with self.assertRaisesRegex(runner.QualificationError, "identities differ"):
            self.run_native()
        self.assertEqual(self.calls, [])

    def test_environment_cannot_switch_away_from_initial_host_proof(self):
        original = link.cargo_environment
        def wrong_library(*args, **kwargs):
            env = original(*args, **kwargs)
            env["SQLITE3_LIB_DIR"] = str(self.root / "alternate-library")
            return env
        with mock.patch.object(link, "cargo_environment", side_effect=wrong_library):
            with self.assertRaisesRegex(runner.QualificationError, "verified host proof"):
                self.run_native()
        self.assertEqual(self.calls, [])

    def test_symlink_tool_or_source_and_nonexecutable_tool_reject(self):
        cargo = self.tools["cargo"]
        real = cargo.with_name("real-cargo")
        cargo.rename(real)
        cargo.symlink_to(real)
        with self.assertRaisesRegex(runner.QualificationError, "physical"):
            self.run_native()
        cargo.unlink()
        real.rename(cargo)
        cargo.chmod(0o644)
        with self.assertRaisesRegex(runner.QualificationError, "executable"):
            self.run_native()
        cargo.chmod(0o755)
        actual = self.root / "physical-source"
        self.source.rename(actual)
        self.source.symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "physical directory"):
            self.run_native()
        self.assertEqual(self.calls, [])

    def test_initial_cargo_config_rejects_before_probe(self):
        for path in (self.cargo_home / "config.toml", self.source / ".cargo/config"):
            self.write(path, b"[build]\nrustc-wrapper='bad'\n")
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "Cargo configuration"):
                self.run_native()
            path.unlink()
        self.assertEqual(self.calls, [])

    def test_probe_metadata_and_timeout_fail_closed_with_retained_summary(self):
        faults = (("compile-probe", 1), ("bundled", 2), ("root", 2), ("missing-feature", 2),
                  ("config-injection", 2), ("compile-timeout", 3))
        for fault, count in faults:
            self.calls = []
            self.evidence = self.root / ("evidence-" + fault)
            with self.subTest(fault=fault), self.assertRaises((ValueError, RuntimeError)):
                self.run_native(fault=fault)
            self.assertEqual(len(self.calls), count)
            summary = json.loads((self.evidence / "summary.json").read_text())
            self.assertEqual(summary["status"], "failed")
            self.assertEqual(summary["passed_tests"], [])

    def test_source_and_tool_mutation_after_metadata_prevent_compilation(self):
        for fault, path in (("source-mutation", self.source / "src/lib.rs"), ("tool-mutation", self.tools["cargo"])):
            original = path.read_bytes()
            self.calls = []
            self.evidence = self.root / fault
            with self.subTest(fault=fault), self.assertRaisesRegex(runner.QualificationError, "changed"):
                self.run_native(fault=fault)
            self.assertEqual([c[0] for c in self.calls], ["compile-probe", "metadata"])
            path.write_bytes(original)

    def test_authoritative_source_is_frozen_across_compile(self):
        expected = runner.digest(self.contract)
        result = self.run_native(fault="contract-swap")
        self.assertEqual(result["inputs"][str(self.contract)], expected)
        self.assertEqual(result["status"], "passed")


@unittest.skipUnless(os.name == "posix", "owned process groups require POSIX")
class LauncherTests(unittest.TestCase):
    def test_logs_remain_bounded_and_nonzero_exit_is_not_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(runner.QualificationError, "7"):
                runner.run_command([sys.executable, "-I", "-c", "print('x' * 10000); raise SystemExit(7)"],
                                   cwd=root, env=dict(os.environ), timeout=3,
                                   log=root / "large.log", log_limit=100)
            result = json.loads((root / "large.json").read_text())
            self.assertGreater(result["original_log_bytes"], 10000)
            self.assertLess(result["retained_log_bytes"], 150)
            self.assertEqual(result["returncode"], 7)

    def test_timeout_and_normal_exit_clean_owned_descendants(self):
        for parent_sleeps in (True, False):
            with self.subTest(parent_sleeps=parent_sleeps), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                child_pid = root / "child.pid"
                command = [sys.executable, "-I", "-c",
                           "import subprocess,sys,time,pathlib; "
                           "p=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)'],"
                           "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                           "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); "
                           + ("time.sleep(30)" if parent_sleeps else "p.poll()"), str(child_pid)]
                try:
                    if parent_sleeps:
                        with self.assertRaisesRegex(runner.QualificationError, "124"):
                            runner.run_command(command, cwd=root, env=dict(os.environ),
                                               timeout=0.4, log=root / "launch.log")
                    else:
                        runner.run_command(command, cwd=root, env=dict(os.environ),
                                           timeout=5, log=root / "launch.log")
                    pid = int(child_pid.read_text())
                    for _ in range(30):
                        state = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                                               capture_output=True, text=True, timeout=3).stdout.strip()
                        if not state or state.startswith("Z"):
                            break
                        time.sleep(0.02)
                    self.assertTrue(not state or state.startswith("Z"), state)
                finally:
                    if child_pid.exists():
                        try:
                            os.kill(int(child_pid.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass


@unittest.skipUnless(sys.platform == "darwin", "macOS sandbox integration")
class SandboxTests(unittest.TestCase):
    def test_fake_compiler_and_child_really_receive_network_eperm(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "TMPDIR": str(root), "LC_ALL": "C"}
            runner.compile_sandbox_selftest([str(runner.SANDBOX), "-p", runner.COMPILE_PROFILE],
                                            cwd=root, env=env, evidence=root)
            self.assertEqual(json.loads((root / "compile-sandbox-probe.log").read_text()),
                             {"network": 1, "child_network": "1"})

    def test_real_os_denies_network_private_reads_and_unowned_writes(self):
        # Keep the controlled sentinel under the real home, but outside every
        # allowed subtree: this proves the broad home rule, not a literal deny.
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary).resolve()
            target, scratch = root / "target", root / "runtime"
            target.mkdir()
            scratch.mkdir()
            sentinel = root / "sentinel"
            sentinel.write_text("synthetic private sentinel")
            profile = root / "runtime.sb"
            profile.write_text(runner.sandbox_profile(target, scratch, root / "other-sentinel"))
            env = runner.runtime_environment(scratch)
            self.assertEqual(env.get("HOME"), os.environ.get("HOME"))
            runner.sandbox_selftest([str(runner.SANDBOX), "-f", str(profile)], scratch=scratch,
                                    sentinel=sentinel, env=env, evidence=root)


if __name__ == "__main__":
    unittest.main()

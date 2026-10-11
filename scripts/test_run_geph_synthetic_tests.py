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

import run_geph_synthetic_tests as runner

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

    def test_reviewed_versions_execute_exact_nine_and_eleven_only(self):
        for version, count in (("0.3.9", 9), ("0.4.3", 11)):
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

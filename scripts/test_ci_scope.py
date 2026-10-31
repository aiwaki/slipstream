from __future__ import annotations

import tempfile
import hashlib
import io
import os
from unittest.mock import patch
import unittest
from pathlib import Path

import ci_scope


class CiScopeTests(unittest.TestCase):
    def physical_root_fixture(self):
        files = {
            ".github/workflows/build-geph.yml": (b"logical root", b"physical root"),
            "scripts/test_geph_source_owned_workflows.py": (b"old tests", b"physical regression"),
            "vendor/geph/SOURCE.json": (b"same source", b"same source"),
            "vendor/geph/Cargo.lock": (b"same lock", b"same lock"),
        }
        bindings = {path: tuple(hashlib.sha256(value).hexdigest() for value in pair)
                    for path, pair in files.items()}
        paths = [".github/workflows/build-geph.yml", "scripts/test_geph_source_owned_workflows.py",
                 "scripts/ci_scope.py", "scripts/test_ci_scope.py", "docs/CURRENT_STATE.md"]
        return files, bindings, paths

    def test_physical_root_cli_pr_requires_the_exact_committed_repair(self):
        files, bindings, paths = self.physical_root_fixture()
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(ci_scope, "GEPH_PHYSICAL_ROOT_FILE_BINDINGS", bindings, create=True), \
             patch.object(ci_scope, "geph_physical_root_delta_from_git", return_value=files, create=True) as read, \
             patch.object(ci_scope, "delivery_delta_from_git", return_value=None), \
             patch("sys.stdin", io.StringIO("\n".join(paths))), \
             patch("sys.stdout", io.StringIO()) as stdout:
            output = Path(tmp) / "scope"
            self.assertEqual(ci_scope.main(["--event-name", "pull_request", "--github-output", str(output)]), 0)
            self.assertIn('"geph_bootstrap":true', stdout.getvalue())
            self.assertIn("geph_bootstrap=true\n", output.read_text())
            read.assert_called_once_with()

    def test_physical_root_scope_refuses_changed_contracts_and_unrelated_files(self):
        files, bindings, paths = self.physical_root_fixture()
        with patch.object(ci_scope, "GEPH_PHYSICAL_ROOT_FILE_BINDINGS", bindings):
            def allowed(changed=paths, delta=files, event="pull_request"):
                return ci_scope.classify_paths(changed, event_name=event,
                    geph_physical_root_delta=delta).geph_bootstrap
            self.assertTrue(allowed())
            self.assertTrue(allowed(list(ci_scope.GEPH_PHYSICAL_ROOT_REQUIRED)))
            self.assertFalse(allowed(event="push"))
            self.assertFalse(allowed(delta=None))
            for missing in (*ci_scope.GEPH_PHYSICAL_ROOT_REQUIRED, "scripts/test_ci_scope.py"):
                with self.subTest(missing=missing):
                    self.assertFalse(allowed([p for p in paths if p != missing]))
            for path, pair in files.items():
                for index in (0, 1):
                    changed = list(pair)
                    changed[index] += b"unreviewed"
                    with self.subTest(path=path, side=index):
                        self.assertFalse(allowed(delta={**files, path: tuple(changed)}))
            for extra in ("vendor/geph/SOURCE.json", "vendor/geph/Cargo.lock", "spike/tproxy.py",
                          ".github/workflows/ci.yml", "security/geph-dependency-audit-policy.json",
                          "README.md", ".gitattributes", "docs/RELEASES.md"):
                with self.subTest(extra=extra):
                    self.assertFalse(allowed([*paths, extra]))

    def test_physical_root_delta_refuses_missing_and_malformed_bytes(self):
        files, bindings, _ = self.physical_root_fixture()
        with patch.object(ci_scope, "GEPH_PHYSICAL_ROOT_FILE_BINDINGS", {}):
            self.assertFalse(ci_scope.reviewed_geph_physical_root_delta({}))
        with patch.object(ci_scope, "GEPH_PHYSICAL_ROOT_FILE_BINDINGS", bindings):
            for path, pair in files.items():
                invalid = [None, {}, [], {p: v for p, v in files.items() if p != path},
                           {**files, "extra": pair}, {**files, path: list(pair)},
                           {**files, path: (pair[0],)}, {**files, path: (None, pair[1])},
                           {**files, path: (pair[0], None)}, {**files, path: ("text", pair[1])}]
                for index, delta in enumerate(invalid):
                    with self.subTest(path=path, invalid=index):
                        self.assertFalse(ci_scope.reviewed_geph_physical_root_delta(delta))

    def test_physical_root_git_reader_binds_both_refs_and_fails_closed(self):
        files, bindings, _ = self.physical_root_fixture()
        base, head = "1" * 40, "2" * 40
        def read(command, **kwargs):
            ref, path = command[2].split(":", 1)
            self.assertEqual(kwargs, {"stderr": ci_scope.subprocess.DEVNULL, "timeout": 10})
            return files[path][ref == head]
        with patch.object(ci_scope, "GEPH_PHYSICAL_ROOT_FILE_BINDINGS", bindings), \
             patch.dict(os.environ, {"BASE_SHA": base, "GITHUB_SHA": head}), \
             patch.object(ci_scope.subprocess, "check_output", side_effect=read) as fetch:
            self.assertEqual(ci_scope.geph_physical_root_delta_from_git(), files)
            self.assertEqual([call.args[0] for call in fetch.call_args_list],
                [["git", "show", f"{ref}:{path}"] for path in bindings for ref in (base, head)])
        for key in ("BASE_SHA", "GITHUB_SHA"):
            for value in ("", "main", head + ":file"):
                with self.subTest(key=key, value=value), \
                     patch.dict(os.environ, {"BASE_SHA": base, "GITHUB_SHA": head, key: value}), \
                     patch.object(ci_scope.subprocess, "check_output") as fetch:
                    self.assertIsNone(ci_scope.geph_physical_root_delta_from_git())
                    fetch.assert_not_called()
        for error in (OSError(), ci_scope.subprocess.CalledProcessError(1, "git"),
                      ci_scope.subprocess.TimeoutExpired("git", 10)):
            with self.subTest(error=type(error).__name__), \
                 patch.dict(os.environ, {"BASE_SHA": base, "GITHUB_SHA": head}), \
                 patch.object(ci_scope.subprocess, "check_output", side_effect=error):
                self.assertIsNone(ci_scope.geph_physical_root_delta_from_git())

    def test_physical_root_cli_does_not_read_or_bootstrap_push_or_incomplete_pair(self):
        _, _, paths = self.physical_root_fixture()
        for event, changed in (("push", paths), ("pull_request", paths[1:])):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as tmp, \
                 patch.object(ci_scope, "geph_physical_root_delta_from_git") as read, \
                 patch.object(ci_scope, "delivery_delta_from_git", return_value=None), \
                 patch("sys.stdin", io.StringIO("\n".join(changed))), \
                 patch("sys.stdout", io.StringIO()) as stdout:
                self.assertEqual(ci_scope.main(["--event-name", event,
                    "--github-output", str(Path(tmp) / "scope")]), 0)
                self.assertIn('"geph_bootstrap":false', stdout.getvalue())
                read.assert_not_called()

    def test_physical_root_bindings_pin_the_unchanged_r4_source_and_lock(self):
        expected = {
            "vendor/geph/SOURCE.json": "69d5de39654dea018075469d20ea7892cc35f5af0466d19a7811ef3316b60df7",
            "vendor/geph/Cargo.lock": "560504e697c28f2114ec16414e5dc372e1903df986ba36792aab9a12c34631cb",
        }
        self.assertEqual(set(ci_scope.GEPH_PHYSICAL_ROOT_FILE_BINDINGS),
                         ci_scope.GEPH_PHYSICAL_ROOT_REQUIRED | expected.keys())
        for path, digest in expected.items():
            self.assertEqual(ci_scope.GEPH_PHYSICAL_ROOT_FILE_BINDINGS[path], (digest, digest))
        for path in ci_scope.GEPH_PHYSICAL_ROOT_REQUIRED:
            before, after = ci_scope.GEPH_PHYSICAL_ROOT_FILE_BINDINGS[path]
            self.assertNotEqual(before, after)
            self.assertRegex(before, r"^[0-9a-f]{64}$")
            self.assertRegex(after, r"^[0-9a-f]{64}$")

    def rsa_only_fixture(self):
        deltas = {
            "vendor/geph/SOURCE.json": (b"old source", b"embedded source"),
            "vendor/geph/Cargo.lock": (b"rsa", b"aws-lc"),
            ci_scope.RSA_ONLY_REVIEW: (None, b"exact source review"),
            "scripts/dependency_audit.py": (b"old audit", b"review-aware audit"),
            "security/geph-dependency-audit-policy.json": (b"exceptions", b"new source review"),
        }
        bindings = {path: (None if before is None else hashlib.sha256(before).hexdigest(),
                          hashlib.sha256(after).hexdigest())
                    for path, (before, after) in deltas.items()}
        return deltas, bindings

    def test_rsa_only_bootstrap_requires_every_reviewed_byte_and_path(self):
        deltas, bindings = self.rsa_only_fixture()
        paths = [*bindings, "scripts/ci_scope.py", "docs/CURRENT_STATE.md"]
        with patch.object(ci_scope, "RSA_ONLY_FILE_BINDINGS", bindings):
            self.assertEqual(ci_scope.classify_paths(paths, event_name="pull_request",
                rsa_only_delta=deltas), ci_scope.CiScope(True, True, False))
            self.assertFalse(ci_scope.classify_paths(paths, event_name="push",
                rsa_only_delta=deltas).geph_bootstrap)
            self.assertFalse(ci_scope.classify_paths(paths,
                event_name="pull_request").geph_bootstrap)
            for path, (before, after) in deltas.items():
                with self.subTest(path=path):
                    self.assertFalse(ci_scope.classify_paths(
                        [p for p in paths if p != path], event_name="pull_request",
                        rsa_only_delta=deltas).geph_bootstrap)
                    for pair in ((b"foreign base", after), (before, after + b"foreign")):
                        self.assertFalse(ci_scope.classify_paths(paths,
                            event_name="pull_request", rsa_only_delta={**deltas, path: pair}).geph_bootstrap)
            for extra in ("spike/tproxy.py", "app-tauri/src-tauri/src/main.rs",
                          "security/dependency-audit-policy.json", "security/geph-source-owned-review/extra.json"):
                with self.subTest(extra=extra):
                    self.assertFalse(ci_scope.classify_paths([*paths, extra],
                        event_name="pull_request", rsa_only_delta=deltas).geph_bootstrap)

    def test_rsa_only_delta_refuses_empty_partial_malformed_and_existing_empty_base(self):
        deltas, bindings = self.rsa_only_fixture()
        with patch.object(ci_scope, "RSA_ONLY_FILE_BINDINGS", {}):
            self.assertFalse(ci_scope.reviewed_rsa_only_delta({}))
        with patch.object(ci_scope, "RSA_ONLY_FILE_BINDINGS", bindings):
            path = ci_scope.RSA_ONLY_REVIEW
            for invalid in (None, {}, {path: deltas[path]}, {**deltas, "extra": (None, b"x")},
                            {**deltas, path: (b"", deltas[path][1])},
                            {**deltas, path: (None, "not bytes")},
                            {**deltas, path: [None, deltas[path][1]]}):
                self.assertFalse(ci_scope.reviewed_rsa_only_delta(invalid))

    def test_rsa_only_git_reader_proves_absence_and_rejects_missing_head(self):
        deltas, bindings = self.rsa_only_fixture()
        base, head = "1" * 40, "2" * 40
        def read(argv, **kwargs):
            if argv[1] == "ls-tree":
                present = bindings if argv[4] == head else [p for p, pair in deltas.items() if pair[0] is not None]
                return "\n".join(present) + "\n"
            ref, path = argv[2].split(":", 1)
            return deltas[path][ref == head]
        with patch.object(ci_scope, "RSA_ONLY_FILE_BINDINGS", bindings), \
             patch.dict(os.environ, {"BASE_SHA": base, "GITHUB_SHA": head}), \
             patch.object(ci_scope.subprocess, "check_output", side_effect=read):
            self.assertEqual(ci_scope.rsa_only_delta_from_git(), deltas)
        with patch.object(ci_scope, "RSA_ONLY_FILE_BINDINGS", bindings), \
             patch.dict(os.environ, {"BASE_SHA": base, "GITHUB_SHA": head}), \
             patch.object(ci_scope.subprocess, "check_output", return_value=""):
            self.assertIsNone(ci_scope.rsa_only_delta_from_git())

    def python_lock_delta(self):
        deltas = {
            path: (f"# {path}\ncertifi==2026.6.17\n".encode(),
                   f"# {path}\ncertifi==2026.10.19\n".encode())
            for path in ci_scope.PYTHON_LOCK_FILE_BINDINGS
        }
        bindings = {path: tuple(hashlib.sha256(value).hexdigest() for value in delta)
                    for path, delta in deltas.items()}
        return deltas, bindings

    def test_certifi_bootstrap_requires_all_exact_locks_and_geph_contract(self):
        deltas, bindings = self.python_lock_delta()
        paths = [*bindings, *ci_scope.GEPH_BOOTSTRAP_REQUIRED]
        with patch.object(ci_scope, "PYTHON_LOCK_FILE_BINDINGS", bindings):
            self.assertEqual(ci_scope.classify_paths(paths, event_name="pull_request",
                python_lock_delta=deltas), ci_scope.CiScope(True, True, False))
            self.assertFalse(ci_scope.classify_paths(paths, event_name="push",
                python_lock_delta=deltas).geph_bootstrap)
            self.assertFalse(ci_scope.classify_paths(paths,
                event_name="pull_request").geph_bootstrap)
            for missing in paths:
                with self.subTest(missing=missing):
                    self.assertFalse(ci_scope.classify_paths(
                        [path for path in paths if path != missing],
                        event_name="pull_request", python_lock_delta=deltas).geph_bootstrap)
            for path, (before, after) in deltas.items():
                for changed in ((b"unreviewed-base", after),
                                (before, b"unreviewed-head"), (before, before),
                                (before, after + b"extra==1.0.0\n"),
                                (before, after + b"--index-url=https://other.invalid/simple\n")):
                    with self.subTest(path=path, changed=changed):
                        self.assertFalse(ci_scope.classify_paths(paths, event_name="pull_request",
                            python_lock_delta={**deltas, path: changed}).geph_bootstrap)
            for extra in ("spike/requirements-runtime.in", "scripts/update_python_locks.sh",
                          "spike/tproxy.py", "security/dependency-audit-policy.json"):
                with self.subTest(extra=extra):
                    self.assertFalse(ci_scope.classify_paths([*paths, extra],
                        event_name="pull_request", python_lock_delta=deltas).geph_bootstrap)
            first = next(iter(deltas))
            for invalid in ({first: deltas[first]},
                            {**deltas, "extra": (b"before", b"after")},
                            {**deltas, first: ("not-bytes", deltas[first][1])}):
                self.assertFalse(ci_scope.reviewed_python_lock_delta(invalid))

    def test_python_lock_git_reader_requires_committed_base_and_head_bytes(self):
        base, head = "1" * 40, "2" * 40
        expected = {
            path: tuple(f"{ref}:{path}".encode() for ref in (base, head))
            for path in ci_scope.PYTHON_LOCK_FILE_BINDINGS
        }
        with patch.dict(os.environ, {"BASE_SHA": base, "GITHUB_SHA": head}), \
             patch.object(ci_scope.subprocess, "check_output",
                          side_effect=lambda command, **kwargs: command[2].encode()) as read:
            self.assertEqual(ci_scope.python_lock_delta_from_git(), expected)
            self.assertCountEqual(
                [call.args[0] for call in read.call_args_list],
                [["git", "show", f"{ref}:{path}"]
                 for path in ci_scope.PYTHON_LOCK_FILE_BINDINGS for ref in (base, head)],
            )
            for call in read.call_args_list:
                self.assertEqual(call.kwargs, {"stderr": ci_scope.subprocess.DEVNULL, "timeout": 10})
        for key in ("BASE_SHA", "GITHUB_SHA"):
            for invalid in ("", "main", head + ":path"):
                with self.subTest(key=key, invalid=invalid), \
                     patch.dict(os.environ, {"BASE_SHA": base, "GITHUB_SHA": head, key: invalid}), \
                     patch.object(ci_scope.subprocess, "check_output") as read:
                    self.assertIsNone(ci_scope.python_lock_delta_from_git())
                    read.assert_not_called()
        for error in (OSError(), ci_scope.subprocess.CalledProcessError(1, "git"),
                      ci_scope.subprocess.TimeoutExpired("git", 10)):
            with self.subTest(error=error), \
                 patch.dict(os.environ, {"BASE_SHA": base, "GITHUB_SHA": head}), \
                 patch.object(ci_scope.subprocess, "check_output", side_effect=error):
                self.assertIsNone(ci_scope.python_lock_delta_from_git())

    def test_python_lock_cli_never_admits_missing_git_evidence_or_push(self):
        deltas, bindings = self.python_lock_delta()
        paths = [*bindings, *ci_scope.GEPH_BOOTSTRAP_REQUIRED]
        for event, evidence, expected in (("pull_request", deltas, True),
                                          ("pull_request", None, False),
                                          ("push", deltas, False)):
            with self.subTest(event=event, evidence=evidence), tempfile.TemporaryDirectory() as tmp, \
                 patch.object(ci_scope, "PYTHON_LOCK_FILE_BINDINGS", bindings), \
                 patch.object(ci_scope, "python_lock_delta_from_git", return_value=evidence) as read, \
                 patch.object(ci_scope.sys, "stdin", io.StringIO("\n".join(paths))), \
                 patch.object(ci_scope.sys, "stdout", io.StringIO()):
                output = Path(tmp) / "github-output"
                self.assertEqual(ci_scope.main(["--event-name", event,
                    "--github-output", str(output)]), 0)
                self.assertEqual(output.read_text(),
                    f"geph_bootstrap={str(expected).lower()}\nproduct=true\nwindows=false\n")
                self.assertEqual(read.call_count, int(event == "pull_request"))

    def test_exact_delivery_bundle_never_exempts_partial_or_unreviewed_app_edits(self):
        paths = list(ci_scope.DELIVERY_FILE_BINDINGS)
        deltas = {path: (f"old:{path}".encode(), f"new:{path}".encode()) for path in paths}
        bindings = {path: tuple(hashlib.sha256(v).hexdigest() for v in delta)
                    for path, delta in deltas.items()}
        changed = [*paths, *ci_scope.DELIVERY_TEST_PATHS, *ci_scope.GEPH_BOOTSTRAP_REQUIRED]
        with patch.object(ci_scope, "DELIVERY_FILE_BINDINGS", bindings):
            self.assertTrue(ci_scope.classify_paths(changed, event_name="pull_request",
                delivery_delta=deltas).geph_bootstrap)
            self.assertFalse(ci_scope.classify_paths(changed, event_name="push",
                delivery_delta=deltas).geph_bootstrap)
            self.assertFalse(ci_scope.classify_paths(changed, event_name="pull_request").geph_bootstrap)
            for missing in changed:
                with self.subTest(missing=missing):
                    self.assertFalse(ci_scope.classify_paths([p for p in changed if p != missing],
                        event_name="pull_request", delivery_delta=deltas).geph_bootstrap)
            for path in paths:
                for altered in ((b"unreviewed-base", deltas[path][1]),
                                (deltas[path][0], b"unreviewed-head"),
                                (deltas[path][0], deltas[path][0])):
                    with self.subTest(path=path, altered=altered):
                        bad = {**deltas, path: altered}
                        self.assertFalse(ci_scope.classify_paths(changed, event_name="pull_request",
                            delivery_delta=bad).geph_bootstrap)
            self.assertFalse(ci_scope.classify_paths(changed + ["spike/tproxy.py"],
                event_name="pull_request", delivery_delta=deltas).geph_bootstrap)
            self.assertFalse(ci_scope.classify_paths(changed + [ci_scope.APP_LOCK],
                event_name="pull_request", delivery_delta=deltas).geph_bootstrap)
            before, after = self.app_lock_delta()
            self.assertTrue(ci_scope.classify_paths(changed + [ci_scope.APP_LOCK],
                event_name="pull_request", delivery_delta=deltas,
                app_lock_delta=(before, after)).geph_bootstrap)
            self.assertFalse(ci_scope.reviewed_delivery_delta({**deltas, "extra": (b"a", b"b")}))
            self.assertFalse(ci_scope.reviewed_delivery_delta({paths[0]: deltas[paths[0]]}))

    def test_delivery_git_reader_requires_exact_refs_and_never_reads_working_tree(self):
        base, head = "1" * 40, "2" * 40
        expected = {
            path: tuple(f"{ref}:{path}".encode() for ref in (base, head))
            for path in ci_scope.DELIVERY_FILE_BINDINGS
        }
        with patch.dict(os.environ, {"BASE_SHA": base, "GITHUB_SHA": head}), \
             patch.object(ci_scope.subprocess, "check_output",
                          side_effect=lambda command, **kwargs: command[2].encode()) as read:
            result = ci_scope.delivery_delta_from_git()
            self.assertEqual(result, expected)
            self.assertCountEqual(
                [call.args[0] for call in read.call_args_list],
                [["git", "show", f"{ref}:{path}"]
                 for path in ci_scope.DELIVERY_FILE_BINDINGS for ref in (base, head)],
            )
        for invalid in ("", "main", head + ":path"):
            with patch.dict(os.environ, {"BASE_SHA": invalid, "GITHUB_SHA": head}), \
                 patch.object(ci_scope.subprocess, "check_output") as read:
                self.assertIsNone(ci_scope.delivery_delta_from_git())
                read.assert_not_called()
        with patch.dict(os.environ, {"BASE_SHA": base, "GITHUB_SHA": head}), \
             patch.object(ci_scope.subprocess, "check_output", side_effect=OSError):
            self.assertIsNone(ci_scope.delivery_delta_from_git())

    def test_synthetic_runner_bootstrap_requires_its_tests(self):
        paths = [*ci_scope.GEPH_BOOTSTRAP_REQUIRED, "scripts/run_geph_synthetic_tests.py"]
        self.assertFalse(ci_scope.classify_paths(paths, event_name="pull_request").geph_bootstrap)
        self.assertTrue(ci_scope.classify_paths(paths + ["scripts/test_run_geph_synthetic_tests.py"],
            event_name="pull_request").geph_bootstrap)

    def test_combined_tls_and_quinn_repair_keeps_exact_lock_boundaries(self):
        repairs = next(repairs for repairs in ci_scope.APP_LOCK_REPAIR_SETS
                       if {repair[0] for repair in repairs} == {"rustls", "quinn-proto"})
        before, after = ["version = 4"], ["version = 4"]
        for name, old, old_hash, new, new_hash in repairs:
            for rows, version, checksum in ((before, old, old_hash), (after, new, new_hash)):
                rows.append(f'[[package]]\nname = "{name}"\nversion = "{version}"\nchecksum = "{checksum}"\n'
                            'source = "registry+https://github.com/rust-lang/crates.io-index"\ndependencies = ["bytes"]')
        before, after = "\n".join(before), "\n".join(after)
        paths = [*ci_scope.GEPH_BOOTSTRAP_REQUIRED, ci_scope.APP_LOCK]
        self.assertTrue(ci_scope.classify_paths(paths, event_name="pull_request",
            app_lock_delta=(before, after)).geph_bootstrap)
        bad_values = [after.replace('"0.11.18"', '"0.11.17"'),
                      after.replace(repairs[-1][-1], "0" * 64),
                      after.replace('dependencies = ["bytes"]', 'dependencies = []'),
                      after.replace('version = 4', 'version = 3'), before,
                      after + '\n[[package]]\nname="other"\nversion="1.0.0"']
        for actual in bad_values:
            with self.subTest(actual=actual):
                self.assertFalse(ci_scope.reviewed_app_lock_repair(before, actual))
        self.assertFalse(ci_scope.classify_paths(paths, event_name="push",
            app_lock_delta=(before, after)).geph_bootstrap)

    def test_emsign_rust_repair_preserves_graph_and_combines_with_exact_certifi(self):
        repairs = next(repairs for repairs in ci_scope.APP_LOCK_REPAIR_SETS
                       if {repair[0] for repair in repairs} == {"rustls-webpki", "webpki-roots"})
        self.assertEqual({(name, old, new) for name, old, _, new, _ in repairs}, {
            ("rustls-webpki", "0.103.15", "0.103.16"),
            ("webpki-roots", "1.0.9", "1.0.10"),
        })
        before, after = ["version = 4"], ["version = 4"]
        for name, old, old_hash, new, new_hash in repairs:
            for rows, version, checksum in ((before, old, old_hash), (after, new, new_hash)):
                rows.append(f'[[package]]\nname="{name}"\nversion="{version}"\nchecksum="{checksum}"\n'
                            'source="registry+https://github.com/rust-lang/crates.io-index"\ndependencies=["ring"]')
        before, after = "\n".join(before), "\n".join(after)
        paths = [*ci_scope.GEPH_BOOTSTRAP_REQUIRED, ci_scope.APP_LOCK]
        self.assertTrue(ci_scope.classify_paths(paths, event_name="pull_request",
            app_lock_delta=(before, after)).geph_bootstrap)
        self.assertFalse(ci_scope.classify_paths(paths, event_name="push",
            app_lock_delta=(before, after)).geph_bootstrap)
        self.assertFalse(ci_scope.classify_paths(paths, event_name="pull_request").geph_bootstrap)
        bad_values = [before, after.replace('dependencies=["ring"]', 'dependencies=[]'),
                      after.replace('version = 4', 'version = 3'),
                      after + '\n[[package]]\nname="extra"\nversion="1.0.0"',
                      after.replace('registry+https://github.com/rust-lang/crates.io-index',
                                    'git+https://other.invalid/repository')]
        for name, old, old_hash, new, new_hash in repairs:
            bad_values.extend((after.replace(new_hash, "0" * 64),
                               after.replace(f'version="{new}"', f'version="{old}"')
                                    .replace(new_hash, old_hash)))
            self.assertFalse(ci_scope.reviewed_app_lock_repair(
                before.replace(old_hash, "0" * 64), after))
            duplicate = (f'\n[[package]]\nname="{name}"\nversion="{new}"\n'
                         f'checksum="{new_hash}"\n'
                         'source="registry+https://github.com/rust-lang/crates.io-index"')
            self.assertFalse(ci_scope.reviewed_app_lock_repair(before + duplicate, after + duplicate))
        for changed in bad_values:
            with self.subTest(changed=changed):
                self.assertFalse(ci_scope.reviewed_app_lock_repair(before, changed))
        deltas, bindings = self.python_lock_delta()
        with patch.object(ci_scope, "PYTHON_LOCK_FILE_BINDINGS", bindings):
            combined = [*paths, *bindings, "scripts/ci_scope.py", "scripts/test_ci_scope.py"]
            self.assertEqual(ci_scope.classify_paths(combined, event_name="pull_request",
                app_lock_delta=(before, after), python_lock_delta=deltas),
                ci_scope.CiScope(True, True, False))
            self.assertFalse(ci_scope.classify_paths(combined, event_name="pull_request",
                python_lock_delta=deltas).geph_bootstrap)
            self.assertFalse(ci_scope.classify_paths(combined, event_name="pull_request",
                app_lock_delta=(before, after)).geph_bootstrap)
            self.assertFalse(ci_scope.classify_paths(
                [path for path in combined if path != "scripts/test_ci_scope.py"],
                event_name="pull_request", app_lock_delta=(before, after),
                python_lock_delta=deltas).geph_bootstrap)

    def app_lock_delta(self):
        before, after = ["version = 4"], ["version = 4"]
        for name, old, old_hash, new, new_hash in ci_scope.APP_LOCK_REPAIRS:
            for rows, version, checksum in ((before, old, old_hash), (after, new, new_hash)):
                rows.append(f'[[package]]\nname = "{name}"\nversion = "{version}"\nchecksum = "{checksum}"\n'
                            'source = "registry+https://github.com/rust-lang/crates.io-index"\ndependencies = ["ring"]')
        return "\n".join(before), "\n".join(after)

    def test_app_lock_exception_rejects_unrelated_or_unverified_changes(self):
        before, after = self.app_lock_delta()
        paths = ["vendor/geph/SOURCE.json", "vendor/geph/Cargo.lock", ci_scope.APP_LOCK]
        self.assertFalse(ci_scope.classify_paths(paths, event_name="pull_request").geph_bootstrap)
        for changed in (after.replace('"ring"', '"unrelated"', 1),
                        after.replace('version = 4', 'version = 3'),
                        after + '\n[[package]]\nname="extra"\nversion="1.0.0"',
                        after.replace('0.23.45', '0.23.46'), before, 'malformed'):
            with self.subTest(changed=changed):
                self.assertFalse(ci_scope.classify_paths(paths, event_name="pull_request",
                    app_lock_delta=(before, changed)).geph_bootstrap)
        self.assertTrue(ci_scope.classify_paths(paths, event_name="pull_request",
            app_lock_delta=(before, after)).geph_bootstrap)

    def test_source_edit_bootstrap_requires_contract_and_tests(self):
        paths = ["vendor/geph/SOURCE.json", "scripts/geph_vendor_source.py",
                 "scripts/test_geph_source_edits.py", "vendor/geph/README.md",
                 ".github/workflows/build-geph.yml", "scripts/test_build_config.py",
                 "scripts/ci_scope.py", "scripts/test_ci_scope.py"]
        self.assertTrue(ci_scope.classify_paths(paths, event_name="pull_request").geph_bootstrap)
        self.assertFalse(ci_scope.classify_paths(paths, event_name="push").geph_bootstrap)
        for missing in ("vendor/geph/SOURCE.json", "scripts/test_geph_source_edits.py",
                        "scripts/test_build_config.py", "scripts/test_ci_scope.py"):
            self.assertFalse(ci_scope.classify_paths([p for p in paths if p != missing],
                event_name="pull_request").geph_bootstrap)
        self.assertFalse(ci_scope.classify_paths(paths + ["spike/tproxy.py"],
            event_name="pull_request").geph_bootstrap)

    def test_rustls_0346_repair_preserves_source_bootstrap_boundaries(self):
        old_hash = "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634"
        new_hash = "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf"
        before = ('version = 4\n[[package]]\nname="rustls"\nversion="0.23.45"\n'
                  f'checksum="{old_hash}"\n'
                  'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                  'dependencies=["ring"]\n[[package]]\nname="unrelated"\nversion="1.0.0"\n')
        after = before.replace('"0.23.45"', '"0.23.46"').replace(old_hash, new_hash)
        paths = ["vendor/geph/SOURCE.json", "vendor/geph/Cargo.lock", ci_scope.APP_LOCK]
        self.assertEqual(ci_scope.classify_paths(paths, event_name="pull_request",
            app_lock_delta=(before, after)), ci_scope.CiScope(True, True, False))
        for original, changed in (
            (before, before), (after, before),
            (before, after.replace(new_hash, "0" * 64)),
            (before.replace(old_hash, "0" * 64), after),
            (before, after.replace('dependencies=["ring"]', 'dependencies=[]')),
            (before, after.replace('version="1.0.0"', 'version="1.0.1"')),
            (before, after.replace('version = 4', 'version = 3')),
            (before, after.replace('name="rustls"', 'name="other"')),
            (before.replace('registry+https://github.com/rust-lang/crates.io-index', 'git+https://example.test/rustls'), after),
        ):
            with self.subTest(original=original, changed=changed):
                self.assertFalse(ci_scope.classify_paths(paths, event_name="pull_request",
                    app_lock_delta=(original, changed)).geph_bootstrap)
        self.assertFalse(ci_scope.classify_paths(paths, event_name="push",
            app_lock_delta=(before, after)).geph_bootstrap)
        self.assertFalse(ci_scope.classify_paths(paths, event_name="pull_request").geph_bootstrap)
        for extra in ("spike/tproxy.py", ".github/workflows/ci.yml", "security/dependency-audit-policy.json"):
            self.assertFalse(ci_scope.classify_paths([*paths, extra], event_name="pull_request",
                app_lock_delta=(before, after)).geph_bootstrap)
        # A target version already in the graph must not become a duplicate
        # package identity, even if the rest of the text matches the repair.
        duplicate = (f'\n[[package]]\nname="rustls"\nversion="0.23.46"\nchecksum="{new_hash}"\n'
                     'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                     'dependencies=["ring"]\n')
        self.assertFalse(ci_scope.reviewed_app_lock_repair(before + duplicate, after + duplicate))

    def test_embedded_source_tests_preserve_exact_bootstrap_boundaries(self):
        paths = ["vendor/geph/SOURCE.json", "vendor/geph/Cargo.lock",
                 "scripts/geph_vendor_source.py", "scripts/test_geph_source_edits.py",
                 "scripts/test_geph_embedded_source.py",
                 "scripts/ci_scope.py", "scripts/test_ci_scope.py"]
        self.assertEqual(ci_scope.classify_paths(paths, event_name="pull_request"),
                         ci_scope.CiScope(True, True, False))
        self.assertFalse(ci_scope.classify_paths(paths, event_name="push").geph_bootstrap)
        for missing in ("vendor/geph/SOURCE.json", "scripts/test_geph_source_edits.py",
                        "scripts/test_ci_scope.py"):
            with self.subTest(missing=missing):
                self.assertFalse(ci_scope.classify_paths(
                    [path for path in paths if path != missing],
                    event_name="pull_request").geph_bootstrap)
        for extra in ("spike/tproxy.py", "app-tauri/src-tauri/src/lib.rs",
                      "app-tauri/src-tauri/Cargo.toml", ".github/workflows/ci.yml",
                      "security/dependency-audit-policy.json"):
            with self.subTest(extra=extra):
                self.assertFalse(ci_scope.classify_paths(
                    [*paths, extra], event_name="pull_request").geph_bootstrap)
        helper_only = ["scripts/geph_vendor_source.py", "scripts/test_geph_source_edits.py",
                       "scripts/test_geph_embedded_source.py"]
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                self.assertEqual(ci_scope.classify_paths(helper_only, event_name=event),
                                 ci_scope.CiScope(False, True, False))

    def test_existing_source_edit_revision_without_lock_change(self):
        paths = ["vendor/geph/SOURCE.json", "vendor/geph/README.md", "docs/CURRENT_STATE.md", "docs/DECISIONS.md",
                 "scripts/ci_scope.py", "scripts/test_ci_scope.py"]
        self.assertTrue(ci_scope.classify_paths(paths, event_name="pull_request").geph_bootstrap)
        self.assertFalse(ci_scope.classify_paths(paths, event_name="push").geph_bootstrap)
        for extra in ("spike/tproxy.py", "vendor/geph/VERSION",
                      "app-tauri/src-tauri/binaries/geph5-client-aarch64-apple-darwin",
                      "app-tauri/src-tauri/src/lib.rs", ".github/workflows/ci.yml"):
            with self.subTest(extra=extra):
                self.assertFalse(ci_scope.classify_paths(paths + [extra],
                    event_name="pull_request").geph_bootstrap)

    def test_exact_geph_contract_sets_bootstrap_only_on_pull_request(self) -> None:
        required = ["vendor/geph/SOURCE.json", "vendor/geph/Cargo.lock"]
        for paths in (
            required,
            [*required, "vendor/geph/VERSION"],
            [
                *required,
                "vendor/geph/VERSION",
                "security/geph-dependency-audit-policy.json",
            ],
        ):
            with self.subTest(paths=paths):
                scope = ci_scope.classify_paths(paths, event_name="pull_request")
                self.assertTrue(scope.geph_bootstrap)
                self.assertTrue(scope.product)
                self.assertFalse(scope.windows)
                self.assertFalse(
                    ci_scope.classify_paths(paths, event_name="push").geph_bootstrap
                )

    def test_bootstrap_rejects_missing_required_or_unrelated_path(self) -> None:
        for paths in (
            ["vendor/geph/SOURCE.json", "vendor/geph/VERSION"],
            ["vendor/geph/Cargo.lock", "vendor/geph/VERSION"],
            [
                "vendor/geph/SOURCE.json",
                "vendor/geph/Cargo.lock",
                "README.md",
            ],
            [
                "vendor/geph/SOURCE.json",
                "vendor/geph/Cargo.lock",
                ".github/workflows/ci.yml",
            ],
        ):
            with self.subTest(paths=paths):
                self.assertFalse(
                    ci_scope.classify_paths(
                        paths, event_name="pull_request"
                    ).geph_bootstrap
                )

    def test_joint_lock_repair_keeps_both_audits_and_rejects_product_edits(self) -> None:
        paths = ["vendor/geph/SOURCE.json", "vendor/geph/Cargo.lock",
                 "app-tauri/src-tauri/Cargo.lock", "scripts/ci_scope.py",
                 "scripts/test_ci_scope.py", "docs/RELEASES.md",
                 "docs/DECISIONS.md", "docs/CURRENT_STATE.md",
                 ".github/workflows/build-geph.yml", "scripts/test_build_config.py"]
        scope = ci_scope.classify_paths(paths, event_name="pull_request", app_lock_delta=self.app_lock_delta())
        self.assertTrue(scope.geph_bootstrap)
        self.assertTrue(scope.product)  # Both independent audit jobs use this.
        self.assertFalse(ci_scope.classify_paths(paths, event_name="push").geph_bootstrap)
        self.assertFalse(ci_scope.classify_paths(
            [p for p in paths if p != "scripts/test_ci_scope.py"],
            event_name="pull_request", app_lock_delta=self.app_lock_delta()).geph_bootstrap)
        self.assertFalse(ci_scope.classify_paths(
            [p for p in paths if p != "scripts/test_build_config.py"],
            event_name="pull_request", app_lock_delta=self.app_lock_delta()).geph_bootstrap)
        for extra in ("app-tauri/src-tauri/Cargo.toml", "app-tauri/src-tauri/src/lib.rs",
                      ".github/workflows/ci.yml", "scripts/build_macos.sh", "spike/tproxy.py",
                      "security/dependency-audit-policy.json"):
            with self.subTest(extra=extra):
                self.assertFalse(ci_scope.classify_paths(
                    [*paths, extra], event_name="pull_request", app_lock_delta=self.app_lock_delta()).geph_bootstrap)

    def test_existing_product_docs_and_windows_scope_is_preserved(self) -> None:
        self.assertEqual(
            ci_scope.classify_paths(["docs/RELEASES.md"], event_name="pull_request"),
            ci_scope.CiScope(False, False, False),
        )
        self.assertEqual(
            ci_scope.classify_paths(
                ["README.md", "notes/example.md"], event_name="pull_request"
            ),
            ci_scope.CiScope(False, False, False),
        )
        self.assertEqual(
            ci_scope.classify_paths(
                ["crates/slipstream-core/src/lib.rs"], event_name="pull_request"
            ),
            ci_scope.CiScope(False, True, True),
        )
        self.assertEqual(
            ci_scope.classify_paths(
                ["spike/tproxy.py"], event_name="pull_request"
            ),
            ci_scope.CiScope(False, True, False),
        )
        self.assertEqual(
            ci_scope.classify_paths([], event_name="push"),
            ci_scope.CiScope(False, True, True),
        )

    def test_invalid_paths_and_events_fail_closed(self) -> None:
        for path in ("/tmp/file", "../escape", "vendor/../escape"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                ci_scope.classify_paths([path], event_name="pull_request")
        with self.assertRaises(ValueError):
            ci_scope.classify_paths(["README.md"], event_name="workflow_dispatch")

    def test_github_output_has_fixed_boolean_fields(self) -> None:
        scope = ci_scope.CiScope(True, True, False)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "github-output"
            ci_scope.write_github_output(output, scope)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "geph_bootstrap=true\nproduct=true\nwindows=false\n",
            )


if __name__ == "__main__":
    unittest.main()

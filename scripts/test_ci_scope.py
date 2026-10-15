from __future__ import annotations

import tempfile
import hashlib
import os
from unittest.mock import patch
import unittest
from pathlib import Path

import ci_scope


class CiScopeTests(unittest.TestCase):
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
        before, after = ["version = 4"], ["version = 4"]
        for name, old, old_hash, new, new_hash in ci_scope.APP_LOCK_REPAIR_SETS[-1]:
            for rows, version, checksum in ((before, old, old_hash), (after, new, new_hash)):
                rows.append(f'[[package]]\nname = "{name}"\nversion = "{version}"\nchecksum = "{checksum}"\n'
                            'source = "registry+https://github.com/rust-lang/crates.io-index"\ndependencies = ["bytes"]')
        before, after = "\n".join(before), "\n".join(after)
        paths = [*ci_scope.GEPH_BOOTSTRAP_REQUIRED, ci_scope.APP_LOCK]
        self.assertTrue(ci_scope.classify_paths(paths, event_name="pull_request",
            app_lock_delta=(before, after)).geph_bootstrap)
        bad_values = [after.replace('"0.11.18"', '"0.11.17"'),
                      after.replace(ci_scope.APP_LOCK_REPAIR_SETS[-1][-1][-1], "0" * 64),
                      after.replace('dependencies = ["bytes"]', 'dependencies = []'),
                      after.replace('version = 4', 'version = 3'), before,
                      after + '\n[[package]]\nname="other"\nversion="1.0.0"']
        for actual in bad_values:
            with self.subTest(actual=actual):
                self.assertFalse(ci_scope.reviewed_app_lock_repair(before, actual))
        self.assertFalse(ci_scope.classify_paths(paths, event_name="push",
            app_lock_delta=(before, after)).geph_bootstrap)

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

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import ci_scope


class CiScopeTests(unittest.TestCase):
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

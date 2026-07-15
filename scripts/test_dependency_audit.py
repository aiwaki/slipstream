from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

import dependency_audit


SOURCE_COMMIT = "a" * 40
TARGET = "aarch64-apple-darwin"
POLICY_PATH = dependency_audit.DEFAULT_POLICY


def scanner_metadata(policy: dict, platform: str = "darwin-arm64") -> dict:
    asset = dependency_audit.scanner_asset(policy, platform)
    return {
        "asset": asset["name"],
        "name": "osv-scanner",
        "platform": platform,
        "sha256": asset["sha256"],
        "version": policy["scanner"]["version"],
    }


def vulnerability(
    advisory_id: str,
    *,
    informational: str | None = None,
    withdrawn: bool = False,
) -> dict:
    item: dict = {"id": advisory_id, "aliases": [], "affected": []}
    if informational:
        item["affected"] = [
            {"database_specific": {"informational": informational}}
        ]
    if withdrawn:
        item["withdrawn"] = "2026-07-01T00:00:00Z"
    return item


def osv_result(*packages: tuple[dict, list[dict]]) -> dict:
    return {
        "results": [
            {
                "source": {"path": "Slipstream.spdx.json", "type": "lockfile"},
                "packages": [
                    {"package": package, "vulnerabilities": vulnerabilities}
                    for package, vulnerabilities in packages
                ],
            }
        ]
    }


class DependencyAuditTests(unittest.TestCase):
    def _build_report(
        self,
        root: Path,
        result: dict,
        *,
        evaluated_on: date = date(2026, 7, 16),
    ) -> tuple[dict, Path]:
        policy = dependency_audit.load_policy(POLICY_PATH)
        sbom = root / "Slipstream.spdx.json"
        sbom.write_text('{"spdxVersion":"SPDX-2.3"}\n', encoding="utf-8")
        report = dependency_audit.build_audit_report(
            osv_result=result,
            policy=policy,
            policy_path=POLICY_PATH,
            sbom_path=sbom,
            scanner=scanner_metadata(policy),
            source_commit=SOURCE_COMMIT,
            target=TARGET,
            evaluated_on=evaluated_on,
        )
        return report, sbom

    def test_reviewed_exception_and_informational_advisory_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = osv_result(
                (
                    {
                        "ecosystem": "crates.io",
                        "name": "quick-xml",
                        "version": "0.39.4",
                    },
                    [
                        vulnerability("RUSTSEC-2026-0194"),
                        vulnerability("RUSTSEC-2026-0195"),
                    ],
                ),
                (
                    {
                        "ecosystem": "crates.io",
                        "name": "unic-common",
                        "version": "0.9.0",
                    },
                    [vulnerability("RUSTSEC-2025-0080", informational="unmaintained")],
                ),
            )
            report, sbom = self._build_report(root, result)

            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["summary"]["accepted_exception"], 2)
            self.assertEqual(report["summary"]["informational"], 1)
            summary = dependency_audit.validate_audit_report(
                report,
                policy_path=POLICY_PATH,
                sbom_path=sbom,
                source_commit=SOURCE_COMMIT,
                target=TARGET,
            )
            self.assertEqual(summary["packages_scanned"], 2)

            tampered = copy.deepcopy(report)
            tampered["findings"][0]["package"]["version"] = "0.39.5"
            with self.assertRaisesRegex(ValueError, "exception package"):
                dependency_audit.validate_audit_report(
                    tampered,
                    policy_path=POLICY_PATH,
                    sbom_path=sbom,
                    source_commit=SOURCE_COMMIT,
                    target=TARGET,
                )

    def test_unreviewed_advisory_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report, _ = self._build_report(
                Path(tmp),
                osv_result(
                    (
                        {"ecosystem": "PyPI", "name": "demo", "version": "1.0"},
                        [vulnerability("GHSA-DEMO-0001")],
                    )
                ),
            )

            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["summary"]["blocking"], 1)

    def test_expired_or_version_mismatched_exception_blocks(self) -> None:
        result = osv_result(
            (
                {
                    "ecosystem": "crates.io",
                    "name": "quick-xml",
                    "version": "0.39.4",
                },
                [vulnerability("RUSTSEC-2026-0194")],
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            report, _ = self._build_report(
                Path(tmp), result, evaluated_on=date(2026, 9, 1)
            )
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["findings"][0]["reason"], "expired_exception")

        result["results"][0]["packages"][0]["package"]["version"] = "0.39.5"
        with tempfile.TemporaryDirectory() as tmp:
            report, _ = self._build_report(Path(tmp), result)
            self.assertEqual(report["status"], "fail")

    def test_report_validation_rejects_input_or_count_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report, sbom = self._build_report(
                root,
                osv_result(
                    (
                        {"ecosystem": "crates.io", "name": "serde", "version": "1"},
                        [],
                    )
                ),
            )
            tampered = copy.deepcopy(report)
            tampered["inputs"]["sbom_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "input hashes"):
                dependency_audit.validate_audit_report(
                    tampered,
                    policy_path=POLICY_PATH,
                    sbom_path=sbom,
                    source_commit=SOURCE_COMMIT,
                    target=TARGET,
                )

            tampered = copy.deepcopy(report)
            tampered["summary"]["advisories"] = 1
            with self.assertRaisesRegex(ValueError, "advisory count"):
                dependency_audit.validate_audit_report(
                    tampered,
                    policy_path=POLICY_PATH,
                    sbom_path=sbom,
                    source_commit=SOURCE_COMMIT,
                    target=TARGET,
                )

    def test_same_inputs_and_date_produce_identical_report(self) -> None:
        result = osv_result(
            (
                {"ecosystem": "crates.io", "name": "serde", "version": "1"},
                [],
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, _ = self._build_report(root, result)
            second, _ = self._build_report(root, result)
            self.assertEqual(
                json.dumps(first, sort_keys=True),
                json.dumps(second, sort_keys=True),
            )

    def test_scanner_operational_error_is_not_treated_as_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scanner = root / "scanner"
            scanner.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
            scanner.chmod(0o755)
            sbom = root / "Slipstream.spdx.json"
            sbom.write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "exit code 7"):
                dependency_audit.run_osv_scan(
                    scanner_path=scanner,
                    sbom_path=sbom,
                )


if __name__ == "__main__":
    unittest.main()

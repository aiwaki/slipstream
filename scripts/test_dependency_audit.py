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
GEPH_POLICY_PATH = (
    dependency_audit.DEFAULT_POLICY.parent / "geph-dependency-audit-policy.json"
)


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


def sbom_package(
    *,
    ecosystem: str,
    name: str,
    version: str,
    sha256: str | None = None,
) -> dict:
    package = {
        "SPDXID": f"SPDXRef-Package-{name}",
        "name": name,
        "versionInfo": version,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:{ecosystem}/{name}@{version}",
            }
        ],
    }
    if sha256 is not None:
        package["checksums"] = [
            {"algorithm": "SHA256", "checksumValue": sha256}
        ]
    return package


class DependencyAuditTests(unittest.TestCase):
    def test_geph_policy_uses_the_same_pinned_scanner_and_fail_closed_rules(self) -> None:
        application = dependency_audit.load_policy(POLICY_PATH)
        geph = dependency_audit.load_policy(GEPH_POLICY_PATH)

        self.assertEqual(geph["scanner"], application["scanner"])
        self.assertEqual(geph["rules"], application["rules"])
        self.assertGreaterEqual(len(geph["exceptions"]), 1)

    def test_geph_schema_v1_report_remains_without_integrity_only_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report, sbom = self._build_report(
                root,
                osv_result(
                    (
                        {
                            "ecosystem": "crates.io",
                            "name": "serde",
                            "version": "1.0.228",
                        },
                        [],
                    )
                ),
                policy_path=GEPH_POLICY_PATH,
            )
            self.assertNotIn("integrity_only", report)
            self.assertNotIn("packages_integrity_only", report["summary"])
            summary = dependency_audit.validate_audit_report(
                report,
                policy_path=GEPH_POLICY_PATH,
                sbom_path=sbom,
                source_commit=SOURCE_COMMIT,
                target=TARGET,
            )
            self.assertEqual(summary["packages_scanned"], 1)
            self.assertEqual(summary["packages_integrity_only"], 0)

    def _build_report(
        self,
        root: Path,
        result: dict,
        *,
        evaluated_on: date = date(2026, 7, 16),
        vendored_transitive_dependencies: str = "top-level-only",
        policy_path: Path = POLICY_PATH,
        sbom_packages: list[dict] | None = None,
    ) -> tuple[dict, Path]:
        policy = dependency_audit.load_policy(policy_path)
        sbom = root / "Slipstream.spdx.json"
        if sbom_packages is None:
            packages = {
                (
                    entry["package"]["ecosystem"],
                    entry["package"]["name"],
                    entry["package"]["version"],
                )
                for source in result["results"]
                for entry in source["packages"]
            }
            sbom_packages = [
                {
                    "SPDXID": f"SPDXRef-Package-{index}",
                    "name": name,
                    "versionInfo": version,
                }
                for index, (_, name, version) in enumerate(
                    sorted(packages), start=1
                )
            ]
        sbom.write_text(
            json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "packages": sbom_packages,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        report = dependency_audit.build_audit_report(
            osv_result=result,
            policy=policy,
            policy_path=policy_path,
            sbom_path=sbom,
            scanner=scanner_metadata(policy),
            source_commit=SOURCE_COMMIT,
            target=TARGET,
            evaluated_on=evaluated_on,
            vendored_transitive_dependencies=vendored_transitive_dependencies,
        )
        return report, sbom

    def _application_policy_path(self, root: Path, **overrides: object) -> Path:
        policy = dependency_audit.load_policy(POLICY_PATH)
        integrity = copy.deepcopy(policy["integrity_only"][0])
        integrity.update(overrides)
        policy["integrity_only"] = [integrity]
        path = root / "policy.json"
        path.write_text(json.dumps(policy), encoding="utf-8")
        return path

    def _chromium_result(self, *, vulnerabilities: list[dict] | None = None) -> dict:
        return osv_result(
            (
                {
                    "ecosystem": "",
                    "name": "chromium-headless-shell",
                    "version": "151.0.7922.77",
                },
                vulnerabilities or [],
            )
        )

    def _chromium_sbom(self, *, sha256: str | None = None) -> list[dict]:
        return [
            sbom_package(
                ecosystem="generic",
                name="chromium-headless-shell",
                version="151.0.7922.77",
                sha256=sha256
                or dependency_audit.load_policy(POLICY_PATH)["integrity_only"][0][
                    "sha256"
                ],
            )
        ]

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

    def test_exact_chromium_incomplete_row_is_integrity_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report, sbom = self._build_report(
                root,
                self._chromium_result(),
                sbom_packages=self._chromium_sbom(),
            )

            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["summary"]["packages_scanned"], 0)
            self.assertEqual(report["summary"]["packages_integrity_only"], 1)
            self.assertEqual(
                report["integrity_only"][0]["purl"],
                "pkg:generic/chromium-headless-shell@151.0.7922.77",
            )
            summary = dependency_audit.validate_audit_report(
                report,
                policy_path=POLICY_PATH,
                sbom_path=sbom,
                source_commit=SOURCE_COMMIT,
                target=TARGET,
            )
            self.assertEqual(summary["packages_scanned"], 0)
            self.assertEqual(summary["packages_integrity_only"], 1)

    def test_unknown_or_vulnerable_incomplete_row_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unknown = osv_result(
                (
                    {"ecosystem": "", "name": "unknown", "version": "1.0"},
                    [],
                )
            )
            with self.assertRaisesRegex(ValueError, "not integrity-only allowlisted"):
                self._build_report(
                    root,
                    unknown,
                    sbom_packages=[
                        sbom_package(
                            ecosystem="generic",
                            name="unknown",
                            version="1.0",
                            sha256="11" * 32,
                        )
                    ],
                )

            with self.assertRaisesRegex(ValueError, "contains vulnerabilities"):
                self._build_report(
                    root,
                    self._chromium_result(
                        vulnerabilities=[vulnerability("GHSA-INCOMPLETE")]
                    ),
                    sbom_packages=self._chromium_sbom(),
                )

            duplicate = self._chromium_result()
            duplicate["results"][0]["packages"].append(
                copy.deepcopy(duplicate["results"][0]["packages"][0])
            )
            with self.assertRaisesRegex(ValueError, "duplicate integrity-only"):
                self._build_report(
                    root,
                    duplicate,
                    sbom_packages=self._chromium_sbom(),
                )

    def test_integrity_only_rejects_hash_purl_expiry_and_report_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            invalid_policy = self._application_policy_path(
                root,
                purl="pkg:generic/not-chromium@151.0.7922.77",
            )
            with self.assertRaisesRegex(ValueError, "purl is invalid"):
                dependency_audit.load_policy(invalid_policy)

            with self.assertRaisesRegex(ValueError, "checksum does not match policy"):
                self._build_report(
                    root,
                    self._chromium_result(),
                    sbom_packages=self._chromium_sbom(sha256="00" * 32),
                )

            invalid_purl = self._chromium_sbom()
            invalid_purl[0]["externalRefs"][0]["referenceLocator"] = (
                "pkg:generic/not-chromium@151.0.7922.77"
            )
            with self.assertRaisesRegex(ValueError, "purl does not match policy"):
                self._build_report(
                    root,
                    self._chromium_result(),
                    sbom_packages=invalid_purl,
                )

            expired_policy = self._application_policy_path(
                root, expires="2026-07-15"
            )
            with self.assertRaisesRegex(ValueError, "policy is expired"):
                self._build_report(
                    root,
                    self._chromium_result(),
                    policy_path=expired_policy,
                    sbom_packages=self._chromium_sbom(),
                )

            report, sbom = self._build_report(
                root,
                self._chromium_result(),
                sbom_packages=self._chromium_sbom(),
            )
            tampered = copy.deepcopy(report)
            tampered["integrity_only"][0]["sha256"] = "ff" * 32
            with self.assertRaisesRegex(ValueError, "does not match policy"):
                dependency_audit.validate_audit_report(
                    tampered,
                    policy_path=POLICY_PATH,
                    sbom_path=sbom,
                    source_commit=SOURCE_COMMIT,
                    target=TARGET,
                )

            tampered = copy.deepcopy(report)
            tampered["summary"]["packages_integrity_only"] = 0
            with self.assertRaisesRegex(ValueError, "count is inconsistent"):
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

    def test_policy_rejects_overlapping_exceptions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = dependency_audit.load_policy(POLICY_PATH)
            duplicate = copy.deepcopy(policy["exceptions"][0])
            duplicate["id"] = "overlapping-review"
            policy["exceptions"].append(duplicate)
            path = root / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "overlap"):
                dependency_audit.load_policy(path)

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

            tampered = copy.deepcopy(report)
            tampered["summary"]["packages_scanned"] = 999
            with self.assertRaisesRegex(ValueError, "package count"):
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

    def test_full_vendor_coverage_is_explicit_and_verified(self) -> None:
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
                vendored_transitive_dependencies="full",
            )
            self.assertEqual(
                report["coverage"]["vendored_transitive_dependencies"],
                "full",
            )
            dependency_audit.validate_audit_report(
                report,
                policy_path=POLICY_PATH,
                sbom_path=sbom,
                source_commit=SOURCE_COMMIT,
                target=TARGET,
                vendored_transitive_dependencies="full",
            )
            with self.assertRaisesRegex(ValueError, "coverage"):
                dependency_audit.validate_audit_report(
                    report,
                    policy_path=POLICY_PATH,
                    sbom_path=sbom,
                    source_commit=SOURCE_COMMIT,
                    target=TARGET,
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

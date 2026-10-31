from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from urllib.parse import quote

import dependency_audit


SOURCE_COMMIT = "a" * 40
TARGET = "aarch64-apple-darwin"
POLICY_PATH = dependency_audit.DEFAULT_POLICY
GEPH_POLICY_PATH = (
    Path(__file__).parent / "fixtures/geph-registry-policy-r3.json"
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
                "referenceLocator": (
                    f"pkg:{ecosystem}/{quote(name, safe='/' if ecosystem in {'npm', 'github'} else '')}"
                    f"@{quote(version, safe='')}"
                ),
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
            package_types = {
                "crates.io": "cargo", "PyPI": "pypi", "npm": "npm",
                "GitHub Actions": "github", "": "generic",
            }
            sbom_packages = [
                sbom_package(ecosystem=package_types[ecosystem], name=name, version=version)
                for ecosystem, name, version in sorted(packages)
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

    def _policy_with_reviewed_exception(self, root: Path) -> Path:
        policy = dependency_audit.load_policy(POLICY_PATH)
        policy["exceptions"] = [
            {
                "advisories": [
                    "RUSTSEC-2026-0194",
                    "RUSTSEC-2026-0195",
                ],
                "ecosystem": "crates.io",
                "expires": "2026-08-31",
                "id": "reviewed-test-exception",
                "package": "quick-xml",
                "reason": "Exercise exact reviewed-exception handling.",
                "version": "0.39.4",
            }
        ]
        path = root / "policy-with-reviewed-exception.json"
        path.write_text(json.dumps(policy), encoding="utf-8")
        return path

    def _chromium_result(self, *, vulnerabilities: list[dict] | None = None) -> dict:
        return osv_result(
            (
                {
                    "ecosystem": "",
                    "name": "chromium-headless-shell",
                    "version": "156.0.8078.80",
                },
                vulnerabilities or [],
            )
        )

    def _chromium_sbom(self, *, sha256: str | None = None) -> list[dict]:
        return [
            sbom_package(
                ecosystem="generic",
                name="chromium-headless-shell",
                version="156.0.8078.80",
                sha256=sha256
                or dependency_audit.load_policy(POLICY_PATH)["integrity_only"][0][
                    "sha256"
                ],
            )
        ]

    def test_reviewed_exception_and_informational_advisory_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path = self._policy_with_reviewed_exception(root)
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
            report, sbom = self._build_report(
                root, result, policy_path=policy_path
            )

            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["summary"]["accepted_exception"], 2)
            self.assertEqual(report["summary"]["informational"], 1)
            summary = dependency_audit.validate_audit_report(
                report,
                policy_path=policy_path,
                sbom_path=sbom,
                source_commit=SOURCE_COMMIT,
                target=TARGET,
            )
            self.assertEqual(summary["packages_scanned"], 2)

            tampered = copy.deepcopy(report)
            tampered["findings"][0]["package"]["version"] = "0.39.5"
            with self.assertRaisesRegex(ValueError, "exception package|package identity"):
                dependency_audit.validate_audit_report(
                    tampered,
                    policy_path=policy_path,
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
                "pkg:generic/chromium-headless-shell@156.0.8078.80",
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
                purl="pkg:generic/not-chromium@156.0.8078.80",
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
                "pkg:generic/not-chromium@156.0.8078.80"
            )
            with self.assertRaisesRegex(ValueError, "purl (?:identity does not match package|does not match policy)"):
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
            policy = dependency_audit.load_policy(
                self._policy_with_reviewed_exception(root)
            )
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
            root = Path(tmp)
            policy_path = self._policy_with_reviewed_exception(root)
            report, _ = self._build_report(
                root,
                result,
                evaluated_on=date(2026, 9, 1),
                policy_path=policy_path,
            )
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["findings"][0]["reason"], "expired_exception")

        result["results"][0]["packages"][0]["package"]["version"] = "0.39.5"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path = self._policy_with_reviewed_exception(root)
            report, _ = self._build_report(
                root, result, policy_path=policy_path
            )
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


class DependencyAuditIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sbom = self.root / "fixture.spdx.json"
        self.policy = dependency_audit.load_policy(GEPH_POLICY_PATH)
        self.policy_path = GEPH_POLICY_PATH
        self.serde = {"ecosystem": "crates.io", "name": "serde", "version": "1.0.228"}
        self.package = sbom_package(ecosystem="cargo", name="serde", version="1.0.228")

    def build(self, packages: list[dict], rows: list[dict], *, vulnerabilities: list[dict] | None = None) -> dict:
        self.sbom.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": packages}))
        return dependency_audit.build_audit_report(
            osv_result=osv_result(*((row, vulnerabilities or []) for row in rows)),
            policy=self.policy, policy_path=self.policy_path, sbom_path=self.sbom,
            scanner=dependency_audit.expected_scanner_metadata(self.policy, "darwin-arm64"),
            source_commit=SOURCE_COMMIT, target=TARGET, evaluated_on=date(2026, 10, 11),
            vendored_transitive_dependencies="full",
        )

    def verify(self, report: dict) -> dict:
        return dependency_audit.validate_audit_report(
            report, policy_path=self.policy_path, sbom_path=self.sbom,
            source_commit=SOURCE_COMMIT, target=TARGET,
            vendored_transitive_dependencies="full",
        )

    def test_rejects_same_count_wrong_name_version_or_ecosystem(self) -> None:
        for field, wrong in (("name", "not-serde"), ("version", "0.0.1"), ("ecosystem", "PyPI")):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "identit"):
                self.build([self.package], [self.serde | {field: wrong}])

    def test_rejects_source_owned_as_registry_and_unrelated_same_count_rows(self) -> None:
        local = [
            {"SPDXID": "SPDXRef-Source-" + str(i), "name": name, "versionInfo": version}
            for i, (name, version) in enumerate([
                ("mizaru2-slipstream-client", "0.1.0"),
                ("slipstream-rsa-client", "0.1.0"),
                ("geph5-broker-protocol", "0.4.3"),
            ])
        ]
        false_registry = [self.serde] + [
            {"ecosystem": "crates.io", "name": p["name"], "version": p["versionInfo"]}
            for p in local
        ]
        unrelated = [
            {"ecosystem": "crates.io", "name": "unrelated-" + str(i), "version": "1"}
            for i in range(4)
        ]
        for rows in (false_registry, unrelated):
            with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, "purl"):
                self.build([self.package, *local], rows)

    def test_rejects_omitted_and_duplicate_scanner_rows(self) -> None:
        with self.assertRaisesRegex(ValueError, "identit"):
            self.build([self.package], [])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.build([self.package], [self.serde, self.serde])

    def test_rejects_duplicate_sbom_ids_and_coordinate_aliases(self) -> None:
        other = sbom_package(ecosystem="cargo", name="other", version="1")
        other["SPDXID"] = self.package["SPDXID"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.build([self.package, other], [self.serde, {"ecosystem": "crates.io", "name": "other", "version": "1"}])
        alias = copy.deepcopy(self.package)
        alias["SPDXID"] = "SPDXRef-different-id-same-coordinates"
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.build([self.package, alias], [self.serde])

    def test_rejects_normalized_alias_duplicates_in_rows_and_sbom(self) -> None:
        for package_type, ecosystem, original, alias in (
            ("pypi", "PyPI", "Some_Package.Name", "some-package-name"),
            ("github", "GitHub Actions", "Owner/Project", "owner/project"),
        ):
            package = sbom_package(ecosystem=package_type, name=original, version="1")
            alias_package = sbom_package(ecosystem=package_type, name=alias, version="1")
            row = {"ecosystem": ecosystem, "name": original, "version": "1"}
            with self.subTest(ecosystem=ecosystem, duplicate="scanner"), self.assertRaisesRegex(ValueError, "duplicate"):
                self.build([package], [row, row | {"name": alias}])
            with self.subTest(ecosystem=ecosystem, duplicate="sbom"), self.assertRaisesRegex(ValueError, "duplicate"):
                self.build([package, alias_package], [row])

    def test_rejects_missing_multiple_unsupported_or_malformed_purls(self) -> None:
        invalid_purls = [
            "pkg:cargo/serde@1.0.228?repository_url=https://example.invalid",
            "pkg:cargo/serde@1.0.228#subpath", "pkg:cargo/serde@%ZZ",
            "pkg:cargo/serde@1.0.228%00", "pkg:cargo/serde@2",
            "pkg:unknown/serde@1.0.228", "pkg:cargo/not-serde@1.0.228",
        ]
        for locator in invalid_purls:
            bad = copy.deepcopy(self.package)
            bad["externalRefs"][0]["referenceLocator"] = locator
            with self.subTest(locator=locator), self.assertRaisesRegex(ValueError, "purl|identity"):
                self.build([bad], [self.serde])
        for refs in ([], self.package["externalRefs"] * 2):
            with self.subTest(refs=refs), self.assertRaisesRegex(ValueError, "purl"):
                self.build([self.package | {"externalRefs": refs}], [self.serde])

    def test_canonical_pypi_github_and_scoped_npm_coordinates(self) -> None:
        packages = [
            sbom_package(ecosystem="pypi", name="Some_Package.Name", version="1.0"),
            sbom_package(ecosystem="github", name="Flowseal/tg-ws-proxy", version="1.11.1"),
            sbom_package(ecosystem="npm", name="@tauri-apps/api", version="2.11.1"),
        ]
        packages[1]["name"] = "A display name"
        rows = [
            {"ecosystem": "PyPI", "name": "some-package-name", "version": "1.0"},
            {"ecosystem": "GitHub Actions", "name": "flowseal/tg-ws-proxy", "version": "1.11.1"},
            {"ecosystem": "npm", "name": "@tauri-apps/api", "version": "2.11.1"},
        ]
        report = self.build(packages, rows)
        self.assertEqual(report["scanned_packages"], sorted(rows, key=lambda p: (p["ecosystem"], p["name"], p["version"])))
        self.assertEqual(self.verify(report)["packages_scanned"], 3)

    def test_verify_requires_identity_evidence_and_rejects_tampering(self) -> None:
        report = self.build([self.package], [self.serde])
        self.assertEqual(self.verify(report)["packages_scanned"], 1)
        legacy = copy.deepcopy(report)
        legacy.pop("scanned_packages", None)
        with self.assertRaisesRegex(ValueError, "identity evidence"):
            self.verify(legacy)
        variants = [[], [self.serde, self.serde], [self.serde | {"name": "different"}], [self.serde | {"version": "0"}], [self.serde | {"ecosystem": "PyPI"}], [self.serde | {"extra": True}]]
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, "identit"):
                self.verify(report | {"scanned_packages": rows})

    def test_normalized_exceptions_match_and_verify_for_pypi_and_github(self) -> None:
        for package_type, ecosystem, name, normalized in (
            ("pypi", "PyPI", "Some_Package.Name", "some-package-name"),
            ("github", "GitHub Actions", "Owner/Project", "owner/project"),
        ):
            self.policy = dependency_audit.load_policy(GEPH_POLICY_PATH)
            self.policy["exceptions"] = [{
                "id": "fixture", "ecosystem": ecosystem, "package": name,
                "version": "1", "expires": "2026-10-31", "reason": "Offline identity fixture",
                "advisories": ["TEST-IDENTITY"],
            }]
            self.policy_path = self.root / "normalized-policy.json"
            self.policy_path.write_text(json.dumps(self.policy))
            self.policy = dependency_audit.load_policy(self.policy_path)
            for scanner_name in (name, normalized):
                with self.subTest(ecosystem=ecosystem, scanner_name=scanner_name):
                    report = self.build(
                        [sbom_package(ecosystem=package_type, name=name, version="1")],
                        [{"ecosystem": ecosystem, "name": scanner_name, "version": "1"}],
                        vulnerabilities=[{"id": "TEST-IDENTITY", "aliases": []}],
                    )
                    self.assertEqual(report["summary"]["accepted_exception"], 1)
                    self.assertEqual(self.verify(report)["accepted_exceptions"], 1)
            self.policy["exceptions"].append(self.policy["exceptions"][0] | {"id": "alias", "package": normalized})
            self.policy_path.write_text(json.dumps(self.policy))
            with self.assertRaisesRegex(ValueError, "overlap"):
                dependency_audit.load_policy(self.policy_path)


class NativeAuditBridgeTests(unittest.TestCase):
    """Partition/orchestration tests; native proof/schema has its own helper suite."""

    def setUp(self) -> None:
        import sys
        import types
        from unittest.mock import patch

        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sbom = self.root / "sbom.json"
        self.source = self.root / "SOURCE.json"
        self.artifacts = self.root / "artifacts"
        self.receipt = self.artifacts / "native-release.json"
        self.advisories = self.root / "advisories"
        self.policy_path = self.root / "policy.json"
        self.source.write_text("reviewed SOURCE")
        self.artifacts.mkdir()
        self.receipt.write_text("verified release receipt")
        self.advisories.mkdir()
        (self.artifacts / "proof").write_text("bound binary")
        (self.advisories / "review.json").write_text("review evidence")
        self.native = {"SPDXID": "SPDXRef-Native-SQLite", "name": "SQLite", "versionInfo": "3.53.2"}
        self.packages = [sbom_package(ecosystem="cargo", name="libsqlite3-sys", version="0.30.1"),
                         sbom_package(ecosystem="cargo", name="serde", version="1"), self.native]
        self.rows = [{"ecosystem": "crates.io", "name": package["name"], "version": package["versionInfo"]}
                     for package in self.packages[:-1]]
        self.sbom.write_text(json.dumps({"packages": self.packages, "documentDescribes": [self.native["SPDXID"]],
            "relationships": [{"spdxElementId": self.packages[0]["SPDXID"],
                               "relationshipType": "DEPENDS_ON", "relatedSpdxElement": self.native["SPDXID"]}]}))
        self.policy = dependency_audit.load_policy(GEPH_POLICY_PATH)
        self.policy.pop("source_owned_review", None)
        self.policy["native_sqlite_review"] = {"fixture_outcome": "pass"}
        self._save_policy()
        self.helper_calls = []
        helper = types.ModuleType("geph_native_sqlite_advisories")
        helper.validate_native_review = self._validate_review
        helper.retain_native_review_evidence = self._retain_review
        patcher = patch.dict(sys.modules, {"geph_native_sqlite_advisories": helper})
        patcher.start(); self.addCleanup(patcher.stop)

    def _save_policy(self) -> None:
        self.policy_path.write_text(json.dumps(self.policy))

    def _validate_review(self, review: dict, **kwargs) -> dict:
        self.helper_calls.append(kwargs)
        self.assertEqual(kwargs["source_path"].read_text(), "reviewed SOURCE")
        self.assertEqual(kwargs["native_receipt"].read_text(), "verified release receipt")
        self.assertTrue(kwargs["native_receipt"].is_relative_to(kwargs["native_artifacts_root"]))
        self.assertEqual((kwargs["native_artifacts_root"] / "proof").read_text(), "bound binary")
        self.assertEqual([package for package in kwargs["sbom"]["packages"]
                          if package["SPDXID"] == self.native["SPDXID"]], [self.native])
        if kwargs["evidence_root"] is not None:
            self.assertEqual((kwargs["evidence_root"] / "review.json").read_text(), "review evidence")
        outcome = review["fixture_outcome"]
        unresolved = int(outcome != "pass")
        return {"schema_version": 1, "package_id": self.native["SPDXID"], "review_sha256": "e" * 64,
                "binding": {"source_sha256": "s" * 64,
                            "native_receipt_sha256": dependency_audit.hash_file(kwargs["native_receipt"])},
                "census": {"fixture": True},
                "decisions": [{"outcome": outcome}], "status": "fail" if unresolved else "pass",
                "summary": {"groups_total": 1, "native_groups": 1, "excluded_groups": 0,
                            "adjudicated_not_affected": 1 - unresolved, "unknown": int(outcome == "unknown"),
                            "affected": int(outcome == "affected"), "census_only": int(outcome == "census_only"),
                            "unresolved": unresolved}}

    def _retain_review(self, review: dict, evidence_root: Path, output_root: Path) -> dict:
        output_root.mkdir(mode=0o700)
        metadata = dependency_audit._snapshot_audit_input(evidence_root / "review.json", output_root / "review.json", 1024)
        if metadata["sha256"] != __import__("hashlib").sha256(b"review evidence").hexdigest():
            raise ValueError("review evidence hash mismatch")
        return {"root": str(output_root), "files": [metadata], "bytes": metadata["size_bytes"]}

    def _build(self, *, rows=None, **overrides) -> dict:
        arguments = {"osv_result": osv_result(*((row, []) for row in (self.rows if rows is None else rows))),
            "policy": self.policy, "policy_path": self.policy_path, "sbom_path": self.sbom,
            "scanner": scanner_metadata(self.policy), "source_commit": SOURCE_COMMIT, "target": TARGET,
            "evaluated_on": date(2026, 10, 13), "vendored_transitive_dependencies": "full",
            "source_path": self.source, "native_receipt": self.receipt,
            "native_artifacts_root": self.artifacts, "native_advisory_evidence": self.advisories}
        return dependency_audit.build_audit_report(**(arguments | overrides))

    def _verify(self, report: dict, **overrides) -> dict:
        arguments = {"policy_path": self.policy_path, "sbom_path": self.sbom, "source_commit": SOURCE_COMMIT,
            "target": TARGET, "vendored_transitive_dependencies": "full", "source_path": self.source,
            "native_receipt": self.receipt, "native_artifacts_root": self.artifacts}
        return dependency_audit.validate_audit_report(report, **(arguments | overrides))

    def test_native_schema2_exact_partition_and_scanner_projection(self) -> None:
        report = self._build()
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["coverage"]["sbom_packages"], "partitioned")
        self.assertEqual(report["package_partition"], {"scanned": sorted(package["SPDXID"] for package in self.packages[:-1]),
                                                     "integrity_only": [], "native": [self.native["SPDXID"]]})
        projection = json.loads(dependency_audit._native_scanner_sbom(json.loads(self.sbom.read_text()), self.native["SPDXID"]))
        self.assertEqual(projection["packages"], self.packages[:-1])
        self.assertEqual(projection["relationships"], [])
        self.assertEqual(projection["documentDescribes"], [])
        self.assertEqual(report["summary"]["packages_scanned"], 2)
        self.assertEqual(self._verify(report)["packages_native"], 1)
        self.assertIsNone(self.helper_calls[-1]["evidence_root"])

    def test_registry_generic_and_native_partitions_are_disjoint_and_complete(self) -> None:
        generic = {"name": "fixture-generic", "version": "1", "purl": "pkg:generic/fixture-generic@1",
                   "sha256": "f" * 64, "reason": "fixture integrity review", "expires": "2099-01-01"}
        self.policy["integrity_only"] = [generic]
        self._save_policy()
        sbom = json.loads(self.sbom.read_text())
        package = sbom_package(ecosystem="generic", name=generic["name"], version="1", sha256=generic["sha256"])
        sbom["packages"].append(package)
        self.sbom.write_text(json.dumps(sbom))
        rows = self.rows + [{"ecosystem": "", "name": generic["name"], "version": "1"}]
        report = self._build(rows=rows)
        self.assertEqual(report["package_partition"]["integrity_only"], [package["SPDXID"]])
        self.assertEqual(self._verify(report)["packages_integrity_only"], 1)
        with self.assertRaisesRegex(ValueError, "identities do not cover"):
            self._build()
        report["package_partition"]["integrity_only"] = []
        report["package_partition"]["native"].append(package["SPDXID"])
        with self.assertRaisesRegex(ValueError, "partition"):
            self._verify(report)

    def test_unknown_affected_and_census_only_block_even_if_report_claims_pass(self) -> None:
        for outcome in ("unknown", "affected", "census_only"):
            with self.subTest(outcome=outcome):
                self.policy["native_sqlite_review"]["fixture_outcome"] = outcome
                self._save_policy()
                report = self._build()
                self.assertEqual(report["status"], "fail")
                self.assertEqual(report["summary"]["native_unresolved"], 1)
                report["status"] = "pass"
                with self.assertRaisesRegex(ValueError, "unresolved or affected"):
                    self._verify(report)
                report["native_sqlite_review"]["status"] = "pass"
                report["native_sqlite_review"]["summary"]["unresolved"] = 0
                with self.assertRaisesRegex(ValueError, "native review"):
                    self._verify(report)

    def test_forged_native_counts_identity_partition_and_projection_are_rejected(self) -> None:
        report = self._build()
        mutations = [
            lambda value: value["native_sqlite_review"].update(package_id="SPDXRef-forged"),
            lambda value: value["native_sqlite_review"]["summary"].update(groups_total=True),
            lambda value: value["summary"].update(packages_native=0),
            lambda value: value["summary"].update(native_unresolved=True),
            lambda value: value["package_partition"]["scanned"].pop(),
            lambda value: value["package_partition"]["native"].append("SPDXRef-forged"),
            lambda value: value["inputs"].update(scanner_sbom_sha256="0" * 64),
            lambda value: value["scanned_packages"].pop(),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                changed = copy.deepcopy(report); mutate(changed)
                with self.assertRaises(ValueError): self._verify(changed)

    def test_wrapper_and_every_registry_identity_remain_required(self) -> None:
        for rows in (self.rows[1:], self.rows + [self.rows[0]],
                     self.rows[1:] + [{"ecosystem": "crates.io", "name": "SQLite", "version": "3.53.2"}],
                     self.rows + [{"ecosystem": "", "name": "SQLite", "version": "3.53.2"}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError): self._build(rows=rows)

    def test_other_missing_purl_package_is_not_covered_by_native_review(self) -> None:
        sbom = json.loads(self.sbom.read_text())
        sbom["packages"].append({"SPDXID": "SPDXRef-source-owned", "name": "another-source", "versionInfo": "1"})
        self.sbom.write_text(json.dumps(sbom))
        with self.assertRaisesRegex(ValueError, "purl"): self._build()

    def test_native_inputs_require_policy_and_all_explicit_paths(self) -> None:
        for argument in ("source_path", "native_receipt", "native_artifacts_root", "native_advisory_evidence"):
            with self.subTest(argument=argument), self.assertRaisesRegex(ValueError, "explicit"):
                self._build(**{argument: None})
        report = self._build()
        for argument in ("source_path", "native_receipt", "native_artifacts_root"):
            with self.subTest(argument=argument), self.assertRaisesRegex(ValueError, "explicit"):
                self._verify(report, **{argument: None})
        del self.policy["native_sqlite_review"]
        self._save_policy()
        with self.assertRaisesRegex(ValueError, "trusted native_sqlite_review"): self._build()
        with self.assertRaisesRegex(ValueError, "trusted native_sqlite_review"): self._verify(report)

    def test_cli_rejects_partial_native_inputs_and_unretained_scan(self) -> None:
        import contextlib
        import io

        common = ["--sbom", str(self.sbom), "--policy", str(self.policy_path),
                  "--source-commit", SOURCE_COMMIT, "--target", TARGET]
        for command in ("scan", "verify"):
            base = [command, *common] + (["--scanner", "unused", "--platform", "darwin-arm64",
                "--evaluation-date", "2026-10-13", "--output", "unused"] if command == "scan" else ["--report", "unused"])
            groups = [["--source", str(self.source)], ["--native-receipt", str(self.receipt)]]
            if command == "scan":
                groups += [["--source", str(self.source), "--native-receipt", str(self.receipt),
                            "--native-artifacts-root", str(self.artifacts)], ["--native-advisory-evidence", str(self.advisories)]]
            for args in groups:
                with self.subTest(command=command, args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    dependency_audit.parse_args(base + args)

    def test_native_scan_retains_frozen_authority_and_projects_only_verified_package(self) -> None:
        import contextlib
        import io
        import sys

        scanner = self.root / "fixture-scanner"
        raw = osv_result(*((row, []) for row in self.rows))
        scanner.write_text(f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
            "if '--version' in sys.argv:\n    print('osv-scanner version 2.3.0'); raise SystemExit(0)\n"
            "projection=Path(sys.argv[sys.argv.index('-L')+1])\nassert projection.name == 'native-scanner.spdx.json'\n"
            f"assert json.loads(projection.read_text())['packages'] == {self.packages[:-1]!r}\n"
            f"assert len(json.loads(Path('input.spdx.json').read_text())['packages']) == 3\n"
            f"Path({str(self.source)!r}).write_text('changed original')\n"
            f"Path({str(self.advisories / 'review.json')!r}).write_text('changed original')\n"
            f"Path(sys.argv[sys.argv.index('--output-file')+1]).write_text({json.dumps(raw)!r})\n")
        scanner.chmod(0o700)
        self.policy["scanner"]["version"] = "2.3.0"
        self.policy["scanner"]["assets"]["darwin-arm64"]["sha256"] = dependency_audit.hash_file(scanner)
        self._save_policy()
        evidence = self.root / "retained"
        output = self.root / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            result = dependency_audit.main(["scan", "--scanner", str(scanner), "--platform", "darwin-arm64",
                "--sbom", str(self.sbom), "--policy", str(self.policy_path), "--source-commit", SOURCE_COMMIT,
                "--target", TARGET, "--evaluation-date", "2026-10-13", "--output", str(output),
                "--evidence-dir", str(evidence), "--source", str(self.source), "--native-receipt", str(self.receipt),
                "--native-artifacts-root", str(self.artifacts), "--native-advisory-evidence", str(self.advisories),
                "--vendored-transitive-dependencies", "full"])
        self.assertEqual(result, 0, (evidence / "receipt.json").read_text())
        report = json.loads(output.read_text())
        receipt = json.loads((evidence / "receipt.json").read_text())
        self.assertEqual(report["inputs"]["scanner_sbom_sha256"], receipt["inputs"]["scanner_sbom"]["sha256"])
        self.assertEqual((evidence / "source.json").read_text(), "reviewed SOURCE")
        self.assertEqual((evidence / "native_receipt.json").read_text(), "verified release receipt")
        self.assertEqual((evidence / "native-advisories/review.json").read_text(), "review evidence")
        self._verify(report, source_path=evidence / "source.json")
        with contextlib.redirect_stdout(io.StringIO()):
            result = dependency_audit.main(["verify", "--report", str(output), "--sbom", str(self.sbom),
                "--policy", str(self.policy_path), "--source-commit", SOURCE_COMMIT, "--target", TARGET,
                "--source", str(evidence / "source.json"), "--native-receipt", str(self.receipt),
                "--native-artifacts-root", str(self.artifacts), "--vendored-transitive-dependencies", "full"])
        self.assertEqual(result, 0)

    def test_invalid_native_evidence_is_retained_and_rejected_before_scanner(self) -> None:
        import contextlib
        import io
        from unittest.mock import patch

        (self.advisories / "review.json").write_text("wrong evidence")
        evidence = self.root / "retained-bad"
        output = self.root / "report.json"
        with patch.object(dependency_audit, "verify_scanner") as scanner, contextlib.redirect_stdout(io.StringIO()):
            result = dependency_audit.main(["scan", "--scanner", "must-not-execute", "--platform", "darwin-arm64",
                "--sbom", str(self.sbom), "--policy", str(self.policy_path), "--source-commit", SOURCE_COMMIT,
                "--target", TARGET, "--evaluation-date", "2026-10-13", "--output", str(output),
                "--evidence-dir", str(evidence), "--source", str(self.source), "--native-receipt", str(self.receipt),
                "--native-artifacts-root", str(self.artifacts), "--native-advisory-evidence", str(self.advisories)])
            scanner.assert_not_called()
        self.assertEqual(result, 1)
        self.assertFalse(output.exists())
        receipt = json.loads((evidence / "receipt.json").read_text())
        self.assertEqual(receipt["status"], "error")
        self.assertEqual(receipt["stage"], "native_evidence")
        self.assertEqual((evidence / "native-advisories/review.json").read_text(), "wrong evidence")

if __name__ == "__main__":
    unittest.main()

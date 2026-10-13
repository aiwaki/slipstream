from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

import dependency_audit as audit
from test_dependency_audit import GEPH_POLICY_PATH, SOURCE_COMMIT, TARGET, osv_result, sbom_package


class DependencyAuditIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sbom = self.root / "fixture.spdx.json"
        self.policy = audit.load_policy(GEPH_POLICY_PATH)
        self.policy_path = GEPH_POLICY_PATH
        self.serde = {"ecosystem": "crates.io", "name": "serde", "version": "1.0.228"}
        self.package = sbom_package(ecosystem="cargo", name="serde", version="1.0.228")

    def build(self, packages: list[dict], rows: list[dict], *, vulnerabilities: list[dict] | None = None) -> dict:
        self.sbom.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": packages}))
        return audit.build_audit_report(
            osv_result=osv_result(*((row, vulnerabilities or []) for row in rows)),
            policy=self.policy, policy_path=self.policy_path, sbom_path=self.sbom,
            scanner=audit.expected_scanner_metadata(self.policy, "darwin-arm64"),
            source_commit=SOURCE_COMMIT, target=TARGET, evaluated_on=date(2026, 10, 11),
            vendored_transitive_dependencies="full",
        )

    def verify(self, report: dict) -> dict:
        return audit.validate_audit_report(
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
            self.policy = audit.load_policy(GEPH_POLICY_PATH)
            self.policy["exceptions"] = [{
                "id": "fixture", "ecosystem": ecosystem, "package": name,
                "version": "1", "expires": "2026-10-31", "reason": "Offline identity fixture",
                "advisories": ["TEST-IDENTITY"],
            }]
            self.policy_path = self.root / "normalized-policy.json"
            self.policy_path.write_text(json.dumps(self.policy))
            self.policy = audit.load_policy(self.policy_path)
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
                audit.load_policy(self.policy_path)


if __name__ == "__main__":
    unittest.main()

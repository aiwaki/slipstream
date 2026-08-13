from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import make_release_sbom
import release_transport_matrix as matrix


SOURCE = "1" * 40
CANDIDATE = f"release-candidate-{SOURCE}"
DIGEST = "2" * 64


def installed_evidence() -> dict:
    return {
        "attestation_schema_version": 3,
        "listener_hosts": ["127.0.0.1", "::1"],
        "listener_port": 1080,
        "natlook_families": ["inet", "inet6"],
        "ipv6_runtime_proof": "lo0_rdr_and_natlook",
        "ipv6_non_lo0_route_to": "loaded_rule_static_only",
        "pf_rule_families": ["inet", "inet6"],
        "startup_health_probe": "passed",
        "state": "active",
    }


def pf_evidence() -> dict:
    return {
        "result": "pass",
        "global_pf": "unchanged",
        "loopback_skip": "restored",
        "natlook_families": ["inet", "inet6"],
        "ipv6_fixture": "owned_lo0_alias_restored",
        "ipv6_runtime_proof": "lo0_rdr_and_natlook",
        "ipv6_non_lo0_route_to": "loaded_rule_static_only",
        "target_port": 18443,
        "proxy_port": 19443,
    }


def quic_evidence() -> dict:
    return {
        "schema_version": 1,
        "result": "passed",
        "versions": ["v1", "v2"],
        "families": ["inet", "inet6"],
        "exact_host_fallback": True,
        "protected_routes_isolation": True,
        "network_mutated": False,
    }


def build_report() -> dict:
    return matrix.build(
        source_commit=SOURCE,
        candidate_id=CANDIDATE,
        candidate_manifest_sha256=DIGEST,
        app_tree_sha256="3" * 64,
        candidate_run_id=42,
        candidate_run_attempt=3,
        readiness_run_id=99,
        readiness_run_attempt=2,
        installed_candidate=installed_evidence(),
        pf_report=pf_evidence(),
        quic_report=quic_evidence(),
    )


class ReleaseTransportMatrixTests(unittest.TestCase):
    def test_report_separates_mechanics_from_live_origin_claims(self) -> None:
        report = build_report()
        self.assertEqual(report["result"], "passed")
        self.assertEqual(
            {item["name"] for item in report["scenarios"]},
            set(matrix.SCENARIOS),
        )
        quic = report["scenarios"][2]
        self.assertEqual(quic["versions"], ["v1", "v2"])
        self.assertEqual(quic["families"], ["inet", "inet6"])
        self.assertFalse(quic["live_origin_transport_asserted"])
        self.assertEqual(
            report["scenarios"][0]["ipv6_runtime_proof"],
            "lo0_rdr_and_natlook",
        )
        self.assertEqual(
            report["scenarios"][0]["ipv6_non_lo0_route_to"],
            "loaded_rule_static_only",
        )
        self.assertEqual(report["real_origin_evidence"], "live-sites.json")
        self.assertEqual(len(report["limitations"]), 2)

    def test_build_rejects_missing_ipv6_or_failed_quic(self) -> None:
        installed = installed_evidence()
        installed["listener_hosts"] = ["127.0.0.1"]
        with self.assertRaisesRegex(ValueError, "installed candidate"):
            matrix.build(
                source_commit=SOURCE,
                candidate_id=CANDIDATE,
                candidate_manifest_sha256=DIGEST,
                app_tree_sha256="3" * 64,
                candidate_run_id=42,
                candidate_run_attempt=3,
                readiness_run_id=99,
                readiness_run_attempt=2,
                installed_candidate=installed,
                pf_report=pf_evidence(),
                quic_report=quic_evidence(),
            )
        with self.assertRaisesRegex(ValueError, "QUIC"):
            matrix.build(
                source_commit=SOURCE,
                candidate_id=CANDIDATE,
                candidate_manifest_sha256=DIGEST,
                app_tree_sha256="3" * 64,
                candidate_run_id=42,
                candidate_run_attempt=3,
                readiness_run_id=99,
                readiness_run_attempt=2,
                installed_candidate=installed_evidence(),
                pf_report=pf_evidence(),
                quic_report={"result": "failed"},
            )

    def test_build_rejects_overclaimed_ipv6_route_to_runtime_proof(self) -> None:
        installed = installed_evidence()
        installed["ipv6_non_lo0_route_to"] = "runtime_passed"
        with self.assertRaisesRegex(ValueError, "installed candidate"):
            matrix.build(
                source_commit=SOURCE,
                candidate_id=CANDIDATE,
                candidate_manifest_sha256=DIGEST,
                app_tree_sha256="3" * 64,
                candidate_run_id=42,
                candidate_run_attempt=3,
                readiness_run_id=99,
                readiness_run_attempt=2,
                installed_candidate=installed,
                pf_report=pf_evidence(),
                quic_report=quic_evidence(),
            )
    def test_validator_rejects_a_different_readiness_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / matrix.REPORT_NAME
            make_release_sbom.write_json_atomic(report, build_report())
            with self.assertRaisesRegex(ValueError, "exact protected evidence"):
                matrix.validate(
                    report,
                    source_commit=SOURCE,
                    candidate_id=CANDIDATE,
                    candidate_manifest_sha256=DIGEST,
                    app_tree_sha256="3" * 64,
                    candidate_run_id=42,
                    candidate_run_attempt=3,
                    readiness_run_id=99,
                    readiness_run_attempt=3,
                )

    def test_validator_rejects_a_live_transport_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / matrix.REPORT_NAME
            report = build_report()
            report["scenarios"][2]["live_origin_transport_asserted"] = True
            make_release_sbom.write_json_atomic(path, report)
            with self.assertRaisesRegex(ValueError, "exact protected evidence"):
                matrix.validate(
                    path,
                    source_commit=SOURCE,
                    candidate_id=CANDIDATE,
                    candidate_manifest_sha256=DIGEST,
                    app_tree_sha256="3" * 64,
                    candidate_run_id=42,
                    candidate_run_attempt=3,
                    readiness_run_id=99,
                    readiness_run_attempt=2,
                )


if __name__ == "__main__":
    unittest.main()

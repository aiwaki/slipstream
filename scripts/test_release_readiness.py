from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import release_readiness


def live_report(result: str = "passed") -> dict:
    sites = []
    for host in release_readiness.REQUIRED_HOSTS:
        site_result = "usable"
        controls = {"direct": "not_needed", "owned_geph": "not_needed"}
        outcomes = ("usable", "usable")
        if result == "inconclusive" and host == release_readiness.REQUIRED_HOSTS[0]:
            site_result = "inconclusive"
            controls = {"direct": "unavailable", "owned_geph": "unavailable"}
            outcomes = ("terminal_error", "terminal_error")
        sites.append(
            {
                "browsers": [
                    {
                        "browser": browser,
                        "deadline_ms": release_readiness.HOST_DEADLINES_MS[host],
                        "elapsed_ms": 1_000,
                        "outcome": outcome,
                        "route": "slipstream_selected",
                    }
                    for browser, outcome in zip(("chrome", "safari"), outcomes)
                ],
                "controls": controls,
                "host": host,
                "result": site_result,
            }
        )
    status = {"passed": 0, "failed": 1, "inconclusive": 2}[result]
    return {
        "schema_version": 1,
        "harness": "safari_chrome_live_sites",
        "harness_exit_status": status,
        "result": result,
        "sites": sites,
    }


def soak_report(*, seconds: float = 1800.1, counter: str | None = None) -> dict:
    counters = {name: 0 for name in release_readiness.ZERO_COUNTERS}
    if counter:
        counters[counter] = 1
    passed = seconds >= 1800 and counter is None
    return {
        "schema_version": 1,
        "harness": "packaged_macos_invisibility_soak",
        "harness_exit_status": 0 if passed else 1,
        "result": "passed" if passed else "failed",
        "requested_duration_seconds": 1800,
        "measured_duration_seconds": seconds,
        "sample_interval_seconds": 0.5,
        "max_sample_gap_seconds": 0.5,
        "visibility_samples": 3600,
        "counters": counters,
        "daemon_pid_stable": True,
        "heartbeat_advanced": True,
    }


class ReleaseReadinessTests(unittest.TestCase):
    def test_live_matrix_requires_two_usable_browsers(self) -> None:
        report = live_report()
        self.assertEqual(release_readiness.validate_live_report(report, 0), "passed")
        report["sites"][0]["browsers"][0]["outcome"] = "terminal_error"
        with self.assertRaisesRegex(ValueError, "two browser successes"):
            release_readiness.validate_live_report(report, 0)

    def test_inconclusive_requires_both_control_routes_unavailable(self) -> None:
        report = live_report("inconclusive")
        self.assertEqual(
            release_readiness.validate_live_report(report, 2), "inconclusive"
        )
        report["sites"][0]["controls"]["owned_geph"] = "reachable"
        with self.assertRaisesRegex(ValueError, "both independent control routes"):
            release_readiness.validate_live_report(report, 2)

    def test_soak_requires_measured_1800_seconds_and_zero_visibility(self) -> None:
        self.assertEqual(
            release_readiness.validate_soak_report(soak_report(), 0), "passed"
        )
        short = soak_report(seconds=1799.9)
        short.update({"harness_exit_status": 0, "result": "passed"})
        with self.assertRaisesRegex(ValueError, "measured evidence"):
            release_readiness.validate_soak_report(short, 0)
        visible = soak_report(counter="frontmost_changes")
        visible.update({"harness_exit_status": 0, "result": "passed"})
        with self.assertRaisesRegex(ValueError, "measured evidence"):
            release_readiness.validate_soak_report(visible, 0)

    def test_proof_binds_candidate_attempt_evidence_and_readiness_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            app = root / "Slipstream.app"
            app.mkdir()
            manifest = {
                "candidate_id": "release-candidate-" + "1" * 40,
                "version": "0.1.9",
                "target": "aarch64-apple-darwin",
                "app_tree_sha256": "2" * 64,
                "source": {
                    "repository": "aiwaki/slipstream",
                    "commit": "1" * 40,
                    "tree": "3" * 40,
                    "archive_sha256": "4" * 64,
                    "source_date_epoch": 1,
                },
            }
            (candidate / "release-candidate-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            manifest_sha256, _ = (
                release_readiness.release_candidate.make_release_manifest.hash_regular_file(
                    candidate / "release-candidate-manifest.json"
                )
            )
            live = root / "live.json"
            live.write_text(json.dumps(live_report()), encoding="utf-8")
            soak = root / "soak.json"
            soak.write_text(json.dumps(soak_report()), encoding="utf-8")
            transport = root / "transport.json"
            transport.write_text(
                json.dumps(
                    release_readiness.release_transport_matrix.build(
                        source_commit="1" * 40,
                        candidate_id=manifest["candidate_id"],
                        candidate_manifest_sha256=manifest_sha256,
                        app_tree_sha256=manifest["app_tree_sha256"],
                        candidate_run_id=42,
                        candidate_run_attempt=3,
                        readiness_run_id=77,
                        readiness_run_attempt=2,
                        installed_candidate={
                            "attestation_schema_version": 3,
                            "listener_hosts": ["127.0.0.1", "::1"],
                            "listener_port": 1080,
                            "natlook_families": ["inet", "inet6"],
                            "ipv6_runtime_proof": "lo0_rdr_and_natlook",
                            "ipv6_non_lo0_route_to": "loaded_rule_static_only",
                            "pf_rule_families": ["inet", "inet6"],
                            "startup_health_probe": "passed",
                            "state": "active",
                        },
                        pf_report={
                            "result": "pass",
                            "global_pf": "unchanged",
                            "loopback_skip": "restored",
                            "natlook_families": ["inet", "inet6"],
                            "ipv6_fixture": "owned_lo0_alias_restored",
                            "ipv6_runtime_proof": "lo0_rdr_and_natlook",
                            "ipv6_non_lo0_route_to": "loaded_rule_static_only",
                            "target_port": 18443,
                            "proxy_port": 19443,
                        },
                        quic_report={
                            "schema_version": 1,
                            "result": "passed",
                            "versions": ["v1", "v2"],
                            "families": ["inet", "inet6"],
                            "exact_host_fallback": True,
                            "protected_routes_isolation": True,
                            "network_mutated": False,
                        },
                    )
                ),
                encoding="utf-8",
            )
            with mock.patch.object(
                release_readiness.release_candidate,
                "validate_manifest",
                return_value={
                    "artifact_count": 6,
                    "manifest_sha256": manifest_sha256,
                },
            ) as validate:
                proof = release_readiness.build_proof(
                    candidate_dir=candidate,
                    app_tree=app,
                    live_report_path=live,
                    live_exit_status=0,
                    soak_report_path=soak,
                    soak_exit_status=0,
                    transport_report_path=transport,
                    candidate_run_id=42,
                    candidate_run_attempt=3,
                    readiness_run_id=77,
                    readiness_run_attempt=2,
                )
            self.assertEqual(proof["readiness"]["result"], "passed")
            self.assertEqual(proof["candidate_build"]["run_attempt"], 3)
            self.assertEqual(proof["readiness"]["run_attempt"], 2)
            self.assertEqual(proof["transport_mechanics"]["result"], "passed")
            self.assertEqual(validate.call_args.kwargs["app_tree"], app)
            self.assertEqual(
                validate.call_args.kwargs["expected_workflow_run_attempt"], 3
            )


if __name__ == "__main__":
    unittest.main()

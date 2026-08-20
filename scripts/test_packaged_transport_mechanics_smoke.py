from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import packaged_transport_mechanics_smoke as smoke


class PackagedTransportMechanicsSmokeTests(unittest.TestCase):
    def test_installed_natlook_owns_ipv6_alias_only_around_matrix(self) -> None:
        fixture = mock.Mock()
        fixture.install.return_value = smoke.pf.IPV6_LOOPBACK_TEST_DESTINATION
        with mock.patch.object(
            smoke.pf,
            "IPv6LoopbackAliasFixture",
            return_value=fixture,
        ), mock.patch.object(smoke, "_probe_installed_natlook") as probe:
            smoke._probe_installed_natlook_matrix(501, 20)

        self.assertEqual(
            probe.call_args_list,
            [
                mock.call(smoke.pf.TEST_DESTINATION, 501, 20),
                mock.call(smoke.pf.IPV6_LOOPBACK_TEST_DESTINATION, 501, 20),
            ],
        )
        fixture.install.assert_called_once_with()
        fixture.cleanup.assert_called_once_with()

    def test_installed_natlook_cleans_ipv6_alias_after_probe_exception(self) -> None:
        fixture = mock.Mock()
        fixture.install.return_value = smoke.pf.IPV6_LOOPBACK_TEST_DESTINATION
        with mock.patch.object(
            smoke.pf,
            "IPv6LoopbackAliasFixture",
            return_value=fixture,
        ), mock.patch.object(
            smoke,
            "_probe_installed_natlook",
            side_effect=(None, RuntimeError("probe failed")),
        ):
            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                smoke._probe_installed_natlook_matrix(501, 20)

        fixture.cleanup.assert_called_once_with()

    def test_installed_natlook_cleanup_failure_fails_the_gate(self) -> None:
        fixture = mock.Mock()
        fixture.install.return_value = smoke.pf.IPV6_LOOPBACK_TEST_DESTINATION
        fixture.cleanup.side_effect = smoke.pf.SmokeError("alias leaked")
        with mock.patch.object(
            smoke.pf,
            "IPv6LoopbackAliasFixture",
            return_value=fixture,
        ), mock.patch.object(smoke, "_probe_installed_natlook"):
            with self.assertRaisesRegex(
                smoke.TransportMechanicsError,
                "fixture cleanup failed: alias leaked",
            ):
                smoke._probe_installed_natlook_matrix(501, 20)

    @mock.patch.dict(
        os.environ,
        {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_RELEASE_READINESS": "1",
        },
        clear=False,
    )
    def test_gate_binds_measured_steps_to_exact_candidate_and_run(self) -> None:
        order: list[str] = []

        quic_report = {"result": "passed", "network_mutated": False}

        def installed(_app_bundle: Path) -> tuple[dict, dict]:
            order.append("installed")
            return {"installed": True}, quic_report

        def pf_gate(**_kwargs) -> dict:
            order.append("pf")
            return {"pf": True}

        with (
            mock.patch.object(
                smoke,
                "_validated_candidate_identity",
                return_value={
                    "candidate_id": "release-candidate-" + "1" * 40,
                    "manifest_sha256": "2" * 64,
                    "app_tree_sha256": "3" * 64,
                },
            ),
            mock.patch.object(smoke, "_qualify_installed_candidate", side_effect=installed),
            mock.patch.object(smoke.pf, "run_smoke", side_effect=pf_gate),
            mock.patch.object(
                smoke.release_transport_matrix,
                "build",
                return_value={"result": "passed"},
            ) as build,
        ):
            result = smoke.run_gate(
                candidate_dir=Path("candidate"),
                app_bundle=Path("Slipstream.app"),
                source_commit="1" * 40,
                candidate_run_id=42,
                candidate_run_attempt=3,
                readiness_run_id=99,
                readiness_run_attempt=2,
            )

        self.assertEqual(result, {"result": "passed"})
        self.assertEqual(order, ["installed", "pf"])
        self.assertEqual(build.call_args.kwargs["candidate_run_attempt"], 3)
        self.assertEqual(build.call_args.kwargs["readiness_run_attempt"], 2)
        self.assertEqual(build.call_args.kwargs["installed_candidate"], {"installed": True})
        self.assertEqual(build.call_args.kwargs["pf_report"], {"pf": True})
        self.assertEqual(build.call_args.kwargs["quic_report"], quic_report)

    @mock.patch.dict(
        os.environ,
        {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_RELEASE_READINESS": "1",
        },
        clear=False,
    )
    def test_failed_install_never_runs_private_pf_or_quic(self) -> None:
        with (
            mock.patch.object(
                smoke,
                "_validated_candidate_identity",
                return_value={
                    "candidate_id": "release-candidate-" + "1" * 40,
                    "manifest_sha256": "2" * 64,
                    "app_tree_sha256": "3" * 64,
                },
            ),
            mock.patch.object(
                smoke,
                "_qualify_installed_candidate",
                side_effect=smoke.TransportMechanicsError("install failed"),
            ),
            mock.patch.object(smoke.pf, "run_smoke") as pf_gate,
        ):
            with self.assertRaisesRegex(smoke.TransportMechanicsError, "install failed"):
                smoke.run_gate(
                    candidate_dir=Path("candidate"),
                    app_bundle=Path("Slipstream.app"),
                    source_commit="1" * 40,
                    candidate_run_id=42,
                    candidate_run_attempt=3,
                    readiness_run_id=99,
                    readiness_run_attempt=2,
                )
        pf_gate.assert_not_called()

    def test_quic_gate_executes_the_installed_daemon_with_capability_and_timeout(self) -> None:
        report = {"result": "passed", "network_mutated": False}
        completed = subprocess.CompletedProcess(
            [], 0, stdout='{"result":"passed","network_mutated":false}\n', stderr=""
        )
        with mock.patch.object(smoke.subprocess, "run", return_value=completed) as run:
            self.assertEqual(smoke._run_packaged_quic_gate(Path("/installed/slipstreamd")), report)
        self.assertEqual(
            run.call_args.args[0],
            ["/installed/slipstreamd", "--transport-mechanics-selftest"],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 20)
        self.assertEqual(
            run.call_args.kwargs["env"]["SLIPSTREAM_TRANSPORT_SELFTEST"], "1"
        )

    def test_unprotected_invocation_is_rejected_before_candidate_access(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(smoke.TransportMechanicsError, "protected CI"):
                smoke.run_gate(
                    candidate_dir=Path("candidate"),
                    app_bundle=Path("Slipstream.app"),
                    source_commit="1" * 40,
                    candidate_run_id=42,
                    candidate_run_attempt=3,
                    readiness_run_id=99,
                    readiness_run_attempt=2,
                )


if __name__ == "__main__":
    unittest.main()

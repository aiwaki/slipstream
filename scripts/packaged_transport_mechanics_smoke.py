#!/usr/bin/env python3
"""Protected macOS gate for exact-candidate TCP/PF and QUIC mechanics.

The candidate is installed long enough to prove its dual-stack listener,
attestation, startup health transaction, and dual-family production PF rules.
After complete uninstall, a scoped non-production PF transaction exercises
Darwin DIOCNATLOOK for IPv4 and IPv6.  Finally, encrypted deterministic QUIC
Initial datagrams exercise v1/v2 observation and exact-host fallback for both
address families.  Real-origin usability remains the responsibility of the
separate Safari/Chrome live-site gate.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import make_release_sbom
import pf_anchor_smoke as pf
import pf_installed_lifecycle_smoke as lifecycle
import release_candidate
import release_transport_matrix


class TransportMechanicsError(RuntimeError):
    """The protected exact-candidate transport gate did not complete."""


def _probe_installed_natlook(destination: str, uid: int, gid: int) -> None:
    """Hold an incomplete TLS record through the installed PF listener.

    The installed daemon calls DIOCNATLOOK before reading the TLS record.  A
    successful lookup leaves this one-byte record pending; a failed lookup
    closes immediately.  The unprivileged client is required because the PF
    contract excludes root-owned traffic.
    """
    family = socket.AF_INET6 if ":" in destination else socket.AF_INET
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(4)
                client.connect((destination, 443))
                client.sendall(b"\x16")
                client.settimeout(1.5)
                try:
                    received = client.recv(1)
                except TimeoutError:
                    os._exit(0)
                os._exit(2 if received == b"" else 3)
        except BaseException:
            os._exit(4)
    _, child_status = os.waitpid(pid, 0)
    if not os.WIFEXITED(child_status) or os.WEXITSTATUS(child_status) != 0:
        raise TransportMechanicsError(
            f"installed candidate NATLOOK failed for family {family}"
        )


def _probe_installed_natlook_matrix(uid: int, gid: int) -> None:
    """Prove both NATLOOK families while owning the disposable IPv6 route."""
    fixture = pf.IPv6LoopbackAliasFixture()
    failure: BaseException | None = None
    try:
        _probe_installed_natlook(pf.TEST_DESTINATION, uid, gid)
        _probe_installed_natlook(fixture.install(), uid, gid)
    except BaseException as exc:
        failure = exc
    try:
        fixture.cleanup()
    except BaseException as exc:
        raise TransportMechanicsError(
            f"installed NATLOOK IPv6 fixture cleanup failed: {exc}"
        ) from failure
    if failure is not None:
        raise failure


def _validated_candidate_identity(
    *,
    candidate_dir: Path,
    app_bundle: Path,
    source_commit: str,
    candidate_run_id: int,
    candidate_run_attempt: int,
) -> dict:
    manifest = release_candidate._read_object(
        candidate_dir / release_candidate.MANIFEST_NAME,
        "candidate manifest",
    )
    source = manifest.get("source")
    if not isinstance(source, dict) or source.get("commit") != source_commit:
        raise TransportMechanicsError("candidate source does not match exact SHA")
    verified = release_candidate.validate_manifest(
        candidate_dir=candidate_dir,
        repository=source.get("repository", ""),
        version=manifest.get("version", ""),
        source_commit=source_commit,
        source_tree=source.get("tree", ""),
        source_archive_sha256=source.get("archive_sha256", ""),
        source_date_epoch=source.get("source_date_epoch", -1),
        target=manifest.get("target", ""),
        expected_workflow_run_id=candidate_run_id,
        expected_workflow_run_attempt=candidate_run_attempt,
        app_tree=app_bundle,
    )
    return {
        "candidate_id": verified["candidate_id"],
        "manifest_sha256": verified["manifest_sha256"],
        "app_tree_sha256": manifest["app_tree_sha256"],
    }


def _run_packaged_quic_gate(executable: Path) -> dict:
    environment = dict(os.environ)
    environment["SLIPSTREAM_TRANSPORT_SELFTEST"] = "1"
    result = subprocess.run(
        [str(executable), "--transport-mechanics-selftest"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    try:
        report = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise TransportMechanicsError(
            "packaged QUIC mechanics returned invalid JSON"
        ) from exc
    if result.returncode != 0:
        raise TransportMechanicsError("packaged QUIC mechanics failed")
    return report


def _qualify_installed_candidate(app_bundle: Path) -> tuple[dict, dict]:
    runner = pf.PfctlRunner()
    before, uid, gid = lifecycle._preflight(runner)
    target = lifecycle.packaged_app_target(app_bundle)
    system = lifecycle.SystemRunner(target)
    failure: BaseException | None = None
    cleanup_errors: list[str] = []
    evidence: dict | None = None
    quic_report: dict | None = None
    try:
        system.run(target.install_command)
        status = lifecycle._wait_for_status("active", timeout=90)
        lifecycle._assert_anchor_active(runner)
        lifecycle._assert_install_attestation(target)
        attestation = json.loads(
            lifecycle.INSTALL_ATTESTATION_PATH.read_text(encoding="utf-8")
        )
        lifecycle._assert_install_attestation_runtime(attestation, status)
        _probe_installed_natlook_matrix(uid, gid)
        if target.attested_installed_path is None:
            raise TransportMechanicsError("candidate omitted installed daemon path")
        quic_report = _run_packaged_quic_gate(target.attested_installed_path)
        listener = attestation.get("listener")
        evidence = {
            "attestation_schema_version": attestation.get("schema_version"),
            "listener_hosts": listener.get("hosts") if isinstance(listener, dict) else None,
            "listener_port": listener.get("port") if isinstance(listener, dict) else None,
            "natlook_families": ["inet", "inet6"],
            "ipv6_runtime_proof": "lo0_rdr_and_natlook",
            "ipv6_non_lo0_route_to": "loaded_rule_static_only",
            "pf_rule_families": ["inet", "inet6"],
            "startup_health_probe": "passed",
            "state": status.get("state"),
        }
    except BaseException as exc:
        failure = exc
    finally:
        cleanup_errors.extend(lifecycle._fallback_uninstall(system, runner, target))
        try:
            lifecycle._assert_clean_install_state(runner)
            pf._assert_same_snapshot(before, pf._pf_snapshot(runner))
        except BaseException as exc:
            cleanup_errors.append(str(exc))
    if cleanup_errors:
        raise TransportMechanicsError("; ".join(cleanup_errors)) from failure
    if failure is not None:
        raise failure
    if evidence is None or quic_report is None:
        raise TransportMechanicsError("installed candidate produced no evidence")
    return evidence, quic_report


def run_gate(
    *,
    candidate_dir: Path,
    app_bundle: Path,
    source_commit: str,
    candidate_run_id: int,
    candidate_run_attempt: int,
    readiness_run_id: int,
    readiness_run_attempt: int,
) -> dict:
    if os.environ.get("CI") != "true" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise TransportMechanicsError("transport mechanics require protected CI")
    if os.environ.get("SLIPSTREAM_RELEASE_READINESS") != "1":
        raise TransportMechanicsError("release-readiness capability is missing")
    identity = _validated_candidate_identity(
        candidate_dir=candidate_dir,
        app_bundle=app_bundle,
        source_commit=source_commit,
        candidate_run_id=candidate_run_id,
        candidate_run_attempt=candidate_run_attempt,
    )
    installed, quic_report = _qualify_installed_candidate(app_bundle)
    # The candidate must be fully absent before the owned test anchor is used.
    pf_report = pf.run_smoke(
        target_port=pf.DEFAULT_TARGET_PORT,
        proxy_port=pf.DEFAULT_PROXY_PORT,
    )
    return release_transport_matrix.build(
        source_commit=source_commit,
        candidate_id=identity["candidate_id"],
        candidate_manifest_sha256=identity["manifest_sha256"],
        app_tree_sha256=identity["app_tree_sha256"],
        candidate_run_id=candidate_run_id,
        candidate_run_attempt=candidate_run_attempt,
        readiness_run_id=readiness_run_id,
        readiness_run_attempt=readiness_run_attempt,
        installed_candidate=installed,
        pf_report=pf_report,
        quic_report=quic_report,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--app-bundle", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--candidate-run-id", type=int, required=True)
    parser.add_argument("--candidate-run-attempt", type=int, required=True)
    parser.add_argument("--readiness-run-id", type=int, required=True)
    parser.add_argument("--readiness-run-attempt", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run_gate(
            candidate_dir=args.candidate_dir,
            app_bundle=args.app_bundle,
            source_commit=args.source_commit,
            candidate_run_id=args.candidate_run_id,
            candidate_run_attempt=args.candidate_run_attempt,
            readiness_run_id=args.readiness_run_id,
            readiness_run_attempt=args.readiness_run_attempt,
        )
    except Exception as exc:
        print(json.dumps({"result": "failed", "error": str(exc)}), file=sys.stderr)
        return 1
    make_release_sbom.write_json_atomic(args.output, report)
    print(json.dumps({"result": "passed", "scenario_count": len(report["scenarios"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate protected, exact-candidate macOS transport-mechanics evidence.

This report deliberately does not claim that a public origin negotiated a
particular QUIC version or address family.  The protected harness proves the
local mechanics, while the independent Safari/Chrome report proves that the
real origin is usable through the installed candidate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


SCHEMA_VERSION = 2
REPORT_NAME = "transport-mechanics.json"
WORKFLOW = ".github/workflows/release-readiness.yml"
SOURCE_PATTERN = re.compile(r"[0-9a-f]{40,64}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
SCENARIOS = (
    "installed_candidate_dual_stack_tcp_natlook",
    "darwin_private_anchor_dual_stack_rollback",
    "quic_v1_v2_ipv4_ipv6_exact_host_fallback",
)
LIMITATIONS = (
    "The installed-candidate transaction proves both loopback listeners, "
    "dual-family production PF rules, and Darwin DIOCNATLOOK for incomplete "
    "TLS records sent to documentation-prefix destinations. A separate "
    "private-anchor transaction proves scoped rollback on non-production ports.",
    "The installed candidate's capability-gated self-test uses deterministic "
    "encrypted QUIC Initial datagrams without network mutation. The "
    "Safari/Chrome live-site gate separately proves xpersonatoy.com usability "
    "and does not claim its negotiated QUIC version or address family.",
)


def _require_identity(
    *,
    source_commit: str,
    candidate_id: str,
    candidate_manifest_sha256: str,
    app_tree_sha256: str,
    candidate_run_id: int,
    candidate_run_attempt: int,
    readiness_run_id: int,
    readiness_run_attempt: int,
) -> None:
    if not SOURCE_PATTERN.fullmatch(source_commit):
        raise ValueError("transport mechanics source commit is invalid")
    if candidate_id != f"release-candidate-{source_commit}":
        raise ValueError("transport mechanics candidate identity is invalid")
    for label, value in (
        ("candidate manifest", candidate_manifest_sha256),
        ("app tree", app_tree_sha256),
    ):
        if not SHA256_PATTERN.fullmatch(value):
            raise ValueError(f"transport mechanics {label} digest is invalid")
    if min(
        candidate_run_id,
        candidate_run_attempt,
        readiness_run_id,
        readiness_run_attempt,
    ) <= 0:
        raise ValueError("transport mechanics workflow identity is invalid")


def _validate_measured_inputs(
    *,
    installed_candidate: dict,
    pf_report: dict,
    quic_report: dict,
) -> None:
    expected_installed = {
        "attestation_schema_version": 3,
        "listener_hosts": ["127.0.0.1", "::1"],
        "listener_port": 1080,
        "natlook_families": ["inet", "inet6"],
        "pf_rule_families": ["inet", "inet6"],
        "startup_health_probe": "passed",
        "state": "active",
    }
    if installed_candidate != expected_installed:
        raise ValueError("installed candidate transport evidence is invalid")
    required_pf = {
        "result": "pass",
        "global_pf": "unchanged",
        "loopback_skip": "restored",
        "natlook_families": ["inet", "inet6"],
    }
    if any(pf_report.get(key) != value for key, value in required_pf.items()):
        raise ValueError("Darwin PF/NATLOOK transport evidence is invalid")
    target_port = pf_report.get("target_port")
    proxy_port = pf_report.get("proxy_port")
    if (
        type(target_port) is not int
        or type(proxy_port) is not int
        or target_port == 443
        or target_port == proxy_port
        or not (1024 <= target_port <= 65535)
        or not (1024 <= proxy_port <= 65535)
    ):
        raise ValueError("Darwin PF smoke ports are invalid")
    expected_quic = {
        "schema_version": 1,
        "result": "passed",
        "versions": ["v1", "v2"],
        "families": ["inet", "inet6"],
        "exact_host_fallback": True,
        "protected_routes_isolation": True,
        "network_mutated": False,
    }
    if quic_report != expected_quic:
        raise ValueError("packaged QUIC transport-mechanics evidence is invalid")


def build(
    *,
    source_commit: str,
    candidate_id: str,
    candidate_manifest_sha256: str,
    app_tree_sha256: str,
    candidate_run_id: int,
    candidate_run_attempt: int,
    readiness_run_id: int,
    readiness_run_attempt: int,
    installed_candidate: dict,
    pf_report: dict,
    quic_report: dict,
) -> dict:
    _require_identity(
        source_commit=source_commit,
        candidate_id=candidate_id,
        candidate_manifest_sha256=candidate_manifest_sha256,
        app_tree_sha256=app_tree_sha256,
        candidate_run_id=candidate_run_id,
        candidate_run_attempt=candidate_run_attempt,
        readiness_run_id=readiness_run_id,
        readiness_run_attempt=readiness_run_attempt,
    )
    _validate_measured_inputs(
        installed_candidate=installed_candidate,
        pf_report=pf_report,
        quic_report=quic_report,
    )
    return _expected_report(
        source_commit=source_commit,
        candidate_id=candidate_id,
        candidate_manifest_sha256=candidate_manifest_sha256,
        app_tree_sha256=app_tree_sha256,
        candidate_run_id=candidate_run_id,
        candidate_run_attempt=candidate_run_attempt,
        readiness_run_id=readiness_run_id,
        readiness_run_attempt=readiness_run_attempt,
    )


def _expected_report(
    *,
    source_commit: str,
    candidate_id: str,
    candidate_manifest_sha256: str,
    app_tree_sha256: str,
    candidate_run_id: int,
    candidate_run_attempt: int,
    readiness_run_id: int,
    readiness_run_attempt: int,
) -> dict:
    _require_identity(
        source_commit=source_commit,
        candidate_id=candidate_id,
        candidate_manifest_sha256=candidate_manifest_sha256,
        app_tree_sha256=app_tree_sha256,
        candidate_run_id=candidate_run_id,
        candidate_run_attempt=candidate_run_attempt,
        readiness_run_id=readiness_run_id,
        readiness_run_attempt=readiness_run_attempt,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "harness": "protected_macos_exact_candidate_transport_mechanics",
        "workflow": WORKFLOW,
        "source_commit": source_commit,
        "candidate": {
            "candidate_id": candidate_id,
            "manifest_sha256": candidate_manifest_sha256,
            "app_tree_sha256": app_tree_sha256,
            "run_id": candidate_run_id,
            "run_attempt": candidate_run_attempt,
        },
        "readiness": {
            "run_id": readiness_run_id,
            "run_attempt": readiness_run_attempt,
        },
        "result": "passed",
        "scenarios": [
            {
                "name": SCENARIOS[0],
                "result": "passed",
                "evidence": "installed_exact_candidate",
                "listener_hosts": ["127.0.0.1", "::1"],
                "listener_port": 1080,
                "natlook_families": ["inet", "inet6"],
                "pf_rule_families": ["inet", "inet6"],
                "startup_health_probe": "passed",
                "test_destinations": "documentation_prefixes",
            },
            {
                "name": SCENARIOS[1],
                "result": "passed",
                "evidence": "darwin_kernel_private_anchor_test_ports",
                "families": ["inet", "inet6"],
                "natlook": "passed",
                "global_pf": "unchanged",
                "loopback_skip": "restored",
                "production_tcp_443_exercised": False,
            },
            {
                "name": SCENARIOS[2],
                "result": "passed",
                "evidence": "installed_candidate_deterministic_encrypted_initials",
                "versions": ["v1", "v2"],
                "families": ["inet", "inet6"],
                "exact_host_fallback": "passed",
                "protected_routes_isolation": "passed",
                "live_origin_transport_asserted": False,
            },
        ],
        "real_origin_evidence": "live-sites.json",
        "limitations": list(LIMITATIONS),
    }


def validate(
    path: Path,
    *,
    source_commit: str,
    candidate_id: str,
    candidate_manifest_sha256: str,
    app_tree_sha256: str,
    candidate_run_id: int,
    candidate_run_attempt: int,
    readiness_run_id: int,
    readiness_run_attempt: int,
) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("transport mechanics report is invalid JSON") from exc
    expected = _expected_report(
        source_commit=source_commit,
        candidate_id=candidate_id,
        candidate_manifest_sha256=candidate_manifest_sha256,
        app_tree_sha256=app_tree_sha256,
        candidate_run_id=candidate_run_id,
        candidate_run_attempt=candidate_run_attempt,
        readiness_run_id=readiness_run_id,
        readiness_run_attempt=readiness_run_attempt,
    )
    if value != expected:
        raise ValueError("transport mechanics do not match exact protected evidence")
    return {"result": "passed", "scenario_count": len(SCENARIOS)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("verify", choices=("verify",))
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--candidate-manifest-sha256", required=True)
    parser.add_argument("--app-tree-sha256", required=True)
    parser.add_argument("--candidate-run-id", type=int, required=True)
    parser.add_argument("--candidate-run-attempt", type=int, required=True)
    parser.add_argument("--readiness-run-id", type=int, required=True)
    parser.add_argument("--readiness-run-attempt", type=int, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = validate(
        args.report,
        source_commit=args.source_commit,
        candidate_id=args.candidate_id,
        candidate_manifest_sha256=args.candidate_manifest_sha256,
        app_tree_sha256=args.app_tree_sha256,
        candidate_run_id=args.candidate_run_id,
        candidate_run_attempt=args.candidate_run_attempt,
        readiness_run_id=args.readiness_run_id,
        readiness_run_attempt=args.readiness_run_attempt,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

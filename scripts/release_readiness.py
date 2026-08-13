#!/usr/bin/env python3
"""Create and verify the protected macOS release-readiness proof."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import make_release_sbom
import release_candidate
import release_transport_matrix


SCHEMA_VERSION = 1
PROOF_NAME = "release-readiness.json"
WORKFLOW = ".github/workflows/release-readiness.yml"
REQUIRED_HOSTS = (
    "xpersonatoy.com",
    "app.aikido.dev",
    "weather.com",
    "capacitorjs.com",
)
HOST_DEADLINES_MS = {
    "xpersonatoy.com": 20_000,
    "app.aikido.dev": 30_000,
    "weather.com": 25_000,
    "capacitorjs.com": 25_000,
}
REQUIRED_BROWSERS = ("chrome", "safari")
MIN_SOAK_SECONDS = 1800
SOAK_SAMPLE_INTERVAL_SECONDS = 0.5
MAX_SOAK_SAMPLE_GAP_SECONDS = 2.0
ZERO_COUNTERS = (
    "coregraphics_window_samples",
    "dock_visible_samples",
    "frontmost_changes",
    "gui_chrome_samples",
    "headless_shell_samples",
    "launch_agent_residue",
    "launch_services_visible_events",
    "unified_log_post_show_process",
    "max_launch_agents",
    "max_worker_profiles",
    "profile_residue",
)


def _read_object(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def validate_live_report(report: dict, exit_status: int) -> str:
    expected_keys = {
        "schema_version",
        "harness",
        "harness_exit_status",
        "result",
        "sites",
    }
    if set(report) != expected_keys:
        raise ValueError("live-site report fields are invalid")
    if report.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("live-site report schema is invalid")
    if report.get("harness") != "safari_chrome_live_sites":
        raise ValueError("live-site harness identity is invalid")
    if exit_status not in (0, 1, 2) or report.get("harness_exit_status") != exit_status:
        raise ValueError("live-site harness exit status does not match the report")
    result = report.get("result")
    expected_exit = {"passed": 0, "failed": 1, "inconclusive": 2}.get(result)
    if expected_exit != exit_status:
        raise ValueError("live-site result does not match the harness exit status")
    sites = report.get("sites")
    if not isinstance(sites, list) or len(sites) != len(REQUIRED_HOSTS):
        raise ValueError("live-site report does not cover the fixed host matrix")
    observed_hosts: list[str] = []
    observed_results: list[str] = []
    for site in sites:
        if not isinstance(site, dict) or set(site) != {
            "browsers",
            "controls",
            "host",
            "result",
        }:
            raise ValueError("live-site entry is invalid")
        host = site.get("host")
        if host not in REQUIRED_HOSTS:
            raise ValueError("live-site host is not in the fixed matrix")
        observed_hosts.append(host)
        browsers = site.get("browsers")
        if not isinstance(browsers, list) or len(browsers) != 2:
            raise ValueError("live-site entry must contain Safari and Chrome")
        browser_names: list[str] = []
        for browser in browsers:
            if not isinstance(browser, dict) or set(browser) != {
                "browser",
                "deadline_ms",
                "elapsed_ms",
                "outcome",
                "route",
            }:
                raise ValueError("browser live-site result is invalid")
            browser_names.append(browser.get("browser"))
            deadline = browser.get("deadline_ms")
            elapsed = browser.get("elapsed_ms")
            if (
                not isinstance(deadline, int)
                or isinstance(deadline, bool)
                or deadline != HOST_DEADLINES_MS[host]
                or not isinstance(elapsed, int)
                or isinstance(elapsed, bool)
                or elapsed < 0
                or elapsed > deadline + 5_000
            ):
                raise ValueError("browser live-site deadline evidence is invalid")
            if browser.get("route") != "slipstream_selected":
                raise ValueError("browser live-site route is invalid")
            if browser.get("outcome") not in {
                "usable",
                "regional_access_denied",
                "edge_access_denied",
                "challenge_or_auth",
                "terminal_error",
            }:
                raise ValueError("browser live-site outcome is invalid")
        if sorted(browser_names) != list(REQUIRED_BROWSERS):
            raise ValueError("live-site browsers are not the fixed Safari/Chrome pair")
        controls = site.get("controls")
        if not isinstance(controls, dict) or set(controls) != {
            "direct",
            "owned_geph",
        }:
            raise ValueError("live-site control routes are invalid")
        site_result = site.get("result")
        browser_usable = all(
            browser.get("outcome") == "usable" for browser in browsers
        )
        if site_result == "usable":
            if not browser_usable or set(controls.values()) != {"not_needed"}:
                raise ValueError("usable live-site result lacks two browser successes")
        elif site_result == "inconclusive":
            if browser_usable or set(controls.values()) != {"unavailable"}:
                raise ValueError(
                    "inconclusive requires both independent control routes unavailable"
                )
        elif site_result == "terminal_error":
            if browser_usable or not set(controls.values()) <= {
                "usable",
                "denial",
                "challenge",
                "origin_error",
                "unavailable",
            } or set(controls.values()) == {"unavailable"}:
                raise ValueError("terminal error has invalid control-route evidence")
        else:
            raise ValueError("live-site result is invalid")
        observed_results.append(site_result)
    if tuple(observed_hosts) != REQUIRED_HOSTS:
        raise ValueError("live-site host order or coverage is invalid")
    derived = (
        "failed"
        if "terminal_error" in observed_results
        else "inconclusive"
        if "inconclusive" in observed_results
        else "passed"
    )
    if derived != result:
        raise ValueError("live-site aggregate result is invalid")
    return result


def validate_soak_report(report: dict, exit_status: int) -> str:
    expected_keys = {
        "schema_version",
        "harness",
        "harness_exit_status",
        "result",
        "requested_duration_seconds",
        "measured_duration_seconds",
        "sample_interval_seconds",
        "max_sample_gap_seconds",
        "visibility_samples",
        "counters",
        "daemon_pid_stable",
        "heartbeat_advanced",
    }
    if set(report) != expected_keys:
        raise ValueError("invisibility report fields are invalid")
    if report.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("invisibility report schema is invalid")
    if report.get("harness") != "packaged_macos_invisibility_soak":
        raise ValueError("invisibility harness identity is invalid")
    if exit_status not in (0, 1) or report.get("harness_exit_status") != exit_status:
        raise ValueError("invisibility harness exit status does not match")
    result = report.get("result")
    if {"passed": 0, "failed": 1}.get(result) != exit_status:
        raise ValueError("invisibility result does not match its exit status")
    requested = report.get("requested_duration_seconds")
    measured = report.get("measured_duration_seconds")
    interval = report.get("sample_interval_seconds")
    max_sample_gap = report.get("max_sample_gap_seconds")
    samples = report.get("visibility_samples")
    counters = report.get("counters")
    if not isinstance(counters, dict) or set(counters) != set(ZERO_COUNTERS):
        raise ValueError("invisibility counters are incomplete")
    zero = all(type(counters[name]) is int and counters[name] == 0 for name in ZERO_COUNTERS)
    duration_ok = (
        type(requested) is int
        and requested >= MIN_SOAK_SECONDS
        and isinstance(measured, (int, float))
        and not isinstance(measured, bool)
        and measured >= requested
        and isinstance(interval, (int, float))
        and not isinstance(interval, bool)
        and interval == SOAK_SAMPLE_INTERVAL_SECONDS
        and isinstance(max_sample_gap, (int, float))
        and not isinstance(max_sample_gap, bool)
        and 0 < max_sample_gap <= MAX_SOAK_SAMPLE_GAP_SECONDS
        and type(samples) is int
        and samples >= int(requested / MAX_SOAK_SAMPLE_GAP_SECONDS) - 1
    )
    evidence_passed = (
        duration_ok
        and zero
        and report.get("daemon_pid_stable") is True
        and report.get("heartbeat_advanced") is True
    )
    if (result == "passed") != evidence_passed:
        raise ValueError("invisibility result does not match measured evidence")
    return result


def build_proof(
    *,
    candidate_dir: Path,
    app_tree: Path,
    live_report_path: Path,
    live_exit_status: int,
    soak_report_path: Path,
    soak_exit_status: int,
    transport_report_path: Path,
    candidate_run_id: int,
    candidate_run_attempt: int,
    readiness_run_id: int,
    readiness_run_attempt: int,
) -> dict:
    if min(candidate_run_id, candidate_run_attempt, readiness_run_id, readiness_run_attempt) <= 0:
        raise ValueError("readiness workflow identity must be positive")
    manifest = release_candidate._read_object(
        candidate_dir / release_candidate.MANIFEST_NAME, "candidate manifest"
    )
    source = manifest.get("source")
    if not isinstance(source, dict):
        raise ValueError("candidate source identity is missing")
    verified = release_candidate.validate_manifest(
        candidate_dir=candidate_dir,
        repository=source.get("repository", ""),
        version=manifest.get("version", ""),
        source_commit=source.get("commit", ""),
        source_tree=source.get("tree", ""),
        source_archive_sha256=source.get("archive_sha256", ""),
        source_date_epoch=source.get("source_date_epoch", -1),
        target=manifest.get("target", ""),
        expected_workflow_run_id=candidate_run_id,
        expected_workflow_run_attempt=candidate_run_attempt,
        app_tree=app_tree,
    )
    live = _read_object(live_report_path, "live-site report")
    soak = _read_object(soak_report_path, "invisibility report")
    transport = release_transport_matrix.validate(
        transport_report_path,
        source_commit=source.get("commit", ""),
        candidate_id=manifest.get("candidate_id", ""),
        candidate_manifest_sha256=verified["manifest_sha256"],
        app_tree_sha256=manifest.get("app_tree_sha256", ""),
        candidate_run_id=candidate_run_id,
        candidate_run_attempt=candidate_run_attempt,
        readiness_run_id=readiness_run_id,
        readiness_run_attempt=readiness_run_attempt,
    )
    live_result = validate_live_report(live, live_exit_status)
    soak_result = validate_soak_report(soak, soak_exit_status)
    result = "passed" if live_result == soak_result == "passed" else (
        "inconclusive" if live_result == "inconclusive" and soak_result == "passed" else "failed"
    )
    manifest_sha256, _ = release_candidate.make_release_manifest.hash_regular_file(
        candidate_dir / release_candidate.MANIFEST_NAME
    )
    live_sha256, _ = release_candidate.make_release_manifest.hash_regular_file(
        live_report_path
    )
    soak_sha256, _ = release_candidate.make_release_manifest.hash_regular_file(
        soak_report_path
    )
    transport_sha256, _ = release_candidate.make_release_manifest.hash_regular_file(
        transport_report_path
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": manifest.get("candidate_id"),
        "candidate_manifest_sha256": manifest_sha256,
        "app_tree_sha256": manifest.get("app_tree_sha256"),
        "source_commit": source.get("commit"),
        "source_tree": source.get("tree"),
        "candidate_build": {
            "run_id": candidate_run_id,
            "run_attempt": candidate_run_attempt,
        },
        "readiness": {
            "workflow": WORKFLOW,
            "run_id": readiness_run_id,
            "run_attempt": readiness_run_attempt,
            "result": result,
        },
        "live_sites": {
            "result": live_result,
            "report_sha256": live_sha256,
            "harness_exit_status": live_exit_status,
        },
        "invisibility_soak": {
            "result": soak_result,
            "report_sha256": soak_sha256,
            "harness_exit_status": soak_exit_status,
            "measured_duration_seconds": soak["measured_duration_seconds"],
        },
        "transport_mechanics": {
            "result": transport["result"],
            "report_sha256": transport_sha256,
            "scenario_count": transport["scenario_count"],
        },
        "verified_candidate_artifacts": verified["artifact_count"],
    }


def verify_proof(
    *,
    proof_path: Path,
    candidate_dir: Path,
    app_tree: Path,
    live_report_path: Path,
    soak_report_path: Path,
    transport_report_path: Path,
    candidate_run_id: int,
    candidate_run_attempt: int,
    readiness_run_id: int,
    readiness_run_attempt: int,
    require_passed: bool,
) -> dict:
    proof = _read_object(proof_path, "release-readiness proof")
    live = _read_object(live_report_path, "live-site report")
    soak = _read_object(soak_report_path, "invisibility report")
    expected = build_proof(
        candidate_dir=candidate_dir,
        app_tree=app_tree,
        live_report_path=live_report_path,
        live_exit_status=int(live.get("harness_exit_status", -1)),
        soak_report_path=soak_report_path,
        soak_exit_status=int(soak.get("harness_exit_status", -1)),
        transport_report_path=transport_report_path,
        candidate_run_id=candidate_run_id,
        candidate_run_attempt=candidate_run_attempt,
        readiness_run_id=readiness_run_id,
        readiness_run_attempt=readiness_run_attempt,
    )
    if proof != expected:
        raise ValueError("release-readiness proof does not match exact evidence")
    if require_passed and proof.get("readiness", {}).get("result") != "passed":
        raise ValueError("release readiness did not pass")
    return {
        "candidate_id": proof["candidate_id"],
        "readiness_run_id": readiness_run_id,
        "result": proof["readiness"]["result"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "verify"):
        current = subparsers.add_parser(command)
        current.add_argument("--candidate-dir", type=Path, required=True)
        current.add_argument("--app-tree", type=Path, required=True)
        current.add_argument("--live-report", type=Path, required=True)
        current.add_argument("--soak-report", type=Path, required=True)
        current.add_argument("--transport-report", type=Path, required=True)
        current.add_argument("--candidate-run-id", type=int, required=True)
        current.add_argument("--candidate-run-attempt", type=int, required=True)
        current.add_argument("--readiness-run-id", type=int, required=True)
        current.add_argument("--readiness-run-attempt", type=int, required=True)
    create = subparsers.choices["create"]
    create.add_argument("--live-exit-status", type=int, required=True)
    create.add_argument("--soak-exit-status", type=int, required=True)
    create.add_argument("--output", type=Path, required=True)
    verify = subparsers.choices["verify"]
    verify.add_argument("--proof", type=Path, required=True)
    verify.add_argument("--require-passed", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    common = {
        "candidate_dir": args.candidate_dir,
        "app_tree": args.app_tree,
        "live_report_path": args.live_report,
        "soak_report_path": args.soak_report,
        "transport_report_path": args.transport_report,
        "candidate_run_id": args.candidate_run_id,
        "candidate_run_attempt": args.candidate_run_attempt,
        "readiness_run_id": args.readiness_run_id,
        "readiness_run_attempt": args.readiness_run_attempt,
    }
    if args.command == "create":
        result = build_proof(
            **common,
            live_exit_status=args.live_exit_status,
            soak_exit_status=args.soak_exit_status,
        )
        make_release_sbom.write_json_atomic(args.output, result)
    else:
        result = verify_proof(
            **common,
            proof_path=args.proof,
            require_passed=args.require_passed,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

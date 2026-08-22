#!/usr/bin/env python3
"""Run one non-authoritative, direct Chrome semantic diagnostic.

This tool deliberately does *not* install or launch Slipstream, activate PF,
start Geph, elevate privileges, or touch system proxy/DNS/PAC/VPN configuration. It is
for isolating a current browser/content hypothesis (for example a visible
challenge or a still-pending Weather document) without spending an
account-backed qualification attempt.  Its result is never release evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import live_site_release_smoke as release

SCHEMA_VERSION = 1
STARTUP_TIMEOUT_SECONDS = 10.0
TEARDOWN_TIMEOUT_SECONDS = 10.0
TEARDOWN_POLL_SECONDS = 0.1
SAFE_ENVIRONMENT_NAMES = frozenset({"LANG", "LC_CTYPE", "TZ"})


def _direct_environment(profile: Path) -> dict[str, str]:
    """Return a minimal browser environment with a temporary home only."""

    environment = {
        name: value
        for name, value in os.environ.items()
        if name in SAFE_ENVIRONMENT_NAMES
    }
    environment["HOME"] = str(profile)
    environment["TMPDIR"] = str(profile)
    return environment


def _chrome_command(executable: Path, profile: Path) -> tuple[str, ...]:
    return (
        str(executable),
        "--headless=new",
        "--disable-background-networking",
        "--disable-crash-reporter",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-features=MediaRouter,OptimizationHints,Translate",
        "--disable-gpu",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-default-browser-check",
        "--no-first-run",
        "--no-proxy-server",
        "--password-store=basic",
        "--remote-debugging-port=0",
        f"--user-data-dir={profile}",
        "about:blank",
    )


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_group_absence(process_group: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_group_exists(process_group):
        if time.monotonic() >= deadline:
            return False
        time.sleep(TEARDOWN_POLL_SECONDS)
    return True


def _wait_for_process_exit(
    process: subprocess.Popen[bytes], timeout: float
) -> bool:
    """Reap the group leader before checking whether its group is gone."""

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return process.poll() is not None


def _signal_process_group(process_group: int, signal_number: int) -> bool:
    try:
        os.killpg(process_group, signal_number)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return True


def _terminate_process(process: subprocess.Popen[bytes]) -> bool:
    """Terminate and verify the diagnostic browser's complete process group."""

    process_group = process.pid
    group_owned = _process_group_exists(process_group)
    if group_owned:
        if not _signal_process_group(process_group, signal.SIGTERM):
            return False
    if not _wait_for_process_exit(process, TEARDOWN_TIMEOUT_SECONDS):
        # A timed-out Popen leader has not been reaped, so it still owns this
        # PID/PGID and an emergency group signal cannot target a reused group.
        if not group_owned or not _signal_process_group(process_group, signal.SIGKILL):
            return False
        if not _wait_for_process_exit(process, TEARDOWN_TIMEOUT_SECONDS):
            return False
    # Never signal a numeric group after reaping its leader: a reused PID/PGID
    # could belong to an unrelated process. A lingering group instead fails
    # closed after the bounded observation below.
    if not _wait_for_process_group_absence(
        process_group, TEARDOWN_TIMEOUT_SECONDS
    ):
        return False
    return True


def _diagnostic_evidence_expression(host: str) -> str:
    """Return only shared bounded evidence plus a final exact-host bit."""

    expected_host = json.dumps(host)
    shared = release._chrome_evidence_expression(host)
    return f"""
(() => {{
  const evidence = ({shared});
  return {{
    evidence,
    same_host: location.hostname.toLowerCase() === {expected_host}
  }};
}})()
"""


def _classify_diagnostic_evidence(host: str, envelope: object) -> tuple[str, str]:
    if not isinstance(envelope, dict) or set(envelope) != {"evidence", "same_host"}:
        return "terminal_error", "document_invalid"
    same_host = envelope.get("same_host")
    if same_host is False:
        return "terminal_error", "origin_mismatch"
    if same_host is not True:
        return "terminal_error", "document_invalid"
    return release._classify_chrome_evidence(host, envelope.get("evidence"))


def _browser_result(
    host: str,
    executable: Path,
) -> dict[str, object]:
    """Observe exactly one allowlisted host without product routing state."""

    executable = executable.resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("Chrome executable is not executable")
    profile = Path(tempfile.mkdtemp(prefix="slipstream-diagnostic-chrome-"))
    process: subprocess.Popen[bytes] | None = None
    observation_started: float | None = None
    finished = time.monotonic()
    outcome = "terminal_error"
    reason = "browser_start_failed"
    try:
        process = subprocess.Popen(
            _chrome_command(executable, profile),
            cwd=profile,
            close_fds=True,
            env=_direct_environment(profile),
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        port = release.chromium._wait_for_devtools_port(
            profile,
            os.getuid(),
            timeout=STARTUP_TIMEOUT_SECONDS,
        )
        targets = release.chromium._devtools_json(port, "/json/list")
        pages = [
            item
            for item in targets
            if isinstance(item, dict)
            and item.get("type") == "page"
            and item.get("url") == "about:blank"
        ]
        if len(pages) != 1 or not isinstance(pages[0].get("webSocketDebuggerUrl"), str):
            raise release.LiveSiteError("Chrome did not expose one clean page")
        debugger = pages[0]["webSocketDebuggerUrl"]
        reason = "navigation_rejected"
        observation_started = time.monotonic()
        navigation = release.chromium._devtools_command(
            debugger,
            port,
            "Page.navigate",
            {"url": f"https://{host}/"},
            response_timeout=STARTUP_TIMEOUT_SECONDS,
        )
        if navigation.get("errorText") not in (None, ""):
            raise release.LiveSiteError("Chrome rejected the HTTPS navigation")
        reason = "browser_observation_failed"
        deadline = observation_started + release.SITES[host]["deadline_ms"] / 1000
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                evaluated = release.chromium._devtools_command(
                    debugger,
                    port,
                    "Runtime.evaluate",
                    {
                        "expression": _diagnostic_evidence_expression(host),
                        "returnByValue": True,
                    },
                    response_timeout=min(2.0, remaining),
                ).get("result")
                envelope = (
                    evaluated.get("value") if isinstance(evaluated, dict) else None
                )
            except (release.chromium.QualificationError, TimeoutError):
                time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
                continue
            outcome, reason = _classify_diagnostic_evidence(host, envelope)
            if outcome in {
                "usable",
                "regional_access_denied",
                "edge_access_denied",
            }:
                break
            time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
        finished = time.monotonic()
    except (OSError, ValueError, release.LiveSiteError, release.chromium.QualificationError):
        finished = time.monotonic()
        outcome = "terminal_error"
    finally:
        cleaned_up = process is None or _terminate_process(process)
        if cleaned_up:
            try:
                shutil.rmtree(profile)
            except OSError:
                cleaned_up = False
        if not cleaned_up:
            outcome = "terminal_error"
            reason = "browser_cleanup_failed"
    elapsed_ms = (
        round((finished - observation_started) * 1000)
        if observation_started is not None
        else 0
    )
    return {
        "browser": "chrome-headless",
        "deadline_ms": release.SITES[host]["deadline_ms"],
        "elapsed_ms": elapsed_ms,
        "outcome": outcome,
        "reason": reason,
        "route": "unverified_local_environment",
    }


def run_diagnostic(host: str, executable: Path) -> dict[str, object]:
    if host not in release.SITES:
        raise ValueError("host is not in the fixed diagnostic allowlist")
    return {
        "browser": "chrome-headless",
        "diagnostic_only": True,
        "host": host,
        "release_eligible": False,
        "result": _browser_result(host, executable),
        "schema_version": SCHEMA_VERSION,
    }


def _write_report(report: dict[str, object], output: Path | None) -> None:
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    if output is not None:
        output.write_text(encoded, encoding="utf-8")
        output.chmod(0o600)
    print(encoded, end="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", choices=sorted(release.SITES), required=True)
    parser.add_argument("--chrome-executable", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_diagnostic(args.host, args.chrome_executable)
    except (OSError, ValueError):
        report = {
            "browser": "chrome-headless",
            "diagnostic_only": True,
            "host": args.host,
            "release_eligible": False,
            "result": {
                "browser": "chrome-headless",
                "deadline_ms": release.SITES[args.host]["deadline_ms"],
                "elapsed_ms": 0,
                "outcome": "terminal_error",
                "reason": "browser_start_failed",
                "route": "unverified_local_environment",
            },
            "schema_version": SCHEMA_VERSION,
        }
        _write_report(report, args.output)
        return 1
    _write_report(report, args.output)
    return 0 if report["result"].get("outcome") == "usable" else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run one non-authoritative, unverified local browser diagnostic.

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
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

import live_site_release_smoke as release

SCHEMA_VERSION = 1
STARTUP_TIMEOUT_SECONDS = 10.0
TEARDOWN_TIMEOUT_SECONDS = 10.0
TEARDOWN_POLL_SECONDS = 0.1
TEARDOWN_TERM_GRACE_SECONDS = 0.5
PROFILE_REMOVAL_TIMEOUT_SECONDS = 5.0
SAFE_ENVIRONMENT_NAMES = frozenset({"LANG", "LC_CTYPE", "TZ"})
ALLOWED_BROWSER_EXECUTABLE_NAMES = frozenset(
    {"Google Chrome for Testing", "chrome-headless-shell"}
)
COMPLETED_DIAGNOSTIC_REASONS = frozenset(
    {
        "",
        "challenge_or_auth",
        "document_too_short",
        "edge_access_denied",
        "navigation_denied",
        "navigation_pending",
        "navigation_rejected",
        "origin_mismatch",
        "readiness_content_missing",
        "readiness_context_invalid",
        "readiness_document_pending_semantic_ready",
        "readiness_signals_invalid",
        "readiness_title_mismatch",
        "readiness_transport_missing",
        "readiness_visibility_missing",
        "regional_access_denied",
    }
)


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
        "--use-mock-keychain",
        f"--user-data-dir={profile}",
        "about:blank",
    )


def _validated_browser_executable(executable: Path) -> Path:
    resolved = executable.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("diagnostic browser executable is not executable")
    if resolved.name not in ALLOWED_BROWSER_EXECUTABLE_NAMES:
        raise ValueError(
            "diagnostic requires Chrome for Testing or chrome-headless-shell"
        )
    return resolved


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


def _remove_owned_profile(profile: Path) -> bool:
    """Remove only the exact owner-controlled temporary profile, boundedly."""

    deadline = time.monotonic() + PROFILE_REMOVAL_TIMEOUT_SECONDS
    while True:
        try:
            metadata = profile.lstat()
        except FileNotFoundError:
            return True
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or mode & 0o077
            or not profile.name.startswith("slipstream-diagnostic-chrome-")
        ):
            return False
        try:
            shutil.rmtree(profile)
        except FileNotFoundError:
            return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(TEARDOWN_POLL_SECONDS)
            continue
        try:
            profile.lstat()
        except FileNotFoundError:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(TEARDOWN_POLL_SECONDS)


def _owned_live_process_group_pids(process_group: int) -> tuple[int, ...]:
    """Return live same-user members while the unreaped leader owns the PGID."""

    members = release.lifecycle._chrome_process_group_members(process_group)
    if any(member.uid != os.getuid() for member in members):
        raise release.lifecycle.LifecycleError(
            "diagnostic browser process group contains a foreign owner"
        )
    return tuple(
        member.pid
        for member in members
        if not member.state.upper().startswith("Z")
    )


def _signal_owned_process_group(
    process_group: int,
    live_process_ids: tuple[int, ...],
    signal_number: int,
) -> None:
    """Atomically signal the verified group while its leader remains unreaped."""

    if not live_process_ids:
        return
    try:
        os.killpg(process_group, signal_number)
    except (ProcessLookupError, PermissionError):
        # A group containing only the zombie leader can report ESRCH/EPERM on
        # macOS. That is success only if an inspection performed while the
        # leader still pins the PGID proves no live member remains.
        if _owned_live_process_group_pids(process_group):
            raise


def _terminate_process(process: subprocess.Popen[bytes]) -> bool:
    """Terminate and verify the diagnostic browser's complete process group."""

    try:
        if os.getpgid(process.pid) != process.pid:
            raise release.lifecycle.LifecycleError(
                "diagnostic browser process-group leader mismatch"
            )
        live_pids = _owned_live_process_group_pids(process.pid)
        _signal_owned_process_group(process.pid, live_pids, signal.SIGTERM)

        grace_deadline = time.monotonic() + TEARDOWN_TERM_GRACE_SECONDS
        while time.monotonic() < grace_deadline:
            if not _owned_live_process_group_pids(process.pid):
                break
            time.sleep(TEARDOWN_POLL_SECONDS)

        kill_deadline = time.monotonic() + TEARDOWN_TIMEOUT_SECONDS
        while True:
            live_pids = _owned_live_process_group_pids(process.pid)
            if not live_pids:
                break
            _signal_owned_process_group(process.pid, live_pids, signal.SIGKILL)
            if time.monotonic() >= kill_deadline:
                raise release.lifecycle.LifecycleError(
                    "diagnostic browser process group survived SIGKILL"
                )
            time.sleep(TEARDOWN_POLL_SECONDS)

        process.wait(timeout=TEARDOWN_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError, release.lifecycle.LifecycleError):
        try:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            process.wait(timeout=TEARDOWN_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError):
            pass
        return False
    return _wait_for_process_group_absence(
        process.pid,
        TEARDOWN_TIMEOUT_SECONDS,
    )


def _diagnostic_evidence_expression(host: str) -> str:
    """Return shared bounded evidence plus a fixed final-host state."""

    expected_host = json.dumps(host)
    shared = release._chrome_evidence_expression(host)
    return f"""
(() => {{
  const evidence = ({shared});
  const hostname = location.hostname.toLowerCase();
  return {{
    evidence,
    host_state: hostname === {expected_host}
      ? "same_host"
      : (hostname === "" ? "not_committed" : "other_host")
  }};
}})()
"""


def _classify_diagnostic_evidence(host: str, envelope: object) -> tuple[str, str]:
    if not isinstance(envelope, dict) or set(envelope) != {"evidence", "host_state"}:
        return "terminal_error", "document_invalid"
    host_state = envelope.get("host_state")
    if host_state == "not_committed":
        return "terminal_error", "navigation_pending"
    if host_state == "other_host":
        return "terminal_error", "origin_mismatch"
    if host_state != "same_host":
        return "terminal_error", "document_invalid"
    return release._classify_chrome_evidence(host, envelope.get("evidence"))


def _target_host_state(
    targets: object,
    debugger: str,
    host: str,
) -> str:
    """Reduce the exact DevTools target URL to one privacy-safe state."""

    if not isinstance(targets, list):
        return "invalid"
    matches = [
        item
        for item in targets
        if isinstance(item, dict)
        and item.get("type") == "page"
        and item.get("webSocketDebuggerUrl") == debugger
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("url"), str):
        return "invalid"
    target_url = matches[0]["url"]
    if target_url == "about:blank":
        return "not_committed"
    try:
        parsed = urlsplit(target_url)
        hostname = parsed.hostname
    except ValueError:
        return "invalid"
    if parsed.scheme.lower() != "https" or hostname is None:
        return "other_host"
    return "same_host" if hostname.lower() == host else "other_host"


def _browser_result(
    host: str,
    executable: Path,
) -> dict[str, object]:
    """Observe exactly one allowlisted host without product routing state."""

    executable = _validated_browser_executable(executable)
    profile = Path(tempfile.mkdtemp(prefix="slipstream-diagnostic-chrome-"))
    process: subprocess.Popen[bytes] | None = None
    observation_started: float | None = None
    finding_observed = False
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
        reason = "browser_observation_failed"
        observation_started = time.monotonic()
        try:
            navigation = release.chromium._devtools_command(
                debugger,
                port,
                "Page.navigate",
                {"url": f"https://{host}/"},
                response_timeout=STARTUP_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            # A pending top-level response can outlive the command socket while
            # Chrome continues committing and rendering its bounded document.
            # Continue semantic observation; this never converts the timeout
            # itself into a pass.
            navigation = None
            reason = "navigation_pending"
        if navigation is not None:
            if navigation.get("errorText") not in (None, ""):
                reason = "navigation_rejected"
                finding_observed = True
                raise release.LiveSiteError("Chrome rejected the HTTPS navigation")
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
            if reason != "document_invalid":
                finding_observed = True
            if outcome in {
                "usable",
                "regional_access_denied",
                "edge_access_denied",
            }:
                break
            time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
        if not finding_observed and reason == "navigation_pending":
            try:
                host_state = _target_host_state(
                    release.chromium._devtools_json(port, "/json/list"),
                    debugger,
                    host,
                )
            except (OSError, release.chromium.QualificationError):
                host_state = "invalid"
            if host_state in {"same_host", "not_committed"}:
                finding_observed = True
            elif host_state == "other_host":
                outcome = "terminal_error"
                reason = "origin_mismatch"
                finding_observed = True
        finished = time.monotonic()
    except release.LiveSiteError:
        finished = time.monotonic()
        outcome = "terminal_error"
    except (OSError, ValueError, release.chromium.QualificationError):
        finished = time.monotonic()
        outcome = "terminal_error"
        if observation_started is not None:
            reason = "browser_observation_failed"
    finally:
        cleaned_up = process is None or _terminate_process(process)
        if cleaned_up and not _remove_owned_profile(profile):
            cleaned_up = False
        if not cleaned_up:
            outcome = "terminal_error"
            reason = "browser_cleanup_failed"
    if reason in COMPLETED_DIAGNOSTIC_REASONS and not finding_observed:
        outcome = "terminal_error"
        reason = "browser_observation_failed"
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
    result = _browser_result(host, executable)
    return {
        "browser": "chrome-headless",
        "diagnostic_completed": result.get("reason")
        in COMPLETED_DIAGNOSTIC_REASONS,
        "diagnostic_only": True,
        "host": host,
        "release_eligible": False,
        "result": result,
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
    parser.add_argument(
        "--require-usable",
        action="store_true",
        help="return 1 when a completed target observation is not usable",
    )
    args = parser.parse_args(argv)
    try:
        report = run_diagnostic(args.host, args.chrome_executable)
    except (OSError, ValueError):
        report = {
            "browser": "chrome-headless",
            "diagnostic_completed": False,
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
    try:
        _write_report(report, args.output)
    except OSError:
        return 2
    if report.get("diagnostic_completed") is not True:
        return 2
    if args.require_usable and report["result"].get("outcome") != "usable":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

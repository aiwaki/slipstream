#!/usr/bin/env python3
"""One Safari session on disposable macOS CI; no application or network fixture."""

from __future__ import annotations

import argparse
import json
import os
import platform
import plistlib
import re
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import live_site_release_smoke as live
import pf_installed_lifecycle_smoke as lifecycle

DRIVER = "/usr/bin/safaridriver"
CLIENT_TIMEOUT = 210
STRATEGIES = {"normal", "none"}
SESSION_STAGES = {
    "driver_ready", "process_absence", "session_create", "process_start",
    "navigate_blank", "verify_blank", "complete",
}


def _require_ci(*, client: bool) -> None:
    if (
        sys.platform != "darwin"
        or os.environ.get("CI") != "true"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("SLIPSTREAM_DISPOSABLE_CI") != "1"
        or (os.geteuid() == 0) != client
    ):
        raise lifecycle.LifecycleError("requires disposable macOS CI and expected user")


def session_probe(strategy: str, driver_url: str, uid: int) -> dict:
    """Use the live gate's transport/ownership checks, without a live-site URL."""
    if strategy not in STRATEGIES or type(uid) is not int or uid <= 0:
        raise ValueError("invalid fixed session inputs")
    driver_url = lifecycle._validated_safaridriver_url(driver_url)
    if driver_url is None:
        raise ValueError("missing local driver")
    session_id = None
    safari_pid = None
    failure = None
    cleanup_errors = []
    cleanup_verified = False
    blank_verified = False
    stage = "driver_ready"
    started = time.monotonic()
    try:
        live._wait_for_safaridriver_ready(driver_url)
        stage = "process_absence"
        lifecycle._assert_no_safari_process(uid, "session-smoke-before")
        stage = "session_create"
        created = lifecycle._webdriver_request(driver_url, "POST", "/session", {
            "capabilities": {"alwaysMatch": {
                "browserName": "safari", "pageLoadStrategy": strategy,
            }},
        })
        value = created.get("value")
        session_id = value.get("sessionId") if isinstance(value, dict) else None
        session_id = session_id or created.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            session_id = None
            raise lifecycle.LifecycleError("missing session identity")
        stage = "process_start"
        safari_pid = lifecycle._wait_for_safari_process(uid, "session-smoke")
        encoded = urllib.parse.quote(session_id, safe="")
        stage = "navigate_blank"
        lifecycle._webdriver_request(driver_url, "POST", f"/session/{encoded}/url",
                                     {"url": "about:blank"})
        stage = "verify_blank"
        current = lifecycle._webdriver_request(driver_url, "GET", f"/session/{encoded}/url")
        if current.get("value") != "about:blank":
            raise lifecycle.LifecycleError("unexpected document")
        blank_verified = True
        stage = "complete"
    except Exception as exc:
        failure = exc
    finally:
        if session_id is not None:
            try:
                lifecycle._webdriver_request(driver_url, "DELETE",
                    f"/session/{urllib.parse.quote(session_id, safe='')}")
            except Exception as exc:
                cleanup_errors.append(lifecycle.webdriver_failure_details(exc))
        if safari_pid is not None:
            try:
                lifecycle._stop_owned_safari_process(safari_pid, uid, "session-smoke")
            except Exception as exc:
                cleanup_errors.append(lifecycle.webdriver_failure_details(exc))
        # A failed creation can still have started Safari. Never adopt/kill an
        # unknown PID, and never infer absence from a missing session/PID.
        try:
            lifecycle._assert_no_safari_process(uid, "session-smoke-after")
            cleanup_verified = not cleanup_errors
        except Exception as exc:
            cleanup_errors.append(lifecycle.webdriver_failure_details(exc))
    return {
        "strategy": strategy, "stage": stage,
        "status": "passed" if failure is None and cleanup_verified else "failed",
        "error": lifecycle.webdriver_failure_details(failure),
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "session_id_observed": session_id is not None,
        "pid_observed": safari_pid is not None,
        "blank_verified": blank_verified,
        "cleanup_verified": cleanup_verified,
        "cleanup_errors": cleanup_errors,
    }


def _token(value: object, pattern: str) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else None


def _runtime_identity() -> dict:
    safari = {}
    try:
        with Path("/Applications/Safari.app/Contents/Info.plist").open("rb") as source:
            safari = plistlib.load(source)
    except (OSError, ValueError):
        pass
    if not isinstance(safari, dict):
        safari = {}
    return {
        "macos_version": _token(platform.mac_ver()[0], r"[0-9.]{1,40}"),
        "safari_version": _token(safari.get("CFBundleShortVersionString"), r"[0-9.]{1,60}"),
        "safari_build": _token(safari.get("CFBundleVersion"), r"[0-9.]{1,60}"),
        "driver_version_source": "bundled_with_safari_not_independently_measured",
        "python_version": _token(platform.python_version(), r"[0-9.]{1,40}"),
        "architecture": _token(platform.machine(), r"arm64|x86_64"),
        "image_os": _token(os.environ.get("ImageOS"), r"[A-Za-z0-9_.-]{1,80}"),
        "image_version": _token(os.environ.get("ImageVersion"), r"[0-9.]{1,80}"),
        "source_sha": _token(os.environ.get("GITHUB_SHA"), r"[0-9a-f]{40}"),
        "run_id": _token(os.environ.get("GITHUB_RUN_ID"), r"[1-9][0-9]{0,19}"),
        "run_attempt": _token(os.environ.get("GITHUB_RUN_ATTEMPT"), r"[1-9][0-9]{0,9}"),
    }


def _validate_error(details: object) -> None:
    if not isinstance(details, dict) or set(details) != {"exception_class", "http_status", "webdriver_error"}:
        raise lifecycle.LifecycleError("invalid client diagnostic shape")
    name, status, code = (details[key] for key in ("exception_class", "http_status", "webdriver_error"))
    if name is not None and (not isinstance(name, str)
                            or name not in lifecycle.WEBDRIVER_EXCEPTION_CLASSES | {"Exception"}):
        raise lifecycle.LifecycleError("invalid client diagnostic class")
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise lifecycle.LifecycleError("invalid client diagnostic status")
    if code is not None and (not isinstance(code, str) or code not in lifecycle.WEBDRIVER_ERROR_CODES):
        raise lifecycle.LifecycleError("invalid client diagnostic code")
    if name is None and (status is not None or code is not None):
        raise lifecycle.LifecycleError("inconsistent client diagnostic")


def _run_client(strategy: str, driver_url: str, uid: int) -> dict:
    result = subprocess.run([
        "/usr/bin/sudo", "-n", "-E", sys.executable, str(Path(__file__).resolve()),
        "--client", "--strategy", strategy, "--safaridriver-url", driver_url,
        "--uid", str(uid),
    ], capture_output=True, timeout=CLIENT_TIMEOUT, check=False)
    # Only this script's bounded structured stdout is accepted. Stderr is never
    # retained, including subprocess/driver messages and session/URL fragments.
    if len(result.stdout) > 8192 or result.returncode not in (0, 1):
        raise lifecycle.LifecycleError("invalid client outcome")
    report = json.loads(result.stdout)
    expected = {"strategy", "stage", "status", "error", "elapsed_ms", "session_id_observed",
                "pid_observed", "blank_verified", "cleanup_verified", "cleanup_errors"}
    if not isinstance(report, dict) or set(report) != expected:
        raise lifecycle.LifecycleError("invalid client report shape")
    if report["strategy"] != strategy or report["stage"] not in SESSION_STAGES:
        raise lifecycle.LifecycleError("invalid client identity")
    if report["status"] not in {"passed", "failed"} or (result.returncode == 0) != (report["status"] == "passed"):
        raise lifecycle.LifecycleError("invalid client status")
    flags = ("session_id_observed", "pid_observed", "blank_verified", "cleanup_verified")
    if any(type(report[name]) is not bool for name in flags):
        raise lifecycle.LifecycleError("invalid client observation flags")
    if type(report["elapsed_ms"]) is not int or not 0 <= report["elapsed_ms"] <= CLIENT_TIMEOUT * 1000:
        raise lifecycle.LifecycleError("invalid client duration")
    _validate_error(report["error"])
    errors = report["cleanup_errors"]
    if not isinstance(errors, list) or len(errors) > 3:
        raise lifecycle.LifecycleError("invalid client cleanup diagnostics")
    for error in errors:
        _validate_error(error)
    if (report["cleanup_verified"] and errors
            or report["pid_observed"] and not report["session_id_observed"]
            or report["blank_verified"] and not report["pid_observed"]):
        raise lifecycle.LifecycleError("inconsistent client observations")
    if report["status"] == "passed" and (
        report["stage"] != "complete" or not all(report[name] for name in flags)
        or errors or report["error"] != lifecycle.webdriver_failure_details(None)
    ):
        raise lifecycle.LifecycleError("incomplete successful client proof")
    return report


def run_smoke(strategy: str) -> dict:
    report = {"schema_version": 1, "harness": "safari_session_smoke", "strategy": strategy,
              "release_qualified": False,
              "status": "failed", "stage": "preflight", "runtime": _runtime_identity(),
              "session": None, "error": lifecycle.webdriver_failure_details(None),
              "driver_started": False, "driver_stopped": False,
              "driver_exit_code": None,
              "absence_verified": False, "cleanup_errors": []}
    driver = None
    preflight_passed = False
    try:
        _require_ci(client=False)
        if strategy not in STRATEGIES:
            raise ValueError("unsupported comparison input")
        preflight_passed = True
        lifecycle._assert_no_safari_process(os.geteuid(), "session-smoke-initial")
        report["stage"] = "driver_enable"
        subprocess.run(["/usr/bin/sudo", "-n", DRIVER, "--enable"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True, timeout=30)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        report["stage"] = "driver_start"
        driver = subprocess.Popen([DRIVER, "--diagnose", "--port", str(port)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report["driver_started"] = True
        if driver.poll() is not None:
            raise lifecycle.LifecycleError("owned driver exited before client")
        report["stage"] = "client"
        report["session"] = _run_client(strategy, f"http://127.0.0.1:{port}", os.geteuid())
        if driver.poll() is not None:
            raise lifecycle.LifecycleError("owned driver exited during client")
        if report["session"]["status"] != "passed":
            raise lifecycle.LifecycleError("session probe refused")
        report["stage"] = "complete"
    except Exception as exc:
        report["error"] = lifecycle.webdriver_failure_details(exc)
    finally:
        if driver is not None:
            try:
                if driver.poll() is None:
                    driver.terminate()
                exit_code = driver.wait(timeout=5)
                report["driver_exit_code"] = exit_code if type(exit_code) is int else None
                report["driver_stopped"] = True
            except Exception as exc:
                report["cleanup_errors"].append(lifecycle.webdriver_failure_details(exc))
        if preflight_passed:
            try:
                lifecycle._assert_no_safari_process(os.geteuid(), "session-smoke-final")
                report["absence_verified"] = True
            except Exception as exc:
                report["cleanup_errors"].append(lifecycle.webdriver_failure_details(exc))
    if (report["stage"] == "complete" and report["driver_stopped"]
            and report["absence_verified"] and not report["cleanup_errors"]):
        report["status"] = "passed"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strategy", choices=sorted(STRATEGIES), required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--client", action="store_true")
    parser.add_argument("--safaridriver-url")
    parser.add_argument("--uid", type=int)
    args = parser.parse_args()
    if args.client:
        try:
            _require_ci(client=True)
            if lifecycle.pf._original_user()[0] != args.uid:
                raise lifecycle.LifecycleError("client user mismatch")
            report = session_probe(args.strategy, args.safaridriver_url, args.uid)
        except Exception as exc:
            # No exception text or traceback is allowed through this boundary.
            print(json.dumps({"error": lifecycle.webdriver_failure_details(exc)}))
            return 2
        print(json.dumps(report, sort_keys=True))
    else:
        if args.output is None:
            parser.error("--output is required")
        report = run_smoke(args.strategy)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as output:
            os.chmod(args.output, 0o600)
            output.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

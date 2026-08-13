#!/usr/bin/env python3
"""Measure a packaged Slipstream background/idle invisibility soak on macOS."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

import pending_navigation_browser_probe_smoke as visibility


SCHEMA_VERSION = 1
RELEASE_DURATION_SECONDS = 1800
SAMPLE_INTERVAL_SECONDS = 0.5
MAX_SAMPLE_GAP_SECONDS = 2.0
MAX_HEARTBEAT_AGE_SECONDS = 5.0
PROFILE_GLOB = "slipstream-browser-probe-" + "[0-9a-f]" * 32
FORBIDDEN_LAUNCH_AGENTS = (
    "dev.slipstream.semantic-browser.plist",
    "dev.slipstream.browser-worker.plist",
)


class SoakError(RuntimeError):
    pass


def _require_protected_ci() -> None:
    expected = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
        "SLIPSTREAM_RELEASE_READINESS": "1",
    }
    missing = [key for key, value in expected.items() if os.environ.get(key) != value]
    if missing or sys.platform != "darwin" or os.geteuid() == 0:
        raise SoakError("invisibility soak requires the console CI user on macOS")


def _read_status() -> dict:
    path = Path("/var/run/slipstream.status")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SoakError("daemon status is unavailable during soak") from exc
    daemon = value.get("daemon") if value.get("schema_version") == 2 else value
    if not isinstance(daemon, dict):
        raise SoakError("daemon status is invalid during soak")
    return daemon


def _wait_status(timeout: float = 90.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            daemon = _read_status()
        except SoakError:
            time.sleep(0.5)
            continue
        heartbeat = daemon.get("heartbeat_seq")
        if daemon.get("state") == "active" and isinstance(heartbeat, int):
            return daemon
        time.sleep(0.5)
    raise SoakError("daemon did not publish an active heartbeat")


def _validate_live_heartbeat(
    daemon: dict,
    *,
    expected_pid: int,
    previous_seq: int,
    last_change_monotonic: float,
    now_wall: float,
    now_monotonic: float,
) -> tuple[int, float]:
    """Require a continuously live daemon, not merely a stale final status file."""
    pid = daemon.get("pid")
    seq = daemon.get("heartbeat_seq")
    updated_at = daemon.get("updated_at")
    if daemon.get("state") != "active" or pid != expected_pid:
        raise SoakError("daemon left the active owned PID during idle soak")
    if type(seq) is not int or seq < previous_seq:
        raise SoakError("daemon heartbeat sequence is invalid during idle soak")
    if not isinstance(updated_at, (int, float)) or isinstance(updated_at, bool):
        raise SoakError("daemon heartbeat timestamp is invalid during idle soak")
    age = now_wall - float(updated_at)
    if age < -1.0 or age > MAX_HEARTBEAT_AGE_SECONDS:
        raise SoakError("daemon heartbeat became stale during idle soak")
    if seq > previous_seq:
        return seq, now_monotonic
    if now_monotonic - last_change_monotonic > MAX_HEARTBEAT_AGE_SECONDS:
        raise SoakError("daemon heartbeat stopped advancing during idle soak")
    return previous_seq, last_change_monotonic


def _profiles() -> set[str]:
    roots = {Path("/tmp"), Path(tempfile.gettempdir())}
    if os.environ.get("TMPDIR"):
        roots.add(Path(os.environ["TMPDIR"]))
    profiles: set[str] = set()
    for root in roots:
        try:
            profiles.update(str(path.resolve()) for path in root.glob(PROFILE_GLOB))
        except OSError:
            continue
    return profiles


def _launch_agents() -> set[str]:
    root = Path.home() / "Library" / "LaunchAgents"
    return {name for name in FORBIDDEN_LAUNCH_AGENTS if (root / name).exists()}


def _run_checked(command: tuple[str, ...], timeout: float = 120.0) -> None:
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=timeout
    )
    if result.returncode != 0:
        raise SoakError(f"command failed during soak: {command[0]}")


def _terminate_owned(process: subprocess.Popen[bytes], executable: Path) -> None:
    if process.poll() is not None:
        return
    actual = visibility._run_text(
        ("/bin/ps", "-p", str(process.pid), "-o", "command="), timeout=5
    ).strip()
    if actual != str(executable) and not actual.startswith(f"{executable} "):
        raise SoakError("refusing to terminate an unowned tray process")
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _sample_window(
    duration_seconds: float,
    callback,
    *,
    monotonic=time.monotonic,
    sleep=time.sleep,
) -> tuple[float, int, float]:
    started = monotonic()
    deadline = started + duration_seconds
    samples = 0
    previous_sample = started
    max_sample_gap = 0.0
    next_sample = started
    while monotonic() < deadline:
        sample_started = monotonic()
        if samples:
            max_sample_gap = max(max_sample_gap, sample_started - previous_sample)
        previous_sample = sample_started
        callback()
        samples += 1
        next_sample += SAMPLE_INTERVAL_SECONDS
        remaining = deadline - monotonic()
        if remaining > 0:
            sleep(min(max(0.0, next_sample - monotonic()), remaining))
    measured = monotonic() - started
    max_sample_gap = max(max_sample_gap, measured - (previous_sample - started))
    return measured, samples, max_sample_gap


def run_soak(app_bundle: Path, duration_seconds: int) -> tuple[dict, int]:
    _require_protected_ci()
    if duration_seconds <= 0:
        raise SoakError("soak duration must be positive")
    app = app_bundle.resolve(strict=True)
    daemon = app / "Contents" / "Resources" / "slipstreamd" / "slipstreamd"
    tray_executable = app / "Contents" / "MacOS" / "slipstream"
    if not daemon.is_file() or not tray_executable.is_file():
        raise SoakError("packaged app is incomplete")
    baseline_frontmost = visibility._frontmost_asn()
    baseline_profiles = _profiles()
    baseline_agents = _launch_agents()
    baseline_gui, baseline_headless = visibility._browser_processes()
    if baseline_gui or baseline_headless or baseline_profiles or baseline_agents:
        raise SoakError("invisibility soak requires a clean browser-worker baseline")

    tray_log = tempfile.TemporaryFile()
    tray: subprocess.Popen[bytes] | None = None
    listener: subprocess.Popen[str] | None = None
    unified_log: subprocess.Popen[str] | None = None
    event_output = ""
    unified_output = ""
    measured_seconds = 0.0
    samples = 0
    max_sample_gap = 0.0
    window_events = 0
    dock_visible_samples = 0
    frontmost_changes = 0
    gui_chrome_samples = 0
    headless_shell_samples = 0
    max_profiles = 0
    max_launch_agents = 0
    first_status: dict | None = None
    last_status: dict | None = None
    failure: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        _run_checked(("/usr/bin/sudo", str(daemon), "--install"))
        first_status = _wait_status()
        listener = subprocess.Popen(
            (
                visibility.LSAPPINFO,
                "listen",
                "+all",
                "wait",
                "-duration",
                str(duration_seconds + 30),
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        unified_log = subprocess.Popen(
            (
                "/usr/bin/log",
                "stream",
                "--style",
                "json",
                "--level",
                "debug",
                "--predicate",
                'eventMessage CONTAINS[c] "PostShowProcess" AND '
                '(eventMessage CONTAINS[c] "slipstream" OR '
                'eventMessage CONTAINS[c] "chrome-headless" OR '
                'eventMessage CONTAINS[c] "chromium")',
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        tray = subprocess.Popen(
            (str(tray_executable),),
            stdin=subprocess.DEVNULL,
            stdout=tray_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        # Observe the launch window at a higher cadence before entering the
        # long idle sample. A focus steal or short-lived AppKit/Chrome window
        # must not disappear inside a one-second blind startup sleep.
        startup_deadline = time.monotonic() + 1.0
        while time.monotonic() < startup_deadline:
            windows = visibility._slipstream_window_ids()
            listing = visibility._launch_services_listing()
            _registered, dock_visible = visibility._slipstream_launch_services_state(
                listing
            )
            gui, headless = visibility._browser_processes()
            current_profiles = _profiles() - baseline_profiles
            current_agents = _launch_agents() - baseline_agents
            window_events += int(bool(windows))
            dock_visible_samples += int(dock_visible)
            frontmost_changes += int(visibility._frontmost_asn() != baseline_frontmost)
            gui_chrome_samples += int(bool(gui))
            headless_shell_samples += int(bool(headless))
            max_profiles = max(max_profiles, len(current_profiles))
            max_launch_agents = max(max_launch_agents, len(current_agents))
            time.sleep(0.05)
        if listener.poll() is not None or unified_log.poll() is not None:
            raise SoakError("visibility sampler exited before measured soak")
        if tray.poll() is not None:
            raise SoakError("tray process exited before measured soak")
        # The measured window starts only after the daemon, tray, LaunchServices
        # listener, and unified-log sampler are all ready.
        first_status = _wait_status()
        expected_pid = first_status.get("pid")
        previous_heartbeat_seq = first_status.get("heartbeat_seq")
        if type(expected_pid) is not int or type(previous_heartbeat_seq) is not int:
            raise SoakError("daemon heartbeat identity is invalid before idle soak")
        last_heartbeat_change = time.monotonic()

        def sample() -> None:
            nonlocal window_events
            nonlocal dock_visible_samples
            nonlocal frontmost_changes
            nonlocal gui_chrome_samples
            nonlocal headless_shell_samples
            nonlocal max_profiles
            nonlocal max_launch_agents
            nonlocal last_status
            nonlocal previous_heartbeat_seq
            nonlocal last_heartbeat_change
            if tray.poll() is not None:
                raise SoakError("tray process exited during idle soak")
            windows = visibility._slipstream_window_ids()
            listing = visibility._launch_services_listing()
            _registered, dock_visible = visibility._slipstream_launch_services_state(
                listing
            )
            gui, headless = visibility._browser_processes()
            current_profiles = _profiles() - baseline_profiles
            current_agents = _launch_agents() - baseline_agents
            window_events += int(bool(windows))
            dock_visible_samples += int(dock_visible)
            frontmost_changes += int(visibility._frontmost_asn() != baseline_frontmost)
            gui_chrome_samples += int(bool(gui))
            headless_shell_samples += int(bool(headless))
            max_profiles = max(max_profiles, len(current_profiles))
            max_launch_agents = max(max_launch_agents, len(current_agents))
            last_status = _read_status()
            previous_heartbeat_seq, last_heartbeat_change = _validate_live_heartbeat(
                last_status,
                expected_pid=expected_pid,
                previous_seq=previous_heartbeat_seq,
                last_change_monotonic=last_heartbeat_change,
                now_wall=time.time(),
                now_monotonic=time.monotonic(),
            )

        measured_seconds, samples, max_sample_gap = _sample_window(
            duration_seconds, sample
        )
    except BaseException as exc:
        failure = exc
    finally:
        if tray is not None:
            try:
                _terminate_owned(tray, tray_executable)
            except BaseException as exc:
                cleanup_errors.append(str(exc))
        try:
            installed = Path("/usr/local/slipstream/slipstreamd")
            if installed.exists():
                _run_checked(("/usr/bin/sudo", str(installed), "--uninstall"))
        except BaseException as exc:
            cleanup_errors.append(str(exc))
        for process, label in ((listener, "events"), (unified_log, "unified")):
            if process is None:
                continue
            process.terminate()
            try:
                output, _ = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
            if label == "events":
                event_output = output
            else:
                unified_output = output
        tray_log.close()

    event_text = event_output.casefold()
    launch_services_visible_events = sum(
        event_text.count(marker.casefold())
        for marker in visibility.FORBIDDEN_LAUNCH_SERVICES_EVENTS
    )
    profile_residue = len(_profiles() - baseline_profiles)
    launch_agent_residue = len(_launch_agents() - baseline_agents)
    unified_log_post_show_process = sum(
        1
        for line in unified_output.splitlines()
        if "postshowprocess" in line.casefold()
        and any(
            marker in line.casefold()
            for marker in ("slipstream", "chrome-headless", "chromium")
        )
    )
    pid_stable = bool(
        first_status
        and last_status
        and first_status.get("pid") == last_status.get("pid")
    )
    first_seq = first_status.get("heartbeat_seq") if first_status else None
    last_seq = last_status.get("heartbeat_seq") if last_status else None
    heartbeat_advanced = (
        isinstance(first_seq, int) and isinstance(last_seq, int) and last_seq > first_seq
    )
    counters = {
        "coregraphics_window_samples": window_events,
        "dock_visible_samples": dock_visible_samples,
        "frontmost_changes": frontmost_changes,
        "gui_chrome_samples": gui_chrome_samples,
        "headless_shell_samples": headless_shell_samples,
        "launch_agent_residue": launch_agent_residue,
        "launch_services_visible_events": launch_services_visible_events,
        "unified_log_post_show_process": unified_log_post_show_process,
        "max_launch_agents": max_launch_agents,
        "max_worker_profiles": max_profiles,
        "profile_residue": profile_residue,
    }
    passed = (
        failure is None
        and not cleanup_errors
        and measured_seconds >= duration_seconds
        and samples > 0
        and max_sample_gap <= MAX_SAMPLE_GAP_SECONDS
        and not any(counters.values())
        and pid_stable
        and heartbeat_advanced
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "harness": "packaged_macos_invisibility_soak",
        "harness_exit_status": 0 if passed else 1,
        "result": "passed" if passed else "failed",
        "requested_duration_seconds": duration_seconds,
        "measured_duration_seconds": round(measured_seconds, 3),
        "sample_interval_seconds": SAMPLE_INTERVAL_SECONDS,
        "max_sample_gap_seconds": round(max_sample_gap, 3),
        "visibility_samples": samples,
        "counters": counters,
        "daemon_pid_stable": pid_stable,
        "heartbeat_advanced": heartbeat_advanced,
    }
    return report, 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-bundle", type=Path, required=True)
    parser.add_argument(
        "--duration-seconds", type=int, default=RELEASE_DURATION_SECONDS
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report, exit_status = run_soak(args.app_bundle, args.duration_seconds)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return exit_status


if __name__ == "__main__":
    raise SystemExit(main())

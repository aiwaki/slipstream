#!/usr/bin/env python3
"""Measure a packaged Slipstream background/idle invisibility soak on macOS."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time

import invisibility_soak_contract
import pending_navigation_browser_probe_smoke as visibility

SCHEMA_VERSION = invisibility_soak_contract.SCHEMA_VERSION
RELEASE_DURATION_SECONDS = 1800
SAMPLE_INTERVAL_SECONDS = 0.5
MAX_SAMPLE_GAP_SECONDS = 2.0
MAX_HEARTBEAT_AGE_SECONDS = 5.0
PROFILE_GLOB = "slipstream-browser-probe-" + "[0-9a-f]" * 32
FORBIDDEN_LAUNCH_AGENTS = (
    "dev.slipstream.semantic-browser.plist",
    "dev.slipstream.browser-worker.plist",
)
CLEANUP_PROBE_INTERVAL_SECONDS = 0.2
CLEANUP_PROBE_TIMEOUT_SECONDS = 3.0
CLEANUP_STABLE_SAMPLES = 3
INSTALLED_DAEMON = Path("/usr/local/slipstream/slipstreamd")
SYSTEM_CLEANUP_PATHS = invisibility_soak_contract.SYSTEM_CLEANUP_PATHS
SYSTEM_CLEANUP_LABELS = invisibility_soak_contract.SYSTEM_CLEANUP_LABELS
CLEANUP_REPORT_SYMBOLS = invisibility_soak_contract.CLEANUP_REPORT_SYMBOLS
UNIFIED_LOG_FILTER_BANNER_PREFIX = "Filtering the log data using "
UNIFIED_LOG_EVENT_MARKERS = ("slipstream", "chrome-headless", "chromium")
UNIFIED_LOG_START_TIMEOUT_SECONDS = 5.0
UNIFIED_LOG_HANDSHAKE_MAX_BYTES = 64 * 1024


class SoakError(RuntimeError):
    pass


class CleanupError(SoakError):
    """Carry only allowlisted cleanup diagnostics across the report boundary."""

    def __init__(self, kind: str, resources: tuple[str, ...] = ()) -> None:
        if kind == "uninstall_command":
            if resources:
                raise ValueError("uninstall cleanup errors cannot name resources")
            self.report_symbols = (kind,)
            message = "product cleanup failed: uninstall_command"
        elif kind in {"probe", "residue"}:
            if not resources or any(
                resource not in SYSTEM_CLEANUP_LABELS for resource in resources
            ):
                raise ValueError("cleanup error resources must be allowlisted")
            resources = tuple(sorted(set(resources)))
            self.report_symbols = tuple(
                f"{kind}:{resource}" for resource in resources
            )
            prefix = (
                "cleanup probe failed"
                if kind == "probe"
                else "product cleanup residue"
            )
            message = prefix + ": " + ",".join(resources)
        else:
            raise ValueError("unknown cleanup error kind")
        super().__init__(message)


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


def _run_cleanup_probe(
    command: tuple[str, ...], label: str
) -> subprocess.CompletedProcess[str]:
    """Run one exact cleanup probe and collapse execution errors to its label."""
    if label not in SYSTEM_CLEANUP_LABELS:
        raise ValueError("cleanup probe label must be allowlisted")
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CleanupError("probe", (label,)) from exc


def _system_cleanup_residues() -> tuple[str, ...]:
    """Return only bounded symbolic names for exact product-owned residue."""
    residues = [
        label for label, path in SYSTEM_CLEANUP_PATHS if os.path.lexists(path)
    ]
    launchd = _run_cleanup_probe(
        (
            "/usr/bin/sudo",
            "/bin/launchctl",
            "print",
            "system/dev.slipstream.tproxy",
        ),
        "launchd_job",
    )
    if launchd.returncode == 0:
        residues.append("launchd_job")
    elif launchd.returncode != 113 or "Could not find service" not in (
        launchd.stdout + launchd.stderr
    ):
        raise CleanupError("probe", ("launchd_job",))
    for label, mode in (("pf_nat_anchor", "-sn"), ("pf_filter_anchor", "-sr")):
        result = _run_cleanup_probe(
            (
                "/usr/bin/sudo",
                "/sbin/pfctl",
                "-a",
                "com.apple/slipstream",
                mode,
            ),
            label,
        )
        if result.returncode != 0:
            raise CleanupError("probe", (label,))
        if result.stdout.strip():
            residues.append(label)
    listener = _run_cleanup_probe(
        (
            "/usr/bin/sudo",
            "/usr/sbin/lsof",
            "-nP",
            "-t",
            "-iTCP:1080",
            "-sTCP:LISTEN",
        ),
        "daemon_listener",
    )
    if listener.returncode == 0 and listener.stdout.strip():
        residues.append("daemon_listener")
    elif not (
        listener.returncode == 1
        and not listener.stdout.strip()
        and not listener.stderr.strip()
    ):
        raise CleanupError("probe", ("daemon_listener",))
    return tuple(sorted(residues))


def _wait_for_system_cleanup_absence(
    *,
    timeout: float = CLEANUP_PROBE_TIMEOUT_SECONDS,
    stable_samples: int = CLEANUP_STABLE_SAMPLES,
    monotonic=time.monotonic,
    sleep=time.sleep,
) -> tuple[str, ...]:
    """Require several consecutive absent samples to catch late reappearance."""
    if timeout <= 0 or stable_samples <= 0:
        raise ValueError("cleanup wait bounds must be positive")
    deadline = monotonic() + timeout
    consecutive_absent = 0
    last_residues: tuple[str, ...] = ("cleanup_state_unstable",)
    while True:
        residues = _system_cleanup_residues()
        if residues:
            last_residues = residues
            consecutive_absent = 0
        else:
            consecutive_absent += 1
            if consecutive_absent >= stable_samples:
                return ()
        if monotonic() >= deadline:
            return last_residues
        sleep(CLEANUP_PROBE_INTERVAL_SECONDS)


def _cleanup_installed_candidate() -> None:
    """Clean once through the root-owned installed daemon, then prove absence."""
    try:
        _run_checked(("/usr/bin/sudo", str(INSTALLED_DAEMON), "--uninstall"))
    except BaseException as exc:
        raise CleanupError("uninstall_command") from exc
    residues = _wait_for_system_cleanup_absence()
    if residues:
        raise CleanupError("residue", residues)


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


def _validate_unified_log_filter_banner(line: str) -> None:
    folded = line.casefold()
    required_terms = ("postshowprocess", *UNIFIED_LOG_EVENT_MARKERS)
    if not line.startswith(UNIFIED_LOG_FILTER_BANNER_PREFIX) or not all(
        term in folded for term in required_terms
    ):
        raise SoakError("unified-log filter banner is invalid")


def _wait_for_unified_log_filter_banner(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float = UNIFIED_LOG_START_TIMEOUT_SECONDS,
) -> bytes:
    if process.stdout is None:
        raise SoakError("unified-log sampler has no output pipe")
    if process.poll() is not None:
        raise SoakError("unified-log sampler exited before its filter banner")
    deadline = time.monotonic() + timeout_seconds
    captured = bytearray()
    while b"\n" not in captured:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SoakError("unified-log filter banner timed out")
        readable, _, _ = select.select((process.stdout,), (), (), remaining)
        if not readable:
            raise SoakError("unified-log filter banner timed out")
        chunk = os.read(process.stdout.fileno(), UNIFIED_LOG_HANDSHAKE_MAX_BYTES)
        if not chunk:
            raise SoakError("unified-log sampler exited before its filter banner")
        captured.extend(chunk)
        if len(captured) > UNIFIED_LOG_HANDSHAKE_MAX_BYTES:
            raise SoakError("unified-log filter banner exceeded its byte limit")
    banner, _, _prefetched = bytes(captured).partition(b"\n")
    try:
        banner_text = banner.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SoakError("unified-log filter banner is not UTF-8") from exc
    _validate_unified_log_filter_banner(banner_text.strip())
    return bytes(captured)


def _count_unified_log_post_show_events(output: str | bytes) -> int:
    """Count only structured PostShowProcess events from ``log stream``.

    ``log stream --predicate`` writes a plain-text filter banner to stdout.
    That banner repeats the complete predicate, including PostShowProcess and
    every product marker, so substring matching mistakes the sampler's own
    banner for a visibility event. NDJSON keeps real events independently
    parseable; any other output remains a fail-closed sampler error.
    """

    if isinstance(output, bytes):
        try:
            output = output.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SoakError("unified-log sampler output is not UTF-8") from exc
    count = 0
    banner_seen = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(UNIFIED_LOG_FILTER_BANNER_PREFIX):
            if banner_seen:
                raise SoakError("unified-log filter banner is invalid")
            _validate_unified_log_filter_banner(line)
            banner_seen = True
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SoakError("unified-log sampler emitted malformed NDJSON") from exc
        if not isinstance(event, dict):
            raise SoakError("unified-log sampler event must be an object")
        message = event.get("eventMessage")
        if not isinstance(message, str):
            raise SoakError("unified-log sampler event has no message")
        message_folded = message.casefold()
        if "postshowprocess" not in message_folded or not any(
            marker in message_folded for marker in UNIFIED_LOG_EVENT_MARKERS
        ):
            raise SoakError("unified-log predicate emitted an unrelated event")
        count += 1
    if not banner_seen:
        raise SoakError("unified-log filter banner is missing")
    return count


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
    unified_log: subprocess.Popen[bytes] | None = None
    event_output = ""
    unified_prefix = b""
    unified_output = b""
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
    cleanup_failures: list[str] = []
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
        if listener.poll() is not None:
            raise SoakError("visibility sampler exited before measured soak")
        if tray.poll() is not None:
            raise SoakError("tray process exited before measured soak")
        # The measured window starts only after the daemon, tray, LaunchServices
        # listener, and high-cadence launch observations are all ready. Start
        # the unified-log stream only now: a menu-bar UIElement emits one
        # expected PostShowProcess while registering, whereas any later show
        # request during the idle interval is a real regression signal.
        first_status = _wait_status()
        unified_log = subprocess.Popen(
            (
                "/usr/bin/log",
                "stream",
                "--style",
                "ndjson",
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
        )
        unified_prefix = _wait_for_unified_log_filter_banner(unified_log)
        if unified_log.poll() is not None:
            raise SoakError("unified-log sampler exited before measured soak")
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
            if listener is None or listener.poll() is not None:
                raise SoakError("visibility sampler exited during idle soak")
            if unified_log is None or unified_log.poll() is not None:
                raise SoakError("unified-log sampler exited during idle soak")
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
        if tray.poll() is not None:
            raise SoakError("tray process exited at measured soak boundary")
        if listener is None or listener.poll() is not None:
            raise SoakError("visibility sampler exited at measured soak boundary")
        if unified_log is None or unified_log.poll() is not None:
            raise SoakError("unified-log sampler exited at measured soak boundary")
    except BaseException as exc:
        failure = exc
    finally:
        if tray is not None:
            try:
                _terminate_owned(tray, tray_executable)
            except BaseException:
                cleanup_failures.append("tray_process")
        try:
            _cleanup_installed_candidate()
        except CleanupError as exc:
            cleanup_failures.extend(exc.report_symbols)
        except BaseException:
            cleanup_failures.append("product_cleanup_unexpected")
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
                unified_output = unified_prefix + output
        tray_log.close()

    event_text = event_output.casefold()
    launch_services_visible_events = sum(
        event_text.count(marker.casefold())
        for marker in visibility.FORBIDDEN_LAUNCH_SERVICES_EVENTS
    )
    profile_residue = len(_profiles() - baseline_profiles)
    launch_agent_residue = len(_launch_agents() - baseline_agents)
    try:
        unified_log_post_show_process = _count_unified_log_post_show_events(
            unified_output
        )
    except SoakError as exc:
        failure = failure or exc
        unified_log_post_show_process = 1
    pid_stable = bool(
        first_status
        and last_status
        and first_status.get("pid") == last_status.get("pid")
    )
    first_seq = first_status.get("heartbeat_seq") if first_status else None
    last_seq = last_status.get("heartbeat_seq") if last_status else None
    heartbeat_advanced = (
        isinstance(first_seq, int)
        and isinstance(last_seq, int)
        and last_seq > first_seq
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
        and not cleanup_failures
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
        "cleanup_failures": sorted(set(cleanup_failures)),
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

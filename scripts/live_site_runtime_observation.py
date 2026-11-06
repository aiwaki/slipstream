"""Passive, bounded failure evidence for the disposable live-site gate.

No probes, retries, settings, keychain access or process/service mutations.
This is diagnostic evidence, never a route-ownership or readiness authority.
"""

from __future__ import annotations

import json
import math
import os
import pwd
import re
import stat
import subprocess
import time
from datetime import datetime
from pathlib import Path

import geph_owned_lifecycle_smoke as geph

MAX_JSON_BYTES = 64 * 1024
SAMPLE_TIMEOUT = 2.0
DAEMON_LOG_PATH = Path("/var/log/slipstream.log")
MAX_LOG_TAIL_BYTES = 64 * 1024
MAX_LOG_EVENTS = 32
FIXED_LOG_HOSTS = frozenset({
    "xpersonatoy.com", "app.aikido.dev", "weather.com", "capacitorjs.com",
})
_LOG_REASONS = {
    "SOCKS connect failed": "connect_failed",
    "first payload timeout": "first_payload_timeout",
    "remote closed without response": "remote_closed",
}
_LOG_LINE = re.compile(
    rb"(?P<at>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{4}) "
    rb">> (?P<message>[^\r\n]{1,240})"
)


def _json_file(path: Path, *, owner: int | None = None) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_JSON_BYTES:
            raise ValueError("invalid diagnostic input")
        if owner is not None and (
            metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("invalid diagnostic owner")
        raw = source.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("diagnostic input exceeded limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid diagnostic object")
    return value


def _integer(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**31 - 1 else None


def _choice(value: object, choices: set[str]) -> str:
    return value if isinstance(value, str) and value in choices else "unknown"


def _timestamp(value: object) -> float | None:
    if isinstance(value, str):
        if not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):?[0-5][0-9])", value,
        ):
            return None
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except (ValueError, OverflowError, OSError):
            return None
    if type(value) not in (int, float):
        return None
    # Unix timestamps through year 9999; reject bool, NaN and infinities.
    return float(value) if 0 <= value <= 253402300799 and math.isfinite(value) else None


def _age_ms(timestamp: float | None, now: float) -> int | None:
    age = now - timestamp if timestamp is not None else None
    return round(age * 1000) if age is not None and 0 <= age <= 86400 else None


def _status(path: Path, now: float) -> dict:
    try:
        value = _json_file(path)
        if value.get("schema_version") != 2:
            raise ValueError("unsupported status schema")
        daemon = value["daemon"]
        backend = value["backends"]["geph"]
        recovery = value["recovery"]
        updated = _timestamp(daemon.get("updated_at"))
        heartbeat = _timestamp(daemon.get("heartbeat_at"))
        health = _timestamp(daemon.get("health_updated_at"))
        return {
            "state": "sampled",
            "daemon_pid": _integer(daemon.get("pid")),
            "daemon_state": _choice(daemon.get("state"), {"active", "dormant", "starting", "stopped"}),
            # Keep the existing publication-age field for sidecar consumers.
            # A fresh heartbeat republishes cached health; it is not a new probe.
            "status_age_ms": _age_ms(updated, now),
            "heartbeat_age_ms": _age_ms(heartbeat if heartbeat is not None else updated, now),
            "health_updated_at": health,
            "health_age_ms": _age_ms(health, now),
            "geph_state": _choice(backend.get("state"), {"up", "down", "off"}),
            "geph_owned": backend.get("owned") if type(backend.get("owned")) is bool else None,
            "port_conflict": backend.get("port_conflict") if type(backend.get("port_conflict")) is bool else None,
            "restart_recommended": backend.get("restart_recommended") if type(backend.get("restart_recommended")) is bool else None,
            "active_sessions": _integer(backend.get("active_sessions")),
            "recovery_state": _choice(recovery.get("state"), {"idle", "recovering", "waiting", "paused", "rearmed"}),
            "recovery_reason": _choice(recovery.get("reason"), {"", "owned_geph_restart_waiting_for_idle", "owned_geph_restart_pending", "resource_pressure"}),
            "recovery_last_action": _choice(recovery.get("last_action"), {"none", "pause_private_pf", "wake", "network_change", "geph_restart"}),
            "recovery_updated_at": _timestamp(recovery.get("updated_at")),
            "recovery_count": _integer(recovery.get("count")),
        }
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {"state": "unavailable"}


def _log_tail(path: Path, deadline: float, seen: set[tuple[int, int]]) -> tuple[dict, bytes]:
    evidence = {"state": "unavailable", "bytes_read": 0,
                "truncated": False, "partial_line_discarded": False}
    if time.monotonic() >= deadline:
        evidence["state"] = "timed_out"
        return evidence, b""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            return evidence, b""
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in seen:
            evidence["state"] = "duplicate"
            return evidence, b""
        seen.add(identity)
        size = metadata.st_size
        start = max(0, size - MAX_LOG_TAIL_BYTES)
        evidence["truncated"] = bool(start)
        os.lseek(fd, start, os.SEEK_SET)
        if time.monotonic() >= deadline:
            evidence["state"] = "timed_out"
            return evidence, b""
        # Read only the sampled size, even if the daemon appends concurrently.
        raw = os.read(fd, min(size, MAX_LOG_TAIL_BYTES))
        evidence["bytes_read"] = len(raw)
        if time.monotonic() >= deadline:
            evidence["state"] = "timed_out"
            return evidence, b""
        if len(raw) != min(size, MAX_LOG_TAIL_BYTES):
            return evidence, b""  # truncated/replaced during the read
        if start:
            # The first fragment may be the tail of an unrelated raw log line.
            raw = raw.partition(b"\n")[2]
            evidence["partial_line_discarded"] = True
        if raw and not raw.endswith(b"\n"):
            raw = raw.rpartition(b"\n")[0]
            evidence["partial_line_discarded"] = True
        evidence["state"] = "sampled"
        return evidence, raw
    except FileNotFoundError:
        evidence["state"] = "missing"
        return evidence, b""
    except OSError:
        return evidence, b""
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _log_event(line: bytes, host: str) -> dict | None:
    matched = _LOG_LINE.fullmatch(line.removesuffix(b"\r"))
    if matched is None:
        return None
    message = matched["message"]
    if message == b"owned Geph LaunchAgent restarted after routing became idle":
        kind, scope = "owned_restart", "daemon"
    else:
        prefix = f"geph route retry for {host}: ".encode("ascii")
        if not message.startswith(prefix):
            return None
        kind = _LOG_REASONS.get(message[len(prefix):].decode("ascii", errors="replace"))
        if kind is None:
            return None
        scope = "host"
    timestamp = _timestamp(matched["at"].decode("ascii"))
    return {"kind": kind, "scope": scope, "at": timestamp} if timestamp is not None else None


def _daemon_log(host: str | None, deadline: float) -> dict:
    observation = {
        "state": "not_requested" if host is None else "unavailable",
        "request_window_scoped": False, "absence_proves_no_dial": False,
        "rate_limited": True, "archive_limit": 1, "rotation_atomic": False,
        "tail_truncated": False, "events_truncated": False, "time_limited": False,
        "sources": {}, "events": [],
        "counts": {kind: 0 for kind in (*_LOG_REASONS.values(), "owned_restart")},
    }
    if not isinstance(host, str) or host not in FIXED_LOG_HOSTS:
        return observation
    seen: set[tuple[int, int]] = set()
    events = []
    # RotatingLogWriter uses path + '.1', not a suffix replacement or glob.
    for label, path in (("current", DAEMON_LOG_PATH), ("archive", Path(f"{DAEMON_LOG_PATH}.1"))):
        evidence, raw = _log_tail(path, deadline, seen)
        observation["sources"][label] = evidence
        observation["tail_truncated"] |= evidence["truncated"]
        observation["time_limited"] |= evidence["state"] == "timed_out"
        for line in raw.split(b"\n"):
            if time.monotonic() >= deadline:
                evidence["state"] = "partial"
                observation["time_limited"] = True
                break
            event = _log_event(line, host)
            if event is not None:
                observation["counts"][event["kind"]] += 1
                events.append(event)
    states = [value["state"] for value in observation["sources"].values()]
    if all(state == "missing" for state in states):
        observation["state"] = "missing"
    elif "sampled" in states or "partial" in states:
        observation["state"] = "sampled" if states[0] == "sampled" and all(
            state in {"sampled", "missing"} for state in states
        ) else "partial"
    observation["events_truncated"] = len(events) > MAX_LOG_EVENTS
    observation["events"] = sorted(events, key=lambda event: event["at"])[-MAX_LOG_EVENTS:]
    return observation


def _command(command: tuple[str, ...], deadline: float) -> tuple[int, str] | None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        result = subprocess.run(command, capture_output=True, check=False, timeout=remaining)
        # In particular, lsof exit1 also means inspection failure. Its empty
        # stdout proves no listener only when stderr is empty as well.
        if result.stderr or len(result.stdout) > MAX_JSON_BYTES:
            return None
        return result.returncode, result.stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return None


def capture(uid: int, status_path: Path, *, host: str | None = None) -> dict:
    """Sample once after a failed operation and before fixture cleanup."""
    started = time.monotonic()
    observed_at = time.time()
    deadline = started + SAMPLE_TIMEOUT
    sample: dict = {
        "observed_at": observed_at,
        "status": _status(status_path, observed_at),
        "daemon_log": _daemon_log(host, deadline),
        "ownership_record": "unavailable",
        "launchd": "unavailable",
        "listener": "unavailable",
    }
    paths = geph.geph_paths(Path(pwd.getpwuid(uid).pw_dir))
    record_pid = None
    try:
        record = _json_file(paths.ownership, owner=uid)
        record_pid = _integer(record.get("pid"))
        valid = bool(record_pid and record.get("uid") == uid
                     and record.get("launchd_label") == geph.GEPH_LABEL
                     and record.get("executable") == str(paths.executable)
                     and record.get("config") == str(paths.config))
        sample["ownership_record"] = "valid" if valid else "invalid"
        record_pid = record_pid if valid else None
    except (OSError, ValueError, TypeError):
        pass
    sample["record_pid"] = record_pid
    result = _command(("/bin/launchctl", "print", f"gui/{uid}/{geph.GEPH_LABEL}"), deadline)
    launchd_pid = None
    if result is not None:
        code, raw = result
        sample["launchd"] = "observed" if code == 0 else "query_failed"
        if code == 0:
            match = re.search(r"^\s*pid\s*=\s*(\d+)\s*$", raw, re.MULTILINE)
            launchd_pid = _integer(int(match[1])) if match else None
            match = re.search(r"^\s*state\s*=\s*([^\r\n]+)$", raw, re.MULTILINE)
            sample["launchd_state"] = _choice(match[1].strip() if match else None,
                                               {"running", "waiting", "not running", "spawn scheduled"})
            match = re.search(r"^\s*last exit code\s*=\s*(\d+)\s*$", raw, re.MULTILINE)
            sample["last_exit_code"] = _integer(int(match[1])) if match else None
    sample["launchd_pid"] = launchd_pid
    result = _command(("/usr/sbin/lsof", "-nP", "-t", f"-iTCP@127.0.0.1:{geph.GEPH_SOCKS_PORT}", "-sTCP:LISTEN"), deadline)
    listeners: list[int] | None = None
    if result is not None:
        code, raw = result
        lines = raw.splitlines()
        if code == 1 and not lines:
            listeners = []
        elif code == 0 and 0 < len(lines) <= 16 and all(re.fullmatch(r"[1-9][0-9]{0,9}", line) for line in lines):
            listeners = sorted({int(line) for line in lines})
        sample["listener"] = "present" if listeners else "absent" if listeners == [] else "unavailable"
    sample["listener_pids"] = listeners
    sample["record_matches_launchd"] = record_pid == launchd_pid if record_pid and launchd_pid else None
    sample["launchd_matches_listener"] = listeners == [launchd_pid] if launchd_pid and listeners is not None else None
    sample["elapsed_ms"] = max(0, round((time.monotonic() - started) * 1000))
    return sample

"""Passive, bounded failure evidence for the disposable live-site gate.

No probes, retries, settings, keychain access or process/service mutations.
This is diagnostic evidence, never a route-ownership or readiness authority.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import stat
import subprocess
import time
from pathlib import Path

import geph_owned_lifecycle_smoke as geph

MAX_JSON_BYTES = 64 * 1024
SAMPLE_TIMEOUT = 2.0


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


def _status(path: Path, now: float) -> dict:
    try:
        value = _json_file(path)
        if value.get("schema_version") != 2:
            raise ValueError("unsupported status schema")
        daemon = value["daemon"]
        backend = value["backends"]["geph"]
        recovery = value["recovery"]
        updated = daemon.get("updated_at")
        age = now - updated if type(updated) in (int, float) else None
        return {
            "state": "sampled",
            "daemon_pid": _integer(daemon.get("pid")),
            "daemon_state": _choice(daemon.get("state"), {"active", "dormant", "starting", "stopped"}),
            "status_age_ms": round(age * 1000) if age is not None and 0 <= age <= 86400 else None,
            "geph_state": _choice(backend.get("state"), {"up", "down", "off"}),
            "geph_owned": backend.get("owned") if type(backend.get("owned")) is bool else None,
            "port_conflict": backend.get("port_conflict") if type(backend.get("port_conflict")) is bool else None,
            "restart_recommended": backend.get("restart_recommended") if type(backend.get("restart_recommended")) is bool else None,
            "active_sessions": _integer(backend.get("active_sessions")),
            "recovery_state": _choice(recovery.get("state"), {"idle", "recovering", "waiting", "paused", "rearmed"}),
            "recovery_reason": _choice(recovery.get("reason"), {"", "owned_geph_restart_waiting_for_idle", "owned_geph_restart_pending", "resource_pressure"}),
        }
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {"state": "unavailable"}


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


def capture(uid: int, status_path: Path) -> dict:
    """Sample once after a failed operation and before fixture cleanup."""
    started = time.monotonic()
    observed_at = time.time()
    deadline = started + SAMPLE_TIMEOUT
    sample: dict = {
        "observed_at": observed_at,
        "status": _status(status_path, observed_at),
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

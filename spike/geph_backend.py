"""Owned Geph identity and LaunchAgent claim verification."""

import json
import os
import stat


MAX_OWNERSHIP_BYTES = 64 * 1024


def ownership_path(home, filename):
    if not home:
        return None
    return os.path.join(
        home,
        "Library",
        "Application Support",
        "dev.slipstream.tray",
        filename,
    )


def read_ownership(path):
    if not path:
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            return None
        if metadata.st_size < 0 or metadata.st_size > MAX_OWNERSHIP_BYTES:
            return None
        with os.fdopen(fd, encoding="utf-8") as handle:
            fd = -1
            value = json.load(handle)
    except (OSError, UnicodeError, ValueError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    return value if isinstance(value, dict) else None


def ownership_file_uid(path):
    try:
        metadata = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid <= 0:
        return None
    return metadata.st_uid


def owned_launch_target(state, owner_uid, launchd_label):
    if (
        not isinstance(state, dict)
        or isinstance(owner_uid, bool)
        or state.get("launchd_label") != launchd_label
    ):
        return None
    state_uid = state.get("uid")
    if isinstance(state_uid, bool):
        return None
    try:
        uid = int(state_uid)
        owner_uid = int(owner_uid)
    except (TypeError, ValueError):
        return None
    if uid <= 0 or uid != owner_uid:
        return None
    return f"gui/{uid}/{launchd_label}"


def listener_pid(runner, port):
    result = runner(
        "/usr/sbin/lsof",
        "-nP",
        f"-iTCP:{port}",
        "-sTCP:LISTEN",
        "-t",
    )
    if result.returncode != 0:
        return None
    try:
        pid = int(result.stdout.splitlines()[0].strip())
    except (IndexError, ValueError):
        return None
    return pid if pid > 0 else None


def process_command(runner, pid):
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return ""
    result = runner("/bin/ps", "-p", str(pid), "-o", "command=")
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def state_matches(state, listener_process_id, command):
    if (
        not isinstance(state, dict)
        or isinstance(listener_process_id, bool)
        or not isinstance(listener_process_id, int)
        or listener_process_id <= 0
    ):
        return False
    state_pid = state.get("pid")
    if isinstance(state_pid, bool):
        return False
    try:
        state_pid = int(state_pid)
    except (TypeError, ValueError):
        return False
    executable = state.get("executable")
    config = state.get("config")
    if (
        state_pid != listener_process_id
        or not isinstance(executable, str)
        or not executable
        or not isinstance(config, str)
        or not config
    ):
        return False
    return command.strip() == f"{executable} --config {config}"


def listener_owned(
    runner,
    port,
    state,
    listener_process_id=None,
    command=None,
):
    if listener_process_id is None:
        listener_process_id = listener_pid(runner, port)
    if command is None and listener_process_id:
        command = process_command(runner, listener_process_id)
    return state_matches(state, listener_process_id, command or "")

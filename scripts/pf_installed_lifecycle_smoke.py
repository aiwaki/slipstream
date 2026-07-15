#!/usr/bin/env python3
"""Disposable macOS install/reinstall/restart/uninstall qualification.

This script performs real privileged lifecycle operations. It refuses to run
outside GitHub Actions with an explicit opt-in environment variable, and it
never runs on a workstation installation. By default it tests the source
installer; ``--app-bundle`` also crashes and restarts the built tray while the
same installed daemon, fresh non-root HTTPS clients, clean-profile Chrome
processes, and fresh Safari automation processes remain healthy.
"""

from __future__ import annotations

import argparse
import errno
import http.client
import json
import os
import plistlib
import pwd
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

import pf_anchor_smoke as pf


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DAEMON = ROOT / "spike" / "tproxy.py"
INSTALL_DIR = Path("/usr/local/slipstream")
INSTALLED_PYTHON = INSTALL_DIR / "venv" / "bin" / "python3"
INSTALLED_DAEMON = INSTALL_DIR / "tproxy.py"
INSTALLED_GEPH_BACKEND = INSTALL_DIR / "geph_backend.py"
INSTALLED_PF_ADAPTER = INSTALL_DIR / "pf_adapter.py"
INSTALLED_PRIMES = INSTALL_DIR / "primes.py"
INSTALLED_ROUTING_POLICY = INSTALL_DIR / "routing_policy.py"
INSTALLED_ROUTING_RECOVERY = INSTALL_DIR / "routing_recovery.py"
INSTALLED_XBOX_DNS = INSTALL_DIR / "xbox_dns.py"
INSTALLED_FROZEN_DAEMON = INSTALL_DIR / "slipstreamd"
LAUNCHD_PLIST = Path("/Library/LaunchDaemons/dev.slipstream.tproxy.plist")
LAUNCHD_LABEL = "system/dev.slipstream.tproxy"
STATUS_PATH = Path("/var/run/slipstream.status")
PF_TOKEN_PATH = Path("/var/run/slipstream-pf.token")
TGWS_LINK_PATH = Path("/var/run/slipstream-tgws.link")
LOG_PATH = Path("/var/log/slipstream.log")
SENTINEL_TARGET_PORT = 18444
SENTINEL_PROXY_PORT = 19444
STOP_MARKER = b"__stop__"
TOKEN_RE = re.compile(r"Token\s*:\s*(\d+)", re.IGNORECASE)
RUNTIME_REARM_SIGNAL = signal.SIGUSR1
QUALIFICATION_WAKE_GAP_SECONDS = 6.0
WAKE_SUSPEND_SECONDS = 8.0
LIFECYCLE_SOAK_CYCLES = 2
HTTPS_PROBE_URL = "https://github.com/robots.txt"
HTTPS_PROBE_MIN_BYTES = 32
CHROME_EXECUTABLE = Path(
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)
CHROME_PROBE_MIN_BYTES = 32
CHROME_PROBE_MARKER = b"User-agent:"
CHROME_PAGE_TIMEOUT_MS = 15_000
CHROME_PROBE_TIMEOUT = 45
CHROME_CAPTURE_LIMIT = 1_048_576
CHROME_PROCESS_STOP_TIMEOUT = 2
CHROME_SIGNAL_PERMISSION_EXIT = 4
CHROME_PID_SIGNAL_HELPER = """\
import os
import sys

expected_pgid = int(sys.argv[1])
signal_number = int(sys.argv[2])
denied = []
for raw_pid in sys.argv[3:]:
    pid = int(raw_pid)
    try:
        if os.getpgid(pid) != expected_pgid:
            continue
        os.kill(pid, signal_number)
    except ProcessLookupError:
        continue
    except PermissionError as exc:
        denied.append(f"pid={pid}: {exc}")
if denied:
    print("; ".join(denied), file=sys.stderr)
    raise SystemExit(4)
"""
SAFARI_PROBE_MIN_BYTES = 32
SAFARI_PROBE_MARKER = "User-agent:"
SAFARI_TCP_PROTOCOLS = frozenset(("h2", "http/1.1"))
SAFARI_COMMAND_TIMEOUT = 30
SAFARI_EXECUTABLE = Path("/Applications/Safari.app/Contents/MacOS/Safari")
SAFARI_PROCESS_NAME = "Safari"
SAFARI_PROCESS_START_TIMEOUT = 10.0
SAFARI_PROCESS_STOP_TIMEOUT = 3.0
WEBDRIVER_RESPONSE_LIMIT = 1_048_576
TRAY_START_TIMEOUT = 15.0


class LifecycleError(RuntimeError):
    """A lifecycle safety condition or assertion failed."""


@dataclass(frozen=True)
class ChromeProcessGroupMember:
    pid: int
    uid: int
    state: str
    executable: str


@dataclass(frozen=True)
class ChromeCapture:
    loaded: bool
    timed_out: bool
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class LifecycleTarget:
    name: str
    install_command: tuple[str, ...]
    uninstall_command: tuple[str, ...]
    installed_program_prefix: tuple[str, ...]
    required_installed_paths: tuple[Path, ...]
    tray_executable: Path | None = None


def script_target() -> LifecycleTarget:
    return LifecycleTarget(
        name="script",
        install_command=(sys.executable, str(SOURCE_DAEMON), "--install"),
        uninstall_command=(
            str(INSTALLED_PYTHON),
            str(INSTALLED_DAEMON),
            "--uninstall",
        ),
        installed_program_prefix=(str(INSTALLED_PYTHON), str(INSTALLED_DAEMON)),
        required_installed_paths=(
            INSTALLED_PYTHON,
            INSTALLED_DAEMON,
            INSTALLED_GEPH_BACKEND,
            INSTALLED_PF_ADAPTER,
            INSTALLED_PRIMES,
            INSTALLED_ROUTING_POLICY,
            INSTALLED_ROUTING_RECOVERY,
            INSTALLED_XBOX_DNS,
        ),
    )


def packaged_app_target(app_bundle: Path) -> LifecycleTarget:
    try:
        app_bundle = app_bundle.expanduser().resolve(strict=True)
    except OSError as exc:
        raise LifecycleError(f"packaged app does not exist: {app_bundle}") from exc
    if not app_bundle.is_dir() or app_bundle.suffix != ".app":
        raise LifecycleError(f"packaged lifecycle target must be a .app: {app_bundle}")
    if app_bundle == INSTALL_DIR or INSTALL_DIR in app_bundle.parents:
        raise LifecycleError("packaged lifecycle source cannot be inside the install dir")

    daemon = app_bundle / "Contents" / "Resources" / "slipstreamd" / "slipstreamd"
    if not daemon.is_file() or not os.access(daemon, os.X_OK):
        raise LifecycleError(f"packaged app has no executable frozen daemon: {daemon}")
    tray = app_bundle / "Contents" / "MacOS" / "slipstream"
    if not tray.is_file() or not os.access(tray, os.X_OK):
        raise LifecycleError(f"packaged app has no executable tray: {tray}")

    return LifecycleTarget(
        name="packaged-app",
        install_command=(str(daemon), "--install"),
        uninstall_command=(str(INSTALLED_FROZEN_DAEMON), "--uninstall"),
        installed_program_prefix=(str(INSTALLED_FROZEN_DAEMON),),
        required_installed_paths=(INSTALLED_FROZEN_DAEMON,),
        tray_executable=tray,
    )


def validate_system_command(
    command: Sequence[str],
    target: LifecycleTarget | None = None,
) -> None:
    target = target or script_target()
    command = tuple(map(str, command))
    allowed = {
        target.install_command,
        target.uninstall_command,
        ("/bin/launchctl", "bootout", "system", str(LAUNCHD_PLIST)),
        ("/bin/launchctl", "bootstrap", "system", str(LAUNCHD_PLIST)),
        ("/bin/launchctl", "kickstart", "-k", LAUNCHD_LABEL),
    }
    if command not in allowed:
        raise LifecycleError("unsupported lifecycle command: " + " ".join(command))


class SystemRunner:
    def __init__(self, target: LifecycleTarget | None = None) -> None:
        self.target = target or script_target()
        self.commands: list[tuple[str, ...]] = []

    def run(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout: int = 180,
    ) -> subprocess.CompletedProcess[str]:
        command = tuple(map(str, command))
        validate_system_command(command, self.target)
        self.commands.append(command)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            output = (result.stdout + "\n" + result.stderr).strip().splitlines()[-30:]
            raise LifecycleError(
                f"command failed ({result.returncode}): {' '.join(command)}\n"
                + "\n".join(output)
            )
        return result

    def audit_log(self) -> list[str]:
        return [" ".join(command) for command in self.commands]


class PersistentSentinelConnection:
    def __init__(self, target_port: int, proxy_port: int, uid: int, gid: int) -> None:
        self.target_port = target_port
        self.proxy_port = proxy_port
        self.uid = uid
        self.gid = gid
        self.connection: socket.socket | None = None
        self.child_pid: int | None = None
        self.child_error_fd: int | None = None
        self.counter = 0

    def start(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(6)
        listener.bind(("127.0.0.1", self.proxy_port))
        listener.listen(1)
        error_read, error_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                listener.close()
                os.close(error_read)
                os.setgroups([])
                os.setgid(self.gid)
                os.setuid(self.uid)
                with socket.create_connection(
                    (pf.TEST_DESTINATION, self.target_port), timeout=5
                ) as client:
                    # launchd restart can legitimately take more than ten
                    # seconds. Once connected, wait indefinitely so only a real
                    # EOF/error (or the explicit STOP marker) ends the sentinel.
                    client.settimeout(None)
                    while True:
                        data = client.recv(4096)
                        if not data or data == STOP_MARKER:
                            break
                        client.sendall(data)
                os._exit(0)
            except BaseException as exc:
                try:
                    os.write(error_write, repr(exc).encode("utf-8", errors="replace")[:1000])
                except OSError:
                    pass
                os._exit(3)

        os.close(error_write)
        os.set_blocking(error_read, False)
        self.child_error_fd = error_read
        self.child_pid = pid
        try:
            connection, _ = listener.accept()
            connection.settimeout(6)
            self.connection = connection
        except BaseException:
            self._stop_child()
            raise
        finally:
            listener.close()
        self.check("connected")

    def check(self, label: str) -> None:
        if self.connection is None:
            raise LifecycleError("sentinel connection is not open")
        self.counter += 1
        payload = f"sentinel:{self.counter}:{label}\n".encode("ascii")
        try:
            self.connection.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                chunk = self.connection.recv(len(payload) - len(received))
                if not chunk:
                    break
                received.extend(chunk)
        except OSError as exc:
            raise LifecycleError(f"sentinel connection broke after {label}") from exc
        if bytes(received) != payload:
            child = "running"
            if self.child_pid is not None:
                pid, status = os.waitpid(self.child_pid, os.WNOHANG)
                if pid:
                    self.child_pid = None
                    child = f"exited:{os.waitstatus_to_exitcode(status)}"
            detail = b""
            if self.child_error_fd is not None:
                try:
                    detail = os.read(self.child_error_fd, 1000)
                except BlockingIOError:
                    pass
            raise LifecycleError(
                f"sentinel echo mismatch after {label}; "
                f"received={bytes(received)!r}; child={child}; detail={detail!r}"
            )

    def _stop_child(self) -> None:
        if self.child_pid is None:
            return
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            pid, _ = os.waitpid(self.child_pid, os.WNOHANG)
            if pid:
                self.child_pid = None
                return
            time.sleep(0.05)
        try:
            os.kill(self.child_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.waitpid(self.child_pid, 0)
        self.child_pid = None

    def close(self) -> None:
        if self.connection is not None:
            try:
                self.connection.sendall(STOP_MARKER)
            except OSError:
                pass
            self.connection.close()
            self.connection = None
        self._stop_child()
        if self.child_error_fd is not None:
            os.close(self.child_error_fd)
            self.child_error_fd = None


def _require_disposable_ci() -> None:
    expected = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
    }
    missing = [name for name, value in expected.items() if os.environ.get(name) != value]
    if missing:
        raise LifecycleError(
            "installed lifecycle smoke is restricted to disposable GitHub Actions: "
            + ", ".join(missing)
        )
    if os.geteuid() != 0:
        raise LifecycleError("installed lifecycle smoke requires sudo")


def _read_status() -> dict | None:
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _daemon_status(status: dict | None) -> dict | None:
    if not isinstance(status, dict):
        return None
    if status.get("schema_version") == 2:
        daemon = status.get("daemon")
        return daemon if isinstance(daemon, dict) else None
    return status


def _recovery_status(status: dict | None) -> dict | None:
    if not isinstance(status, dict) or status.get("schema_version") != 2:
        return None
    recovery = status.get("recovery")
    return recovery if isinstance(recovery, dict) else None


def _wait_for_status(
    expected: str,
    *,
    previous_pid: int | None = None,
    timeout: float = 60,
) -> dict:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = _read_status()
        daemon = _daemon_status(last)
        if daemon and daemon.get("state") == expected:
            pid = int(daemon.get("pid") or 0)
            updated_at = daemon.get("updated_at", daemon.get("ts", 0))
            fresh = time.time() - float(updated_at or 0) < 15
            changed = previous_pid is None or (pid and pid != previous_pid)
            if fresh and changed:
                return daemon
        time.sleep(0.5)
    raise LifecycleError(f"daemon did not reach {expected}; last status={last!r}")


def _wait_for_same_daemon(
    expected: str,
    *,
    expected_pid: int,
    updated_after: float,
    timeout: float = 20,
) -> dict:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = _read_status()
        daemon = _daemon_status(last)
        if daemon:
            pid = int(daemon.get("pid") or 0)
            updated_at = float(daemon.get("updated_at", daemon.get("ts", 0)) or 0)
            if (
                daemon.get("state") == expected
                and pid == expected_pid
                and updated_at > updated_after
                and time.time() - updated_at < 15
            ):
                return daemon
        time.sleep(0.2)
    raise LifecycleError(
        f"daemon {expected_pid} stopped publishing {expected}; last status={last!r}"
    )


def _wait_for_rearm(
    expected_reason: str,
    *,
    expected_pid: int,
    previous_count: int,
    timeout: float = 20,
) -> dict:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = _read_status()
        daemon = _daemon_status(last)
        recovery = _recovery_status(last)
        if daemon and recovery:
            pid = int(daemon.get("pid") or 0)
            updated_at = float(daemon.get("updated_at", daemon.get("ts", 0)) or 0)
            count = int(recovery.get("count") or 0)
            if (
                daemon.get("state") == "active"
                and pid == expected_pid
                and time.time() - updated_at < 15
                and count > previous_count
                and recovery.get("last_action") == expected_reason
            ):
                return last
        time.sleep(0.2)
    raise LifecycleError(
        f"daemon did not record {expected_reason} rearm; last status={last!r}"
    )


def _process_command_for_pid(pid: int) -> str:
    result = subprocess.run(
        ("/bin/ps", "-p", str(pid), "-o", "command="),
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _process_identity_for_pid(pid: int) -> tuple[int, str] | None:
    result = subprocess.run(
        ("/bin/ps", "-p", str(pid), "-o", "uid=", "-o", "command="),
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    line = result.stdout.strip() if result.returncode == 0 else ""
    parts = line.split(None, 1)
    if len(parts) != 2:
        return None
    try:
        return int(parts[0]), parts[1]
    except ValueError:
        return None


def _assert_owned_tray_pid(executable: Path, pid: int, uid: int) -> None:
    identity = _process_identity_for_pid(pid)
    try:
        expected = str(executable.resolve(strict=True))
    except OSError as exc:
        raise LifecycleError(f"packaged tray executable disappeared: {executable}") from exc
    owned = False
    if identity is not None:
        actual_uid, command = identity
        owned = actual_uid == uid and (
            command == expected or command.startswith(expected + " ")
        )
    if not owned:
        raise LifecycleError(
            f"refusing to signal unowned tray pid {pid}: identity={identity!r}"
        )


def _user_environment(uid: int) -> tuple[dict[str, str], Path]:
    try:
        account = pwd.getpwuid(uid)
    except KeyError as exc:
        raise LifecycleError(f"cannot resolve original user id {uid}") from exc
    environment = {
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": os.environ.get("LANG", "en_US.UTF-8"),
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
    }
    if os.environ.get("TMPDIR"):
        environment["TMPDIR"] = os.environ["TMPDIR"]
    return environment, Path(account.pw_dir)


def _user_supplementary_groups(uid: int, gid: int) -> tuple[int, ...]:
    try:
        account = pwd.getpwuid(uid)
        groups = os.getgrouplist(account.pw_name, gid)
    except (KeyError, OSError) as exc:
        raise LifecycleError(f"cannot resolve original user groups for {uid}") from exc
    return tuple(sorted(group for group in set(groups) if group != gid))


class PackagedTrayProcess:
    def __init__(self, executable: Path, uid: int, gid: int) -> None:
        self.executable = executable.resolve(strict=True)
        self.uid = uid
        self.gid = gid
        self.process: subprocess.Popen | None = None
        self.log = None

    def _log_tail(self) -> str:
        if self.log is None:
            return ""
        self.log.flush()
        self.log.seek(0)
        return self.log.read().decode("utf-8", errors="replace")[-2000:]

    def start(self) -> int:
        if self.process is not None:
            raise LifecycleError("packaged tray is already running")
        environment, home = _user_environment(self.uid)
        self.log = tempfile.TemporaryFile()
        self.process = subprocess.Popen(
            (str(self.executable),),
            cwd=home,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            user=self.uid,
            group=self.gid,
            extra_groups=(),
        )
        deadline = time.monotonic() + TRAY_START_TIMEOUT
        owned_since = None
        last_error = ""
        while time.monotonic() < deadline:
            returncode = self.process.poll()
            if returncode is not None:
                detail = self._log_tail()
                self._close_handles()
                raise LifecycleError(
                    f"packaged tray exited during startup ({returncode}): {detail}"
                )
            try:
                _assert_owned_tray_pid(self.executable, self.process.pid, self.uid)
                owned_since = owned_since or time.monotonic()
                if time.monotonic() - owned_since >= 2:
                    return self.process.pid
            except LifecycleError as exc:
                last_error = str(exc)
                owned_since = None
            time.sleep(0.2)
        detail = self._log_tail()
        self.stop()
        raise LifecycleError(
            f"packaged tray did not remain active: {last_error}; log={detail}"
        )

    def crash(self) -> None:
        if self.process is None:
            raise LifecycleError("packaged tray is not running")
        _assert_owned_tray_pid(self.executable, self.process.pid, self.uid)
        os.kill(self.process.pid, signal.SIGKILL)
        self.process.wait(timeout=5)
        self._close_handles()

    def stop(self) -> None:
        if self.process is None:
            self._close_handles()
            return
        if self.process.poll() is None:
            _assert_owned_tray_pid(self.executable, self.process.pid, self.uid)
            os.kill(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _assert_owned_tray_pid(self.executable, self.process.pid, self.uid)
                os.kill(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        self._close_handles()

    def _close_handles(self) -> None:
        self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None


def _probe_suffix(label: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", label.lower()).strip("-") or "probe"


def _https_probe_command(label: str) -> tuple[str, ...]:
    suffix = _probe_suffix(label)
    return (
        "/usr/bin/curl",
        "--silent",
        "--show-error",
        "--fail",
        "--location",
        "--ipv4",
        "--http1.1",
        "--noproxy",
        "*",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--header",
        "Cache-Control: no-cache",
        f"{HTTPS_PROBE_URL}?slipstream-lifecycle={suffix}",
    )


def _run_https_probe(uid: int, gid: int, label: str) -> int:
    environment, home = _user_environment(uid)
    result = subprocess.run(
        _https_probe_command(label),
        cwd=home,
        env=environment,
        capture_output=True,
        check=False,
        timeout=35,
        user=uid,
        group=gid,
        extra_groups=(),
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")[-1000:]
        raise LifecycleError(f"HTTPS client probe {label} failed: {detail}")
    if len(result.stdout) < HTTPS_PROBE_MIN_BYTES:
        raise LifecycleError(
            f"HTTPS client probe {label} returned only {len(result.stdout)} bytes"
        )
    return len(result.stdout)


def _chrome_probe_command(
    executable: Path,
    profile_dir: Path,
    label: str,
) -> tuple[str, ...]:
    suffix = _probe_suffix(label)
    return (
        str(executable),
        "--headless",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-features=MediaRouter,OptimizationHints,Translate",
        "--disable-quic",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-default-browser-check",
        "--no-first-run",
        "--no-proxy-server",
        "--password-store=basic",
        f"--user-data-dir={profile_dir}",
        f"--timeout={CHROME_PAGE_TIMEOUT_MS}",
        "--dump-dom",
        f"{HTTPS_PROBE_URL}?slipstream-chrome={suffix}",
    )


@contextmanager
def _chrome_operation(operation: str) -> Iterator[None]:
    try:
        yield
    except ProcessLookupError:
        raise
    except LifecycleError:
        raise
    except OSError as exc:
        raise LifecycleError(
            f"Chrome operation {operation} failed: {type(exc).__name__}: {exc}"
        ) from exc


def _read_capture(capture, *, tail: bool = False) -> bytes:
    operation = "capture-read-tail" if tail else "capture-read"
    with _chrome_operation(operation):
        size = os.fstat(capture.fileno()).st_size
        length = min(size, CHROME_CAPTURE_LIMIT)
        offset = max(0, size - length) if tail else 0
        return os.pread(capture.fileno(), length, offset)


def _chrome_process_group_members(
    process_group: int,
) -> tuple[ChromeProcessGroupMember, ...]:
    result = subprocess.run(
        ("/bin/ps", "-axo", "pid=,pgid=,uid=,stat=,comm="),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=CHROME_PROCESS_STOP_TIMEOUT,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")[-1000:].strip()
        raise LifecycleError(
            f"Chrome process-group inspection failed ({result.returncode}): {detail}"
        )

    members = []
    for raw_line in result.stdout.decode("utf-8", errors="replace").splitlines():
        fields = raw_line.strip().split(None, 4)
        if len(fields) != 5:
            if raw_line.strip():
                raise LifecycleError(
                    f"invalid Chrome process-group row: {raw_line!r}"
                )
            continue
        try:
            pid = int(fields[0])
            observed_group = int(fields[1])
            uid = int(fields[2])
        except ValueError as exc:
            raise LifecycleError(
                f"invalid Chrome process-group row: {raw_line!r}"
            ) from exc
        if observed_group == process_group:
            members.append(
                ChromeProcessGroupMember(
                    pid=pid,
                    uid=uid,
                    state=fields[3],
                    executable=fields[4],
                )
            )
    return tuple(sorted(members, key=lambda member: member.pid))


def _signal_owned_chrome_processes(
    process_group: int,
    signal_number: int,
    *,
    uid: int | None,
    gid: int | None,
    supplementary_groups: tuple[int, ...],
) -> bool:
    identity = {}
    if uid is None:
        uid = os.geteuid()
    else:
        if gid is None:
            raise LifecycleError("Chrome signal helper requires a group ID")
        identity = {
            "user": uid,
            "group": gid,
            "extra_groups": supplementary_groups,
        }

    members = _chrome_process_group_members(process_group)
    owned_pids = tuple(member.pid for member in members if member.uid == uid)
    if not owned_pids:
        return False

    result = subprocess.run(
        (
            sys.executable,
            "-I",
            "-c",
            CHROME_PID_SIGNAL_HELPER,
            str(process_group),
            str(signal_number),
            *(str(pid) for pid in owned_pids),
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=CHROME_PROCESS_STOP_TIMEOUT,
        **identity,
    )
    if result.returncode == 0:
        return True

    detail = result.stderr.decode("utf-8", errors="replace")[-1000:].strip()
    message = (
        f"owned-PID signal helper exited {result.returncode}"
        f" for pgid={process_group} signal={signal_number} pids={owned_pids}"
    )
    if detail:
        message = f"{message}: {detail}"
    if result.returncode == CHROME_SIGNAL_PERMISSION_EXIT:
        raise PermissionError(errno.EPERM, message)
    raise OSError(errno.EIO, message)


def _stop_owned_chrome_process_group(
    process: subprocess.Popen,
    process_group: int,
    *,
    uid: int | None = None,
    gid: int | None = None,
    supplementary_groups: tuple[int, ...] = (),
) -> None:
    if process_group != process.pid:
        with _chrome_operation("process-leader-kill-after-group-mismatch"):
            process.kill()
        with _chrome_operation("process-leader-wait-after-group-mismatch"):
            process.wait(timeout=CHROME_PROCESS_STOP_TIMEOUT)
        raise LifecycleError(
            "Chrome process group mismatch: "
            f"pid={process.pid} pgid={process_group}"
        )

    with _chrome_operation("process-group-term"):
        _signal_owned_chrome_processes(
            process_group,
            signal.SIGTERM,
            uid=uid,
            gid=gid,
            supplementary_groups=supplementary_groups,
        )
    try:
        with _chrome_operation("process-leader-wait-after-term"):
            process.wait(timeout=CHROME_PROCESS_STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        with _chrome_operation("process-group-kill-after-timeout"):
            _signal_owned_chrome_processes(
                process_group,
                signal.SIGKILL,
                uid=uid,
                gid=gid,
                supplementary_groups=supplementary_groups,
            )
        with _chrome_operation("process-leader-wait-after-kill"):
            process.wait(timeout=CHROME_PROCESS_STOP_TIMEOUT)
    else:
        # Chrome helpers inherit the dedicated process group. The browser can
        # exit before a helper that still owns a capture descriptor.
        with _chrome_operation("process-group-kill-after-leader-exit"):
            _signal_owned_chrome_processes(
                process_group,
                signal.SIGKILL,
                uid=uid,
                gid=gid,
                supplementary_groups=supplementary_groups,
            )


def _capture_chrome_output(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    uid: int | None,
    gid: int | None,
    supplementary_groups: tuple[int, ...],
    timeout: float = CHROME_PROBE_TIMEOUT,
) -> ChromeCapture:
    with _chrome_operation("capture-files-create"):
        stdout_capture = tempfile.TemporaryFile()
        stderr_capture = tempfile.TemporaryFile()
    process = None
    process_group = None
    loaded = False
    timed_out = False
    try:
        identity = {}
        if uid is not None:
            identity = {
                "user": uid,
                "group": gid,
                "extra_groups": supplementary_groups,
            }
        with _chrome_operation("spawn"):
            process = subprocess.Popen(
                tuple(command),
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout_capture,
                stderr=stderr_capture,
                start_new_session=True,
                **identity,
            )
        process_group = process.pid
        try:
            with _chrome_operation("process-group-verify"):
                actual_process_group = os.getpgid(process.pid)
        except ProcessLookupError:
            process.wait(timeout=CHROME_PROCESS_STOP_TIMEOUT)
        else:
            if actual_process_group != process_group:
                _stop_owned_chrome_process_group(
                    process,
                    actual_process_group,
                    uid=uid,
                    gid=gid,
                    supplementary_groups=supplementary_groups,
                )
        deadline = time.monotonic() + timeout
        while True:
            stdout = _read_capture(stdout_capture)
            loaded = (
                len(stdout) >= CHROME_PROBE_MIN_BYTES
                and CHROME_PROBE_MARKER in stdout
            )
            if loaded:
                break
            if process.poll() is not None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            time.sleep(min(0.1, remaining))
    finally:
        try:
            if process is not None and process_group is not None:
                _stop_owned_chrome_process_group(
                    process,
                    process_group,
                    uid=uid,
                    gid=gid,
                    supplementary_groups=supplementary_groups,
                )
        finally:
            stdout = _read_capture(stdout_capture)
            stderr = _read_capture(stderr_capture, tail=True)
            with _chrome_operation("capture-files-close"):
                stdout_capture.close()
                stderr_capture.close()

    if process is None:
        raise LifecycleError("Chrome process did not start")
    loaded = (
        len(stdout) >= CHROME_PROBE_MIN_BYTES
        and CHROME_PROBE_MARKER in stdout
    )
    return ChromeCapture(
        loaded=loaded,
        timed_out=timed_out,
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _run_chrome_probe(
    uid: int,
    gid: int,
    label: str,
    executable: Path = CHROME_EXECUTABLE,
) -> int:
    with _chrome_operation("executable-preflight"):
        try:
            executable = executable.resolve(strict=True)
        except FileNotFoundError as exc:
            raise LifecycleError(
                f"Chrome executable is unavailable: {executable}"
            ) from exc
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise LifecycleError(f"Chrome executable is not runnable: {executable}")

    with _chrome_operation("user-identity"):
        environment, home = _user_environment(uid)
        supplementary_groups = _user_supplementary_groups(uid, gid)
    with _chrome_operation("profile-create"):
        profile_dir = Path(tempfile.mkdtemp(prefix="slipstream-chrome-"))
    try:
        with _chrome_operation("profile-ownership"):
            os.chown(profile_dir, uid, gid)
            profile_dir.chmod(0o700)
        result = _capture_chrome_output(
            _chrome_probe_command(executable, profile_dir, label),
            cwd=home,
            environment=environment,
            timeout=CHROME_PROBE_TIMEOUT,
            uid=uid,
            gid=gid,
            supplementary_groups=supplementary_groups,
        )
    finally:
        shutil.rmtree(profile_dir, ignore_errors=True)

    if result.loaded:
        return len(result.stdout)
    detail = (result.stdout + b"\n" + result.stderr).decode(
        "utf-8", errors="replace"
    )[-2000:]
    if result.timed_out:
        raise LifecycleError(f"Chrome probe {label} timed out: {detail}")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")[-2000:]
        raise LifecycleError(f"Chrome probe {label} failed: {detail}")
    if len(result.stdout) < CHROME_PROBE_MIN_BYTES:
        raise LifecycleError(
            f"Chrome probe {label} returned only {len(result.stdout)} bytes"
        )
    if CHROME_PROBE_MARKER not in result.stdout:
        detail = result.stdout.decode("utf-8", errors="replace")[-1000:]
        raise LifecycleError(
            f"Chrome probe {label} did not load the expected page: {detail}"
        )
    return len(result.stdout)


def _validated_safaridriver_url(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise LifecycleError("SafariDriver URL has an invalid port") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or not 1 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise LifecycleError(
            "SafariDriver URL must be an uncredentialed http://127.0.0.1:<port> endpoint"
        )
    return f"http://127.0.0.1:{port}"


def _webdriver_request(
    base_url: str,
    method: str,
    path: str,
    payload: dict | None = None,
    *,
    timeout: float = SAFARI_COMMAND_TIMEOUT,
) -> dict:
    base_url = _validated_safaridriver_url(base_url)
    if base_url is None:
        raise LifecycleError("SafariDriver URL is required")
    port = urllib.parse.urlsplit(base_url).port
    if port is None:
        raise LifecycleError("SafariDriver URL has no port")
    if not path.startswith("/") or ".." in path:
        raise LifecycleError(f"invalid WebDriver path: {path!r}")
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        body = response.read(WEBDRIVER_RESPONSE_LIMIT + 1)
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise LifecycleError(
            f"SafariDriver {method} {path} failed: {exc}"
        ) from exc
    finally:
        connection.close()
    if len(body) > WEBDRIVER_RESPONSE_LIMIT:
        raise LifecycleError(f"SafariDriver {method} {path} response is too large")
    if response.status >= 400:
        detail = body[:4000].decode("utf-8", errors="replace")
        raise LifecycleError(
            f"SafariDriver {method} {path} returned HTTP {response.status}: {detail}"
        )
    try:
        result = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        detail = body[:1000].decode("utf-8", errors="replace")
        raise LifecycleError(
            f"SafariDriver {method} {path} returned invalid JSON: {detail}"
        ) from exc
    if not isinstance(result, dict):
        raise LifecycleError(f"SafariDriver {method} {path} returned a non-object")
    value = result.get("value")
    if isinstance(value, dict) and value.get("error"):
        raise LifecycleError(
            f"SafariDriver {method} {path} failed: "
            f"{value.get('error')}: {value.get('message', '')}"
        )
    return result


def _assert_safaridriver_ready(base_url: str) -> None:
    result = _webdriver_request(base_url, "GET", "/status", timeout=5)
    value = result.get("value")
    if not isinstance(value, dict) or value.get("ready") is not True:
        raise LifecycleError(f"SafariDriver is not ready: {result!r}")


def _safari_pid_candidates() -> tuple[int, ...]:
    result = subprocess.run(
        ("/usr/bin/pgrep", "-x", SAFARI_PROCESS_NAME),
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    if result.returncode == 1:
        return ()
    if result.returncode != 0:
        detail = result.stderr.strip()[-1000:]
        raise LifecycleError(f"cannot inspect Safari processes: {detail}")
    pids = []
    for line in result.stdout.splitlines():
        try:
            pid = int(line.strip())
        except ValueError as exc:
            raise LifecycleError(f"invalid Safari pid from pgrep: {line!r}") from exc
        if pid > 0:
            pids.append(pid)
    return tuple(sorted(set(pids)))


def _safari_process_identity_for_pid(pid: int) -> tuple[int, str, str] | None:
    result = subprocess.run(
        ("/bin/ps", "-p", str(pid), "-o", "uid=", "-o", "stat=", "-o", "command="),
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    line = result.stdout.strip() if result.returncode == 0 else ""
    parts = line.split(None, 2)
    if len(parts) != 3:
        return None
    try:
        return int(parts[0]), parts[1], parts[2]
    except ValueError:
        return None


def _safari_identity_is_stopped(
    identity: tuple[int, str, str] | None,
    uid: int,
) -> bool:
    if identity is None:
        return False
    actual_uid, state, _command = identity
    return actual_uid == uid and state.startswith("Z")


def _safari_identity_matches(
    identity: tuple[int, str, str] | None,
    uid: int,
) -> bool:
    if identity is None:
        return False
    actual_uid, _state, command = identity
    try:
        arguments = tuple(shlex.split(command))
    except ValueError:
        arguments = ()
    return bool(
        actual_uid == uid
        and arguments
        and _same_executable(arguments[0], str(SAFARI_EXECUTABLE))
    )


def _owned_safari_pids(uid: int) -> tuple[int, ...]:
    if not SAFARI_EXECUTABLE.is_file() or not os.access(SAFARI_EXECUTABLE, os.X_OK):
        raise LifecycleError(f"Safari executable is unavailable: {SAFARI_EXECUTABLE}")
    owned = []
    conflicts = []
    for pid in _safari_pid_candidates():
        identity = _safari_process_identity_for_pid(pid)
        if identity is None:
            continue
        if _safari_identity_is_stopped(identity, uid):
            continue
        if _safari_identity_matches(identity, uid):
            owned.append(pid)
        else:
            conflicts.append((pid, *identity))
    if conflicts:
        raise LifecycleError(
            f"refusing Safari process control with unexpected identities: {conflicts!r}"
        )
    return tuple(owned)


def _assert_no_safari_process(uid: int, label: str) -> None:
    pids = _owned_safari_pids(uid)
    if pids:
        raise LifecycleError(
            f"Safari probe {label} requires a fresh process; already running: {pids}"
        )


def _wait_for_safari_process(uid: int, label: str) -> int:
    deadline = time.monotonic() + SAFARI_PROCESS_START_TIMEOUT
    while time.monotonic() < deadline:
        pids = _owned_safari_pids(uid)
        if len(pids) == 1:
            return pids[0]
        if len(pids) > 1:
            raise LifecycleError(
                f"Safari probe {label} started multiple browser processes: {pids}"
            )
        time.sleep(0.1)
    raise LifecycleError(f"Safari probe {label} did not start Safari")


def _safari_pid_is_owned(pid: int, uid: int) -> bool:
    identity = _safari_process_identity_for_pid(pid)
    if identity is None:
        return False
    if _safari_identity_is_stopped(identity, uid):
        return False
    if not _safari_identity_matches(identity, uid):
        raise LifecycleError(
            f"refusing to signal unowned Safari pid {pid}: identity={identity!r}"
        )
    return True


def _stop_owned_safari_process(pid: int, uid: int, label: str) -> None:
    deadline = time.monotonic() + SAFARI_PROCESS_STOP_TIMEOUT
    while time.monotonic() < deadline:
        if not _safari_pid_is_owned(pid, uid):
            return
        time.sleep(0.1)

    for stop_signal in (signal.SIGTERM, signal.SIGKILL):
        if not _safari_pid_is_owned(pid, uid):
            return
        try:
            os.kill(pid, stop_signal)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + SAFARI_PROCESS_STOP_TIMEOUT
        while time.monotonic() < deadline:
            if not _safari_pid_is_owned(pid, uid):
                return
            time.sleep(0.1)
    raise LifecycleError(f"Safari probe {label} could not stop owned pid {pid}")


def _run_safari_probe(base_url: str, label: str, uid: int) -> int:
    session_id = None
    safari_pid = None
    failure = None
    size = 0
    try:
        _assert_no_safari_process(uid, label)
        created = _webdriver_request(
            base_url,
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "safari",
                        "pageLoadStrategy": "normal",
                    }
                }
            },
        )
        value = created.get("value")
        if isinstance(value, dict):
            session_id = value.get("sessionId")
        session_id = session_id or created.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise LifecycleError(
                f"SafariDriver did not return a session id: {created!r}"
            )
        safari_pid = _wait_for_safari_process(uid, label)
        encoded_session = urllib.parse.quote(session_id, safe="")
        _webdriver_request(
            base_url,
            "POST",
            f"/session/{encoded_session}/timeouts",
            {"pageLoad": 20_000, "script": 10_000},
        )
        suffix = _probe_suffix(label)
        _webdriver_request(
            base_url,
            "POST",
            f"/session/{encoded_session}/url",
            {"url": f"{HTTPS_PROBE_URL}?slipstream-safari={suffix}"},
        )
        source = _webdriver_request(
            base_url,
            "GET",
            f"/session/{encoded_session}/source",
        ).get("value")
        if not isinstance(source, str):
            raise LifecycleError("SafariDriver page source is not text")
        size = len(source.encode("utf-8"))
        if size < SAFARI_PROBE_MIN_BYTES:
            raise LifecycleError(
                f"Safari probe {label} returned only {size} bytes"
            )
        if SAFARI_PROBE_MARKER not in source:
            raise LifecycleError(
                f"Safari probe {label} did not load the expected page: {source[-1000:]}"
            )
        protocol = _webdriver_request(
            base_url,
            "POST",
            f"/session/{encoded_session}/execute/sync",
            {
                "script": (
                    "const entry = performance.getEntriesByType('navigation')[0]; "
                    "return entry ? entry.nextHopProtocol : '';"
                ),
                "args": [],
            },
        ).get("value")
        if protocol not in SAFARI_TCP_PROTOCOLS:
            raise LifecycleError(
                f"Safari probe {label} did not prove a TCP route: "
                f"nextHopProtocol={protocol!r}"
            )
    except BaseException as exc:
        failure = exc
    finally:
        cleanup_errors = []
        if session_id:
            encoded_session = urllib.parse.quote(session_id, safe="")
            try:
                _webdriver_request(
                    base_url,
                    "DELETE",
                    f"/session/{encoded_session}",
                    timeout=10,
                )
            except BaseException as exc:
                cleanup_errors.append(exc)
        if safari_pid is not None:
            try:
                _stop_owned_safari_process(safari_pid, uid, label)
            except BaseException as exc:
                cleanup_errors.append(exc)
        try:
            _assert_no_safari_process(uid, f"{label} cleanup")
        except BaseException as exc:
            cleanup_errors.append(exc)
        if cleanup_errors:
            cleanup_detail = "; ".join(str(error) for error in cleanup_errors)
            if failure is not None:
                raise LifecycleError(
                    f"{failure}; Safari cleanup failed: {cleanup_detail}"
                ) from failure
            raise LifecycleError(f"Safari cleanup failed: {cleanup_detail}")
    if failure is not None:
        raise failure
    return size


def _process_arguments_for_pid(pid: int) -> tuple[str, ...]:
    try:
        return tuple(shlex.split(_process_command_for_pid(pid)))
    except ValueError:
        return ()


def _same_executable(left: str, right: str) -> bool:
    if left == right:
        return True
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _assert_owned_daemon_pid(target: LifecycleTarget, pid: int) -> None:
    command = _process_command_for_pid(pid)
    try:
        arguments = tuple(shlex.split(command))
    except ValueError:
        arguments = ()
    expected = target.installed_program_prefix
    executable_matches = False
    if arguments and expected:
        executable_matches = _same_executable(arguments[0], expected[0])
        source_install = (
            len(expected) >= 2 and expected[1] == str(INSTALLED_DAEMON)
        )
        if source_install and not executable_matches:
            harness_arguments = _process_arguments_for_pid(os.getpid())
            executable_matches = bool(harness_arguments) and _same_executable(
                arguments[0], harness_arguments[0]
            )
    owned = (
        executable_matches
        and len(arguments) >= len(expected)
        and arguments[1:len(expected)] == expected[1:]
    )
    if not owned:
        raise LifecycleError(
            f"refusing to signal unowned pid {pid}: command={command!r}"
        )


def _signal_owned_daemon(
    target: LifecycleTarget,
    pid: int,
    signum: int,
) -> None:
    _assert_owned_daemon_pid(target, pid)
    try:
        os.kill(pid, signum)
    except ProcessLookupError as exc:
        raise LifecycleError(f"owned daemon pid {pid} disappeared") from exc


def _recovery_count(status: dict | None) -> int:
    recovery = _recovery_status(status)
    return int(recovery.get("count") or 0) if recovery else 0


def _daemon_updated_at(status: dict | None) -> float:
    daemon = _daemon_status(status)
    if not daemon:
        return 0.0
    return float(daemon.get("updated_at", daemon.get("ts", 0)) or 0)


def _wait_for_path(path: Path, *, present: bool, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() == present:
            return
        time.sleep(0.2)
    state = "appear" if present else "disappear"
    raise LifecycleError(f"{path} did not {state}")


def _patch_launchd_for_local_only(plist_path: Path) -> None:
    with plist_path.open("rb") as handle:
        data = plistlib.load(handle)
    environment = dict(data.get("EnvironmentVariables") or {})
    environment["SLIP_GEPH"] = "0"
    environment["SLIP_RUNTIME_WAKE_GAP_SECONDS"] = str(
        int(QUALIFICATION_WAKE_GAP_SECONDS)
    )
    data["EnvironmentVariables"] = environment
    arguments = list(data.get("ProgramArguments") or [])
    if "--no-voice" not in arguments:
        arguments.append("--no-voice")
    data["ProgramArguments"] = arguments
    fd, temporary = tempfile.mkstemp(prefix="slipstream-lifecycle-", suffix=".plist")
    try:
        with os.fdopen(fd, "wb") as handle:
            plistlib.dump(data, handle, sort_keys=True)
        os.chmod(temporary, 0o644)
        os.replace(temporary, plist_path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _acquire_test_pf_reference(runner: pf.PfctlRunner) -> str:
    result = runner.run("-E", check=True)
    match = TOKEN_RE.search(result.stdout + "\n" + result.stderr)
    if not match:
        raise LifecycleError("pfctl -E did not return a releasable token")
    return match.group(1)


def _release_pf_reference(runner: pf.PfctlRunner, token: str | None) -> None:
    if not token:
        return
    runner.run("-X", token, check=True)


def _sentinel_state_lines(runner: pf.PfctlRunner) -> tuple[str, ...]:
    states = runner.run("-s", "states", check=True).stdout
    return tuple(
        sorted(
            line.strip()
            for line in states.splitlines()
            if str(SENTINEL_TARGET_PORT) in line or str(SENTINEL_PROXY_PORT) in line
        )
    )


def _assert_sentinel_state(
    runner: pf.PfctlRunner,
    expected: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    lines = _sentinel_state_lines(runner)
    if not lines:
        info = runner.run("-s", "info", check=True).stdout
        references = runner.run("-s", "References", check=True).stdout
        reference_count = sum(
            1 for line in references.splitlines() if line.strip() and "TOKEN" not in line.upper()
        )
        enabled = "Status: Enabled" in info
        raise LifecycleError(
            "sentinel PF state disappeared; "
            f"pf_enabled={enabled}; reference_rows={reference_count}"
        )
    if expected is not None and lines != expected:
        raise LifecycleError(
            f"sentinel PF state changed; before={expected!r}; after={lines!r}"
        )
    return lines


def _daemon_pf_log_tail() -> tuple[str, ...]:
    try:
        lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ()
    selected = [
        line[-500:]
        for line in lines
        if any(word in line.lower() for word in (" pf ", "anchor", "legacy", "cleanup"))
    ]
    return tuple(selected[-20:])


def _lifecycle_failure(stage: str, exc: BaseException) -> LifecycleError:
    return LifecycleError(
        f"stage={stage}; {type(exc).__name__}: {exc}; "
        f"daemon_pf_log={_daemon_pf_log_tail()!r}"
    )


def _rule_has_port(rules: str, port: int) -> bool:
    return bool(re.search(rf"\bport\s*(?:=\s*)?{port}\b", rules))


def _assert_anchor_active(runner: pf.PfctlRunner) -> None:
    nat, rules = pf._anchor_snapshot(runner, pf.SLIPSTREAM_ANCHOR)
    if not _rule_has_port(nat, 443) or not _rule_has_port(nat, 1080) or "route-to" not in rules:
        raise LifecycleError(
            "installed daemon did not arm the production private anchor: "
            f"nat={nat!r}, rules={rules!r}"
        )


def _assert_private_raw_log(path: Path, expected_uid: int = 0) -> None:
    try:
        log_stat = path.lstat()
    except OSError as exc:
        raise LifecycleError(f"installed daemon log is unavailable: {exc}") from exc
    if not stat.S_ISREG(log_stat.st_mode):
        raise LifecycleError(f"installed daemon log is not a regular file: {path}")
    if stat.S_IMODE(log_stat.st_mode) != 0o600:
        raise LifecycleError(
            f"installed daemon log mode is not 0600: {stat.S_IMODE(log_stat.st_mode):04o}"
        )
    if log_stat.st_uid != expected_uid:
        raise LifecycleError(
            f"installed daemon log has unexpected owner: uid={log_stat.st_uid}"
        )


def _assert_installed_payload(target: LifecycleTarget) -> None:
    for path in target.required_installed_paths:
        if not path.is_file():
            raise LifecycleError(f"{target.name} install omitted required payload: {path}")
    if not os.access(target.required_installed_paths[0], os.X_OK):
        raise LifecycleError(
            f"{target.name} installed daemon is not executable: "
            f"{target.required_installed_paths[0]}"
        )

    _assert_private_raw_log(LOG_PATH)

    try:
        with LAUNCHD_PLIST.open("rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise LifecycleError(f"cannot read installed LaunchDaemon plist: {exc}") from exc
    arguments = tuple(map(str, data.get("ProgramArguments") or ()))
    expected = target.installed_program_prefix
    if arguments[: len(expected)] != expected:
        raise LifecycleError(
            f"{target.name} LaunchDaemon does not use the installed payload: "
            f"expected prefix={expected!r}, actual={arguments!r}"
        )


def _assert_clean_install_state(runner: pf.PfctlRunner) -> None:
    pf._assert_empty_anchor(runner, pf.SLIPSTREAM_ANCHOR)
    for path in (
        LAUNCHD_PLIST,
        STATUS_PATH,
        PF_TOKEN_PATH,
        TGWS_LINK_PATH,
        INSTALLED_DAEMON,
        INSTALLED_PRIMES,
        INSTALLED_FROZEN_DAEMON,
    ):
        if path.exists():
            raise LifecycleError(f"installed lifecycle residue remains: {path}")
    if INSTALL_DIR.exists() and any(INSTALL_DIR.iterdir()):
        raise LifecycleError(f"installed lifecycle residue remains: {INSTALL_DIR}")


def _preflight(runner: pf.PfctlRunner) -> tuple[pf.PfSnapshot, int, int]:
    _require_disposable_ci()
    uid, gid = pf._original_user()
    for path in (LAUNCHD_PLIST, STATUS_PATH, PF_TOKEN_PATH, TGWS_LINK_PATH):
        if path.exists():
            raise LifecycleError(f"refusing existing Slipstream state: {path}")
    if INSTALL_DIR.exists():
        raise LifecycleError(f"refusing existing install directory: {INSTALL_DIR}")
    pf._assert_empty_anchor(runner, pf.SLIPSTREAM_ANCHOR)
    pf._assert_empty_anchor(runner, pf.SENTINEL_ANCHOR)
    return pf._pf_snapshot(runner), uid, gid


def _fallback_uninstall(
    system: SystemRunner,
    runner: pf.PfctlRunner,
    target: LifecycleTarget,
) -> list[str]:
    errors = []
    if target.required_installed_paths[0].exists():
        try:
            system.run(target.uninstall_command)
        except Exception as exc:
            errors.append(f"product uninstall: {exc}")
    if LAUNCHD_PLIST.exists():
        try:
            system.run(("/bin/launchctl", "bootout", "system", str(LAUNCHD_PLIST)), check=False)
        except Exception as exc:
            errors.append(f"launchctl bootout: {exc}")
    try:
        pf._flush_anchor(runner, pf.SLIPSTREAM_ANCHOR)
    except Exception as exc:
        errors.append(f"production anchor cleanup: {exc}")
    if PF_TOKEN_PATH.exists():
        try:
            token = PF_TOKEN_PATH.read_text(encoding="ascii").strip()
            if not token.isdigit():
                raise LifecycleError("invalid production PF token")
            runner.run("-X", token, check=True)
        except Exception as exc:
            errors.append(f"production token cleanup: {exc}")
    for path in (LAUNCHD_PLIST, STATUS_PATH, PF_TOKEN_PATH, TGWS_LINK_PATH):
        path.unlink(missing_ok=True)
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    return errors


def run_lifecycle(
    target: LifecycleTarget | None = None,
    safaridriver_url: str | None = None,
) -> dict:
    target = target or script_target()
    safaridriver_url = _validated_safaridriver_url(safaridriver_url)
    runner = pf.PfctlRunner()
    system = SystemRunner(target)
    before, uid, gid = _preflight(runner)
    if target.tray_executable is not None:
        if safaridriver_url is None:
            raise LifecycleError(
                "packaged lifecycle requires a disposable SafariDriver endpoint"
            )
        _assert_safaridriver_ready(safaridriver_url)
    elif safaridriver_url is not None:
        raise LifecycleError("SafariDriver is only valid for packaged lifecycle")
    test_token: str | None = None
    sentinel: PersistentSentinelConnection | None = None
    sentinel_snapshot: tuple[str, str] | None = None
    sentinel_states: tuple[str, ...] | None = None
    tray: PackagedTrayProcess | None = None
    tray_events: list[str] = []
    https_client_probes: list[str] = []
    chrome_probes: list[str] = []
    safari_probes: list[str] = []
    stage = "acquire-pf-reference"
    failure: BaseException | None = None
    cleanup_errors: list[str] = []

    def record_client_probes(label: str) -> None:
        nonlocal stage
        stage = f"{label}:https"
        https_client_probes.append(f"{label}:{_run_https_probe(uid, gid, label)}")
        stage = f"{label}:chrome"
        chrome_probes.append(f"{label}:{_run_chrome_probe(uid, gid, label)}")
        if safaridriver_url is not None:
            stage = f"{label}:safari"
            safari_probes.append(
                f"{label}:{_run_safari_probe(safaridriver_url, label, uid)}"
            )

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    previous_handlers = {
        sig: signal.signal(sig, interrupt) for sig in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        test_token = _acquire_test_pf_reference(runner)
        stage = "sentinel-anchor"
        rules = pf.build_redirect_rules(
            target_port=SENTINEL_TARGET_PORT,
            proxy_port=SENTINEL_PROXY_PORT,
        ).replace("user != root\n", "user != root keep state\n")
        pf._load_anchor(runner, pf.SENTINEL_ANCHOR, rules)
        sentinel_snapshot = pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR)
        stage = "sentinel-connection"
        sentinel = PersistentSentinelConnection(
            SENTINEL_TARGET_PORT,
            SENTINEL_PROXY_PORT,
            uid,
            gid,
        )
        sentinel.start()
        sentinel_states = _assert_sentinel_state(runner)

        stage = "cold-install"
        system.run(target.install_command)
        cold = _wait_for_status("dormant", timeout=90)
        pf._assert_empty_anchor(runner, pf.SLIPSTREAM_ANCHOR)
        _assert_installed_payload(target)
        if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
            raise LifecycleError("cold install changed the sentinel anchor")
        sentinel.check("cold-install")
        _assert_sentinel_state(runner, sentinel_states)

        stage = "reinstall"
        system.run(target.install_command)
        reinstalled = _wait_for_status(
            "dormant",
            previous_pid=int(cold["pid"]),
            timeout=90,
        )
        pf._assert_empty_anchor(runner, pf.SLIPSTREAM_ANCHOR)
        _assert_installed_payload(target)
        if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
            raise LifecycleError("reinstall changed the sentinel anchor")
        sentinel.check("reinstall")
        _assert_sentinel_state(runner, sentinel_states)

        stage = "activate-local-only"
        system.run(("/bin/launchctl", "bootout", "system", str(LAUNCHD_PLIST)))
        _wait_for_path(STATUS_PATH, present=False)
        _patch_launchd_for_local_only(LAUNCHD_PLIST)
        system.run(("/bin/launchctl", "bootstrap", "system", str(LAUNCHD_PLIST)))
        active = _wait_for_status(
            "active",
            previous_pid=int(reinstalled["pid"]),
            timeout=60,
        )
        _assert_anchor_active(runner)
        sentinel.check("active-start")
        _assert_sentinel_state(runner, sentinel_states)

        stage = "daemon-restart"
        system.run(("/bin/launchctl", "kickstart", "-k", LAUNCHD_LABEL))
        restarted = _wait_for_status(
            "active",
            previous_pid=int(active["pid"]),
            timeout=60,
        )
        _assert_anchor_active(runner)
        if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
            raise LifecycleError("daemon restart changed the sentinel anchor")
        _assert_sentinel_state(runner, sentinel_states)
        sentinel.check("daemon-restart")

        if target.tray_executable is not None:
            record_client_probes("before-tray-start")

            stage = "tray-start"
            baseline = _daemon_updated_at(_read_status())
            tray = PackagedTrayProcess(target.tray_executable, uid, gid)
            tray.start()
            _wait_for_same_daemon(
                "active",
                expected_pid=int(restarted["pid"]),
                updated_after=baseline,
            )
            tray_events.append("started")
            _assert_anchor_active(runner)
            if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
                raise LifecycleError("tray start changed the sentinel anchor")
            sentinel.check("tray-start")
            _assert_sentinel_state(runner, sentinel_states)
            record_client_probes("tray-running")

            stage = "tray-crash"
            baseline = _daemon_updated_at(_read_status())
            tray.crash()
            tray_events.append("crashed")
            _wait_for_same_daemon(
                "active",
                expected_pid=int(restarted["pid"]),
                updated_after=baseline,
            )
            _assert_anchor_active(runner)
            if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
                raise LifecycleError("tray crash changed the sentinel anchor")
            sentinel.check("tray-crash")
            _assert_sentinel_state(runner, sentinel_states)
            record_client_probes("after-tray-crash")

            stage = "tray-restart"
            baseline = _daemon_updated_at(_read_status())
            tray.start()
            _wait_for_same_daemon(
                "active",
                expected_pid=int(restarted["pid"]),
                updated_after=baseline,
            )
            tray_events.append("restarted")
            _assert_anchor_active(runner)
            if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
                raise LifecycleError("tray restart changed the sentinel anchor")
            sentinel.check("tray-restart")
            _assert_sentinel_state(runner, sentinel_states)
            record_client_probes("after-tray-restart")
            stage = "tray-stop"
            baseline = _daemon_updated_at(_read_status())
            tray.stop()
            _wait_for_same_daemon(
                "active",
                expected_pid=int(restarted["pid"]),
                updated_after=baseline,
            )
            tray_events.append("stopped")
            _assert_anchor_active(runner)
            if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
                raise LifecycleError("tray stop changed the sentinel anchor")
            sentinel.check("tray-stop")
            _assert_sentinel_state(runner, sentinel_states)

        lifecycle_rearms = []
        daemon_pid = int(restarted["pid"])
        current_status = _read_status()
        previous_rearm_count = _recovery_count(current_status)
        for cycle in range(1, LIFECYCLE_SOAK_CYCLES + 1):
            stage = f"wake:{cycle}:suspend"
            _signal_owned_daemon(target, daemon_pid, signal.SIGSTOP)
            try:
                time.sleep(WAKE_SUSPEND_SECONDS)
            finally:
                stage = f"wake:{cycle}:resume"
                _signal_owned_daemon(target, daemon_pid, signal.SIGCONT)
            stage = f"wake:{cycle}:verify"
            current_status = _wait_for_rearm(
                "wake",
                expected_pid=daemon_pid,
                previous_count=previous_rearm_count,
                timeout=30,
            )
            previous_rearm_count = _recovery_count(current_status)
            lifecycle_rearms.append(f"wake:{cycle}")
            _assert_anchor_active(runner)
            if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
                raise LifecycleError("wake recovery changed the sentinel anchor")
            sentinel.check(f"wake-{cycle}")
            _assert_sentinel_state(runner, sentinel_states)

            stage = f"network-change:{cycle}"
            _signal_owned_daemon(target, daemon_pid, RUNTIME_REARM_SIGNAL)
            current_status = _wait_for_rearm(
                "network_change",
                expected_pid=daemon_pid,
                previous_count=previous_rearm_count,
            )
            previous_rearm_count = _recovery_count(current_status)
            lifecycle_rearms.append(f"network_change:{cycle}")
            _assert_anchor_active(runner)
            if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
                raise LifecycleError(
                    "network-change recovery changed the sentinel anchor"
                )
            sentinel.check(f"network-change-{cycle}")
            _assert_sentinel_state(runner, sentinel_states)

        stage = "uninstall"
        system.run(target.uninstall_command)
        _wait_for_path(LAUNCHD_PLIST, present=False)
        _assert_clean_install_state(runner)
        if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
            raise LifecycleError("uninstall changed the sentinel anchor")
        sentinel.check("uninstall")
        _assert_sentinel_state(runner, sentinel_states)
    except BaseException as exc:
        failure = _lifecycle_failure(stage, exc)
    finally:
        for sig in previous_handlers:
            signal.signal(sig, signal.SIG_IGN)
        if tray is not None:
            try:
                tray.stop()
            except Exception as exc:
                cleanup_errors.append(f"packaged tray cleanup: {exc}")
        cleanup_errors.extend(_fallback_uninstall(system, runner, target))
        if sentinel is not None:
            sentinel.close()
        try:
            pf._flush_anchor(runner, pf.SENTINEL_ANCHOR)
        except Exception as exc:
            cleanup_errors.append(f"sentinel cleanup: {exc}")
        try:
            _release_pf_reference(runner, test_token)
        except Exception as exc:
            cleanup_errors.append(f"test PF token cleanup: {exc}")
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)

    if cleanup_errors:
        raise LifecycleError("; ".join(cleanup_errors)) from failure
    pf._assert_empty_anchor(runner, pf.SLIPSTREAM_ANCHOR)
    pf._assert_empty_anchor(runner, pf.SENTINEL_ANCHOR)
    pf._assert_same_snapshot(before, pf._pf_snapshot(runner))
    if failure is not None:
        raise failure
    return {
        "result": "pass",
        "target": target.name,
        "cold_install": "dormant",
        "reinstall": "new_pid_and_payload_replaced",
        "active_start": "private_anchor_loaded",
        "restart": "new_pid_and_anchor_loaded",
        "packaged_tray": tray_events or ["not_applicable"],
        "https_client_probes": https_client_probes or ["not_applicable"],
        "chrome_probes": chrome_probes or ["not_applicable"],
        "safari_probes": safari_probes or ["not_applicable"],
        "lifecycle_rearms": lifecycle_rearms,
        "uninstall": "clean",
        "sentinel_connection": "preserved",
        "sentinel_state": "preserved",
        "global_pf": "unchanged",
        "system_commands": system.audit_log(),
        "pf_commands": runner.audit_log(),
    }


def dry_run(target_name: str = "script") -> dict:
    return {
        "result": "dry-run",
        "target": target_name,
        "restricted_to": "disposable GitHub Actions macOS runner",
        "cold_install": "Geph unavailable; PF must stay dormant",
        "active_phase": "SLIP_GEPH=0 in test-only installed plist",
        "packaged_tray": (
            "start, crash, restart, and stop exact user-owned process"
            if target_name == "packaged-app"
            else "not applicable"
        ),
        "https_client_probes": (
            "fresh non-root HTTPS client before and after tray crash"
            if target_name == "packaged-app"
            else "not applicable"
        ),
        "chrome_probes": (
            "fresh-profile Chrome process before and after tray crash"
            if target_name == "packaged-app"
            else "not applicable"
        ),
        "safari_probes": (
            "fresh Safari process with an isolated WebDriver session before and "
            "after tray crash"
            if target_name == "packaged-app"
            else "not applicable"
        ),
        "lifecycle_rearms": (
            f"{LIFECYCLE_SOAK_CYCLES} suspend/wake and network-change cycles"
        ),
        "sentinel_connection": "must survive install, reinstall, restart, and uninstall",
        "intercepts_tcp_443": "only briefly on the disposable runner",
        "workstation_allowed": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--app-bundle",
        type=Path,
        help="test the frozen daemon embedded in this built Slipstream.app",
    )
    parser.add_argument(
        "--safaridriver-url",
        help="localhost SafariDriver endpoint prepared by disposable CI",
    )
    args = parser.parse_args(argv)
    try:
        target = packaged_app_target(args.app_bundle) if args.app_bundle else script_target()
        report = (
            dry_run(target.name)
            if args.dry_run
            else run_lifecycle(target, args.safaridriver_url)
        )
    except (LifecycleError, pf.SmokeError, KeyboardInterrupt) as exc:
        print(json.dumps({"result": "fail", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

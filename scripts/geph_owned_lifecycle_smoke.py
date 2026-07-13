#!/usr/bin/env python3
"""Qualify Slipstream's packaged, account-backed Geph LaunchAgent on disposable CI."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path


APP_CONFIG_RELATIVE = Path("Library/Application Support/dev.slipstream.tray")
DAEMON_LABEL = "dev.slipstream.tproxy"
DAEMON_PLIST = Path("/Library/LaunchDaemons/dev.slipstream.tproxy.plist")
GEPH_LABEL = "dev.slipstream.geph"
GEPH_PLIST_NAME = "dev.slipstream.geph.plist"
GEPH_KEYCHAIN_SERVICE = "dev.slipstream.geph"
GEPH_KEYCHAIN_ACCOUNT = "account-secret"
GEPH_SECRET_ENV = "SLIPSTREAM_GEPH_ACCOUNT_SECRET"
GEPH_SOCKS_PORT = 9954
EXTERNAL_GEPH_PORT = 9909
PAYLOAD_HOST = "store.steampowered.com"
PAYLOAD_PATH = "/"
PAYLOAD_MIN_BYTES = 2048
START_TIMEOUT = 180.0
PROCESS_STOP_TIMEOUT = 10.0


class QualificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class GephPaths:
    config_dir: Path
    runtime_dir: Path
    executable: Path
    launcher: Path
    settings: Path
    config: Path
    cache: Path
    ownership: Path
    plist: Path


@dataclass(frozen=True)
class OwnedGephState:
    pid: int
    uid: int
    executable: Path
    config: Path
    launchd_label: str


def geph_paths(home: Path) -> GephPaths:
    config_dir = home / APP_CONFIG_RELATIVE
    runtime_dir = config_dir / "runtime"
    return GephPaths(
        config_dir=config_dir,
        runtime_dir=runtime_dir,
        executable=runtime_dir / "geph5-client",
        launcher=runtime_dir / "geph-launcher",
        settings=config_dir / "geph.json",
        config=config_dir / "geph-active.yaml",
        cache=config_dir / "geph-cache.db",
        ownership=config_dir / "geph-owned.json",
        plist=home / "Library/LaunchAgents" / GEPH_PLIST_NAME,
    )


def _require_disposable_ci() -> None:
    required = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
    }
    missing = [key for key, value in required.items() if os.environ.get(key) != value]
    if missing:
        raise QualificationError(
            "refusing owned Geph qualification outside disposable GitHub Actions"
        )
    if sys.platform != "darwin":
        raise QualificationError("owned Geph qualification requires macOS")
    if os.geteuid() == 0:
        raise QualificationError("owned Geph qualification must run as the login user")


def _take_secret() -> str:
    secret = os.environ.pop(GEPH_SECRET_ENV, "").strip()
    if not secret:
        raise QualificationError(f"missing protected {GEPH_SECRET_ENV} secret")
    return secret


def _run(
    command: tuple[str, ...],
    *,
    check: bool = True,
    timeout: float = 15.0,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=env,
    )
    if check and result.returncode != 0:
        raise QualificationError(
            f"command failed ({command[0]} {command[1] if len(command) > 1 else ''})"
        )
    return result


def _launchd_label_disabled_from_output(raw: str, label: str) -> bool | None:
    pattern = rf'^\s*"{re.escape(label)}"\s*=>\s*([^,\s]+),?\s*$'
    match = re.search(pattern, raw, re.MULTILINE)
    if match is None:
        return None
    state = match.group(1)
    if state in {"true", "disabled"}:
        return True
    if state in {"false", "enabled"}:
        return False
    return None


def _daemon_is_disabled() -> bool:
    result = _run(("/bin/launchctl", "print-disabled", "system"), check=False)
    if result.returncode != 0:
        return False
    return _launchd_label_disabled_from_output(result.stdout, DAEMON_LABEL) is True


def _launchd_target(uid: int) -> str:
    return f"gui/{uid}/{GEPH_LABEL}"


def _launchd_pid(uid: int) -> int | None:
    result = _run(
        ("/bin/launchctl", "print", _launchd_target(uid)),
        check=False,
    )
    if result.returncode != 0:
        return None
    match = re.search(r"^\s*pid\s*=\s*(\d+)\s*$", result.stdout, re.MULTILINE)
    return int(match.group(1)) if match else None


def _listener_pids(port: int) -> tuple[int, ...]:
    result = _run(
        (
            "/usr/sbin/lsof",
            "-nP",
            "-t",
            f"-iTCP@127.0.0.1:{port}",
            "-sTCP:LISTEN",
        ),
        check=False,
    )
    if result.returncode not in (0, 1):
        raise QualificationError(f"cannot inspect listener on port {port}")
    try:
        return tuple(sorted({int(line) for line in result.stdout.splitlines() if line}))
    except ValueError as exc:
        raise QualificationError(f"invalid listener identity on port {port}") from exc


def _process_identity(pid: int) -> tuple[int, str] | None:
    result = _run(
        ("/bin/ps", "-o", "uid=", "-o", "command=", "-p", str(pid)),
        check=False,
    )
    line = result.stdout.strip() if result.returncode == 0 else ""
    parts = line.split(None, 1)
    if len(parts) != 2:
        return None
    try:
        return int(parts[0]), parts[1]
    except ValueError:
        return None


def _write_private_json(path: Path, value: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


def _keychain_exists() -> bool:
    result = _run(
        (
            "/usr/bin/security",
            "find-generic-password",
            "-s",
            GEPH_KEYCHAIN_SERVICE,
            "-a",
            GEPH_KEYCHAIN_ACCOUNT,
        ),
        check=False,
    )
    return result.returncode == 0


def _keychain_add(secret: str) -> None:
    if _keychain_exists():
        raise QualificationError("refusing to replace an existing Slipstream Keychain item")
    result = _run(
        (
            "/usr/bin/security",
            "add-generic-password",
            "-s",
            GEPH_KEYCHAIN_SERVICE,
            "-a",
            GEPH_KEYCHAIN_ACCOUNT,
            "-w",
            secret,
        ),
        check=False,
    )
    if result.returncode != 0:
        raise QualificationError("unable to create the disposable Geph Keychain item")


def _keychain_delete() -> None:
    _run(
        (
            "/usr/bin/security",
            "delete-generic-password",
            "-s",
            GEPH_KEYCHAIN_SERVICE,
            "-a",
            GEPH_KEYCHAIN_ACCOUNT,
        ),
        check=False,
    )


def _read_owned_state(paths: GephPaths, uid: int) -> OwnedGephState:
    try:
        stat_result = paths.ownership.lstat()
        if not paths.ownership.is_file() or paths.ownership.is_symlink():
            raise QualificationError("Geph ownership record is not a regular file")
        if stat_result.st_uid != uid or stat_result.st_mode & 0o777 != 0o600:
            raise QualificationError("Geph ownership record is not owner-private")
        raw = json.loads(paths.ownership.read_text(encoding="utf-8"))
        state = OwnedGephState(
            pid=int(raw["pid"]),
            uid=int(raw["uid"]),
            executable=Path(raw["executable"]),
            config=Path(raw["config"]),
            launchd_label=str(raw["launchd_label"]),
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise QualificationError("invalid Geph ownership record") from exc
    if state.uid != uid:
        raise QualificationError("Geph ownership UID mismatch")
    if state.launchd_label != GEPH_LABEL:
        raise QualificationError("Geph ownership label mismatch")
    if state.executable != paths.executable or state.config != paths.config:
        raise QualificationError("Geph ownership path mismatch")
    return state


def _assert_private_runtime(paths: GephPaths, uid: int) -> None:
    expected = (
        (paths.config_dir, 0o700, True),
        (paths.runtime_dir, 0o700, True),
        (paths.executable, 0o700, False),
        (paths.launcher, 0o700, False),
        (paths.settings, 0o600, False),
        (paths.config, 0o600, False),
        (paths.ownership, 0o600, False),
        (paths.plist, 0o600, False),
    )
    for path, mode, directory in expected:
        try:
            value = path.lstat()
        except OSError as exc:
            raise QualificationError(f"private Geph runtime path is missing: {path.name}") from exc
        if path.is_symlink() or value.st_uid != uid:
            raise QualificationError(f"private Geph runtime ownership mismatch: {path.name}")
        valid_type = stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)
        if not valid_type:
            raise QualificationError(f"private Geph runtime type mismatch: {path.name}")
        if stat.S_IMODE(value.st_mode) != mode:
            raise QualificationError(f"private Geph runtime mode mismatch: {path.name}")
    if paths.cache.exists():
        value = paths.cache.lstat()
        if (
            paths.cache.is_symlink()
            or not stat.S_ISREG(value.st_mode)
            or value.st_uid != uid
            or stat.S_IMODE(value.st_mode) != 0o600
        ):
            raise QualificationError("private Geph cache ownership mismatch")


def _assert_owned_geph(paths: GephPaths, uid: int, state: OwnedGephState) -> None:
    current = _read_owned_state(paths, uid)
    if current != state:
        raise QualificationError("Geph ownership changed before a protected action")
    _assert_private_runtime(paths, uid)
    identity = _process_identity(state.pid)
    expected_prefix = f"{paths.executable} --config {paths.config}"
    if identity is None or identity[0] != uid or identity[1] != expected_prefix:
        raise QualificationError("owned Geph process identity mismatch")
    if _launchd_pid(uid) != state.pid:
        raise QualificationError("owned Geph LaunchAgent PID mismatch")
    if _listener_pids(GEPH_SOCKS_PORT) != (state.pid,):
        raise QualificationError("owned Geph listener PID mismatch")


def _wait_for_owned_geph(
    paths: GephPaths,
    uid: int,
    *,
    previous_pid: int | None = None,
    timeout: float = START_TIMEOUT,
) -> OwnedGephState:
    deadline = time.monotonic() + timeout
    last_error = "ownership record unavailable"
    while time.monotonic() < deadline:
        try:
            state = _read_owned_state(paths, uid)
            if previous_pid is not None and state.pid == previous_pid:
                last_error = "LaunchAgent has not replaced the terminated PID"
            else:
                _assert_owned_geph(paths, uid, state)
                return state
        except QualificationError as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise QualificationError(f"owned Geph did not become ready: {last_error}")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise QualificationError("SOCKS endpoint closed during handshake")
        chunks.extend(chunk)
    return bytes(chunks)


def _socks_connect_request(host: str, port: int) -> bytes:
    try:
        encoded = host.encode("idna")
    except UnicodeError as exc:
        raise QualificationError("invalid SOCKS destination") from exc
    if not encoded or len(encoded) > 255 or not 0 < port < 65536:
        raise QualificationError("invalid SOCKS destination")
    return b"\x05\x01\x00\x03" + bytes((len(encoded),)) + encoded + port.to_bytes(2, "big")


def _socks_connect(host: str, port: int, timeout: float = 20.0) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", GEPH_SOCKS_PORT), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise QualificationError("owned Geph rejected the SOCKS method")
        sock.sendall(_socks_connect_request(host, port))
        version, reply, _reserved, address_type = _recv_exact(sock, 4)
        if version != 5 or reply != 0:
            raise QualificationError(f"owned Geph SOCKS CONNECT failed with code {reply}")
        if address_type == 1:
            _recv_exact(sock, 4)
        elif address_type == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0])
        elif address_type == 4:
            _recv_exact(sock, 16)
        else:
            raise QualificationError("owned Geph returned an invalid SOCKS address")
        _recv_exact(sock, 2)
        return sock
    except BaseException:
        sock.close()
        raise


def _payload_probe() -> dict[str, str | int]:
    raw = _socks_connect(PAYLOAD_HOST, 443)
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=PAYLOAD_HOST) as tls:
            request = (
                f"GET {PAYLOAD_PATH} HTTP/1.1\r\n"
                f"Host: {PAYLOAD_HOST}\r\n"
                "User-Agent: Slipstream-owned-Geph-qualification/1\r\n"
                "Accept: text/html,*/*;q=0.1\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls.sendall(request)
            payload = bytearray()
            while len(payload) < 65536:
                chunk = tls.recv(8192)
                if not chunk:
                    break
                payload.extend(chunk)
            first_line = bytes(payload).split(b"\r\n", 1)[0]
            if len(payload) < PAYLOAD_MIN_BYTES or not first_line.startswith(b"HTTP/"):
                raise QualificationError("owned Geph returned an incomplete HTTPS payload")
            return {
                "bytes": len(payload),
                "protocol": tls.version() or "unknown",
                "status": first_line.decode("ascii", errors="replace"),
            }
    except BaseException:
        raw.close()
        raise


def _wait_for_payload(timeout: float = START_TIMEOUT) -> dict[str, str | int]:
    deadline = time.monotonic() + timeout
    last_error = "payload probe not attempted"
    while time.monotonic() < deadline:
        try:
            return _payload_probe()
        except (OSError, ssl.SSLError, QualificationError) as exc:
            last_error = str(exc)
        time.sleep(2)
    raise QualificationError(f"owned Geph payload did not become ready: {last_error}")


class ExternalListenerSentinel:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.bind(("127.0.0.1", EXTERNAL_GEPH_PORT))
            self.socket.listen(4)
            self.socket.settimeout(0.2)
        except BaseException:
            self.socket.close()
            raise
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                client, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with client:
                client.sendall(b"external-sentinel")

    def check(self) -> None:
        try:
            with socket.create_connection(
                ("127.0.0.1", EXTERNAL_GEPH_PORT), timeout=2
            ) as client:
                if client.recv(32) != b"external-sentinel":
                    raise QualificationError("external Geph sentinel payload changed")
        except OSError as exc:
            raise QualificationError("external Geph sentinel was disrupted") from exc

    def close(self) -> None:
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=2)


class PackagedTray:
    def __init__(self, executable: Path, home: Path, uid: int) -> None:
        self.executable = executable.resolve(strict=True)
        self.home = home
        self.uid = uid
        self.process: subprocess.Popen[bytes] | None = None
        self.log = tempfile.TemporaryFile()

    def start(self) -> int:
        environment = {
            "HOME": str(self.home),
            "USER": os.environ.get("USER", "runner"),
            "LOGNAME": os.environ.get("LOGNAME", os.environ.get("USER", "runner")),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": os.environ.get("LANG", "en_US.UTF-8"),
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_DISPOSABLE_CI": "1",
        }
        self.process = subprocess.Popen(
            (str(self.executable),),
            cwd=self.home,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise QualificationError("packaged tray exited during startup")
            identity = _process_identity(self.process.pid)
            if identity == (self.uid, str(self.executable)):
                return self.process.pid
            time.sleep(0.2)
        raise QualificationError("packaged tray identity was not established")

    def crash(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise QualificationError("packaged tray is not running")
        identity = _process_identity(self.process.pid)
        if identity != (self.uid, str(self.executable)):
            raise QualificationError("refusing to signal an unowned tray process")
        os.kill(self.process.pid, signal.SIGKILL)
        self.process.wait(timeout=PROCESS_STOP_TIMEOUT)
        self.process = None

    def close(self) -> None:
        try:
            if self.process is not None and self.process.poll() is None:
                expected = (self.uid, str(self.executable))
                if _process_identity(self.process.pid) != expected:
                    raise QualificationError("refusing to signal an unowned tray process")
                os.kill(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=PROCESS_STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    if _process_identity(self.process.pid) != expected:
                        raise QualificationError(
                            "tray identity changed before forced cleanup"
                        )
                    os.kill(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=PROCESS_STOP_TIMEOUT)
        finally:
            self.process = None
            self.log.close()


def _kill_owned_geph(paths: GephPaths, uid: int, state: OwnedGephState) -> None:
    _assert_owned_geph(paths, uid, state)
    result = _run(
        ("/bin/launchctl", "kill", "SIGKILL", _launchd_target(uid)),
        check=False,
    )
    if result.returncode != 0:
        raise QualificationError("unable to signal the verified owned Geph job")


def _bootout_owned_geph(uid: int) -> None:
    result = _run(
        ("/bin/launchctl", "bootout", _launchd_target(uid)),
        check=False,
    )
    if result.returncode != 0 and _launchd_pid(uid) is not None:
        raise QualificationError("unable to boot out the owned Geph LaunchAgent")


def _wait_for_listener_gone(timeout: float = PROCESS_STOP_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _listener_pids(GEPH_SOCKS_PORT):
            return
        time.sleep(0.2)
    raise QualificationError("owned Geph listener survived cleanup")


def _preflight(app_bundle: Path, paths: GephPaths) -> Path:
    executable = app_bundle / "Contents/MacOS/slipstream"
    if not app_bundle.is_dir() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise QualificationError("packaged Slipstream executable is unavailable")
    if not _daemon_is_disabled():
        raise QualificationError("root daemon label is not durably disabled")
    if DAEMON_PLIST.exists():
        raise QualificationError("root daemon plist exists before user-level qualification")
    if paths.config_dir.exists() or paths.plist.exists():
        raise QualificationError("disposable Slipstream user state is not clean")
    if _keychain_exists():
        raise QualificationError("disposable Slipstream Keychain state is not clean")
    if _listener_pids(GEPH_SOCKS_PORT):
        raise QualificationError("owned Geph port is already occupied")
    return executable


def run_qualification(app_bundle: Path) -> dict[str, object]:
    _require_disposable_ci()
    secret = _take_secret()
    home = Path.home().resolve()
    uid = os.getuid()
    paths = geph_paths(home)
    executable = _preflight(app_bundle.resolve(strict=True), paths)
    sentinel = ExternalListenerSentinel()
    tray = PackagedTray(executable, home, uid)
    keychain_created = False
    failure: BaseException | None = None
    cleanup_errors: list[str] = []
    result: dict[str, object] = {}
    try:
        sentinel.check()
        _write_private_json(paths.settings, {"enabled": "1", "exit": "auto"})
        _keychain_add(secret)
        keychain_created = True
        secret = ""

        tray.start()
        initial = _wait_for_owned_geph(paths, uid)
        initial_payload = _wait_for_payload()
        sentinel.check()

        tray.crash()
        _assert_owned_geph(paths, uid, initial)
        trayless_payload = _wait_for_payload()
        sentinel.check()

        _kill_owned_geph(paths, uid, initial)
        recovered = _wait_for_owned_geph(paths, uid, previous_pid=initial.pid)
        recovered_payload = _wait_for_payload()
        sentinel.check()

        result = {
            "result": "pass",
            "restricted_to": "protected disposable GitHub Actions macOS runner",
            "root_daemon": "absent and disabled",
            "packaged_tray": "crashed without stopping owned Geph",
            "owned_geph": "KeepAlive replaced the verified PID",
            "payload": {
                "initial": initial_payload,
                "trayless": trayless_payload,
                "recovered": recovered_payload,
            },
            "external_listener": "preserved",
            "system_network_state": "not mutated",
        }
    except BaseException as exc:
        failure = exc
    finally:
        secret = ""
        try:
            tray.close()
        except Exception as exc:
            cleanup_errors.append(f"tray cleanup: {exc}")
        try:
            _bootout_owned_geph(uid)
            _wait_for_listener_gone()
        except Exception as exc:
            cleanup_errors.append(f"owned Geph cleanup: {exc}")
        if keychain_created:
            _keychain_delete()
        try:
            if paths.config_dir.exists():
                shutil.rmtree(paths.config_dir)
            paths.plist.unlink(missing_ok=True)
        except Exception as exc:
            cleanup_errors.append(f"private runtime cleanup: {exc}")
        try:
            sentinel.check()
        except Exception as exc:
            cleanup_errors.append(f"external listener cleanup check: {exc}")
        sentinel.close()

    if cleanup_errors:
        raise QualificationError("; ".join(cleanup_errors)) from failure
    if keychain_created and _keychain_exists():
        raise QualificationError("owned Geph Keychain item survived cleanup") from failure
    if paths.config_dir.exists() or paths.plist.exists():
        raise QualificationError("owned Geph artifacts survived cleanup") from failure
    if _listener_pids(GEPH_SOCKS_PORT):
        raise QualificationError("owned Geph listener survived cleanup") from failure
    if not _daemon_is_disabled() or DAEMON_PLIST.exists():
        raise QualificationError("root daemon boundary changed during qualification") from failure
    if failure is not None:
        raise failure
    return result


def dry_run() -> dict[str, object]:
    return {
        "result": "dry-run",
        "restricted_to": "protected disposable GitHub Actions macOS runner",
        "root_daemon": "must be absent and durably disabled",
        "packaged_tray": "bootstraps the exact user LaunchAgent, then crashes",
        "owned_geph": "real account, exact ownership, SOCKS payload, KeepAlive PID replacement",
        "external_listener": "127.0.0.1:9909 sentinel must survive",
        "system_network_state": "DNS, proxy, PAC, VPN, interfaces, and PF are read-only",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-bundle", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.dry_run:
        print(json.dumps(dry_run(), indent=2, sort_keys=True))
        return 0
    if args.app_bundle is None:
        parser.error("--app-bundle is required outside --dry-run")
    try:
        result = run_qualification(args.app_bundle)
    except Exception as exc:
        print(f"owned Geph qualification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

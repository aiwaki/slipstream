#!/usr/bin/env python3
"""Disposable macOS install/restart/uninstall qualification for Slipstream.

This script performs real privileged lifecycle operations. It refuses to run
outside GitHub Actions with an explicit opt-in environment variable, and it
never runs on a workstation installation.
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence

import pf_anchor_smoke as pf


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DAEMON = ROOT / "spike" / "tproxy.py"
INSTALL_DIR = Path("/usr/local/slipstream")
INSTALLED_PYTHON = INSTALL_DIR / "venv" / "bin" / "python3"
INSTALLED_DAEMON = INSTALL_DIR / "tproxy.py"
INSTALLED_PRIMES = INSTALL_DIR / "primes.py"
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


class LifecycleError(RuntimeError):
    """A lifecycle safety condition or assertion failed."""


def validate_system_command(command: Sequence[str]) -> None:
    command = tuple(map(str, command))
    allowed = {
        (sys.executable, str(SOURCE_DAEMON), "--install"),
        (str(INSTALLED_PYTHON), str(INSTALLED_DAEMON), "--uninstall"),
        ("/bin/launchctl", "bootout", "system", str(LAUNCHD_PLIST)),
        ("/bin/launchctl", "bootstrap", "system", str(LAUNCHD_PLIST)),
        ("/bin/launchctl", "kickstart", "-k", LAUNCHD_LABEL),
    }
    if command not in allowed:
        raise LifecycleError("unsupported lifecycle command: " + " ".join(command))


class SystemRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout: int = 180,
    ) -> subprocess.CompletedProcess[str]:
        command = tuple(map(str, command))
        validate_system_command(command)
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
        self.counter = 0

    def start(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(6)
        listener.bind(("127.0.0.1", self.proxy_port))
        listener.listen(1)
        pid = os.fork()
        if pid == 0:
            try:
                listener.close()
                os.setgroups([])
                os.setgid(self.gid)
                os.setuid(self.uid)
                with socket.create_connection(
                    (pf.TEST_DESTINATION, self.target_port), timeout=5
                ) as client:
                    client.settimeout(10)
                    while True:
                        data = client.recv(4096)
                        if not data or data == STOP_MARKER:
                            break
                        client.sendall(data)
                os._exit(0)
            except BaseException:
                os._exit(3)

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
            raise LifecycleError(
                f"sentinel echo mismatch after {label}; "
                f"received={bytes(received)!r}; child={child}"
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
        if last and last.get("state") == expected:
            pid = int(last.get("pid") or 0)
            fresh = time.time() - float(last.get("ts") or 0) < 15
            changed = previous_pid is None or (pid and pid != previous_pid)
            if fresh and changed:
                return last
        time.sleep(0.5)
    raise LifecycleError(f"daemon did not reach {expected}; last status={last!r}")


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


def _assert_sentinel_state(runner: pf.PfctlRunner) -> None:
    states = runner.run("-s", "states", check=True).stdout
    if str(SENTINEL_TARGET_PORT) not in states and str(SENTINEL_PROXY_PORT) not in states:
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


def _rule_has_port(rules: str, port: int) -> bool:
    return bool(re.search(rf"\bport\s*(?:=\s*)?{port}\b", rules))


def _assert_anchor_active(runner: pf.PfctlRunner) -> None:
    nat, rules = pf._anchor_snapshot(runner, pf.SLIPSTREAM_ANCHOR)
    if not _rule_has_port(nat, 443) or not _rule_has_port(nat, 1080) or "route-to" not in rules:
        raise LifecycleError(
            "installed daemon did not arm the production private anchor: "
            f"nat={nat!r}, rules={rules!r}"
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


def _fallback_uninstall(system: SystemRunner, runner: pf.PfctlRunner) -> list[str]:
    errors = []
    if INSTALLED_PYTHON.exists() and INSTALLED_DAEMON.exists():
        try:
            system.run((str(INSTALLED_PYTHON), str(INSTALLED_DAEMON), "--uninstall"))
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


def run_lifecycle() -> dict:
    runner = pf.PfctlRunner()
    system = SystemRunner()
    before, uid, gid = _preflight(runner)
    test_token: str | None = None
    sentinel: PersistentSentinelConnection | None = None
    sentinel_snapshot: tuple[str, str] | None = None
    failure: BaseException | None = None
    cleanup_errors: list[str] = []

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    previous_handlers = {
        sig: signal.signal(sig, interrupt) for sig in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        test_token = _acquire_test_pf_reference(runner)
        rules = pf.build_redirect_rules(
            target_port=SENTINEL_TARGET_PORT,
            proxy_port=SENTINEL_PROXY_PORT,
        ).replace("user != root\n", "user != root keep state\n")
        pf._load_anchor(runner, pf.SENTINEL_ANCHOR, rules)
        sentinel_snapshot = pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR)
        sentinel = PersistentSentinelConnection(
            SENTINEL_TARGET_PORT,
            SENTINEL_PROXY_PORT,
            uid,
            gid,
        )
        sentinel.start()
        _assert_sentinel_state(runner)

        system.run((sys.executable, str(SOURCE_DAEMON), "--install"))
        cold = _wait_for_status("dormant", timeout=90)
        pf._assert_empty_anchor(runner, pf.SLIPSTREAM_ANCHOR)
        if not INSTALLED_PRIMES.is_file():
            raise LifecycleError("script-mode install omitted primes.py")
        if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
            raise LifecycleError("cold install changed the sentinel anchor")
        sentinel.check("cold-install")
        _assert_sentinel_state(runner)

        system.run(("/bin/launchctl", "bootout", "system", str(LAUNCHD_PLIST)))
        _wait_for_path(STATUS_PATH, present=False)
        _patch_launchd_for_local_only(LAUNCHD_PLIST)
        system.run(("/bin/launchctl", "bootstrap", "system", str(LAUNCHD_PLIST)))
        active = _wait_for_status("active", previous_pid=int(cold["pid"]), timeout=60)
        _assert_anchor_active(runner)
        sentinel.check("active-start")
        _assert_sentinel_state(runner)

        system.run(("/bin/launchctl", "kickstart", "-k", LAUNCHD_LABEL))
        restarted = _wait_for_status(
            "active",
            previous_pid=int(active["pid"]),
            timeout=60,
        )
        _assert_anchor_active(runner)
        if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
            raise LifecycleError("daemon restart changed the sentinel anchor")
        _assert_sentinel_state(runner)
        sentinel.check("daemon-restart")

        system.run((str(INSTALLED_PYTHON), str(INSTALLED_DAEMON), "--uninstall"))
        _wait_for_path(LAUNCHD_PLIST, present=False)
        _assert_clean_install_state(runner)
        if pf._anchor_snapshot(runner, pf.SENTINEL_ANCHOR) != sentinel_snapshot:
            raise LifecycleError("uninstall changed the sentinel anchor")
        sentinel.check("uninstall")
        _assert_sentinel_state(runner)
    except BaseException as exc:
        failure = exc
    finally:
        for sig in previous_handlers:
            signal.signal(sig, signal.SIG_IGN)
        cleanup_errors.extend(_fallback_uninstall(system, runner))
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
        "cold_install": "dormant",
        "active_start": "private_anchor_loaded",
        "restart": "new_pid_and_anchor_loaded",
        "uninstall": "clean",
        "sentinel_connection": "preserved",
        "sentinel_state": "preserved",
        "global_pf": "unchanged",
        "system_commands": system.audit_log(),
        "pf_commands": runner.audit_log(),
    }


def dry_run() -> dict:
    return {
        "result": "dry-run",
        "restricted_to": "disposable GitHub Actions macOS runner",
        "cold_install": "Geph unavailable; PF must stay dormant",
        "active_phase": "SLIP_GEPH=0 in test-only installed plist",
        "sentinel_connection": "must survive install, restart, and uninstall",
        "intercepts_tcp_443": "only briefly on the disposable runner",
        "workstation_allowed": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = dry_run() if args.dry_run else run_lifecycle()
    except (LifecycleError, pf.SmokeError, KeyboardInterrupt) as exc:
        print(json.dumps({"result": "fail", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

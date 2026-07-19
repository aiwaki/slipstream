#!/usr/bin/env python3
"""Privileged, scoped smoke test for Slipstream's private PF anchor.

The smoke test is intended for a disposable macOS runner. It never installs or
starts Slipstream, never targets TCP/443, and refuses to run while Slipstream
state already exists. All rule writes are restricted to two owned anchors. If
PF initially skips lo0, the smoke uses Slipstream's durable lease + private
ioctl path and requires the exact original flag state after cleanup.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import socket
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
SPIKE = ROOT / "spike"
PFCTL = Path("/sbin/pfctl")
SLIPSTREAM_ANCHOR = "com.apple/slipstream"
SENTINEL_ANCHOR = "com.apple/slipstream-smoke-sentinel"
OWNED_ANCHORS = frozenset({SLIPSTREAM_ANCHOR, SENTINEL_ANCHOR})
PRODUCTION_TOKEN_PATH = Path("/var/run/slipstream-pf.token")
SMOKE_TOKEN_PATH = Path("/var/run/slipstream-pf-smoke.token")
PRODUCTION_SKIP_LEASE_PATH = Path("/var/run/slipstream-pf-lo0-skip.json")
SMOKE_SKIP_LEASE_PATH = Path("/var/run/slipstream-pf-smoke-lo0-skip.json")
STATUS_PATH = Path("/var/run/slipstream.status")
TEST_DESTINATION = "198.51.100.1"
DEFAULT_TARGET_PORT = 18443
DEFAULT_PROXY_PORT = 19443
MARKER = b"slipstream-pf-smoke\n"


class SmokeError(RuntimeError):
    """A safety precondition or smoke assertion failed."""


@dataclass(frozen=True)
class PfSnapshot:
    enabled: bool
    nat_rules: str
    filter_rules: str
    loopback_skip: bool


def validate_pfctl_args(args: Sequence[str]) -> None:
    """Reject every PF mutation outside the two smoke-owned anchors."""
    args = tuple(str(value) for value in args)
    if not args:
        raise SmokeError("empty pfctl command")
    if Path(args[0]).name != "pfctl":
        raise SmokeError(f"unexpected executable: {args[0]}")
    tail = args[1:]
    if tail in {
        ("-s", "info"),
        ("-s", "states"),
        ("-s", "References"),
        ("-v", "-s", "Interfaces"),
        ("-sn",),
        ("-sr",),
        ("-E",),
    }:
        return
    if len(tail) == 2 and tail[0] == "-X" and tail[1]:
        return
    if len(tail) == 3 and tail[0] == "-a":
        anchor = tail[1].lstrip("/")
        if anchor in OWNED_ANCHORS and tail[2] in {"-sn", "-sr"}:
            return
    if len(tail) == 4 and tail[0] == "-a":
        anchor = tail[1].lstrip("/")
        if anchor in OWNED_ANCHORS:
            if tail[2] == "-f" and tail[3]:
                return
            if tail[2] == "-F" and tail[3] in {"rules", "nat"}:
                return
    raise SmokeError(f"unsupported or unscoped pfctl command: {' '.join(args)}")


class PfctlRunner:
    def __init__(self, executable: Path = PFCTL) -> None:
        self.executable = executable
        self.commands: list[tuple[str, ...]] = []

    def run(self, *args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        command = (str(self.executable), *map(str, args))
        validate_pfctl_args(command)
        self.commands.append(command)
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if check and result.returncode != 0:
            raise SmokeError(
                f"pfctl failed ({result.returncode}): {self.display(command)}\n"
                f"{result.stderr.strip()}"
            )
        return result

    @staticmethod
    def display(command: Sequence[str]) -> str:
        command = list(command)
        if "-X" in command:
            command[command.index("-X") + 1] = "<redacted-token>"
        return " ".join(command)

    def audit_log(self) -> list[str]:
        return [self.display(command) for command in self.commands]


def build_redirect_rules(*, target_port: int, proxy_port: int) -> str:
    if target_port == 443:
        raise SmokeError("the smoke test must never intercept TCP/443")
    for name, port in (("target", target_port), ("proxy", proxy_port)):
        if not 1024 <= port <= 65535:
            raise SmokeError(f"{name} port must be between 1024 and 65535")
    if target_port == proxy_port:
        raise SmokeError("target and proxy ports must differ")
    return (
        "rdr on lo0 inet proto tcp from any to ! 127.0.0.0/8 "
        f"port {target_port} -> 127.0.0.1 port {proxy_port}\n"
        "pass out quick on ! lo0 route-to (lo0 127.0.0.1) inet proto tcp "
        f"from any to any port {target_port} user != root\n"
        "pass out quick on lo0 inet proto tcp from any to any "
        f"port {target_port} no state\n"
        "pass in quick on lo0 reply-to (lo0 127.0.0.1) inet proto tcp "
        f"from any to 127.0.0.1 port {proxy_port}\n"
    )


def sentinel_rules() -> str:
    return (
        "pass quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 "
        'port 65534 label "slipstream-smoke-sentinel"\n'
    )


def _load_anchor(runner: PfctlRunner, anchor: str, rules: str) -> None:
    if anchor not in OWNED_ANCHORS:
        raise SmokeError(f"refusing to load unowned anchor {anchor}")
    path: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pf.conf", delete=False) as handle:
            handle.write(rules)
            path = handle.name
        runner.run("-a", anchor, "-f", path, check=True)
    finally:
        if path:
            Path(path).unlink(missing_ok=True)


def _flush_anchor(runner: PfctlRunner, anchor: str) -> None:
    errors = []
    for modifier in ("rules", "nat"):
        result = runner.run("-a", anchor, "-F", modifier)
        if result.returncode != 0:
            errors.append(f"{modifier}: {result.stderr.strip()}")
    if errors:
        raise SmokeError(f"unable to flush {anchor}: " + "; ".join(errors))


def _anchor_snapshot(runner: PfctlRunner, anchor: str) -> tuple[str, str]:
    nat = runner.run("-a", anchor, "-sn", check=True).stdout.strip()
    rules = runner.run("-a", anchor, "-sr", check=True).stdout.strip()
    return nat, rules


def _pf_snapshot(runner: PfctlRunner) -> PfSnapshot:
    info = runner.run("-s", "info", check=True).stdout
    if "Status: Enabled" in info:
        enabled = True
    elif "Status: Disabled" in info:
        enabled = False
    else:
        raise SmokeError("unable to determine PF enabled state")
    interfaces = runner.run("-v", "-s", "Interfaces", check=True).stdout.splitlines()
    values = {line.strip() for line in interfaces}
    if "lo0 (skip)" in values:
        loopback_skip = True
    elif "lo0" in values:
        loopback_skip = False
    else:
        raise SmokeError("unable to determine PF lo0 skip state")
    return PfSnapshot(
        enabled=enabled,
        nat_rules=runner.run("-sn", check=True).stdout.strip(),
        filter_rules=runner.run("-sr", check=True).stdout.strip(),
        loopback_skip=loopback_skip,
    )


def _assert_empty_anchor(runner: PfctlRunner, anchor: str) -> None:
    nat, rules = _anchor_snapshot(runner, anchor)
    if nat or rules:
        raise SmokeError(f"anchor {anchor} is already in use")


def _assert_same_snapshot(before: PfSnapshot, after: PfSnapshot) -> None:
    if before != after:
        changed = []
        if before.enabled != after.enabled:
            changed.append("enabled state")
        if before.nat_rules != after.nat_rules:
            changed.append("global NAT rules")
        if before.filter_rules != after.filter_rules:
            changed.append("global filter rules")
        if before.loopback_skip != after.loopback_skip:
            changed.append("lo0 skip state")
        raise SmokeError("PF snapshot changed after cleanup: " + ", ".join(changed))


def _original_user() -> tuple[int, int]:
    try:
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ["SUDO_GID"])
    except (KeyError, ValueError) as exc:
        raise SmokeError("run through sudo from a non-root user") from exc
    if uid <= 0 or gid < 0:
        raise SmokeError("SUDO_UID must identify a non-root user")
    return uid, gid


def _open_listener(proxy_port: int) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.settimeout(5)
    listener.bind(("127.0.0.1", proxy_port))
    listener.listen(1)
    return listener


def _probe_redirect(
    *,
    listener: socket.socket,
    target_port: int,
    uid: int,
    gid: int,
    destination: str = TEST_DESTINATION,
) -> None:

    pid = os.fork()
    if pid == 0:
        try:
            listener.close()
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            with socket.create_connection((destination, target_port), timeout=4) as client:
                received = client.recv(len(MARKER))
            os._exit(0 if received == MARKER else 2)
        except BaseException:
            os._exit(3)

    child_status: int | None = None
    try:
        connection, _ = listener.accept()
        with connection:
            connection.sendall(MARKER)
    except (OSError, TimeoutError) as exc:
        raise SmokeError("test-port redirect did not reach the local listener") from exc
    finally:
        listener.close()
        _, child_status = os.waitpid(pid, 0)
    if not os.WIFEXITED(child_status) or os.WEXITSTATUS(child_status) != 0:
        raise SmokeError("unprivileged test client did not traverse the PF redirect")


def _import_tproxy():
    if str(SPIKE) not in sys.path:
        sys.path.insert(0, str(SPIKE))
    import tproxy  # noqa: PLC0415

    return tproxy


def _configure_tproxy_for_smoke(tproxy, runner: PfctlRunner, rules: str) -> None:
    def scoped_run(program: str, *args: str):
        if Path(program).name != "pfctl":
            raise SmokeError(f"unexpected command from tproxy: {program}")
        return runner.run(*args)

    tproxy._run = scoped_run
    tproxy.PF_ANCHOR = SLIPSTREAM_ANCHOR
    tproxy.PF_TOKEN_PATH = str(SMOKE_TOKEN_PATH)
    tproxy.PF_SKIP_LEASE_PATH = str(SMOKE_SKIP_LEASE_PATH)
    tproxy.PF_RULES = rules
    tproxy.GEPH_ENABLED = True
    tproxy.GEPH_PORTS = [tproxy.GEPH_OWNED_PORT]
    tproxy._pf_enable_token = None
    tproxy._pf_applied = False
    tproxy._geph_up = False
    tproxy._geph_port = None
    tproxy._geph_backend_hold_until = 0.0
    tproxy._geph_backend_hold_reason = ""


def _preflight(runner: PfctlRunner) -> tuple[PfSnapshot, int, int]:
    if platform.system() != "Darwin":
        raise SmokeError("PF smoke requires macOS")
    if os.geteuid() != 0:
        raise SmokeError("PF smoke requires root")
    if not PFCTL.is_file():
        raise SmokeError(f"pfctl not found at {PFCTL}")
    uid, gid = _original_user()
    for path in (
        PRODUCTION_TOKEN_PATH,
        SMOKE_TOKEN_PATH,
        PRODUCTION_SKIP_LEASE_PATH,
        SMOKE_SKIP_LEASE_PATH,
        STATUS_PATH,
    ):
        if path.exists():
            raise SmokeError(f"refusing to run while Slipstream state exists: {path}")
    _assert_empty_anchor(runner, SLIPSTREAM_ANCHOR)
    _assert_empty_anchor(runner, SENTINEL_ANCHOR)
    return _pf_snapshot(runner), uid, gid


def _release_smoke_token(tproxy, runner: PfctlRunner) -> None:
    if tproxy is not None:
        result = tproxy._pf_release_enable_token()
        if result is not None and result.returncode != 0:
            raise SmokeError("unable to release PF enable token")
    elif SMOKE_TOKEN_PATH.exists():
        token = SMOKE_TOKEN_PATH.read_text(encoding="ascii").strip()
        if token:
            runner.run("-X", token, check=True)
        SMOKE_TOKEN_PATH.unlink(missing_ok=True)


def _restore_loopback_before_token_release(tproxy, runner: PfctlRunner) -> bool:
    if tproxy is not None and not tproxy._restore_pf_loopback_skip():
        return False
    _release_smoke_token(tproxy, runner)
    return True


def run_smoke(*, target_port: int, proxy_port: int) -> dict:
    rules = build_redirect_rules(target_port=target_port, proxy_port=proxy_port)
    runner = PfctlRunner()
    before, uid, gid = _preflight(runner)
    tproxy = None
    sentinel_before: tuple[str, str] | None = None
    cleanup_errors: list[str] = []
    failure: BaseException | None = None
    listener: socket.socket | None = None

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    previous_handlers = {
        sig: signal.signal(sig, interrupt) for sig in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        listener = _open_listener(proxy_port)
        _load_anchor(runner, SENTINEL_ANCHOR, sentinel_rules())
        sentinel_before = _anchor_snapshot(runner, SENTINEL_ANCHOR)
        if not sentinel_before[1]:
            raise SmokeError("sentinel anchor did not load")

        tproxy = _import_tproxy()
        _configure_tproxy_for_smoke(tproxy, runner, rules)
        if not tproxy.arm_private_pf_if_ready(proxy_port):
            raise SmokeError("local routing did not arm without Geph")
        if tproxy.geo_exit_backend_ready():
            raise SmokeError("absent Geph was reported as ready")
        mode = stat.S_IMODE(SMOKE_TOKEN_PATH.stat().st_mode)
        if mode != 0o600:
            raise SmokeError(f"PF token mode is {mode:o}, expected 600")
        if before.loopback_skip:
            skip_mode = stat.S_IMODE(SMOKE_SKIP_LEASE_PATH.stat().st_mode)
            if skip_mode != 0o600:
                raise SmokeError(
                    f"PF loopback lease mode is {skip_mode:o}, expected 600"
                )
        elif SMOKE_SKIP_LEASE_PATH.exists():
            raise SmokeError("PF loopback lease was created without owning the skip flag")

        nat, filters = _anchor_snapshot(runner, SLIPSTREAM_ANCHOR)
        if str(target_port) not in nat or str(proxy_port) not in nat:
            raise SmokeError("private anchor did not load the test redirect")
        if str(target_port) not in filters or "route-to" not in filters:
            raise SmokeError("private anchor did not load the test route rule")
        if _anchor_snapshot(runner, SENTINEL_ANCHOR) != sentinel_before:
            raise SmokeError("arming Slipstream changed the sentinel anchor")

        _probe_redirect(
            listener=_open_listener(target_port),
            target_port=target_port,
            uid=uid,
            gid=gid,
            destination="127.0.0.1",
        )
        _probe_redirect(
            listener=listener,
            target_port=target_port,
            uid=uid,
            gid=gid,
        )
        if not tproxy.suspend_geo_exit_backend("pf smoke runtime failure"):
            raise SmokeError("runtime failure did not cool down Geph")
        if _anchor_snapshot(runner, SLIPSTREAM_ANCHOR) != (nat, filters):
            raise SmokeError("Geph cooldown changed the private anchor")
        if not tproxy.pause_private_pf():
            raise SmokeError("explicit private PF pause failed")
        _assert_empty_anchor(runner, SLIPSTREAM_ANCHOR)
        if _anchor_snapshot(runner, SENTINEL_ANCHOR) != sentinel_before:
            raise SmokeError("runtime suspension changed the sentinel anchor")
    except BaseException as exc:
        failure = exc
    finally:
        for sig in previous_handlers:
            signal.signal(sig, signal.SIG_IGN)
        if listener is not None:
            listener.close()
        for anchor in (SLIPSTREAM_ANCHOR, SENTINEL_ANCHOR):
            try:
                _flush_anchor(runner, anchor)
            except Exception as exc:  # cleanup must attempt every remaining step
                cleanup_errors.append(f"flush {anchor}: {exc}")
        try:
            if not _restore_loopback_before_token_release(tproxy, runner):
                raise SmokeError("PF loopback skip restoration failed")
        except Exception as exc:
            cleanup_errors.append(f"restore PF loopback before token release: {exc}")
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)

    if cleanup_errors:
        raise SmokeError("; ".join(cleanup_errors)) from failure
    _assert_empty_anchor(runner, SLIPSTREAM_ANCHOR)
    _assert_empty_anchor(runner, SENTINEL_ANCHOR)
    if SMOKE_SKIP_LEASE_PATH.exists():
        raise SmokeError("PF loopback lease remains after cleanup")
    after = _pf_snapshot(runner)
    _assert_same_snapshot(before, after)
    if failure is not None:
        raise failure
    return {
        "result": "pass",
        "cold_start": "dormant",
        "runtime_failure": "private_anchor_flushed",
        "sentinel": "unchanged",
        "global_pf": "unchanged",
        "loopback_target": "excluded",
        "loopback_skip": "restored",
        "target_port": target_port,
        "proxy_port": proxy_port,
        "commands": runner.audit_log(),
    }


def dry_run(*, target_port: int, proxy_port: int) -> dict:
    build_redirect_rules(target_port=target_port, proxy_port=proxy_port)
    return {
        "result": "dry-run",
        "platform": "macOS disposable runner",
        "production_anchor": SLIPSTREAM_ANCHOR,
        "sentinel_anchor": SENTINEL_ANCHOR,
        "target_port": target_port,
        "proxy_port": proxy_port,
        "intercepts_tcp_443": False,
        "loopback_skip": "temporarily cleared only when present, then restored",
        "forbidden_operations": [
            "global ruleset reload",
            "pfctl -d",
            "global state flush",
            "external anchor mutation",
            "Slipstream installation",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    parser.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT)
    args = parser.parse_args(argv)
    try:
        report = (
            dry_run(target_port=args.target_port, proxy_port=args.proxy_port)
            if args.dry_run
            else run_smoke(target_port=args.target_port, proxy_port=args.proxy_port)
        )
    except (SmokeError, KeyboardInterrupt) as exc:
        print(json.dumps({"result": "fail", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

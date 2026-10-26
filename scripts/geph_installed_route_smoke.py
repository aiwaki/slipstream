#!/usr/bin/env python3
"""Account-backed installed-daemon route continuity, in disposable macOS CI.

The client connects to an owned IPv6 loopback alias but sends a reviewed geo SNI.
The installed PF/daemon path must send it through real Geph. A distinct local
HTTPS origin counts any system-route fallback. No daemon hooks, public DNS
changes, fake backend health, or system trust changes are used. The local CA is
loaded only by this fixture's client; production canaries retain their roots.
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
from pathlib import Path
import plistlib
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable

import geph_owned_lifecycle_smoke as geph
import pf_anchor_smoke as pf

HOST = "store.steampowered.com"
REQUEST_PATH = "/"
FIXTURE_ANCHOR = "com.apple/000-slipstream-geph-route-smoke"
FIXTURE_TAG = "SLIPSTREAM_GEPH_ROUTE_CONTROL"
SYSTEM_BODY = b"slipstream-installed-geph-system-route-control\n"
MAX_BODY = 2 * 1024 * 1024


class RouteQualificationError(RuntimeError):
    """Only fixture-authored, credential-free invariant descriptions."""


def _error_receipt(error: BaseException | None) -> dict | None:
    if error is None:
        return None
    return {
        "type": type(error).__name__,
        "reason": str(error)[:180] if isinstance(error, RouteQualificationError) else "external operation failed",
    }


def _private_bytes(path: Path, uid: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid or stat.S_IMODE(meta.st_mode) != 0o600:
            raise RouteQualificationError("fixture input is not an owner-private regular file")
        value = os.read(fd, 65537)
        if len(value) > 65536:
            raise RouteQualificationError("fixture input exceeds the bounded read")
        return value
    finally:
        os.close(fd)


class SettingsSnapshot:
    """Keep exact private bytes in memory, never in the public receipt."""
    def __init__(self, path: Path, uid: int, gid: int):
        self.path, self.uid, self.gid = path, uid, gid
        self.original = self.current = _private_bytes(path, uid)
        config = json.loads(self.original)
        if not isinstance(config, dict) or config.get("enabled") != "1":
            raise RouteQualificationError("staged owned Geph must already be explicitly enabled")

    def replace(self, payload: bytes) -> None:
        if _private_bytes(self.path, self.uid) != self.current:
            raise RouteQualificationError("Geph settings changed outside this fixture")
        fd, name = tempfile.mkstemp(prefix=".route-qualification-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchown(stream.fileno(), self.uid, self.gid)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
            self.current = payload
        finally:
            Path(name).unlink(missing_ok=True)

    def disable(self) -> None:
        value = json.loads(self.original)
        value["enabled"] = "0"
        self.replace(json.dumps(value).encode())

    def restore(self) -> None:
        if self.current != self.original:
            self.replace(self.original)
        if _private_bytes(self.path, self.uid) != self.original:
            raise RouteQualificationError("Geph settings restoration was not exact")


class OwnedBackend:
    """Only mutate the coordinator's exact verified LaunchAgent."""
    def __init__(self, paths: geph.GephPaths, uid: int):
        self.paths, self.uid = paths, uid
        self.state = geph._wait_for_owned_geph(paths, uid)
        self.plist = _private_bytes(paths.plist, uid)
        payload = plistlib.loads(self.plist)
        if payload.get("Label") != geph.GEPH_LABEL or payload.get("ProgramArguments") != [str(paths.launcher)]:
            raise RouteQualificationError("unexpected staged Geph launch authority")
        self.mutated = False

    def _verify_plist(self) -> None:
        if _private_bytes(self.paths.plist, self.uid) != self.plist:
            raise RouteQualificationError("Geph LaunchAgent changed during qualification")

    def present(self) -> bool:
        result = geph._run(("/bin/launchctl", "print", geph._launchd_target(self.uid)), check=False)
        if result.returncode == 0:
            return True
        if "could not find service" in (result.stdout + result.stderr).lower():
            return False
        raise RouteQualificationError("cannot prove staged Geph LaunchAgent absence")

    def stop(self) -> None:
        self._verify_plist()
        self.state = geph._wait_for_owned_geph(self.paths, self.uid)
        geph._assert_owned_geph(self.paths, self.uid, self.state)
        self.mutated = True  # bootout may take effect even when its command times out
        geph._bootout_owned_geph(self.uid)
        geph._wait_for_listener_gone()
        if self.present():
            raise RouteQualificationError("staged Geph LaunchAgent survived bootout")
        expected = (self.uid, f"{self.paths.executable} --config {self.paths.config}")
        if geph._process_identity(self.state.pid) == expected:
            raise RouteQualificationError("staged Geph process survived bootout")

    def start(self) -> None:
        self._verify_plist()
        previous_pid = self.state.pid
        if not self.present():
            if geph._listener_pids(geph.GEPH_SOCKS_PORT):
                raise RouteQualificationError("unowned listener occupies staged Geph port")
            geph._run(("/bin/launchctl", "bootstrap", f"gui/{self.uid}", str(self.paths.plist)))
            self.state = geph._wait_for_owned_geph(self.paths, self.uid, previous_pid=previous_pid)
        else:
            self.state = geph._wait_for_owned_geph(self.paths, self.uid)
        geph._assert_owned_geph(self.paths, self.uid, self.state)


class SentinelPfIsolation:
    """Exclude only root control dials from lo0 re-interception in disposable CI.

    Production PF excludes root only on the physical-interface route-to rule.
    Our destination lives on lo0, so its root-origin packets need a fixture-only
    tag before inbound rdr. Unprivileged clients receive no tag and still use
    the untouched production rdr/NATLOOK path. This is not localhost policy
    qualification; both positive controls must actually reach the sentinel.
    """
    def __init__(self):
        self.runner = pf.PfctlRunner()
        self.before = None
        self.production = None
        self.attempted = False

    @staticmethod
    def _run(*args: str):
        if args not in {
            ("-sn",), ("-sr",), ("-F", "rules"), ("-F", "nat"),
        } and not (len(args) == 2 and args[0] == "-f" and args[1]):
            raise RouteQualificationError("unscoped fixture PF command")
        result = subprocess.run(
            (str(pf.PFCTL), "-a", FIXTURE_ANCHOR, *args),
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode:
            raise RouteQualificationError("scoped fixture PF operation failed")
        return result.stdout.strip()

    def snapshot(self):
        return self._run("-sn"), self._run("-sr")

    @staticmethod
    def production_snapshot():
        outputs = []
        for action in ("-sn", "-sr"):
            result = subprocess.run(
                (str(pf.PFCTL), "-a", "com.apple/slipstream", action),
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode:
                raise RouteQualificationError("cannot inspect production PF anchor")
            outputs.append(result.stdout.strip())
        return tuple(outputs)

    def install(self, address: str, directory: Path):
        if address != pf.IPV6_LOOPBACK_TEST_DESTINATION:
            raise RouteQualificationError("unexpected fixture destination")
        if any(self.snapshot()):
            raise RouteQualificationError("fixture PF anchor is already occupied")
        self.before = pf._pf_snapshot(self.runner)
        self.production = self.production_snapshot()
        if not self.before.enabled or not all(self.production):
            raise RouteQualificationError("installed production PF must already be active")
        if 'rdr-anchor "com.apple/*"' not in self.before.nat_rules or 'anchor "com.apple/*"' not in self.before.filter_rules:
            raise RouteQualificationError("expected existing wildcard PF anchors are absent")
        rules = directory / "sentinel.pf.conf"
        rules.write_text(
            f"no rdr on lo0 inet6 proto tcp from any to {address}/128 port 443 tagged {FIXTURE_TAG}\n"
            f"pass out quick on lo0 inet6 proto tcp from any to {address}/128 port 443 user root tag {FIXTURE_TAG} no state\n"
        )
        self.attempted = True
        self._run("-f", str(rules))
        if not all(self.snapshot()):
            raise RouteQualificationError("fixture PF isolation rules were not installed")
        if self.production_snapshot() != self.production:
            raise RouteQualificationError("production PF changed while adding fixture isolation")

    def close(self):
        if not self.attempted:
            return
        errors = []
        for kind in ("rules", "nat"):
            try:
                self._run("-F", kind)
            except Exception as exc:
                errors.append(type(exc).__name__)
        if any(self.snapshot()):
            errors.append("fixture rules survived cleanup")
        if self.production_snapshot() != self.production:
            errors.append("production PF changed")
        pf._assert_same_snapshot(self.before, pf._pf_snapshot(self.runner))
        if errors:
            raise RouteQualificationError("; ".join(errors))


class SystemOrigin:
    def __init__(self):
        self.alias = pf.IPv6LoopbackAliasFixture()
        self.isolation = SentinelPfIsolation()
        self.directory = Path(tempfile.mkdtemp(prefix="slipstream-geph-route-"))
        # The unprivileged client reads only the public certificate; the key is 0600.
        self.directory.chmod(0o711)
        self.certificate = self.directory / "certificate.pem"
        self.server = None
        self.thread = None
        self.lock = threading.Lock()
        self.connections = 0
        self.requests = 0

    def counts(self) -> dict[str, int]:
        with self.lock:
            return {"connections": self.connections, "requests": self.requests}

    def start(self) -> None:
        config = self.directory / "openssl.cnf"
        key = self.directory / "key.pem"
        config.write_text(
            "[req]\ndistinguished_name=subject\nprompt=no\nx509_extensions=extensions\n"
            f"[subject]\nCN={HOST}\n[extensions]\nsubjectAltName=DNS:{HOST}\n"
            "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
        )
        # Precreate with restrictive mode before openssl can write any key bytes.
        key_fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(key_fd)
        result = subprocess.run(("/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1", "-config", str(config), "-keyout", str(key), "-out", str(self.certificate)), capture_output=True, timeout=15)
        if result.returncode:
            raise RouteQualificationError("local control certificate generation failed")
        if stat.S_IMODE(key.stat().st_mode) != 0o600:
            raise RouteQualificationError("local control key permissions changed")
        self.certificate.chmod(0o644)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certificate, key)
        fixture = self

        class Server(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6
            daemon_threads = True

            def get_request(self):
                client, address = super().get_request()
                with fixture.lock:
                    fixture.connections += 1
                client.settimeout(10)
                try:
                    return context.wrap_socket(client, server_side=True), address
                except BaseException:
                    client.close()
                    raise

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                with fixture.lock:
                    fixture.requests += 1
                self.send_response(200)
                self.send_header("Content-Length", str(len(SYSTEM_BODY)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(SYSTEM_BODY)

            def log_message(self, *_args):
                pass

        address = self.alias.install()
        self.isolation.install(address, self.directory)
        self.server = Server((address, 443), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        try:
            if self.server is not None:
                if self.thread is not None and self.thread.is_alive():
                    self.server.shutdown()
                self.server.server_close()
                if self.thread is not None and self.thread.ident is not None:
                    self.thread.join(timeout=2)
        finally:
            try:
                self.isolation.close()
            finally:
                try:
                    self.alias.cleanup()
                finally:
                    for file in self.directory.iterdir():
                        file.unlink()
                    self.directory.rmdir()


def client_probe(destination: str, certificate: Path) -> dict:
    """Fresh verified HTTPS, full bounded body, no redirect/auth replay."""
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=certificate)
    context.set_alpn_protocols(["http/1.1"])
    try:
        with socket.create_connection((destination, 443), timeout=15) as raw:
            with context.wrap_socket(raw, server_hostname=HOST) as tls:
                tls.sendall((f"GET {REQUEST_PATH} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: Slipstream-route-qualification/1\r\nConnection: close\r\n\r\n").encode())
                response = http.client.HTTPResponse(tls)
                response.begin()
                if response.length is not None and response.length > MAX_BODY:
                    raise RouteQualificationError("response too large")
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY or response.length not in (None, 0):
                    raise RouteQualificationError("response incomplete or too large")
                if response.status != 200 or len(body) < 32:
                    raise RouteQualificationError("public canary did not return a complete successful body")
                return {"route": "system" if body == SYSTEM_BODY else "owned", "bytes": len(body), "status": response.status}
    except (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError) as exc:
        return {"route": "closed", "error": type(exc).__name__}


def _probe(origin: SystemOrigin, uid: int, gid: int, *, timeout: float = 25) -> dict:
    result = subprocess.run(
        (sys.executable, str(Path(__file__).resolve()), "--client", origin.alias.address, str(origin.certificate)),
        user=uid, group=gid, extra_groups=[], capture_output=True, text=True, timeout=timeout,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    if result.returncode:
        raise RouteQualificationError("fresh client did not complete (timeout, TLS or HTTP failure)")
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or value.get("route") not in {"owned", "system", "closed"}:
        raise RouteQualificationError("fresh client returned an invalid receipt")
    return value


def _status(read_status: Callable, pid: int | None = None) -> dict:
    status = read_status()
    if not isinstance(status, dict) or status.get("schema_version") != 2:
        raise RouteQualificationError("fresh StatusV2 required")
    daemon = status.get("daemon", {})
    actual_pid = daemon.get("pid")
    if not isinstance(actual_pid, int) or isinstance(actual_pid, bool) or actual_pid <= 0:
        raise RouteQualificationError("installed daemon identity is missing")
    if daemon.get("state") != "active" or not 0 <= time.time() - daemon.get("updated_at", 0) < 15 or (pid is not None and daemon.get("pid") != pid):
        raise RouteQualificationError("installed daemon changed or stopped being fresh/active")
    local = status.get("backends", {}).get("local_engine", {})
    firewall = status.get("environment", {}).get("pf", {})
    if local.get("state") != "ready" or firewall.get("state") != "ready" or not all(firewall.get(key) is True for key in ("applied", "enabled", "rules_loaded")):
        raise RouteQualificationError("installed packet capture is not ready")
    if status.get("environment", {}).get("dns", {}).get("state") != "configured":
        raise RouteQualificationError("fixture requires configured system DNS without Smart DNS")
    return status


def _wait_backend(read_status: Callable, pid: int, up: bool, *, updated_after: float, timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = _status(read_status, pid)
        backend = status.get("backends", {}).get("geph", {})
        if status["daemon"]["updated_at"] <= updated_after:
            time.sleep(0.5)
            continue
        if backend.get("port_conflict"):
            raise RouteQualificationError("Geph port conflict during qualification")
        if up and backend.get("state") == "up" and backend.get("owned"):
            return
        if not up and backend.get("state") in {"off", "down"} and not backend.get("owned"):
            return
        time.sleep(0.5)
    raise RouteQualificationError("installed daemon did not observe backend transition")


def _expect(probe: dict, route: str, origin: SystemOrigin, expected_counts: dict) -> None:
    if probe.get("route") != route or origin.counts() != expected_counts:
        raise RouteQualificationError(f"route invariant failed: expected {route}, observed {probe.get('route')}")


def _wait_owned_payload(origin: SystemOrigin, uid: int, gid: int,
                        read_status: Callable, pid: int, expected_counts: dict,
                        timeout: float = 90) -> dict:
    # The monitor's "up" does not clear the production backend cooldown. Wait
    # through controlled closes; never modify health, timers, or the daemon.
    deadline = time.monotonic() + timeout
    closed = 0
    while time.monotonic() < deadline:
        _status(read_status, pid)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        observed = _probe(origin, uid, gid, timeout=min(25, remaining))
        _status(read_status, pid)
        if time.monotonic() >= deadline:
            break
        if observed.get("route") == "owned":
            _expect(observed, "owned", origin, expected_counts)
            return {**observed, "closed_before_payload": closed}
        _expect(observed, "closed", origin, expected_counts)
        closed += 1
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
    raise RouteQualificationError(
        f"owned payload did not recover after {closed} controlled closures"
    )


def run_qualification(uid: int, gid: int, home: Path, read_status: Callable) -> dict:
    if sys.platform != "darwin" or os.geteuid() != 0 or uid <= 0 or any(os.environ.get(k) != v for k, v in {"CI": "true", "GITHUB_ACTIONS": "true", "SLIPSTREAM_DISPOSABLE_CI": "1"}.items()):
        raise RouteQualificationError("installed route qualification requires disposable macOS CI root")
    if home.stat().st_uid != uid:
        raise RouteQualificationError("console home ownership differs from the staged user")
    paths = geph.geph_paths(home)
    settings = SettingsSnapshot(paths.settings, uid, gid)
    backend = OwnedBackend(paths, uid)
    initial_status = _status(read_status)
    pid = initial_status["daemon"]["pid"]
    origin = SystemOrigin()
    receipt = {"result": "pending", "stage": "local-origin", "probes": [], "system_counts": {}}
    failure = None
    cleanup_errors = []
    try:
        origin.start()
        # Scoped fixture isolation lets root reach lo0: prove the alternate path is live.
        control = client_probe(origin.alias.address, origin.certificate)
        baseline = origin.counts()
        if control.get("route") != "system" or baseline != {"connections": 1, "requests": 1}:
            raise RouteQualificationError("original destination positive control failed")
        receipt["stage"] = "initial-owned"
        geph._wait_for_payload(targets=(geph.PayloadTarget(HOST, REQUEST_PATH),))
        _wait_backend(read_status, pid, True, updated_after=initial_status["daemon"]["updated_at"])
        initial = _wait_owned_payload(origin, uid, gid, read_status, pid, baseline)
        receipt["probes"].append(initial)
        receipt["stage"] = "enabled-outage"
        changed_at = time.time()
        backend.stop()
        _wait_backend(read_status, pid, False, updated_after=changed_at)
        for _ in range(3):
            _status(read_status, pid)
            if _private_bytes(paths.settings, uid) != settings.original:
                raise RouteQualificationError("enabled intent changed during outage")
            observed = _probe(origin, uid, gid)
            receipt["probes"].append(observed)
            _expect(observed, "closed", origin, baseline)
        receipt["stage"] = "enabled-recovery"
        changed_at = time.time()
        backend.start()
        geph._wait_for_payload(targets=(geph.PayloadTarget(HOST, REQUEST_PATH),))
        _wait_backend(read_status, pid, True, updated_after=changed_at)
        recovered = _wait_owned_payload(origin, uid, gid, read_status, pid, baseline)
        receipt["probes"].append(recovered)
        if _private_bytes(paths.settings, uid) != settings.original:
            raise RouteQualificationError("recovery changed enabled intent")
        receipt["stage"] = "disabled-positive-control"
        changed_at = time.time()
        backend.stop()
        _wait_backend(read_status, pid, False, updated_after=changed_at)
        settings.disable()
        disabled = _probe(origin, uid, gid)
        receipt["probes"].append(disabled)
        _expect(disabled, "system", origin, {k: v + 1 for k, v in baseline.items()})
        receipt["result"] = "pass"
    except BaseException as exc:
        failure = exc
    finally:
        receipt["system_counts"] = origin.counts()
        try:
            settings.restore()
            if backend.mutated:
                changed_at = time.time()
                backend.start()
                geph._wait_for_payload(targets=(geph.PayloadTarget(HOST, REQUEST_PATH),))
                _wait_backend(read_status, pid, True, updated_after=changed_at)
                restored = _wait_owned_payload(origin, uid, gid, read_status, pid, receipt["system_counts"])
                receipt["restored_probe"] = restored
            else:
                geph._assert_owned_geph(paths, uid, backend.state)
        except BaseException as exc:
            cleanup_errors.append(_error_receipt(exc))
        try:
            origin.close()
        except BaseException as exc:
            cleanup_errors.append(_error_receipt(exc))
    if failure is not None or cleanup_errors:
        receipt["result"] = "fail"
        receipt["failure"] = _error_receipt(failure)
        receipt["cleanup_errors"] = cleanup_errors
        raise RouteQualificationError(json.dumps(receipt, sort_keys=True)) from failure
    receipt["stage"] = "restored"
    receipt["settings"] = "exact original private bytes restored"
    receipt["daemon_pid_unchanged"] = True
    return receipt


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "--client":
        raise SystemExit("private fixture client only")
    try:
        print(json.dumps(client_probe(sys.argv[2], Path(sys.argv[3]))))
    except Exception as exc:
        # Public receipt contains only the class, never response bodies or credentials.
        print(json.dumps({"error": type(exc).__name__}))
        raise SystemExit(1)

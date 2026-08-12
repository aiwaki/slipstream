#!/usr/bin/env python3
"""Disposable fixture for the composed pending-navigation recovery path."""

from __future__ import annotations

import http.server
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading
import time


FIXTURE_HOST = "pending.slipstream.invalid"
FIXTURE_PUBLIC_IP = "93.184.216.34"
PRODUCTION_BROKER_SOCKET = Path("/var/run/slipstream-browser-probe.sock")
PRODUCTION_WORKER_RUNTIME = Path(
    "/var/run/slipstream-browser-probe-workers"
)
WORKER_ARGUMENT = "--pending-navigation-browser-probe"
WORKER_PROFILE_RE = re.compile(
    r"\Aslipstream-browser-probe-[0-9a-f]{32}\Z"
)
WORKER_RUNTIME_RE = re.compile(
    r"\Adev\.slipstream\.browser-probe\.[0-9a-f]{16}\Z"
)
LAUNCHD_PID_RE = re.compile(r"^\s*pid = ([0-9]+)\s*$", re.MULTILINE)
COMPOSED_READY_MARKER = b"User-agent: slipstream-composed-ready"
MAX_COMPOSED_NAVIGATION_SECONDS = 35.0
IDLE_OBSERVATION_SECONDS = 3.0
MAX_IDLE_CPU_DELTA_SECONDS = 1.0
DAEMON_FIXTURE_HOST_ENV = "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_HOST"
DAEMON_FIXTURE_IP_ENV = "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_IP"
DAEMON_FIXTURE_PORT_ENV = "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_PORT"
DISPOSABLE_QUALIFICATION_ENVIRONMENT_KEYS = frozenset((
    "CI",
    "GITHUB_ACTIONS",
    "SLIPSTREAM_DISPOSABLE_CI",
    "SLIPSTREAM_BROWSER_PROBE_CHROME",
    "SLIPSTREAM_BROWSER_PROBE_ORIGIN",
    "SLIPSTREAM_BROWSER_PROBE_HOST_RESOLVER_RULES",
    "SLIPSTREAM_BROWSER_PROBE_IGNORE_CERTIFICATE_ERRORS",
    DAEMON_FIXTURE_HOST_ENV,
    DAEMON_FIXTURE_IP_ENV,
    DAEMON_FIXTURE_PORT_ENV,
))


class ComposedQualificationError(RuntimeError):
    """A disposable composed-navigation safety or evidence check failed."""


def require_disposable_ci() -> None:
    expected = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
    }
    missing = [
        name for name, value in expected.items() if os.environ.get(name) != value
    ]
    if missing:
        raise ComposedQualificationError(
            "composed navigation qualification requires disposable GitHub "
            f"Actions: missing={missing!r}"
        )


class _ReusableThreadingHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class ComposedHttpsFixture:
    """Make the original and worker requests share one deterministic state."""

    def __init__(self) -> None:
        self._temporary = Path(
            tempfile.mkdtemp(prefix="slipstream-composed-navigation-")
        )
        self._lock = threading.Lock()
        self._release = threading.Event()
        self._second_root = threading.Event()
        self._ready = threading.Event()
        self._servers: list[_ReusableThreadingHTTPServer] = []
        self._threads: list[threading.Thread] = []
        self._records: list[dict[str, object]] = []
        self._counts = {"root": 0, "css": 0, "js": 0, "image": 0, "ready": 0}
        self._worker_port = 0
        self._original_port = 0
        self._started_at = 0.0

    @property
    def worker_port(self) -> int:
        if self._worker_port <= 0:
            raise ComposedQualificationError("fixture is not running")
        return self._worker_port

    @property
    def records(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            return tuple(dict(record) for record in self._records)

    def ready(self) -> bool:
        return self._ready.is_set()

    def _record(self, channel: str, path: str) -> int:
        with self._lock:
            key = {
                "/": "root",
                "/style.css": "css",
                "/app.js": "js",
                "/pixel.svg": "image",
                "/ready": "ready",
            }.get(path)
            if key is not None:
                self._counts[key] += 1
                count = self._counts[key]
            else:
                count = 0
            self._records.append({
                "channel": channel,
                "path": path,
                "count": count,
                "elapsed_ms": int((time.monotonic() - self._started_at) * 1000),
            })
            if key == "root" and count >= 2:
                self._second_root.set()
            if key == "ready":
                self._ready.set()
            return count

    def _certificate(self) -> tuple[Path, Path]:
        config = self._temporary / "openssl.cnf"
        certificate = self._temporary / "certificate.pem"
        key = self._temporary / "key.pem"
        config.write_text(
            "\n".join((
                "[req]",
                "distinguished_name=subject",
                "prompt=no",
                "x509_extensions=extensions",
                "[subject]",
                f"CN={FIXTURE_HOST}",
                "[extensions]",
                f"subjectAltName=DNS:{FIXTURE_HOST}",
                "keyUsage=digitalSignature,keyEncipherment",
                "extendedKeyUsage=serverAuth",
                "",
            )),
            encoding="utf-8",
        )
        result = subprocess.run(
            (
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "1",
                "-config",
                str(config),
                "-keyout",
                str(key),
                "-out",
                str(certificate),
            ),
            capture_output=True,
            timeout=15.0,
            check=False,
        )
        if result.returncode != 0:
            raise ComposedQualificationError(
                "composed fixture certificate generation failed"
            )
        key.chmod(0o600)
        return certificate, key

    def _handler(self, channel: str):
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, content_type: str, payload: bytes) -> None:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
                self.wfile.flush()
                self.close_connection = True

            def do_GET(self) -> None:
                path = self.path.partition("?")[0]
                count = fixture._record(channel, path)
                if path == "/" and count <= 2:
                    fixture._release.wait(MAX_COMPOSED_NAVIGATION_SECONDS + 10.0)
                    self.close_connection = True
                    return
                if path == "/":
                    self._send(
                        "text/html; charset=utf-8",
                        b"<!doctype html><html><head>"
                        b"<link rel='stylesheet' href='/style.css'>"
                        b"</head><body><div id='state'>waiting</div>"
                        b"<img id='proof' src='/pixel.svg' alt='fixture'>"
                        b"<script src='/app.js'></script>"
                        b"</body></html>",
                    )
                elif path == "/style.css":
                    self._send(
                        "text/css; charset=utf-8",
                        b"body{background:#edf7ff;color:#17324d}",
                    )
                elif path == "/app.js":
                    self._send(
                        "application/javascript; charset=utf-8",
                        b"addEventListener('load',()=>{const image="
                        b"document.getElementById('proof');const styled="
                        b"getComputedStyle(document.body).backgroundColor==="
                        b"'rgb(237, 247, 255)';if(image.complete&&"
                        b"image.naturalWidth>0&&styled){document.getElementById("
                        b"'state').textContent='User-agent: "
                        b"slipstream-composed-ready';fetch('/ready',"
                        b"{cache:'no-store'}).catch(()=>{});}});",
                    )
                elif path == "/pixel.svg":
                    self._send(
                        "image/svg+xml",
                        b"<svg xmlns='http://www.w3.org/2000/svg' width='2' "
                        b"height='2'><rect width='2' height='2' fill='#1b84d6'/>"
                        b"</svg>",
                    )
                elif path == "/ready":
                    self._send("text/plain; charset=utf-8", b"")
                else:
                    self.send_error(404)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        return Handler

    @staticmethod
    def _wrap_server(
        address: tuple[str, int],
        handler,
        certificate: Path,
        key: Path,
    ) -> _ReusableThreadingHTTPServer:
        server = _ReusableThreadingHTTPServer(address, handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        return server

    def start(self) -> None:
        require_disposable_ci()
        if self._servers:
            raise ComposedQualificationError("fixture is already running")
        certificate, key = self._certificate()
        try:
            public_server = self._wrap_server(
                ("127.0.0.1", 0),
                self._handler("original"),
                certificate,
                key,
            )
            worker_server = self._wrap_server(
                ("127.0.0.1", 0),
                self._handler("worker"),
                certificate,
                key,
            )
            self._original_port = int(public_server.server_address[1])
            self._worker_port = int(worker_server.server_address[1])
            self._servers = [public_server, worker_server]
            self._started_at = time.monotonic()
            for index, server in enumerate(self._servers):
                thread = threading.Thread(
                    target=server.serve_forever,
                    name=f"slipstream-composed-https-{index}",
                    daemon=True,
                )
                thread.start()
                self._threads.append(thread)
        except BaseException:
            if not self._servers:
                for server in (
                    locals().get("public_server"),
                    locals().get("worker_server"),
                ):
                    if server is not None:
                        server.server_close()
                shutil.rmtree(self._temporary, ignore_errors=True)
            else:
                self.close()
            raise

    def wait_for_second_root(self, timeout: float = 20.0) -> None:
        if not self._second_root.wait(timeout):
            raise ComposedQualificationError(
                "packaged worker did not start its correlated navigation"
            )

    def qualification_environment(
        self,
        chrome_executable: Path,
    ) -> dict[str, str]:
        try:
            chrome = chrome_executable.resolve(strict=True)
        except OSError as error:
            raise ComposedQualificationError(
                f"composed Chrome executable is unavailable: {chrome_executable}"
            ) from error
        if not chrome.is_file() or not os.access(chrome, os.X_OK):
            raise ComposedQualificationError(
                f"composed Chrome executable is not runnable: {chrome}"
            )
        return {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_DISPOSABLE_CI": "1",
            "SLIPSTREAM_BROWSER_PROBE_CHROME": str(chrome),
            "SLIPSTREAM_BROWSER_PROBE_ORIGIN": (
                f"https://{FIXTURE_HOST}:{self.worker_port}/"
            ),
            "SLIPSTREAM_BROWSER_PROBE_HOST_RESOLVER_RULES": (
                f"MAP {FIXTURE_HOST} 127.0.0.1, EXCLUDE localhost"
            ),
            "SLIPSTREAM_BROWSER_PROBE_IGNORE_CERTIFICATE_ERRORS": "1",
            DAEMON_FIXTURE_HOST_ENV: FIXTURE_HOST,
            DAEMON_FIXTURE_IP_ENV: FIXTURE_PUBLIC_IP,
            DAEMON_FIXTURE_PORT_ENV: str(self._original_port),
        }

    def report(self) -> dict[str, object]:
        records = self.records
        roots = [record for record in records if record["path"] == "/"]
        if len(roots) != 3:
            raise ComposedQualificationError(
                f"expected exactly three root requests, observed {len(roots)}"
            )
        if [record["channel"] for record in roots] != [
            "original",
            "worker",
            "original",
        ]:
            raise ComposedQualificationError(
                f"root request composition is wrong: {roots!r}"
            )
        first_ms, worker_ms, retry_ms = [int(record["elapsed_ms"]) for record in roots]
        if worker_ms - first_ms < 7_500 or retry_ms - worker_ms < 7_500:
            raise ComposedQualificationError(
                f"pending observation windows were bypassed: {roots!r}"
            )
        expected = {"css": 1, "js": 1, "image": 1, "ready": 1}
        observed = {key: self._counts[key] for key in expected}
        if observed != expected or not self._ready.is_set():
            raise ComposedQualificationError(
                f"styled completion evidence is incomplete: {observed!r}"
            )
        return {
            "root_requests": len(roots),
            "root_channels": [record["channel"] for record in roots],
            "worker_started_ms": worker_ms,
            "original_retry_ms": retry_ms,
            "css_requests": observed["css"],
            "javascript_requests": observed["js"],
            "image_requests": observed["image"],
            "ready_callbacks": observed["ready"],
        }

    def close(self) -> None:
        self._release.set()
        for index, server in enumerate(self._servers):
            if index < len(self._threads):
                server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=3.0)
            if thread.is_alive():
                raise ComposedQualificationError(
                    "composed HTTPS fixture survived cleanup"
                )
        self._servers.clear()
        self._threads.clear()
        self._worker_port = 0
        self._original_port = 0
        shutil.rmtree(self._temporary, ignore_errors=True)

    def __enter__(self) -> "ComposedHttpsFixture":
        self.start()
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


def original_navigation_command(
    chrome_executable: Path,
    profile_directory: Path,
) -> tuple[str, ...]:
    return (
        str(chrome_executable),
        "--headless",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-features=MediaRouter,OptimizationHints,Translate",
        "--disable-quic",
        "--disable-sync",
        "--ignore-certificate-errors",
        "--metrics-recording-only",
        "--no-default-browser-check",
        "--no-first-run",
        "--no-proxy-server",
        "--password-store=basic",
        f"--host-resolver-rules=MAP {FIXTURE_HOST} {FIXTURE_PUBLIC_IP}, "
        "EXCLUDE localhost",
        f"--user-data-dir={profile_directory}",
        f"--timeout={int(MAX_COMPOSED_NAVIGATION_SECONDS * 1000)}",
        "--dump-dom",
        f"https://{FIXTURE_HOST}/",
    )


def _worker_profiles(root: Path = Path("/tmp")) -> tuple[Path, ...]:
    try:
        entries = tuple(root.iterdir())
    except FileNotFoundError:
        return ()
    return tuple(
        path for path in entries if WORKER_PROFILE_RE.fullmatch(path.name)
    )


def _worker_processes(uid: int) -> tuple[int, ...]:
    result = subprocess.run(
        ("/bin/ps", "-axo", "pid=,uid=,command="),
        capture_output=True,
        text=True,
        timeout=10.0,
        check=False,
    )
    if result.returncode != 0:
        raise ComposedQualificationError("browser worker process scan failed")
    matches = []
    for raw_line in result.stdout.splitlines():
        fields = raw_line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        try:
            pid = int(fields[0])
            observed_uid = int(fields[1])
        except ValueError:
            continue
        if observed_uid == uid and fields[2].endswith(f" {WORKER_ARGUMENT}"):
            matches.append(pid)
    return tuple(sorted(matches))


def _cpu_seconds(value: str) -> float:
    fields = value.strip().split(":")
    if len(fields) not in {2, 3}:
        raise ComposedQualificationError(f"invalid daemon CPU time: {value!r}")
    try:
        numbers = [float(field) for field in fields]
    except ValueError as error:
        raise ComposedQualificationError(
            f"invalid daemon CPU time: {value!r}"
        ) from error
    if len(numbers) == 2:
        minutes, seconds = numbers
        return minutes * 60.0 + seconds
    hours, minutes, seconds = numbers
    return hours * 3600.0 + minutes * 60.0 + seconds


def _daemon_cpu_seconds(pid: int) -> float:
    result = subprocess.run(
        ("/bin/ps", "-p", str(pid), "-o", "time="),
        capture_output=True,
        text=True,
        timeout=10.0,
        check=False,
    )
    if result.returncode != 0:
        raise ComposedQualificationError("daemon CPU sample failed")
    if not result.stdout.strip():
        raise ComposedQualificationError("daemon disappeared during idle sample")
    return _cpu_seconds(result.stdout)


def _assert_broker_socket(uid: int) -> None:
    try:
        metadata = os.lstat(PRODUCTION_BROKER_SOCKET)
    except OSError as error:
        raise ComposedQualificationError(
            "production pending-navigation broker is unavailable"
        ) from error
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ComposedQualificationError(
            "production pending-navigation broker ownership is not exact"
        )


def assert_worker_idle(uid: int, daemon_pid: int) -> dict[str, object]:
    """Measure the normal idle boundary before the first browser job."""
    require_disposable_ci()
    deadline = time.monotonic() + 10.0
    while True:
        try:
            _assert_broker_socket(uid)
            break
        except ComposedQualificationError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    baseline_profiles = _worker_profiles()
    if baseline_profiles:
        raise ComposedQualificationError(
            f"browser worker profiles predate the idle sample: {baseline_profiles!r}"
        )
    if PRODUCTION_WORKER_RUNTIME.exists() and any(
        PRODUCTION_WORKER_RUNTIME.iterdir()
    ):
        raise ComposedQualificationError(
            "browser worker runtime is non-empty before a live job"
        )
    if _worker_processes(uid):
        raise ComposedQualificationError(
            "browser worker process exists before a live job"
        )
    before = _daemon_cpu_seconds(daemon_pid)
    time.sleep(IDLE_OBSERVATION_SECONDS)
    after = _daemon_cpu_seconds(daemon_pid)
    delta = max(0.0, after - before)
    if delta > MAX_IDLE_CPU_DELTA_SECONDS:
        raise ComposedQualificationError(
            f"idle daemon consumed {delta:.3f}s CPU during the sample"
        )
    if _worker_profiles() or _worker_processes(uid):
        raise ComposedQualificationError(
            "idle daemon started a browser worker without a live job"
        )
    return {
        "observation_ms": int(IDLE_OBSERVATION_SECONDS * 1000),
        "daemon_cpu_delta_ms": int(delta * 1000),
        "worker_processes": 0,
        "worker_profiles": 0,
        "broker_mode": "0600",
    }


def assert_worker_clean(uid: int, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        runtime_empty = (
            not PRODUCTION_WORKER_RUNTIME.exists()
            or not any(PRODUCTION_WORKER_RUNTIME.iterdir())
        )
        if runtime_empty and not _worker_profiles() and not _worker_processes(uid):
            return
        time.sleep(0.1)
    raise ComposedQualificationError(
        "packaged browser worker left process, profile, or runtime residue"
    )


def assert_worker_active(uid: int, *, timeout: float = 5.0) -> dict[str, object]:
    """Prove one exact worker and its browser are live before uninstall."""
    require_disposable_ci()
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = worker_diagnostics(uid)
        processes = tuple(last.get("processes") or ())
        profiles = tuple(last.get("profiles") or ())
        runtime = tuple(last.get("runtime") or ())
        if len(processes) == len(profiles) == len(runtime) == 1:
            launch = runtime[0]
            label = launch.get("name") if isinstance(launch, dict) else None
            entries = launch.get("entries") if isinstance(launch, dict) else None
            if (
                isinstance(label, str)
                and WORKER_RUNTIME_RE.fullmatch(label) is not None
                and launch.get("owner") == uid
                and launch.get("mode") == "0700"
                and entries == (
                    "worker.plist",
                    "worker.stderr.log",
                    "worker.stdout.log",
                )
            ):
                result = subprocess.run(
                    ("/bin/launchctl", "print", f"gui/{uid}/{label}"),
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                    check=False,
                )
                match = LAUNCHD_PID_RE.search(result.stdout)
                if (
                    result.returncode == 0
                    and match is not None
                    and int(match.group(1)) == processes[0]
                ):
                    return {
                        "worker_processes": 1,
                        "worker_profiles": 1,
                        "worker_runtime_directories": 1,
                        "launchagent": "loaded",
                    }
        time.sleep(0.1)
    raise ComposedQualificationError(
        f"packaged browser worker was not provably active: {last!r}"
    )


def worker_diagnostics(uid: int) -> dict[str, object]:
    """Return bounded ownership metadata for a timed-out disposable worker."""
    processes = _worker_processes(uid)
    profiles = tuple(path.name for path in _worker_profiles())
    runtime = []
    try:
        directories = tuple(PRODUCTION_WORKER_RUNTIME.iterdir())
    except FileNotFoundError:
        directories = ()
    except OSError as error:
        return {
            "processes": processes,
            "profiles": profiles,
            "runtime_error": type(error).__name__,
        }
    for directory in directories[:8]:
        if WORKER_RUNTIME_RE.fullmatch(directory.name) is None:
            runtime.append({"name": "unexpected"})
            continue
        try:
            metadata = os.lstat(directory)
            entries = tuple(sorted(path.name for path in directory.iterdir()))
        except OSError as error:
            runtime.append({
                "name": directory.name,
                "error": type(error).__name__,
            })
            continue
        runtime.append({
            "name": directory.name,
            "owner": metadata.st_uid,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "entries": entries[:8],
        })
    return {
        "processes": processes,
        "profiles": profiles,
        "runtime": tuple(runtime),
    }

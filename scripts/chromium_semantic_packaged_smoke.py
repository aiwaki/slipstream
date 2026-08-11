#!/usr/bin/env python3
"""Qualify the packaged Chromium semantic route path on disposable macOS CI.

The harness composes the real unpacked extension, packaged native host,
owner-only daemon socket, packaged root daemon, and an already-qualified
account-backed owned Geph. Local HTTPS pages provide deterministic semantic
denial, incomplete-response, pending-navigation, and styled-success states.
The pending-navigation fixture observes and forwards the exact privacy-bounded
v3 native message before emulating the correlated relay close; route-learning
scenarios independently confirm the same hostname through real Geph.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import http.server
import json
import os
import plistlib
import pwd
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import geph_owned_lifecycle_smoke as geph_smoke
import pf_anchor_smoke as pf
import pf_installed_lifecycle_smoke as lifecycle


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXTENSION = ROOT / "browser-companion" / "chromium"
NATIVE_HOST_NAME = "dev.slipstream.semantic"
NATIVE_HOST_ORIGIN = "chrome-extension://cecdingohhpfggapnlbghppcegbaciam/"
NATIVE_HOST_RELATIVE_PATH = Path(
    "Library/Application Support/Google/Chrome/NativeMessagingHosts"
) / f"{NATIVE_HOST_NAME}.json"
CHROME_FOR_TESTING_NATIVE_HOST_RELATIVE_PATH = Path(
    "Library/Application Support/Google/ChromeForTesting/NativeMessagingHosts"
) / f"{NATIVE_HOST_NAME}.json"
PROFILE_NATIVE_HOST_RELATIVE_PATH = (
    Path("NativeMessagingHosts") / f"{NATIVE_HOST_NAME}.json"
)
NATIVE_MESSAGE_TAP_RUNTIME_RELATIVE_PATH = Path(
    "Library/Application Support/dev.slipstream.tray/qualification"
)
SEMANTIC_SOCKET = Path("/var/run/slipstream-semantic.sock")
AUTO_GEPH_STATE = lifecycle.AUTO_GEPH_STATE_PATH
FIXTURE_HOST = "example.org"
INCOMPLETE_FIXTURE_HOST = "example.net"
PENDING_NAVIGATION_FIXTURE_HOST = "example.edu"
REGIONAL_DENIAL_SCENARIO = "regional_denial"
INCOMPLETE_RESPONSE_SCENARIO = "incomplete_response"
PENDING_NAVIGATION_SCENARIO = "navigation_pending"
FIXTURE_SCENARIOS = frozenset(
    (
        REGIONAL_DENIAL_SCENARIO,
        INCOMPLETE_RESPONSE_SCENARIO,
        PENDING_NAVIGATION_SCENARIO,
    )
)
STYLED_MARKER = "SLIPSTREAM_SEMANTIC_STYLED_READY"
CHROME_TIMEOUT = 55.0
PENDING_NAVIGATION_SIGNAL_TIMEOUT = 20.0
PENDING_NAVIGATION_MIN_DELAY_MS = 8_000
PENDING_NAVIGATION_CONFIDENCE_BPS = 10_000
NATIVE_MESSAGE_MAX_BODY = 64 * 1024
NATIVE_MESSAGE_FORWARD_TIMEOUT = 15.0
PENDING_NAVIGATION_SIGNAL_KEYS = frozenset(
    (
        "category",
        "confidence_bps",
        "host",
        "observed_at_unix_ms",
        "request_started_at_unix_ms",
        "schema_version",
        "signal_id",
        "source",
        "top_level",
    )
)
CHROME_JOB_PREFIX = "dev.slipstream.chromium-semantic"
DEVTOOLS_ACTIVE_PORT = "DevToolsActivePort"
DEVTOOLS_TIMEOUT = 15.0
MAX_DEVTOOLS_RESPONSE = 64 * 1024
MAX_WEBSOCKET_HEADERS = 16 * 1024
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WORKER_READY_EXPRESSION = """
(async () => {
  if (globalThis.__slipstreamWorkerReadyV1 !== true) {
    return {ready: false, stage: "worker_marker_missing"};
  }
  try {
    const response = await chrome.runtime.sendNativeMessage(
      "dev.slipstream.semantic",
      {
        schema_version: 0,
        source: "qualification_worker_ready",
        phase: "native_ready"
      }
    );
    const ready = response !== null && typeof response === "object";
    return {
      ready,
      stage: ready ? "native_response_received" : "native_response_invalid"
    };
  } catch (error) {
    const message = String(error && error.message || "").toLowerCase();
    let stage = "native_host_error";
    if (message.includes("host not found")) {
      stage = "native_host_not_found";
    } else if (message.includes("forbidden")) {
      stage = "native_host_forbidden";
    } else if (message.includes("exited")) {
      stage = "native_host_exited";
    } else if (message.includes("communication")) {
      stage = "native_host_communication_failed";
    }
    return {ready: false, stage};
  }
})()
""".strip()
WORKER_READY_STAGES = frozenset(
    {
        "worker_marker_missing",
        "native_response_received",
        "native_response_invalid",
        "native_host_not_found",
        "native_host_forbidden",
        "native_host_exited",
        "native_host_communication_failed",
        "native_host_error",
    }
)


class QualificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class FixtureSnapshot:
    root_visits: int
    css_requests: int
    script_requests: int
    image_requests: int
    ready_requests: int
    pending_navigation_signals: int = 0
    pending_navigation_error: str | None = None


@dataclass(frozen=True)
class ChromeLaunch:
    target: str
    pid: int
    process_group: int


@dataclass(frozen=True)
class ChromeProcess:
    pid: int
    process_group: int
    command: str


@dataclass
class ChromeOwnership:
    process_groups: set[int]


@dataclass(frozen=True)
class NativeHostRegistration:
    path: Path
    created_directories: tuple[Path, ...]


@dataclass(frozen=True)
class NativeMessageTap:
    runtime_directory: Path
    executable: Path
    manifest: Path
    capture: Path
    status: Path
    created_directories: tuple[Path, ...]


def _require_disposable_ci() -> tuple[int, int]:
    required = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
    }
    if any(os.environ.get(key) != value for key, value in required.items()):
        raise QualificationError(
            "Chromium semantic qualification requires disposable GitHub Actions"
        )
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise QualificationError(
            "Chromium semantic qualification requires sudo on disposable macOS"
        )
    try:
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ["SUDO_GID"])
    except (KeyError, ValueError) as exc:
        raise QualificationError("SUDO_UID/SUDO_GID must identify the login user") from exc
    if uid <= 0 or gid < 0:
        raise QualificationError("SUDO_UID must identify a non-root user")
    return uid, gid


def _run(
    command: tuple[str, ...],
    *,
    check: bool = True,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        detail = (result.stdout + "\n" + result.stderr).strip().splitlines()[-20:]
        raise QualificationError(
            f"command failed ({result.returncode}): {command[0]}\n"
            + "\n".join(detail)
        )
    return result


def _read_private_bytes(path: Path, expected_uid: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
            or metadata.st_size > 64 * 1024
        ):
            raise QualificationError(f"{path} is not a bounded owner-private file")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 16 * 1024))
            if not chunk:
                raise QualificationError(f"{path} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise QualificationError(f"{path} changed while being read")
    finally:
        os.close(fd)
    return b"".join(chunks)


def _decode_json_object(payload: bytes, path: Path) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError(f"{path} does not contain valid JSON") from exc
    if not isinstance(value, dict):
        raise QualificationError(f"{path} does not contain a JSON object")
    return value


def _read_private_json(path: Path, expected_uid: int) -> dict[str, object]:
    return _decode_json_object(_read_private_bytes(path, expected_uid), path)


def _validate_pending_navigation_signal(
    payload: dict[str, object],
    expected_host: str,
) -> None:
    if set(payload) != PENDING_NAVIGATION_SIGNAL_KEYS:
        raise QualificationError(
            "pending-navigation signal contains non-contract fields"
        )
    if (
        payload.get("schema_version") != 3
        or payload.get("source") != "browser_extension"
        or payload.get("host") != expected_host
        or payload.get("category") != PENDING_NAVIGATION_SCENARIO
        or payload.get("confidence_bps") != PENDING_NAVIGATION_CONFIDENCE_BPS
        or payload.get("top_level") is not True
    ):
        raise QualificationError("pending-navigation signal metadata is invalid")
    signal_id = payload.get("signal_id")
    observed_at = payload.get("observed_at_unix_ms")
    request_started_at = payload.get("request_started_at_unix_ms")
    if (
        not isinstance(signal_id, str)
        or len(signal_id) != 32
        or any(character not in "0123456789abcdef" for character in signal_id)
        or type(observed_at) is not int
        or type(request_started_at) is not int
        or request_started_at <= 0
        or observed_at < request_started_at + PENDING_NAVIGATION_MIN_DELAY_MS
    ):
        raise QualificationError("pending-navigation signal timing is invalid")


def _pending_navigation_tap_source(
    target_executable: Path,
    capture: Path,
    status: Path,
    interpreter: Path,
) -> bytes:
    target = json.dumps(str(target_executable))
    destination = json.dumps(str(capture))
    status_path = json.dumps(str(status))
    return (
        f"#!{interpreter}\n"
        "import fcntl, json, os, struct, subprocess, sys\n"
        f"TARGET = {target}\n"
        f"CAPTURE = {destination}\n"
        f"STATUS = {status_path}\n"
        "STATUS_LOCK = f'{STATUS}.lock'\n"
        "STAGE_RANK = {\n"
        "    'host_started': 0,\n"
        "    'message_read': 1,\n"
        "    'child_started': 2,\n"
        "    'child_timeout': 3,\n"
        "    'child_completed': 3,\n"
        "    'empty_child_response': 3,\n"
        "    'response_forwarded': 4,\n"
        "    'ack_published': 5,\n"
        "}\n"
        "def write_private(path, body):\n"
        "    temporary = f'{path}.{os.getpid()}.tmp'\n"
        "    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n"
        "    try:\n"
        "        remaining = memoryview(body)\n"
        "        while remaining:\n"
        "            written = os.write(fd, remaining)\n"
        "            if written <= 0:\n"
        "                raise SystemExit(5)\n"
        "            remaining = remaining[written:]\n"
        "        os.fsync(fd)\n"
        "    finally:\n"
        "        os.close(fd)\n"
        "    os.replace(temporary, path)\n"
        "def mark(stage, **fields):\n"
        "    lock_fd = os.open(\n"
        "        STATUS_LOCK, os.O_RDWR | os.O_CREAT, 0o600\n"
        "    )\n"
        "    try:\n"
        "        fcntl.flock(lock_fd, fcntl.LOCK_EX)\n"
        "        try:\n"
        "            with open(STATUS, 'rb') as stream:\n"
        "                previous = json.loads(stream.read())\n"
        "        except (FileNotFoundError, OSError, ValueError):\n"
        "            previous = {}\n"
        "        attempts = previous.get('attempts', 0)\n"
        "        if type(attempts) is not int or attempts < 0:\n"
        "            attempts = 0\n"
        "        if stage == 'host_started':\n"
        "            attempts += 1\n"
        "        previous_rank = previous.get('stage_rank', -1)\n"
        "        if type(previous_rank) is not int:\n"
        "            previous_rank = -1\n"
        "        stage_rank = STAGE_RANK[stage]\n"
        "        if previous_rank > stage_rank:\n"
        "            fields = previous\n"
        "        fields['attempts'] = attempts\n"
        "        fields['stage'] = fields.get('stage', stage)\n"
        "        fields['stage_rank'] = fields.get('stage_rank', stage_rank)\n"
        "        write_private(STATUS, json.dumps(\n"
        "            fields, sort_keys=True, separators=(',', ':')\n"
        "        ).encode())\n"
        "    finally:\n"
        "        fcntl.flock(lock_fd, fcntl.LOCK_UN)\n"
        "        os.close(lock_fd)\n"
        "def read_exact(stream, size):\n"
        "    data = bytearray()\n"
        "    while len(data) < size:\n"
        "        chunk = stream.read(size - len(data))\n"
        "        if not chunk:\n"
        "            raise SystemExit(2)\n"
        "        data.extend(chunk)\n"
        "    return bytes(data)\n"
        "mark('host_started', argv_count=len(sys.argv) - 1)\n"
        "header = read_exact(sys.stdin.buffer, 4)\n"
        "length = struct.unpack('=I', header)[0]\n"
        f"if length <= 0 or length > {NATIVE_MESSAGE_MAX_BODY}:\n"
        "    raise SystemExit(3)\n"
        "body = read_exact(sys.stdin.buffer, length)\n"
        "payload = json.loads(body)\n"
        "category = payload.get('category') if isinstance(payload, dict) else None\n"
        "mark('message_read', argv_count=len(sys.argv) - 1, "
        "body_bytes=len(body), category=category)\n"
        "child = subprocess.Popen(\n"
        "    [TARGET, *sys.argv[1:]],\n"
        "    stdin=subprocess.PIPE,\n"
        "    stdout=subprocess.PIPE,\n"
        "    stderr=subprocess.DEVNULL,\n"
        ")\n"
        "mark('child_started', child_pid=child.pid, category=category)\n"
        "try:\n"
        "    output, _ = child.communicate(\n"
        f"        header + body, timeout={NATIVE_MESSAGE_FORWARD_TIMEOUT!r}\n"
        "    )\n"
        "except subprocess.TimeoutExpired:\n"
        "    child.kill()\n"
        "    child.communicate()\n"
        "    mark('child_timeout', category=category)\n"
        "    raise SystemExit(4)\n"
        "mark('child_completed', category=category, "
        "child_returncode=child.returncode, child_output_bytes=len(output))\n"
        "if child.returncode != 0:\n"
        "    raise SystemExit(child.returncode)\n"
        "if not output:\n"
        "    mark('empty_child_response', category=category)\n"
        "    raise SystemExit(6)\n"
        "sys.stdout.buffer.write(output)\n"
        "sys.stdout.buffer.flush()\n"
        "mark('response_forwarded', category=category, "
        "child_output_bytes=len(output))\n"
        "if payload.get('category') == 'navigation_pending':\n"
        "    write_private(CAPTURE, body)\n"
        "    mark('ack_published', category=category, "
        "child_output_bytes=len(output))\n"
        "raise SystemExit(0)\n"
    ).encode("utf-8")


def _create_pending_navigation_tap(
    home: Path,
    profile: Path,
    uid: int,
    gid: int,
    target_executable: Path,
) -> NativeMessageTap:
    runtime_parent, created_directories = _ensure_owner_directory_path(
        home,
        NATIVE_MESSAGE_TAP_RUNTIME_RELATIVE_PATH,
        uid,
        gid,
    )
    runtime_directory = runtime_parent / profile.name
    try:
        runtime_directory.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise QualificationError(
            "pending-navigation native host runtime already exists"
        ) from exc
    os.chown(runtime_directory, uid, gid)
    runtime_directory.chmod(0o700)
    created_directories = (*created_directories, runtime_directory)
    executable = runtime_directory / "pending-navigation-native-host.py"
    manifest = runtime_directory / "pending-navigation-native-host.json"
    capture = runtime_directory / "pending-navigation-signal.json"
    status = runtime_directory / "pending-navigation-native-host-status.json"
    interpreter = Path(sys.executable).resolve(strict=True)
    tap = NativeMessageTap(
        runtime_directory,
        executable,
        manifest,
        capture,
        status,
        created_directories,
    )
    try:
        _write_owner_private_file(
            executable,
            _pending_navigation_tap_source(
                target_executable,
                capture,
                status,
                interpreter,
            ),
            uid,
            gid,
        )
        executable.chmod(0o700)
        _write_owner_private_file(
            manifest,
            json.dumps(
                {
                    "allowed_origins": [NATIVE_HOST_ORIGIN],
                    "name": NATIVE_HOST_NAME,
                    "path": str(executable),
                    "type": "stdio",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
            uid,
            gid,
        )
    except BaseException:
        _remove_native_message_tap(tap, uid)
        raise
    return tap


def _is_exact_native_host(
    payload: dict[str, object],
    expected_executable: Path,
) -> bool:
    return (
        payload.get("name") == NATIVE_HOST_NAME
        and payload.get("path") == str(expected_executable)
        and payload.get("type") == "stdio"
        and payload.get("allowed_origins") == [NATIVE_HOST_ORIGIN]
    )


def _fixture_response(
    path: str,
    *,
    root_visit: int,
    scenario: str = REGIONAL_DENIAL_SCENARIO,
) -> tuple[int, str, bytes]:
    if path == "/":
        if root_visit == 1:
            if scenario == REGIONAL_DENIAL_SCENARIO:
                body = (
                    "<!doctype html><html><head>"
                    "<title>Unavailable in your area</title></head>"
                    "<body><main>This content is no longer available in your area"
                    "</main></body></html>"
                ).encode("utf-8")
            elif scenario == INCOMPLETE_RESPONSE_SCENARIO:
                body = (
                    "<!doctype html><html><head><title>Loading</title></head>"
                    "<body><main>Incomplete response fixture</main></body></html>"
                ).encode("utf-8")
            else:
                raise QualificationError(f"unknown fixture scenario: {scenario}")
        else:
            body = (
                "<!doctype html><html><head><title>Semantic route ready</title>"
                '<link rel="stylesheet" href="/style.css"></head>'
                '<body><main id="result">waiting</main>'
                '<img id="proof-image" src="/proof.svg" alt="proof">'
                '<script src="/app.js"></script></body></html>'
            ).encode("utf-8")
        return 200, "text/html; charset=utf-8", body
    if path == "/style.css":
        return (
            200,
            "text/css; charset=utf-8",
            (
                "body{background:rgb(235,244,255);color:rgb(18,30,48);"
                "font-family:system-ui,sans-serif}main{font-size:24px}"
            ).encode("utf-8"),
        )
    if path == "/app.js":
        return (
            200,
            "text/javascript; charset=utf-8",
            (
                "addEventListener('load',()=>{"
                "const image=document.getElementById('proof-image');"
                "const styled=getComputedStyle(document.body).backgroundColor"
                "==='rgb(235, 244, 255)';"
                "if(image.complete&&image.naturalWidth>0&&styled){"
                f"document.getElementById('result').textContent='{STYLED_MARKER}';"
                "document.documentElement.dataset.slipstreamReady='true';"
                "fetch('/ready',{cache:'no-store'}).catch(()=>{});"
                "}});"
            ).encode("utf-8"),
        )
    if path == "/proof.svg":
        return (
            200,
            "image/svg+xml",
            (
                '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32">'
                '<rect width="32" height="32" fill="#4f7cff"/></svg>'
            ).encode("utf-8"),
        )
    if path == "/ready":
        return 204, "text/plain; charset=utf-8", b""
    return 404, "text/plain; charset=utf-8", b"not found\n"


def _fixture_content_length(
    path: str,
    *,
    root_visit: int,
    scenario: str,
    body: bytes,
) -> int:
    if (
        scenario == INCOMPLETE_RESPONSE_SCENARIO
        and path == "/"
        and root_visit == 1
    ):
        return len(body) + 4096
    return len(body)


class SemanticHttpsFixture:
    def __init__(
        self,
        host: str = FIXTURE_HOST,
        scenario: str = REGIONAL_DENIAL_SCENARIO,
    ) -> None:
        if scenario not in FIXTURE_SCENARIOS:
            raise QualificationError(f"unknown fixture scenario: {scenario}")
        self.host = host
        self.scenario = scenario
        self.directory: Path | None = None
        self.server: http.server.ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.root_visits = 0
        self.css_requests = 0
        self.script_requests = 0
        self.image_requests = 0
        self.ready_requests = 0
        self.pending_navigation_signals = 0
        self.pending_navigation_error: str | None = None
        self.pending_navigation_capture: Path | None = None
        self.pending_navigation_uid: int | None = None

    @property
    def port(self) -> int:
        if self.server is None:
            raise QualificationError("semantic HTTPS fixture is not running")
        return int(self.server.server_address[1])

    def _certificate(self, directory: Path) -> tuple[Path, Path]:
        config = directory / "openssl.cnf"
        certificate = directory / "certificate.pem"
        key = directory / "key.pem"
        config.write_text(
            "\n".join(
                (
                    "[req]",
                    "distinguished_name=subject",
                    "prompt=no",
                    "x509_extensions=extensions",
                    "[subject]",
                    f"CN={self.host}",
                    "[extensions]",
                    f"subjectAltName=DNS:{self.host}",
                    "keyUsage=digitalSignature,keyEncipherment",
                    "extendedKeyUsage=serverAuth",
                    "",
                )
            ),
            encoding="utf-8",
        )
        _run(
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
            )
        )
        key.chmod(0o600)
        return certificate, key

    def start(self) -> None:
        if self.server is not None:
            raise QualificationError("semantic HTTPS fixture is already running")
        self.directory = Path(tempfile.mkdtemp(prefix="slipstream-semantic-https-"))
        certificate, key = self._certificate(self.directory)
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                path = self.path.partition("?")[0]
                with fixture.lock:
                    if path == "/":
                        fixture.root_visits += 1
                        root_visit = fixture.root_visits
                    else:
                        root_visit = fixture.root_visits
                    if path == "/style.css":
                        fixture.css_requests += 1
                    elif path == "/app.js":
                        fixture.script_requests += 1
                    elif path == "/proof.svg":
                        fixture.image_requests += 1
                    elif path == "/ready":
                        fixture.ready_requests += 1
                if (
                    fixture.scenario == PENDING_NAVIGATION_SCENARIO
                    and path == "/"
                    and root_visit == 1
                ):
                    try:
                        payload = fixture._wait_for_pending_navigation_signal()
                        _validate_pending_navigation_signal(payload, fixture.host)
                    except QualificationError as exc:
                        with fixture.lock:
                            fixture.pending_navigation_error = str(exc)
                    else:
                        with fixture.lock:
                            fixture.pending_navigation_signals += 1
                    self.close_connection = True
                    return
                status, content_type, body = _fixture_response(
                    path,
                    root_visit=root_visit,
                    scenario=fixture.scenario,
                )
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header(
                    "Content-Length",
                    str(
                        _fixture_content_length(
                            path,
                            root_visit=root_visit,
                            scenario=fixture.scenario,
                            body=body,
                        )
                    ),
                )
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                # BaseHTTPRequestHandler does not infer connection state from
                # response headers on an HTTP/1.1 keep-alive request.
                self.close_connection = True

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
            name="semantic-https-fixture",
        )
        self.thread.start()

    def arm_pending_navigation_tap(self, capture: Path, uid: int) -> None:
        if self.scenario != PENDING_NAVIGATION_SCENARIO:
            raise QualificationError("native-message tap is only valid for pending navigation")
        self.pending_navigation_capture = capture
        self.pending_navigation_uid = uid

    def _wait_for_pending_navigation_signal(self) -> dict[str, object]:
        capture = self.pending_navigation_capture
        uid = self.pending_navigation_uid
        if capture is None or uid is None:
            raise QualificationError("pending-navigation native-message tap is not armed")
        deadline = time.monotonic() + PENDING_NAVIGATION_SIGNAL_TIMEOUT
        last_error: BaseException | None = None
        while time.monotonic() < deadline:
            try:
                return _read_private_json(capture, uid)
            except FileNotFoundError:
                pass
            except (OSError, QualificationError, ValueError) as exc:
                last_error = exc
            time.sleep(0.05)
        raise QualificationError(
            f"pending-navigation signal was not captured: {last_error}"
        )

    def snapshot(self) -> FixtureSnapshot:
        with self.lock:
            return FixtureSnapshot(
                root_visits=self.root_visits,
                css_requests=self.css_requests,
                script_requests=self.script_requests,
                image_requests=self.image_requests,
                ready_requests=self.ready_requests,
                pending_navigation_signals=self.pending_navigation_signals,
                pending_navigation_error=self.pending_navigation_error,
            )

    def close(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=3)
        self.server = None
        self.thread = None
        if self.directory is not None:
            shutil.rmtree(self.directory, ignore_errors=True)
        self.directory = None


def _validate_extension(path: Path) -> Path:
    path = path.expanduser().resolve(strict=True)
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        manifest.get("manifest_version") != 3
        or manifest.get("permissions")
        != ["nativeMessaging", "storage", "webRequest"]
        or manifest.get("host_permissions") != ["https://*/*"]
        or not isinstance(manifest.get("key"), str)
        or not manifest["key"]
    ):
        raise QualificationError("Chromium companion manifest is not the reviewed shape")
    for name in ("detector.js", "content.js", "service-worker.js", "service-worker-core.js"):
        if not (path / name).is_file():
            raise QualificationError(f"Chromium companion is missing {name}")
    return path


def _validate_chrome_for_testing(path: Path) -> Path:
    path = path.expanduser().resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise QualificationError(f"Chrome for Testing is not runnable: {path}")
    result = _run((str(path), "--version"), check=False)
    version = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode != 0 or "Google Chrome for Testing" not in version:
        raise QualificationError(
            "semantic qualification requires Google Chrome for Testing; "
            "branded Chrome 137+ ignores --load-extension"
        )
    return path


def _wait_for_native_host(
    home: Path,
    expected_executable: Path,
    uid: int,
    *,
    timeout: float = 20.0,
) -> Path:
    path = home / NATIVE_HOST_RELATIVE_PATH
    deadline = time.monotonic() + timeout
    last_error = "manifest absent"
    while time.monotonic() < deadline:
        try:
            payload = _read_private_json(path, uid)
            if _is_exact_native_host(payload, expected_executable):
                return path
            last_error = f"invalid manifest metadata or payload: {payload!r}"
        except (FileNotFoundError, OSError, ValueError, QualificationError) as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise QualificationError(f"packaged native host did not register: {last_error}")


def _remove_exact_native_host(
    path: Path,
    expected_executable: Path,
    uid: int,
) -> None:
    payload = _read_private_json(path, uid)
    if not _is_exact_native_host(payload, expected_executable):
        raise QualificationError("refusing to remove a foreign native host manifest")
    path.unlink()
    if path.exists():
        raise QualificationError("owned native host manifest survived cleanup")


def _wait_for_semantic_socket(uid: int, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last = "absent"
    while time.monotonic() < deadline:
        try:
            metadata = SEMANTIC_SOCKET.lstat()
            if (
                stat.S_ISSOCK(metadata.st_mode)
                and metadata.st_uid == uid
                and stat.S_IMODE(metadata.st_mode) == 0o600
            ):
                return
            last = (
                f"mode={stat.S_IMODE(metadata.st_mode):04o} "
                f"uid={metadata.st_uid}"
            )
        except OSError as exc:
            last = str(exc)
        time.sleep(0.25)
    raise QualificationError(f"owner-only semantic socket is unavailable: {last}")


def _wait_for_owned_geph_backend(*, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = lifecycle._read_status()
        backends = last.get("backends") if isinstance(last, dict) else None
        geph = backends.get("geph") if isinstance(backends, dict) else None
        if (
            isinstance(geph, dict)
            and geph.get("state") == "up"
            and geph.get("owned") is True
            and not geph.get("port_conflict")
        ):
            return
        time.sleep(0.5)
    raise QualificationError(f"daemon did not admit the owned Geph backend: {last!r}")


def _chrome_command(
    executable: Path,
    profile: Path,
    extension: Path,
    fixture_port: int,
    fixture_host: str = FIXTURE_HOST,
) -> tuple[str, ...]:
    return (
        str(executable),
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-features=MediaRouter,OptimizationHints,Translate",
        "--disable-quic",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-default-browser-check",
        "--no-first-run",
        "--no-proxy-server",
        "--new-window",
        "--password-store=basic",
        "--ignore-certificate-errors",
        f"--disable-extensions-except={extension}",
        f"--load-extension={extension}",
        f"--host-resolver-rules=MAP {fixture_host} 127.0.0.1, EXCLUDE localhost",
        "--remote-debugging-port=0",
        f"--user-data-dir={profile}",
        "about:blank",
    )


def _chrome_app_bundle(executable: Path) -> Path:
    try:
        bundle = executable.parents[2]
    except IndexError as exc:
        raise QualificationError(
            f"Chrome executable is not inside an application bundle: {executable}"
        ) from exc
    info = bundle / "Contents" / "Info.plist"
    if not info.is_file():
        raise QualificationError(
            f"Chrome executable has no application bundle metadata: {executable}"
        )
    return bundle


def _launchservices_app_bundle(
    executable: Path,
    profile: Path,
    uid: int,
    gid: int,
) -> Path:
    bundle = _chrome_app_bundle(executable).resolve(strict=True)
    if bundle.suffix.lower() == ".app":
        return bundle

    wrapper = profile / "Chrome for Testing.app"
    if wrapper.exists() or wrapper.is_symlink():
        raise QualificationError(
            f"private LaunchServices application wrapper already exists: {wrapper}"
        )
    shutil.copytree(
        bundle,
        wrapper,
        symlinks=True,
        copy_function=shutil.copy2,
    )
    for root, directories, files in os.walk(wrapper, followlinks=False):
        os.chown(root, uid, gid, follow_symlinks=False)
        for name in (*directories, *files):
            os.chown(Path(root) / name, uid, gid, follow_symlinks=False)
    wrapper.chmod(0o700)
    if not (wrapper / "Contents" / "Info.plist").is_file():
        raise QualificationError(
            f"LaunchServices application wrapper has no bundle metadata: {wrapper}"
        )
    return wrapper


def _launchservices_executable(
    source_executable: Path,
    application_bundle: Path,
) -> Path:
    source_bundle = _chrome_app_bundle(source_executable).resolve(strict=True)
    try:
        relative = source_executable.resolve(strict=True).relative_to(source_bundle)
    except ValueError as exc:
        raise QualificationError(
            "Chrome executable escaped its validated application bundle"
        ) from exc
    executable = application_bundle / relative
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise QualificationError(
            f"LaunchServices application executable is unavailable: {executable}"
        )
    return executable


def _chrome_open_command(
    executable: Path,
    profile: Path,
    extension: Path,
    fixture_port: int,
    stdout_path: Path,
    stderr_path: Path,
    application_bundle: Path | None = None,
    fixture_host: str = FIXTURE_HOST,
) -> tuple[str, ...]:
    chrome = _chrome_command(
        executable,
        profile,
        extension,
        fixture_port,
        fixture_host,
    )
    return (
        "/usr/bin/open",
        "-n",
        "-W",
        "-j",
        "--stdout",
        str(stdout_path),
        "--stderr",
        str(stderr_path),
        "-a",
        str(application_bundle or _chrome_app_bundle(executable)),
        "--args",
        *chrome[1:],
    )


def _chrome_launch_agent_payload(
    label: str,
    environment: dict[str, str],
    home: Path,
    chrome_stdout_path: Path,
    chrome_stderr_path: Path,
    launcher_stdout_path: Path,
    launcher_stderr_path: Path,
    executable: Path,
    profile: Path,
    extension: Path,
    fixture_port: int,
    application_bundle: Path | None = None,
    fixture_host: str = FIXTURE_HOST,
) -> dict[str, object]:
    return {
        "Label": label,
        "ProgramArguments": list(
            _chrome_open_command(
                executable,
                profile,
                extension,
                fixture_port,
                chrome_stdout_path,
                chrome_stderr_path,
                application_bundle,
                fixture_host,
            )
        ),
        "RunAtLoad": True,
        "ProcessType": "Interactive",
        "LimitLoadToSessionType": "Aqua",
        "AbandonProcessGroup": False,
        "WorkingDirectory": str(home),
        "EnvironmentVariables": dict(environment),
        "StandardOutPath": str(launcher_stdout_path),
        "StandardErrorPath": str(launcher_stderr_path),
    }


def _write_owner_private_file(
    path: Path,
    payload: bytes,
    uid: int,
    gid: int,
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = os.open(path, flags, 0o600)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise QualificationError(f"private file write made no progress: {path}")
            remaining = remaining[written:]
        os.fsync(fd)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _read_owner_private_tail(path: Path, uid: int, limit: int = 4000) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise QualificationError(f"{path} is not an owner-private capture")
        length = min(metadata.st_size, limit)
        return os.pread(fd, length, max(0, metadata.st_size - length))
    finally:
        os.close(fd)


def _read_owner_bounded_file(
    path: Path,
    uid: int,
    limit: int = MAX_DEVTOOLS_RESPONSE,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != uid
            or mode & 0o022
            or metadata.st_size <= 0
            or metadata.st_size > limit
        ):
            raise QualificationError(f"{path} is not a bounded owner-controlled file")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 16 * 1024))
            if not chunk:
                raise QualificationError(f"{path} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise QualificationError(f"{path} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _parse_devtools_active_port(payload: bytes) -> int:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise QualificationError("DevToolsActivePort is not ASCII") from exc
    if (
        len(lines) != 2
        or not lines[0].isdigit()
        or not lines[1].startswith("/devtools/browser/")
    ):
        raise QualificationError("DevToolsActivePort has an invalid shape")
    port = int(lines[0])
    if port <= 0 or port > 65_535:
        raise QualificationError("DevToolsActivePort exposes an invalid port")
    return port


def _wait_for_devtools_port(
    profile: Path,
    uid: int,
    *,
    timeout: float = DEVTOOLS_TIMEOUT,
) -> int:
    path = profile / DEVTOOLS_ACTIVE_PORT
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            return _parse_devtools_active_port(
                _read_owner_bounded_file(path, uid)
            )
        except (FileNotFoundError, QualificationError, OSError) as exc:
            last_error = exc
        time.sleep(0.1)
    raise QualificationError(
        f"Chrome did not publish an owner-controlled DevTools endpoint: {last_error}"
    )


def _devtools_json(
    port: int,
    path: str,
    *,
    method: str = "GET",
) -> object:
    if port <= 0 or port > 65_535 or not path.startswith("/"):
        raise QualificationError("refusing an invalid DevTools endpoint")
    url = f"http://127.0.0.1:{port}{path}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, method=method)
    with opener.open(request, timeout=2.0) as response:
        if response.geturl() != url:
            raise QualificationError("DevTools redirected outside its exact endpoint")
        payload = response.read(MAX_DEVTOOLS_RESPONSE + 1)
    if len(payload) > MAX_DEVTOOLS_RESPONSE:
        raise QualificationError("DevTools response exceeded its bounded limit")
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError("DevTools returned invalid JSON") from exc


def _worker_debugger_path(url: str, expected_port: int) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "ws"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != expected_port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path.startswith("/devtools/")
    ):
        raise QualificationError("worker debugger URL escaped the exact loopback endpoint")
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def _receive_until(
    connection: socket.socket,
    delimiter: bytes,
    limit: int,
) -> tuple[bytes, bytes]:
    payload = bytearray()
    while delimiter not in payload:
        chunk = connection.recv(min(4096, limit - len(payload) + 1))
        if not chunk:
            raise QualificationError("worker debugger closed during handshake")
        payload.extend(chunk)
        if len(payload) > limit:
            raise QualificationError("worker debugger handshake exceeded its limit")
    head, remainder = bytes(payload).split(delimiter, 1)
    return head, remainder


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise QualificationError("worker debugger closed before a complete frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _connect_worker_debugger(url: str, expected_port: int) -> socket.socket:
    path = _worker_debugger_path(url, expected_port)
    connection = socket.create_connection(("127.0.0.1", expected_port), timeout=2.0)
    try:
        connection.settimeout(2.0)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{expected_port}\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "\r\n"
        ).encode("ascii")
        connection.sendall(request)
        raw_headers, remainder = _receive_until(
            connection,
            b"\r\n\r\n",
            MAX_WEBSOCKET_HEADERS,
        )
        if remainder:
            raise QualificationError(
                "worker debugger sent data before the protocol request"
            )
        lines = raw_headers.decode("iso-8859-1").split("\r\n")
        status = lines[0].split(" ", 2) if lines else []
        if len(status) < 2 or status[0] != "HTTP/1.1" or status[1] != "101":
            raise QualificationError("worker debugger rejected the WebSocket upgrade")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if not separator:
                raise QualificationError("worker debugger returned malformed headers")
            normalized = name.strip().lower()
            if normalized in headers:
                raise QualificationError("worker debugger returned duplicate headers")
            headers[normalized] = value.strip()
        expected_accept = base64.b64encode(
            hashlib.sha1(
                f"{key}{WEBSOCKET_GUID}".encode("ascii"),
                usedforsecurity=False,
            ).digest()
        ).decode("ascii")
        if (
            headers.get("upgrade", "").lower() != "websocket"
            or "upgrade"
            not in {
                token.strip().lower()
                for token in headers.get("connection", "").split(",")
            }
            or headers.get("sec-websocket-accept") != expected_accept
        ):
            raise QualificationError("worker debugger returned an invalid upgrade")
        return connection
    except BaseException:
        connection.close()
        raise


def _send_websocket_json(connection: socket.socket, value: object) -> None:
    payload = json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(payload) > MAX_DEVTOOLS_RESPONSE:
        raise QualificationError("worker debugger request exceeded its limit")
    mask = os.urandom(4)
    if len(payload) < 126:
        header = bytes((0x81, 0x80 | len(payload)))
    else:
        header = bytes((0x81, 0xFE)) + struct.pack("!H", len(payload))
    masked = bytes(
        byte ^ mask[index % len(mask)]
        for index, byte in enumerate(payload)
    )
    connection.sendall(header + mask + masked)


def _receive_websocket_json(connection: socket.socket) -> object:
    header = _receive_exact(connection, 2)
    final = bool(header[0] & 0x80)
    opcode = header[0] & 0x0F
    masked = bool(header[1] & 0x80)
    length = header[1] & 0x7F
    if not final or masked or opcode != 0x1:
        raise QualificationError("worker debugger returned an unsupported frame")
    if length == 126:
        length = struct.unpack("!H", _receive_exact(connection, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _receive_exact(connection, 8))[0]
    if length > MAX_DEVTOOLS_RESPONSE:
        raise QualificationError("worker debugger frame exceeded its limit")
    payload = _receive_exact(connection, length)
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError("worker debugger returned invalid JSON") from exc


def _devtools_command(
    debugger_url: str,
    port: int,
    method: str,
    params: dict[str, object],
) -> dict[str, object]:
    connection = _connect_worker_debugger(debugger_url, port)
    try:
        _send_websocket_json(
            connection,
            {
                "id": 1,
                "method": method,
                "params": params,
            },
        )
        for _ in range(20):
            response = _receive_websocket_json(connection)
            if not isinstance(response, dict) or response.get("id") != 1:
                continue
            error = response.get("error")
            if error is not None:
                raise QualificationError(
                    f"DevTools command {method!r} failed: {error!r}"
                )
            result = response.get("result")
            if not isinstance(result, dict):
                raise QualificationError(
                    f"DevTools command {method!r} returned no result"
                )
            return result
        raise QualificationError(
            f"DevTools omitted the response for command {method!r}"
        )
    finally:
        connection.close()


def _worker_runtime_probe(debugger_url: str, port: int) -> tuple[bool, str]:
    result = _devtools_command(
        debugger_url,
        port,
        "Runtime.evaluate",
        {
            "expression": WORKER_READY_EXPRESSION,
            "returnByValue": True,
            "awaitPromise": True,
        },
    )
    evaluation = result.get("result")
    if not isinstance(evaluation, dict) or evaluation.get("type") != "object":
        return False, "invalid_devtools_result"
    value = evaluation.get("value")
    if not isinstance(value, dict):
        return False, "invalid_devtools_result"
    ready = value.get("ready")
    stage = value.get("stage")
    if not isinstance(ready, bool) or stage not in WORKER_READY_STAGES:
        return False, "invalid_devtools_result"
    return ready, stage


def _worker_runtime_ready(debugger_url: str, port: int) -> bool:
    return _worker_runtime_probe(debugger_url, port)[0]


def _wait_for_extension_worker(
    profile: Path,
    uid: int,
    *,
    timeout: float = DEVTOOLS_TIMEOUT,
) -> int:
    port = _wait_for_devtools_port(profile, uid, timeout=timeout)
    expected_url = f"{NATIVE_HOST_ORIGIN}service-worker.js"
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            targets = _devtools_json(port, "/json/list")
            if not isinstance(targets, list):
                raise QualificationError("DevTools target list is not an array")
            matching = [
                target
                for target in targets
                if (
                    isinstance(target, dict)
                    and target.get("type") == "service_worker"
                    and target.get("url") == expected_url
                )
            ]
            if len(matching) > 1:
                raise QualificationError(
                    "DevTools exposed duplicate Slipstream service workers"
                )
            if len(matching) == 1:
                debugger_url = matching[0].get("webSocketDebuggerUrl")
                if not isinstance(debugger_url, str):
                    raise QualificationError(
                        "Slipstream service worker has no debugger endpoint"
                    )
                ready, stage = _worker_runtime_probe(debugger_url, port)
                if ready:
                    return port
                last_error = QualificationError(
                    "exact Slipstream service worker is not runtime-ready: "
                    f"{stage}"
                )
            else:
                last_error = QualificationError(
                    "exact Slipstream service worker is not runtime-ready: "
                    "worker_target_missing"
                )
        except (OSError, QualificationError) as exc:
            last_error = exc
        time.sleep(0.1)
    raise QualificationError(
        f"Chrome did not start the exact Slipstream service worker: {last_error}"
    )


def _open_fixture_with_devtools(port: int, fixture: SemanticHttpsFixture) -> None:
    target_url = (
        f"https://{fixture.host}:{fixture.port}/"
        "?slipstream-semantic=1"
    )
    targets = _devtools_json(port, "/json/list")
    if not isinstance(targets, list):
        raise QualificationError("DevTools target list is not an array")
    pages = [
        target
        for target in targets
        if (
            isinstance(target, dict)
            and target.get("type") == "page"
            and target.get("url") == "about:blank"
        )
    ]
    if len(pages) != 1:
        raise QualificationError(
            "DevTools did not expose exactly one owned about:blank page"
        )
    debugger_url = pages[0].get("webSocketDebuggerUrl")
    if not isinstance(debugger_url, str):
        raise QualificationError("owned about:blank page has no debugger endpoint")
    result = _devtools_command(
        debugger_url,
        port,
        "Page.navigate",
        {"url": target_url},
    )
    if not isinstance(result.get("frameId"), str) or not result["frameId"]:
        raise QualificationError("DevTools did not navigate the owned page")
    error_text = result.get("errorText")
    if error_text not in (None, ""):
        raise QualificationError(
            f"DevTools rejected the semantic fixture navigation: {error_text!r}"
        )


def _launch_agent_pid(target: str) -> int | None:
    result = _run(("/bin/launchctl", "print", target), check=False)
    if result.returncode != 0:
        return None
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("pid = "):
            try:
                pid = int(line.removeprefix("pid = "))
            except ValueError as exc:
                raise QualificationError(
                    f"Chrome LaunchAgent exposed an invalid pid: {line!r}"
                ) from exc
            return pid if pid > 0 else None
    return None


def _process_identity(pid: int) -> tuple[int, int]:
    result = _run(
        ("/bin/ps", "-p", str(pid), "-o", "uid=,pgid="),
        check=False,
    )
    fields = result.stdout.strip().split()
    if result.returncode != 0 or len(fields) != 2:
        raise QualificationError(f"cannot verify Chrome process identity for pid {pid}")
    try:
        uid, process_group = (int(field) for field in fields)
    except ValueError as exc:
        raise QualificationError(
            f"Chrome process identity is invalid for pid {pid}: {fields!r}"
        ) from exc
    if process_group <= 0:
        raise QualificationError(f"Chrome process group is invalid for pid {pid}")
    return uid, process_group


def _owned_chrome_processes(
    uid: int,
    executable: Path,
    profile: Path,
    ownership: ChromeOwnership | None = None,
) -> tuple[ChromeProcess, ...]:
    executable = executable.resolve(strict=True)
    bundle = _chrome_app_bundle(executable).resolve(strict=True)
    profile_argument = f"--user-data-dir={profile}"
    main_prefix = f"{executable} "
    helper_prefix = f"{bundle}/Contents/Frameworks/"
    result = _run(
        ("/bin/ps", "-ww", "-axo", "pid=,uid=,pgid=,command="),
        check=False,
    )
    if result.returncode != 0:
        raise QualificationError("cannot enumerate exact Chrome processes")

    candidates: list[tuple[ChromeProcess, bool, bool]] = []
    for raw_line in result.stdout.splitlines():
        fields = raw_line.strip().split(None, 3)
        if len(fields) != 4:
            continue
        try:
            pid, observed_uid, process_group = (
                int(fields[0]),
                int(fields[1]),
                int(fields[2]),
            )
        except ValueError:
            continue
        command = fields[3]
        is_main = command == str(executable) or command.startswith(main_prefix)
        if (
            observed_uid != uid
            or process_group <= 0
            or not (is_main or command.startswith(helper_prefix))
        ):
            continue
        candidates.append(
            (
                ChromeProcess(pid, process_group, command),
                profile_argument in command.split(),
                is_main,
            )
        )

    rooted_groups = {
        process.process_group
        for process, has_profile_argument, is_main in candidates
        if has_profile_argument and is_main
    }
    if ownership is not None:
        ownership.process_groups.update(rooted_groups)
        rooted_groups.update(ownership.process_groups)
    matches = [
        process
        for process, has_profile_argument, is_main in candidates
        if (
            (is_main and has_profile_argument)
            or (not is_main and process.process_group in rooted_groups)
        )
    ]
    return tuple(sorted(matches, key=lambda process: process.pid))


def _wait_for_owned_chrome_process(
    uid: int,
    executable: Path,
    profile: Path,
    ownership: ChromeOwnership | None = None,
    *,
    timeout: float = 15.0,
) -> ChromeProcess:
    executable_prefix = f"{executable.resolve(strict=True)} "
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        main = tuple(
            process
            for process in _owned_chrome_processes(
                uid,
                executable,
                profile,
                ownership,
            )
            if process.command == str(executable)
            or process.command.startswith(executable_prefix)
        )
        if len(main) == 1:
            return main[0]
        if len(main) > 1:
            raise QualificationError(
                "fresh Chrome profile is owned by multiple browser processes"
            )
        time.sleep(0.1)
    raise QualificationError("LaunchServices did not publish the exact Chrome process")


def _owned_chrome_process_alive(
    expected: ChromeProcess,
    uid: int,
    executable: Path,
    profile: Path,
    ownership: ChromeOwnership | None = None,
) -> bool:
    return any(
        process == expected
        for process in _owned_chrome_processes(
            uid,
            executable,
            profile,
            ownership,
        )
    )


def _signal_owned_chrome_processes(
    uid: int,
    executable: Path,
    profile: Path,
    signal_number: int,
    ownership: ChromeOwnership | None = None,
) -> None:
    observed = _owned_chrome_processes(uid, executable, profile, ownership)
    for process in reversed(observed):
        if not _owned_chrome_process_alive(
            process,
            uid,
            executable,
            profile,
            ownership,
        ):
            continue
        try:
            os.kill(process.pid, signal_number)
        except ProcessLookupError:
            continue


def _wait_for_owned_chrome_absence(
    uid: int,
    executable: Path,
    profile: Path,
    ownership: ChromeOwnership | None = None,
    *,
    timeout: float = 5.0,
    settle_time: float = 0.0,
) -> bool:
    deadline = time.monotonic() + timeout
    absent_since: float | None = None
    while True:
        now = time.monotonic()
        if now >= deadline:
            return False
        if _owned_chrome_processes(uid, executable, profile, ownership):
            absent_since = None
        else:
            if absent_since is None:
                absent_since = now
            if now - absent_since >= settle_time:
                return True
        time.sleep(0.1)


def _stop_owned_chrome_processes(
    uid: int,
    executable: Path,
    profile: Path,
    ownership: ChromeOwnership | None = None,
    *,
    timeout: float = 5.0,
    settle_time: float = 0.0,
) -> None:
    if ownership is None:
        ownership = ChromeOwnership(set())
    _signal_owned_chrome_processes(
        uid,
        executable,
        profile,
        signal.SIGTERM,
        ownership,
    )
    if not _wait_for_owned_chrome_absence(
        uid,
        executable,
        profile,
        ownership,
        timeout=timeout,
        settle_time=settle_time,
    ):
        _signal_owned_chrome_processes(
            uid,
            executable,
            profile,
            signal.SIGKILL,
            ownership,
        )
        if not _wait_for_owned_chrome_absence(
            uid,
            executable,
            profile,
            ownership,
            timeout=timeout,
            settle_time=settle_time,
        ):
            raise QualificationError(
                "exact LaunchServices Chrome processes survived cleanup"
            )


def _bootstrap_chrome_launch_agent(
    uid: int,
    label: str,
    plist_path: Path,
    *,
    timeout: float = 10.0,
) -> ChromeLaunch:
    target = f"gui/{uid}/{label}"
    if _run(("/bin/launchctl", "print", target), check=False).returncode == 0:
        raise QualificationError(f"Chrome LaunchAgent already exists: {target}")

    try:
        _run(("/bin/launchctl", "bootstrap", f"gui/{uid}", str(plist_path)))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pid = _launch_agent_pid(target)
            if pid is not None:
                observed_uid, process_group = _process_identity(pid)
                if observed_uid != uid:
                    raise QualificationError(
                        "Chrome LaunchAgent started with the wrong identity: "
                        f"expected uid={uid}, observed uid={observed_uid}"
                    )
                return ChromeLaunch(target, pid, process_group)
            time.sleep(0.1)
        raise QualificationError(f"Chrome LaunchAgent did not publish a pid: {target}")
    except BaseException:
        _run(("/bin/launchctl", "kill", "SIGKILL", target), check=False)
        _run(("/bin/launchctl", "bootout", target), check=False)
        try:
            _wait_for_launch_agent_absence(target)
        except Exception as cleanup_exc:
            raise QualificationError(
                f"Chrome LaunchAgent bootstrap cleanup failed: {target}"
            ) from cleanup_exc
        raise


def _wait_for_launch_agent_absence(target: str, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _run(("/bin/launchctl", "print", target), check=False)
        if lifecycle.launchd_job_absent(result):
            return
        time.sleep(0.1)
    raise QualificationError(f"Chrome LaunchAgent survived bootout: {target}")


def _stop_chrome_launch_agent(
    launch: ChromeLaunch,
    *,
    uid: int,
    gid: int,
    supplementary_groups: tuple[int, ...],
    executable: Path,
    profile: Path,
    ownership: ChromeOwnership | None = None,
    post_bootout_settle_time: float = 0.0,
) -> None:
    if ownership is None:
        ownership = ChromeOwnership(set())
    browser_error: Exception | None = None
    try:
        _stop_owned_chrome_processes(
            uid,
            executable,
            profile,
            ownership,
        )
    except Exception as exc:
        browser_error = exc

    launchd_error: Exception | None = None
    for signal_name in ("SIGTERM", "SIGKILL"):
        _run(
            ("/bin/launchctl", "kill", signal_name, launch.target),
            check=False,
        )
        _run(("/bin/launchctl", "bootout", launch.target), check=False)
        try:
            _wait_for_launch_agent_absence(launch.target)
            launchd_error = None
            break
        except Exception as exc:
            launchd_error = exc

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        members = lifecycle._chrome_process_group_members(launch.process_group)
        if not any(member.uid == uid for member in members):
            break
        time.sleep(0.1)
    else:
        lifecycle._signal_owned_chrome_processes(
            launch.process_group,
            signal.SIGKILL,
            uid=uid,
            gid=gid,
            supplementary_groups=supplementary_groups,
        )
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            members = lifecycle._chrome_process_group_members(launch.process_group)
            if not any(member.uid == uid for member in members):
                break
            time.sleep(0.1)
        else:
            raise QualificationError(
                "Chrome process group survived exact LaunchAgent cleanup: "
                f"{launch.process_group}"
            )

    if post_bootout_settle_time > 0:
        try:
            _stop_owned_chrome_processes(
                uid,
                executable,
                profile,
                ownership,
                timeout=10.0,
                settle_time=post_bootout_settle_time,
            )
        except Exception as exc:
            if browser_error is None:
                browser_error = exc

    if launchd_error is not None:
        members = lifecycle._chrome_process_group_members(launch.process_group)
        if any(member.uid == uid for member in members):
            raise QualificationError(
                "Chrome LaunchAgent and process group survived cleanup: "
                f"{launch.target}"
            ) from launchd_error
        raise QualificationError(
            f"Chrome LaunchAgent survived exact cleanup: {launch.target}"
        ) from launchd_error
    if _owned_chrome_processes(uid, executable, profile, ownership):
        raise QualificationError(
            "exact LaunchServices Chrome processes appeared after cleanup"
        )
    if browser_error is not None:
        raise QualificationError(
            "exact LaunchServices Chrome process cleanup could not be verified"
        ) from browser_error


def _wait_for_learned_host(host: str, *, timeout: float = 30.0) -> float:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = _read_private_json(AUTO_GEPH_STATE, 0)
            expiry = last.get(host) if isinstance(last, dict) else None
            if isinstance(expiry, (int, float)) and not isinstance(expiry, bool):
                if float(expiry) > time.time():
                    return float(expiry)
        except FileNotFoundError:
            pass
        time.sleep(0.25)
    raise QualificationError(f"semantic route was not learned for {host}: {last!r}")


def _remove_owned_profile(profile: Path) -> None:
    shutil.rmtree(profile)
    if profile.exists():
        raise QualificationError("fresh Chrome profile survived cleanup")


def _copy_exact_native_host(
    source: Path,
    destination: Path,
    uid: int,
    gid: int,
    expected_executable: Path,
) -> Path:
    payload = _read_private_bytes(source, uid)
    manifest = _decode_json_object(payload, source)
    if not _is_exact_native_host(manifest, expected_executable):
        raise QualificationError("refusing to copy a foreign native host manifest")
    fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise QualificationError("native host copy made no progress")
            remaining = remaining[written:]
        os.fsync(fd)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    if destination.read_bytes() != payload:
        raise QualificationError("native host copy differs from source manifest")
    return destination


def _install_profile_native_host(
    profile: Path,
    source: Path,
    uid: int,
    gid: int,
    expected_executable: Path,
) -> Path:
    destination = profile / PROFILE_NATIVE_HOST_RELATIVE_PATH
    destination.parent.mkdir(mode=0o700)
    os.chown(destination.parent, uid, gid)
    return _copy_exact_native_host(
        source,
        destination,
        uid,
        gid,
        expected_executable,
    )


def _require_owner_directory(path: Path, uid: int, description: str) -> None:
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise QualificationError(f"{description} is not owner-controlled: {path}")


def _ensure_owner_directory_path(
    home: Path,
    relative: Path,
    uid: int,
    gid: int,
) -> tuple[Path, tuple[Path, ...]]:
    current = home
    created: list[Path] = []
    for component in relative.parts:
        current = current / component
        try:
            _require_owner_directory(
                current,
                uid,
                "Chrome for Testing native host directory",
            )
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            os.chown(current, uid, gid)
            current.chmod(0o700)
            created.append(current)
            _require_owner_directory(
                current,
                uid,
                "Chrome for Testing native host directory",
            )
    return current, tuple(created)


def _install_chrome_for_testing_native_host(
    home: Path,
    source: Path,
    uid: int,
    gid: int,
    expected_executable: Path,
) -> NativeHostRegistration:
    relative_parent = CHROME_FOR_TESTING_NATIVE_HOST_RELATIVE_PATH.parent
    directory, created = _ensure_owner_directory_path(
        home,
        relative_parent,
        uid,
        gid,
    )
    destination = directory / CHROME_FOR_TESTING_NATIVE_HOST_RELATIVE_PATH.name
    try:
        _copy_exact_native_host(
            source,
            destination,
            uid,
            gid,
            expected_executable,
        )
    except BaseException:
        for created_directory in reversed(created):
            created_directory.rmdir()
        raise
    return NativeHostRegistration(destination, created)


def _remove_chrome_for_testing_native_host(
    registration: NativeHostRegistration,
    expected_executable: Path,
    uid: int,
) -> None:
    _remove_exact_native_host(registration.path, expected_executable, uid)
    for directory in reversed(registration.created_directories):
        _require_owner_directory(
            directory,
            uid,
            "Chrome for Testing native host directory",
        )
        try:
            directory.rmdir()
        except OSError as exc:
            if exc.errno == errno.ENOTEMPTY:
                break
            raise


def _remove_native_message_tap(tap: NativeMessageTap, uid: int) -> None:
    if (
        not tap.created_directories
        or tap.created_directories[-1] != tap.runtime_directory
    ):
        raise QualificationError(
            "native message tap runtime is not the final created directory"
        )
    expected_paths = (
        tap.executable,
        tap.manifest,
        tap.capture,
        tap.status,
        Path(f"{tap.status}.lock"),
    )
    if any(path.parent != tap.runtime_directory for path in expected_paths):
        raise QualificationError("native message tap escaped its runtime")
    try:
        _require_owner_directory(
            tap.runtime_directory,
            uid,
            "native message tap runtime",
        )
    except FileNotFoundError:
        pass
    else:
        shutil.rmtree(tap.runtime_directory)
        if tap.runtime_directory.exists():
            raise QualificationError("native message tap runtime survived cleanup")
    for directory in reversed(tap.created_directories[:-1]):
        try:
            _require_owner_directory(
                directory,
                uid,
                "native message tap parent",
            )
        except FileNotFoundError:
            continue
        try:
            directory.rmdir()
        except OSError as exc:
            if exc.errno == errno.ENOTEMPTY:
                break
            raise


def _run_chrome(
    uid: int,
    gid: int,
    extension: Path,
    fixture: SemanticHttpsFixture,
    executable: Path,
    native_host_manifest: Path,
    native_host_executable: Path,
) -> FixtureSnapshot:
    executable = executable.resolve(strict=True)
    environment, home = lifecycle._user_environment(uid)
    supplementary_groups = lifecycle._user_supplementary_groups(uid, gid)
    profile = Path(tempfile.mkdtemp(prefix="slipstream-semantic-chrome-"))
    stdout_path = profile / "chrome.stdout"
    stderr_path = profile / "chrome.stderr"
    launcher_stdout_path = profile / "launcher.stdout"
    launcher_stderr_path = profile / "launcher.stderr"
    plist_path = profile / "chrome-launch-agent.plist"
    label = f"{CHROME_JOB_PREFIX}.{os.getpid()}"
    launch: ChromeLaunch | None = None
    browser: ChromeProcess | None = None
    ownership = ChromeOwnership(set())
    bootstrap_started = False
    native_host_registration: NativeHostRegistration | None = None
    native_message_tap: NativeMessageTap | None = None
    registered_native_host_executable = native_host_executable
    registered_native_host_manifest = native_host_manifest
    native_tap_status: Path | None = None
    snapshot: FixtureSnapshot | None = None
    failure: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        os.chown(profile, uid, gid)
        profile.chmod(0o700)
        application_bundle = _launchservices_app_bundle(
            executable,
            profile,
            uid,
            gid,
        )
        executable = _launchservices_executable(
            executable,
            application_bundle,
        )
        if fixture.scenario == PENDING_NAVIGATION_SCENARIO:
            tap = _create_pending_navigation_tap(
                home,
                profile,
                uid,
                gid,
                native_host_executable,
            )
            native_message_tap = tap
            fixture.arm_pending_navigation_tap(tap.capture, uid)
            registered_native_host_executable = tap.executable
            registered_native_host_manifest = tap.manifest
            native_tap_status = tap.status
        native_host_registration = _install_chrome_for_testing_native_host(
            home,
            registered_native_host_manifest,
            uid,
            gid,
            registered_native_host_executable,
        )
        _install_profile_native_host(
            profile,
            registered_native_host_manifest,
            uid,
            gid,
            registered_native_host_executable,
        )
        _write_owner_private_file(stdout_path, b"", uid, gid)
        _write_owner_private_file(stderr_path, b"", uid, gid)
        _write_owner_private_file(launcher_stdout_path, b"", uid, gid)
        _write_owner_private_file(launcher_stderr_path, b"", uid, gid)
        payload = _chrome_launch_agent_payload(
            label,
            environment,
            home,
            stdout_path,
            stderr_path,
            launcher_stdout_path,
            launcher_stderr_path,
            executable,
            profile,
            extension,
            fixture.port,
            application_bundle,
            fixture.host,
        )
        _write_owner_private_file(
            plist_path,
            plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True),
            uid,
            gid,
        )
        bootstrap_started = True
        launch = _bootstrap_chrome_launch_agent(
            uid,
            label,
            plist_path,
        )
        browser = _wait_for_owned_chrome_process(
            uid,
            executable,
            profile,
            ownership,
        )
        devtools_port = _wait_for_extension_worker(profile, uid)
        _open_fixture_with_devtools(devtools_port, fixture)

        deadline = time.monotonic() + CHROME_TIMEOUT
        while time.monotonic() < deadline:
            snapshot = fixture.snapshot()
            if snapshot.ready_requests == 1:
                break
            if snapshot.ready_requests > 1:
                raise QualificationError(
                    f"Chrome emitted duplicate semantic ready callbacks: {snapshot!r}"
                )
            if (
                _launch_agent_pid(launch.target) != launch.pid
                or not _owned_chrome_process_alive(
                    browser,
                    uid,
                    executable,
                    profile,
                    ownership,
                )
            ):
                raise QualificationError(
                    "LaunchServices Chrome exited before semantic completion"
                )
            time.sleep(0.1)
        else:
            raise QualificationError(
                f"Chrome semantic page timed out with fixture evidence: "
                f"{fixture.snapshot()!r}"
            )
    except BaseException as exc:
        failure = exc
    finally:
        profile_cleanup_safe = not bootstrap_started
        try:
            if launch is not None:
                _stop_chrome_launch_agent(
                    launch,
                    uid=uid,
                    gid=gid,
                    supplementary_groups=supplementary_groups,
                    executable=executable,
                    profile=profile,
                    ownership=ownership,
                    post_bootout_settle_time=5.0 if browser is None else 0.0,
                )
                profile_cleanup_safe = True
            elif bootstrap_started:
                partial_errors: list[Exception] = []
                try:
                    _wait_for_launch_agent_absence(f"gui/{uid}/{label}")
                except Exception as exc:
                    partial_errors.append(exc)
                try:
                    _stop_owned_chrome_processes(
                        uid,
                        executable,
                        profile,
                        ownership,
                        timeout=10.0,
                        settle_time=5.0,
                    )
                except Exception as exc:
                    partial_errors.append(exc)
                if partial_errors:
                    raise QualificationError(
                        "partial Chrome bootstrap cleanup could not be verified"
                    ) from partial_errors[0]
                profile_cleanup_safe = True
        except Exception as exc:
            cleanup_errors.append(f"Chrome LaunchAgent cleanup: {exc}")
        if native_host_registration is not None:
            try:
                _remove_chrome_for_testing_native_host(
                    native_host_registration,
                    registered_native_host_executable,
                    uid,
                )
            except Exception as exc:
                cleanup_errors.append(
                    f"Chrome for Testing native host cleanup: {exc}"
                )
        diagnostics: list[tuple[str, bytes]] = []
        for name, path in (
            ("LaunchServices", launcher_stderr_path),
            ("Chrome", stderr_path),
            ("Native message tap", native_tap_status),
        ):
            if path is None:
                continue
            try:
                captured = _read_owner_private_tail(path, uid)
            except FileNotFoundError:
                captured = b""
            except Exception as exc:
                captured = b""
                cleanup_errors.append(f"{name} diagnostic capture: {exc}")
            diagnostics.append((name, captured))
        if native_message_tap is not None:
            try:
                _remove_native_message_tap(native_message_tap, uid)
            except Exception as exc:
                cleanup_errors.append(f"Native message tap cleanup: {exc}")
        if profile_cleanup_safe:
            try:
                _remove_owned_profile(profile)
            except Exception as exc:
                cleanup_errors.append(f"Chrome profile cleanup: {exc}")
        else:
            cleanup_errors.append(
                f"Chrome profile retained until LaunchAgent cleanup: {profile}"
            )

    if cleanup_errors:
        raise QualificationError("; ".join(cleanup_errors)) from failure
    if failure is not None:
        detail = "\n".join(
            f"{name} stderr:\n{captured.decode('utf-8', errors='replace')}"
            for name, captured in diagnostics
            if captured
        )
        raise QualificationError(
            f"Chrome semantic page did not qualify: {failure}\n{detail}"
        ) from failure
    if snapshot is None:
        raise QualificationError("Chrome semantic page produced no fixture evidence")
    return snapshot


def _assert_fixture_complete(
    snapshot: FixtureSnapshot,
    scenario: str = REGIONAL_DENIAL_SCENARIO,
) -> None:
    if snapshot.root_visits != 2:
        raise QualificationError(
            f"semantic page did not reload exactly once: {snapshot!r}"
        )
    if min(
        snapshot.css_requests,
        snapshot.script_requests,
        snapshot.image_requests,
    ) < 1:
        raise QualificationError(
            f"styled semantic page omitted a mandatory resource: {snapshot!r}"
        )
    if snapshot.ready_requests != 1:
        raise QualificationError(
            f"styled semantic page did not emit one ready callback: {snapshot!r}"
        )
    if scenario == PENDING_NAVIGATION_SCENARIO:
        if snapshot.pending_navigation_error is not None:
            raise QualificationError(snapshot.pending_navigation_error)
        if snapshot.pending_navigation_signals != 1:
            raise QualificationError(
                "pending navigation did not emit exactly one v3 signal: "
                f"{snapshot!r}"
            )


def _assert_daemon_absent_and_disabled() -> None:
    result = _run(
        ("/bin/launchctl", "print", lifecycle.LAUNCHD_LABEL),
        check=False,
    )
    if not lifecycle.launchd_job_absent(result):
        raise QualificationError("root daemon survived semantic qualification")
    if not geph_smoke._daemon_is_disabled():
        raise QualificationError("root daemon label is not durably disabled")


def run_qualification(
    app_bundle: Path,
    chrome_executable: Path,
    extension: Path = DEFAULT_EXTENSION,
) -> dict[str, object]:
    uid, gid = _require_disposable_ci()
    chrome_executable = _validate_chrome_for_testing(chrome_executable)
    extension = _validate_extension(extension)
    app_bundle = app_bundle.expanduser().resolve(strict=True)
    target = lifecycle.packaged_app_target(app_bundle)
    if target.tray_executable is None:
        raise QualificationError("packaged target has no tray executable")
    user = pwd.getpwuid(uid)
    home = Path(user.pw_dir).resolve()
    runner = pf.PfctlRunner()
    before_snapshot, preflight_uid, preflight_gid = lifecycle._preflight(runner)
    if (preflight_uid, preflight_gid) != (uid, gid):
        raise QualificationError("disposable lifecycle user identity changed")
    if AUTO_GEPH_STATE.exists() or SEMANTIC_SOCKET.exists():
        raise QualificationError("semantic daemon runtime already exists")
    native_host_path = _wait_for_native_host(
        home,
        target.tray_executable,
        uid,
    )

    system = lifecycle.SystemRunner(target)
    fixtures = (
        (
            REGIONAL_DENIAL_SCENARIO,
            SemanticHttpsFixture(
                FIXTURE_HOST,
                REGIONAL_DENIAL_SCENARIO,
            ),
        ),
        (
            INCOMPLETE_RESPONSE_SCENARIO,
            SemanticHttpsFixture(
                INCOMPLETE_FIXTURE_HOST,
                INCOMPLETE_RESPONSE_SCENARIO,
            ),
        ),
        (
            PENDING_NAVIGATION_SCENARIO,
            SemanticHttpsFixture(
                PENDING_NAVIGATION_FIXTURE_HOST,
                PENDING_NAVIGATION_SCENARIO,
            ),
        ),
    )
    installed = False
    failure: BaseException | None = None
    cleanup_errors: list[str] = []
    result: dict[str, object] = {}
    try:
        system.run(target.install_command)
        installed = True
        lifecycle._wait_for_status("active")
        lifecycle._assert_installed_payload(target)
        lifecycle._assert_anchor_active(runner)
        _wait_for_semantic_socket(uid)
        _wait_for_owned_geph_backend()

        scenario_results: dict[str, dict[str, object]] = {}
        for scenario, fixture in fixtures:
            fixture.start()
            try:
                snapshot = _run_chrome(
                    uid,
                    gid,
                    extension,
                    fixture,
                    chrome_executable,
                    native_host_path,
                    target.tray_executable,
                )
            except BaseException as exc:
                raise QualificationError(
                    f"{scenario} browser qualification failed: {exc}"
                ) from exc
            expiry = (
                None
                if scenario == PENDING_NAVIGATION_SCENARIO
                else _wait_for_learned_host(fixture.host)
            )
            _assert_fixture_complete(snapshot, scenario)
            scenario_results[scenario] = {
                "host": fixture.host,
                "reloads": snapshot.root_visits - 1,
                "browser_ready_callbacks": snapshot.ready_requests,
                "pending_navigation_v3_signals": (
                    snapshot.pending_navigation_signals
                ),
                "mandatory_resources": {
                    "css": snapshot.css_requests,
                    "javascript": snapshot.script_requests,
                    "image": snapshot.image_requests,
                },
                "learned_route_ttl_seconds": (
                    None
                    if expiry is None
                    else max(0, int(expiry - time.time()))
                ),
            }
            fixture.close()
        result = {
            "result": "pass",
            "restricted_to": "protected disposable GitHub Actions macOS runner",
            "browser": "Chrome for Testing with a fresh owner-only profile",
            "chrome_sandbox": "enabled",
            "browser_launch": "LaunchServices in the console user's Aqua session",
            "extension": "unpacked frozen-origin Chromium companion",
            "native_host": "packaged exact-origin Rust host",
            "daemon_ipc": "owner-only semantic socket",
            "confirmation": "real account-backed owned Geph",
            "semantic_scenarios": scenario_results,
            "styled_dom": (
                "each browser callback follows CSS, JavaScript, and image readiness"
            ),
        }
    except BaseException as exc:
        failure = exc
    finally:
        for scenario, fixture in fixtures:
            try:
                fixture.close()
            except Exception as exc:
                cleanup_errors.append(f"{scenario} fixture cleanup: {exc}")
        try:
            _remove_exact_native_host(
                native_host_path,
                target.tray_executable,
                uid,
            )
        except Exception as exc:
            cleanup_errors.append(f"native host cleanup: {exc}")
        try:
            if installed or target.required_installed_paths[0].exists():
                system.run(target.uninstall_command)
        except Exception as exc:
            cleanup_errors.append(f"product uninstall: {exc}")
            cleanup_errors.extend(
                lifecycle._fallback_uninstall(system, runner, target)
            )
        try:
            lifecycle._assert_clean_install_state(runner)
            if AUTO_GEPH_STATE.exists() or SEMANTIC_SOCKET.exists():
                raise QualificationError(
                    "semantic route runtime survived product uninstall"
                )
            _assert_daemon_absent_and_disabled()
            pf._assert_same_snapshot(before_snapshot, pf._pf_snapshot(runner))
        except Exception as exc:
            cleanup_errors.append(f"system cleanup verification: {exc}")

    if cleanup_errors:
        raise QualificationError("; ".join(cleanup_errors)) from failure
    if failure is not None:
        raise failure
    return result


def dry_run() -> dict[str, object]:
    return {
        "result": "dry-run",
        "restricted_to": "protected disposable GitHub Actions macOS runner",
        "path": (
            "regional denial and incomplete top-level response -> Chromium "
            "extension -> packaged native host -> owner-only daemon IPC -> "
            "distinct real owned Geph confirmation -> one reload per scenario"
        ),
        "browser": (
            "Chrome for Testing; branded Chrome 137+ ignores unpacked "
            "--load-extension"
        ),
        "native_host_registration": (
            "exact packaged manifest copied into the disposable browser profile"
        ),
        "success": (
            "each scenario yields one reload and styled DOM plus CSS, "
            "JavaScript, and image"
        ),
        "browser_launch": "LaunchServices in the console user's Aqua session",
        "chrome_sandbox": "enabled",
        "production_overrides": "none",
    }


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("--app-bundle", type=Path)
    parser.add_argument("--chrome-executable", type=Path)
    parser.add_argument("--extension", type=Path, default=DEFAULT_EXTENSION)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.dry_run:
        print(json.dumps(dry_run(), indent=2, sort_keys=True))
        return 0
    if args.app_bundle is None:
        parser.error("--app-bundle is required outside --dry-run")
    if args.chrome_executable is None:
        parser.error("--chrome-executable is required outside --dry-run")
    try:
        result = run_qualification(
            args.app_bundle,
            args.chrome_executable,
            args.extension,
        )
    except Exception as exc:
        print(f"Chromium semantic qualification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

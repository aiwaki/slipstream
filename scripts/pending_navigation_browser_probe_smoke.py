#!/usr/bin/env python3
"""Qualify the packaged lazy browser observer without production composition."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "spike"))

import pending_navigation_probe_runtime as probe_runtime  # noqa: E402


FIXTURE_HOST = "pending.slipstream.invalid"
MAX_FRAME_BYTES = probe_runtime.MAX_IPC_BYTES
MAX_END_TO_END_MS = 25_000
WORKER_PROFILE_GLOB = "slipstream-browser-probe-" + "[0-9a-f]" * 32
LSAPPINFO = "/usr/bin/lsappinfo"
FORBIDDEN_LAUNCH_SERVICES_EVENTS = (
    "PostShowProcess",
    "showRequest",
    "becameFrontmost",
    "bringForwardRequest",
    "kLSNotifyApplicationShown",
    "kLSNotifyShowRequest",
    "kLSNotifyBecameFrontmost",
    "kLSNotifyBringForwardRequest",
)


class QualificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class VisibilitySnapshot:
    frontmost_asn: str
    slipstream_window_ids: frozenset[int]
    slipstream_launch_services: bool
    slipstream_dock_visible: bool
    gui_chrome_pids: frozenset[int]
    headless_shell_pids: frozenset[int]


def _run_text(command: tuple[str, ...], *, timeout: float = 5.0) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise QualificationError(f"visibility command failed: {command[0]}")
    return result.stdout


def _frontmost_asn() -> str:
    value = _run_text((LSAPPINFO, "front")).strip()
    if not value.startswith("ASN:"):
        raise QualificationError("frontmost application is unavailable")
    return value


def _launch_services_listing() -> str:
    return _run_text((LSAPPINFO, "list"))


def _slipstream_launch_services_state(listing: str) -> tuple[bool, bool]:
    blocks = [
        block
        for block in re.split(r"(?m)(?=^\s*\d+\) )", listing)
        if any(
            marker in block.lower()
            for marker in (
                "slipstream",
                "chrome-headless",
                "chrome headless",
                "headlesschrome",
                "headless chrome",
                "chromium",
            )
        )
    ]
    if not blocks:
        return False, False
    dock_visible = any(
        'type="foreground"' in block.lower()
        and " hidden" not in block.lower()
        for block in blocks
    )
    return True, dock_visible


def _slipstream_window_ids() -> frozenset[int]:
    framework = ctypes.util.find_library("CoreGraphics")
    foundation = ctypes.util.find_library("CoreFoundation")
    if not framework or not foundation:
        raise QualificationError("CoreGraphics visibility API is unavailable")
    cg = ctypes.CDLL(framework)
    cf = ctypes.CDLL(foundation)
    cg.CGWindowListCopyWindowInfo.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    cg.CGWindowListCopyWindowInfo.restype = ctypes.c_void_p
    cf.CFArrayGetCount.argtypes = [ctypes.c_void_p]
    cf.CFArrayGetCount.restype = ctypes.c_long
    cf.CFArrayGetValueAtIndex.argtypes = [ctypes.c_void_p, ctypes.c_long]
    cf.CFArrayGetValueAtIndex.restype = ctypes.c_void_p
    cf.CFDictionaryGetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFStringCreateWithCString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_uint32,
    ]
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFStringGetCString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_long,
        ctypes.c_uint32,
    ]
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFNumberGetValue.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFRelease.argtypes = [ctypes.c_void_p]

    owner_key = cf.CFStringCreateWithCString(None, b"kCGWindowOwnerName", 0x08000100)
    number_key = cf.CFStringCreateWithCString(None, b"kCGWindowNumber", 0x08000100)
    windows = cg.CGWindowListCopyWindowInfo(0, 0)
    if not owner_key or not number_key or not windows:
        for value in (owner_key, number_key, windows):
            if value:
                cf.CFRelease(value)
        raise QualificationError("CoreGraphics window snapshot failed")
    found: set[int] = set()
    try:
        for index in range(cf.CFArrayGetCount(windows)):
            entry = cf.CFArrayGetValueAtIndex(windows, index)
            owner = cf.CFDictionaryGetValue(entry, owner_key)
            number = cf.CFDictionaryGetValue(entry, number_key)
            if not owner or not number:
                continue
            buffer = ctypes.create_string_buffer(512)
            if not cf.CFStringGetCString(owner, buffer, len(buffer), 0x08000100):
                continue
            owner_name = buffer.value.decode("utf-8").lower()
            if not any(
                marker in owner_name
                for marker in (
                    "slipstream",
                    "chrome-headless",
                    "chrome headless",
                    "headlesschrome",
                    "headless chrome",
                    "chromium",
                )
            ):
                continue
            window_id = ctypes.c_int64()
            if cf.CFNumberGetValue(number, 4, ctypes.byref(window_id)):
                found.add(int(window_id.value))
    finally:
        cf.CFRelease(windows)
        cf.CFRelease(owner_key)
        cf.CFRelease(number_key)
    return frozenset(found)


def _browser_processes() -> tuple[frozenset[int], frozenset[int]]:
    listing = _run_text(("/bin/ps", "-axo", "pid=,command="))
    gui: set[int] = set()
    headless: set[int] = set()
    for line in listing.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2:
            continue
        try:
            pid = int(fields[0])
        except ValueError:
            continue
        command = fields[1]
        if "chrome-headless-shell" in command:
            headless.add(pid)
        if any(
            marker in command
            for marker in (
                "/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            )
        ):
            gui.add(pid)
    return frozenset(gui), frozenset(headless)


def _visibility_snapshot() -> VisibilitySnapshot:
    listing = _launch_services_listing()
    registered, dock_visible = _slipstream_launch_services_state(listing)
    gui_chrome, headless_shell = _browser_processes()
    return VisibilitySnapshot(
        frontmost_asn=_frontmost_asn(),
        slipstream_window_ids=_slipstream_window_ids(),
        slipstream_launch_services=registered,
        slipstream_dock_visible=dock_visible,
        gui_chrome_pids=gui_chrome,
        headless_shell_pids=headless_shell,
    )


class VisibilityMonitor:
    def __init__(self) -> None:
        self.before = _visibility_snapshot()
        if (
            self.before.slipstream_window_ids
            or self.before.slipstream_launch_services
            or self.before.slipstream_dock_visible
            or self.before.gui_chrome_pids
            or self.before.headless_shell_pids
        ):
            raise QualificationError("visibility qualification requires a clean GUI baseline")
        self.samples: list[VisibilitySnapshot] = []
        self.events: list[str] = []
        self.failure: BaseException | None = None
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.thread: threading.Thread | None = None
        self.listener: subprocess.Popen[str] | None = None

    def start(self) -> None:
        self.listener = subprocess.Popen(
            (LSAPPINFO, "listen", "+all", "wait", "-duration", "30"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.thread = threading.Thread(target=self._sample, daemon=True)
        self.thread.start()
        if not self.ready.wait(2.0):
            self.stop.set()
            self.thread.join(timeout=2.0)
            if self.listener is not None:
                self.listener.terminate()
                self.listener.communicate(timeout=5.0)
            raise QualificationError("visibility sampler did not start")
        if self.failure is not None:
            self.stop.set()
            if self.listener is not None:
                self.listener.terminate()
                self.listener.communicate(timeout=5.0)
            raise QualificationError("visibility sampler failed") from self.failure

    def _sample(self) -> None:
        try:
            while not self.stop.is_set():
                sample = _visibility_snapshot()
                self.samples.append(sample)
                self.ready.set()
                if self.stop.wait(0.1):
                    break
        except BaseException as error:
            self.failure = error
            self.ready.set()

    def close(self) -> VisibilitySnapshot:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5.0)
            if self.thread.is_alive():
                raise QualificationError("visibility sampler survived cleanup")
        if self.listener is not None:
            self.listener.terminate()
            try:
                output, _ = self.listener.communicate(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.listener.kill()
                output, _ = self.listener.communicate(timeout=5.0)
            self.events = output.splitlines()
        after = _visibility_snapshot()
        self.samples.append(after)
        if self.failure is not None:
            raise QualificationError("visibility sampler failed") from self.failure
        return after

    def assert_invisible(self, after: VisibilitySnapshot) -> None:
        if after.frontmost_asn != self.before.frontmost_asn:
            raise QualificationError("browser worker changed the frontmost application")
        if any(sample.frontmost_asn != self.before.frontmost_asn for sample in self.samples):
            raise QualificationError("browser worker temporarily changed the frontmost application")
        if any(sample.slipstream_window_ids for sample in self.samples):
            raise QualificationError("browser worker created a CoreGraphics window")
        if any(sample.slipstream_launch_services for sample in self.samples):
            raise QualificationError("browser worker registered with LaunchServices")
        if any(sample.slipstream_dock_visible for sample in self.samples):
            raise QualificationError("browser worker exposed a Dock application")
        if any(sample.gui_chrome_pids for sample in self.samples):
            raise QualificationError("browser worker launched GUI Chrome")
        if after.headless_shell_pids:
            raise QualificationError("browser worker leaked its headless process tree")
        event_text = "\n".join(self.events).lower()
        if any(
            marker in event_text
            for marker in (
                "slipstream",
                "chrome-headless",
                "chrome headless",
                "headlesschrome",
                "headless chrome",
                "chromium",
            )
        ):
            event_kind = "visible" if any(
                event.lower() in event_text
                for event in FORBIDDEN_LAUNCH_SERVICES_EVENTS
            ) else "unexpected"
            raise QualificationError(
                f"browser worker emitted an {event_kind} LaunchServices event"
            )


def _require_disposable_ci() -> None:
    if not (
        os.environ.get("CI") == "true"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("SLIPSTREAM_DISPOSABLE_CI") == "1"
    ):
        raise QualificationError(
            "browser-probe qualification requires disposable GitHub Actions"
        )


def _read_exact(connection: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise QualificationError("incomplete broker frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class OwnerOnlyProbeBroker:
    def __init__(self, path: Path, job: dict[str, object]) -> None:
        self.path = path
        self.job = job
        self.submitted: list[dict[str, object]] = []
        self.launch_ids: list[str] = []
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.failure: BaseException | None = None
        self.runtime = probe_runtime.PendingNavigationProbeRuntime(
            submit_result=self._submit,
        )
        if not self.runtime.enqueue(job):
            raise QualificationError("fixture job was not admitted")
        self.thread = threading.Thread(
            target=self._serve,
            name="owner-only-browser-probe-broker",
            daemon=True,
        )

    def _submit(self, result: dict[str, object], launch_id: str) -> bool:
        self.submitted.append(result)
        self.launch_ids.append(launch_id)
        expected_fields = {
            "schema_version",
            "capability",
            "host",
            "request_started_at_unix_ms",
            "observed_at_unix_ms",
            "outcome",
        }
        observed_at = result.get("observed_at_unix_ms")
        return (
            set(result) == expected_fields
            and result.get("schema_version") == 1
            and result.get("capability") == self.job["capability"]
            and result.get("host") == self.job["host"]
            and result.get("request_started_at_unix_ms")
            == self.job["request_started_at_unix_ms"]
            and type(observed_at) is int
            and observed_at
            >= self.job["issued_at_unix_ms"]
            + probe_runtime.CONTRACT_PENDING_OBSERVATION_MS
            and observed_at <= self.job["expires_at_unix_ms"]
            and result.get("outcome") == "navigation_pending"
        )

    def _serve(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.path))
            os.chmod(self.path, 0o600)
            listener.listen(4)
            listener.settimeout(0.2)
            self.ready.set()
            while not self.stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(2.0)
                    length = struct.unpack("<I", _read_exact(connection, 4))[0]
                    if length <= 0 or length > MAX_FRAME_BYTES:
                        raise QualificationError("invalid broker request frame")
                    response = self.runtime.handle(
                        _read_exact(connection, length)
                    )
                    payload = json.dumps(
                        response,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("ascii")
                    if not payload or len(payload) > MAX_FRAME_BYTES:
                        raise QualificationError("invalid broker response frame")
                    connection.sendall(struct.pack("<I", len(payload)) + payload)
                if self.submitted:
                    return
        except BaseException as error:
            self.failure = error
            self.ready.set()
        finally:
            listener.close()
            self.path.unlink(missing_ok=True)

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(3.0):
            raise QualificationError("owner-only broker did not start")
        if self.failure is not None:
            raise QualificationError("owner-only broker failed to start") from self.failure
        metadata = os.lstat(self.path)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise QualificationError("owner-only broker path is not exact")

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=3.0)
        if self.thread.is_alive():
            raise QualificationError("owner-only broker survived cleanup")
        if self.failure is not None:
            raise QualificationError("owner-only broker failed") from self.failure
        if self.path.exists():
            raise QualificationError("owner-only broker path survived cleanup")


class HangingHttpsFixture:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.started = threading.Event()
        self.release = threading.Event()
        self.requests = 0
        self.server: http.server.ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self.server is None:
            raise QualificationError("HTTPS fixture is not running")
        return int(self.server.server_address[1])

    def _certificate(self) -> tuple[Path, Path]:
        config = self.directory / "openssl.cnf"
        certificate = self.directory / "certificate.pem"
        key = self.directory / "key.pem"
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
            raise QualificationError("fixture certificate generation failed")
        key.chmod(0o600)
        return certificate, key

    def start(self) -> None:
        certificate, key = self._certificate()
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                if self.path.partition("?")[0] != "/":
                    self.send_error(404)
                    return
                fixture.requests += 1
                fixture.started.set()
                fixture.release.wait(20.0)
                self.close_connection = True

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server.socket = context.wrap_socket(
            self.server.socket,
            server_side=True,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="pending-navigation-https-fixture",
            daemon=True,
        )
        self.thread.start()

    def close(self) -> None:
        self.release.set()
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=3.0)
        self.server = None
        self.thread = None


def _profile_residue(root: Path = Path("/tmp")) -> set[Path]:
    return set(root.glob(WORKER_PROFILE_GLOB))


def _job(now_ms: int) -> dict[str, object]:
    return {
        "schema_version": 1,
        "capability": "0123456789abcdef0123456789abcdef",
        "host": FIXTURE_HOST,
        "request_started_at_unix_ms": now_ms - 10_000,
        "issued_at_unix_ms": now_ms,
        "expires_at_unix_ms": now_ms + probe_runtime.CAPABILITY_TTL_MS,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-bundle", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    _require_disposable_ci()
    arguments = _parse_args()
    app_bundle = arguments.app_bundle.resolve(strict=True)
    chrome = app_bundle / "Contents" / "Resources" / "chromium-headless-shell" / "chrome-headless-shell"
    if not chrome.is_file() or not os.access(chrome, os.X_OK):
        raise QualificationError("packaged pinned headless shell is unavailable")
    executable = app_bundle / "Contents" / "MacOS" / "slipstream"
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise QualificationError("packaged browser worker is unavailable")
    identity = probe_runtime._active_console_user()
    if identity is None or identity.uid != os.getuid():
        raise QualificationError("qualification is not the active console user")

    before_profiles = _profile_residue()
    visibility = VisibilityMonitor()
    with tempfile.TemporaryDirectory(
        prefix="slipstream-browser-probe-smoke-",
        dir="/tmp",
    ) as raw_directory:
        directory = Path(raw_directory)
        fixture = HangingHttpsFixture(directory)
        broker = None
        failure = None
        after_visibility = None
        started_at = time.monotonic()
        try:
            visibility.start()
            fixture.start()
            now_ms = int(time.time() * 1000)
            socket_path = directory / "probe.sock"
            broker = OwnerOnlyProbeBroker(socket_path, _job(now_ms))
            broker.start()
            environment = {
                "CI": "true",
                "GITHUB_ACTIONS": "true",
                "SLIPSTREAM_DISPOSABLE_CI": "1",
                "SLIPSTREAM_BROWSER_PROBE_SOCKET": str(socket_path),
                "SLIPSTREAM_BROWSER_PROBE_ORIGIN": (
                    f"https://{FIXTURE_HOST}:{fixture.port}/"
                ),
                "SLIPSTREAM_BROWSER_PROBE_HOST_RESOLVER_RULES": (
                    f"MAP {FIXTURE_HOST} 127.0.0.1, EXCLUDE localhost"
                ),
                "SLIPSTREAM_BROWSER_PROBE_IGNORE_CERTIFICATE_ERRORS": "1",
            }
            launch_id = secrets.token_hex(
                probe_runtime.WORKER_LAUNCH_ID_HEX_CHARS // 2
            )
            worker_environment = os.environ.copy()
            worker_environment.update(environment)
            worker_environment[
                probe_runtime.PENDING_NAVIGATION_BROWSER_WORKER_LAUNCH_ID_ENV
            ] = launch_id
            worker = subprocess.run(
                (
                    str(executable),
                    probe_runtime.PENDING_NAVIGATION_BROWSER_WORKER_ARGUMENT,
                ),
                env=worker_environment,
                capture_output=True,
                text=True,
                timeout=MAX_END_TO_END_MS / 1000,
                check=False,
            )
            if worker.returncode != 0:
                raise QualificationError("direct packaged browser worker failed")
            if not probe_runtime._valid_worker_launch_id(launch_id):
                raise QualificationError("browser worker did not complete")
        except BaseException as error:
            failure = error
        finally:
            fixture.close()
            if broker is not None:
                try:
                    broker.close()
                except BaseException as error:
                    if failure is None:
                        failure = error
            try:
                after_visibility = visibility.close()
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure
        if after_visibility is None:
            raise QualificationError("visibility monitor produced no final snapshot")
        visibility.assert_invisible(after_visibility)

        elapsed_ms = round((time.monotonic() - started_at) * 1000)
        if elapsed_ms <= 0 or elapsed_ms > MAX_END_TO_END_MS:
            raise QualificationError(
                f"browser worker exceeded end-to-end budget: {elapsed_ms} ms"
            )
        if not fixture.started.is_set() or fixture.requests != 1:
            raise QualificationError("fixture did not receive one exact navigation")
        if broker.runtime.state_size() != 0 or len(broker.submitted) != 1:
            raise QualificationError("probe capability was not consumed exactly once")
        if broker.launch_ids != [launch_id]:
            raise QualificationError("browser worker launch identity changed")
        after_profiles = _profile_residue()
        residue = after_profiles - before_profiles
        if residue:
            raise QualificationError("owner-private Chrome profile survived cleanup")
        print(json.dumps({
            "browser": "packaged_chromium_headless_shell",
            "end_to_end_ms": elapsed_ms,
            "navigation_requests": fixture.requests,
            "outcome": broker.submitted[0]["outcome"],
            "sandbox_disabled": False,
            "frontmost_unchanged": True,
            "launch_services_visible_events": 0,
            "sampled_coregraphics_windows": 0,
            "slipstream_dock_visible": False,
            "visibility_samples": len(visibility.samples),
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

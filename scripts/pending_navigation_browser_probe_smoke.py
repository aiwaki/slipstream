#!/usr/bin/env python3
"""Qualify the packaged lazy browser observer without production composition."""

from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "spike"))

import pending_navigation_probe_runtime as probe_runtime  # noqa: E402


FIXTURE_HOST = "pending.slipstream.invalid"
MAX_FRAME_BYTES = probe_runtime.MAX_IPC_BYTES
MAX_END_TO_END_MS = 25_000


class QualificationError(RuntimeError):
    pass


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

    def _submit(self, result: dict[str, object]) -> bool:
        self.submitted.append(result)
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


def _profile_residue() -> set[Path]:
    return set(Path("/tmp").glob("slipstream-browser-probe-*"))


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
    parser.add_argument("--chrome-executable", type=Path)
    return parser.parse_args()


def main() -> int:
    _require_disposable_ci()
    arguments = _parse_args()
    app_bundle = arguments.app_bundle.resolve(strict=True)
    chrome = (
        arguments.chrome_executable.resolve(strict=True)
        if arguments.chrome_executable is not None
        else None
    )
    executable = app_bundle / "Contents" / "MacOS" / "slipstream"
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise QualificationError("packaged browser worker is unavailable")
    identity = probe_runtime._active_console_user()
    if identity is None or identity.uid != os.getuid():
        raise QualificationError("qualification is not the active console user")

    before_profiles = _profile_residue()
    with tempfile.TemporaryDirectory(
        prefix="slipstream-browser-probe-smoke-",
        dir="/tmp",
    ) as raw_directory:
        directory = Path(raw_directory)
        fixture = HangingHttpsFixture(directory)
        broker = None
        failure = None
        started_at = time.monotonic()
        try:
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
            if chrome is not None:
                environment["SLIPSTREAM_BROWSER_PROBE_CHROME"] = str(chrome)
            launcher = probe_runtime.PendingNavigationBrowserWorkerLauncher(
                executable=executable,
                runtime_root=directory / "launchers",
                disposable_environment=environment,
            )
            if launcher.launch() is not True:
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
        if failure is not None:
            raise failure

        elapsed_ms = round((time.monotonic() - started_at) * 1000)
        if elapsed_ms <= 0 or elapsed_ms > MAX_END_TO_END_MS:
            raise QualificationError(
                f"browser worker exceeded end-to-end budget: {elapsed_ms} ms"
            )
        if not fixture.started.is_set() or fixture.requests != 1:
            raise QualificationError("fixture did not receive one exact navigation")
        if broker.runtime.state_size() != 0 or len(broker.submitted) != 1:
            raise QualificationError("probe capability was not consumed exactly once")
        after_profiles = _profile_residue()
        residue = after_profiles - before_profiles
        if residue:
            raise QualificationError("owner-private Chrome profile survived cleanup")
        print(json.dumps({
            "browser": (
                "chrome_for_testing"
                if chrome is not None
                else "installed_google_chrome"
            ),
            "end_to_end_ms": elapsed_ms,
            "navigation_requests": fixture.requests,
            "outcome": broker.submitted[0]["outcome"],
            "sandbox_disabled": False,
            "visible_window": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Qualify the packaged Chromium semantic route path on disposable macOS CI.

The harness composes the real unpacked extension, packaged native host,
owner-only daemon socket, packaged root daemon, and an already-qualified
account-backed owned Geph. A local HTTPS page provides deterministic semantic
denial and styled-success states; the daemon independently confirms the same
hostname through real Geph before learning it.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import plistlib
import pwd
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
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
PROFILE_NATIVE_HOST_RELATIVE_PATH = (
    Path("NativeMessagingHosts") / f"{NATIVE_HOST_NAME}.json"
)
SEMANTIC_SOCKET = Path("/var/run/slipstream-semantic.sock")
AUTO_GEPH_STATE = lifecycle.AUTO_GEPH_STATE_PATH
FIXTURE_HOST = "example.org"
INCOMPLETE_FIXTURE_HOST = "example.net"
REGIONAL_DENIAL_SCENARIO = "regional_denial"
INCOMPLETE_RESPONSE_SCENARIO = "incomplete_response"
FIXTURE_SCENARIOS = frozenset(
    (REGIONAL_DENIAL_SCENARIO, INCOMPLETE_RESPONSE_SCENARIO)
)
STYLED_MARKER = "SLIPSTREAM_SEMANTIC_STYLED_READY"
CHROME_TIMEOUT = 55.0
CHROME_JOB_PREFIX = "dev.slipstream.chromium-semantic"


class QualificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class FixtureSnapshot:
    root_visits: int
    css_requests: int
    script_requests: int
    image_requests: int
    ready_requests: int


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

    def snapshot(self) -> FixtureSnapshot:
        with self.lock:
            return FixtureSnapshot(
                root_visits=self.root_visits,
                css_requests=self.css_requests,
                script_requests=self.script_requests,
                image_requests=self.image_requests,
                ready_requests=self.ready_requests,
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
        or manifest.get("permissions") != ["nativeMessaging", "webNavigation"]
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
        f"--user-data-dir={profile}",
        f"https://{fixture_host}:{fixture_port}/?slipstream-semantic=1",
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
                raise QualificationError("profile native host write made no progress")
            remaining = remaining[written:]
        os.fsync(fd)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    if destination.read_bytes() != payload:
        raise QualificationError("profile native host differs from packaged manifest")
    return destination


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
        _install_profile_native_host(
            profile,
            native_host_manifest,
            uid,
            gid,
            native_host_executable,
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
        diagnostics: list[tuple[str, bytes]] = []
        for name, path in (
            ("LaunchServices", launcher_stderr_path),
            ("Chrome", stderr_path),
        ):
            try:
                captured = _read_owner_private_tail(path, uid)
            except FileNotFoundError:
                captured = b""
            except Exception as exc:
                captured = b""
                cleanup_errors.append(f"{name} diagnostic capture: {exc}")
            diagnostics.append((name, captured))
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


def _assert_fixture_complete(snapshot: FixtureSnapshot) -> None:
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
            expiry = _wait_for_learned_host(fixture.host)
            _assert_fixture_complete(snapshot)
            scenario_results[scenario] = {
                "host": fixture.host,
                "reloads": snapshot.root_visits - 1,
                "browser_ready_callbacks": snapshot.ready_requests,
                "mandatory_resources": {
                    "css": snapshot.css_requests,
                    "javascript": snapshot.script_requests,
                    "image": snapshot.image_requests,
                },
                "learned_route_ttl_seconds": max(
                    0,
                    int(expiry - time.time()),
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

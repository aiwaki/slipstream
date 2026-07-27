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
import pwd
import shutil
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
CHROME_EXECUTABLE = Path(
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)
NATIVE_HOST_NAME = "dev.slipstream.semantic"
NATIVE_HOST_ORIGIN = "chrome-extension://cecdingohhpfggapnlbghppcegbaciam/"
NATIVE_HOST_RELATIVE_PATH = Path(
    "Library/Application Support/Google/Chrome/NativeMessagingHosts"
) / f"{NATIVE_HOST_NAME}.json"
SEMANTIC_SOCKET = Path("/var/run/slipstream-semantic.sock")
AUTO_GEPH_STATE = lifecycle.AUTO_GEPH_STATE_PATH
FIXTURE_HOST = "example.org"
STYLED_MARKER = "SLIPSTREAM_SEMANTIC_STYLED_READY"
CHROME_TIMEOUT = 55.0


class QualificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class FixtureSnapshot:
    root_visits: int
    css_requests: int
    script_requests: int
    image_requests: int


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


def _read_private_json(path: Path, expected_uid: int) -> dict[str, object]:
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
        with os.fdopen(fd, encoding="utf-8") as handle:
            fd = -1
            payload = json.load(handle)
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(payload, dict):
        raise QualificationError(f"{path} does not contain a JSON object")
    return payload


def _fixture_response(
    path: str,
    *,
    root_visit: int,
) -> tuple[int, str, bytes]:
    if path == "/":
        if root_visit == 1:
            body = (
                "<!doctype html><html><head>"
                "<title>Unavailable in your area</title></head>"
                "<body><main>This content is no longer available in your area"
                "</main></body></html>"
            ).encode("utf-8")
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
    return 404, "text/plain; charset=utf-8", b"not found\n"


class SemanticHttpsFixture:
    def __init__(self, host: str = FIXTURE_HOST) -> None:
        self.host = host
        self.directory: Path | None = None
        self.server: http.server.ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.root_visits = 0
        self.css_requests = 0
        self.script_requests = 0
        self.image_requests = 0

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
                status, content_type, body = _fixture_response(
                    path,
                    root_visit=root_visit,
                )
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
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
        or manifest.get("permissions") != ["nativeMessaging"]
        or not isinstance(manifest.get("key"), str)
        or not manifest["key"]
    ):
        raise QualificationError("Chromium companion manifest is not the frozen v1 shape")
    for name in ("detector.js", "content.js", "service-worker.js", "service-worker-core.js"):
        if not (path / name).is_file():
            raise QualificationError(f"Chromium companion is missing {name}")
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
            if (
                payload.get("name") == NATIVE_HOST_NAME
                and payload.get("path") == str(expected_executable)
                and payload.get("type") == "stdio"
                and payload.get("allowed_origins") == [NATIVE_HOST_ORIGIN]
            ):
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
    if (
        payload.get("name") != NATIVE_HOST_NAME
        or payload.get("path") != str(expected_executable)
        or payload.get("type") != "stdio"
        or payload.get("allowed_origins") != [NATIVE_HOST_ORIGIN]
    ):
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
) -> tuple[str, ...]:
    return (
        str(executable),
        "--headless=new",
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
        "--password-store=basic",
        "--ignore-certificate-errors",
        f"--disable-extensions-except={extension}",
        f"--load-extension={extension}",
        f"--host-resolver-rules=MAP {FIXTURE_HOST} 127.0.0.1, EXCLUDE localhost",
        f"--user-data-dir={profile}",
        "--virtual-time-budget=20000",
        "--run-all-compositor-stages-before-draw",
        "--dump-dom",
        f"https://{FIXTURE_HOST}:{fixture_port}/?slipstream-semantic=1",
    )


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


def _run_chrome(
    uid: int,
    gid: int,
    extension: Path,
    fixture_port: int,
    executable: Path = CHROME_EXECUTABLE,
) -> bytes:
    executable = executable.resolve(strict=True)
    environment, home = lifecycle._user_environment(uid)
    supplementary_groups = lifecycle._user_supplementary_groups(uid, gid)
    profile = Path(tempfile.mkdtemp(prefix="slipstream-semantic-chrome-"))
    try:
        os.chown(profile, uid, gid)
        profile.chmod(0o700)
        capture = lifecycle._capture_chrome_output(
            _chrome_command(executable, profile, extension, fixture_port),
            cwd=home,
            environment=environment,
            uid=uid,
            gid=gid,
            supplementary_groups=supplementary_groups,
            timeout=CHROME_TIMEOUT,
        )
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    output = capture.stdout
    if capture.timed_out or capture.returncode != 0 or STYLED_MARKER.encode() not in output:
        detail = (capture.stdout + b"\n" + capture.stderr).decode(
            "utf-8",
            errors="replace",
        )[-4000:]
        raise QualificationError(f"Chrome semantic page did not qualify: {detail}")
    return output


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
    extension: Path = DEFAULT_EXTENSION,
) -> dict[str, object]:
    uid, gid = _require_disposable_ci()
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
    fixture = SemanticHttpsFixture()
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

        fixture.start()
        output = _run_chrome(uid, gid, extension, fixture.port)
        expiry = _wait_for_learned_host(FIXTURE_HOST)
        snapshot = fixture.snapshot()
        _assert_fixture_complete(snapshot)
        result = {
            "result": "pass",
            "restricted_to": "protected disposable GitHub Actions macOS runner",
            "browser": "real Chrome with a fresh owner-only profile",
            "extension": "unpacked frozen-origin Chromium companion",
            "native_host": "packaged exact-origin Rust host",
            "daemon_ipc": "owner-only semantic socket",
            "confirmation": "real account-backed owned Geph",
            "reloads": snapshot.root_visits - 1,
            "styled_dom_bytes": len(output),
            "mandatory_resources": {
                "css": snapshot.css_requests,
                "javascript": snapshot.script_requests,
                "image": snapshot.image_requests,
            },
            "learned_route_ttl_seconds": max(0, int(expiry - time.time())),
        }
    except BaseException as exc:
        failure = exc
    finally:
        try:
            fixture.close()
        except Exception as exc:
            cleanup_errors.append(f"fixture cleanup: {exc}")
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
            "regional denial -> Chromium extension -> packaged native host -> "
            "owner-only daemon IPC -> real owned Geph confirmation -> one reload"
        ),
        "success": "styled DOM plus CSS, JavaScript, and image",
        "production_overrides": "none",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-bundle", type=Path)
    parser.add_argument("--extension", type=Path, default=DEFAULT_EXTENSION)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.dry_run:
        print(json.dumps(dry_run(), indent=2, sort_keys=True))
        return 0
    if args.app_bundle is None:
        parser.error("--app-bundle is required outside --dry-run")
    try:
        result = run_qualification(args.app_bundle, args.extension)
    except Exception as exc:
        print(f"Chromium semantic qualification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Bounded owner-only job/result broker for pending-navigation probes."""

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import secrets
import socket
import stat
import struct
import subprocess
import threading
import time


SCHEMA_VERSION = 1
OPERATION_CLAIM = "claim"
OPERATION_SUBMIT = "submit"
OPERATION_NONE = "none"
REASON_ACCEPTED = "accepted"
REASON_INVALID_REQUEST = "invalid_request"
REASON_JOB_READY = "job_ready"
REASON_NO_JOB = "no_job"
REASON_RESULT_REJECTED = "result_rejected"
REASON_EFFECT_UNAVAILABLE = "effect_unavailable"

CAPABILITY_HEX_CHARS = 32
CAPABILITY_TTL_MS = 30_000
CONTRACT_PENDING_OBSERVATION_MS = 8_000
CLAIM_LEASE_SECONDS = 5.0
MAX_LIVE_JOBS = 32
MAX_ENQUEUE_AGE_MS = 5_000
MAX_IPC_BYTES = 2_048
IPC_TIMEOUT_SECONDS = 2.0
CONSOLE_IDENTITY_POLL_SECONDS = 2.0
PENDING_NAVIGATION_PROBE_SOCKET_PATH = (
    "/var/run/slipstream-browser-probe.sock"
)
PENDING_NAVIGATION_BROWSER_WORKER = (
    os.environ.get("SLIPSTREAM_PENDING_NAVIGATION_BROWSER_WORKER")
    or "/Applications/Slipstream.app/Contents/MacOS/slipstream"
)
PENDING_NAVIGATION_BROWSER_WORKER_ARGUMENT = (
    "--pending-navigation-browser-probe"
)
PENDING_NAVIGATION_BROWSER_WORKER_RUNTIME = (
    "/var/run/slipstream-browser-probe-workers"
)
PENDING_NAVIGATION_BROWSER_WORKER_TIMEOUT_SECONDS = 27.0
_BROWSER_WORKER_GRACEFUL_CLEANUP_SECONDS = 8.0
_BROWSER_WORKER_TERMINATION_ERROR = "worker_terminated"
PENDING_NAVIGATION_BROWSER_WORKER_LABEL_PREFIX = (
    "dev.slipstream.browser-probe"
)
_BROWSER_WORKER_DISPOSABLE_ENVIRONMENT = frozenset((
    "CI",
    "GITHUB_ACTIONS",
    "SLIPSTREAM_DISPOSABLE_CI",
    "SLIPSTREAM_BROWSER_PROBE_CHROME",
    "SLIPSTREAM_BROWSER_PROBE_SOCKET",
    "SLIPSTREAM_BROWSER_PROBE_ORIGIN",
    "SLIPSTREAM_BROWSER_PROBE_HOST_RESOLVER_RULES",
    "SLIPSTREAM_BROWSER_PROBE_IGNORE_CERTIFICATE_ERRORS",
))
_DISPOSABLE_CI_MARKERS = {
    "CI": "true",
    "GITHUB_ACTIONS": "true",
    "SLIPSTREAM_DISPOSABLE_CI": "1",
}
_BROWSER_WORKER_ERROR_RE = re.compile(
    r"\Aslipstream browser probe failed: ([a-z0-9_]{1,64})\n?\Z"
)
_BROWSER_WORKER_LABEL_RE = re.compile(
    rf"\A{re.escape(PENDING_NAVIGATION_BROWSER_WORKER_LABEL_PREFIX)}\."
    r"[0-9a-f]{16}\Z"
)
_BROWSER_WORKER_ERROR_MAX_BYTES = 256
_BROWSER_WORKER_PLIST_MAX_BYTES = 16 * 1024

_CAPABILITY_RE = re.compile(
    rf"^[0-9a-f]{{{CAPABILITY_HEX_CHARS}}}$"
)
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_JOB_FIELDS = frozenset((
    "schema_version",
    "capability",
    "host",
    "request_started_at_unix_ms",
    "issued_at_unix_ms",
    "expires_at_unix_ms",
))


class PendingNavigationProbeRuntimeError(ValueError):
    def __init__(self, message, *, worker_cleanup_confirmed=False):
        super().__init__(message)
        self.worker_cleanup_confirmed = bool(worker_cleanup_confirmed)


def browser_worker_disposable_environment(environment=None):
    """Forward only the closed browser fixture surface in disposable CI."""
    source = os.environ if environment is None else environment
    if not isinstance(source, dict) and source is not os.environ:
        try:
            source = dict(source)
        except (TypeError, ValueError):
            return {}
    if any(source.get(name) != value for name, value in _DISPOSABLE_CI_MARKERS.items()):
        return {}
    return {
        name: source[name]
        for name in _BROWSER_WORKER_DISPOSABLE_ENVIRONMENT
        if isinstance(source.get(name), str) and source[name]
    }


@dataclass(frozen=True, slots=True)
class ConsoleUserIdentity:
    uid: int
    gid: int
    username: str
    home: str


@dataclass(frozen=True, slots=True)
class _BrowserWorkerLaunchPaths:
    directory: Path
    plist: Path
    stdout: Path
    stderr: Path


@dataclass(slots=True)
class _QueuedProbeJob:
    job: dict
    expires_at_monotonic: float
    claimed_until_monotonic: float = 0.0


def _response(accepted, operation, reason, job=None):
    return {
        "schema_version": SCHEMA_VERSION,
        "accepted": bool(accepted),
        "operation": operation,
        "reason": reason,
        "job": job,
    }


def _reject_duplicate_keys(pairs):
    payload = {}
    for key, value in pairs:
        if key in payload:
            raise PendingNavigationProbeRuntimeError("duplicate_key")
        payload[key] = value
    return payload


def _parse_request(payload):
    if (
        not isinstance(payload, bytes)
        or not payload
        or len(payload) > MAX_IPC_BYTES
    ):
        raise PendingNavigationProbeRuntimeError("invalid_payload")
    try:
        request = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PendingNavigationProbeRuntimeError("invalid_json") from error
    if not isinstance(request, dict):
        raise PendingNavigationProbeRuntimeError("invalid_shape")
    return request


def _read_exact(connection, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise PendingNavigationProbeRuntimeError("incomplete_frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _parse_response(payload, operation):
    response = _parse_request(payload)
    if set(response) != {
        "schema_version",
        "accepted",
        "operation",
        "reason",
        "job",
    }:
        raise PendingNavigationProbeRuntimeError("invalid_response_shape")
    if (
        type(response.get("schema_version")) is not int
        or response["schema_version"] != SCHEMA_VERSION
        or type(response.get("accepted")) is not bool
        or response.get("operation") != operation
        or not isinstance(response.get("reason"), str)
    ):
        raise PendingNavigationProbeRuntimeError("invalid_response")
    return response


def _canonical_host(value):
    if not isinstance(value, str) or not value.isascii():
        return None
    if not value or len(value) > 253 or value != value.lower().strip("."):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return None
    labels = value.split(".")
    if len(labels) < 2 or any(
        not _HOST_LABEL_RE.fullmatch(label) for label in labels
    ):
        return None
    return value


def _valid_positive_int(value):
    return type(value) is int and value > 0


def _validate_job(job, now_unix_ms):
    if not isinstance(job, dict) or set(job) != _JOB_FIELDS:
        return None
    if type(job.get("schema_version")) is not int or job["schema_version"] != 1:
        return None
    capability = job.get("capability")
    host = _canonical_host(job.get("host"))
    request_started_at = job.get("request_started_at_unix_ms")
    issued_at = job.get("issued_at_unix_ms")
    expires_at = job.get("expires_at_unix_ms")
    if (
        not isinstance(capability, str)
        or not _CAPABILITY_RE.fullmatch(capability)
        or host is None
        or not _valid_positive_int(request_started_at)
        or not _valid_positive_int(issued_at)
        or not _valid_positive_int(expires_at)
        or request_started_at > issued_at
        or expires_at - issued_at != CAPABILITY_TTL_MS
        or not 0 <= now_unix_ms - issued_at <= MAX_ENQUEUE_AGE_MS
        or expires_at <= now_unix_ms
    ):
        return None
    return dict(job)


class PendingNavigationProbeRuntime:
    """Queue exact capability jobs and submit results through one local effect."""

    def __init__(
        self,
        *,
        submit_result,
        claim_job=None,
        wall_clock_ms=None,
        monotonic_clock=None,
        max_live_jobs=MAX_LIVE_JOBS,
        claim_lease_seconds=CLAIM_LEASE_SECONDS,
    ):
        if (
            not callable(submit_result)
            or (claim_job is not None and not callable(claim_job))
            or type(max_live_jobs) is not int
            or max_live_jobs <= 0
            or not isinstance(claim_lease_seconds, (int, float))
            or isinstance(claim_lease_seconds, bool)
            or claim_lease_seconds <= 0
        ):
            raise ValueError("pending-navigation probe runtime bounds are invalid")
        self._submit_result = submit_result
        self._claim_job = claim_job
        self._wall_clock_ms = wall_clock_ms or (lambda: int(time.time() * 1000))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._max_live_jobs = max_live_jobs
        self._claim_lease_seconds = float(claim_lease_seconds)
        self._jobs = OrderedDict()
        self._lock = threading.Lock()

    def _prune_locked(self, now_monotonic):
        for capability, queued in tuple(self._jobs.items()):
            if queued.expires_at_monotonic <= now_monotonic:
                self._jobs.pop(capability, None)
        while len(self._jobs) > self._max_live_jobs:
            self._jobs.popitem(last=False)

    def enqueue(self, job):
        now_unix_ms = self._wall_clock_ms()
        now_monotonic = self._monotonic_clock()
        if type(now_unix_ms) is not int or now_unix_ms <= 0:
            return False
        validated = _validate_job(job, now_unix_ms)
        if validated is None:
            return False
        capability = validated["capability"]
        expires_at_monotonic = now_monotonic + (
            validated["expires_at_unix_ms"] - now_unix_ms
        ) / 1000.0
        with self._lock:
            self._prune_locked(now_monotonic)
            if capability in self._jobs:
                return False
            self._jobs[capability] = _QueuedProbeJob(
                job=validated,
                expires_at_monotonic=expires_at_monotonic,
            )
            self._prune_locked(now_monotonic)
            return capability in self._jobs

    def _claim(self):
        now_monotonic = self._monotonic_clock()
        claimed_job = None
        with self._lock:
            self._prune_locked(now_monotonic)
            for queued in self._jobs.values():
                if queued.claimed_until_monotonic > now_monotonic:
                    continue
                queued.claimed_until_monotonic = min(
                    queued.expires_at_monotonic,
                    now_monotonic + self._claim_lease_seconds,
                )
                claimed_job = dict(queued.job)
                break
        if claimed_job is None:
            return _response(True, OPERATION_CLAIM, REASON_NO_JOB)
        if self._claim_job is not None:
            try:
                observed = self._claim_job(dict(claimed_job)) is True
            except Exception:
                observed = False
            if not observed:
                with self._lock:
                    self._jobs.pop(claimed_job["capability"], None)
                return _response(True, OPERATION_CLAIM, REASON_NO_JOB)
        return _response(
            True,
            OPERATION_CLAIM,
            REASON_JOB_READY,
            claimed_job,
        )

    def _submit(self, result):
        if not isinstance(result, dict):
            return _response(
                False,
                OPERATION_SUBMIT,
                REASON_INVALID_REQUEST,
            )
        capability = result.get("capability")
        if isinstance(capability, str) and _CAPABILITY_RE.fullmatch(capability):
            with self._lock:
                self._jobs.pop(capability, None)
        try:
            accepted = self._submit_result(result) is True
        except Exception:
            return _response(
                False,
                OPERATION_SUBMIT,
                REASON_EFFECT_UNAVAILABLE,
            )
        return _response(
            accepted,
            OPERATION_SUBMIT,
            REASON_ACCEPTED if accepted else REASON_RESULT_REJECTED,
        )

    def handle(self, payload):
        try:
            request = _parse_request(payload)
        except PendingNavigationProbeRuntimeError:
            return _response(False, OPERATION_NONE, REASON_INVALID_REQUEST)
        if type(request.get("schema_version")) is not int:
            return _response(False, OPERATION_NONE, REASON_INVALID_REQUEST)
        if request["schema_version"] != SCHEMA_VERSION:
            return _response(False, OPERATION_NONE, REASON_INVALID_REQUEST)
        operation = request.get("operation")
        if operation == OPERATION_CLAIM and set(request) == {
            "schema_version",
            "operation",
        }:
            return self._claim()
        if operation == OPERATION_SUBMIT and set(request) == {
            "schema_version",
            "operation",
            "result",
        }:
            return self._submit(request["result"])
        return _response(False, OPERATION_NONE, REASON_INVALID_REQUEST)

    def state_size(self):
        now_monotonic = self._monotonic_clock()
        with self._lock:
            self._prune_locked(now_monotonic)
            return len(self._jobs)

    def discard(self, capability):
        if not isinstance(capability, str):
            return False
        with self._lock:
            return self._jobs.pop(capability, None) is not None


def encode_frame(payload):
    if not isinstance(payload, bytes):
        raise TypeError("pending-navigation frame payload must be bytes")
    return struct.pack("<I", len(payload)) + payload


async def _read_frame(reader):
    header = await asyncio.wait_for(
        reader.readexactly(4),
        timeout=IPC_TIMEOUT_SECONDS,
    )
    length = struct.unpack("<I", header)[0]
    if length <= 0 or length > MAX_IPC_BYTES:
        raise PendingNavigationProbeRuntimeError("invalid_frame")
    return await asyncio.wait_for(
        reader.readexactly(length),
        timeout=IPC_TIMEOUT_SECONDS,
    )


async def handle_pending_navigation_probe_client(reader, writer, runtime):
    try:
        payload = await _read_frame(reader)
        response = await asyncio.to_thread(runtime.handle, payload)
    except (
        asyncio.IncompleteReadError,
        asyncio.TimeoutError,
        PendingNavigationProbeRuntimeError,
        struct.error,
    ):
        response = _response(False, OPERATION_NONE, REASON_INVALID_REQUEST)
    except Exception:
        response = _response(False, OPERATION_NONE, REASON_EFFECT_UNAVAILABLE)
    encoded = json.dumps(
        response,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    try:
        writer.write(encode_frame(encoded))
        await asyncio.wait_for(
            writer.drain(),
            timeout=IPC_TIMEOUT_SECONDS,
        )
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


@dataclass(frozen=True, slots=True)
class UnixSocketIdentity:
    device: int
    inode: int


def _socket_identity(path):
    record = os.lstat(path)
    if not stat.S_ISSOCK(record.st_mode):
        raise OSError("pending-navigation path is not a Unix socket")
    return UnixSocketIdentity(record.st_dev, record.st_ino)


def remove_owned_socket(path, identity):
    try:
        current = _socket_identity(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if current != identity:
        return False
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True


def remove_stale_owned_socket(path=PENDING_NAVIGATION_PROBE_SOCKET_PATH):
    try:
        record = os.lstat(path)
    except FileNotFoundError:
        return True
    if (
        not stat.S_ISSOCK(record.st_mode)
        or stat.S_IMODE(record.st_mode) != 0o600
    ):
        return False
    return remove_owned_socket(
        path,
        UnixSocketIdentity(record.st_dev, record.st_ino),
    )


async def _refuse_active_socket(path):
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(path),
            timeout=0.2,
        )
    except (ConnectionRefusedError, FileNotFoundError):
        return
    except (asyncio.TimeoutError, OSError) as error:
        raise OSError(
            "pending-navigation socket ownership is unclear"
        ) from error
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass
    raise OSError("pending-navigation socket is already active")


@dataclass
class OwnedPendingNavigationProbeServer:
    server: asyncio.AbstractServer
    path: str
    identity: UnixSocketIdentity
    _closed: bool = False

    async def close(self):
        if self._closed:
            return
        self._closed = True
        self.server.close()
        await self.server.wait_closed()
        remove_owned_socket(self.path, self.identity)


@dataclass
class OwnedPendingNavigationProbeServerSupervisor:
    path: str
    runtime: PendingNavigationProbeRuntime
    identity_provider: object
    poll_interval: float = CONSOLE_IDENTITY_POLL_SECONDS
    error_handler: object = None
    _server: OwnedPendingNavigationProbeServer = None
    _session_identity: tuple = None
    _task: asyncio.Task = None
    _closing: asyncio.Event = None

    def __post_init__(self):
        if self.poll_interval <= 0:
            raise ValueError(
                "pending-navigation identity poll interval must be positive"
            )
        self._closing = asyncio.Event()

    @staticmethod
    def _normalize_identity(identity):
        if identity is None:
            return None
        try:
            uid, gid, session = identity
        except (TypeError, ValueError):
            return None
        if (
            type(uid) is not int
            or uid <= 0
            or type(gid) is not int
            or gid < 0
            or not isinstance(session, str)
            or not session
        ):
            return None
        return uid, gid, session

    async def _close_server(self):
        server = self._server
        self._server = None
        self._session_identity = None
        if server is not None:
            await server.close()

    async def _reconcile(self):
        desired = self._normalize_identity(self.identity_provider())
        if desired == self._session_identity:
            return
        await self._close_server()
        if desired is None:
            return
        uid, gid, _ = desired
        self._server = await start_owned_pending_navigation_probe_server(
            self.path,
            uid,
            gid,
            self.runtime,
        )
        self._session_identity = desired

    async def _run(self):
        try:
            while not self._closing.is_set():
                try:
                    await self._reconcile()
                except Exception as error:
                    await self._close_server()
                    if self.error_handler is not None:
                        self.error_handler(error)
                try:
                    await asyncio.wait_for(
                        self._closing.wait(),
                        timeout=self.poll_interval,
                    )
                except asyncio.TimeoutError:
                    pass
        finally:
            await self._close_server()

    async def start(self):
        if self._task is not None:
            return self
        await self._reconcile()
        self._task = asyncio.create_task(self._run())
        return self

    async def close(self):
        if self._closing.is_set():
            if self._task is not None:
                await asyncio.gather(self._task, return_exceptions=True)
            return
        self._closing.set()
        if self._task is not None:
            await asyncio.gather(self._task, return_exceptions=True)
        else:
            await self._close_server()


async def start_pending_navigation_probe_server_supervisor(
    path,
    identity_provider,
    runtime,
    *,
    poll_interval=CONSOLE_IDENTITY_POLL_SECONDS,
    error_handler=None,
):
    supervisor = OwnedPendingNavigationProbeServerSupervisor(
        path=path,
        runtime=runtime,
        identity_provider=identity_provider,
        poll_interval=poll_interval,
        error_handler=error_handler,
    )
    return await supervisor.start()


async def start_owned_pending_navigation_probe_server(path, uid, gid, runtime):
    if uid <= 0 or gid < 0:
        raise ValueError(
            "pending-navigation socket requires a non-root owner"
        )
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if (
            not stat.S_ISSOCK(existing.st_mode)
            or existing.st_uid not in {0, uid}
        ):
            raise OSError(
                "refusing to replace an unowned pending-navigation path"
            )
        identity = UnixSocketIdentity(existing.st_dev, existing.st_ino)
        await _refuse_active_socket(path)
        if not remove_owned_socket(path, identity):
            raise OSError(
                "unable to remove stale pending-navigation socket"
            )

    server = await asyncio.start_unix_server(
        lambda reader, writer: handle_pending_navigation_probe_client(
            reader,
            writer,
            runtime,
        ),
        path=path,
        limit=MAX_IPC_BYTES + 4,
        start_serving=False,
    )
    try:
        identity = _socket_identity(path)
        os.chown(path, uid, gid)
        os.chmod(path, 0o600)
        record = os.lstat(path)
        if (
            record.st_uid != uid
            or record.st_gid != gid
            or stat.S_IMODE(record.st_mode) != 0o600
        ):
            raise OSError(
                "pending-navigation socket ownership verification failed"
            )
        await server.start_serving()
    except Exception:
        server.close()
        await server.wait_closed()
        try:
            remove_owned_socket(path, identity)
        except UnboundLocalError:
            pass
        raise
    return OwnedPendingNavigationProbeServer(server, path, identity)


class PendingNavigationProbeWorkerClient:
    """One-shot owner client for the exact claim/submit protocol."""

    def __init__(
        self,
        path=PENDING_NAVIGATION_PROBE_SOCKET_PATH,
        *,
        expected_uid=None,
        timeout=IPC_TIMEOUT_SECONDS,
    ):
        if (
            not isinstance(path, str)
            or not path
            or type(expected_uid) is bool
            or (
                expected_uid is not None
                and (not isinstance(expected_uid, int) or expected_uid < 0)
            )
            or not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or timeout <= 0
        ):
            raise ValueError("pending-navigation worker client is invalid")
        self._path = path
        self._expected_uid = (
            os.getuid() if expected_uid is None else expected_uid
        )
        self._timeout = float(timeout)

    def _validate_socket(self):
        record = os.lstat(self._path)
        if (
            not stat.S_ISSOCK(record.st_mode)
            or record.st_uid != self._expected_uid
            or stat.S_IMODE(record.st_mode) != 0o600
        ):
            raise PendingNavigationProbeRuntimeError("unowned_socket")

    def _request(self, operation, request):
        payload = json.dumps(
            request,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if not payload or len(payload) > MAX_IPC_BYTES:
            raise PendingNavigationProbeRuntimeError("request_too_large")
        self._validate_socket()
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(self._timeout)
            connection.connect(self._path)
            connection.sendall(struct.pack("<I", len(payload)) + payload)
            length = struct.unpack("<I", _read_exact(connection, 4))[0]
            if length <= 0 or length > MAX_IPC_BYTES:
                raise PendingNavigationProbeRuntimeError(
                    "invalid_response_frame"
                )
            return _parse_response(
                _read_exact(connection, length),
                operation,
            )
        except (OSError, struct.error) as error:
            raise PendingNavigationProbeRuntimeError(
                "ipc_unavailable"
            ) from error
        finally:
            connection.close()

    def claim(self):
        response = self._request(
            OPERATION_CLAIM,
            {
                "schema_version": SCHEMA_VERSION,
                "operation": OPERATION_CLAIM,
            },
        )
        if not response["accepted"]:
            raise PendingNavigationProbeRuntimeError("claim_rejected")
        if response["reason"] == REASON_NO_JOB and response["job"] is None:
            return None
        job = response["job"]
        if response["reason"] != REASON_JOB_READY or not isinstance(job, dict):
            raise PendingNavigationProbeRuntimeError("invalid_claim_response")
        issued_at = job.get("issued_at_unix_ms")
        validated = _validate_job(
            job,
            issued_at if _valid_positive_int(issued_at) else 0,
        )
        if validated is None:
            raise PendingNavigationProbeRuntimeError("invalid_claimed_job")
        return validated

    def submit(self, result):
        response = self._request(
            OPERATION_SUBMIT,
            {
                "schema_version": SCHEMA_VERSION,
                "operation": OPERATION_SUBMIT,
                "result": result,
            },
        )
        valid_reason = (
            response["reason"] == REASON_ACCEPTED
            if response["accepted"]
            else response["reason"] in {
                REASON_EFFECT_UNAVAILABLE,
                REASON_INVALID_REQUEST,
                REASON_RESULT_REJECTED,
            }
        )
        if response["job"] is not None or not valid_reason:
            raise PendingNavigationProbeRuntimeError("invalid_submit_response")
        return response


def _active_console_user():
    try:
        uid = os.stat("/dev/console").st_uid
        account = pwd.getpwuid(uid)
    except (KeyError, OSError):
        return None
    if (
        uid <= 0
        or account.pw_gid < 0
        or account.pw_name in {"loginwindow", "_mbsetupuser"}
        or not os.path.isabs(account.pw_dir)
    ):
        return None
    return ConsoleUserIdentity(
        uid=uid,
        gid=account.pw_gid,
        username=account.pw_name,
        home=account.pw_dir,
    )


def _run_browser_worker_command(command):
    try:
        return subprocess.run(
            tuple(command),
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PendingNavigationProbeRuntimeError(
            "browser_worker_command_failed"
        ) from error


def _launchd_job_absent(result):
    if result.returncode == 0:
        return False
    combined = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
    return (
        "could not find service" in combined
        or "service not found" in combined
        or "no such process" in combined
    )


def _launchd_job_pid(result):
    if result.returncode != 0:
        return None
    for raw_line in (result.stdout or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("pid = "):
            continue
        try:
            pid = int(line.removeprefix("pid = "))
        except ValueError as error:
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_pid_invalid"
            ) from error
        return pid if pid > 0 else None
    return None


def _launchd_last_exit_code(result):
    if result.returncode != 0:
        return None
    for raw_line in (result.stdout or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("last exit code = "):
            continue
        try:
            return int(line.removeprefix("last exit code = "))
        except ValueError as error:
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_exit_invalid"
            ) from error
    return None


def _browser_worker_process_identity(result):
    if result.returncode != 0:
        return None
    fields = (result.stdout or "").strip().split(None, 1)
    if len(fields) != 2:
        return None
    try:
        uid = int(fields[0])
    except ValueError:
        return None
    return uid, fields[1]


class PendingNavigationBrowserWorkerLauncher:
    """Launch one packaged browser observer in the exact Aqua console session."""

    def __init__(
        self,
        *,
        executable=PENDING_NAVIGATION_BROWSER_WORKER,
        runtime_root=PENDING_NAVIGATION_BROWSER_WORKER_RUNTIME,
        identity_probe=None,
        command_runner=None,
        monotonic_clock=None,
        sleep=None,
        timeout=PENDING_NAVIGATION_BROWSER_WORKER_TIMEOUT_SECONDS,
        disposable_environment=None,
    ):
        if (
            not isinstance(executable, (str, os.PathLike))
            or not os.fspath(executable)
            or not isinstance(runtime_root, (str, os.PathLike))
            or not os.fspath(runtime_root)
            or not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or timeout <= 0
        ):
            raise ValueError("pending-navigation browser launcher is invalid")
        self._executable = Path(executable)
        self._runtime_root = Path(runtime_root)
        self._identity_probe = identity_probe or _active_console_user
        self._command_runner = command_runner or _run_browser_worker_command
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._timeout = float(timeout)
        self._disposable_environment = dict(disposable_environment or {})
        if self._disposable_environment:
            disposable = (
                os.environ.get("CI") == "true"
                and os.environ.get("GITHUB_ACTIONS") == "true"
                and os.environ.get("SLIPSTREAM_DISPOSABLE_CI") == "1"
            )
            if (
                not disposable
                or not set(self._disposable_environment).issubset(
                    _BROWSER_WORKER_DISPOSABLE_ENVIRONMENT
                )
                or any(
                    not isinstance(value, str)
                    or not value
                    or len(value) > 1024
                    or "\x00" in value
                    for value in self._disposable_environment.values()
                )
            ):
                raise ValueError(
                    "pending-navigation disposable environment is invalid"
                )

    def _identity(self):
        identity = self._identity_probe()
        if not isinstance(identity, ConsoleUserIdentity):
            raise PendingNavigationProbeRuntimeError(
                "console_user_unavailable"
            )
        if (
            identity.uid <= 0
            or identity.gid < 0
            or not identity.username
            or identity.username in {"root", "loginwindow", "_mbsetupuser"}
            or not os.path.isabs(identity.home)
        ):
            raise PendingNavigationProbeRuntimeError(
                "console_user_invalid"
            )
        return identity

    def _validate_executable(self, identity):
        try:
            metadata = os.lstat(self._executable)
        except OSError as error:
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_unavailable"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or not os.path.isabs(self._executable)
            or metadata.st_uid not in {0, identity.uid}
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not metadata.st_mode & 0o111
        ):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_unowned"
            )

    def _prepare_runtime_root(self):
        try:
            self._runtime_root.mkdir(mode=0o755, parents=True, exist_ok=True)
            metadata = os.lstat(self._runtime_root)
        except OSError as error:
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unavailable"
            ) from error
        allowed_owners = {0} if os.geteuid() == 0 else {os.getuid()}
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in allowed_owners
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unowned"
            )

    @staticmethod
    def _write_private(path, payload, identity):
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags, 0o600)
            try:
                remaining = memoryview(payload)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError("private write made no progress")
                    remaining = remaining[written:]
                os.fchown(descriptor, identity.uid, identity.gid)
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unavailable"
            ) from error

    def _prepare_launch(self, identity, label):
        self._prepare_runtime_root()
        directory = self._runtime_root / label
        try:
            directory.mkdir(mode=0o700)
            os.chown(directory, identity.uid, identity.gid)
            directory.chmod(0o700)
        except OSError as error:
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unavailable"
            ) from error
        paths = _BrowserWorkerLaunchPaths(
            directory=directory,
            plist=directory / "worker.plist",
            stdout=directory / "worker.stdout.log",
            stderr=directory / "worker.stderr.log",
        )
        try:
            self._write_private(paths.stdout, b"", identity)
            self._write_private(paths.stderr, b"", identity)
            environment = {
                "HOME": identity.home,
                "LOGNAME": identity.username,
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "USER": identity.username,
            }
            environment.update(self._disposable_environment)
            payload = {
                "Label": label,
                "ProgramArguments": [
                    str(self._executable),
                    PENDING_NAVIGATION_BROWSER_WORKER_ARGUMENT,
                ],
                "RunAtLoad": True,
                "ProcessType": "Interactive",
                "LimitLoadToSessionType": "Aqua",
                "AbandonProcessGroup": False,
                "WorkingDirectory": identity.home,
                "EnvironmentVariables": environment,
                "StandardOutPath": str(paths.stdout),
                "StandardErrorPath": str(paths.stderr),
            }
            self._write_private(
                paths.plist,
                plistlib.dumps(
                    payload,
                    fmt=plistlib.FMT_XML,
                    sort_keys=True,
                ),
                identity,
            )
        except BaseException:
            for path in (paths.plist, paths.stdout, paths.stderr):
                try:
                    metadata = os.lstat(path)
                except FileNotFoundError:
                    continue
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid != identity.uid
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise PendingNavigationProbeRuntimeError(
                        "browser_worker_runtime_unowned"
                    )
                path.unlink()
            metadata = os.lstat(directory)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != identity.uid
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise PendingNavigationProbeRuntimeError(
                    "browser_worker_runtime_unowned"
                )
            directory.rmdir()
            raise
        return paths

    @staticmethod
    def _validate_private_runtime_file(path, identity):
        metadata = os.lstat(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != identity.uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unowned"
            )
        return metadata

    @classmethod
    def _read_private_runtime_file(cls, path, identity, limit):
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != identity.uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > limit
            ):
                raise PendingNavigationProbeRuntimeError(
                    "browser_worker_runtime_unowned"
                )
            payload = os.read(descriptor, limit + 1)
            if len(payload) != metadata.st_size:
                raise PendingNavigationProbeRuntimeError(
                    "browser_worker_runtime_unowned"
                )
            return payload
        finally:
            os.close(descriptor)

    def _validate_stale_launch(self, paths, identity, label):
        directory = os.lstat(paths.directory)
        if (
            not stat.S_ISDIR(directory.st_mode)
            or stat.S_ISLNK(directory.st_mode)
            or directory.st_uid != identity.uid
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unowned"
            )
        self._validate_private_runtime_file(paths.stdout, identity)
        self._validate_private_runtime_file(paths.stderr, identity)
        payload = plistlib.loads(
            self._read_private_runtime_file(
                paths.plist,
                identity,
                _BROWSER_WORKER_PLIST_MAX_BYTES,
            )
        )
        if not isinstance(payload, dict):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unowned"
            )
        environment = payload.get("EnvironmentVariables")
        expected_environment = {
            "HOME": identity.home,
            "LOGNAME": identity.username,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "USER": identity.username,
        }
        expected_environment.update(self._disposable_environment)
        if not isinstance(environment, dict):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unowned"
            )
        persisted_disposable_environment = (
            self._disposable_environment == _DISPOSABLE_CI_MARKERS
            and all(
                environment.get(name) == value
                for name, value in expected_environment.items()
            )
            and set(environment).difference({
                "HOME",
                "LOGNAME",
                "PATH",
                "USER",
            }).issubset(_BROWSER_WORKER_DISPOSABLE_ENVIRONMENT)
            and all(
                isinstance(value, str)
                and value
                and len(value) <= 1024
                and "\x00" not in value
                for value in environment.values()
            )
        )
        if (
            set(payload) != {
                "AbandonProcessGroup",
                "EnvironmentVariables",
                "Label",
                "LimitLoadToSessionType",
                "ProcessType",
                "ProgramArguments",
                "RunAtLoad",
                "StandardErrorPath",
                "StandardOutPath",
                "WorkingDirectory",
            }
            or payload.get("Label") != label
            or payload.get("ProgramArguments") != [
                str(self._executable),
                PENDING_NAVIGATION_BROWSER_WORKER_ARGUMENT,
            ]
            or payload.get("RunAtLoad") is not True
            or payload.get("ProcessType") != "Interactive"
            or payload.get("LimitLoadToSessionType") != "Aqua"
            or payload.get("AbandonProcessGroup") is not False
            or payload.get("WorkingDirectory") != identity.home
            or payload.get("StandardOutPath") != str(paths.stdout)
            or payload.get("StandardErrorPath") != str(paths.stderr)
            or (
                environment != expected_environment
                and not persisted_disposable_environment
            )
        ):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unowned"
            )

    @staticmethod
    def _identity_for_uid(uid):
        try:
            account = pwd.getpwuid(uid)
        except KeyError as error:
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unowned"
            ) from error
        if (
            uid <= 0
            or account.pw_gid < 0
            or not account.pw_name
            or account.pw_name in {"root", "loginwindow", "_mbsetupuser"}
            or not os.path.isabs(account.pw_dir)
        ):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unowned"
            )
        return ConsoleUserIdentity(
            uid=uid,
            gid=account.pw_gid,
            username=account.pw_name,
            home=account.pw_dir,
        )

    def cleanup_stale(self, *, remove_root=False):
        try:
            root = os.lstat(self._runtime_root)
        except FileNotFoundError:
            return True
        allowed_owners = {0} if os.geteuid() == 0 else {os.getuid()}
        if (
            not stat.S_ISDIR(root.st_mode)
            or stat.S_ISLNK(root.st_mode)
            or root.st_uid not in allowed_owners
            or stat.S_IMODE(root.st_mode) & 0o022
        ):
            return False
        try:
            entries = tuple(self._runtime_root.iterdir())
        except OSError:
            return False
        for directory in entries:
            label = directory.name
            if _BROWSER_WORKER_LABEL_RE.fullmatch(label) is None:
                return False
            try:
                metadata = os.lstat(directory)
                identity = self._identity_for_uid(metadata.st_uid)
                paths = _BrowserWorkerLaunchPaths(
                    directory=directory,
                    plist=directory / "worker.plist",
                    stdout=directory / "worker.stdout.log",
                    stderr=directory / "worker.stderr.log",
                )
                self._validate_stale_launch(paths, identity, label)
                target = f"gui/{identity.uid}/{label}"
                state = self._print(target)
                if _launchd_job_absent(state):
                    self._cleanup_launch(
                        target,
                        paths,
                        None,
                        identity,
                    )
                    continue
                pid = _launchd_job_pid(state)
                if pid is not None:
                    self._validate_process(pid, identity)
                self._cleanup_launch(target, paths, pid, identity)
            except (
                OSError,
                ValueError,
                plistlib.InvalidFileException,
                PendingNavigationProbeRuntimeError,
            ):
                return False
        if remove_root:
            try:
                self._runtime_root.rmdir()
            except FileNotFoundError:
                pass
            except OSError:
                return False
        return True

    def _run(self, command):
        result = self._command_runner(tuple(command))
        if (
            not hasattr(result, "returncode")
            or not hasattr(result, "stdout")
            or not hasattr(result, "stderr")
        ):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_command_invalid"
            )
        return result

    def _print(self, target):
        return self._run(("/bin/launchctl", "print", target))

    def _validate_process(self, pid, identity):
        result = self._run((
            "/bin/ps",
            "-p",
            str(pid),
            "-o",
            "uid=,command=",
        ))
        observed = _browser_worker_process_identity(result)
        expected_command = (
            f"{self._executable} "
            f"{PENDING_NAVIGATION_BROWSER_WORKER_ARGUMENT}"
        )
        if observed != (identity.uid, expected_command):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_identity_mismatch"
            )

    def _wait_for_pid(self, target, identity):
        deadline = self._monotonic_clock() + 5.0
        while self._monotonic_clock() < deadline:
            state = self._print(target)
            if _launchd_job_absent(state):
                raise PendingNavigationProbeRuntimeError(
                    "browser_worker_disappeared"
                )
            pid = _launchd_job_pid(state)
            if pid is not None:
                self._validate_process(pid, identity)
                return pid
            self._sleep(0.05)
        raise PendingNavigationProbeRuntimeError(
            "browser_worker_start_timeout"
        )

    def _wait_for_exit(self, target, pid, identity, *, timeout=None):
        wait_seconds = self._timeout if timeout is None else float(timeout)
        deadline = self._monotonic_clock() + wait_seconds
        while self._monotonic_clock() < deadline:
            state = self._print(target)
            if _launchd_job_absent(state):
                raise PendingNavigationProbeRuntimeError(
                    "browser_worker_disappeared"
                )
            observed_pid = _launchd_job_pid(state)
            if observed_pid is not None:
                if observed_pid != pid:
                    raise PendingNavigationProbeRuntimeError(
                        "browser_worker_pid_replaced"
                    )
                try:
                    self._validate_process(observed_pid, identity)
                except PendingNavigationProbeRuntimeError:
                    refreshed = self._print(target)
                    if _launchd_job_absent(refreshed):
                        raise PendingNavigationProbeRuntimeError(
                            "browser_worker_disappeared"
                        )
                    refreshed_pid = _launchd_job_pid(refreshed)
                    if refreshed_pid is not None:
                        if refreshed_pid != pid:
                            raise PendingNavigationProbeRuntimeError(
                                "browser_worker_pid_replaced"
                            )
                        raise
                    exit_code = _launchd_last_exit_code(refreshed)
                    if exit_code is not None:
                        return exit_code
            else:
                exit_code = _launchd_last_exit_code(state)
                if exit_code is not None:
                    return exit_code
            self._sleep(0.1)
        raise PendingNavigationProbeRuntimeError(
            "browser_worker_exit_timeout"
        )

    def _wait_absent(self, target):
        deadline = self._monotonic_clock() + 5.0
        while self._monotonic_clock() < deadline:
            if _launchd_job_absent(self._print(target)):
                return
            self._sleep(0.05)
        raise PendingNavigationProbeRuntimeError(
            "browser_worker_cleanup_failed"
        )

    def _cleanup_launch(self, target, paths, pid, identity):
        if pid is not None:
            try:
                self._validate_process(pid, identity)
            except PendingNavigationProbeRuntimeError:
                pass
            else:
                self._run((
                    "/bin/launchctl",
                    "kill",
                    "SIGTERM",
                    target,
                ))
                # The packaged worker catches SIGTERM and removes only its
                # already-validated Chrome process tree and private profile.
                # Keep the job loaded until that bounded cleanup has exited;
                # bootout first would bypass the worker's owned cleanup.
                self._wait_for_exit(
                    target,
                    pid,
                    identity,
                    timeout=_BROWSER_WORKER_GRACEFUL_CLEANUP_SECONDS,
                )
                if self._read_worker_error(
                    paths.stderr,
                    identity,
                ) != _BROWSER_WORKER_TERMINATION_ERROR:
                    raise PendingNavigationProbeRuntimeError(
                        "browser_worker_cleanup_failed"
                    )
        self._run(("/bin/launchctl", "bootout", target))
        try:
            self._wait_absent(target)
        except PendingNavigationProbeRuntimeError:
            if pid is not None:
                try:
                    self._validate_process(pid, identity)
                except PendingNavigationProbeRuntimeError:
                    pass
                else:
                    self._run((
                        "/bin/launchctl",
                        "kill",
                        "SIGKILL",
                        target,
                    ))
            self._run(("/bin/launchctl", "bootout", target))
            self._wait_absent(target)
        metadata = os.lstat(paths.directory)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != identity.uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_runtime_unowned"
            )
        for path in (paths.plist, paths.stdout, paths.stderr):
            metadata = os.lstat(path)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != identity.uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise PendingNavigationProbeRuntimeError(
                    "browser_worker_runtime_unowned"
                )
            path.unlink()
        paths.directory.rmdir()

    @staticmethod
    def _read_worker_error(path, identity):
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags)
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != identity.uid
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size <= 0
                    or metadata.st_size > _BROWSER_WORKER_ERROR_MAX_BYTES
                ):
                    return "unknown"
                payload = os.read(
                    descriptor,
                    _BROWSER_WORKER_ERROR_MAX_BYTES + 1,
                )
                if len(payload) != metadata.st_size:
                    return "unknown"
            finally:
                os.close(descriptor)
        except OSError:
            return "unknown"
        try:
            message = payload.decode("ascii")
        except UnicodeDecodeError:
            return "unknown"
        match = _BROWSER_WORKER_ERROR_RE.fullmatch(message)
        return match.group(1) if match is not None else "unknown"

    def launch(self):
        identity = self._identity()
        self._validate_executable(identity)
        label = (
            f"{PENDING_NAVIGATION_BROWSER_WORKER_LABEL_PREFIX}."
            f"{secrets.token_hex(8)}"
        )
        target = f"gui/{identity.uid}/{label}"
        paths = self._prepare_launch(identity, label)
        pid = None
        failure = None
        exit_code = None
        worker_error = "unknown"
        try:
            if not _launchd_job_absent(self._print(target)):
                raise PendingNavigationProbeRuntimeError(
                    "browser_worker_already_loaded"
                )
            result = self._run((
                "/bin/launchctl",
                "bootstrap",
                f"gui/{identity.uid}",
                str(paths.plist),
            ))
            if result.returncode != 0:
                raise PendingNavigationProbeRuntimeError(
                    "browser_worker_bootstrap_failed"
                )
            pid = self._wait_for_pid(target, identity)
            exit_code = self._wait_for_exit(target, pid, identity)
            if exit_code != 0:
                worker_error = self._read_worker_error(
                    paths.stderr,
                    identity,
                )
            if self._identity() != identity:
                raise PendingNavigationProbeRuntimeError(
                    "console_user_changed"
                )
        except BaseException as error:
            failure = error
        cleanup_failure = None
        try:
            self._cleanup_launch(target, paths, pid, identity)
        except BaseException as error:
            cleanup_failure = error
        if cleanup_failure is not None:
            raise PendingNavigationProbeRuntimeError(
                "browser_worker_cleanup_failed"
            ) from cleanup_failure
        if failure is not None:
            try:
                failure.worker_cleanup_confirmed = True
            except (AttributeError, TypeError):
                pass
            raise failure
        if exit_code != 0:
            raise PendingNavigationProbeRuntimeError(
                f"browser_worker_failed:{worker_error}",
                worker_cleanup_confirmed=True,
            )
        return True


def cleanup_stale_browser_worker_runtime(*, remove_root=False, executable=None):
    launcher_options = {}
    if executable is not None:
        launcher_options["executable"] = executable
    return PendingNavigationBrowserWorkerLauncher(
        disposable_environment=browser_worker_disposable_environment(),
        **launcher_options,
    ).cleanup_stale(
        remove_root=remove_root,
    )


class LazyPendingNavigationProbeWorker:
    """Start at most one blocking one-shot worker only while jobs exist."""

    def __init__(
        self,
        *,
        pending_jobs,
        launch_worker,
        retry_seconds=CLAIM_LEASE_SECONDS,
        thread_factory=None,
        error_handler=None,
        worker_completed=None,
    ):
        if (
            not callable(pending_jobs)
            or not callable(launch_worker)
            or not isinstance(retry_seconds, (int, float))
            or isinstance(retry_seconds, bool)
            or retry_seconds <= 0
            or (error_handler is not None and not callable(error_handler))
            or (worker_completed is not None and not callable(worker_completed))
        ):
            raise ValueError("pending-navigation worker lifecycle is invalid")
        self._pending_jobs = pending_jobs
        self._launch_worker = launch_worker
        self._retry_seconds = float(retry_seconds)
        self._thread_factory = thread_factory or threading.Thread
        self._error_handler = error_handler
        self._worker_completed = worker_completed
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def _job_count(self):
        try:
            count = self._pending_jobs()
        except Exception:
            return 0
        return count if type(count) is int and count > 0 else 0

    def _run(self):
        try:
            while not self._stop.is_set() and self._job_count():
                cleanup_confirmed = False
                try:
                    self._launch_worker()
                    cleanup_confirmed = True
                except Exception as error:
                    cleanup_confirmed = bool(
                        getattr(error, "worker_cleanup_confirmed", False)
                    )
                    if self._error_handler is not None:
                        try:
                            self._error_handler(error)
                        except Exception:
                            pass
                finally:
                    if cleanup_confirmed and self._worker_completed is not None:
                        try:
                            self._worker_completed()
                        except Exception:
                            pass
                if not self._job_count():
                    break
                self._stop.wait(self._retry_seconds)
        finally:
            with self._lock:
                self._thread = None
                restart = not self._stop.is_set() and bool(self._job_count())
            if restart:
                self.notify_job_ready()

    def notify_job_ready(self):
        if self._stop.is_set() or not self._job_count():
            return False
        with self._lock:
            if self._thread is not None:
                return False
            thread = self._thread_factory(
                target=self._run,
                name="slipstream-browser-probe",
                daemon=True,
            )
            self._thread = thread
        try:
            thread.start()
        except BaseException:
            with self._lock:
                if self._thread is thread:
                    self._thread = None
            raise
        return True

    def active(self):
        with self._lock:
            return self._thread is not None

    def discard_unstarted(self, discard):
        """Discard queued work only while no worker can race the callback."""
        if not callable(discard):
            return False
        with self._lock:
            if self._thread is not None:
                return False
            try:
                return bool(discard())
            except Exception:
                return False

    def close(self, timeout=IPC_TIMEOUT_SECONDS):
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        return not self.active()

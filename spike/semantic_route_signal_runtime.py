"""Bounded runtime and owner-only framed IPC for browser semantic signals."""

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
import json
import os
import socket
import stat
import struct
import threading
import time

from semantic_route_signal import (
    ACTION_NONE,
    CATEGORY_INCOMPLETE_RESPONSE,
    CATEGORY_NAVIGATION_PENDING,
    MAX_SIGNAL_BYTES,
    ROUTE_UNKNOWN,
    SemanticRouteSignalContext,
    SemanticSignalError,
    parse_semantic_route_signal,
    reduce_semantic_route_signal,
)


FRAME_HEADER_BYTES = 4
MAX_RUNTIME_ENTRIES = 256
RUNTIME_ENTRY_TTL_SECONDS = 300.0
IPC_READ_TIMEOUT_SECONDS = 2.0
IPC_WRITE_TIMEOUT_SECONDS = 2.0
CONSOLE_IDENTITY_POLL_SECONDS = 2.0

REASON_CONFIRMATION_NOT_SCHEDULED = "confirmation_not_scheduled"
REASON_CONTEXT_UNAVAILABLE = "context_unavailable"
REASON_READ_TIMEOUT = "read_timeout"
REASON_INVALID_FRAME = "invalid_frame"


def _response(accepted, action, reason):
    return {
        "schema_version": 1,
        "accepted": bool(accepted),
        "action": action,
        "reason": reason,
    }


class SemanticRouteSignalRuntime:
    """Apply the pure reducer with bounded replay state and injected effects."""

    def __init__(
        self,
        *,
        route_class_for_host,
        owned_geph_ready,
        request_confirmation,
        request_incomplete_confirmation=None,
        request_pending_navigation=None,
        wall_clock_ms=None,
        monotonic_clock=None,
        max_entries=MAX_RUNTIME_ENTRIES,
        entry_ttl_seconds=RUNTIME_ENTRY_TTL_SECONDS,
    ):
        if max_entries <= 0 or entry_ttl_seconds <= 0:
            raise ValueError("semantic signal runtime bounds must be positive")
        self._route_class_for_host = route_class_for_host
        self._owned_geph_ready = owned_geph_ready
        self._request_confirmation = request_confirmation
        self._request_incomplete_confirmation = request_incomplete_confirmation
        self._request_pending_navigation = request_pending_navigation
        self._wall_clock_ms = wall_clock_ms or (lambda: int(time.time() * 1000))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._max_entries = max_entries
        self._entry_ttl_seconds = entry_ttl_seconds
        self._seen_signal_ids = OrderedDict()
        self._accepted_hosts = OrderedDict()
        self._lock = threading.Lock()

    def _prune_locked(self, now_mono):
        for state in (self._seen_signal_ids, self._accepted_hosts):
            while state:
                _, (_, expiry) = next(iter(state.items()))
                if expiry > now_mono:
                    break
                state.popitem(last=False)
            while len(state) > self._max_entries:
                state.popitem(last=False)

    def _remember_locked(self, state, key, value, now_mono):
        state.pop(key, None)
        state[key] = (value, now_mono + self._entry_ttl_seconds)
        while len(state) > self._max_entries:
            state.popitem(last=False)

    def handle(self, payload):
        try:
            signal = parse_semantic_route_signal(payload)
        except SemanticSignalError as error:
            return _response(False, ACTION_NONE, error.code)

        now_ms = self._wall_clock_ms()
        now_mono = self._monotonic_clock()
        try:
            route_class = self._route_class_for_host(signal.host)
            backend_ready = (
                bool(self._owned_geph_ready())
                if (
                    route_class == ROUTE_UNKNOWN
                    and signal.category != CATEGORY_NAVIGATION_PENDING
                )
                else False
            )
        except Exception:
            return _response(False, ACTION_NONE, REASON_CONTEXT_UNAVAILABLE)

        with self._lock:
            self._prune_locked(now_mono)
            signal_id_seen = signal.signal_id in self._seen_signal_ids
            accepted_key = (signal.host, signal.category)
            accepted_host = self._accepted_hosts.get(accepted_key)
            last_accepted_at = accepted_host[0] if accepted_host else None
            decision = reduce_semantic_route_signal(
                signal,
                SemanticRouteSignalContext(
                    now_unix_ms=now_ms,
                    route_class=route_class,
                    owned_geph_payload_ready=backend_ready,
                    last_accepted_at_unix_ms=last_accepted_at,
                    signal_id_seen=signal_id_seen,
                ),
            )
            if not signal_id_seen:
                self._remember_locked(
                    self._seen_signal_ids,
                    signal.signal_id,
                    now_ms,
                    now_mono,
                )
            if decision.accepted:
                self._remember_locked(
                    self._accepted_hosts,
                    accepted_key,
                    now_ms,
                    now_mono,
                )

        if not decision.accepted:
            return _response(False, decision.action, decision.reason)
        confirmation = self._request_confirmation
        if signal.category == CATEGORY_INCOMPLETE_RESPONSE:
            confirmation = self._request_incomplete_confirmation
        elif signal.category == CATEGORY_NAVIGATION_PENDING:
            confirmation = self._request_pending_navigation
        try:
            if signal.category == CATEGORY_NAVIGATION_PENDING:
                scheduled = bool(
                    confirmation
                    and confirmation(
                        signal.host,
                        signal.request_started_at_unix_ms,
                    )
                )
            else:
                scheduled = bool(confirmation and confirmation(signal.host))
        except Exception:
            scheduled = False
        if not scheduled:
            with self._lock:
                accepted_host = self._accepted_hosts.get(accepted_key)
                if accepted_host is not None and accepted_host[0] == now_ms:
                    self._accepted_hosts.pop(accepted_key, None)
            return _response(False, ACTION_NONE, REASON_CONFIRMATION_NOT_SCHEDULED)
        return _response(True, decision.action, decision.reason)

    def state_sizes(self):
        with self._lock:
            self._prune_locked(self._monotonic_clock())
            return len(self._seen_signal_ids), len(self._accepted_hosts)


def encode_frame(payload):
    if not isinstance(payload, bytes):
        raise TypeError("frame payload must be bytes")
    return struct.pack("<I", len(payload)) + payload


async def _read_frame(reader):
    header = await asyncio.wait_for(
        reader.readexactly(FRAME_HEADER_BYTES),
        timeout=IPC_READ_TIMEOUT_SECONDS,
    )
    length = struct.unpack("<I", header)[0]
    if length > MAX_SIGNAL_BYTES:
        raise SemanticSignalError("payload_too_large")
    return await asyncio.wait_for(
        reader.readexactly(length),
        timeout=IPC_READ_TIMEOUT_SECONDS,
    )


async def handle_semantic_signal_client(reader, writer, runtime):
    try:
        payload = await _read_frame(reader)
        response = await asyncio.to_thread(runtime.handle, payload)
    except asyncio.TimeoutError:
        response = _response(False, ACTION_NONE, REASON_READ_TIMEOUT)
    except (asyncio.IncompleteReadError, struct.error):
        response = _response(False, ACTION_NONE, REASON_INVALID_FRAME)
    except SemanticSignalError as error:
        response = _response(False, ACTION_NONE, error.code)
    except Exception:
        response = _response(False, ACTION_NONE, REASON_CONTEXT_UNAVAILABLE)
    encoded = json.dumps(
        response,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    try:
        writer.write(encode_frame(encoded))
        await asyncio.wait_for(
            writer.drain(),
            timeout=IPC_WRITE_TIMEOUT_SECONDS,
        )
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


@dataclass(frozen=True)
class UnixSocketIdentity:
    device: int
    inode: int


def _socket_identity(path):
    record = os.lstat(path)
    if not stat.S_ISSOCK(record.st_mode):
        raise OSError("semantic signal path is not a Unix socket")
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


def remove_stale_owned_socket(path):
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
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(path),
            timeout=0.2,
        )
    except (ConnectionRefusedError, FileNotFoundError):
        return
    except (asyncio.TimeoutError, OSError) as error:
        raise OSError("semantic signal socket ownership is unclear") from error
    del reader
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass
    raise OSError("semantic signal socket is already active")


@dataclass
class OwnedSemanticSignalServer:
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
class OwnedSemanticSignalServerSupervisor:
    path: str
    runtime: SemanticRouteSignalRuntime
    identity_provider: object
    poll_interval: float = CONSOLE_IDENTITY_POLL_SECONDS
    error_handler: object = None
    _server: OwnedSemanticSignalServer = None
    _session_identity: tuple = None
    _task: asyncio.Task = None
    _closing: asyncio.Event = None

    def __post_init__(self):
        if self.poll_interval <= 0:
            raise ValueError("semantic signal identity poll interval must be positive")
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
            not isinstance(uid, int)
            or isinstance(uid, bool)
            or uid <= 0
            or not isinstance(gid, int)
            or isinstance(gid, bool)
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
        self._server = await start_owned_semantic_signal_server(
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


async def start_semantic_signal_server_supervisor(
    path,
    identity_provider,
    runtime,
    *,
    poll_interval=CONSOLE_IDENTITY_POLL_SECONDS,
    error_handler=None,
):
    supervisor = OwnedSemanticSignalServerSupervisor(
        path=path,
        runtime=runtime,
        identity_provider=identity_provider,
        poll_interval=poll_interval,
        error_handler=error_handler,
    )
    return await supervisor.start()


async def start_owned_semantic_signal_server(path, uid, gid, runtime):
    if uid <= 0 or gid < 0:
        raise ValueError("semantic signal socket requires a non-root owner")
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if (
            not stat.S_ISSOCK(existing.st_mode)
            or existing.st_uid not in {0, uid}
        ):
            raise OSError("refusing to replace an unowned semantic signal path")
        identity = UnixSocketIdentity(existing.st_dev, existing.st_ino)
        await _refuse_active_socket(path)
        if not remove_owned_socket(path, identity):
            raise OSError("unable to remove stale semantic signal socket")

    server = await asyncio.start_unix_server(
        lambda reader, writer: handle_semantic_signal_client(
            reader,
            writer,
            runtime,
        ),
        path=path,
        limit=MAX_SIGNAL_BYTES + FRAME_HEADER_BYTES,
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
            raise OSError("semantic signal socket ownership verification failed")
        await server.start_serving()
    except Exception:
        server.close()
        await server.wait_closed()
        try:
            remove_owned_socket(path, identity)
        except UnboundLocalError:
            pass
        raise
    return OwnedSemanticSignalServer(server, path, identity)

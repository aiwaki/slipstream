"""Async socket adapter for the pure connection-race reducer."""

import asyncio
from dataclasses import dataclass
import itertools
import socket
import time
from typing import Awaitable, Callable, Optional

import address_attempts
import connection_race


Resolver = Callable[[str, int], Awaitable[tuple]]
Connector = Callable[
    [address_attempts.AddressCandidate, int],
    Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]
Clock = Callable[[], int]


@dataclass(frozen=True)
class OwnedStream:
    """A connected stream whose lifetime belongs to exactly one caller."""

    candidate_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

    async def close(self):
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            pass


@dataclass(frozen=True)
class ConnectionRaceIoResult:
    transition: connection_race.ConnectionRaceTransition
    connection: Optional[OwnedStream] = None


@dataclass(frozen=True)
class _TaskOutcome:
    event: connection_race.ConnectionRaceEvent
    connection: Optional[OwnedStream] = None


@dataclass(frozen=True)
class _Operation:
    kind: str
    serial: int
    candidate_id: str = ""
    at_ms: Optional[int] = None


@dataclass(frozen=True)
class _Completion:
    event: connection_race.ConnectionRaceEvent
    serial: int


def monotonic_ms():
    return time.monotonic_ns() // 1_000_000


def _scoped_ipv6_address(address, scope_id):
    if not scope_id or "%" in address:
        return address
    return f"{address}%{scope_id}"


def _candidates_from_addrinfo(records):
    candidates = []
    seen = set()
    for family, socktype, _protocol, _canonname, sockaddr in records:
        if socktype != socket.SOCK_STREAM:
            continue
        if family == socket.AF_INET:
            family_name = address_attempts.FAMILY_IPV4
            address = sockaddr[0]
        elif family == socket.AF_INET6:
            family_name = address_attempts.FAMILY_IPV6
            scope_id = sockaddr[3] if len(sockaddr) > 3 else 0
            address = _scoped_ipv6_address(sockaddr[0], scope_id)
        else:
            continue
        identity = (family_name, address)
        if identity in seen:
            continue
        seen.add(identity)
        candidates.append(
            address_attempts.AddressCandidate(
                id=f"system:{family_name}:{address}",
                family=family_name,
                address=address,
                source="system_resolver",
            )
        )
    return tuple(candidates)


async def resolve_system_candidates(host, port):
    """Resolve without changing the system resolver or its configuration."""
    records = await asyncio.get_running_loop().getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    return _candidates_from_addrinfo(records)


async def open_candidate_connection(candidate, port):
    """Connect to one numeric candidate without triggering another DNS lookup."""
    families = {
        address_attempts.FAMILY_IPV4: socket.AF_INET,
        address_attempts.FAMILY_IPV6: socket.AF_INET6,
    }
    family = families.get(candidate.family)
    if family is None:
        raise ValueError("candidate family must be ipv4 or ipv6")
    return await asyncio.open_connection(
        candidate.address,
        port,
        family=family,
        flags=socket.AI_NUMERICHOST,
    )


async def _close_quietly(connection):
    try:
        await connection.close()
    except Exception:
        # writer.close() has already run; cleanup must not mask the race result.
        pass


class _RaceSession:
    def __init__(self, host, port, resolver, connector, clock_ms):
        self.host = host
        self.port = port
        self.resolver = resolver
        self.connector = connector
        self.clock_ms = clock_ms
        self._serial = itertools.count()
        self._pending = {}
        self._ready = []
        self._wake_tasks = {}
        self._candidate_tasks = {}
        self._started_candidates = set()
        self._cancelled_candidates = set()
        self._connections = {}
        self._resolver_started = False

    def _track(self, coroutine, kind, candidate_id="", at_ms=None):
        operation = _Operation(
            kind,
            next(self._serial),
            candidate_id=candidate_id,
            at_ms=at_ms,
        )
        task = asyncio.create_task(coroutine)
        self._pending[task] = operation
        return task

    async def _run_resolver(self):
        try:
            candidates = tuple(await self.resolver(self.host, self.port))
        except Exception:
            return _TaskOutcome(
                connection_race.ConnectionRaceEvent(
                    connection_race.EVENT_RESOLVE_FAILED,
                    self.clock_ms(),
                )
            )
        event_kind = (
            connection_race.EVENT_RESOLVED
            if candidates
            else connection_race.EVENT_RESOLVE_FAILED
        )
        return _TaskOutcome(
            connection_race.ConnectionRaceEvent(
                event_kind,
                self.clock_ms(),
                candidates=candidates,
            )
        )

    async def _run_connector(self, candidate):
        try:
            reader, writer = await self.connector(candidate, self.port)
        except Exception:
            return _TaskOutcome(
                connection_race.ConnectionRaceEvent(
                    connection_race.EVENT_ATTEMPT_FAILED,
                    self.clock_ms(),
                    candidate_id=candidate.id,
                )
            )
        connection = OwnedStream(candidate.id, reader, writer)
        return _TaskOutcome(
            connection_race.ConnectionRaceEvent(
                connection_race.EVENT_ATTEMPT_SUCCEEDED,
                self.clock_ms(),
                candidate_id=candidate.id,
            ),
            connection,
        )

    async def _run_wake(self, at_ms):
        delay_seconds = max(0, at_ms - self.clock_ms()) / 1000
        await asyncio.sleep(delay_seconds)
        return _TaskOutcome(
            connection_race.ConnectionRaceEvent(
                connection_race.EVENT_WAKE,
                at_ms,
            )
        )

    def _start_resolver(self):
        if self._resolver_started:
            raise RuntimeError("resolver command may only run once")
        self._resolver_started = True
        self._track(self._run_resolver(), connection_race.COMMAND_RESOLVE)

    def _start_candidate(self, candidate_id, state):
        if candidate_id in self._started_candidates:
            raise RuntimeError("candidate command may only run once")
        candidates = {
            candidate.id: candidate for candidate in state.candidates
        }
        candidate = candidates.get(candidate_id)
        if candidate is None:
            raise RuntimeError("start command references an unknown candidate")
        self._started_candidates.add(candidate_id)
        task = self._track(
            self._run_connector(candidate),
            connection_race.COMMAND_START,
            candidate_id=candidate_id,
        )
        self._candidate_tasks[candidate_id] = task

    def _start_wake(self, at_ms):
        if at_ms is None:
            raise RuntimeError("wake command requires at_ms")
        if at_ms in self._wake_tasks:
            return
        task = self._track(
            self._run_wake(at_ms),
            connection_race.COMMAND_WAKE,
            at_ms=at_ms,
        )
        self._wake_tasks[at_ms] = task

    async def _cancel_candidate(self, candidate_id):
        self._cancelled_candidates.add(candidate_id)
        task = self._candidate_tasks.get(candidate_id)
        if task is not None and not task.done():
            task.cancel()
        connection = self._connections.pop(candidate_id, None)
        if connection is not None:
            await _close_quietly(connection)

    async def apply_commands(self, commands, state):
        for command in commands:
            if command.kind == connection_race.COMMAND_RESOLVE:
                self._start_resolver()
            elif command.kind == connection_race.COMMAND_START:
                self._start_candidate(command.candidate_id, state)
            elif command.kind == connection_race.COMMAND_CANCEL:
                await self._cancel_candidate(command.candidate_id)
            elif command.kind == connection_race.COMMAND_WAKE:
                self._start_wake(command.at_ms)
            else:
                raise RuntimeError(f"unknown connection-race command: {command.kind}")

    def _forget_operation(self, task, operation):
        self._pending.pop(task, None)
        if operation.kind == connection_race.COMMAND_START:
            self._candidate_tasks.pop(operation.candidate_id, None)
        elif operation.kind == connection_race.COMMAND_WAKE:
            self._wake_tasks.pop(operation.at_ms, None)

    async def _harvest_done(self):
        completions = []
        done = sorted(
            (task for task in self._pending if task.done()),
            key=lambda task: self._pending[task].serial,
        )
        for task in done:
            operation = self._pending[task]
            self._forget_operation(task, operation)
            try:
                outcome = task.result()
            except asyncio.CancelledError:
                continue
            event = outcome.event
            if (
                event.candidate_id
                and event.candidate_id in self._cancelled_candidates
            ):
                if outcome.connection is not None:
                    await _close_quietly(outcome.connection)
                continue
            if outcome.connection is not None:
                previous = self._connections.get(event.candidate_id)
                if previous is not None:
                    await _close_quietly(outcome.connection)
                    raise RuntimeError("candidate produced more than one stream")
                self._connections[event.candidate_id] = outcome.connection
            completions.append(_Completion(event, operation.serial))
        completions.sort(
            key=lambda item: (
                item.event.now_ms,
                item.event.kind == connection_race.EVENT_WAKE,
                item.serial,
            )
        )
        self._ready.extend(completions)

    async def next_completion(self):
        while not self._ready:
            if not self._pending:
                raise RuntimeError("active connection race has no pending I/O")
            await asyncio.wait(
                tuple(self._pending),
                return_when=asyncio.FIRST_COMPLETED,
            )
            # Let callbacks made runnable by the same readiness turn settle too.
            await asyncio.sleep(0)
            await self._harvest_done()
        return self._ready.pop(0)

    def take_connection(self, candidate_id):
        connection = self._connections.pop(candidate_id, None)
        if connection is None:
            raise RuntimeError("connected race has no owned winner stream")
        return connection

    async def shutdown(self):
        tasks = tuple(self._pending)
        for task in tasks:
            task.cancel()
        if tasks:
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, _TaskOutcome) and outcome.connection is not None:
                    await _close_quietly(outcome.connection)
        self._pending.clear()
        self._candidate_tasks.clear()
        self._wake_tasks.clear()
        connections = tuple(self._connections.values())
        self._connections.clear()
        for connection in connections:
            await _close_quietly(connection)


def _validate_target(host, port):
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must not be empty")
    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise ValueError("port must be between 1 and 65535")


async def open_connection_race(
    host,
    port,
    circuit_states,
    key,
    race_config,
    circuit_config,
    *,
    resolver=resolve_system_candidates,
    connector=open_candidate_connection,
    clock_ms=monotonic_ms,
):
    """Run one reducer-controlled connection race and return its owned winner."""
    _validate_target(host, port)
    transition = connection_race.start_connection_race(
        circuit_states,
        key,
        race_config,
        circuit_config,
        clock_ms(),
    )
    session = _RaceSession(host, port, resolver, connector, clock_ms)
    connection = None
    try:
        await session.apply_commands(transition.commands, transition.state)
        while transition.state.phase not in connection_race.TERMINAL_PHASES:
            completion = await session.next_completion()
            event = completion.event
            if (
                event.kind == connection_race.EVENT_WAKE
                and event.now_ms < transition.state.updated_at_ms
            ):
                continue
            transition = connection_race.advance_connection_race(
                transition.circuit_states,
                transition.state,
                event,
                race_config,
                circuit_config,
            )
            await session.apply_commands(transition.commands, transition.state)
        if transition.state.phase == connection_race.PHASE_CONNECTED:
            connection = session.take_connection(
                transition.state.winner_candidate_id
            )
        return ConnectionRaceIoResult(transition, connection)
    finally:
        await session.shutdown()

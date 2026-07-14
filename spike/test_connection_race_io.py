import asyncio
from pathlib import Path
import socket

import pytest

import address_attempts
import connection_race
import connection_race_io
import route_circuit


TPROXY_PATH = Path(__file__).with_name("tproxy.py")


def _race_config(**overrides):
    values = {
        "timeout_ms": 500,
        "stagger_ms": 0,
        "max_concurrent": 2,
        "preferred_family": address_attempts.FAMILY_IPV4,
    }
    values.update(overrides)
    return connection_race.ConnectionRaceConfig(**values)


def test_adapter_is_not_wired_into_transparent_runtime():
    assert "connection_race_io" not in TPROXY_PATH.read_text(encoding="utf-8")


def _circuit_config(**overrides):
    values = {
        "failure_threshold": 2,
        "open_duration_ms": 10_000,
        "half_open_max_in_flight": 1,
        "success_threshold": 1,
    }
    values.update(overrides)
    return route_circuit.CircuitConfig(**values)


def _key():
    return route_circuit.RouteCircuitKey(
        "generic",
        "direct_passthrough",
        "direct",
    )


def _candidate(candidate_id, address="127.0.0.1"):
    return address_attempts.AddressCandidate(
        candidate_id,
        address_attempts.FAMILY_IPV4,
        address,
        "test",
    )


def _static_resolver(*candidates):
    async def resolve(_host, _port):
        return tuple(candidates)

    return resolve


class _LoopbackServer:
    def __init__(self):
        self.server = None
        self.active = set()
        self.accepted = 0

    @property
    def port(self):
        return self.server.sockets[0].getsockname()[1]

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle,
            "127.0.0.1",
            0,
        )
        return self

    async def _handle(self, reader, writer):
        self.active.add(writer)
        self.accepted += 1
        try:
            line = await reader.readline()
            if line:
                writer.write(b"pong\n")
                await writer.drain()
            await reader.read()
        finally:
            self.active.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def wait_for_active(self, expected):
        for _ in range(100):
            if len(self.active) == expected:
                return
            await asyncio.sleep(0.01)
        raise AssertionError(
            f"expected {expected} active connections, found {len(self.active)}"
        )

    async def close(self):
        self.server.close()
        await self.server.wait_closed()
        writers = tuple(self.active)
        for writer in writers:
            writer.close()
        if writers:
            await asyncio.gather(
                *(writer.wait_closed() for writer in writers),
                return_exceptions=True,
            )
        await self.wait_for_active(0)


def test_real_loopback_connection_transfers_winner_ownership():
    async def scenario():
        server = await _LoopbackServer().start()
        connection = None
        try:
            result = await asyncio.wait_for(
                connection_race_io.open_connection_race(
                    "loopback.test",
                    server.port,
                    {},
                    _key(),
                    _race_config(),
                    _circuit_config(),
                    resolver=_static_resolver(_candidate("primary")),
                ),
                timeout=2,
            )
            assert result.transition.state.phase == connection_race.PHASE_CONNECTED
            assert result.transition.state.winner_candidate_id == "primary"
            connection = result.connection
            assert connection is not None
            await server.wait_for_active(1)

            connection.writer.write(b"ping\n")
            await connection.writer.drain()
            assert await connection.reader.readline() == b"pong\n"
        finally:
            if connection is not None:
                await connection.close()
            await server.close()

    asyncio.run(scenario())


def test_refused_first_candidate_falls_back_to_loopback_listener():
    async def scenario():
        server = await _LoopbackServer().start()
        connection = None

        async def connector(candidate, port):
            if candidate.id == "refused":
                raise ConnectionRefusedError
            return await connection_race_io.open_candidate_connection(
                candidate,
                port,
            )

        try:
            result = await asyncio.wait_for(
                connection_race_io.open_connection_race(
                    "fallback.test",
                    server.port,
                    {},
                    _key(),
                    _race_config(max_concurrent=1),
                    _circuit_config(),
                    resolver=_static_resolver(
                        _candidate("refused", "127.0.0.2"),
                        _candidate("listener"),
                    ),
                    connector=connector,
                ),
                timeout=2,
            )
            connection = result.connection
            assert connection is not None
            assert result.transition.state.winner_candidate_id == "listener"
            assert [
                (attempt.candidate_id, attempt.state)
                for attempt in result.transition.state.attempts
            ] == [
                ("refused", address_attempts.ATTEMPT_FAILED),
                ("listener", address_attempts.ATTEMPT_SUCCEEDED),
            ]
        finally:
            if connection is not None:
                await connection.close()
            await server.close()

    asyncio.run(scenario())


def test_simultaneous_real_connectors_choose_first_and_close_loser():
    async def scenario():
        server = await _LoopbackServer().start()
        connection = None
        opened = []
        release = asyncio.Event()

        async def connector(candidate, port):
            stream = await connection_race_io.open_candidate_connection(
                _candidate(candidate.id),
                port,
            )
            opened.append(candidate.id)
            if len(opened) == 2:
                release.set()
            await release.wait()
            return stream

        try:
            result = await asyncio.wait_for(
                connection_race_io.open_connection_race(
                    "simultaneous.test",
                    server.port,
                    {},
                    _key(),
                    _race_config(timeout_ms=1_000),
                    _circuit_config(),
                    resolver=_static_resolver(
                        _candidate("first"),
                        _candidate("second", "192.0.2.1"),
                    ),
                    connector=connector,
                    clock_ms=lambda: 100,
                ),
                timeout=2,
            )
            connection = result.connection
            assert connection is not None
            assert set(opened) == {"first", "second"}
            assert result.transition.state.winner_candidate_id == "first"
            await server.wait_for_active(1)
        finally:
            if connection is not None:
                await connection.close()
            await server.close()

    asyncio.run(scenario())


def test_deadline_cancels_stalled_connector_once():
    async def scenario():
        cancelled = 0

        async def connector(_candidate, _port):
            nonlocal cancelled
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelled += 1
                raise

        result = await asyncio.wait_for(
            connection_race_io.open_connection_race(
                "stall.test",
                443,
                {},
                _key(),
                _race_config(timeout_ms=30, max_concurrent=1),
                _circuit_config(),
                resolver=_static_resolver(_candidate("stalled")),
                connector=connector,
            ),
            timeout=1,
        )
        assert result.connection is None
        assert result.transition.state.phase == connection_race.PHASE_TIMED_OUT
        assert cancelled == 1

    asyncio.run(scenario())


def test_caller_cancellation_cleans_up_pending_connector():
    async def scenario():
        started = asyncio.Event()
        cancelled = 0

        async def connector(_candidate, _port):
            nonlocal cancelled
            started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelled += 1
                raise

        task = asyncio.create_task(
            connection_race_io.open_connection_race(
                "cancel.test",
                443,
                {},
                _key(),
                _race_config(timeout_ms=10_000, max_concurrent=1),
                _circuit_config(),
                resolver=_static_resolver(_candidate("pending")),
                connector=connector,
            )
        )
        await asyncio.wait_for(started.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cancelled == 1

    asyncio.run(scenario())


def test_open_route_circuit_rejects_before_resolver_or_connector():
    async def scenario():
        resolver_calls = 0
        connector_calls = 0

        async def resolver(_host, _port):
            nonlocal resolver_calls
            resolver_calls += 1
            return (_candidate("refused"),)

        async def connector(_candidate, _port):
            nonlocal connector_calls
            connector_calls += 1
            raise ConnectionRefusedError

        first = await connection_race_io.open_connection_race(
            "circuit.test",
            443,
            {},
            _key(),
            _race_config(),
            _circuit_config(failure_threshold=1),
            resolver=resolver,
            connector=connector,
        )
        assert first.transition.state.phase == connection_race.PHASE_EXHAUSTED

        second = await connection_race_io.open_connection_race(
            "circuit.test",
            443,
            first.transition.circuit_states,
            _key(),
            _race_config(),
            _circuit_config(failure_threshold=1),
            resolver=resolver,
            connector=connector,
        )
        assert second.transition.state.phase == connection_race.PHASE_REJECTED
        assert second.transition.state.reason == "open"
        assert resolver_calls == 1
        assert connector_calls == 1

    asyncio.run(scenario())


def test_protected_discord_geph_route_rejects_before_io():
    async def scenario():
        calls = []

        async def resolver(_host, _port):
            calls.append("resolver")
            return (_candidate("forbidden"),)

        async def connector(_candidate, _port):
            calls.append("connector")
            raise AssertionError("protected route reached connector")

        result = await connection_race_io.open_connection_race(
            "updates.discord.com",
            443,
            {},
            route_circuit.RouteCircuitKey("discord", "geo_exit", "geph"),
            _race_config(),
            _circuit_config(),
            resolver=resolver,
            connector=connector,
        )
        assert result.transition.state.phase == connection_race.PHASE_REJECTED
        assert result.transition.state.reason == "protected_route_mismatch"
        assert calls == []

    asyncio.run(scenario())


def test_addrinfo_conversion_preserves_order_scope_and_deduplicates():
    records = [
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("fe80::1", 443, 0, 4),
        ),
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("fe80::1", 443, 0, 4),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.0.2.1", 443),
        ),
        (
            socket.AF_UNIX,
            socket.SOCK_STREAM,
            0,
            "",
            ("ignored",),
        ),
    ]
    candidates = connection_race_io._candidates_from_addrinfo(records)
    assert [candidate.id for candidate in candidates] == [
        "system:ipv6:fe80::1%4",
        "system:ipv4:192.0.2.1",
    ]
    assert [candidate.source for candidate in candidates] == [
        "system_resolver",
        "system_resolver",
    ]

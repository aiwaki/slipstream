import asyncio

import address_attempts
import connection_probe
import connection_race


class _Writer:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def _options(**overrides):
    values = {
        "service_group": "generic",
        "route_class": "unknown",
        "backend_id": "local_engine",
        "timeout_ms": 500,
        "stagger_ms": 0,
        "max_concurrent": 2,
    }
    values.update(overrides)
    return values


def test_numeric_candidates_preserve_order_family_scope_and_deduplicate():
    candidates = connection_probe.numeric_candidates(
        (
            "192.0.2.1",
            "192.0.2.1",
            "2001:0db8::1",
            "fe80::1%7",
        ),
        source="fixture",
    )

    assert [candidate.address for candidate in candidates] == [
        "192.0.2.1",
        "2001:db8::1",
        "fe80::1%7",
    ]
    assert [candidate.family for candidate in candidates] == [
        address_attempts.FAMILY_IPV4,
        address_attempts.FAMILY_IPV6,
        address_attempts.FAMILY_IPV6,
    ]
    assert [candidate.id for candidate in candidates] == [
        "fixture:ipv4:192.0.2.1",
        "fixture:ipv6:2001:db8::1",
        "fixture:ipv6:fe80::1%7",
    ]


def test_stalled_first_probe_is_cancelled_after_second_returns_payload():
    async def scenario():
        first_started = asyncio.Event()
        first_cancelled = asyncio.Event()
        winner_writer = _Writer()

        async def dial(address):
            if address == "192.0.2.1":
                first_started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    first_cancelled.set()
            await first_started.wait()
            return object(), winner_writer, b"server-first"

        result = await connection_probe.race_probe_dials(
            "race.test",
            443,
            ("192.0.2.1", "192.0.2.2"),
            dial,
            **_options(),
        )
        try:
            assert result.transition.state.phase == connection_race.PHASE_CONNECTED
            assert result.address == "192.0.2.2"
            assert result.server_first == b"server-first"
            assert result.attempted_count == 2
            assert first_cancelled.is_set()
            assert winner_writer.closed is False
        finally:
            await result.close()
        assert winner_writer.closed is True

    asyncio.run(scenario())


def test_simultaneous_probe_success_closes_non_winning_stream():
    async def scenario():
        release = asyncio.Event()
        started = []
        writers = {}

        async def dial(address):
            writer = _Writer()
            writers[address] = writer
            started.append(address)
            if len(started) == 2:
                release.set()
            await release.wait()
            return object(), writer, address.encode("ascii")

        result = await connection_probe.race_probe_dials(
            "simultaneous.test",
            443,
            ("192.0.2.1", "192.0.2.2"),
            dial,
            **_options(),
        )
        try:
            assert result.address in {"192.0.2.1", "192.0.2.2"}
            loser = ({"192.0.2.1", "192.0.2.2"} - {result.address}).pop()
            assert writers[result.address].closed is False
            assert writers[loser].closed is True
        finally:
            await result.close()
        assert all(writer.closed for writer in writers.values())

    asyncio.run(scenario())


def test_timeout_cancels_stalled_probe():
    async def scenario():
        cancelled = asyncio.Event()

        async def dial(_address):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        result = await connection_probe.race_probe_dials(
            "timeout.test",
            443,
            ("192.0.2.1",),
            dial,
            **_options(timeout_ms=10, max_concurrent=1),
        )

        assert result.connection is None
        assert result.transition.state.phase == connection_race.PHASE_TIMED_OUT
        assert cancelled.is_set()

    asyncio.run(scenario())


def test_default_one_shot_circuit_does_not_suppress_the_next_request():
    async def scenario():
        calls = []

        async def dial(address):
            calls.append(address)
            return None

        for _ in range(2):
            result = await connection_probe.race_probe_dials(
                "retry.test",
                443,
                ("192.0.2.1",),
                dial,
                **_options(max_concurrent=1),
            )
            assert result.connection is None
            assert result.transition.state.phase == connection_race.PHASE_EXHAUSTED

        assert calls == ["192.0.2.1", "192.0.2.1"]

    asyncio.run(scenario())


def test_protected_local_group_rejects_geph_before_dial():
    async def scenario():
        called = False

        async def dial(_address):
            nonlocal called
            called = True
            return object(), _Writer(), b"unexpected"

        result = await connection_probe.race_probe_dials(
            "updates.discord.com",
            443,
            ("192.0.2.1",),
            dial,
            **_options(
                service_group="discord",
                route_class="geo_exit",
                backend_id="geph",
            ),
        )

        assert result.connection is None
        assert result.transition.state.phase == connection_race.PHASE_REJECTED
        assert result.transition.state.reason == "protected_route_mismatch"
        assert called is False

    asyncio.run(scenario())

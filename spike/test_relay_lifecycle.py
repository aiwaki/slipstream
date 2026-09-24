"""Socket-free relay regressions: ingress, backpressure and causal close order."""

import asyncio
from collections import deque
from types import SimpleNamespace

import pytest
import tproxy


class _Clock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = asyncio.Queue()

    async def sleep(self, delay):
        future = asyncio.get_running_loop().create_future()
        self.sleeps.put_nowait((delay, future))
        await future

    async def tick(self):
        delay, future = await self.sleeps.get()
        self.now += delay
        future.set_result(None)
        await asyncio.sleep(0)


class _ClockedAsyncio:
    def __init__(self, clock):
        self.sleep = clock.sleep

    def __getattr__(self, name):
        return getattr(asyncio, name)


class _Reader:
    def __init__(self, *responses):
        self.responses = deque(responses)
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()

    async def read(self, _size):
        if self.responses:
            response = self.responses.popleft()
            if isinstance(response, BaseException):
                raise response
            return response
        self.waiting.set()
        await self.release.wait()
        return b""


class _Writer:
    def __init__(self):
        self.payload = bytearray()
        self.closed = False

    def write(self, data):
        self.payload.extend(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class _BlockedDrainWriter(_Writer):
    def __init__(self, block_on=1):
        super().__init__()
        self.block_on = block_on
        self.drains = 0
        self.blocked = asyncio.Event()
        self.release = asyncio.Event()

    async def drain(self):
        self.drains += 1
        if self.drains == self.block_on:
            self.blocked.set()
            await self.release.wait()


def _run(coroutine):
    async def bounded():
        # Failure guard only; assertions use events and the injected clock.
        return await asyncio.wait_for(coroutine, timeout=2.0)

    return asyncio.run(bounded())


async def _cancel(task):
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.fixture
def relay_clock(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(tproxy, "time", SimpleNamespace(monotonic=lambda: clock.now))
    monkeypatch.setattr(tproxy, "asyncio", _ClockedAsyncio(clock))
    monkeypatch.setattr(tproxy, "_record_relay_diagnostic", lambda _activity: None)
    return clock


@pytest.mark.parametrize("completes_record", (True, False))
def test_partial_tls_watchdog_does_not_cut_ingress_during_backpressure(
    relay_clock, completes_record
):
    async def scenario():
        complete = b"\x17\x03\x03\x00\x08" + b"a" * 8
        partial = b"\x17\x03\x03\x00\x10" + b"b" * 4
        ingress = b"b" * (12 if completes_record else 4)
        upstream = _Reader(complete + partial, ingress)
        downstream = _BlockedDrainWriter(block_on=2)
        callbacks = []
        activity = tproxy._RelayActivity(
            last_downstream_at=relay_clock.now,
            on_first_downstream=lambda: callbacks.append("delivered"),
        )
        task = asyncio.create_task(tproxy.relay_local_stream(
            _Reader(), _Writer(), upstream, downstream, activity,
            detect_partial_tls_stall=True,
        ))
        try:
            await downstream.blocked.wait()
            assert not activity.upstream_read_pending
            assert activity.tls_complete_records == (2 if completes_record else 1)
            assert activity.downstream_bytes == len(complete + partial)
            assert callbacks == ["delivered"]
            assert bytes(downstream.payload) == complete + partial + ingress

            # More than one watchdog interval passes while browser drain is
            # blocked. Received TLS framing is current; delivery is not claimed.
            await relay_clock.tick()
            await relay_clock.tick()
            assert not activity.partial_tls_record_stalled
            assert not task.done()
            assert activity.diagnostic_reason == ""
            assert activity.downstream_bytes == len(complete + partial)
            assert callbacks == ["delivered"]

            downstream.release.set()
            await upstream.waiting.wait()
            assert activity.upstream_read_pending
            assert activity.downstream_bytes == len(complete + partial + ingress)
            assert callbacks == ["delivered"]
        finally:
            await _cancel(task)
        assert not activity.server_read_ended_at
        assert not activity.client_read_ended_at

    _run(scenario())


def test_server_eof_order_survives_delayed_writer_cleanup(relay_clock):
    async def scenario():
        class SlowCloseWriter(_Writer):
            def __init__(self):
                super().__init__()
                self.cleaning = asyncio.Event()

            async def wait_closed(self):
                self.cleaning.set()
                await asyncio.Event().wait()

        client = _Reader()
        downstream = SlowCloseWriter()
        activity = tproxy._RelayActivity(last_downstream_at=relay_clock.now)
        task = asyncio.create_task(tproxy.relay_local_stream(
            client, _Writer(), _Reader(b""), downstream, activity,
        ))
        await downstream.cleaning.wait()
        assert activity.server_read_ended_at == 100.0
        relay_clock.now = 101.0
        client.release.set()
        await task
        assert activity.server_ended_first
        assert not activity.client_ended_first
        assert activity.server_read_ended_at < activity.client_read_ended_at
        assert activity.diagnostic_reason == "upstream_eof"

    _run(scenario())


def test_client_eof_order_survives_delayed_half_close(relay_clock):
    async def scenario():
        class HalfCloseWriter(_BlockedDrainWriter):
            def can_write_eof(self):
                return True

            def write_eof(self):
                pass

        upstream_reader = _Reader()
        upstream_writer = HalfCloseWriter()
        activity = tproxy._RelayActivity(last_downstream_at=relay_clock.now)
        task = asyncio.create_task(tproxy.relay_local_stream(
            _Reader(b""), upstream_writer, upstream_reader, _Writer(), activity,
        ))
        await upstream_writer.blocked.wait()
        assert activity.client_read_ended_at == 100.0
        relay_clock.now = 101.0
        upstream_reader.release.set()
        await task
        assert activity.client_ended_first
        assert not activity.server_ended_first
        assert activity.client_read_ended_at < activity.server_read_ended_at
        # An orderly client half-close is not a terminating branch. The later
        # upstream EOF terminates this relay without reversing its peer order.
        assert activity.diagnostic_reason == "upstream_eof"

    _run(scenario())


def test_relay_cancellation_never_records_peer_eof(relay_clock):
    async def scenario():
        client = _Reader()
        server = _Reader()
        activity = tproxy._RelayActivity(last_downstream_at=relay_clock.now)
        task = asyncio.create_task(tproxy.relay_local_stream(
            client, _Writer(), server, _Writer(), activity,
        ))
        await client.waiting.wait()
        await server.waiting.wait()
        await _cancel(task)
        assert activity.client_end_at and activity.server_end_at
        assert not activity.client_read_ended_at
        assert not activity.server_read_ended_at
        assert not activity.client_eof
        assert not activity.client_ended_first
        assert not activity.server_ended_first
        assert not activity.upstream_read_pending
        assert activity.diagnostic_reason == "cancellation"

    _run(scenario())


def test_true_partial_waiting_read_watchdog_does_not_manufacture_peer_eof(
    relay_clock,
):
    async def scenario():
        framed_prefix = (
            b"\x17\x03\x03\x00\x08" + b"a" * 8
            + b"\x17\x03\x03\x00\x10" + b"b" * 4
        )
        server = _Reader(framed_prefix)
        activity = tproxy._RelayActivity(last_downstream_at=relay_clock.now)
        task = asyncio.create_task(tproxy.relay_local_stream(
            _Reader(), _Writer(), server, _Writer(), activity,
            detect_partial_tls_stall=True,
        ))
        await server.waiting.wait()
        assert activity.upstream_read_pending
        await relay_clock.tick()
        await task
        assert activity.partial_tls_record_stalled
        assert activity.diagnostic_reason == "local_partial_record_watchdog"
        assert activity.downstream_bytes == len(framed_prefix)
        assert not activity.server_read_ended_at
        assert not activity.client_read_ended_at
        assert not activity.server_ended_first
        assert not activity.client_ended_first
        assert not activity.upstream_read_pending

    _run(scenario())


@pytest.mark.parametrize("direction", ("upstream", "downstream"))
@pytest.mark.parametrize("operation", ("write", "drain"))
def test_writer_failure_never_becomes_peer_eof(relay_clock, direction, operation):
    async def scenario():
        class FailedWriter(_Writer):
            def write(self, data):
                if operation == "write":
                    raise BrokenPipeError("synthetic write failure")
                super().write(data)

            async def drain(self):
                if operation == "drain":
                    raise ConnectionResetError("synthetic drain failure")

        client = _Reader(b"client payload") if direction == "upstream" else _Reader()
        server = _Reader(b"server payload") if direction == "downstream" else _Reader()
        up_writer = FailedWriter() if direction == "upstream" else _Writer()
        down_writer = FailedWriter() if direction == "downstream" else _Writer()
        activity = tproxy._RelayActivity(last_downstream_at=relay_clock.now)
        await tproxy.relay_local_stream(
            client, up_writer, server, down_writer, activity,
        )
        assert activity.diagnostic_reason == "write_error"
        assert not activity.server_read_failed
        assert not activity.client_read_failed
        assert not activity.server_read_ended_at
        assert not activity.client_read_ended_at
        assert not activity.client_eof
        assert not activity.server_ended_first
        assert not activity.client_ended_first
        assert not activity.downstream_bytes
        assert activity.downstream_write_failed is (direction == "downstream")

    _run(scenario())

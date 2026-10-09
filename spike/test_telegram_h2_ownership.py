"""Cancellation ownership regressions for the bundled Telegram H2 transport."""
import asyncio
import importlib
import ssl
from types import SimpleNamespace

import httpx
import pytest

from test_telegram_h2_transport import transport_module

h2 = transport_module
cf = importlib.import_module('slipstream_tg_vendor.cf_h2')


def run(coro):
    asyncio.run(asyncio.wait_for(coro, 8))


async def checkpoint():
    # Let scheduled cancellation/close workers reach their event barriers.
    for _ in range(4):
        await asyncio.sleep(0)


class Writer:
    def __init__(self):
        self.transport = self
        self.closed = False
        self.aborted = False
        self.waiting = asyncio.Event()
        self.finish_close = asyncio.Event()
        self.waits = 0

    def write(self, data):
        pass

    async def drain(self):
        pass

    def get_extra_info(self, name):
        return SimpleNamespace(selected_alpn_protocol=lambda: 'h2')

    def close(self):
        self.closed = True

    def abort(self):
        self.aborted = True
        self.finish_close.set()

    async def wait_closed(self):
        self.waits += 1
        self.waiting.set()
        await self.finish_close.wait()


class Reader:
    async def read(self, count):
        await asyncio.Future()


def test_connection_close_survives_repeated_cancellation_and_coalesces():
    async def scenario():
        writer = Writer()
        connection = h2._Connection(Reader(), writer, 4, 2)
        first = asyncio.create_task(connection.aclose())
        await writer.waiting.wait()
        first.cancel()
        await checkpoint()
        first.cancel()
        second = asyncio.create_task(connection.aclose())
        await checkpoint()
        try:
            assert not first.done(), 'cancelled close abandoned its owned writer'
            assert writer.waits == 1, 'concurrent close must share one cleanup worker'
        finally:
            writer.finish_close.set()
            await asyncio.gather(first, second, return_exceptions=True)
        assert first.cancelled()
        assert connection.reader_task.done()
        assert writer.closed
    run(scenario())


def test_connection_close_aborts_after_existing_close_deadline():
    async def scenario():
        writer = Writer()
        connection = h2._Connection(Reader(), writer, 4, 2)
        await connection.aclose()
        assert writer.aborted, 'timed-out TLS flush still owns an open transport'
        assert connection.reader_task.done()
    run(scenario())


@pytest.mark.parametrize('stage', ['connect', 'trace'])
@pytest.mark.parametrize('reconnect', [False, True])
def test_transport_close_joins_inflight_connect_and_never_dispatches_after_close(monkeypatch, stage, reconnect):
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        writer = Writer()
        writer.finish_close.set()
        requests = []

        async def connect(*args, **kwargs):
            if stage == 'connect':
                entered.set()
                await release.wait()
            return Reader(), writer

        async def trace(event, info):
            if stage == 'trace' and event == 'connection.start_tls.complete':
                entered.set()
                await release.wait()

        async def request(self, req):
            requests.append(req)
            return httpx.Response(200, content=b'unexpected late request')

        monkeypatch.setattr(h2.asyncio, 'open_connection', connect)
        monkeypatch.setattr(h2._Connection, 'request', request)
        transport = h2.H2Transport(ssl.create_default_context())
        if reconnect:
            old_writer = Writer()
            old_writer.finish_close.set()
            transport.connection = h2._Connection(Reader(), old_writer, 4, 2)
            transport.connection.fail(httpx.ReadError('old connection failed'))
        opening = asyncio.create_task(transport.handle_async_request(httpx.Request(
            'POST', 'https://example.test/api', content=b'data',
            extensions={'timeout': {'connect': 2, 'write': 2}, 'trace': trace})))
        await entered.wait()
        closing = asyncio.create_task(transport.aclose())
        await checkpoint()
        assert transport.closed
        closing.cancel()
        await checkpoint()
        closing.cancel()
        release.set()
        results = await asyncio.gather(opening, closing, return_exceptions=True)
        try:
            assert requests == [], 'request dispatched after terminal close intent'
            assert isinstance(results[0], httpx.ConnectError)
            assert writer.closed
            assert transport.connection is None or transport.connection.reader_task.done()
            assert closing.cancelled()
        finally:
            await transport.aclose()
    run(scenario())


def test_repeated_request_cancel_releases_lane_permit(monkeypatch):
    async def scenario():
        lane = cf._HttpLane('example.test', 1)
        channel = cf._HttpChannel(lane, 1, 'ownership')
        posted, releasing = asyncio.Event(), asyncio.Event()
        original_release = lane._release

        async def post(*args, **kwargs):
            posted.set()
            await asyncio.Future()

        async def release(length):
            releasing.set()
            await original_release(length)

        monkeypatch.setattr(lane, '_post', post)
        monkeypatch.setattr(lane, '_release', release)
        await channel.send(b'\0' * 8, False)
        await posted.wait()
        request = next(iter(channel.pending))
        await lane.capacity.acquire()
        try:
            request.cancel()
            await releasing.wait()
            request.cancel()
            await checkpoint()
        finally:
            lane.capacity.release()
        await asyncio.gather(request, return_exceptions=True)
        await channel.close()
        await lane.close()
        assert lane.inflight == lane.queued_bytes == channel.pending_bytes == 0
        assert not channel.pending
    run(scenario())


@pytest.mark.parametrize('owner', ['channel', 'lane'])
def test_close_joins_request_cleanup_despite_repeated_cancel(monkeypatch, owner):
    async def scenario():
        lane = cf._HttpLane('example.test', 1)
        channel = cf._HttpChannel(lane, 1, 'ownership')
        posted, cleaning, release, finished = (asyncio.Event() for _ in range(4))

        async def post(*args, **kwargs):
            posted.set()
            try:
                await asyncio.Future()
            finally:
                cleaning.set()
                await release.wait()
                finished.set()

        monkeypatch.setattr(lane, '_post', post)
        await channel.send(b'\0' * 8, False)
        await posted.wait()
        target = channel if owner == 'channel' else lane
        first = asyncio.create_task(target.close())
        await cleaning.wait()
        first.cancel()
        await checkpoint()
        first.cancel()
        second = asyncio.create_task(target.close())
        await checkpoint()
        try:
            assert not first.done(), 'close returned while request cleanup was interrupted'
        finally:
            release.set()
            await asyncio.gather(first, second, return_exceptions=True)
            await lane.close()
        assert finished.is_set(), 'duplicate close cancellation interrupted request finalizer'
        assert channel.close_done and channel not in lane.channels
        assert lane.inflight == lane.queued_bytes == 0
        assert lane.client.is_closed
    run(scenario())


def test_pool_close_owns_lane_still_in_preflight(monkeypatch):
    async def scenario():
        entered, cleaning, release = (asyncio.Event() for _ in range(3))
        lanes = []

        async def preflight(lane):
            lanes.append(lane)
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleaning.set()
                await release.wait()

        monkeypatch.setattr(cf._HttpLane, '_preflight', preflight)
        monkeypatch.setattr(cf.balancer, 'get_domains_for_dc', lambda dc: ['example.test'])
        pool = cf.CfH2Pool()
        opening = asyncio.create_task(pool.open(2, 'ownership'))
        await entered.wait()
        closing = asyncio.create_task(pool.close())
        await checkpoint()
        try:
            assert cleaning.is_set(), 'pool close did not cancel its pending lane setup'
            assert not closing.done(), 'pool close returned before setup resources were reclaimed'
        finally:
            release.set()
            if not opening.done() and not opening.cancelling():
                opening.cancel()
            await asyncio.gather(opening, closing, return_exceptions=True)
            await pool.close()
        assert all(lane.closed and lane.client.is_closed for lane in lanes)
        assert not pool.lanes
        with pytest.raises(ConnectionError):
            await pool.open(2, 'late')
    run(scenario())


def test_close_during_old_connection_cleanup_prevents_new_connect(monkeypatch):
    async def scenario():
        calls = []
        writer = Writer()
        transport = h2.H2Transport(ssl.create_default_context())
        transport.connection = h2._Connection(Reader(), writer, 4, 2)
        transport.connection.fail(httpx.ReadError('old connection failed'))

        async def connect(*args, **kwargs):
            calls.append(args)
            raise AssertionError('new TLS connection after terminal close')

        monkeypatch.setattr(h2.asyncio, 'open_connection', connect)
        opening = asyncio.create_task(transport.handle_async_request(httpx.Request(
            'POST', 'https://example.test/api', content=b'data')))
        await writer.waiting.wait()
        closing = asyncio.create_task(transport.aclose())
        await checkpoint()
        assert transport.closed
        writer.finish_close.set()
        results = await asyncio.gather(opening, closing, return_exceptions=True)
        assert calls == []
        assert isinstance(results[0], httpx.ConnectError)
        assert writer.closed
    run(scenario())


@pytest.mark.parametrize('handoff', ['close', 'cancel'])
def test_open_reclaims_channel_when_handoff_is_interrupted(monkeypatch, handoff):
    async def scenario():
        pool = cf.CfH2Pool()
        channels = []
        real_wait_for = asyncio.wait_for

        async def make_channel(dc, label):
            lane = cf._HttpLane('example.test', 1)
            pool.lanes[lane.host] = lane
            channel = cf._HttpChannel(lane, 1, label)
            channels.append(channel)
            return channel

        async def at_handoff(awaitable, timeout):
            value = await real_wait_for(awaitable, timeout)
            if isinstance(value, cf._HttpChannel):
                # Setup has finished, but its caller has not claimed the result.
                if handoff == 'close':
                    await pool.close()
                else:
                    asyncio.current_task().cancel()
                    await asyncio.sleep(0)
            return value

        monkeypatch.setattr(pool, '_open', make_channel)
        monkeypatch.setattr(cf.asyncio, 'wait_for', at_handoff)
        try:
            with pytest.raises(ConnectionError if handoff == 'close' else asyncio.CancelledError):
                await pool.open(2, 'handoff')
            assert channels[0].close_done
            assert channels[0] not in channels[0].lane.channels
        finally:
            await pool.close()
    run(scenario())

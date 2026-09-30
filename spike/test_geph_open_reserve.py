"""The app must not multiply Geph internal attempts or replay application bytes."""
import asyncio
import pytest
import tproxy


class Writer:
    def __init__(self):
        self.closed = False
        self.data = []
    def write(self, data): self.data.append(data)
    async def drain(self): pass
    def close(self): self.closed = True
    async def wait_closed(self): pass


@pytest.mark.parametrize('owned', [False, True])
@pytest.mark.parametrize('fails', [False, True])
def test_single_socks_request_even_when_open_is_slow(monkeypatch, owned, fails):
    async def run():
        calls = []
        writer = Writer()
        async def opening(*args):
            calls.append(args)
            await asyncio.sleep(.4)  # Beyond the removed app-level hedge delay.
            return None if fails else (object(), writer)
        monkeypatch.setattr(tproxy, '_open_geph_socks', opening)
        monkeypatch.setattr(tproxy, '_geph_owned', owned)
        monkeypatch.setattr(tproxy, '_geph_port', tproxy.GEPH_OWNED_PORT if owned else 9909)
        result = await tproxy.dial_via_geph('example.com', 443, b'hello')
        assert len(calls) == 1
        assert (result is None) == fails
        assert writer.data == ([] if fails else [b'hello'])
    asyncio.run(run())


def test_cancel_drains_single_opening(monkeypatch):
    async def run():
        started, stopped = [], []
        async def opening(*args):
            started.append(True)
            try: await asyncio.Future()
            finally: stopped.append(True)
        monkeypatch.setattr(tproxy, '_open_geph_socks', opening)
        monkeypatch.setattr(tproxy, '_geph_port', tproxy.GEPH_OWNED_PORT)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(tproxy.dial_via_geph('example.com',443,b'hello'), .5)
        assert len(started) == len(stopped) == 1
    asyncio.run(run())


def test_real_socks_slow_open_sends_first_flight_once(monkeypatch):
    async def run():
        received, handlers = [], []
        async def serve(r,w):
            handlers.append(asyncio.current_task())
            try:
                assert await r.readexactly(3) == b'\x05\x01\x00'
                w.write(b'\x05\x00'); await w.drain()
                head = await r.readexactly(5)
                await r.readexactly(head[4]+2)
                await asyncio.sleep(.4)
                w.write(b'\x05\x00\x00\x01'+b'\x00'*6); await w.drain()
                received.append(await r.read())
            finally:
                w.close(); await w.wait_closed()
        server = await asyncio.start_server(serve,'127.0.0.1',0)
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setattr(tproxy,'GEPH_OWNED_PORT',port)
        monkeypatch.setattr(tproxy,'_geph_port',port)
        monkeypatch.setattr(tproxy,'_geph_owned',True)
        try:
            result = await asyncio.wait_for(tproxy.dial_via_geph('example.com',443,b'client-hello'),2)
            assert result is not None
            await tproxy._close_stream_writer(result[1])
            await asyncio.wait_for(asyncio.gather(*handlers),1)
            assert received == [b'client-hello'] and len(handlers) == 1
        finally:
            server.close(); await server.wait_closed()
    asyncio.run(run())


def test_send_failure_never_replays_on_reserve(monkeypatch):
    async def run():
        class FailingWriter(Writer):
            async def drain(self): raise OSError('write failed')
        w = FailingWriter(); calls = []
        async def opening(*args): calls.append(args); return object(),w
        monkeypatch.setattr(tproxy,'_open_geph_socks',opening)
        monkeypatch.setattr(tproxy,'_geph_owned',True)
        monkeypatch.setattr(tproxy,'_geph_port',tproxy.GEPH_OWNED_PORT)
        assert await tproxy.dial_via_geph('example.com',443,b'hello') is None
        assert calls and len(calls) == 1 and w.closed and w.data == [b'hello']
    asyncio.run(run())

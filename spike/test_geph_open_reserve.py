"""New-tunnel failures must not duplicate bytes or leak reserve sockets."""
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


@pytest.mark.parametrize('first_fails', [False, True])
def test_reserve_recovers_without_replaying_first_flight(monkeypatch, first_fails):
    async def run():
        calls = []
        cancelled = []
        writer = Writer()
        async def opening(*args):
            calls.append(args)
            if len(calls) == 1:
                if first_fails: return None
                try: await asyncio.Future()
                finally: cancelled.append(True)
            return object(), writer
        monkeypatch.setattr(tproxy, '_open_geph_socks', opening)
        monkeypatch.setattr(tproxy, '_geph_owned', True)
        monkeypatch.setattr(tproxy, '_geph_port', tproxy.GEPH_OWNED_PORT)
        result = await asyncio.wait_for(tproxy.dial_via_geph('example.com', 443, b'hello'), 1)
        assert result[1] is writer
        assert writer.data == [b'hello']
        assert len(calls) == 2 and not writer.closed
        assert bool(cancelled) != first_fails
    asyncio.run(run())


def test_fast_open_has_no_reserve(monkeypatch):
    async def run():
        calls = []
        async def opening(*args):
            calls.append(args)
            return object(), Writer()
        monkeypatch.setattr(tproxy, '_open_geph_socks', opening)
        assert await tproxy._open_owned_geph_with_reserve('example.com',443,9954)
        assert len(calls) == 1
    asyncio.run(run())


def test_cancel_cleans_both_openings(monkeypatch):
    async def run():
        started, stopped = [], []
        async def opening(*args):
            started.append(True)
            try: await asyncio.Future()
            finally: stopped.append(True)
        monkeypatch.setattr(tproxy, '_open_geph_socks', opening)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(tproxy._open_owned_geph_with_reserve('example.com',443,9954), .5)
        assert len(started) == len(stopped) == 2
    asyncio.run(run())


def test_external_listener_gets_single_attempt(monkeypatch):
    async def run():
        calls = []
        async def opening(*args): calls.append(args); return None
        monkeypatch.setattr(tproxy, '_open_geph_socks', opening)
        monkeypatch.setattr(tproxy, '_geph_owned', False)
        monkeypatch.setattr(tproxy, '_geph_port', 9909)
        assert await tproxy.dial_via_geph('example.com',443,b'hello') is None
        assert len(calls) == 1
    asyncio.run(run())


def test_real_socks_stall_closes_loser_and_sends_to_winner_only(monkeypatch):
    async def run():
        received, handlers = [], []
        async def serve(r,w):
            ordinal = len(handlers); handlers.append(asyncio.current_task())
            try:
                assert await r.readexactly(3) == b'\x05\x01\x00'
                w.write(b'\x05\x00'); await w.drain()
                head = await r.readexactly(5)
                await r.readexactly(head[4]+2)
                if ordinal == 0:
                    received.append((ordinal, await r.read()))
                else:
                    w.write(b'\x05\x00\x00\x01'+b'\x00'*6); await w.drain()
                    received.append((ordinal, await r.read()))
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
            assert sorted(received) == [(0,b''),(1,b'client-hello')]
        finally:
            server.close(); await server.wait_closed()
    asyncio.run(run())


def test_simultaneous_success_closes_unused_tunnel(monkeypatch):
    async def run():
        writers = [Writer(), Writer()]
        gate = asyncio.Event()
        calls = []
        async def opening(*args):
            n = len(calls); calls.append(n)
            if n: gate.set()
            await gate.wait()
            return object(), writers[n]
        monkeypatch.setattr(tproxy, '_open_geph_socks', opening)
        result = await tproxy._open_owned_geph_with_reserve('example.com',443,9954)
        assert sum(w.closed for w in writers) == 1
        assert not result[1].closed
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

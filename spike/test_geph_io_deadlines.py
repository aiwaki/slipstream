"""A partial local Geph reply cannot retain sessions or monitor work forever."""
import asyncio
import json
from types import SimpleNamespace

import pytest
import tproxy


class ControlSocket:
    def __init__(self, chunks, clock):
        self.chunks = list(chunks)
        self.clock = clock
        self.closed = False
        self.timeouts = []
        self.reads = 0

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, data):
        assert b'conn_info' in data

    def recv(self, size):
        self.reads += 1
        self.clock.now += 1
        value = self.chunks.pop(0)
        if isinstance(value, BaseException):
            raise value
        if len(value) > size:
            self.chunks.insert(0, value[size:])
        return value[:size]

    def close(self):
        self.closed = True


def control_fixture(monkeypatch, chunks):
    clock = SimpleNamespace(now=100.0)
    sock = ControlSocket(chunks, clock)
    monkeypatch.setattr(tproxy, "time", SimpleNamespace(monotonic=lambda: clock.now))
    monkeypatch.setattr(tproxy.socket, "create_connection", lambda *args, **kwargs: sock)
    return clock, sock


def test_geph_control_rpc_uses_absolute_deadline(monkeypatch):
    clock, sock = control_fixture(monkeypatch, [b' '] * 8 + [b'{"result":{"sessions":[1]}}\n'])
    assert tproxy._geph_conn_info_sessions(9955, timeout=3) is None
    assert clock.now <= 103.0
    assert sock.closed


def test_geph_control_rpc_closes_socket_on_receive_failure(monkeypatch):
    _clock, sock = control_fixture(monkeypatch, [TimeoutError("unresponsive")])
    assert tproxy._geph_conn_info_sessions(9955) is None
    assert sock.closed


def test_geph_control_rpc_limits_reply_size(monkeypatch):
    _clock, sock = control_fixture(monkeypatch, [b' ' * 100_000, b'{"result":{"sessions":[1]}}\n'])
    assert tproxy._geph_conn_info_sessions(9955, timeout=30) is None
    assert sock.reads <= 2
    assert sock.closed


@pytest.mark.parametrize("sessions", ("unexpected", {"one": 1}, 1, None))
def test_geph_control_rpc_rejects_malformed_session_shape(monkeypatch, sessions):
    _clock, sock = control_fixture(monkeypatch, [json.dumps({"result":{"sessions":sessions}}).encode()+b'\n'])
    assert tproxy._geph_conn_info_sessions(9955) is None
    assert sock.closed


def test_geph_control_rpc_accepts_fragmented_valid_response(monkeypatch):
    _clock, sock = control_fixture(monkeypatch, [b'{"result":', b'{"sessions":[{},{}]}}\n'])
    assert tproxy._geph_conn_info_sessions(9955, timeout=3) == 2
    assert sock.closed


@pytest.mark.parametrize("reply", (b'\x05\x00\x00\x01', b'\x05\x00\x00\x04'+b'\x00'*16))
def test_socks_reply_tail_is_included_in_connect_deadline(monkeypatch, reply):
    async def scenario():
        closed = asyncio.Event()
        handlers = []
        async def serve(reader, writer):
            handlers.append(asyncio.current_task())
            try:
                assert await reader.readexactly(3) == b'\x05\x01\x00'
                writer.write(b'\x05\x00'); await writer.drain()
                head = await reader.readexactly(5)
                await reader.readexactly(head[4] + 2)
                writer.write(reply); await writer.drain()
                assert await reader.read() == b''
                closed.set()
            finally:
                writer.close(); await writer.wait_closed()
        server = await asyncio.start_server(serve, '127.0.0.1', 0)
        monkeypatch.setattr(tproxy, 'GEPH_SOCKS_REPLY_TIMEOUT', .025, raising=False)
        try:
            result = await asyncio.wait_for(tproxy._open_geph_socks('example.com',443,server.sockets[0].getsockname()[1]), .4)
            assert result is None
            await asyncio.wait_for(closed.wait(), .4)
        finally:
            server.close(); await server.wait_closed()
            await asyncio.gather(*handlers, return_exceptions=True)
    asyncio.run(scenario())

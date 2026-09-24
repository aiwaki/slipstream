"""Reserve profiles must preserve TLS and work beyond a first-byte probe."""
import asyncio
import ssl
import subprocess
from collections import OrderedDict

import pytest
import tproxy


def unpack_records(blob):
    bodies = []
    while blob:
        n = int.from_bytes(blob[3:5], 'big')
        assert n and len(blob) >= n + 5
        bodies.append(blob[5:5+n])
        blob = blob[5+n:]
    return b''.join(bodies)


@pytest.mark.parametrize('mode', tproxy.DISCORD_RESERVE_MODES)
def test_transcript_tail_and_foreign_host_preserved(mode):
    host = 'cdn.discordapp.com'
    hello = tproxy.build_fake_clienthello(host)
    tail = b'\x14\x03\x03\x00\x01\x01'
    parts = tproxy._reserve_flight_parts(hello + tail, host, mode)
    wire = b''.join(parts)
    assert wire.endswith(tail)
    assert unpack_records(wire[:-len(tail)]) == hello[5:]
    if mode.startswith('tcp'):
        assert wire == hello + tail and len(parts) > 1
    else:
        assert wire != hello + tail
    assert tproxy._reserve_flight_parts(hello, 'example.com', mode) == (hello,)
    for malformed in [hello[:4], hello[:-1], hello.replace(b'\x16', b'\x17', 1), hello + b'']:
        if malformed != hello:
            assert tproxy._reserve_flight_parts(malformed, host, mode) == (malformed,)


def test_all_reserves_reachable_after_failures_without_cross_host_damage(monkeypatch):
    monkeypatch.setattr(tproxy, '_strat_cache', OrderedDict())
    monkeypatch.setattr(tproxy, '_strat_scores', OrderedDict())
    host = 'cdn.discordapp.com'
    seen = []
    for _ in range(len(tproxy.strategy_order(host))):
        strategy = tproxy.strategy_order(host)[0]
        assert strategy['name'] not in seen
        seen.append(strategy['name'])
        tproxy._record_strategy_result(host, strategy['name'], False, payload=True)
    assert set(s['name'] for s in tproxy.DISCORD_RESERVES) <= set(seen)
    for other in ['youtube.com', 'example.com', 'discord.com.evil.test']:
        assert not any(s.get('flight_mode') for s in tproxy.strategy_order(other))


@pytest.fixture(scope='module')
def tls_contexts(tmp_path_factory):
    root = tmp_path_factory.mktemp('reserve-tls')
    cert, key = root/'cert.pem', root/'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-keyout', str(key), '-out', str(cert), '-subj', '/CN=cdn.discordapp.com',
                    '-addext', 'subjectAltName=DNS:cdn.discordapp.com'], check=True, capture_output=True)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    client = ssl.create_default_context(cafile=str(cert))
    return client, server


@pytest.mark.parametrize('strategy', tproxy.DISCORD_RESERVE_CANDIDATES, ids=lambda s: s['name'])
def test_real_tls_handshake_and_complete_application_payload(strategy, tls_contexts):
    client_ctx, server_ctx = tls_contexts
    ci, co, si, so = [ssl.MemoryBIO() for _ in range(4)]
    client = client_ctx.wrap_bio(ci, co, server_hostname='cdn.discordapp.com')
    server = server_ctx.wrap_bio(si, so, server_side=True)
    done_c = done_s = False
    first = True
    for _ in range(20):
        try:
            client.do_handshake(); done_c = True
        except ssl.SSLWantReadError:
            pass
        data = co.read()
        if data:
            if first:
                fake = tproxy._discord_matched_decoy(data, strategy['decoy_family'])
                assert fake and fake != data
                for part in tproxy._reserve_flight_parts(data, 'cdn.discordapp.com', strategy['flight_mode']):
                    si.write(part)
                    try:
                        server.do_handshake(); done_s = True
                    except ssl.SSLWantReadError:
                        pass
                first = False
            else:
                si.write(data)
        try:
            server.do_handshake(); done_s = True
        except ssl.SSLWantReadError:
            pass
        data = so.read()
        if data:
            ci.write(data)
        if done_c and done_s:
            break
    assert done_c and done_s
    payload = bytes(range(256)) * 4096
    received = bytearray()
    for start in range(0, len(payload), 16384):
        server.write(payload[start:start+16384])
        ci.write(so.read())
        received.extend(client.read(16384))
    assert bytes(received) == payload


def test_cancellation_between_tcp_parts_closes_connection(monkeypatch):
    closed, writes = [], []
    class Socket:
        def getsockname(self): return ('127.0.0.1', 12345)
    class Writer:
        def get_extra_info(self, name): return Socket()
        def write(self, b): writes.append(b)
        async def drain(self): pass
    async def connect(*a, **k): return None, Writer()
    async def cancel(*a): raise asyncio.CancelledError
    async def close(w): closed.append(w)
    monkeypatch.setattr(tproxy.asyncio, 'open_connection', connect)
    monkeypatch.setattr(tproxy.asyncio, 'sleep', cancel)
    monkeypatch.setattr(tproxy, 'inject_fake_for_host', lambda *a: None)
    monkeypatch.setattr(tproxy, '_close_stream_writer', close)
    hello = tproxy.build_fake_clienthello('cdn.discordapp.com')
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(tproxy.dial_and_probe_fake('127.0.0.1', 443, hello,
                    host='cdn.discordapp.com', decoy_family='mail', flight_mode='tcp_header'))
    assert writes == [hello[:1]] and len(closed) == 1


def test_unqualified_record_profiles_never_enter_runtime_ladder():
    assert len(tproxy.DISCORD_RESERVES) == 8
    assert all(s['flight_mode'].startswith('tcp_') for s in tproxy.DISCORD_RESERVES)
    assert not any(s.get('flight_mode', '').startswith('record_')
                   for s in tproxy.strategy_order('cdn.discordapp.com'))

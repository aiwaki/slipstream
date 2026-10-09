"""Regression tests for independent decoys and payload-qualified recovery."""
import asyncio
import base64
import hashlib
from collections import OrderedDict

import pytest
import tproxy


@pytest.fixture(autouse=True)
def isolated_learning(monkeypatch):
    monkeypatch.setattr(tproxy, '_strat_cache', OrderedDict())
    monkeypatch.setattr(tproxy, '_strat_scores', OrderedDict())
    monkeypatch.setattr(tproxy, 'save_strat_cache', lambda: None)


@pytest.mark.parametrize('host', ['discord.com', 'cdn.discordapp.com', 'finland14023.discord.media', 'gateway-us-east1-b.discord.gg', 'new-service.discord.com'])
def test_distinct_wire_decoys_and_no_foreign_route(host):
    hello = tproxy.build_fake_clienthello(host)
    copies = []
    for strategy in tproxy.strategy_order(host):
        if strategy.get('decoy_family'):
            fake = tproxy._discord_matched_decoy(hello, strategy['decoy_family'])
            assert len(fake) == len(hello)
            assert fake != hello
            assert tproxy.parse_sni(fake[5:]) != host
            copies.append((fake, tproxy._reserve_flight_parts(hello, host, strategy.get('flight_mode'))))
    assert copies and len(copies) == len(set(copies))
    assert tproxy.parse_sni(hello[5:]) == host
    assert not tproxy.is_geo_exit_route(host)


def test_failed_cached_primary_yields_to_independent_decoy():
    host = 'cdn.discordapp.com'
    for _ in range(100):
        tproxy._record_strategy_result(host, 'discord_matched_fake', True)
    tproxy.remember_strategy(host, 'discord_matched_fake')
    tproxy._record_strategy_result(host, 'discord_matched_fake', False)
    assert tproxy.strategy_order(host)[0]['name'].startswith('discord_decoy_')
    tproxy._record_strategy_result(host, 'discord_decoy_mail', True)
    tproxy.remember_strategy(host, 'discord_decoy_mail')
    assert tproxy.strategy_order(host)[0]['name'] == 'discord_decoy_mail'


def test_decoys_never_expand_to_youtube_or_unrelated_hosts():
    for host in ['youtube.com', 'googlevideo.com', 'example.com', 'discord.com.evil.test']:
        assert all(not s.get('decoy_family') for s in tproxy.strategy_order(host))
        assert tproxy._discord_matched_substitute(host, 'mail') is None


def response(body, status=b'200 OK', length=None):
    return b'HTTP/1.1 ' + status + b'\r\nContent-Length: ' + str(len(body) if length is None else length).encode() + b'\r\n\r\n' + body


@pytest.mark.parametrize('kind,body', [('png', b'\x89PNG\r\n\x1a\n' + b'x'*1024), ('json', b'{"url":"wss://gateway.discord.gg"}')])
def test_public_object_requires_complete_successful_payload(kind, body):
    spec = {'payload_complete': kind}
    complete = response(body)
    assert tproxy._validated_local_canary_payload(complete, spec, b'') >= 64
    for bad in [complete[:-1], response(body, b'403 Forbidden'), response(body, b'522 Timeout'), response(b'<html>blocked</html>')]:
        assert tproxy._validated_local_canary_payload(bad, spec, b'', closed=True) == 0


def test_websocket_requires_full_headers_and_matching_accept():
    spec = {'payload_probe': 'websocket_upgrade'}
    request = tproxy._local_payload_canary_request('gateway.discord.gg', spec)
    key = request.split(b'Sec-WebSocket-Key: ')[1].split(b'\r\n')[0]
    accept = base64.b64encode(hashlib.sha1(key+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
    reply = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+b'\r\n\r\n'
    assert tproxy._validated_local_canary_payload(reply, spec, request) == 64
    for bad in [reply[:-2], reply.replace(accept, b'wrong'), reply.replace(b'Connection: Upgrade', b'Connection: close')]:
        assert tproxy._validated_local_canary_payload(bad, spec, request) == 0


def test_resweep_recovers_with_full_object_and_preserves_other_host(monkeypatch):
    host = 'cdn.discordapp.com'
    tproxy.remember_strategy('discord.com', 'discord_matched_fake')
    calls = []
    async def resolve(*args):
        return ['203.0.113.10']
    async def probe(ip, candidate, strategy, spec):
        calls.append(strategy['name'])
        body = b'\x89PNG\r\n\x1a\n' + b'x'*1024
        reply = response(body, length=len(body)+100) if len(calls)==1 else response(body)
        return tproxy._validated_local_canary_payload(reply, spec, b'', closed=True)
    monkeypatch.setattr(tproxy, 'resolve_connection_ips', resolve)
    monkeypatch.setattr(tproxy, '_run_local_payload_probe', probe)
    assert asyncio.run(tproxy._resweep_local_bypass_host(host))
    assert calls == ['discord_matched_fake', 'discord_decoy_mail']
    assert tproxy._strat_cache[host] == 'discord_decoy_mail'
    assert tproxy._strat_cache['discord.com'] == 'discord_matched_fake'
    assert tproxy.strategy_order(host)[0]['name'] == 'discord_decoy_mail'


def test_strategy_choice_reaches_wire_injector(monkeypatch):
    seen = []
    async def dial(ip, port, blob, **kwargs):
        seen.append(kwargs)
    monkeypatch.setattr(tproxy, 'dial_and_probe_fake', dial)
    hello = tproxy.build_fake_clienthello('cdn.discordapp.com')
    asyncio.run(tproxy.dial_strategy('203.0.113.10',443,hello[:5],hello[5:],'cdn.discordapp.com',tproxy.STRAT_BY_NAME['discord_decoy_mail']))
    assert seen == [{'host': 'cdn.discordapp.com', 'decoy_family': 'mail'}]


def test_tls_prefix_cannot_erase_recent_full_payload_failure():
    host, name = 'cdn.discordapp.com', 'discord_matched_fake'
    tproxy.remember_strategy(host, name)
    tproxy._record_strategy_result(host, name, False, payload=True)
    for _ in range(100):
        tproxy._record_strategy_result(host, name, True)
    assert tproxy.strategy_order(host)[0]['name'] != name
    tproxy._record_strategy_result(host, name, True, payload=True)
    assert tproxy.strategy_order(host)[0]['name'] == name

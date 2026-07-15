"""Deterministic data-plane contracts for the transparent routing handler.

These fixtures exercise the real ``_handle_impl`` decision and relay path. Only
the OS-facing pieces (PF destination lookup, DNS, and upstream diallers) are
replaced, so no test can reach the network or mutate local routing state.
"""

from __future__ import annotations

import asyncio
import struct
from collections import deque
from dataclasses import dataclass

import pytest
import tproxy


@dataclass(frozen=True)
class TrafficContract:
    name: str
    policy_host: str
    tls_host: str | None
    destination_ip: str
    resolved_ip: str | None
    route_class: str
    service_group: str
    backend: str
    response: bytes


CORE_TRAFFIC_CONTRACTS = (
    TrafficContract(
        name="discord-updater-local",
        policy_host="updates.discord.com",
        tls_host="updates.discord.com",
        destination_ip="203.0.113.10",
        resolved_ip="198.51.100.10",
        route_class=tproxy.ROUTE_LOCAL_BYPASS,
        service_group=tproxy.SERVICE_DISCORD,
        backend="local",
        response=b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndiscord",
    ),
    TrafficContract(
        name="youtube-web-local",
        policy_host="www.youtube.com",
        tls_host="www.youtube.com",
        destination_ip="203.0.113.11",
        resolved_ip="198.51.100.11",
        route_class=tproxy.ROUTE_LOCAL_BYPASS,
        service_group=tproxy.SERVICE_YOUTUBE,
        backend="local",
        response=b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nyoutube",
    ),
    TrafficContract(
        name="chatgpt-websocket-geo",
        policy_host="ws.chatgpt.com",
        tls_host="ws.chatgpt.com",
        destination_ip="203.0.113.12",
        resolved_ip=None,
        route_class=tproxy.ROUTE_GEO_EXIT,
        service_group=tproxy.SERVICE_OPENAI,
        backend="geph",
        response=(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        ),
    ),
    TrafficContract(
        name="chatgpt-websocket-smart-dns",
        policy_host="ws.chatgpt.com",
        tls_host="ws.chatgpt.com",
        destination_ip="203.0.113.16",
        resolved_ip=None,
        route_class=tproxy.ROUTE_GEO_EXIT,
        service_group=tproxy.SERVICE_OPENAI,
        backend="smart_dns",
        response=(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        ),
    ),
    TrafficContract(
        name="steam-store-geo",
        policy_host="store.steampowered.com",
        tls_host="store.steampowered.com",
        destination_ip="203.0.113.13",
        resolved_ip=None,
        route_class=tproxy.ROUTE_GEO_EXIT,
        service_group=tproxy.SERVICE_STEAM_STORE,
        backend="geph",
        response=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nsteam",
    ),
    TrafficContract(
        name="generic-local",
        policy_host="example.invalid",
        tls_host="example.invalid",
        destination_ip="203.0.113.14",
        resolved_ip="198.51.100.14",
        route_class=tproxy.ROUTE_UNKNOWN,
        service_group=tproxy.SERVICE_GENERIC,
        backend="local",
        response=b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ngeneric",
    ),
)


class ScriptedReader:
    def __init__(self, *, exact=(), stream=(), block_when_empty=False):
        self._exact = deque(exact)
        self._stream = deque(stream)
        self._block_when_empty = block_when_empty

    async def readexactly(self, size):
        if not self._exact:
            raise asyncio.IncompleteReadError(b"", size)
        data = self._exact.popleft()
        if len(data) != size:
            raise AssertionError(f"expected {size} bytes, got {len(data)}")
        return data

    async def read(self, _size=-1):
        if self._stream:
            return self._stream.popleft()
        if self._block_when_empty:
            await asyncio.Event().wait()
        return b""


class CaptureWriter:
    def __init__(self):
        self.payload = bytearray()
        self.closed = False
        self._socket = object()

    def get_extra_info(self, name):
        return self._socket if name == "socket" else None

    def write(self, data):
        self.payload.extend(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True


def static_tls_fixture_record(host):
    """Build a fixed TLS first flight with SNI for handler-only contract tests."""
    name = host.encode("ascii")
    server_name = b"\x00" + struct.pack("!H", len(name)) + name
    sni_list = struct.pack("!H", len(server_name)) + server_name
    sni_extension = b"\x00\x00" + struct.pack("!H", len(sni_list)) + sni_list
    extensions = struct.pack("!H", len(sni_extension)) + sni_extension
    ciphers = b"\x00\x2f"
    client_hello = (
        b"\x03\x03"
        + (b"\x42" * 32)
        + b"\x00"
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(client_hello))[1:] + client_hello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_client(host, *, block_after_hello):
    record = static_tls_fixture_record(host)
    assert tproxy.parse_sni(record[5:]) == host
    return (
        ScriptedReader(
            exact=(record[:5], record[5:]),
            block_when_empty=block_after_hello,
        ),
        record,
    )


def probed_upstream_response(payload):
    first_size = min(16, len(payload))
    return (
        ScriptedReader(stream=(payload[first_size:],)),
        CaptureWriter(),
        payload[:first_size],
    )


def streaming_upstream_response(payload):
    return ScriptedReader(stream=(payload,)), CaptureWriter()


async def forbidden_backend(name, *_args, **_kwargs):
    raise AssertionError(f"{name} must not be selected by this traffic contract")


async def run_handler(reader, writer):
    await asyncio.wait_for(tproxy._handle_impl(reader, writer), timeout=1.0)


def isolate_runtime_state(monkeypatch):
    tproxy.reset_runtime_route_circuits()
    monkeypatch.setattr(tproxy, "_dead", {})
    monkeypatch.setattr(tproxy, "_strat_cache", {})
    monkeypatch.setattr(tproxy, "_strat_scores", {})
    monkeypatch.setattr(tproxy, "_xbox_dns_candidates", {})
    monkeypatch.setattr(tproxy, "_clean_eof_stalls", {})
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_owned", False)
    monkeypatch.setattr(tproxy, "_record_strategy_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "remember_strategy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        tproxy,
        "note_local_bypass_runtime_result",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(tproxy, "note_local_stream_stall", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        tproxy,
        "note_clean_eof_stream_stall",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(tproxy, "note_local_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "_clear_clean_eof_stalls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "route_health_event", lambda *_args, **_kwargs: None)


@pytest.mark.parametrize("contract", CORE_TRAFFIC_CONTRACTS, ids=lambda item: item.name)
def test_core_tls_traffic_contracts(monkeypatch, contract):
    """Route class, backend exclusion, and full relay must agree per user journey."""
    isolate_runtime_state(monkeypatch)
    policy = tproxy.route_policy(contract.policy_host)
    assert policy["route_class"] == contract.route_class
    assert policy["service_group"] == contract.service_group

    client, expected_first_flight = tls_client(
        contract.tls_host,
        block_after_hello=contract.backend == "local",
    )
    writer = CaptureWriter()
    calls = []
    suspensions = []

    monkeypatch.setattr(
        tproxy,
        "orig_dst",
        lambda _sock: (contract.destination_ip, 443),
    )
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "suspend_transparent_routing", suspensions.append)
    monkeypatch.setattr(tproxy, "log_geph_route_failure", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: calls.append("clear-geph"))

    if contract.backend == "local":
        assert contract.resolved_ip

        async def fake_dns(host, fallback_ip):
            calls.append(("dns", host, fallback_ip))
            return [contract.resolved_ip]

        async def fake_local(ip, port, head, body, host, strategy):
            assert head + body == expected_first_flight
            calls.append(("local", ip, port, host, strategy["name"], strategy["fake"]))
            return probed_upstream_response(contract.response)

        async def no_geph(*args, **kwargs):
            await forbidden_backend("Geph", *args, **kwargs)

        async def no_direct(*args, **kwargs):
            await forbidden_backend("direct dial", *args, **kwargs)

        monkeypatch.setattr(tproxy, "resolve_connection_ips", fake_dns)
        monkeypatch.setattr(tproxy, "dial_strategy", fake_local)
        monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
        monkeypatch.setattr(tproxy, "dial_plain", no_direct)
        monkeypatch.setattr(tproxy, "_geph_up", False)
    elif contract.backend == "smart_dns":
        async def fake_smart_dns(host, port, first_flight):
            assert first_flight == expected_first_flight
            calls.append(("smart_dns", host, port, first_flight))
            return "198.51.100.16", probed_upstream_response(contract.response)

        async def no_geph(*args, **kwargs):
            await forbidden_backend("Geph", *args, **kwargs)

        async def no_local(*args, **kwargs):
            await forbidden_backend("local desync", *args, **kwargs)

        async def no_direct(*args, **kwargs):
            await forbidden_backend("direct dial", *args, **kwargs)

        async def no_dns(*args, **kwargs):
            await forbidden_backend("generic DNS resolution", *args, **kwargs)

        monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: True)
        monkeypatch.setattr(tproxy, "_try_smart_dns_geo_connect", fake_smart_dns)
        monkeypatch.setattr(tproxy, "_geph_up", True)
        monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
        monkeypatch.setattr(tproxy, "dial_strategy", no_local)
        monkeypatch.setattr(tproxy, "dial_plain", no_direct)
        monkeypatch.setattr(tproxy, "resolve_connection_ips", no_dns)
    else:
        async def fake_geph(host, port, first_flight):
            assert first_flight == expected_first_flight
            assert tproxy.geph_active_session_count() == 1
            calls.append(("geph", host, port, first_flight))
            return streaming_upstream_response(contract.response)

        async def no_local(*args, **kwargs):
            await forbidden_backend("local desync", *args, **kwargs)

        async def no_direct(*args, **kwargs):
            await forbidden_backend("direct dial", *args, **kwargs)

        async def no_dns(*args, **kwargs):
            await forbidden_backend("DNS resolution", *args, **kwargs)

        monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
        monkeypatch.setattr(tproxy, "_geph_up", True)
        monkeypatch.setattr(tproxy, "dial_via_geph", fake_geph)
        monkeypatch.setattr(tproxy, "dial_strategy", no_local)
        monkeypatch.setattr(tproxy, "dial_plain", no_direct)
        monkeypatch.setattr(tproxy, "resolve_connection_ips", no_dns)

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == contract.response
    assert tproxy.geph_active_session_count() == 0
    assert suspensions == []
    if contract.backend == "local":
        assert calls[0] == ("dns", contract.tls_host, contract.destination_ip)
        backend_calls = [call for call in calls if call[0] == "local"]
        assert len(backend_calls) == 1
        assert backend_calls[0][:4] == (
            "local",
            contract.resolved_ip,
            443,
            contract.tls_host,
        )
        if contract.route_class == tproxy.ROUTE_LOCAL_BYPASS:
            assert backend_calls[0][5] is True
    elif contract.backend == "smart_dns":
        assert [call[:3] for call in calls if call[0] == "smart_dns"] == [
            ("smart_dns", contract.tls_host, 443)
        ]
    else:
        assert [call[:3] for call in calls if call[0] == "geph"] == [
            ("geph", contract.tls_host, 443)
        ]


def test_local_handler_races_addresses_inside_one_strategy_without_geph(
    monkeypatch,
):
    """A stalled CDN edge must not delay a healthy edge or change route class."""
    isolate_runtime_state(monkeypatch)
    host = "updates.discord.com"
    first_ip = "198.51.100.20"
    second_ip = "198.51.100.21"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndiscord"
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    first_started = asyncio.Event()
    first_cancelled = asyncio.Event()
    calls = []

    async def fake_dns(actual_host, fallback_ip):
        assert (actual_host, fallback_ip) == (host, "203.0.113.20")
        return [first_ip, second_ip]

    async def fake_local(ip, port, head, body, actual_host, strategy):
        assert (port, head + body, actual_host) == (
            443,
            expected_first_flight,
            host,
        )
        calls.append((ip, strategy["name"]))
        if ip == first_ip:
            first_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                first_cancelled.set()
        await first_started.wait()
        return probed_upstream_response(response)

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.20", 443))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", fake_dns)
    monkeypatch.setattr(tproxy, "dial_strategy", fake_local)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "ADDRESS_RACE_STAGGER_MS", 0)
    monkeypatch.setattr(tproxy, "ADDRESS_RACE_TIMEOUT_MS", 500)

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert calls == [
        (first_ip, calls[0][1]),
        (second_ip, calls[0][1]),
    ]
    assert first_cancelled.is_set()
    policy = tproxy.route_policy(host)
    assert policy["service_group"] == tproxy.SERVICE_DISCORD
    assert policy["route_class"] == tproxy.ROUTE_LOCAL_BYPASS
    assert policy["strategy_set"] == tproxy.STRATEGY_FAKE_ONLY


def test_smart_dns_handler_races_proven_addresses_without_reaching_geph(
    monkeypatch,
):
    """Smart DNS may vary its edge, but the route remains the proven backend."""
    isolate_runtime_state(monkeypatch)
    host = "ws.chatgpt.com"
    first_ip = "198.51.100.30"
    second_ip = "198.51.100.31"
    response = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
    client, expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    first_started = asyncio.Event()
    first_cancelled = asyncio.Event()
    calls = []

    async def fake_system_dns(actual_host):
        assert actual_host == host
        return [first_ip, second_ip]

    async def fake_probe(ip, port, first_flight, probe_timeout=3.0):
        assert (port, first_flight, probe_timeout) == (
            443,
            expected_first_flight,
            3.0,
        )
        calls.append(ip)
        if ip == first_ip:
            first_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                first_cancelled.set()
        await first_started.wait()
        return probed_upstream_response(response)

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.30", 443))
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: True)
    monkeypatch.setattr(tproxy, "smart_dns_available", lambda: True)
    monkeypatch.setattr(tproxy, "system_resolve_async", fake_system_dns)
    monkeypatch.setattr(tproxy, "dial_and_probe", fake_probe)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "ADDRESS_RACE_STAGGER_MS", 0)
    monkeypatch.setattr(tproxy, "ADDRESS_RACE_TIMEOUT_MS", 500)

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert calls == [first_ip, second_ip]
    assert first_cancelled.is_set()


def test_telegram_raw_dc_contract_is_safety_passthrough(monkeypatch):
    """Bare MTProto stays untouched; the user-facing blocked-network path is tg-ws-proxy."""
    isolate_runtime_state(monkeypatch)
    policy = tproxy.route_policy("telegram.org")
    assert policy["route_class"] == tproxy.ROUTE_DIRECT
    assert policy["service_group"] == tproxy.SERVICE_TELEGRAM

    destination_ip = "149.154.160.1"
    initial = b"\x01\x02\x03\x04\x05"
    body = b"mtproto-client"
    response = b"mtproto-server"
    client = ScriptedReader(exact=(initial,), stream=(body,))
    writer = CaptureWriter()
    calls = []

    async def fake_direct(ip, port, first_flight):
        assert first_flight == initial + body
        calls.append(("direct", ip, port, first_flight))
        return streaming_upstream_response(response)

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: (destination_ip, 443))
    monkeypatch.setattr(tproxy, "dial_plain", fake_direct)
    monkeypatch.setattr(tproxy, "dial_strategy", lambda *args, **kwargs: no_backend("local desync", *args, **kwargs))
    monkeypatch.setattr(tproxy, "dial_via_geph", lambda *args, **kwargs: no_backend("Geph", *args, **kwargs))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", lambda *args, **kwargs: no_backend("DNS", *args, **kwargs))
    monkeypatch.setattr(tproxy, "note_telegram_direct_success", lambda: calls.append(("success",)))
    monkeypatch.setattr(
        tproxy,
        "note_telegram_direct_failure",
        lambda reason: pytest.fail(f"unexpected Telegram failure: {reason}"),
    )

    asyncio.run(run_handler(client, writer))

    assert calls == [
        ("direct", destination_ip, 443, initial + body),
        ("success",),
    ]
    assert bytes(writer.payload) == response


def test_smart_dns_runtime_miss_falls_back_to_geph_without_local_desync(monkeypatch):
    """A proven Smart DNS route may fail at runtime, but never escapes to local bypass."""
    isolate_runtime_state(monkeypatch)
    host = "ws.chatgpt.com"
    client, expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    calls = []
    response = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"

    async def smart_dns_miss(actual_host, port, first_flight):
        assert (actual_host, port, first_flight) == (host, 443, expected_first_flight)
        calls.append(("smart_dns", actual_host))
        return None

    async def fake_geph(actual_host, port, first_flight):
        assert (actual_host, port, first_flight) == (host, 443, expected_first_flight)
        calls.append(("geph", actual_host))
        return streaming_upstream_response(response)

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.17", 443))
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: True)
    monkeypatch.setattr(tproxy, "_try_smart_dns_geo_connect", smart_dns_miss)
    monkeypatch.setattr(
        tproxy,
        "_smart_dns_mark_failure",
        lambda actual_host, reason, group: calls.append(("smart_dns_miss", actual_host, reason, group)),
    )
    monkeypatch.setattr(tproxy, "dial_via_geph", fake_geph)
    monkeypatch.setattr(tproxy, "dial_strategy", lambda *args, **kwargs: no_backend("local desync", *args, **kwargs))
    monkeypatch.setattr(tproxy, "dial_plain", lambda *args, **kwargs: no_backend("direct dial", *args, **kwargs))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", lambda *args, **kwargs: no_backend("generic DNS", *args, **kwargs))
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: calls.append(("clear_geph",)))

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert calls == [
        ("smart_dns", host),
        ("smart_dns_miss", host, "smart dns runtime probe failed", tproxy.SERVICE_OPENAI),
        ("geph", host),
        ("clear_geph",),
    ]


def test_geo_exit_early_close_pauses_private_pf_without_local_fallback(monkeypatch):
    """A SOCKS connect without downstream bytes must leave the retry on native routing."""
    isolate_runtime_state(monkeypatch)
    host = "ws.chatgpt.com"
    client, expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    failures = []
    suspensions = []

    async def empty_geph(actual_host, port, first_flight):
        assert (actual_host, port, first_flight) == (host, 443, expected_first_flight)
        return streaming_upstream_response(b"")

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.18", 443))
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "dial_via_geph", empty_geph)
    monkeypatch.setattr(tproxy, "dial_strategy", lambda *args, **kwargs: no_backend("local desync", *args, **kwargs))
    monkeypatch.setattr(tproxy, "dial_plain", lambda *args, **kwargs: no_backend("direct dial", *args, **kwargs))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", lambda *args, **kwargs: no_backend("generic DNS", *args, **kwargs))
    monkeypatch.setattr(tproxy, "log_geph_route_failure", lambda actual_host, reason: failures.append((actual_host, reason)))
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: pytest.fail("empty payload must not clear failure"))
    monkeypatch.setattr(tproxy, "suspend_transparent_routing", suspensions.append)

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == b""
    assert failures == [(host, "remote closed without response")]
    assert suspensions == ["geo-exit remote close before payload"]


@pytest.mark.parametrize("smart_dns_ready", [False, True], ids=["no-smart-dns", "smart-dns-miss"])
def test_geo_exit_unavailable_never_falls_back_to_local(monkeypatch, smart_dns_ready):
    """A broken geo backend pauses only Slipstream's PF anchor for the retry."""
    isolate_runtime_state(monkeypatch)
    host = "ws.chatgpt.com"
    assert tproxy.route_policy(host)["route_class"] == tproxy.ROUTE_GEO_EXIT
    client, expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    suspensions = []
    smart_dns_misses = []

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    async def smart_dns_miss(actual_host, port, first_flight):
        assert (actual_host, port, first_flight) == (host, 443, expected_first_flight)
        smart_dns_misses.append(actual_host)
        return None

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.15", 443))
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: smart_dns_ready)
    monkeypatch.setattr(tproxy, "_try_smart_dns_geo_connect", smart_dns_miss)
    monkeypatch.setattr(tproxy, "_smart_dns_mark_failure", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "dial_via_geph", lambda *args, **kwargs: no_backend("Geph", *args, **kwargs))
    monkeypatch.setattr(tproxy, "dial_strategy", lambda *args, **kwargs: no_backend("local desync", *args, **kwargs))
    monkeypatch.setattr(tproxy, "dial_plain", lambda *args, **kwargs: no_backend("direct dial", *args, **kwargs))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", lambda *args, **kwargs: no_backend("DNS", *args, **kwargs))
    monkeypatch.setattr(tproxy, "log_geph_route_failure", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "suspend_transparent_routing", suspensions.append)

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == b""
    assert writer.closed is True
    assert suspensions == ["geo-exit tunnel down"]
    assert smart_dns_misses == ([host] if smart_dns_ready else [])


def test_local_circuit_counts_one_full_strategy_ladder_as_one_failure(monkeypatch):
    """Individual desync misses must not open the protected backend circuit."""
    isolate_runtime_state(monkeypatch)
    host = "updates.discord.com"
    calls = []
    clock = iter((0, 1, 2, 3, 4))
    strategies = (
        {"name": "fake-a", "fake": b"a"},
        {"name": "fake-b", "fake": b"b"},
    )

    async def fake_dns(actual_host, fallback_ip):
        calls.append(("dns", actual_host, fallback_ip))
        return ["198.51.100.40"]

    async def failed_strategy(ip, port, head, body, actual_host, strategy):
        calls.append(("local", actual_host, strategy["name"]))
        return None

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.40", 443))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", fake_dns)
    monkeypatch.setattr(tproxy, "strategy_order", lambda _host: strategies)
    monkeypatch.setattr(tproxy, "dial_strategy", failed_strategy)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "DEAD_TTL", 0)
    monkeypatch.setattr(
        tproxy,
        "_runtime_route_circuit_now_ms",
        lambda: next(clock),
    )

    writers = []
    for _ in range(3):
        client, _first_flight = tls_client(host, block_after_hello=False)
        writer = CaptureWriter()
        writers.append(writer)
        asyncio.run(run_handler(client, writer))

    assert len([call for call in calls if call[0] == "dns"]) == 2
    assert [call[2] for call in calls if call[0] == "local"] == [
        "fake-a",
        "fake-b",
        "fake-a",
        "fake-b",
    ]
    assert all(writer.closed for writer in writers)
    snapshot = tproxy.runtime_route_circuit_snapshot()
    assert len(snapshot) == 1
    assert snapshot[0].key.service_group == tproxy.SERVICE_DISCORD
    assert snapshot[0].key.route_class == tproxy.ROUTE_LOCAL_BYPASS
    assert snapshot[0].key.backend_id == tproxy.BACKEND_LOCAL_ENGINE
    assert snapshot[0].state.phase == tproxy.route_circuit.PHASE_OPEN
    assert snapshot[0].state.consecutive_failures == 2


def test_smart_dns_circuit_suppresses_only_smart_dns_then_uses_owned_geph(
    monkeypatch,
):
    """A cooling Smart DNS backend must not change the reviewed geo route."""
    isolate_runtime_state(monkeypatch)
    host = "ws.chatgpt.com"
    calls = []
    suspensions = []
    clock = iter(range(11))
    response = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"

    async def smart_dns_miss(actual_host, port, _first_flight):
        calls.append(("smart_dns", actual_host, port))
        return None

    async def healthy_geph(actual_host, port, _first_flight):
        calls.append(("geph", actual_host, port))
        return streaming_upstream_response(response)

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.41", 443))
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: True)
    monkeypatch.setattr(tproxy, "_try_smart_dns_geo_connect", smart_dns_miss)
    monkeypatch.setattr(
        tproxy,
        "_smart_dns_mark_failure",
        lambda actual_host, _reason, _group: calls.append(
            ("smart_dns_failure", actual_host)
        ),
    )
    monkeypatch.setattr(tproxy, "dial_via_geph", healthy_geph)
    monkeypatch.setattr(
        tproxy,
        "dial_strategy",
        lambda *args, **kwargs: no_backend("local desync", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "resolve_connection_ips",
        lambda *args, **kwargs: no_backend("generic DNS", *args, **kwargs),
    )
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: None)
    monkeypatch.setattr(tproxy, "suspend_transparent_routing", suspensions.append)
    monkeypatch.setattr(
        tproxy,
        "_runtime_route_circuit_now_ms",
        lambda: next(clock),
    )

    for _ in range(3):
        client, _first_flight = tls_client(host, block_after_hello=False)
        writer = CaptureWriter()
        asyncio.run(run_handler(client, writer))
        assert bytes(writer.payload) == response

    assert [call[0] for call in calls].count("smart_dns") == 2
    assert [call[0] for call in calls].count("smart_dns_failure") == 2
    assert [call[0] for call in calls].count("geph") == 3
    assert suspensions == []
    snapshot = tproxy.runtime_route_circuit_snapshot()
    assert len(snapshot) == 1
    assert snapshot[0].key.backend_id == tproxy.GEO_BACKEND_SMART_DNS
    assert snapshot[0].state.phase == tproxy.route_circuit.PHASE_OPEN


def test_geph_half_open_recovers_on_first_payload_before_long_relay_ends(
    monkeypatch,
):
    """A healthy long-lived stream must release the single half-open permit."""
    isolate_runtime_state(monkeypatch)
    host = "ws.chatgpt.com"
    policy = tproxy.route_policy(host)
    response = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
    clears = []

    tproxy.runtime_route_circuit_record_result(
        policy,
        tproxy.GEO_BACKEND_GEPH,
        False,
        owned=True,
        now_ms=0,
    )
    tproxy.runtime_route_circuit_record_result(
        policy,
        tproxy.GEO_BACKEND_GEPH,
        False,
        owned=True,
        now_ms=1,
    )
    assert tproxy.runtime_route_circuit_snapshot()[0].state.phase == (
        tproxy.route_circuit.PHASE_OPEN
    )

    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    clock = iter((1001, 1002))

    async def long_lived_geph(actual_host, port, first_flight):
        assert (actual_host, port, first_flight) == (
            host,
            443,
            expected_first_flight,
        )
        return (
            ScriptedReader(stream=(response,), block_when_empty=True),
            CaptureWriter(),
        )

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.43", 443))
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "dial_via_geph", long_lived_geph)
    monkeypatch.setattr(
        tproxy,
        "dial_strategy",
        lambda *args, **kwargs: no_backend("local desync", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "resolve_connection_ips",
        lambda *args, **kwargs: no_backend("generic DNS", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "clear_geph_route_failure",
        lambda: clears.append("clear"),
    )
    monkeypatch.setattr(
        tproxy,
        "log_geph_route_failure",
        lambda *_args, **_kwargs: pytest.fail("healthy payload is not a failure"),
    )
    monkeypatch.setattr(
        tproxy,
        "suspend_transparent_routing",
        lambda _reason: pytest.fail("healthy payload must not pause routing"),
    )
    monkeypatch.setattr(
        tproxy,
        "_runtime_route_circuit_now_ms",
        lambda: next(clock),
    )

    async def scenario():
        task = asyncio.create_task(tproxy._handle_impl(client, writer))
        for _ in range(20):
            if writer.payload:
                break
            await asyncio.sleep(0)
        assert bytes(writer.payload) == response
        assert tproxy.runtime_route_circuit_snapshot() == ()
        assert tproxy.runtime_route_circuit_allows(
            policy,
            tproxy.GEO_BACKEND_GEPH,
            owned=True,
            now_ms=1003,
        ) is True
        assert not task.done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())

    assert clears == ["clear"]
    assert tproxy.geph_active_session_count() == 0


def test_unknown_local_failures_do_not_persist_or_promote_to_geph(monkeypatch):
    """Unclassified sites keep trying their local ladder independently."""
    isolate_runtime_state(monkeypatch)
    host = "unclassified.example"
    calls = []

    async def fake_dns(actual_host, _fallback_ip):
        calls.append(("dns", actual_host))
        return ["198.51.100.42"]

    async def failed_strategy(_ip, _port, _head, _body, actual_host, _strategy):
        calls.append(("local", actual_host))
        return None

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.42", 443))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", fake_dns)
    monkeypatch.setattr(
        tproxy,
        "strategy_order",
        lambda _host: ({"name": "plain", "fake": b""},),
    )
    monkeypatch.setattr(tproxy, "dial_strategy", failed_strategy)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
    monkeypatch.setattr(tproxy, "xbox_dns_resolve_async", lambda _host: asyncio.sleep(0, result=[]))
    monkeypatch.setattr(tproxy, "DEAD_TTL", 0)

    for _ in range(2):
        client, _first_flight = tls_client(host, block_after_hello=False)
        writer = CaptureWriter()
        asyncio.run(run_handler(client, writer))

    assert [call[0] for call in calls].count("dns") == 2
    assert [call[0] for call in calls].count("local") == 2
    assert tproxy.runtime_route_circuit_snapshot() == ()


def test_external_geph_never_enters_owned_runtime_circuit_state():
    tproxy.reset_runtime_route_circuits()
    policy = tproxy.route_policy("ws.chatgpt.com")

    assert tproxy.runtime_route_circuit_before_request(
        policy,
        tproxy.GEO_BACKEND_GEPH,
        owned=False,
        now_ms=0,
    ) is None
    assert tproxy.runtime_route_circuit_record_result(
        policy,
        tproxy.GEO_BACKEND_GEPH,
        False,
        owned=False,
        now_ms=1,
    ) is None
    assert tproxy.runtime_route_circuit_snapshot() == ()


def test_runtime_circuit_state_failure_cannot_block_the_selected_route(monkeypatch):
    class BrokenRegistry:
        def __init__(self):
            self.cleared = False

        def apply(self, _event):
            raise ValueError("corrupt state")

        def clear(self):
            self.cleared = True

    registry = BrokenRegistry()
    monkeypatch.setattr(tproxy, "_runtime_route_circuits", registry)
    policy = tproxy.route_policy("updates.discord.com")

    assert tproxy.runtime_route_circuit_allows(
        policy,
        tproxy.BACKEND_LOCAL_ENGINE,
        now_ms=0,
    ) is True
    assert registry.cleared is True

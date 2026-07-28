"""Deterministic data-plane contracts for the transparent routing handler.

These fixtures exercise the real ``_handle_impl`` decision and relay path. Only
the OS-facing pieces (PF destination lookup, DNS, and upstream diallers) are
replaced, so no test can reach the network or mutate local routing state.
"""

from __future__ import annotations

import asyncio
import struct
import time
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
        name="github-direct",
        policy_host="github.com",
        tls_host="github.com",
        destination_ip="203.0.113.14",
        resolved_ip=None,
        route_class=tproxy.ROUTE_DIRECT,
        service_group=tproxy.SERVICE_GITHUB,
        backend="direct",
        response=b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ngithub",
    ),
    TrafficContract(
        name="generic-baseline-direct",
        policy_host="example.invalid",
        tls_host="example.invalid",
        destination_ip="203.0.113.15",
        resolved_ip=None,
        route_class=tproxy.ROUTE_UNKNOWN,
        service_group=tproxy.SERVICE_GENERIC,
        backend="direct",
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
    monkeypatch.setattr(tproxy, "_xbox_dns_attempts", {})
    monkeypatch.setattr(tproxy, "_clean_eof_stalls", {})
    monkeypatch.setattr(tproxy, "_server_first_closes", {})
    monkeypatch.setattr(tproxy, "_auto_geph", {})
    monkeypatch.setattr(tproxy, "_auto_geph_candidates", {})
    monkeypatch.setattr(tproxy, "_local_partial_stalls", {})
    monkeypatch.setattr(tproxy, "_local_zero_payload_failures", {})
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_owned", False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_reason", "")
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
        "note_local_ladder_partial_stall",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        tproxy,
        "note_clean_eof_stream_stall",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        tproxy,
        "note_server_first_route_close",
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
        block_after_hello=contract.backend in ("local", "direct"),
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
    monkeypatch.setattr(tproxy, "suspend_geo_exit_backend", suspensions.append)
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
    elif contract.backend == "direct":
        async def fake_direct(ip, port, first_flight):
            assert first_flight == expected_first_flight
            calls.append(("direct", ip, port, first_flight))
            return streaming_upstream_response(contract.response)

        async def fake_system_probe(ip, port, first_flight):
            assert first_flight == expected_first_flight
            calls.append(("direct", ip, port, first_flight))
            return (
                tproxy.SYSTEM_PROBE_PAYLOAD,
                probed_upstream_response(contract.response),
            )

        async def no_geph(*args, **kwargs):
            await forbidden_backend("Geph", *args, **kwargs)

        async def no_local(*args, **kwargs):
            await forbidden_backend("local desync", *args, **kwargs)

        async def no_dns(*args, **kwargs):
            await forbidden_backend("DNS resolution", *args, **kwargs)

        monkeypatch.setattr(tproxy, "dial_plain", fake_direct)
        monkeypatch.setattr(tproxy, "_try_exact_system_probe", fake_system_probe)
        monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
        monkeypatch.setattr(tproxy, "dial_strategy", no_local)
        monkeypatch.setattr(tproxy, "resolve_connection_ips", no_dns)
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
        monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
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
    elif contract.backend == "direct":
        assert [call[:3] for call in calls if call[0] == "direct"] == [
            ("direct", contract.destination_ip, 443)
        ]
    elif contract.backend == "smart_dns":
        assert [call[:3] for call in calls if call[0] == "smart_dns"] == [
            ("smart_dns", contract.tls_host, 443)
        ]
    else:
        assert [call[:3] for call in calls if call[0] == "geph"] == [
            ("geph", contract.tls_host, 443)
        ]


def test_tls_without_sni_preserves_exact_system_destination(monkeypatch):
    """ECH/no-SNI traffic must not be guessed, re-resolved, or desynchronized."""
    isolate_runtime_state(monkeypatch)
    body = b"\x00" * 64
    head = b"\x16\x03\x01" + struct.pack("!H", len(body))
    first_flight = head + body
    assert tproxy.parse_sni(body) is None
    client = ScriptedReader(exact=(head, body), block_when_empty=True)
    writer = CaptureWriter()
    calls = []
    response = b"opaque tls response"

    async def exact_direct(ip, port, payload):
        calls.append((ip, port, payload))
        return streaming_upstream_response(response)

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.30", 443))
    monkeypatch.setattr(tproxy, "dial_plain", exact_direct)
    monkeypatch.setattr(
        tproxy,
        "resolve_connection_ips",
        lambda *args, **kwargs: no_backend("DNS resolution", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_strategy",
        lambda *args, **kwargs: no_backend("local strategy", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_via_geph",
        lambda *args, **kwargs: no_backend("Geph", *args, **kwargs),
    )

    asyncio.run(run_handler(client, writer))

    assert calls == [("203.0.113.30", 443, first_flight)]
    assert bytes(writer.payload) == response


def test_unknown_direct_connect_failure_continues_local_recovery_same_request(
    monkeypatch,
):
    """A first-flight-only route can be retried before any server byte is exposed."""
    isolate_runtime_state(monkeypatch)
    host = "temporarily-blocked.example"
    response = b"Xbox DNS local recovery payload"
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    calls = []

    async def failed_direct(ip, port, first_flight):
        calls.append((ip, port, first_flight))
        return tproxy.SYSTEM_PROBE_CLOSED, None

    async def healthy_xbox(actual_host, port, head, body, **_kwargs):
        calls.append(("xbox", actual_host, port, head + body))
        return "198.51.100.31", probed_upstream_response(response)

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.31", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", failed_direct)
    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", healthy_xbox)
    monkeypatch.setattr(
        tproxy,
        "runtime_route_circuit_allows",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        tproxy,
        "resolve_connection_ips",
        lambda *args, **kwargs: no_backend("local DNS", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_strategy",
        lambda *args, **kwargs: no_backend("local strategy", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_via_geph",
        lambda *args, **kwargs: no_backend("Geph", *args, **kwargs),
    )

    asyncio.run(run_handler(client, writer))

    assert calls == [
        ("203.0.113.31", 443, expected_first_flight),
        ("xbox", host, 443, expected_first_flight),
    ]
    assert bytes(writer.payload) == response


def test_exact_system_probe_timeout_commits_the_original_stream(monkeypatch):
    upstream_reader = ScriptedReader(block_when_empty=True)
    upstream_writer = CaptureWriter()

    async def exact_direct(_ip, _port, _first_flight):
        return upstream_reader, upstream_writer

    monkeypatch.setattr(tproxy, "dial_plain", exact_direct)

    state, result = asyncio.run(
        tproxy._try_exact_system_probe(
            "203.0.113.32",
            443,
            b"client hello",
            probe_timeout=0.01,
        )
    )

    assert state == tproxy.SYSTEM_PROBE_PENDING
    assert result == (upstream_reader, upstream_writer, b"")
    assert upstream_writer.closed is False


def test_exact_system_probe_eof_is_replay_safe(monkeypatch):
    upstream_reader = ScriptedReader()
    upstream_writer = CaptureWriter()

    async def exact_direct(_ip, _port, _first_flight):
        return upstream_reader, upstream_writer

    monkeypatch.setattr(tproxy, "dial_plain", exact_direct)

    state, result = asyncio.run(
        tproxy._try_exact_system_probe(
            "203.0.113.33",
            443,
            b"client hello",
            probe_timeout=0.01,
        )
    )

    assert state == tproxy.SYSTEM_PROBE_CLOSED
    assert result is None
    assert upstream_writer.closed is True


def test_exact_system_probe_cancellation_closes_the_owned_stream(monkeypatch):
    upstream_reader = ScriptedReader(block_when_empty=True)
    upstream_writer = CaptureWriter()

    async def exact_direct(_ip, _port, _first_flight):
        return upstream_reader, upstream_writer

    monkeypatch.setattr(tproxy, "dial_plain", exact_direct)

    async def scenario():
        task = asyncio.create_task(
            tproxy._try_exact_system_probe(
                "203.0.113.34",
                443,
                b"client hello",
                probe_timeout=30.0,
            )
        )
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())

    assert upstream_writer.closed is True


def test_unknown_xbox_failure_advances_to_local_ladder_without_geph(monkeypatch):
    """An exhausted Xbox DNS stage must continue locally in the same retry."""
    isolate_runtime_state(monkeypatch)
    host = "partial-http2.example"
    local_ip = "198.51.100.42"
    response = b"HTTP/2 local recovery payload"
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    calls = []
    tproxy._mark_xbox_dns_candidate(host)

    async def failed_xbox(actual_host, port, head, body, **_kwargs):
        calls.append(("xbox", actual_host, port, head + body))
        return None

    async def local_dns(actual_host, fallback_ip):
        calls.append(("dns", actual_host, fallback_ip))
        return [local_ip]

    async def local_strategy(ip, port, head, body, actual_host, strategy):
        calls.append(("local", ip, port, actual_host, strategy["name"]))
        assert head + body == expected_first_flight
        return probed_upstream_response(response)

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.41", 443))
    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", failed_xbox)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", local_dns)
    monkeypatch.setattr(tproxy, "dial_strategy", local_strategy)
    monkeypatch.setattr(
        tproxy,
        "dial_plain",
        lambda *args, **kwargs: no_backend("system direct", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_via_geph",
        lambda *args, **kwargs: no_backend("Geph", *args, **kwargs),
    )

    asyncio.run(run_handler(client, writer))

    assert [call[0] for call in calls] == ["xbox", "dns", "local"]
    assert bytes(writer.payload) == response
    assert not tproxy._xbox_dns_candidate_active(host)
    assert tproxy._xbox_dns_attempted_recently(host)
    assert (
        tproxy.unknown_recovery_stage(host)
        == tproxy.UNKNOWN_RECOVERY_LOCAL_LADDER
    )

    calls.clear()
    retry_client, _ = tls_client(host, block_after_hello=True)
    retry_writer = CaptureWriter()
    asyncio.run(run_handler(retry_client, retry_writer))

    assert [call[0] for call in calls] == ["dns", "local"]
    assert bytes(retry_writer.payload) == response


def test_unknown_exhaustion_uses_only_verified_owned_geph_same_request(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    host = "foreign-ip-only.example"
    local_ip = "198.51.100.61"
    response = b"\x16\x03\x03\x00\x60" + (b"G" * 96)
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    calls = []
    strategies = (
        tproxy.STRAT_BY_NAME["split64+fake"],
        tproxy.STRAT_BY_NAME["split16+fake"],
    )

    async def failed_system(ip, port, first_flight):
        calls.append(("system", ip, port, first_flight))
        return tproxy.SYSTEM_PROBE_CLOSED, None

    async def failed_xbox(
        actual_host,
        port,
        head,
        body,
        *,
        attempt_summary=None,
    ):
        calls.append(("xbox", actual_host, port, head + body))
        if attempt_summary is not None:
            attempt_summary["attempted"] = 1
            attempt_summary["outcomes"] = {
                "198.51.100.60": tproxy.ROUTE_PROBE_CLOSED,
            }
        return None

    async def local_dns(actual_host, fallback_ip):
        calls.append(("dns", actual_host, fallback_ip))
        return [local_ip]

    async def failed_local(ip, port, head, body, actual_host, strategy):
        calls.append(("local", ip, port, actual_host, strategy["name"]))
        assert head + body == expected_first_flight
        tproxy._publish_route_probe_outcome(tproxy.ROUTE_PROBE_CLOSED)
        return None

    async def healthy_owned_geph(actual_host, port, first_flight):
        calls.append(("geph", actual_host, port, first_flight))
        return streaming_upstream_response(response)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.61", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", failed_system)
    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", failed_xbox)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", local_dns)
    monkeypatch.setattr(tproxy, "strategy_order", lambda _host: strategies)
    monkeypatch.setattr(tproxy, "dial_strategy", failed_local)
    monkeypatch.setattr(tproxy, "dial_via_geph", healthy_owned_geph)
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: None)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    asyncio.run(run_handler(client, writer))

    assert [call[0] for call in calls] == [
        "system",
        "xbox",
        "dns",
        "local",
        "local",
        "geph",
    ]
    assert bytes(writer.payload) == response
    assert tproxy._auto_geph_learned_exact_host(host)
    assert tproxy.geph_active_session_count() == 0


def test_proven_unknown_waits_for_owned_geph_recovery_during_backend_hold(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    host = "recovering-foreign-exit.example"
    first_flight = static_tls_fixture_record(host)
    response = b"\x16\x03\x03\x00\x60" + (b"R" * 96)
    reader = ScriptedReader()
    writer = CaptureWriter()
    calls = []
    probe_calls = []
    now = time.monotonic()

    async def healthy_owned_geph(actual_host, port, payload):
        calls.append((actual_host, port, payload))
        return streaming_upstream_response(response)

    def observe_owned_geph_recovery():
        probe_calls.append(True)
        return "ready" if len(probe_calls) > 1 else "down"

    monkeypatch.setattr(
        tproxy,
        "AUTO_GEPH_RECOVERY_GRACE",
        0.05,
        raising=False,
    )
    monkeypatch.setattr(
        tproxy,
        "AUTO_GEPH_RECOVERY_POLL",
        0.001,
        raising=False,
    )
    monkeypatch.setattr(tproxy, "dial_via_geph", healthy_owned_geph)
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        observe_owned_geph_recovery,
    )
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: None)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_geph_backend_hold_until",
        time.time() + tproxy.GEPH_BACKEND_FAILURE_HOLD,
    )
    tproxy._auto_geph_candidates[host] = now + 10.0

    assert asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            first_flight,
            reader,
            writer,
        )
    )
    assert len(probe_calls) == 2
    assert calls == [(host, 443, first_flight)]
    assert bytes(writer.payload) == response
    assert tproxy._auto_geph_learned_exact_host(host)
    assert tproxy._geph_backend_hold_until == 0.0
    assert tproxy._geph_backend_hold_reason == ""
    assert tproxy.geph_active_session_count() == 0


def test_proven_unknown_survives_background_confirmation_race(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "background-confirmed-foreign-exit.example"
    first_flight = static_tls_fixture_record(host)
    response = b"\x16\x03\x03\x00\x60" + (b"B" * 96)
    writer = CaptureWriter()
    now = time.monotonic()

    async def healthy_owned_geph(_host, _port, _payload):
        return streaming_upstream_response(response)

    async def complete_background_confirmation():
        await asyncio.sleep(0.005)
        tproxy._auto_geph[host] = time.time() + 60.0
        tproxy._auto_geph_candidates.pop(host, None)
        tproxy._geph_up = True

    monkeypatch.setattr(
        tproxy,
        "AUTO_GEPH_RECOVERY_GRACE",
        0.05,
    )
    monkeypatch.setattr(
        tproxy,
        "AUTO_GEPH_RECOVERY_POLL",
        0.001,
    )
    monkeypatch.setattr(tproxy, "dial_via_geph", healthy_owned_geph)
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        lambda: "down",
    )
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    tproxy._auto_geph_candidates[host] = now + 10.0

    async def exercise():
        confirmation = asyncio.create_task(complete_background_confirmation())
        selected = await tproxy._try_unknown_owned_geph_route(
            host,
            443,
            first_flight,
            ScriptedReader(),
            writer,
        )
        await confirmation
        return selected

    assert asyncio.run(exercise())
    assert bytes(writer.payload) == response
    assert tproxy._auto_geph_learned_exact_host(host)
    assert tproxy.geph_active_session_count() == 0


def test_unproven_unknown_never_waits_for_owned_geph_recovery(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "unproven-foreign-exit.example"
    sleep_calls = []

    async def forbidden_sleep(delay):
        sleep_calls.append(delay)
        raise AssertionError("unproven host must not wait for Geph")

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    monkeypatch.setattr(tproxy.asyncio, "sleep", forbidden_sleep)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        lambda: pytest.fail("unproven host must not probe Geph"),
    )
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    selected = asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            static_tls_fixture_record(host),
            ScriptedReader(),
            CaptureWriter(),
        )
    )

    assert not selected
    assert sleep_calls == []
    assert host not in tproxy._auto_geph


def test_proven_unknown_stops_when_conflict_appears_during_recovery(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "conflicted-foreign-exit.example"

    def observe_conflict():
        tproxy._geph_port_conflict = True
        tproxy._geph_port = None
        return "down"

    async def forbidden_sleep(_delay):
        raise AssertionError("listener conflict must stop recovery immediately")

    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_probe_owned_geph_recovery_state",
        observe_conflict,
    )
    monkeypatch.setattr(tproxy.asyncio, "sleep", forbidden_sleep)
    tproxy._auto_geph_candidates[host] = time.monotonic() + 10.0

    assert not asyncio.run(tproxy._wait_for_owned_geph_candidate(host))
    assert tproxy._geph_port_conflict


def test_unknown_local_timeouts_do_not_become_owned_geph_proof(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "slow-but-not-closed.example"
    local_ip = "198.51.100.62"
    client, _expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    strategies = (
        tproxy.STRAT_BY_NAME["split64+fake"],
        tproxy.STRAT_BY_NAME["split16+fake"],
    )

    async def failed_system(_ip, _port, _first_flight):
        return tproxy.SYSTEM_PROBE_CLOSED, None

    async def closed_xbox(
        _actual_host,
        _port,
        _head,
        _body,
        *,
        attempt_summary=None,
    ):
        if attempt_summary is not None:
            attempt_summary["attempted"] = 1
            attempt_summary["outcomes"] = {
                "198.51.100.60": tproxy.ROUTE_PROBE_CLOSED,
            }
        return None

    async def local_dns(_actual_host, _fallback_ip):
        return [local_ip]

    async def timed_out_local(*_args, **_kwargs):
        tproxy._publish_route_probe_outcome(tproxy.ROUTE_PROBE_PENDING)
        return None

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.62", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", failed_system)
    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", closed_xbox)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", local_dns)
    monkeypatch.setattr(tproxy, "strategy_order", lambda _host: strategies)
    monkeypatch.setattr(tproxy, "dial_strategy", timed_out_local)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == b""
    assert writer.closed is True
    assert host not in tproxy._auto_geph
    evidence = tproxy._local_zero_payload_failures.get(host) or {}
    assert set(evidence) == {
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
    }


def test_unknown_first_server_payload_forbids_route_replay(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "healthy-system-route.example"
    response = b"\x16\x03\x03\x00\x60" + (b"S" * 96)
    client, _expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()

    async def healthy_system(_ip, _port, _first_flight):
        return (
            tproxy.SYSTEM_PROBE_PAYLOAD,
            probed_upstream_response(response),
        )

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.62", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", healthy_system)
    monkeypatch.setattr(
        tproxy,
        "_try_xbox_dns_local_connect",
        lambda *args, **kwargs: no_backend("Xbox DNS", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_strategy",
        lambda *args, **kwargs: no_backend("local strategy", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_via_geph",
        lambda *args, **kwargs: no_backend("Geph", *args, **kwargs),
    )

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_unknown_server_first_close_feeds_exact_route_evidence(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "short-server-close.example"
    response = b"\x17\x03\x03\x00\x60" + (b"S" * 96)
    client, _expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    observations = []

    async def short_system(_ip, _port, _first_flight):
        return (
            tproxy.SYSTEM_PROBE_PAYLOAD,
            probed_upstream_response(response),
        )

    def record_close(actual_host, stage, activity, **kwargs):
        observations.append((
            actual_host,
            stage,
            activity.server_ended_first,
            activity.downstream_bytes,
            kwargs["duration"],
        ))
        return False

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.64", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", short_system)
    monkeypatch.setattr(tproxy, "note_server_first_route_close", record_close)
    monkeypatch.setattr(
        tproxy,
        "_try_xbox_dns_local_connect",
        lambda *args, **kwargs: no_backend("Xbox DNS", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_strategy",
        lambda *args, **kwargs: no_backend("local strategy", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_via_geph",
        lambda *args, **kwargs: no_backend("Geph", *args, **kwargs),
    )

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert len(observations) == 1
    actual_host, stage, server_ended_first, downstream_bytes, duration = (
        observations[0]
    )
    assert actual_host == host
    assert stage == tproxy.AUTO_GEPH_STAGE_SYSTEM
    assert server_ended_first
    assert downstream_bytes == len(response)
    assert duration >= 0


def test_unknown_slow_system_route_is_committed_without_replay(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "slow-system-route.example"
    response = b"\x16\x03\x03\x00\x60" + (b"S" * 96)
    client, _expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()

    async def pending_system(_ip, _port, _first_flight):
        return (
            tproxy.SYSTEM_PROBE_PENDING,
            (ScriptedReader(stream=(response,)), CaptureWriter(), b""),
        )

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.63", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", pending_system)
    monkeypatch.setattr(
        tproxy,
        "_try_xbox_dns_local_connect",
        lambda *args, **kwargs: no_backend("Xbox DNS", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_strategy",
        lambda *args, **kwargs: no_backend("local strategy", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_via_geph",
        lambda *args, **kwargs: no_backend("Geph", *args, **kwargs),
    )

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_unknown_recovery_never_uses_an_external_geph_listener(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "external-geph-is-not-owned.example"
    dialled = []
    tproxy._auto_geph_candidates[host] = time.monotonic() + 60.0

    async def external_geph(*args, **kwargs):
        dialled.append((args, kwargs))
        return streaming_upstream_response(b"G" * 128)

    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", False)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_EXTERNAL_PORT)
    monkeypatch.setattr(tproxy, "dial_via_geph", external_geph)
    monkeypatch.setattr(
        tproxy.asyncio,
        "sleep",
        lambda _delay: pytest.fail("external Geph must not enter recovery wait"),
    )

    handled = asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            b"client hello",
            ScriptedReader(),
            CaptureWriter(),
        )
    )

    assert handled is False
    assert dialled == []
    assert tproxy.geph_active_session_count() == 0


def test_unknown_zero_byte_server_close_arms_next_retry_recovery(monkeypatch):
    """A successful TCP handshake is not a healthy transparent route."""
    note_local_stream_stall = tproxy.note_local_stream_stall
    isolate_runtime_state(monkeypatch)
    host = "early-close.example"

    async def exact_direct(_ip, _port, _first_flight):
        return object(), object()

    async def zero_byte_close(
        _reader,
        _up_w,
        _up_r,
        _writer,
        activity,
        **_kwargs,
    ):
        activity.server_ended_first = True
        activity.server_end_at = activity.last_downstream_at
        return 0, 0

    monkeypatch.setattr(tproxy, "dial_plain", exact_direct)
    monkeypatch.setattr(tproxy, "relay_local_stream", zero_byte_close)
    monkeypatch.setattr(tproxy, "note_local_stream_stall", note_local_stream_stall)

    assert asyncio.run(
        tproxy._try_exact_system_passthrough(
            host,
            "203.0.113.32",
            443,
            b"client hello",
            object(),
            object(),
            track_unknown=True,
        )
    )
    assert tproxy._xbox_dns_candidate_active(host)


def test_healthy_low_volume_exact_stream_does_not_feed_recovery(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "quiet-websocket.example"

    async def exact_direct(_ip, _port, _first_flight):
        return object(), object()

    async def healthy_quiet_stream(
        _reader,
        _up_w,
        _up_r,
        _writer,
        activity,
        **_kwargs,
    ):
        activity.first_downstream_seen = True
        activity.last_downstream_at += 20.0
        activity.server_ended_first = True
        return 0, 1

    def unexpected_recovery_sample(*_args, **_kwargs):
        raise AssertionError("healthy exact streams must not feed recovery")

    monkeypatch.setattr(tproxy, "dial_plain", exact_direct)
    monkeypatch.setattr(tproxy, "relay_local_stream", healthy_quiet_stream)
    monkeypatch.setattr(tproxy, "note_local_result", unexpected_recovery_sample)

    for _ in range(3):
        assert asyncio.run(
            tproxy._try_exact_system_passthrough(
                host,
                "203.0.113.33",
                443,
                b"client hello",
                object(),
                object(),
                track_unknown=True,
            )
        )
    assert not tproxy._xbox_dns_candidate_active(host)


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


def test_youtube_media_direct_first_stops_after_plain_payload(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "rr5---sn-test.googlevideo.com"
    destination_ip = "203.0.113.40"
    response = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\n\r\nmedia"
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    calls = []

    async def one_address(actual_host, fallback_ip):
        assert (actual_host, fallback_ip) == (host, destination_ip)
        return [destination_ip]

    async def local_route(ip, port, head, body, actual_host, strategy):
        assert (ip, port, head + body, actual_host) == (
            destination_ip,
            443,
            expected_first_flight,
            host,
        )
        calls.append(strategy["name"])
        if strategy["name"] != "plain":
            pytest.fail("healthy direct media must not enter desync fallback")
        return probed_upstream_response(response)

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    tproxy._strat_cache[host] = "split64+fake"
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: (destination_ip, 443))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", one_address)
    monkeypatch.setattr(tproxy, "dial_strategy", local_route)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)

    asyncio.run(run_handler(client, writer))

    assert calls == ["plain"]
    assert bytes(writer.payload) == response
    assert tproxy.route_policy(host) == {
        "host": host,
        "route_class": tproxy.ROUTE_DIRECT_FIRST,
        "service_group": tproxy.SERVICE_YOUTUBE,
        "strategy_set": tproxy.STRATEGY_DIRECT_FIRST,
    }


def test_youtube_media_direct_stall_falls_back_locally_without_geph(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "rr5---sn-test.googlevideo.com"
    destination_ip = "203.0.113.41"
    response = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\n\r\nmedia"
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    calls = []

    async def one_address(actual_host, fallback_ip):
        assert (actual_host, fallback_ip) == (host, destination_ip)
        return [destination_ip]

    async def local_route(ip, port, head, body, actual_host, strategy):
        assert (ip, port, head + body, actual_host) == (
            destination_ip,
            443,
            expected_first_flight,
            host,
        )
        calls.append(strategy["name"])
        if strategy["name"] == "plain":
            return None
        return probed_upstream_response(response)

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    tproxy._strat_cache[host] = "split64+fake"
    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: (destination_ip, 443))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", one_address)
    monkeypatch.setattr(tproxy, "dial_strategy", local_route)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)

    asyncio.run(run_handler(client, writer))

    assert calls == ["plain", "split64+fake"]
    assert bytes(writer.payload) == response
    assert not tproxy.is_geo_exit_route(host)


def test_youtube_media_dead_cooldown_preserves_one_local_fallback(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "rr5---sn-test.googlevideo.com"
    destination_ips = ["203.0.113.42", "203.0.113.43"]
    response = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\n\r\nmedia"
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    calls = []

    async def two_addresses(actual_host, fallback_ip):
        assert (actual_host, fallback_ip) == (host, destination_ips[0])
        return list(destination_ips)

    async def local_route(ip, port, head, body, actual_host, strategy):
        assert (port, head + body, actual_host) == (
            443,
            expected_first_flight,
            host,
        )
        calls.append((ip, strategy["name"]))
        if strategy["name"] == "plain":
            return None
        return probed_upstream_response(response)

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    tproxy._dead[host] = tproxy.time.monotonic() + 60
    tproxy._strat_cache[host] = "split64+fake"
    monkeypatch.setattr(
        tproxy,
        "orig_dst",
        lambda _sock: (destination_ips[0], 443),
    )
    monkeypatch.setattr(tproxy, "resolve_connection_ips", two_addresses)
    monkeypatch.setattr(tproxy, "dial_strategy", local_route)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)

    asyncio.run(run_handler(client, writer))

    assert calls == [
        (destination_ips[0], "plain"),
        (destination_ips[0], "split64+fake"),
    ]
    assert bytes(writer.payload) == response
    assert host not in tproxy._dead


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
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
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


def test_proven_exact_unknown_host_uses_owned_geph_without_local_replay(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "partial-stall.example"
    client, expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"
    calls = []

    async def fake_geph(actual_host, port, first_flight):
        assert (actual_host, port, first_flight) == (
            host,
            443,
            expected_first_flight,
        )
        calls.append(("geph", actual_host))
        return streaming_upstream_response(response)

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.19", 443))
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    tproxy._auto_geph[host] = tproxy.time.time() + 3600
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "dial_via_geph", fake_geph)
    monkeypatch.setattr(
        tproxy,
        "dial_strategy",
        lambda *args, **kwargs: no_backend("local desync", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_plain",
        lambda *args, **kwargs: no_backend("direct dial", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "resolve_connection_ips",
        lambda *args, **kwargs: no_backend("generic DNS", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "clear_geph_route_failure",
        lambda: calls.append(("clear_geph",)),
    )

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert calls == [("geph", host), ("clear_geph",)]


@pytest.mark.parametrize(
    ("geph_owned", "geph_port"),
    (
        (True, tproxy.GEPH_OWNED_PORT),
        (False, tproxy.GEPH_EXTERNAL_PORT),
    ),
)
def test_learned_unknown_host_without_ready_owned_geph_uses_exact_system_route(
    monkeypatch,
    geph_owned,
    geph_port,
):
    isolate_runtime_state(monkeypatch)
    host = "partial-stall.example"
    client, _expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"
    destination = ("203.0.113.19", 443)
    calls = []

    async def fake_direct(ip, port, first_flight):
        assert (ip, port) == destination
        calls.append(("system", ip, port, first_flight))
        return streaming_upstream_response(response)

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: destination)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", geph_owned)
    monkeypatch.setattr(tproxy, "_geph_port", geph_port)
    tproxy._auto_geph[host] = tproxy.time.time() + 3600
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(
        tproxy,
        "dial_via_geph",
        lambda *args, **kwargs: no_backend("Geph", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_strategy",
        lambda *args, **kwargs: no_backend("local desync", *args, **kwargs),
    )
    monkeypatch.setattr(tproxy, "dial_plain", fake_direct)
    monkeypatch.setattr(
        tproxy,
        "resolve_connection_ips",
        lambda *args, **kwargs: no_backend("generic DNS", *args, **kwargs),
    )

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert len(calls) == 1
    assert calls[0][:3] == ("system", *destination)


def test_geo_exit_early_close_cools_only_geph_without_replaying_the_stream(monkeypatch):
    """A consumed zero-byte stream cannot be replayed, but local PF stays active."""
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
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "dial_via_geph", empty_geph)
    monkeypatch.setattr(tproxy, "dial_strategy", lambda *args, **kwargs: no_backend("local desync", *args, **kwargs))
    monkeypatch.setattr(tproxy, "dial_plain", lambda *args, **kwargs: no_backend("direct dial", *args, **kwargs))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", lambda *args, **kwargs: no_backend("generic DNS", *args, **kwargs))
    monkeypatch.setattr(tproxy, "log_geph_route_failure", lambda actual_host, reason: failures.append((actual_host, reason)))
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: pytest.fail("empty payload must not clear failure"))
    monkeypatch.setattr(tproxy, "suspend_geo_exit_backend", suspensions.append)

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == b""
    assert failures == [(host, "remote closed without response")]
    assert suspensions == ["geo-exit remote close before payload"]


@pytest.mark.parametrize(
    "smart_dns_ready",
    [False, True],
    ids=["no-smart-dns", "smart-dns-miss"],
)
@pytest.mark.parametrize(
    "geph_enabled",
    [False, True],
    ids=["geph-disabled", "geph-enabled-but-absent"],
)
def test_geo_exit_without_app_backend_uses_original_system_destination(
    monkeypatch,
    smart_dns_ready,
    geph_enabled,
):
    """Custom DNS, an external VPN, or an ordinary route remain OS-owned."""
    isolate_runtime_state(monkeypatch)
    host = "ws.chatgpt.com"
    assert tproxy.route_policy(host)["route_class"] == tproxy.ROUTE_GEO_EXIT
    client, expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    suspensions = []
    smart_dns_misses = []
    direct_calls = []
    response = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    async def smart_dns_miss(actual_host, port, first_flight):
        assert (actual_host, port, first_flight) == (host, 443, expected_first_flight)
        smart_dns_misses.append(actual_host)
        return None

    async def system_route(ip, port, first_flight):
        assert (ip, port, first_flight) == (
            "203.0.113.15",
            443,
            expected_first_flight,
        )
        direct_calls.append(ip)
        return streaming_upstream_response(response)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.15", 443))
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", geph_enabled)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_owned", False)
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: smart_dns_ready)
    monkeypatch.setattr(tproxy, "_try_smart_dns_geo_connect", smart_dns_miss)
    monkeypatch.setattr(tproxy, "_smart_dns_mark_failure", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "dial_via_geph", lambda *args, **kwargs: no_backend("Geph", *args, **kwargs))
    monkeypatch.setattr(tproxy, "dial_strategy", lambda *args, **kwargs: no_backend("local desync", *args, **kwargs))
    monkeypatch.setattr(tproxy, "dial_plain", system_route)
    monkeypatch.setattr(
        tproxy,
        "dial_and_probe",
        lambda *args, **kwargs: no_backend("first-payload probe", *args, **kwargs),
    )
    monkeypatch.setattr(tproxy, "resolve_connection_ips", lambda *args, **kwargs: no_backend("DNS", *args, **kwargs))
    monkeypatch.setattr(tproxy, "log_geph_route_failure", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "suspend_geo_exit_backend", suspensions.append)

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert suspensions == []
    assert smart_dns_misses == ([host] if smart_dns_ready else [])
    assert direct_calls == ["203.0.113.15"]


def test_geo_exit_backend_hold_uses_system_route_without_geph_redial(monkeypatch):
    """A live SOCKS probe cannot bypass the owned backend failure hold."""
    isolate_runtime_state(monkeypatch)
    host = "ws.chatgpt.com"
    client, expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    direct_calls = []
    response = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
    hold_until = 130.0

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    async def system_route(ip, port, first_flight):
        assert (ip, port, first_flight) == (
            "203.0.113.19",
            443,
            expected_first_flight,
        )
        direct_calls.append(ip)
        return streaming_upstream_response(response)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.19", 443))
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", hold_until)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_reason", "early close")
    monkeypatch.setattr(tproxy.time, "time", lambda: 100.0)
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(
        tproxy,
        "dial_via_geph",
        lambda *args, **kwargs: no_backend("Geph", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "suspend_geo_exit_backend",
        lambda *_args, **_kwargs: pytest.fail("active hold must not be extended"),
    )
    monkeypatch.setattr(
        tproxy,
        "dial_strategy",
        lambda *args, **kwargs: no_backend("local desync", *args, **kwargs),
    )
    monkeypatch.setattr(tproxy, "dial_plain", system_route)
    monkeypatch.setattr(
        tproxy,
        "dial_and_probe",
        lambda *args, **kwargs: no_backend("first-payload probe", *args, **kwargs),
    )
    monkeypatch.setattr(
        tproxy,
        "resolve_connection_ips",
        lambda *args, **kwargs: no_backend("DNS", *args, **kwargs),
    )

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert direct_calls == ["203.0.113.19"]
    assert tproxy.geph_active_session_count() == 0
    assert tproxy._geph_backend_hold_until == hold_until
    assert tproxy._geph_backend_hold_reason == "early close"


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
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
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
    monkeypatch.setattr(tproxy, "suspend_geo_exit_backend", suspensions.append)
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
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
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
        "suspend_geo_exit_backend",
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


def test_incomplete_unknown_local_evidence_does_not_promote_to_geph(monkeypatch):
    """One local strategy is insufficient evidence for a foreign exit."""
    isolate_runtime_state(monkeypatch)
    host = "unclassified.example"
    calls = []

    async def fake_dns(actual_host, _fallback_ip):
        calls.append(("dns", actual_host))
        return ["198.51.100.42"]

    async def failed_direct(_ip, _port, _first_flight):
        calls.append(("direct", host))
        return tproxy.SYSTEM_PROBE_CLOSED, None

    async def failed_strategy(_ip, _port, _head, _body, actual_host, _strategy):
        calls.append(("local", actual_host))
        return None

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.42", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", failed_direct)
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

    assert [call[0] for call in calls].count("direct") == 1
    assert [call[0] for call in calls].count("dns") == 2
    assert [call[0] for call in calls].count("local") == 2
    assert host not in tproxy._auto_geph
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

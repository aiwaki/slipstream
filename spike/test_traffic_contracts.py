"""Deterministic data-plane contracts for the transparent routing handler.

These fixtures exercise the real ``_handle_impl`` decision and relay path. Only
the OS-facing pieces (PF destination lookup, DNS, and upstream diallers) are
replaced, so no test can reach the network or mutate local routing state.
"""

from __future__ import annotations

import asyncio
import struct
import threading
import time
from collections import OrderedDict, deque
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


class MutableTproxyClock:
    """Control only tproxy's monotonic clock, not asyncio's event-loop clock."""

    def __init__(self, monotonic):
        self.value = monotonic

    def monotonic(self):
        return self.value

    def __getattr__(self, name):
        return getattr(time, name)


class TproxyAsyncioFacade:
    """Override one asyncio primitive without mutating the process module."""

    def __init__(self, wait):
        self.wait = wait

    def __getattr__(self, name):
        return getattr(asyncio, name)


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
    monkeypatch.setattr(tproxy, "_transport_incomplete_client_first_evidence", {})
    monkeypatch.setattr(tproxy, "_semantic_plain_confirming", {})
    monkeypatch.setattr(tproxy, "_semantic_plain_last_probe", {})
    monkeypatch.setattr(tproxy, "_semantic_plain_probe_window", deque())
    monkeypatch.setattr(tproxy, "_protected_local_server_first_closes", {})
    monkeypatch.setattr(tproxy, "_direct_first_local_fallback_until", {})
    monkeypatch.setattr(tproxy, "_auto_geph", {})
    monkeypatch.setattr(tproxy, "_auto_geph_confirming", {})
    monkeypatch.setattr(tproxy, "_auto_geph_confirmation_tokens", {})
    monkeypatch.setattr(tproxy, "_auto_geph_last_probe", {})
    monkeypatch.setattr(tproxy, "_auto_geph_retry_after_drain", {})
    monkeypatch.setattr(tproxy, "_auto_geph_candidates", {})
    monkeypatch.setattr(tproxy, "_local_partial_stalls", {})
    monkeypatch.setattr(tproxy, "_local_zero_payload_failures", {})
    monkeypatch.setattr(tproxy, "_auto_geph_one_shot_consumed_at", {})
    monkeypatch.setattr(tproxy, "_auto_geph_successor_requests", {})
    monkeypatch.setattr(tproxy, "_auto_geph_noise_invalidated", set())
    monkeypatch.setattr(tproxy, "_route_preflight_cache", OrderedDict())
    monkeypatch.setattr(tproxy, "_route_preflight_window", deque())
    monkeypatch.setattr(tproxy, "_route_preflight_consumed", OrderedDict())
    monkeypatch.setattr(
        tproxy,
        "_transport_incomplete_server_first_evidence",
        {},
    )
    monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
    monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", False)
    monkeypatch.setattr(tproxy, "_geph_port", None)
    monkeypatch.setattr(tproxy, "_geph_port_conflict", False)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_until", 0.0)
    monkeypatch.setattr(tproxy, "_geph_backend_hold_reason", "")
    monkeypatch.setattr(
        tproxy,
        "_auto_geph_last_status",
        dict(tproxy._auto_geph_last_status),
    )
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
    monkeypatch.setattr(
        tproxy,
        "note_protected_local_server_first_close",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(tproxy, "note_local_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "_clear_clean_eof_stalls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tproxy, "route_health_event", lambda *_args, **_kwargs: None)


def request_only_geph_claim(
    host,
    *,
    capability,
    exact_address="8.8.8.8",
    eligible_after_monotonic,
    deadline_monotonic,
):
    return tproxy._RoutePreflightRequestOnlyGephClaim(
        marker=tproxy._ROUTE_PREFLIGHT_REQUEST_ONLY_GEPH,
        capability=capability,
        host=host,
        exact_address=exact_address,
        port=443,
        confirmed_geph_pid=41,
        eligible_after_monotonic=eligible_after_monotonic,
        deadline_monotonic=deadline_monotonic,
    )


def enable_request_only_owned_geph(monkeypatch):
    monkeypatch.setattr(tproxy, "AUTO_GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        lambda pid: pid == 41,
    )


def request_only_non_learning_snapshot():
    return {
        "route_cache": tuple(tproxy._route_preflight_cache.items()),
        "learned": dict(tproxy._auto_geph),
        "candidates": dict(tproxy._auto_geph_candidates),
        "successors": dict(tproxy._auto_geph_successor_requests),
        "status": dict(tproxy._auto_geph_last_status),
    }


def seed_complete_unknown_zero_payload_proof(host, now):
    tproxy._local_zero_payload_failures[host] = {
        tproxy.AUTO_GEPH_STAGE_SYSTEM: now,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS: now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake": now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake": now,
    }


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

        async def fake_system_probe(ip, port, first_flight, **_kwargs):
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
        if contract.name == "discord-updater-local":
            assert backend_calls[0][5] is False
        elif contract.route_class == tproxy.ROUTE_LOCAL_BYPASS:
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

    async def failed_direct(ip, port, first_flight, **_kwargs):
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


def test_exact_system_probe_timeout_is_replay_safe(monkeypatch):
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

    assert state == tproxy.SYSTEM_PROBE_TIMEOUT
    assert result is None
    assert upstream_writer.closed is True


def test_exact_system_probe_can_preserve_a_slow_established_stream(monkeypatch):
    upstream_reader = ScriptedReader(block_when_empty=True)
    upstream_writer = CaptureWriter()

    async def exact_direct(_ip, _port, _first_flight, **_kwargs):
        return upstream_reader, upstream_writer

    monkeypatch.setattr(tproxy, "dial_plain", exact_direct)

    state, exact = asyncio.run(
        tproxy._try_exact_system_probe(
            "203.0.113.32",
            443,
            b"client hello",
            deadline_monotonic=time.monotonic() + 0.01,
            preserve_timeout_stream=True,
        )
    )

    assert state == tproxy.SYSTEM_PROBE_TIMEOUT
    assert exact == (upstream_reader, upstream_writer, b"")
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


def test_unknown_initial_route_probes_start_concurrently():
    exact_started = asyncio.Event()
    preflight_started = asyncio.Event()
    exact_writer = CaptureWriter()
    exact_payload = b"slow direct payload"

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        exact_started.set()
        await preflight_started.wait()
        return (
            tproxy.SYSTEM_PROBE_PAYLOAD,
            (ScriptedReader(), exact_writer, exact_payload),
        )

    async def route_preflight(_host, _ip, **_kwargs):
        preflight_started.set()
        await exact_started.wait()
        return None

    async def scenario():
        now = time.monotonic()
        return await asyncio.wait_for(
            tproxy._run_unknown_initial_route_race(
                "slow-direct.example",
                "203.0.113.40",
                443,
                b"client hello",
                hard_recovery_deadline_monotonic=now + 1.0,
                semantic_handoff_deadline_monotonic=now + 2.0,
                exact_probe=exact_probe,
                route_preflight=route_preflight,
            ),
            timeout=0.5,
        )

    state, exact, claim = asyncio.run(scenario())

    assert state == tproxy.SYSTEM_PROBE_PAYLOAD
    assert exact[2] == exact_payload
    assert claim is None
    assert not exact_writer.closed


def test_unknown_initial_semantic_claim_discards_held_direct_stream():
    exact_returned = asyncio.Event()
    exact_writer = CaptureWriter()
    claim = object()

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        exact_returned.set()
        return (
            tproxy.SYSTEM_PROBE_PAYLOAD,
            (ScriptedReader(), exact_writer, b"blocked direct payload"),
        )

    async def route_preflight(_host, _ip, **_kwargs):
        await exact_returned.wait()
        return claim

    async def scenario():
        now = time.monotonic()
        return await tproxy._run_unknown_initial_route_race(
            "strict-denial.example",
            "203.0.113.41",
            443,
            b"client hello",
            hard_recovery_deadline_monotonic=now + 1.0,
            semantic_handoff_deadline_monotonic=now + 2.0,
            exact_probe=exact_probe,
            route_preflight=route_preflight,
        )

    state, exact, selected = asyncio.run(scenario())

    assert state == tproxy.SYSTEM_PROBE_PAYLOAD
    assert exact is None
    assert selected is claim
    assert exact_writer.closed


def test_unknown_initial_timeout_stays_unclear_without_route_claim():
    preflight_finished = asyncio.Event()

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        await preflight_finished.wait()
        return tproxy.SYSTEM_PROBE_TIMEOUT, None

    async def route_preflight(_host, _ip, **_kwargs):
        preflight_finished.set()
        return None

    async def scenario():
        now = time.monotonic()
        return await tproxy._run_unknown_initial_route_race(
            "timeout-is-unclear.example",
            "203.0.113.42",
            443,
            b"client hello",
            hard_recovery_deadline_monotonic=now + 1.0,
            semantic_handoff_deadline_monotonic=now + 2.0,
            exact_probe=exact_probe,
            route_preflight=route_preflight,
        )

    state, exact, claim = asyncio.run(scenario())

    assert state == tproxy.SYSTEM_PROBE_TIMEOUT
    assert exact is None
    assert claim is None


def test_unknown_initial_exact_payload_beats_provisional_tls_stall_claim(
    monkeypatch,
):
    preflight_started = asyncio.Event()
    exact_writer = CaptureWriter()
    clock = MutableTproxyClock(100.0)
    monkeypatch.setattr(tproxy, "time", clock)
    hard_deadline = 101.0
    semantic_deadline = 102.0
    claim = request_only_geph_claim(
        "request-only-payload.example",
        capability="a" * 32,
        exact_address="8.8.8.8",
        eligible_after_monotonic=hard_deadline,
        deadline_monotonic=semantic_deadline,
    )

    async def exact_probe(_ip, _port, _first_flight, **kwargs):
        assert kwargs["deadline_monotonic"] == hard_deadline
        await preflight_started.wait()
        return (
            tproxy.SYSTEM_PROBE_PAYLOAD,
            (ScriptedReader(), exact_writer, b"direct server bytes"),
        )

    async def route_preflight(_host, _ip, **_kwargs):
        preflight_started.set()
        return claim

    async def scenario():
        return await tproxy._run_unknown_initial_route_race(
            claim.host,
            claim.exact_address,
            443,
            b"client hello",
            hard_recovery_deadline_monotonic=hard_deadline,
            semantic_handoff_deadline_monotonic=semantic_deadline,
            exact_probe=exact_probe,
            route_preflight=route_preflight,
        )

    state, exact, selected = asyncio.run(scenario())

    assert state == tproxy.SYSTEM_PROBE_PAYLOAD
    assert exact[2] == b"direct server bytes"
    assert selected is None
    assert not exact_writer.closed


def test_unknown_initial_exact_timeout_selects_completed_tls_stall_claim(
    monkeypatch,
):
    preflight_started = asyncio.Event()
    exact_writer = CaptureWriter()
    exact_result = (ScriptedReader(block_when_empty=True), exact_writer, b"")
    clock = MutableTproxyClock(200.0)
    monkeypatch.setattr(tproxy, "time", clock)
    hard_deadline = 201.0
    semantic_deadline = 202.0
    claim = request_only_geph_claim(
        "request-only-timeout.example",
        capability="b" * 32,
        exact_address="8.8.8.8",
        eligible_after_monotonic=hard_deadline,
        deadline_monotonic=semantic_deadline,
    )

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        await preflight_started.wait()
        clock.value = hard_deadline
        return tproxy.SYSTEM_PROBE_TIMEOUT, exact_result

    async def route_preflight(_host, _ip, **_kwargs):
        preflight_started.set()
        return claim

    async def scenario():
        return await tproxy._run_unknown_initial_route_race(
            claim.host,
            claim.exact_address,
            443,
            b"client hello",
            hard_recovery_deadline_monotonic=hard_deadline,
            semantic_handoff_deadline_monotonic=semantic_deadline,
            exact_probe=exact_probe,
            route_preflight=route_preflight,
        )

    state, exact, selected = asyncio.run(scenario())

    assert state == tproxy.SYSTEM_PROBE_TIMEOUT
    assert exact is exact_result
    assert selected is claim
    assert not exact_writer.closed


@pytest.mark.parametrize(
    ("mismatch", "race_port"),
    (
        ("host", 443),
        ("ip", 443),
        ("port", 8443),
        ("eligibility", 443),
        ("deadline", 443),
    ),
)
def test_unknown_initial_mismatched_tls_stall_claim_preserves_exact(
    monkeypatch,
    mismatch,
    race_port,
):
    clock = MutableTproxyClock(300.0)
    monkeypatch.setattr(tproxy, "time", clock)
    host = "request-only-bound.example"
    exact_address = "8.8.8.8"
    hard_deadline = 301.0
    semantic_deadline = 302.0
    claim = request_only_geph_claim(
        "different-host.example" if mismatch == "host" else host,
        capability="c" * 32,
        exact_address=("1.1.1.1" if mismatch == "ip" else exact_address),
        eligible_after_monotonic=(
            hard_deadline + 0.25
            if mismatch == "eligibility"
            else hard_deadline
        ),
        deadline_monotonic=(
            semantic_deadline - 0.25
            if mismatch == "deadline"
            else semantic_deadline
        ),
    )
    exact_writer = CaptureWriter()
    exact_result = (ScriptedReader(block_when_empty=True), exact_writer, b"")

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        clock.value = hard_deadline
        return tproxy.SYSTEM_PROBE_TIMEOUT, exact_result

    async def route_preflight(_host, _ip, **_kwargs):
        return claim

    async def scenario():
        return await tproxy._run_unknown_initial_route_race(
            host,
            exact_address,
            race_port,
            b"client hello",
            hard_recovery_deadline_monotonic=hard_deadline,
            semantic_handoff_deadline_monotonic=semantic_deadline,
            exact_probe=exact_probe,
            route_preflight=route_preflight,
        )

    state, exact, selected = asyncio.run(scenario())

    assert state == tproxy.SYSTEM_PROBE_TIMEOUT
    assert exact is exact_result
    assert selected is None
    assert not exact_writer.closed


def test_unknown_initial_exact_timeout_awaits_unfinished_nonprovisional_preflight():
    preflight_started = asyncio.Event()
    preflight_release = asyncio.Event()
    preflight_finished = False
    preflight_cancelled = False
    exact_writer = CaptureWriter()
    exact_result = (ScriptedReader(), exact_writer, b"")

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        await preflight_started.wait()
        asyncio.get_running_loop().call_later(0.01, preflight_release.set)
        return tproxy.SYSTEM_PROBE_TIMEOUT, exact_result

    async def route_preflight(_host, _ip, **_kwargs):
        nonlocal preflight_cancelled, preflight_finished
        preflight_started.set()
        try:
            await preflight_release.wait()
        except asyncio.CancelledError:
            preflight_cancelled = True
            raise
        preflight_finished = True
        return None

    async def scenario():
        now = time.monotonic()
        return await tproxy._run_unknown_initial_route_race(
            "unfinished-preflight.example",
            "8.8.8.8",
            443,
            b"client hello",
            hard_recovery_deadline_monotonic=now + 1.0,
            semantic_handoff_deadline_monotonic=now + 2.0,
            exact_probe=exact_probe,
            route_preflight=route_preflight,
        )

    state, exact, selected = asyncio.run(scenario())

    assert state == tproxy.SYSTEM_PROBE_TIMEOUT
    assert exact is exact_result
    assert selected is None
    assert preflight_finished
    assert not preflight_cancelled
    assert not exact_writer.closed


def test_unknown_initial_exact_timeout_selects_late_ordinary_semantic_claim():
    preflight_started = asyncio.Event()
    preflight_release = asyncio.Event()
    preflight_finished = False
    preflight_cancelled = False
    exact_writer = CaptureWriter()
    exact_result = (ScriptedReader(), exact_writer, b"")
    ordinary_claim = object()

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        await preflight_started.wait()
        asyncio.get_running_loop().call_later(0.01, preflight_release.set)
        return tproxy.SYSTEM_PROBE_TIMEOUT, exact_result

    async def route_preflight(_host, _ip, **_kwargs):
        nonlocal preflight_cancelled, preflight_finished
        preflight_started.set()
        try:
            await preflight_release.wait()
        except asyncio.CancelledError:
            preflight_cancelled = True
            raise
        preflight_finished = True
        return ordinary_claim

    async def scenario():
        now = time.monotonic()
        return await tproxy._run_unknown_initial_route_race(
            "late-ordinary-claim.example",
            "8.8.8.8",
            443,
            b"client hello",
            hard_recovery_deadline_monotonic=now + 1.0,
            semantic_handoff_deadline_monotonic=now + 2.0,
            exact_probe=exact_probe,
            route_preflight=route_preflight,
        )

    state, exact, selected = asyncio.run(scenario())

    assert state == tproxy.SYSTEM_PROBE_TIMEOUT
    assert exact is None
    assert selected is ordinary_claim
    assert preflight_finished
    assert not preflight_cancelled
    assert exact_writer.closed


def test_unknown_initial_exact_timeout_rejects_late_tls_stall_claim(
    monkeypatch,
):
    preflight_started = asyncio.Event()
    preflight_release = asyncio.Event()
    preflight_finished = False
    preflight_cancelled = False
    exact_writer = CaptureWriter()
    exact_result = (ScriptedReader(), exact_writer, b"")
    clock = MutableTproxyClock(400.0)
    monkeypatch.setattr(tproxy, "time", clock)
    hard_deadline = 401.0
    semantic_deadline = 402.0
    late_claim = request_only_geph_claim(
        "late-request-only.example",
        capability="d" * 32,
        eligible_after_monotonic=hard_deadline,
        deadline_monotonic=semantic_deadline,
    )

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        await preflight_started.wait()
        clock.value = hard_deadline
        asyncio.get_running_loop().call_later(0.01, preflight_release.set)
        return tproxy.SYSTEM_PROBE_TIMEOUT, exact_result

    async def route_preflight(_host, _ip, **_kwargs):
        nonlocal preflight_cancelled, preflight_finished
        preflight_started.set()
        try:
            await preflight_release.wait()
        except asyncio.CancelledError:
            preflight_cancelled = True
            raise
        preflight_finished = True
        return late_claim

    async def scenario():
        return await tproxy._run_unknown_initial_route_race(
            late_claim.host,
            late_claim.exact_address,
            443,
            b"client hello",
            hard_recovery_deadline_monotonic=hard_deadline,
            semantic_handoff_deadline_monotonic=semantic_deadline,
            exact_probe=exact_probe,
            route_preflight=route_preflight,
        )

    state, exact, selected = asyncio.run(scenario())

    assert state == tproxy.SYSTEM_PROBE_TIMEOUT
    assert exact is exact_result
    assert selected is None
    assert preflight_finished
    assert not preflight_cancelled
    assert not exact_writer.closed


def test_unknown_initial_unclear_awaits_unfinished_ordinary_semantic_claim():
    preflight_started = asyncio.Event()
    preflight_release = asyncio.Event()
    preflight_finished = False
    preflight_cancelled = False
    ordinary_claim = object()

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        await preflight_started.wait()
        asyncio.get_running_loop().call_later(0.01, preflight_release.set)
        return tproxy.SYSTEM_PROBE_UNCLEAR, None

    async def route_preflight(_host, _ip, **_kwargs):
        nonlocal preflight_cancelled, preflight_finished
        preflight_started.set()
        try:
            await preflight_release.wait()
        except asyncio.CancelledError:
            preflight_cancelled = True
            raise
        preflight_finished = True
        return ordinary_claim

    async def scenario():
        now = time.monotonic()
        return await tproxy._run_unknown_initial_route_race(
            "unclear-with-ordinary-claim.example",
            "8.8.8.8",
            443,
            b"client hello",
            hard_recovery_deadline_monotonic=now + 1.0,
            semantic_handoff_deadline_monotonic=now + 2.0,
            exact_probe=exact_probe,
            route_preflight=route_preflight,
        )

    state, exact, selected = asyncio.run(scenario())

    assert state == tproxy.SYSTEM_PROBE_UNCLEAR
    assert exact is None
    assert selected is ordinary_claim
    assert preflight_finished
    assert not preflight_cancelled


def test_unknown_initial_preflight_exception_closes_completed_exact_stream():
    exact_returned = asyncio.Event()
    exact_writer = CaptureWriter()

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        exact_returned.set()
        return (
            tproxy.SYSTEM_PROBE_PAYLOAD,
            (ScriptedReader(), exact_writer, b"held payload"),
        )

    async def route_preflight(_host, _ip, **_kwargs):
        await exact_returned.wait()
        raise RuntimeError("preflight failed")

    async def scenario():
        now = time.monotonic()
        with pytest.raises(RuntimeError, match="preflight failed"):
            await tproxy._run_unknown_initial_route_race(
                "preflight-exception.example",
                "203.0.113.43",
                443,
                b"client hello",
                hard_recovery_deadline_monotonic=now + 1.0,
                semantic_handoff_deadline_monotonic=now + 2.0,
                exact_probe=exact_probe,
                route_preflight=route_preflight,
            )

    asyncio.run(scenario())

    assert exact_writer.closed


def test_unknown_initial_exact_exception_cancels_semantic_sibling():
    preflight_started = asyncio.Event()
    preflight_cancelled = False

    async def exact_probe(_ip, _port, _first_flight, **_kwargs):
        await preflight_started.wait()
        raise RuntimeError("exact failed")

    async def route_preflight(_host, _ip, **_kwargs):
        nonlocal preflight_cancelled
        preflight_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            preflight_cancelled = True
            raise

    async def scenario():
        now = time.monotonic()
        with pytest.raises(RuntimeError, match="exact failed"):
            await tproxy._run_unknown_initial_route_race(
                "exact-exception.example",
                "203.0.113.44",
                443,
                b"client hello",
                hard_recovery_deadline_monotonic=now + 1.0,
                semantic_handoff_deadline_monotonic=now + 2.0,
                exact_probe=exact_probe,
                route_preflight=route_preflight,
            )

    asyncio.run(scenario())

    assert preflight_cancelled


def test_probe_evidence_distinguishes_timeout_from_cancellation():
    assert tproxy._probe_attempts_confirm_zero_payload(
        {
            "198.51.100.10": tproxy.ROUTE_PROBE_CLOSED,
            "198.51.100.11": tproxy.ROUTE_PROBE_CLOSED,
        },
        2,
    )
    assert not tproxy._probe_attempts_confirm_zero_payload(
        {
            "198.51.100.10": tproxy.ROUTE_PROBE_CLOSED,
            "198.51.100.11": tproxy.ROUTE_PROBE_TIMEOUT,
        },
        2,
    )
    assert not tproxy._probe_attempts_confirm_zero_payload(
        {"198.51.100.10": tproxy.ROUTE_PROBE_PENDING},
        1,
    )
    assert not tproxy._probe_attempts_confirm_zero_payload(
        {"198.51.100.10": tproxy.ROUTE_PROBE_FAILED},
        1,
    )


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

    async def failed_xbox(
        actual_host,
        port,
        head,
        body,
        *,
        attempt_summary=None,
        **_kwargs,
    ):
        calls.append(("xbox", actual_host, port, head + body))
        attempt_summary["attempted"] = 1
        attempt_summary["outcomes"] = {
            "198.51.100.41": tproxy.ROUTE_PROBE_CLOSED,
        }
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
    confirmations = []
    strategies = (
        tproxy.STRAT_BY_NAME["split64+fake"],
        tproxy.STRAT_BY_NAME["split16+fake"],
    )

    async def failed_system(ip, port, first_flight, **_kwargs):
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
    monkeypatch.setattr(
        tproxy,
        "_schedule_auto_geph_confirmation_before_relay",
        lambda actual_host, **_kwargs: confirmations.append(actual_host) or True,
    )
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
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert confirmations == [host]
    assert tproxy.geph_active_session_count() == 0


def _assert_one_shot_geph_watermark_for_host(host):
    assert host in tproxy._auto_geph_one_shot_consumed_at
    assert tproxy._auto_geph_one_shot_consumed_at[host] == max(
        tproxy._local_zero_payload_failures[host].values()
    )


def test_unknown_exact_proof_uses_one_shot_geph_during_network_noise(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    host = "network-noisy-foreign-exit.example"
    local_ip = "198.51.100.62"
    response = b"\x16\x03\x03\x00\x60" + (b"N" * 96)
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    calls = []
    confirmations = []
    strategies = (
        tproxy.STRAT_BY_NAME["split64+fake"],
        tproxy.STRAT_BY_NAME["split16+fake"],
    )
    now = time.monotonic()

    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        tproxy._local_zero_payload_failures[
            f"background-noise-{index}.example"
        ] = {tproxy.AUTO_GEPH_STAGE_SYSTEM: now}
    # The route candidate was authorized before unrelated failures made the
    # network-wide guard noisy. It must be downgraded, not learned later.
    tproxy._auto_geph_candidates[host] = now + 60.0

    async def failed_system(ip, port, first_flight, **_kwargs):
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

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.62", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", failed_system)
    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", failed_xbox)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", local_dns)
    monkeypatch.setattr(tproxy, "strategy_order", lambda _host: strategies)
    monkeypatch.setattr(tproxy, "dial_strategy", failed_local)
    monkeypatch.setattr(tproxy, "dial_via_geph", healthy_owned_geph)
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: None)
    monkeypatch.setattr(
        tproxy,
        "_schedule_auto_geph_confirmation_before_relay",
        lambda actual_host, **_kwargs: confirmations.append(actual_host) or True,
    )
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
    assert host not in tproxy._auto_geph_candidates
    assert host in tproxy._local_zero_payload_failures
    _assert_one_shot_geph_watermark_for_host(host)
    assert not tproxy._auto_geph_one_shot_request_proven(host)
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert confirmations == []
    assert tproxy.geph_active_session_count() == 0


def test_unknown_one_shot_geph_without_payload_is_not_reused(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "network-noisy-empty-geph.example"
    first_flight = static_tls_fixture_record(host)
    upstream_writer = CaptureWriter()
    confirmations = []
    now = time.monotonic()
    stages = {
        tproxy.AUTO_GEPH_STAGE_SYSTEM: now,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS: now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake": now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake": now,
    }

    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        tproxy._local_zero_payload_failures[
            f"background-empty-{index}.example"
        ] = {tproxy.AUTO_GEPH_STAGE_SYSTEM: now}
    tproxy._local_zero_payload_failures[host] = dict(stages)

    async def empty_owned_geph(_host, _port, _payload):
        return ScriptedReader(), upstream_writer

    monkeypatch.setattr(tproxy, "dial_via_geph", empty_owned_geph)
    monkeypatch.setattr(
        tproxy,
        "_schedule_auto_geph_confirmation_before_relay",
        lambda actual_host, **_kwargs: confirmations.append(actual_host) or True,
    )
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    selected = asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            first_flight,
            ScriptedReader(),
            CaptureWriter(),
        )
    )

    assert not selected
    assert upstream_writer.closed is True
    assert host in tproxy._local_zero_payload_failures
    _assert_one_shot_geph_watermark_for_host(host)
    assert not tproxy._auto_geph_one_shot_request_proven(host)
    assert host not in tproxy._auto_geph_candidates
    assert host not in tproxy._auto_geph_successor_requests
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert confirmations == []
    assert tproxy.geph_active_session_count() == 0


def test_late_one_shot_handoff_retains_exactly_one_successor(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "late-owned-geph-handoff.example"
    first_flight = static_tls_fixture_record(host)
    response = b"\x16\x03\x03\x00\x60" + (b"S" * 96)
    now = time.monotonic()
    stages = {
        tproxy.AUTO_GEPH_STAGE_SYSTEM: now,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS: now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake": now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake": now,
    }
    for index in range(tproxy.AUTO_GEPH_NET_BAD):
        tproxy._local_zero_payload_failures[
            f"late-handoff-noise-{index}.example"
        ] = {tproxy.AUTO_GEPH_STAGE_SYSTEM: now}
    tproxy._local_zero_payload_failures[host] = dict(stages)

    async def slow_owned_geph(_host, _port, _payload):
        return (
            ScriptedReader(stream=(response,), block_when_empty=True),
            CaptureWriter(),
        )

    monkeypatch.setattr(tproxy, "dial_via_geph", slow_owned_geph)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    selected = asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            first_flight,
            ScriptedReader(),
            CaptureWriter(),
        )
    )

    assert selected
    assert host in tproxy._auto_geph_successor_requests
    assert tproxy._claim_auto_geph_successor_request(host)
    assert host not in tproxy._auto_geph_successor_requests
    assert not tproxy._claim_auto_geph_successor_request(host)


def test_generic_owned_geph_helper_rejects_request_only_claim(monkeypatch):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(400.0)
    monkeypatch.setattr(tproxy, "time", clock)
    host = "request-only-generic-reject.example"
    claim = request_only_geph_claim(
        host,
        capability="d" * 32,
        eligible_after_monotonic=401.0,
        deadline_monotonic=402.0,
    )
    before = request_only_non_learning_snapshot()

    async def forbidden_candidate(*_args, **_kwargs):
        raise AssertionError("request-only authority cannot enter generic Geph")

    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_candidate",
        forbidden_candidate,
    )

    selected = asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            b"client hello",
            ScriptedReader(),
            CaptureWriter(),
            successor_claim=claim,
        )
    )

    assert not selected
    assert claim.capability not in tproxy._route_preflight_consumed
    assert request_only_non_learning_snapshot() == before


def test_request_only_route_requires_held_exact_stream(monkeypatch):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(500.0)
    monkeypatch.setattr(tproxy, "time", clock)
    host = "request-only-held-exact.example"
    claim = request_only_geph_claim(
        host,
        capability="e" * 32,
        eligible_after_monotonic=501.0,
        deadline_monotonic=502.0,
    )
    clock.value = 501.0
    before = request_only_non_learning_snapshot()

    result = asyncio.run(
        tproxy._try_request_only_tls_stall_geph_route(
            host,
            claim.exact_address,
            443,
            b"client hello",
            ScriptedReader(),
            CaptureWriter(),
            held_exact=None,
            claim=claim,
            eligible_after_monotonic=claim.eligible_after_monotonic,
            deadline_monotonic=claim.deadline_monotonic,
        )
    )

    assert isinstance(result, tproxy._RequestOnlyRouteResult)
    assert result.outcome is tproxy._RequestOnlyRouteOutcome.NO_ROUTE
    assert result.exact is None
    assert claim.capability not in tproxy._route_preflight_consumed
    assert request_only_non_learning_snapshot() == before


@pytest.mark.parametrize(
    "failure",
    (
        "eligibility",
        "deadline",
        "readiness",
        "pid",
        "restart_drain",
        "session",
        "dial",
        "short_eof",
        "pid_after_payload",
    ),
)
def test_request_only_route_failures_return_held_exact(
    monkeypatch,
    failure,
):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(600.0)
    monkeypatch.setattr(tproxy, "time", clock)
    enable_request_only_owned_geph(monkeypatch)
    host = "request-only-fail-open.example"
    claim = request_only_geph_claim(
        host,
        capability="f" * 32,
        eligible_after_monotonic=601.0,
        deadline_monotonic=610.0,
    )
    clock.value = 601.0
    eligible_after = claim.eligible_after_monotonic
    exact_writer = CaptureWriter()
    held_exact = (
        ScriptedReader(block_when_empty=True),
        exact_writer,
        b"",
    )
    geph_writer = CaptureWriter()
    client_writer = CaptureWriter()
    real_payload_dial = tproxy._dial_via_geph_first_payload

    async def forbidden_payload(*_args, **_kwargs):
        raise AssertionError(f"{failure} must stop before a Geph payload dial")

    async def unavailable_payload(*_args, **_kwargs):
        return None, "first payload unavailable"

    async def short_geph_stream(*_args, **_kwargs):
        return ScriptedReader(stream=(b"S" * 63,)), geph_writer

    async def qualified_payload(*_args, **_kwargs):
        return (
            ScriptedReader(),
            geph_writer,
            b"G" * tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES,
        ), None

    monkeypatch.setattr(
        tproxy,
        "_dial_via_geph_first_payload",
        forbidden_payload,
    )
    if failure == "eligibility":
        eligible_after += 0.25
    elif failure == "deadline":
        clock.value = claim.deadline_monotonic
    elif failure == "readiness":
        monkeypatch.setattr(tproxy, "_geph_up", False)
    elif failure == "pid":
        monkeypatch.setattr(
            tproxy,
            "_owned_geph_confirmation_pid_matches",
            lambda _pid: False,
        )
    elif failure == "restart_drain":
        monkeypatch.setattr(tproxy, "_geph_restart_draining", True)
    elif failure == "session":
        monkeypatch.setattr(tproxy, "_geph_session_started", lambda: False)
    elif failure == "dial":
        monkeypatch.setattr(
            tproxy,
            "_dial_via_geph_first_payload",
            unavailable_payload,
        )
    elif failure == "short_eof":
        monkeypatch.setattr(tproxy, "dial_via_geph", short_geph_stream)
        monkeypatch.setattr(
            tproxy,
            "_dial_via_geph_first_payload",
            real_payload_dial,
        )
    elif failure == "pid_after_payload":
        pid_matches = iter((True, True, False))
        monkeypatch.setattr(
            tproxy,
            "_owned_geph_confirmation_pid_matches",
            lambda _pid: next(pid_matches),
        )
        monkeypatch.setattr(
            tproxy,
            "_dial_via_geph_first_payload",
            qualified_payload,
        )

    before = request_only_non_learning_snapshot()
    result = asyncio.run(
        tproxy._try_request_only_tls_stall_geph_route(
            host,
            claim.exact_address,
            443,
            b"client hello",
            ScriptedReader(),
            client_writer,
            held_exact=held_exact,
            claim=claim,
            eligible_after_monotonic=eligible_after,
            deadline_monotonic=claim.deadline_monotonic,
        )
    )

    assert isinstance(result, tproxy._RequestOnlyRouteResult)
    assert result.outcome is tproxy._RequestOnlyRouteOutcome.EXACT
    assert result.exact is held_exact
    assert not exact_writer.closed
    assert bytes(client_writer.payload) == b""
    assert request_only_non_learning_snapshot() == before
    assert tproxy.geph_active_session_count() == 0
    consumed = claim.capability in tproxy._route_preflight_consumed
    assert consumed is (failure not in {"eligibility", "deadline"})
    if failure in {"short_eof", "pid_after_payload"}:
        assert geph_writer.closed


def test_request_only_route_both_streams_empty_returns_no_route(monkeypatch):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(650.0)
    monkeypatch.setattr(tproxy, "time", clock)
    enable_request_only_owned_geph(monkeypatch)
    host = "request-only-both-empty.example"
    claim = request_only_geph_claim(
        host,
        capability="e" * 32,
        eligible_after_monotonic=651.0,
        deadline_monotonic=660.0,
    )
    clock.value = claim.eligible_after_monotonic
    exact_writer = CaptureWriter()
    held_exact = (ScriptedReader(), exact_writer, b"")
    client_writer = CaptureWriter()
    geph_dials = []

    async def unavailable_payload(*args, **kwargs):
        geph_dials.append((args, kwargs))
        return None, "first payload unavailable"

    monkeypatch.setattr(
        tproxy,
        "_dial_via_geph_first_payload",
        unavailable_payload,
    )
    before = request_only_non_learning_snapshot()

    result = asyncio.run(
        tproxy._try_request_only_tls_stall_geph_route(
            host,
            claim.exact_address,
            443,
            b"client hello",
            ScriptedReader(),
            client_writer,
            held_exact=held_exact,
            claim=claim,
            eligible_after_monotonic=claim.eligible_after_monotonic,
            deadline_monotonic=claim.deadline_monotonic,
        )
    )

    assert result.outcome is tproxy._RequestOnlyRouteOutcome.NO_ROUTE
    assert result.exact is None
    assert exact_writer.closed
    assert len(geph_dials) == 1
    assert bytes(client_writer.payload) == b""
    assert claim.capability in tproxy._route_preflight_consumed
    assert request_only_non_learning_snapshot() == before
    assert tproxy.geph_active_session_count() == 0


def test_request_only_route_cancellation_closes_held_exact_and_session(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(675.0)
    monkeypatch.setattr(tproxy, "time", clock)
    enable_request_only_owned_geph(monkeypatch)
    host = "request-only-cancelled.example"
    claim = request_only_geph_claim(
        host,
        capability="d" * 32,
        eligible_after_monotonic=676.0,
        deadline_monotonic=685.0,
    )
    clock.value = claim.eligible_after_monotonic
    exact_writer = CaptureWriter()
    held_exact = (
        ScriptedReader(block_when_empty=True),
        exact_writer,
        b"",
    )
    client_writer = CaptureWriter()
    geph_entered = asyncio.Event()

    async def blocked_payload(*_args, **_kwargs):
        geph_entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(
        tproxy,
        "_dial_via_geph_first_payload",
        blocked_payload,
    )
    before = request_only_non_learning_snapshot()

    async def scenario():
        task = asyncio.create_task(
            tproxy._try_request_only_tls_stall_geph_route(
                host,
                claim.exact_address,
                443,
                b"client hello",
                ScriptedReader(),
                client_writer,
                held_exact=held_exact,
                claim=claim,
                eligible_after_monotonic=claim.eligible_after_monotonic,
                deadline_monotonic=claim.deadline_monotonic,
            )
        )
        await asyncio.wait_for(geph_entered.wait(), timeout=1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())

    assert exact_writer.closed
    assert bytes(client_writer.payload) == b""
    assert claim.capability in tproxy._route_preflight_consumed
    assert request_only_non_learning_snapshot() == before
    assert tproxy.geph_active_session_count() == 0


def test_request_only_route_fragmented_geph_payload_is_single_use(monkeypatch):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(700.0)
    monkeypatch.setattr(tproxy, "time", clock)
    enable_request_only_owned_geph(monkeypatch)
    host = "request-only-fragmented-payload.example"
    claim = request_only_geph_claim(
        host,
        capability="1" * 32,
        eligible_after_monotonic=701.0,
        deadline_monotonic=710.0,
    )
    clock.value = 701.0
    exact_writer = CaptureWriter()
    held_exact = (
        ScriptedReader(block_when_empty=True),
        exact_writer,
        b"",
    )
    geph_writer = CaptureWriter()
    client_writer = CaptureWriter()
    dials = []

    async def fragmented_geph(actual_host, port, first_flight):
        dials.append((actual_host, port, first_flight))
        return (
            ScriptedReader(stream=(b"A", b"B" * 31, b"C" * 32)),
            geph_writer,
        )

    async def bounded_relay(
        _client_reader,
        upstream_writer,
        _upstream_reader,
        _client_writer,
        _activity,
        **_kwargs,
    ):
        assert upstream_writer is geph_writer
        upstream_writer.close()
        return 0, 0

    monkeypatch.setattr(tproxy, "dial_via_geph", fragmented_geph)
    monkeypatch.setattr(tproxy, "relay_local_stream", bounded_relay)
    before = request_only_non_learning_snapshot()

    first = asyncio.run(
        tproxy._try_request_only_tls_stall_geph_route(
            host,
            claim.exact_address,
            443,
            b"client hello",
            ScriptedReader(),
            client_writer,
            held_exact=held_exact,
            claim=claim,
            eligible_after_monotonic=claim.eligible_after_monotonic,
            deadline_monotonic=claim.deadline_monotonic,
        )
    )
    second_writer = CaptureWriter()
    second_exact = (
        ScriptedReader(block_when_empty=True),
        second_writer,
        b"",
    )
    second = asyncio.run(
        tproxy._try_request_only_tls_stall_geph_route(
            host,
            claim.exact_address,
            443,
            b"client hello",
            ScriptedReader(),
            CaptureWriter(),
            held_exact=second_exact,
            claim=claim,
            eligible_after_monotonic=claim.eligible_after_monotonic,
            deadline_monotonic=claim.deadline_monotonic,
        )
    )

    assert tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES == 64
    assert first.outcome is tproxy._RequestOnlyRouteOutcome.GEPH_HANDLED
    assert first.exact is None
    assert second.outcome is tproxy._RequestOnlyRouteOutcome.EXACT
    assert second.exact is second_exact
    assert dials == [(host, 443, b"client hello")]
    assert bytes(client_writer.payload) == b"A" + b"B" * 31 + b"C" * 32
    assert exact_writer.closed
    assert geph_writer.closed
    assert not second_writer.closed
    assert claim.capability in tproxy._route_preflight_consumed
    assert request_only_non_learning_snapshot() == before
    assert tproxy.geph_active_session_count() == 0


def test_request_only_route_exact_payload_wins_geph_tie(monkeypatch):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(800.0)
    monkeypatch.setattr(tproxy, "time", clock)
    enable_request_only_owned_geph(monkeypatch)
    host = "request-only-exact-tie.example"
    claim = request_only_geph_claim(
        host,
        capability="2" * 32,
        eligible_after_monotonic=801.0,
        deadline_monotonic=810.0,
    )
    clock.value = 801.0
    direct_payload = b"direct wins tie"
    exact_writer = CaptureWriter()
    held_exact = (ScriptedReader(stream=(direct_payload,)), exact_writer, b"")
    geph_writer = CaptureWriter()
    client_writer = CaptureWriter()

    async def qualified_payload(*_args, **_kwargs):
        return (
            ScriptedReader(),
            geph_writer,
            b"G" * tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES,
        ), None

    async def complete_both(tasks, *, return_when):
        del return_when
        await asyncio.gather(*tasks)
        return set(tasks), set()

    monkeypatch.setattr(
        tproxy,
        "_dial_via_geph_first_payload",
        qualified_payload,
    )
    monkeypatch.setattr(tproxy, "asyncio", TproxyAsyncioFacade(complete_both))
    before = request_only_non_learning_snapshot()

    result = asyncio.run(
        tproxy._try_request_only_tls_stall_geph_route(
            host,
            claim.exact_address,
            443,
            b"client hello",
            ScriptedReader(),
            client_writer,
            held_exact=held_exact,
            claim=claim,
            eligible_after_monotonic=claim.eligible_after_monotonic,
            deadline_monotonic=claim.deadline_monotonic,
        )
    )

    assert result.outcome is tproxy._RequestOnlyRouteOutcome.EXACT
    assert result.exact == (held_exact[0], exact_writer, direct_payload)
    assert not exact_writer.closed
    assert geph_writer.closed
    assert bytes(client_writer.payload) == b""
    assert claim.capability in tproxy._route_preflight_consumed
    assert request_only_non_learning_snapshot() == before
    assert tproxy.geph_active_session_count() == 0


def test_request_only_route_rechecks_late_exact_payload_before_commit(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(900.0)
    monkeypatch.setattr(tproxy, "time", clock)
    enable_request_only_owned_geph(monkeypatch)
    host = "request-only-late-exact.example"
    claim = request_only_geph_claim(
        host,
        capability="3" * 32,
        eligible_after_monotonic=901.0,
        deadline_monotonic=910.0,
    )
    clock.value = 901.0
    exact_started = asyncio.Event()
    release_exact = asyncio.Event()
    exact_returned = asyncio.Event()
    direct_payload = b"late direct payload"

    class LateExactReader:
        async def read(self, _size=-1):
            exact_started.set()
            await release_exact.wait()
            exact_returned.set()
            return direct_payload

    exact_writer = CaptureWriter()
    held_exact = (LateExactReader(), exact_writer, b"")
    geph_writer = CaptureWriter()
    client_writer = CaptureWriter()

    async def qualified_payload(*_args, **_kwargs):
        await exact_started.wait()
        return (
            ScriptedReader(),
            geph_writer,
            b"G" * tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES,
        ), None

    async def geph_finishes_before_late_exact(tasks, *, return_when):
        del return_when
        exact_task, geph_task = tasks
        await geph_task
        release_exact.set()
        await exact_returned.wait()
        assert exact_task.done()
        return {geph_task}, {exact_task}

    monkeypatch.setattr(
        tproxy,
        "_dial_via_geph_first_payload",
        qualified_payload,
    )
    monkeypatch.setattr(
        tproxy,
        "asyncio",
        TproxyAsyncioFacade(geph_finishes_before_late_exact),
    )
    before = request_only_non_learning_snapshot()

    result = asyncio.run(
        tproxy._try_request_only_tls_stall_geph_route(
            host,
            claim.exact_address,
            443,
            b"client hello",
            ScriptedReader(),
            client_writer,
            held_exact=held_exact,
            claim=claim,
            eligible_after_monotonic=claim.eligible_after_monotonic,
            deadline_monotonic=claim.deadline_monotonic,
        )
    )

    assert result.outcome is tproxy._RequestOnlyRouteOutcome.EXACT
    assert result.exact == (held_exact[0], exact_writer, direct_payload)
    assert not exact_writer.closed
    assert geph_writer.closed
    assert bytes(client_writer.payload) == b""
    assert claim.capability in tproxy._route_preflight_consumed
    assert request_only_non_learning_snapshot() == before
    assert tproxy.geph_active_session_count() == 0


def test_request_only_final_pid_check_yields_to_newly_ready_exact(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(920.0)
    monkeypatch.setattr(tproxy, "time", clock)
    enable_request_only_owned_geph(monkeypatch)
    host = "request-only-final-pid-exact.example"
    claim = request_only_geph_claim(
        host,
        capability="5" * 32,
        eligible_after_monotonic=921.0,
        deadline_monotonic=930.0,
    )
    clock.value = 921.0
    exact_started = asyncio.Event()
    release_exact = asyncio.Event()
    direct_payload = b"exact became ready during final PID check"

    class FinalPidExactReader:
        async def read(self, _size=-1):
            exact_started.set()
            await release_exact.wait()
            return direct_payload

    exact_writer = CaptureWriter()
    held_exact = (FinalPidExactReader(), exact_writer, b"")
    geph_writer = CaptureWriter()
    client_writer = CaptureWriter()
    pid_checks = 0

    def pid_matches(_pid):
        nonlocal pid_checks
        pid_checks += 1
        if pid_checks == 3:
            release_exact.set()
        return True

    async def qualified_payload(*_args, **_kwargs):
        await exact_started.wait()
        return (
            ScriptedReader(),
            geph_writer,
            b"G" * tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES,
        ), None

    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        pid_matches,
    )
    monkeypatch.setattr(
        tproxy,
        "_dial_via_geph_first_payload",
        qualified_payload,
    )
    before = request_only_non_learning_snapshot()

    result = asyncio.run(
        tproxy._try_request_only_tls_stall_geph_route(
            host,
            claim.exact_address,
            443,
            b"client hello",
            ScriptedReader(),
            client_writer,
            held_exact=held_exact,
            claim=claim,
            eligible_after_monotonic=claim.eligible_after_monotonic,
            deadline_monotonic=claim.deadline_monotonic,
        )
    )

    assert pid_checks == 3
    assert result.outcome is tproxy._RequestOnlyRouteOutcome.EXACT
    assert result.exact == (held_exact[0], exact_writer, direct_payload)
    assert not exact_writer.closed
    assert geph_writer.closed
    assert bytes(client_writer.payload) == b""
    assert request_only_non_learning_snapshot() == before
    assert tproxy.geph_active_session_count() == 0


def test_request_only_final_pid_check_rechecks_advanced_deadline(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(940.0)
    monkeypatch.setattr(tproxy, "time", clock)
    enable_request_only_owned_geph(monkeypatch)
    host = "request-only-final-pid-deadline.example"
    claim = request_only_geph_claim(
        host,
        capability="6" * 32,
        eligible_after_monotonic=941.0,
        deadline_monotonic=950.0,
    )
    clock.value = 941.0
    exact_writer = CaptureWriter()
    held_exact = (
        ScriptedReader(block_when_empty=True),
        exact_writer,
        b"",
    )
    geph_writer = CaptureWriter()
    client_writer = CaptureWriter()
    pid_checks = 0

    def pid_matches(_pid):
        nonlocal pid_checks
        pid_checks += 1
        if pid_checks == 3:
            clock.value = claim.deadline_monotonic + 1.0
        return True

    async def qualified_payload(*_args, **_kwargs):
        return (
            ScriptedReader(),
            geph_writer,
            b"G" * tproxy.AUTO_GEPH_CONFIRM_MIN_BYTES,
        ), None

    monkeypatch.setattr(
        tproxy,
        "_owned_geph_confirmation_pid_matches",
        pid_matches,
    )
    monkeypatch.setattr(
        tproxy,
        "_dial_via_geph_first_payload",
        qualified_payload,
    )
    before = request_only_non_learning_snapshot()

    result = asyncio.run(
        tproxy._try_request_only_tls_stall_geph_route(
            host,
            claim.exact_address,
            443,
            b"client hello",
            ScriptedReader(),
            client_writer,
            held_exact=held_exact,
            claim=claim,
            eligible_after_monotonic=claim.eligible_after_monotonic,
            deadline_monotonic=claim.deadline_monotonic,
        )
    )

    assert pid_checks == 3
    assert result.outcome is tproxy._RequestOnlyRouteOutcome.EXACT
    assert result.exact is held_exact
    assert not exact_writer.closed
    assert geph_writer.closed
    assert bytes(client_writer.payload) == b""
    assert request_only_non_learning_snapshot() == before
    assert tproxy.geph_active_session_count() == 0


def test_owned_geph_handoff_uses_only_remaining_client_deadline(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "bounded-owned-handoff.example"
    response = b"\x16\x03\x03\x00\x60" + (b"B" * 96)
    writer = CaptureWriter()
    seen_timeouts = []
    claim = tproxy._AutoGephSuccessorClaim(
        marker=tproxy._AUTO_GEPH_SUCCESSOR_CLAIM,
        host=host,
    )

    async def candidate_ready(*_args, **_kwargs):
        return True

    async def bounded_payload(_host, _port, _flight, timeout):
        seen_timeouts.append(timeout)
        return (ScriptedReader(), CaptureWriter(), response), None

    monkeypatch.setattr(tproxy, "_wait_for_owned_geph_candidate", candidate_ready)
    monkeypatch.setattr(tproxy, "_dial_via_geph_first_payload", bounded_payload)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    deadline = time.monotonic() + 0.5
    selected = asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            static_tls_fixture_record(host),
            ScriptedReader(),
            writer,
            successor_claim=claim,
            deadline_monotonic=deadline,
        )
    )

    assert selected
    assert bytes(writer.payload) == response
    assert len(seen_timeouts) == 1
    assert 0 < seen_timeouts[0] <= 0.5
    assert tproxy.geph_active_session_count() == 0


def test_owned_geph_deadline_expiry_never_dials_or_grants_successor(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "expired-owned-handoff.example"
    claim = tproxy._AutoGephSuccessorClaim(
        marker=tproxy._AUTO_GEPH_SUCCESSOR_CLAIM,
        host=host,
    )

    async def blocked_candidate(*_args, **_kwargs):
        await asyncio.Event().wait()

    async def forbidden_payload(*_args, **_kwargs):
        raise AssertionError("deadline expiry must stop before target CONNECT")

    monkeypatch.setattr(tproxy, "_wait_for_owned_geph_candidate", blocked_candidate)
    monkeypatch.setattr(tproxy, "_dial_via_geph_first_payload", forbidden_payload)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    selected = asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            static_tls_fixture_record(host),
            ScriptedReader(),
            CaptureWriter(),
            successor_claim=claim,
            deadline_monotonic=time.monotonic() + 0.01,
        )
    )

    assert not selected
    assert host not in tproxy._auto_geph_successor_requests
    assert tproxy.geph_active_session_count() == 0


def test_successor_uses_owned_geph_before_local_recovery(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "successor-before-local.example"
    response = b"\x16\x03\x03\x00\x60" + (b"T" * 96)
    client, expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    calls = []

    assert tproxy._grant_auto_geph_successor_request(host)

    async def healthy_owned_geph(actual_host, port, first_flight):
        assert host not in tproxy._auto_geph_successor_requests
        calls.append((actual_host, port, first_flight))
        return (
            ScriptedReader(stream=(response,), block_when_empty=True),
            CaptureWriter(),
        )

    async def unexpected_local(*_args, **_kwargs):
        raise AssertionError("successor must run before every local route stage")

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.63", 443))
    monkeypatch.setattr(tproxy, "dial_via_geph", healthy_owned_geph)
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", unexpected_local)
    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", unexpected_local)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", unexpected_local)
    monkeypatch.setattr(tproxy, "dial_strategy", unexpected_local)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    asyncio.run(run_handler(client, writer))

    assert calls == [(host, 443, expected_first_flight)]
    assert bytes(writer.payload) == response
    assert host not in tproxy._auto_geph_successor_requests
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_successor_is_bounded_and_excludes_protected_hosts(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "bounded-successor.example"
    now = time.monotonic()

    monkeypatch.setattr(tproxy, "AUTO_GEPH_STATE_MAX", 2)
    assert tproxy._grant_auto_geph_successor_request(
        "oldest-successor.example",
        now=now - 2.0,
    )
    assert tproxy._grant_auto_geph_successor_request(
        "middle-successor.example",
        now=now - 1.0,
    )
    assert tproxy._grant_auto_geph_successor_request(host, now=now)
    assert set(tproxy._auto_geph_successor_requests) == {
        "middle-successor.example",
        host,
    }
    assert not tproxy._claim_auto_geph_successor_request(
        host,
        now=now + tproxy.AUTO_GEPH_SUCCESSOR_TTL + 0.01,
    )
    assert not tproxy._grant_auto_geph_successor_request("youtube.com", now=now)
    assert not tproxy._grant_auto_geph_successor_request(
        "updates.discord.com",
        now=now,
    )


def test_successor_claim_cannot_move_to_another_host(monkeypatch):
    isolate_runtime_state(monkeypatch)
    source_host = "successor-source.example"
    other_host = "successor-other.example"
    waits = []

    assert tproxy._grant_auto_geph_successor_request(source_host)
    claim = tproxy._claim_auto_geph_successor_request(source_host)
    assert claim

    async def reject_unproven_candidate(host, *, one_shot_authorized=False):
        waits.append((host, one_shot_authorized))
        return False

    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_candidate",
        reject_unproven_candidate,
    )

    selected = asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            other_host,
            443,
            static_tls_fixture_record(other_host),
            ScriptedReader(),
            CaptureWriter(),
            successor_claim=claim,
        )
    )

    assert not selected
    assert waits == [(other_host, False)]


def test_downstream_close_after_owned_payload_grants_successor(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "closed-downstream-handoff.example"
    first_flight = static_tls_fixture_record(host)
    response = b"\x16\x03\x03\x00\x60" + (b"U" * 96)
    now = time.monotonic()
    seed_complete_unknown_zero_payload_proof(host, now)
    tproxy._auto_geph_candidates[host] = now + 10.0

    class ClosedWriter(CaptureWriter):
        async def drain(self):
            raise BrokenPipeError("client closed")

    async def healthy_owned_geph(_host, _port, _payload):
        return streaming_upstream_response(response)

    monkeypatch.setattr(tproxy, "dial_via_geph", healthy_owned_geph)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    selected = asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            first_flight,
            ScriptedReader(),
            ClosedWriter(),
        )
    )

    assert selected
    assert host in tproxy._auto_geph_successor_requests
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_candidate_request_becomes_spent_one_shot_when_noise_arrives_mid_dial(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    host = "candidate-noise-during-dial.example"
    first_flight = static_tls_fixture_record(host)
    response = b"\x16\x03\x03\x00\x60" + (b"R" * 96)
    client_writer = CaptureWriter()
    confirmations = []
    status_events = []
    now = time.monotonic()
    tproxy._local_zero_payload_failures[host] = {
        tproxy.AUTO_GEPH_STAGE_SYSTEM: now,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS: now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake": now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake": now,
    }
    tproxy._auto_geph_candidates[host] = now + 60.0

    async def noisy_owned_geph(_host, _port, _payload):
        for index in range(tproxy.AUTO_GEPH_NET_BAD):
            tproxy._local_zero_payload_failures[
                f"mid-dial-noise-{index}.example"
            ] = {tproxy.AUTO_GEPH_STAGE_SYSTEM: time.monotonic()}
        assert tproxy._network_wide_unknown_failure_visible()
        return streaming_upstream_response(response)

    monkeypatch.setattr(tproxy, "dial_via_geph", noisy_owned_geph)
    monkeypatch.setattr(
        tproxy,
        "_schedule_auto_geph_confirmation_before_relay",
        lambda actual_host, **_kwargs: confirmations.append(actual_host) or True,
    )
    original_set_status = tproxy._set_auto_geph_status

    def record_status(state, actual_host="", reason="", bytes_read=0):
        status_events.append((state, actual_host, reason, bytes_read))
        original_set_status(state, actual_host, reason, bytes_read)

    monkeypatch.setattr(tproxy, "_set_auto_geph_status", record_status)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    selected = asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            first_flight,
            ScriptedReader(),
            client_writer,
        )
    )

    assert selected
    assert bytes(client_writer.payload) == response
    assert host not in tproxy._auto_geph_candidates
    _assert_one_shot_geph_watermark_for_host(host)
    assert not tproxy._auto_geph_one_shot_request_proven(host)
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert confirmations == []
    assert any(
        state == "one_shot" and actual_host == host
        for state, actual_host, _reason, _bytes_read in status_events
    )
    assert tproxy.geph_active_session_count() == 0


def test_unknown_one_shot_proof_is_consumed_before_backend_wait(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "network-noisy-backend-wait.example"
    now = time.monotonic()
    stages = {
        tproxy.AUTO_GEPH_STAGE_SYSTEM: now,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS: now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split64+fake": now,
        f"{tproxy.AUTO_GEPH_STAGE_STRATEGY_PREFIX}split16+fake": now,
    }
    other_candidate = "background-wait-0.example"
    for index in range(tproxy.AUTO_GEPH_NET_BAD - 1):
        tproxy._local_zero_payload_failures[
            f"background-wait-{index}.example"
        ] = dict(stages)
    tproxy._auto_geph_candidates[other_candidate] = now + 60.0
    tproxy._local_zero_payload_failures[host] = dict(stages)

    async def unavailable_after_claim(_host, *, one_shot_authorized=False):
        assert one_shot_authorized
        assert host in tproxy._local_zero_payload_failures
        assert not tproxy._auto_geph_one_shot_request_proven(host)
        assert tproxy._network_wide_unknown_failure_visible()
        assert not tproxy._auto_geph_candidate_allowed(other_candidate)
        return False

    monkeypatch.setattr(
        tproxy,
        "_wait_for_owned_geph_candidate",
        unavailable_after_claim,
    )

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
    assert host in tproxy._local_zero_payload_failures
    assert not tproxy._auto_geph_one_shot_request_proven(host)
    assert host not in tproxy._auto_geph_candidates
    assert not tproxy._auto_geph_candidate_allowed(other_candidate)


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
    confirmations = []
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
    monkeypatch.setattr(
        tproxy,
        "_schedule_auto_geph_confirmation_before_relay",
        lambda actual_host, **_kwargs: confirmations.append(actual_host) or True,
    )
    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(
        tproxy,
        "_geph_backend_hold_until",
        time.time() + tproxy.GEPH_BACKEND_FAILURE_HOLD,
    )
    monkeypatch.setattr(
        tproxy,
        "_geph_backend_hold_reason",
        "earlier payload miss",
    )
    seed_complete_unknown_zero_payload_proof(host, now)
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
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert confirmations == [host]
    assert tproxy._geph_backend_hold_until > time.time()
    assert tproxy._geph_backend_hold_reason == "earlier payload miss"
    assert tproxy.geph_active_session_count() == 0


def test_spent_candidate_survives_noise_during_owned_geph_recovery(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    host = "candidate-noise-during-recovery.example"
    first_flight = static_tls_fixture_record(host)
    response = b"\x16\x03\x03\x00\x60" + (b"N" * 96)
    writer = CaptureWriter()
    confirmations = []
    now = time.monotonic()
    seed_complete_unknown_zero_payload_proof(host, now)
    tproxy._auto_geph_candidates[host] = now + 10.0

    def recover_after_noise():
        observed_at = time.monotonic()
        for index in range(tproxy.AUTO_GEPH_NET_BAD):
            tproxy._local_zero_payload_failures[
                f"recovery-noise-{index}.example"
            ] = {tproxy.AUTO_GEPH_STAGE_SYSTEM: observed_at}
        assert tproxy._network_wide_unknown_failure_visible(observed_at)
        assert host not in tproxy._auto_geph_candidates
        return "ready"

    async def healthy_owned_geph(_host, _port, _payload):
        return streaming_upstream_response(response)

    monkeypatch.setattr(tproxy, "_geph_up", False)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "_probe_owned_geph_recovery_state", recover_after_noise)
    monkeypatch.setattr(tproxy, "dial_via_geph", healthy_owned_geph)
    monkeypatch.setattr(
        tproxy,
        "_schedule_auto_geph_confirmation_before_relay",
        lambda actual_host, **_kwargs: confirmations.append(actual_host) or True,
    )

    assert asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            first_flight,
            ScriptedReader(),
            writer,
        )
    )
    assert bytes(writer.payload) == response
    _assert_one_shot_geph_watermark_for_host(host)
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert confirmations == []
    assert tproxy._auto_geph_last_status["state"] == "one_shot"
    assert tproxy.geph_active_session_count() == 0


def test_proven_unknown_learns_only_from_independent_confirmation(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "background-confirmed-foreign-exit.example"
    first_flight = static_tls_fixture_record(host)
    response = b"\x16\x03\x03\x00\x60" + (b"B" * 96)
    writer = CaptureWriter()
    now = time.monotonic()

    async def healthy_owned_geph(_host, _port, _payload):
        return streaming_upstream_response(response)

    def complete_background_confirmation(actual_host, **_kwargs):
        assert actual_host == host
        tproxy._auto_geph[host] = time.time() + 60.0
        tproxy._auto_geph_candidates.pop(host, None)
        tproxy._geph_up = True
        return True

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
        "_schedule_auto_geph_confirmation_before_relay",
        complete_background_confirmation,
    )
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    seed_complete_unknown_zero_payload_proof(host, now)
    tproxy._auto_geph_candidates[host] = now + 10.0

    async def exercise():
        return await tproxy._try_unknown_owned_geph_route(
            host,
            443,
            first_flight,
            ScriptedReader(),
            writer,
        )

    assert asyncio.run(exercise())
    assert bytes(writer.payload) == response
    assert tproxy._auto_geph_learned_exact_host(host)
    assert tproxy.geph_active_session_count() == 0


def test_proven_unknown_schedules_confirmation_before_long_lived_relay(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    host = "long-lived-foreign-exit.example"
    first_flight = static_tls_fixture_record(host)
    response = b"\x16\x03\x03\x00\x60" + (b"L" * 96)
    writer = CaptureWriter()
    confirmations = []
    relay_observations = []

    async def healthy_owned_geph(_host, _port, _payload):
        return streaming_upstream_response(response)

    async def long_lived_relay(*_args, **_kwargs):
        relay_observations.append(tuple(confirmations))
        tproxy._auto_geph_candidates.pop(host, None)
        return None

    monkeypatch.setattr(tproxy, "dial_via_geph", healthy_owned_geph)
    monkeypatch.setattr(tproxy, "relay_local_stream", long_lived_relay)
    monkeypatch.setattr(
        tproxy,
        "_schedule_auto_geph_confirmation_before_relay",
        lambda actual_host, **_kwargs: confirmations.append(actual_host) or True,
    )
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    now = time.monotonic()
    seed_complete_unknown_zero_payload_proof(host, now)
    tproxy._auto_geph_candidates[host] = now + 10.0

    assert asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            first_flight,
            ScriptedReader(),
            writer,
        )
    )
    assert confirmations == [host]
    assert relay_observations == [(host,)]
    assert bytes(writer.payload) == response
    assert tproxy.geph_active_session_count() == 0


def test_failed_early_confirmation_retries_once_after_relay_drain(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "post-drain-confirmation.example"
    first_flight = static_tls_fixture_record(host)
    response = b"\x16\x03\x03\x00\x60" + (b"D" * 96)
    writer = CaptureWriter()
    confirmation_attempts = []
    post_drain_completed = threading.Event()

    async def healthy_owned_geph(_host, _port, _payload):
        return streaming_upstream_response(response)

    async def relay_past_candidate_ttl(*_args, **_kwargs):
        tproxy._auto_geph_candidates.pop(host, None)
        return None

    def failed_confirmation(actual_host, **_kwargs):
        confirmation_attempts.append(
            (actual_host, tproxy.geph_active_session_count(), "early")
        )
        tproxy._auto_geph_confirmation_completed(actual_host, False)
        return True

    def post_drain_confirmation(
        actual_host,
        *,
        drain_reserved=False,
        candidate_authorized=False,
    ):
        confirmation_attempts.append(
            (actual_host, tproxy.geph_active_session_count(), "post-drain")
        )
        assert drain_reserved
        assert candidate_authorized
        assert tproxy._geph_restart_draining
        assert not tproxy._geph_session_started()
        post_drain_completed.set()
        return False

    monkeypatch.setattr(tproxy, "dial_via_geph", healthy_owned_geph)
    monkeypatch.setattr(tproxy, "relay_local_stream", relay_past_candidate_ttl)
    monkeypatch.setattr(
        tproxy,
        "_schedule_auto_geph_confirmation",
        failed_confirmation,
    )
    monkeypatch.setattr(tproxy, "_confirm_auto_geph", post_drain_confirmation)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    now = time.monotonic()
    seed_complete_unknown_zero_payload_proof(host, now)
    tproxy._auto_geph_candidates[host] = now + 10.0

    assert asyncio.run(
        tproxy._try_unknown_owned_geph_route(
            host,
            443,
            first_flight,
            ScriptedReader(),
            writer,
        )
    )
    assert post_drain_completed.wait(1.0)
    assert confirmation_attempts == [
        (host, 1, "early"),
        (host, 0, "post-drain"),
    ]
    assert host not in tproxy._auto_geph_retry_after_drain
    assert bytes(writer.payload) == response
    assert tproxy.geph_active_session_count() == 0
    assert not tproxy._geph_restart_draining


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


def test_unknown_bounded_route_timeouts_never_authorize_owned_geph(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "foreign-exit-by-timeout.example"
    local_ip = "198.51.100.62"
    client, _expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    evidence_before_geph = []
    local_attempts = []
    confirmations = []
    strategies = tuple(
        tproxy.STRAT_BY_NAME[name]
        for name in tproxy.GENERAL_STRATS
    )

    async def failed_system(_ip, _port, _first_flight, **_kwargs):
        return tproxy.SYSTEM_PROBE_TIMEOUT, None

    async def timed_out_xbox(
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
                "198.51.100.60": tproxy.ROUTE_PROBE_TIMEOUT,
            }
        return None

    async def local_dns(_actual_host, _fallback_ip):
        return [local_ip]

    async def timed_out_local(_ip, _port, _head, _body, _host, strategy):
        local_attempts.append(strategy["name"])
        tproxy._publish_route_probe_outcome(tproxy.ROUTE_PROBE_TIMEOUT)
        return None

    async def forbidden_owned_geph(_host, _port, _first_flight):
        evidence_before_geph.append(
            set(tproxy._local_zero_payload_failures.get(host) or {})
        )
        raise AssertionError("a timeout cannot authorize owned Geph")

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.62", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", failed_system)
    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", timed_out_xbox)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", local_dns)
    monkeypatch.setattr(tproxy, "strategy_order", lambda _host: strategies)
    monkeypatch.setattr(tproxy, "dial_strategy", timed_out_local)
    monkeypatch.setattr(tproxy, "dial_via_geph", forbidden_owned_geph)
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: None)
    monkeypatch.setattr(
        tproxy,
        "_schedule_auto_geph_confirmation_before_relay",
        lambda actual_host, **_kwargs: confirmations.append(actual_host) or True,
    )
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == b""
    assert not tproxy._auto_geph_learned_exact_host(host)
    assert confirmations == []
    assert evidence_before_geph == []
    assert local_attempts == list(tproxy.GENERAL_STRATS)
    assert host not in tproxy._local_zero_payload_failures
    assert host not in tproxy._dead


def test_unknown_first_server_payload_forbids_route_replay(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "healthy-system-route.example"
    response = b"\x16\x03\x03\x00\x60" + (b"S" * 96)
    client, _expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()

    async def healthy_system(_ip, _port, _first_flight, **_kwargs):
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

    async def short_system(_ip, _port, _first_flight, **_kwargs):
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
            kwargs["probe_ip"],
            kwargs["strategy_name"],
            kwargs["repeat_claimed"],
            kwargs["repeat_probe_ip"],
        ))
        return False

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.64", 443))
    monkeypatch.setattr(
        tproxy,
        "_claim_server_first_repeat_stage",
        lambda _host: (tproxy.AUTO_GEPH_STAGE_SYSTEM, "1.1.1.1"),
    )
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
    (
        actual_host,
        stage,
        server_ended_first,
        downstream_bytes,
        duration,
        probe_ip,
        strategy_name,
        repeat_claimed,
        repeat_probe_ip,
    ) = observations[0]
    assert actual_host == host
    assert stage == tproxy.AUTO_GEPH_STAGE_SYSTEM
    assert server_ended_first
    assert downstream_bytes == len(response)
    assert duration >= 0
    assert probe_ip == "203.0.113.64"
    assert strategy_name == "plain"
    assert repeat_claimed
    assert repeat_probe_ip == "1.1.1.1"


def test_system_plain_route_runs_held_preflight_before_committing(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "regional-denial-contract.example"
    response = b"\x17\x03\x03\x00\x60" + (b"S" * 96)
    client, _expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    preflights = []

    async def short_system(_ip, _port, _first_flight, **_kwargs):
        return (
            tproxy.SYSTEM_PROBE_PAYLOAD,
            probed_upstream_response(response),
        )

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("1.1.1.1", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", short_system)
    async def healthy_direct_preflight(actual_host, ip, **_kwargs):
        preflights.append((actual_host, ip))
        return None

    monkeypatch.setattr(tproxy, "_run_initial_route_preflight", healthy_direct_preflight)
    monkeypatch.setattr(
        tproxy,
        "_schedule_semantic_plain_denial_probe",
        lambda *_args, **_kwargs: pytest.fail(
            "held preflight replaced the post-commit semantic probe"
        ),
    )

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert preflights == [(host, "1.1.1.1")]
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_expired_direct_stream_enters_local_recovery_without_geph(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "slow-established-direct.example"
    response = b"eventual direct TLS payload"
    client, _expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    exact_writer = CaptureWriter()

    async def slow_system(_ip, _port, _first_flight, **_kwargs):
        return (
            tproxy.SYSTEM_PROBE_TIMEOUT,
            (ScriptedReader(stream=(response,)), exact_writer, b""),
        )

    async def inconclusive_preflight(*_args, **_kwargs):
        return None

    async def forbidden_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("1.1.1.1", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", slow_system)
    monkeypatch.setattr(
        tproxy,
        "_run_initial_route_preflight",
        inconclusive_preflight,
    )
    monkeypatch.setattr(tproxy, "_try_unknown_owned_geph_route", forbidden_geph)

    async def local_route(*_args, **_kwargs):
        assert exact_writer.closed
        return "8.8.8.8", probed_upstream_response(response)
    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", local_route)
    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_strict_preflight_switches_the_same_first_request_to_owned_geph(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    host = "same-request-semantic-switch.example"
    direct_response = b"direct regional denial"
    recovered_response = b"owned Geph usable payload"
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    exact_writer = CaptureWriter()
    exact_started = asyncio.Event()
    preflight_started = asyncio.Event()
    handoffs = []

    async def held_system(_ip, _port, _first_flight, **_kwargs):
        exact_started.set()
        await preflight_started.wait()
        return (
            tproxy.SYSTEM_PROBE_PAYLOAD,
            (
                ScriptedReader(),
                exact_writer,
                direct_response,
            ),
        )

    async def strict_preflight(actual_host, ip, **kwargs):
        preflight_started.set()
        await exact_started.wait()
        assert actual_host == host
        assert ip == "1.1.1.1"
        deadline_delta = (
            kwargs["deadline_monotonic"]
            - kwargs["local_recovery_deadline_monotonic"]
        )
        assert deadline_delta == pytest.approx(
            tproxy.UNKNOWN_RECOVERY_SEMANTIC_HANDOFF_TIMEOUT
            - tproxy.UNKNOWN_RECOVERY_TOTAL_TIMEOUT,
            abs=0.1,
        )
        return tproxy._RoutePreflightOwnedGephClaim(
            marker=tproxy._ROUTE_PREFLIGHT_OWNED_GEPH_CLAIM,
            capability="a" * 32,
            host=host,
            deadline_monotonic=kwargs["deadline_monotonic"],
        )

    async def owned_handoff(
        actual_host,
        port,
        first_flight,
        _reader,
        client_writer,
        *,
        successor_claim=None,
        deadline_monotonic=None,
    ):
        handoffs.append(
            (
                actual_host,
                port,
                first_flight,
                successor_claim,
                deadline_monotonic,
            )
        )
        client_writer.write(recovered_response)
        await client_writer.drain()
        return True

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("1.1.1.1", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", held_system)
    monkeypatch.setattr(tproxy, "_run_initial_route_preflight", strict_preflight)
    monkeypatch.setattr(tproxy, "_try_unknown_owned_geph_route", owned_handoff)

    asyncio.run(run_handler(client, writer))

    assert exact_writer.closed
    assert bytes(writer.payload) == recovered_response
    assert direct_response not in bytes(writer.payload)
    assert len(handoffs) == 1
    assert handoffs[0][0:3] == (host, 443, expected_first_flight)
    assert isinstance(handoffs[0][3], tproxy._RoutePreflightOwnedGephClaim)
    assert handoffs[0][4] == handoffs[0][3].deadline_monotonic


def test_handler_dispatches_bound_request_only_race_result(monkeypatch):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(1000.0)
    monkeypatch.setattr(tproxy, "time", clock)
    host = "request-only-handler-branch.example"
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    client_writer = CaptureWriter()
    exact_writer = CaptureWriter()
    race_exact = (
        ScriptedReader(block_when_empty=True),
        exact_writer,
        b"",
    )
    recovered = b"request-only Geph response"
    seen = []

    async def request_only_race(
        actual_host,
        exact_address,
        port,
        first_flight,
        **kwargs,
    ):
        assert actual_host == host
        assert exact_address == "8.8.8.8"
        assert port == 443
        assert first_flight == expected_first_flight
        claim = request_only_geph_claim(
            host,
            capability="4" * 32,
            exact_address=exact_address,
            eligible_after_monotonic=(
                kwargs["hard_recovery_deadline_monotonic"]
            ),
            deadline_monotonic=(
                kwargs["semantic_handoff_deadline_monotonic"]
            ),
        )
        return tproxy.SYSTEM_PROBE_TIMEOUT, race_exact, claim

    async def request_only_handoff(
        actual_host,
        exact_address,
        port,
        first_flight,
        _reader,
        writer,
        *,
        held_exact,
        claim,
        eligible_after_monotonic,
        deadline_monotonic,
    ):
        seen.append((actual_host, exact_address, port, first_flight, claim))
        assert held_exact is race_exact
        assert eligible_after_monotonic == claim.eligible_after_monotonic
        assert deadline_monotonic == claim.deadline_monotonic
        held_exact[1].close()
        writer.write(recovered)
        return tproxy._RequestOnlyRouteResult(
            tproxy._RequestOnlyRouteOutcome.GEPH_HANDLED
        )

    async def forbidden_generic(*_args, **_kwargs):
        raise AssertionError("request-only branch cannot enter generic Geph")

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("8.8.8.8", 443))
    monkeypatch.setattr(
        tproxy,
        "_run_unknown_initial_route_race",
        request_only_race,
    )
    monkeypatch.setattr(
        tproxy,
        "_try_request_only_tls_stall_geph_route",
        request_only_handoff,
    )
    monkeypatch.setattr(
        tproxy,
        "_try_unknown_owned_geph_route",
        forbidden_generic,
    )

    asyncio.run(run_handler(client, client_writer))

    assert len(seen) == 1
    assert seen[0][0:4] == (
        host,
        "8.8.8.8",
        443,
        expected_first_flight,
    )
    assert isinstance(seen[0][4], tproxy._RoutePreflightRequestOnlyGephClaim)
    assert exact_writer.closed
    assert bytes(client_writer.payload) == recovered


def test_handler_resumes_same_held_exact_after_request_only_declines(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    clock = MutableTproxyClock(1100.0)
    monkeypatch.setattr(tproxy, "time", clock)
    host = "request-only-handler-exact.example"
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    client_writer = CaptureWriter()
    exact_writer = CaptureWriter()
    direct_response = b"\x17\x03\x03\x00\x08direct!!"
    race_exact = (
        ScriptedReader(stream=(direct_response[7:],)),
        exact_writer,
        direct_response[:7],
    )
    seen = []

    async def request_only_race(
        actual_host,
        exact_address,
        port,
        first_flight,
        **kwargs,
    ):
        assert actual_host == host
        assert exact_address == "8.8.4.4"
        assert port == 443
        assert first_flight == expected_first_flight
        claim = request_only_geph_claim(
            host,
            capability="5" * 32,
            exact_address=exact_address,
            eligible_after_monotonic=(
                kwargs["hard_recovery_deadline_monotonic"]
            ),
            deadline_monotonic=(
                kwargs["semantic_handoff_deadline_monotonic"]
            ),
        )
        return tproxy.SYSTEM_PROBE_TIMEOUT, race_exact, claim

    async def request_only_handoff(
        actual_host,
        exact_address,
        port,
        first_flight,
        _reader,
        writer,
        *,
        held_exact,
        claim,
        eligible_after_monotonic,
        deadline_monotonic,
    ):
        seen.append((actual_host, exact_address, port, first_flight, claim))
        assert writer is client_writer
        assert held_exact is race_exact
        assert not held_exact[1].closed
        assert eligible_after_monotonic == claim.eligible_after_monotonic
        assert deadline_monotonic == claim.deadline_monotonic
        return tproxy._RequestOnlyRouteResult(
            tproxy._RequestOnlyRouteOutcome.EXACT,
            held_exact,
        )

    async def forbidden_fallback(*_args, **_kwargs):
        raise AssertionError(
            "held request-only exact stream cannot enter another route"
        )

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("8.8.4.4", 443))
    monkeypatch.setattr(
        tproxy,
        "_run_unknown_initial_route_race",
        request_only_race,
    )
    monkeypatch.setattr(
        tproxy,
        "_try_request_only_tls_stall_geph_route",
        request_only_handoff,
    )
    monkeypatch.setattr(
        tproxy,
        "_try_unknown_owned_geph_route",
        forbidden_fallback,
    )
    monkeypatch.setattr(
        tproxy,
        "_try_xbox_dns_local_connect",
        forbidden_fallback,
    )
    monkeypatch.setattr(tproxy, "resolve_connection_ips", forbidden_fallback)
    monkeypatch.setattr(tproxy, "dial_strategy", forbidden_fallback)

    asyncio.run(run_handler(client, client_writer))

    assert len(seen) == 1
    assert seen[0][0:4] == (
        host,
        "8.8.4.4",
        443,
        expected_first_flight,
    )
    assert isinstance(seen[0][4], tproxy._RoutePreflightRequestOnlyGephClaim)
    assert bytes(client_writer.payload) == direct_response
    assert exact_writer.closed
    assert host not in tproxy._route_preflight_cache
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_hard_preflight_failure_continues_local_recovery_same_request(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    host = "hard-preflight-close.example"
    direct_response = b"discarded direct TLS bytes"
    recovered_response = b"Xbox DNS local recovery payload"
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    exact_writer = CaptureWriter()
    calls = []

    async def short_system(_ip, _port, _first_flight, **_kwargs):
        first_size = min(16, len(direct_response))
        return (
            tproxy.SYSTEM_PROBE_PAYLOAD,
            (
                ScriptedReader(stream=(direct_response[first_size:],)),
                exact_writer,
                direct_response[:first_size],
            ),
        )

    async def hard_preflight(actual_host, ip, **kwargs):
        calls.append(("preflight", actual_host, ip))
        return tproxy._local_recovery_preflight_claim(
            actual_host,
            kwargs["local_recovery_deadline_monotonic"],
        )

    async def healthy_xbox(actual_host, port, head, body, **_kwargs):
        calls.append(("xbox", actual_host, port, head + body))
        return "198.51.100.31", probed_upstream_response(recovered_response)

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.31", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", short_system)
    monkeypatch.setattr(tproxy, "_run_initial_route_preflight", hard_preflight)
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
        ("preflight", host, "203.0.113.31"),
        ("xbox", host, 443, expected_first_flight),
    ]
    assert exact_writer.closed
    assert bytes(writer.payload) == recovered_response
    assert direct_response not in bytes(writer.payload)


def test_hard_local_recovery_requires_three_parallel_closed_stages(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "parallel-hard-proof.example"
    strategies = tuple(
        tproxy.STRAT_BY_NAME[name]
        for name in tproxy.GENERAL_STRATS[:2]
    )
    entered = 0
    peak = 0
    release = asyncio.Event()
    lock = asyncio.Lock()

    async def enter_stage():
        nonlocal entered, peak
        async with lock:
            entered += 1
            peak = max(peak, entered)
            if entered == 3:
                release.set()
        await release.wait()

    async def closed_xbox(
        _host,
        _port,
        _head,
        _body,
        *,
        attempt_summary=None,
        timeout_ms=None,
    ):
        assert timeout_ms > 0
        await enter_stage()
        attempt_summary["attempted"] = 1
        attempt_summary["outcomes"] = {
            "198.51.100.80": tproxy.ROUTE_PROBE_CLOSED,
        }
        return None

    race_index = 0

    async def closed_race(
        _host,
        _port,
        _addresses,
        _dial_candidate,
        *,
        attempt_outcomes=None,
        timeout_ms=None,
        **_kwargs,
    ):
        nonlocal race_index
        assert timeout_ms > 0
        race_index += 1
        await enter_stage()
        attempt_outcomes[f"198.51.100.8{race_index}"] = (
            tproxy.ROUTE_PROBE_CLOSED
        )
        return None, 1

    async def local_dns(_host, _fallback):
        return ["198.51.100.81"]

    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", closed_xbox)
    monkeypatch.setattr(tproxy, "_race_probe_addresses", closed_race)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", local_dns)
    monkeypatch.setattr(
        tproxy,
        "_strategy_order_for_attempt",
        lambda *_args: strategies,
    )

    result = asyncio.run(
        tproxy._try_hard_local_recovery(
            host,
            "203.0.113.80",
            443,
            b"head",
            b"body",
            deadline_monotonic=time.monotonic() + 8.0,
        )
    )

    assert peak == 3
    assert result.raced is None
    assert result.proof_complete
    assert set(tproxy._local_zero_payload_failures[host]) == {
        tproxy.AUTO_GEPH_STAGE_SYSTEM,
        tproxy.AUTO_GEPH_STAGE_XBOX_DNS,
        *(f"strategy:{strategy['name']}" for strategy in strategies),
    }
    assert tproxy._auto_geph_learning_candidate_proven(host)


def test_hard_local_recovery_local_payload_cancels_other_stages(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "parallel-local-winner.example"
    response = b"local winner"
    strategies = tuple(
        tproxy.STRAT_BY_NAME[name]
        for name in tproxy.GENERAL_STRATS[:2]
    )
    cancelled = 0

    async def healthy_xbox(*_args, attempt_summary=None, **_kwargs):
        await asyncio.sleep(0)
        return "198.51.100.90", probed_upstream_response(response)

    async def blocked_race(*_args, **_kwargs):
        nonlocal cancelled
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled += 1
            raise

    async def local_dns(_host, _fallback):
        return ["198.51.100.91"]

    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", healthy_xbox)
    monkeypatch.setattr(tproxy, "_race_probe_addresses", blocked_race)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", local_dns)
    monkeypatch.setattr(
        tproxy,
        "_strategy_order_for_attempt",
        lambda *_args: strategies,
    )

    result = asyncio.run(
        tproxy._try_hard_local_recovery(
            host,
            "203.0.113.90",
            443,
            b"head",
            b"body",
            deadline_monotonic=time.monotonic() + 8.0,
        )
    )

    assert result.raced is not None
    assert result.via_xbox_dns
    assert not result.proof_complete
    assert cancelled == 2
    assert host not in tproxy._local_zero_payload_failures
    assert not tproxy._auto_geph_learning_candidate_proven(host)


def test_hard_local_recovery_keeps_shared_resolver_alive_after_local_winner(
    monkeypatch,
):
    isolate_runtime_state(monkeypatch)
    host = "parallel-resolver-owner.example"
    strategies = tuple(
        tproxy.STRAT_BY_NAME[name]
        for name in tproxy.GENERAL_STRATS[:2]
    )
    resolver_release = asyncio.Event()
    resolver_cancelled = False

    async def healthy_xbox(*_args, **_kwargs):
        return "198.51.100.92", probed_upstream_response(b"local winner")

    async def local_dns(_host, _fallback):
        nonlocal resolver_cancelled
        try:
            await resolver_release.wait()
        except asyncio.CancelledError:
            resolver_cancelled = True
            raise
        return ["198.51.100.93"]

    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", healthy_xbox)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", local_dns)
    monkeypatch.setattr(
        tproxy,
        "_strategy_order_for_attempt",
        lambda *_args: strategies,
    )

    async def scenario():
        result = await tproxy._try_hard_local_recovery(
            host,
            "203.0.113.92",
            443,
            b"head",
            b"body",
            deadline_monotonic=time.monotonic() + 8.0,
        )
        assert not resolver_cancelled
        resolver_release.set()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return result

    result = asyncio.run(scenario())

    assert result.raced is not None
    assert result.via_xbox_dns
    assert not resolver_cancelled


def test_hard_local_recovery_closes_simultaneous_losing_payloads(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "parallel-multiple-winners.example"
    strategies = tuple(
        tproxy.STRAT_BY_NAME[name]
        for name in tproxy.GENERAL_STRATS[:2]
    )
    entered = 0
    release = asyncio.Event()
    upstreams = []

    async def enter_stage():
        nonlocal entered
        entered += 1
        if entered == 3:
            release.set()
        await release.wait()

    def response(label):
        upstream = probed_upstream_response(label)
        upstreams.append(upstream)
        return upstream

    async def healthy_xbox(*_args, **_kwargs):
        await enter_stage()
        return "198.51.100.94", response(b"xbox")

    async def healthy_race(*_args, **_kwargs):
        await enter_stage()
        index = len(upstreams) + 95
        return (f"198.51.100.{index}", response(b"strategy")), 1

    async def local_dns(_host, _fallback):
        return ["198.51.100.95"]

    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", healthy_xbox)
    monkeypatch.setattr(tproxy, "_race_probe_addresses", healthy_race)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", local_dns)
    monkeypatch.setattr(
        tproxy,
        "_strategy_order_for_attempt",
        lambda *_args: strategies,
    )

    result = asyncio.run(
        tproxy._try_hard_local_recovery(
            host,
            "203.0.113.94",
            443,
            b"head",
            b"body",
            deadline_monotonic=time.monotonic() + 8.0,
        )
    )

    assert result.raced is not None
    assert result.via_xbox_dns
    winner_writer = result.raced[1][1]
    assert len(upstreams) == 3
    assert not winner_writer.closed
    assert sum(upstream[1].closed for upstream in upstreams) == 2


@pytest.mark.parametrize(
    "unclear_outcome",
    (
        tproxy.ROUTE_PROBE_TIMEOUT,
        tproxy.ROUTE_PROBE_PENDING,
        tproxy.ROUTE_PROBE_FAILED,
    ),
)
def test_hard_local_recovery_unclear_stage_never_publishes_proof(
    monkeypatch,
    unclear_outcome,
):
    isolate_runtime_state(monkeypatch)
    host = f"parallel-unclear-{unclear_outcome}.example"
    strategies = tuple(
        tproxy.STRAT_BY_NAME[name]
        for name in tproxy.GENERAL_STRATS[:2]
    )

    async def closed_xbox(
        *_args,
        attempt_summary=None,
        **_kwargs,
    ):
        attempt_summary["attempted"] = 1
        attempt_summary["outcomes"] = {
            "198.51.100.100": tproxy.ROUTE_PROBE_CLOSED,
        }
        return None

    race_index = 0

    async def mixed_race(*_args, attempt_outcomes=None, **_kwargs):
        nonlocal race_index
        race_index += 1
        attempt_outcomes[f"198.51.100.10{race_index}"] = (
            unclear_outcome if race_index == 1 else tproxy.ROUTE_PROBE_CLOSED
        )
        return None, 1

    async def local_dns(_host, _fallback):
        return ["198.51.100.101"]

    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", closed_xbox)
    monkeypatch.setattr(tproxy, "_race_probe_addresses", mixed_race)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", local_dns)
    monkeypatch.setattr(
        tproxy,
        "_strategy_order_for_attempt",
        lambda *_args: strategies,
    )

    result = asyncio.run(
        tproxy._try_hard_local_recovery(
            host,
            "203.0.113.100",
            443,
            b"head",
            b"body",
            deadline_monotonic=time.monotonic() + 8.0,
        )
    )

    assert not result.proof_complete
    assert host not in tproxy._local_zero_payload_failures
    assert not tproxy._auto_geph_learning_candidate_proven(host)


def test_unknown_slow_system_route_is_committed_without_replay(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "slow-system-route.example"
    response = b"\x16\x03\x03\x00\x60" + (b"S" * 96)
    client, _expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()

    async def pending_system(_ip, _port, _first_flight, **_kwargs):
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


def test_unknown_handshake_only_idle_runs_correlated_browser_probe(monkeypatch):
    """A quiet TLS relay advances only after its local browser probe result."""
    isolate_runtime_state(monkeypatch)
    host = "idle-system-route.example"
    response = b"\x17\x03\x03\x00\x60" + (b"S" * 96)
    client, _expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    signal_times = []

    class Runtime:
        def __init__(self):
            self.jobs = []

        def enqueue(self, job, *, prioritize=False):
            self.jobs.append(job)
            return True

        def discard(self, _capability):
            return False

    class Worker:
        def notify_job_ready(self):
            return True

        def active(self):
            return True

    runtime = Runtime()
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_runtime", runtime)
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_worker", Worker())
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_available", True)
    tproxy._shutdown_started.clear()

    async def pending_system(_ip, _port, _first_flight, **_kwargs):
        return (
            tproxy.SYSTEM_PROBE_PENDING,
            (ScriptedReader(), CaptureWriter(), response),
        )

    async def healthy_direct_preflight(*_args, **_kwargs):
        return None

    async def handshake_idle(
        _reader,
        _up_w,
        _up_r,
        _writer,
        activity,
        **_kwargs,
    ):
        assert callable(activity.on_downstream_idle)
        assert activity.pending_navigation_eligible
        assert not activity.downstream_idle_retry
        assert not tproxy._xbox_dns_candidate_active(
            host,
            now=activity.last_downstream_at,
        )
        assert not tproxy._request_pending_navigation_retry(
            host,
            activity.pending_navigation_started_at_unix_ms,
            now=(
                activity.last_downstream_at
                + tproxy.UNKNOWN_PRE_RESPONSE_IDLE
                - 0.001
            ),
        )
        activity.last_downstream_at -= (
            tproxy.UNKNOWN_PRE_RESPONSE_IDLE + 0.001
        )
        assert activity.on_downstream_idle()
        assert len(runtime.jobs) == 1
        job = runtime.jobs[0]
        completion_now = (
            time.monotonic() + tproxy.UNKNOWN_PRE_RESPONSE_IDLE + 0.001
        )
        assert tproxy._submit_pending_navigation_probe_result(
            {
                "schema_version": 1,
                "capability": job["capability"],
                "host": job["host"],
                "request_started_at_unix_ms": job[
                    "request_started_at_unix_ms"
                ],
                "observed_at_unix_ms": (
                    job["issued_at_unix_ms"]
                    + int(tproxy.UNKNOWN_PRE_RESPONSE_IDLE * 1000)
                    + 1
                ),
                "outcome": tproxy.PENDING_NAVIGATION_PROBE_OUTCOME_PENDING,
            },
            now=completion_now,
        )
        signal_times.append(completion_now)
        assert activity.downstream_idle_retry
        return 0, 0

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("1.1.1.1", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", pending_system)
    monkeypatch.setattr(
        tproxy,
        "_run_initial_route_preflight",
        healthy_direct_preflight,
    )
    monkeypatch.setattr(tproxy, "relay_local_stream", handshake_idle)
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
    assert tproxy._xbox_dns_candidate_active(host, now=signal_times[0])
    assert not tproxy._auto_geph_learned_exact_host(host)


def test_unknown_client_first_body_abort_reaches_content_confirmation(monkeypatch):
    """A browser-side HTTP/2 body failure must survive relay cancellation."""
    isolate_runtime_state(monkeypatch)
    host = "partial-body-contract.example"
    payload = b"R" * 9000
    response = b"\x17\x03\x03" + len(payload).to_bytes(2, "big") + payload
    confirmations = []
    clean_eof_advances = []

    async def pending_system(_ip, _port, _first_flight, **_kwargs):
        return (
            tproxy.SYSTEM_PROBE_PENDING,
            (ScriptedReader(), CaptureWriter(), response),
        )

    async def healthy_direct_preflight(*_args, **_kwargs):
        return None

    async def client_first_abort(
        _reader,
        _up_w,
        _up_r,
        _writer,
        activity,
        **_kwargs,
    ):
        activity.client_eof = True
        activity.client_ended_first = True
        activity.client_end_at = activity.last_downstream_at + 0.1
        activity.server_end_at = activity.client_end_at + 0.1
        return 0, 0

    def schedule(candidate, ip, strategy, *, now):
        confirmations.append((candidate, ip, strategy, now))
        return True

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("1.1.1.1", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", pending_system)
    monkeypatch.setattr(
        tproxy,
        "_run_initial_route_preflight",
        healthy_direct_preflight,
    )
    monkeypatch.setattr(tproxy, "relay_local_stream", client_first_abort)
    monkeypatch.setattr(tproxy, "_clean_eof_stream_stalled", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        tproxy,
        "note_clean_eof_stream_stall",
        lambda *args, **kwargs: clean_eof_advances.append((args, kwargs)),
    )
    monkeypatch.setattr(
        tproxy,
        "_schedule_transport_incomplete_response_confirmation",
        schedule,
    )

    for _ in range(2):
        client, _first_flight = tls_client(host, block_after_hello=True)
        asyncio.run(run_handler(client, CaptureWriter()))

    assert len(confirmations) == 1
    assert confirmations[0][:3] == (host, "1.1.1.1", "plain")
    assert clean_eof_advances == []
    assert not tproxy._xbox_dns_candidate_active(host)
    assert not tproxy.is_geo_exit_route(host)


def test_unknown_partial_tls_watchdog_preserves_candidate_without_bypassing_ladder(
    monkeypatch,
):
    """A framed system-route stall preserves evidence but cannot authorize."""
    isolate_runtime_state(monkeypatch)
    host = "partial-record-contract.example"
    response = b"\x17\x03\x03\x00\x08" + b"R" * 8
    confirmations = []

    async def pending_system(_ip, _port, _first_flight, **_kwargs):
        return (
            tproxy.SYSTEM_PROBE_PENDING,
            (ScriptedReader(), CaptureWriter(), response),
        )

    async def healthy_direct_preflight(*_args, **_kwargs):
        return None

    async def partial_record_stall(
        _reader,
        _up_w,
        _up_r,
        _writer,
        activity,
        **_kwargs,
    ):
        activity.partial_tls_record_stalled = True
        activity.tls_complete_records = 1
        activity.tls_record_expected = 4096
        activity.tls_record_buffer = bytearray(b"partial")
        return 0, 0

    def schedule(candidate, ip, strategy, *, now, runner=None):
        confirmations.append((candidate, ip, strategy, now, runner))
        return True

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("1.1.1.1", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", pending_system)
    monkeypatch.setattr(
        tproxy,
        "_run_initial_route_preflight",
        healthy_direct_preflight,
    )
    monkeypatch.setattr(tproxy, "relay_local_stream", partial_record_stall)
    monkeypatch.setattr(
        tproxy,
        "_schedule_transport_incomplete_response_confirmation",
        schedule,
    )

    client, _first_flight = tls_client(host, block_after_hello=True)
    asyncio.run(run_handler(client, CaptureWriter()))

    assert confirmations == []
    assert tproxy._transport_incomplete_plain_candidates[host][0] == "1.1.1.1"
    assert not tproxy.is_geo_exit_route(host)


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


def test_youtube_media_server_first_close_reaches_only_local_recovery(monkeypatch):
    isolate_runtime_state(monkeypatch)
    host = "rr5---sn-test.googlevideo.com"
    destination_ip = "203.0.113.44"
    response = b"\x17\x03\x03\x00\x08" + b"a" * 8
    client, expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    observations = []

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
        assert strategy["name"] == "plain"
        return probed_upstream_response(response)

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    def observe(actual_host, strategy_name, activity, **kwargs):
        observations.append((actual_host, strategy_name, activity, kwargs))
        return True

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: (destination_ip, 443))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", one_address)
    monkeypatch.setattr(tproxy, "dial_strategy", local_route)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
    monkeypatch.setattr(
        tproxy,
        "note_protected_local_server_first_close",
        observe,
    )

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == response
    assert len(observations) == 1
    actual_host, strategy_name, activity, kwargs = observations[0]
    assert actual_host == host
    assert strategy_name == "plain"
    assert activity.server_ended_first
    assert activity.tls_complete_records == 1
    assert kwargs["duration"] >= 0
    assert not tproxy.is_geo_exit_route(host)


def test_youtube_medium_media_cuts_move_next_request_to_local_fallback(monkeypatch):
    original_observer = tproxy.note_protected_local_server_first_close
    isolate_runtime_state(monkeypatch)
    host = "rr5---sn-test.googlevideo.com"
    destination_ip = "203.0.113.45"
    record_payload = b"m" * (16 * 1024)
    record = (
        b"\x17\x03\x03"
        + len(record_payload).to_bytes(2, "big")
        + record_payload
    )
    response = record * 6
    calls = []
    observations = []
    runtime_results = []

    async def one_address(actual_host, fallback_ip):
        assert (actual_host, fallback_ip) == (host, destination_ip)
        return [destination_ip]

    async def local_route(ip, port, head, body, actual_host, strategy):
        assert (ip, port, actual_host) == (destination_ip, 443, host)
        assert head + body
        calls.append(strategy["name"])
        return probed_upstream_response(response)

    async def no_geph(*args, **kwargs):
        await forbidden_backend("Geph", *args, **kwargs)

    def observe(actual_host, strategy_name, activity, **kwargs):
        recovered = original_observer(
            actual_host,
            strategy_name,
            activity,
            **kwargs,
        )
        observations.append(
            (
                strategy_name,
                activity.server_ended_first,
                activity.client_ended_first,
                activity.downstream_bytes,
                activity.tls_framing_valid,
                activity.tls_complete_records,
                recovered,
            )
        )
        return recovered

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: (destination_ip, 443))
    monkeypatch.setattr(tproxy, "resolve_connection_ips", one_address)
    monkeypatch.setattr(tproxy, "dial_strategy", local_route)
    monkeypatch.setattr(tproxy, "dial_via_geph", no_geph)
    monkeypatch.setattr(
        tproxy,
        "note_local_bypass_runtime_result",
        lambda actual_host, ok, *args, **kwargs: runtime_results.append(
            (actual_host, ok, args, kwargs)
        ),
    )
    monkeypatch.setattr(
        tproxy,
        "note_protected_local_server_first_close",
        observe,
    )

    for _attempt in range(3):
        client, _expected_first_flight = tls_client(
            host,
            block_after_hello=True,
        )
        writer = CaptureWriter()
        asyncio.run(run_handler(client, writer))
        assert bytes(writer.payload) == response

    assert calls[:2] == ["plain", "plain"]
    assert calls[2] != "plain", observations
    assert runtime_results
    assert all(not ok for _host, ok, _args, _kwargs in runtime_results)
    assert tproxy._direct_first_local_fallback_active(host)
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
def test_learned_unknown_host_without_ready_owned_geph_fails_closed(
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

    assert bytes(writer.payload) == b""
    assert writer.closed is True
    assert calls == []


@pytest.mark.parametrize(
    "runtime_learned",
    [False, True],
    ids=["reviewed", "learned-exact-host"],
)
def test_reviewed_geo_exit_zero_payload_never_falls_back_to_direct(
    monkeypatch,
    runtime_learned,
):
    """A retained first flight may retry owned Geph, but not a known-bad route."""
    isolate_runtime_state(monkeypatch)
    host = "ws.chatgpt.com"
    client, expected_first_flight = tls_client(host, block_after_hello=False)
    writer = CaptureWriter()
    failures = []
    suspensions = []
    direct_calls = []
    response = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"

    async def empty_geph(actual_host, port, first_flight):
        assert (actual_host, port, first_flight) == (host, 443, expected_first_flight)
        return streaming_upstream_response(b"")

    async def system_route(ip, port, first_flight):
        assert (ip, port, first_flight) == (
            "203.0.113.18",
            443,
            expected_first_flight,
        )
        direct_calls.append(ip)
        return streaming_upstream_response(response)

    async def no_backend(name, *args, **kwargs):
        await forbidden_backend(name, *args, **kwargs)

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("203.0.113.18", 443))
    original_runtime_policy = tproxy.runtime_route_policy
    monkeypatch.setattr(
        tproxy,
        "runtime_route_policy",
        lambda actual_host: {
            **original_runtime_policy(actual_host),
            "runtime_learned": runtime_learned,
        },
    )
    monkeypatch.setattr(tproxy, "GEPH_ENABLED", True)
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_owned", True)
    monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
    monkeypatch.setattr(tproxy, "smart_dns_route_enabled", lambda _host: False)
    monkeypatch.setattr(tproxy, "dial_via_geph", empty_geph)
    monkeypatch.setattr(
        tproxy,
        "_coalesced_owned_geph_recovery_for_replay",
        lambda _host: asyncio.sleep(0, result=False),
    )
    monkeypatch.setattr(tproxy, "dial_strategy", lambda *args, **kwargs: no_backend("local desync", *args, **kwargs))
    monkeypatch.setattr(tproxy, "dial_plain", system_route)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", lambda *args, **kwargs: no_backend("generic DNS", *args, **kwargs))
    monkeypatch.setattr(tproxy, "log_geph_route_failure", lambda actual_host, reason: failures.append((actual_host, reason)))
    monkeypatch.setattr(tproxy, "clear_geph_route_failure", lambda: pytest.fail("empty payload must not clear failure"))
    monkeypatch.setattr(tproxy, "suspend_geo_exit_backend", suspensions.append)

    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == b""
    assert direct_calls == []
    assert failures == [(host, "remote closed without response")]
    assert suspensions == ["geo-exit first payload unavailable"]


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

    async def failed_direct(_ip, _port, _first_flight, **_kwargs):
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


@pytest.mark.parametrize("stage", [
    tproxy.UNKNOWN_RECOVERY_XBOX_DNS,
    tproxy.UNKNOWN_RECOVERY_LOCAL_LADDER,
])
def test_failed_local_strategy_reenters_independent_preflight(monkeypatch, stage):
    isolate_runtime_state(monkeypatch)
    host = "regional-denial-contract.example"
    response = b"\x17\x03\x03\x00\x60" + (b"S" * 96)
    client, _expected_first_flight = tls_client(host, block_after_hello=True)
    writer = CaptureWriter()
    preflights = []
    local_attempts = []
    recovered = b"recovered local response"
    exact_writer = CaptureWriter()

    async def short_system(_ip, _port, _first_flight, **_kwargs):
        return (
            tproxy.SYSTEM_PROBE_PAYLOAD,
            (ScriptedReader(stream=()), exact_writer, response),
        )

    monkeypatch.setattr(tproxy, "orig_dst", lambda _sock: ("1.1.1.1", 443))
    monkeypatch.setattr(tproxy, "_try_exact_system_probe", short_system)
    async def healthy_direct_preflight(actual_host, ip, **_kwargs):
        preflights.append((actual_host, ip))
        return None

    monkeypatch.setattr(tproxy, "_run_initial_route_preflight", healthy_direct_preflight)
    monkeypatch.setattr(
        tproxy,
        "_schedule_semantic_plain_denial_probe",
        lambda *_args, **_kwargs: pytest.fail(
            "held preflight replaced the post-commit semantic probe"
        ),
    )

    monkeypatch.setattr(tproxy, "_unknown_recovery_stage_for_attempt",
                        lambda *_args: stage)
    tproxy._local_partial_stalls[host] = {"local:tlsrec": time.monotonic()}
    async def local_xbox(*_args, **_kwargs):
        assert stage == tproxy.UNKNOWN_RECOVERY_XBOX_DNS
        local_attempts.append("xbox")
        return "1.1.1.2", probed_upstream_response(recovered)

    async def local_strategy(*_args, **_kwargs):
        assert stage == tproxy.UNKNOWN_RECOVERY_LOCAL_LADDER
        local_attempts.append("strategy")
        return probed_upstream_response(recovered)

    async def addresses(*_args):
        return ["1.1.1.2"]

    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", local_xbox)
    monkeypatch.setattr(tproxy, "dial_strategy", local_strategy)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", addresses)
    asyncio.run(run_handler(client, writer))

    assert bytes(writer.payload) == recovered
    assert exact_writer.closed
    assert len(local_attempts) == 1
    assert preflights == [(host, "1.1.1.1")]
    assert not tproxy._auto_geph_learned_exact_host(host)


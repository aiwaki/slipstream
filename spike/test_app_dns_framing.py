"""Real HTTP response framing over memory, with no resolver connections."""

import http.client
import io
import socket
import struct
from types import SimpleNamespace

import pytest

import app_dns


def _packet(address="203.0.113.42", *, truncated=False):
    query = app_dns.build_a_query("example.com", 0x1234)
    flags = 0x8180 | (0x0200 if truncated else 0)
    return (
        struct.pack("!HHHHHH", 0x1234, flags, 1, 1, 0, 0) + query[12:]
        + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
        + socket.inet_aton(address)
    )


def _wire(packet, framing="length"):
    prefix = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
    if framing in ("length", "short"):
        size = len(packet) + (9 if framing == "short" else 0)
        return prefix + f"Content-Length: {size}\r\n\r\n".encode() + packet
    if framing in ("chunked", "unterminated_chunked"):
        terminal = b"0\r\n\r\n" if framing == "chunked" else b""
        return (prefix + b"Transfer-Encoding: chunked\r\n\r\n"
                + f"{len(packet):x}\r\n".encode() + packet + b"\r\n" + terminal)
    assert framing == "eof"
    return prefix + b"Connection: close\r\n\r\n" + packet


def _memory_connections(monkeypatch, wires):
    pending = list(wires)
    connections = []

    class Connection:
        def __init__(self, ip, name, timeout):
            assert pending, "unexpected extra resolver request"
            self.endpoint = (ip, name, timeout)
            self.closed = False
            self.read_limits = []
            raw = pending.pop(0)
            owner = self

            class Response(http.client.HTTPResponse):
                def read(self, amt=None):
                    owner.read_limits.append(amt)
                    assert amt == app_dns.APP_DOH_MAX_RESPONSE + 1
                    return super().read(amt)

            self.response = Response(SimpleNamespace(makefile=lambda *_: io.BytesIO(raw)))
            self.response.begin()
            connections.append(self)

        def request(self, method, path, *, body, headers):
            assert method == "POST" and path == "/dns-query"
            assert body == app_dns.build_a_query("example.com", 0x1234)
            assert headers == {
                "Accept": "application/dns-message", "Content-Type": "application/dns-message",
            }

        def getresponse(self):
            return self.response

        def close(self):
            self.closed = True
            self.response.close()

    monkeypatch.setattr(app_dns.secrets, "randbits", lambda _bits: 0x1234)
    monkeypatch.setattr(app_dns, "_DirectHttpsConnection", Connection)
    return connections, pending


def _assert_closed(connections):
    assert connections and all(item.closed and item.response.isclosed() for item in connections)
    assert all(item.read_limits == [app_dns.APP_DOH_MAX_RESPONSE + 1] for item in connections)


@pytest.mark.parametrize("fault", ("short", "tc"))
def test_endpoint_rejects_incomplete_http_or_truncated_dns(monkeypatch, fault):
    packet = _packet(truncated=fault == "tc")
    connections, pending = _memory_connections(
        monkeypatch, [_wire(packet, "short" if fault == "short" else "length")],
    )
    assert app_dns._query_endpoint("1.1.1.1", "cloudflare-dns.com", "example.com", 1.5) == []
    assert not pending
    _assert_closed(connections)


@pytest.mark.parametrize("framing", ("length", "chunked", "eof"))
def test_endpoint_accepts_complete_supported_http_framing(monkeypatch, framing):
    connections, pending = _memory_connections(monkeypatch, [_wire(_packet(), framing)])
    assert app_dns._query_endpoint("1.1.1.1", "cloudflare-dns.com", "example.com", 1.5) == ["203.0.113.42"]
    assert not pending
    _assert_closed(connections)


@pytest.mark.parametrize("fault", ("unterminated_chunked", "oversize"))
def test_endpoint_keeps_chunk_completion_and_size_guards(monkeypatch, fault):
    wire = (
        _wire(b"x" * (app_dns.APP_DOH_MAX_RESPONSE + 1))
        if fault == "oversize" else _wire(_packet(), fault)
    )
    connections, _ = _memory_connections(monkeypatch, [wire])
    assert app_dns._query_endpoint("1.1.1.1", "cloudflare-dns.com", "example.com", 1.5) == []
    _assert_closed(connections)


@pytest.mark.parametrize("fault", ("short", "tc"))
def test_rejected_provider_answer_never_enters_positive_cache(monkeypatch, fault):
    first = _wire(_packet("203.0.113.11", truncated=fault == "tc"),
                  "short" if fault == "short" else "length")
    connections, pending = _memory_connections(monkeypatch, [first, _wire(_packet())])
    monkeypatch.setattr(app_dns, "_cache", app_dns.OrderedDict())
    monkeypatch.setattr(app_dns.time, "monotonic", lambda: 100.0)
    assert app_dns.resolve("Example.COM.", timeout=1.5) == ["203.0.113.42"]
    assert app_dns.resolve("example.com", timeout=1.5) == ["203.0.113.42"]
    assert [item.endpoint for item in connections] == [
        ("1.1.1.1", "cloudflare-dns.com", 1.5), ("8.8.8.8", "dns.google", 1.5),
    ]
    assert app_dns._cache["example.com"] == (("203.0.113.42",), 400.0)
    assert not pending
    _assert_closed(connections)


def test_two_incomplete_answers_keep_existing_negative_cache(monkeypatch):
    connections, pending = _memory_connections(
        monkeypatch, [_wire(_packet(), "short"), _wire(_packet(truncated=True))],
    )
    monkeypatch.setattr(app_dns, "_cache", app_dns.OrderedDict())
    monkeypatch.setattr(app_dns.time, "monotonic", lambda: 100.0)
    assert app_dns.resolve("example.com") == []
    assert app_dns.resolve("example.com") == []
    assert len(connections) == 2 and not pending
    assert app_dns._cache["example.com"] == ((), 130.0)
    _assert_closed(connections)

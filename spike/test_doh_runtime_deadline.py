"""Resolver endpoint failure must not break fallback or hold a pool worker."""
from collections import OrderedDict
import ssl
from types import SimpleNamespace

import tproxy


def test_doh_connect_error_is_an_endpoint_failure(monkeypatch):
    def connect(*args, **kwargs):
        raise OSError("unreachable resolver")
    monkeypatch.setattr(tproxy.socket, "create_connection", connect)
    assert tproxy._doh_query("1.1.1.1", "cloudflare-dns.com", "example.com") is None


class Tls:
    def __init__(self, incoming):
        self.incoming = incoming
    def do_handshake(self): pass
    def write(self, data): return len(data)
    def read(self, size):
        data = self.incoming.read(size)
        if not data:
            raise ssl.SSLWantReadError()
        return data


class Context:
    def wrap_bio(self, incoming, outgoing, **kwargs):
        return Tls(incoming)


class Socket:
    def __init__(self, chunks, clock):
        self.chunks = list(chunks)
        self.clock = clock
        self.closed = False
        self.timeout = 3
    def settimeout(self, timeout): self.timeout = timeout
    def setsockopt(self, *args): pass
    def recv(self, size):
        if not self.chunks: return b""
        if self.timeout < 1:
            self.clock.now += self.timeout
            raise TimeoutError("synthetic timeout")
        self.clock.now += 1
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]
    def close(self): self.closed = True


def configure(monkeypatch, chunks):
    clock = SimpleNamespace(now=100.0)
    sock = Socket(chunks, clock)
    monkeypatch.setattr(tproxy, "time", SimpleNamespace(monotonic=lambda: clock.now))
    monkeypatch.setattr(tproxy, "_doh_ssl_context", Context)
    monkeypatch.setattr(tproxy.socket, "create_connection", lambda *a, **kw: sock)
    return clock, sock


def test_doh_slow_reply_has_total_deadline(monkeypatch):
    clock, sock = configure(monkeypatch, [b" "] * 8 + [b'{"Answer":[{"type":1,"data":"93.184.216.34"}]}'])
    assert tproxy._doh_query("1.1.1.1", "cloudflare-dns.com", "example.com", 3) is None
    assert clock.now <= 103
    assert sock.closed


def test_doh_response_size_is_bounded(monkeypatch):
    _clock, sock = configure(monkeypatch, [b" " * 100_000, b'{"Answer":[{"type":1,"data":"93.184.216.34"}]}'])
    assert tproxy._doh_query("1.1.1.1", "cloudflare-dns.com", "example.com", 30) is None
    assert sock.closed


def test_doh_resolver_continues_after_first_connect_error(monkeypatch):
    _clock, sock = configure(monkeypatch, [b'{"Answer":[{"type":1,"data":"93.184.216.34"}]}'])
    endpoints = [("1.1.1.1", "cloudflare-dns.com"), ("8.8.8.8", "dns.google")]
    calls = []
    def connect(address, **kwargs):
        calls.append(address)
        if address[0] == "1.1.1.1":
            raise OSError("first resolver unavailable")
        return sock
    monkeypatch.setattr(tproxy, "DOH", endpoints)
    monkeypatch.setattr(tproxy, "_doh_cache", OrderedDict())
    monkeypatch.setattr(tproxy.socket, "create_connection", connect)
    assert tproxy.doh_resolve("example.com") == ["93.184.216.34"]
    assert calls == [("1.1.1.1", 443), ("8.8.8.8", 443)]
    assert sock.closed

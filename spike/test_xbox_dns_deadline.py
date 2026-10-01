"""No-network checks for the optional absolute-budget DoH path."""

import ssl
import struct
import threading

import pytest

import xbox_dns


class Clock:
    now = 100.0

    def __call__(self):
        return self.now


class PlainBioTls:
    """Exercise the real bounded stream, with deterministic TLS BIO operations."""

    def __init__(self, incoming, outgoing):
        self.incoming = incoming
        self.outgoing = outgoing

    def do_handshake(self):
        return None

    def write(self, data):
        return self.outgoing.write(data)

    def read(self, size):
        if self.incoming.pending or self.incoming.eof:
            return self.incoming.read(size)
        raise ssl.SSLWantReadError()


class Context:
    def __init__(self):
        self.calls = []

    def wrap_bio(self, incoming, outgoing, **kwargs):
        self.calls.append(kwargs)
        return PlainBioTls(incoming, outgoing)


class RawSocket:
    def __init__(self, clock, chunks=(), *, connect_cost=0, connect_error=False,
                 send_cost=0, recv_cost=0, cancel_on=None, event=None):
        self.clock = clock
        self.chunks = list(chunks)
        self.connect_cost = connect_cost
        self.connect_error = connect_error
        self.send_cost = send_cost
        self.recv_cost = recv_cost
        self.cancel_on = cancel_on
        self.event = event
        self.timeouts = []
        self.addresses = []
        self.sent = b""
        self.closed = 0
        self.recv_count = 0

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def _advance(self, cost, phase):
        self.clock.now += cost
        if self.cancel_on == phase:
            self.event.set()

    def connect(self, address):
        self.addresses.append(address)
        self._advance(self.connect_cost, "connect")
        if self.connect_error:
            raise OSError("simulated connect failure")

    def send(self, data):
        self.sent += bytes(data)
        self._advance(self.send_cost, "send")
        return len(data)

    def recv(self, size):
        self.recv_count += 1
        self._advance(self.recv_cost, "recv")
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]

    def close(self):
        self.closed += 1


def dns_packet():
    query = xbox_dns.build_a_query("example.com", 0x1234)
    return (
        struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        + query[12:] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
        + b"\xcb\x00\x71\x2a"
    )


def response(body=None, *, status=b"200 OK", headers=None):
    body = dns_packet() if body is None else body
    headers = (
        b"Content-Type: application/dns-message\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        if headers is None else headers
    )
    return b"HTTP/1.1 " + status + b"\r\n" + headers + b"\r\n" + body


@pytest.fixture
def harness(monkeypatch):
    clock = Clock()
    context = Context()
    sockets = []
    calls = []
    monkeypatch.setattr(xbox_dns.time, "monotonic", clock)
    monkeypatch.setattr(xbox_dns, "_tls_context", lambda: context)
    monkeypatch.setattr(xbox_dns.secrets, "randbits", lambda bits: 0x1234)
    monkeypatch.setattr(xbox_dns, "_cache", xbox_dns.OrderedDict())

    def socket_factory(family, kind):
        calls.append((family, kind))
        if not sockets:
            pytest.fail("unexpected socket or extra endpoint attempt")
        return sockets.pop(0)

    monkeypatch.setattr(xbox_dns.socket, "socket", socket_factory)
    monkeypatch.setattr(
        xbox_dns.socket, "getaddrinfo",
        lambda *a, **kw: pytest.fail("bounded path must not use system DNS"),
    )
    return clock, context, sockets, calls


def test_shared_deadline_shrinks_across_endpoints_and_each_real_stream_io(harness):
    clock, context, sockets, calls = harness
    message = response()
    boundary = message.index(b"\r\n\r\n") + 4
    first = RawSocket(clock, connect_cost=2, connect_error=True)
    second = RawSocket(clock, [message[:boundary], message[boundary:]],
                       connect_cost=1, send_cost=1, recv_cost=1)
    sockets.extend([first, second])

    assert xbox_dns.resolve("Example.COM.", timeout=8, deadline=1000) == ["203.0.113.42"]
    assert first.timeouts == [8]
    assert second.timeouts == [6, 5, 4, 3]
    assert first.addresses == [("111.88.96.50", 443)]
    assert second.addresses == [("111.88.96.51", 443)]
    assert context.calls == [{"server_side": False, "server_hostname": "xbox-dns.ru"}]
    assert calls == [(xbox_dns.socket.AF_INET, xbox_dns.socket.SOCK_STREAM)] * 2
    assert second.sent.startswith(b"POST /dns-query HTTP/1.1\r\nHost: xbox-dns.ru\r\n")
    assert second.sent.endswith(xbox_dns.build_a_query("example.com", 0x1234))
    assert first.closed == second.closed == 1
    assert xbox_dns.resolve("example.com", timeout=8, deadline=110) == ["203.0.113.42"]
    assert len(calls) == 2


def test_caller_deadline_wins_over_timeout_and_does_not_start_next_endpoint(harness):
    clock, _context, sockets, _calls = harness
    first = RawSocket(clock, connect_cost=2, connect_error=True)
    sockets.append(first)

    assert xbox_dns.resolve("example.com", timeout=8, deadline=102) == []
    assert first.timeouts == [2]
    assert first.closed == 1
    assert not xbox_dns._cache


@pytest.mark.parametrize("phase", ["connect", "send", "recv"])
def test_cancellation_stops_subsequent_io_and_does_not_cache(harness, phase):
    clock, _context, sockets, _calls = harness
    event = threading.Event()
    first = RawSocket(clock, [response()], cancel_on=phase, event=event)
    sockets.append(first)

    assert xbox_dns.resolve("example.com", timeout=8, deadline=110, cancel_event=event) == []
    assert first.closed == 1
    assert not xbox_dns._cache
    if phase == "connect":
        assert not first.sent
    if phase != "recv":
        assert first.recv_count == 0


@pytest.mark.parametrize("cancelled", [True, False])
def test_inactive_lookup_does_not_return_cached_success_or_open_socket(harness, cancelled):
    clock, _context, _sockets, calls = harness
    event = threading.Event()
    if cancelled:
        event.set()
    xbox_dns._cache["example.com"] = (("203.0.113.42",), 200)
    before = xbox_dns._cache.copy()

    assert xbox_dns.resolve("example.com", deadline=110 if cancelled else 100,
                            cancel_event=event) == []
    assert not calls
    assert xbox_dns._cache == before


def test_cancel_only_path_has_one_timeout_budget(harness):
    clock, _context, sockets, _calls = harness
    first = RawSocket(clock, connect_cost=3, connect_error=True)
    sockets.append(first)

    assert xbox_dns.resolve("example.com", cancel_event=threading.Event()) == []
    assert first.timeouts == [xbox_dns.XBOX_DOH_TIMEOUT]
    assert not xbox_dns._cache


def test_dripping_response_cannot_renew_deadline(harness):
    clock, _context, sockets, _calls = harness
    first = RawSocket(clock, [bytes([byte]) for byte in response()], recv_cost=1)
    sockets.append(first)

    assert xbox_dns.resolve("example.com", timeout=3, deadline=110) == []
    assert first.recv_count == 3
    assert first.timeouts == [3, 3, 3, 2, 1]
    assert first.closed == 1
    assert not xbox_dns._cache


def test_complete_chunked_body_is_decoded_only_once(harness, monkeypatch):
    clock, _context, sockets, _calls = harness
    packet = dns_packet()
    message = response(
        f"{len(packet):x}\r\n".encode() + packet + b"\r\n0\r\n\r\n",
        headers=b"Content-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n",
    )
    first = RawSocket(clock, [message[:90], message[90:]])
    sockets.append(first)
    decode = xbox_dns.http_response_completion.http_response_body
    decoded = []

    def record_decode(*args, **kwargs):
        decoded.append(args[0])
        return decode(*args, **kwargs)

    monkeypatch.setattr(xbox_dns.http_response_completion, "http_response_body", record_decode)
    assert xbox_dns.resolve("example.com", deadline=110) == ["203.0.113.42"]
    assert decoded == [message]
    assert first.closed == 1


@pytest.mark.parametrize("message", [
    response(status=b"302 Found"),
    response(headers=b"Content-Type: text/html\r\nContent-Length: 45\r\n"),
    response(headers=b"Content-Type: x-application/dns-message\r\nContent-Length: 45\r\n"),
    response(headers=b"Content-Type: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: 45\r\n"),
    response(headers=b"Content-Type: application/dns-message\r\nContent-Encoding: gzip\r\nContent-Length: 45\r\n"),
    response(headers=b"Content-Type: application/dns-message\r\n"),
    response()[:-1],
    response() + b"extra",
    response(headers=b"Content-Type: application/dns-message\r\nContent-Length: 45\r\nTransfer-Encoding: chunked\r\n"),
    response(b"3\r\nabc\r\n", headers=b"Content-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n"),
    response(headers=b"Content-Type: application/dns-message\r\nInvalid header\r\nContent-Length: 45\r\n"),
    response(dns_packet()[:2] + bytes([dns_packet()[2] | 0x02]) + dns_packet()[3:]),
])
def test_rejects_unusable_http_or_dns_response_and_closes_both_endpoints(harness, message):
    clock, _context, sockets, calls = harness
    first = RawSocket(clock, [message])
    second = RawSocket(clock, [message])
    sockets.extend([first, second])

    assert xbox_dns.resolve("example.com", deadline=110) == []
    assert first.closed == second.closed == 1
    assert len(calls) == 2


@pytest.mark.parametrize("oversized_headers", [False, True])
def test_response_limits_fail_closed_without_unbounded_read(harness, monkeypatch, oversized_headers):
    clock, _context, sockets, _calls = harness
    monkeypatch.setattr(xbox_dns, "XBOX_DOH_MAX_RESPONSE", 48)
    monkeypatch.setattr(xbox_dns, "XBOX_DOH_MAX_HEADERS", 128)
    message = (
        b"HTTP/1.1 200 OK\r\nX-Pad: " + b"x" * 200
        if oversized_headers else response(b"x" * 49)
    )
    first = RawSocket(clock, [message])
    second = RawSocket(clock, [message])
    sockets.extend([first, second])

    assert xbox_dns.resolve("example.com", deadline=110) == []
    assert first.closed == second.closed == 1
    assert first.recv_count == second.recv_count == 1


@pytest.mark.parametrize("timeout,deadline", [
    (0, 110), (-1, 110), (float("inf"), 110),
    (3, float("nan")), (3, float("inf")), (None, 110),
])
def test_invalid_budget_is_inert(harness, timeout, deadline):
    _clock, _context, _sockets, calls = harness
    assert xbox_dns.resolve("example.com", timeout=timeout, deadline=deadline) == []
    assert not calls
    assert not xbox_dns._cache


def test_tls_constructor_failure_closes_raw_socket(harness, monkeypatch):
    clock, context, sockets, _calls = harness
    first = RawSocket(clock)
    second = RawSocket(clock)
    sockets.extend([first, second])

    def fail(*args, **kwargs):
        raise ValueError("simulated TLS constructor failure")

    monkeypatch.setattr(context, "wrap_bio", fail)
    assert xbox_dns.resolve("example.com", deadline=110) == []
    assert first.closed == second.closed == 1

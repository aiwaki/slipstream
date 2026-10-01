"""Socket-free, clock-controlled tests of measured encrypted TLS ingress."""

from collections import deque
import ssl
import threading

import pytest

from bootstrap_tls_stream import BootstrapTlsStream


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class RawSocket:
    def __init__(self, clock, incoming=(), *, write_limit=65536, write_cost=0.0):
        self.clock = clock
        self.incoming = deque(incoming)
        self.write_limit = write_limit
        self.write_cost = write_cost
        self.sent = []
        self.read_timeouts = []
        self.write_timeouts = []
        self.timeout = None
        self.close_count = 0
        self.after_send = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def send(self, data):
        self.write_timeouts.append(self.timeout)
        if self.write_cost > self.timeout:
            self.clock.now += self.timeout
            raise TimeoutError("synthetic write timeout")
        self.clock.now += self.write_cost
        sent = bytes(data[:self.write_limit])
        self.sent.append(sent)
        if self.after_send is not None:
            self.after_send()
        return len(sent)

    def recv(self, _size):
        self.read_timeouts.append(self.timeout)
        if not self.incoming or self.incoming[0][0] > self.timeout:
            self.clock.now += self.timeout
            raise TimeoutError("synthetic receive timeout")
        delay, result = self.incoming.popleft()
        self.clock.now += delay
        if isinstance(result, BaseException):
            raise result
        return result

    def close(self):
        self.close_count += 1


class ScriptedTls:
    def __init__(self, incoming, outgoing):
        self.incoming = incoming
        self.outgoing = outgoing
        self.handshake_actions = deque()
        self.read_actions = deque()
        self.write_actions = deque()
        self.write_limit = 65536

    def _action(self, actions, default):
        value = actions.popleft() if actions else default
        if callable(value):
            value = value(self)
        if isinstance(value, BaseException):
            raise value
        return value

    def do_handshake(self):
        return self._action(self.handshake_actions, None)

    def read(self, _size):
        return self._action(self.read_actions, ssl.SSLWantReadError())

    def write(self, cleartext):
        if self.write_actions:
            return self._action(self.write_actions, None)
        written = min(len(cleartext), self.write_limit)
        self.outgoing.write(b"encrypted:" + bytes(cleartext[:written]))
        return written


class Context:
    def wrap_bio(self, incoming, outgoing, *, server_side, server_hostname):
        self.server_side = server_side
        self.server_hostname = server_hostname
        self.tls = ScriptedTls(incoming, outgoing)
        return self.tls


def stream_fixture(*, incoming=(), deadline=120.0, **kwargs):
    clock = Clock()
    raw = RawSocket(clock, incoming)
    context = Context()
    stream = BootstrapTlsStream(
        raw, context, "synthetic.example", deadline, monotonic=clock, **kwargs,
    )
    return stream, raw, context.tls, clock


def emit_then_raise(payload, exception):
    def action(tls):
        tls.outgoing.write(payload)
        raise exception
    return action


def test_encrypted_fragments_keep_single_plaintext_read_alive_beyond_idle_window():
    stream, raw, tls, clock = stream_fixture(
        incoming=[(2.0, b"fragment")] * 4,
    )
    tls.read_actions.extend([ssl.SSLWantReadError()] * 4 + [b"complete plaintext"])
    assert stream.recv(1024) == b"complete plaintext"
    assert clock.now == 108.0
    assert raw.read_timeouts == [6.0] * 4
    assert stream.wire_bytes_measured is True
    assert stream.wire_bytes == 32
    assert stream.wire_idle_seconds == 0.0


def test_continuous_encrypted_progress_still_hits_absolute_deadline_not_wire_idle():
    stream, raw, tls, clock = stream_fixture(
        incoming=[(2.0, b"fragment")] * 4, deadline=107.0,
    )
    tls.read_actions.extend([ssl.SSLWantReadError()] * 4)
    with pytest.raises(TimeoutError):
        stream.recv(1024)
    assert clock.now == 107.0
    assert raw.read_timeouts == [6.0, 5.0, 3.0, 1.0]
    assert stream.wire_bytes == 24
    assert stream.wire_idle_seconds == 1.0
    with pytest.raises(TimeoutError):
        stream.recv(1024)
    assert len(raw.read_timeouts) == 4


def test_true_wire_silence_expires_six_seconds_after_last_encrypted_fragment():
    stream, raw, _tls, clock = stream_fixture(incoming=[(2.0, b"partial record")])
    with pytest.raises(TimeoutError):
        stream.recv(1024)
    assert clock.now == 108.0
    assert raw.read_timeouts == [6.0, 6.0]
    assert stream.wire_idle_seconds == 6.0
    assert stream.wire_bytes == len(b"partial record")


def test_request_send_resets_response_idle_only_after_all_ciphertext_is_sent():
    stream, raw, tls, clock = stream_fixture(deadline=130.0)
    raw.write_limit = 2
    raw.write_cost = 0.25
    tls.write_limit = 2
    clock.now = 105.0
    stream.sendall(b"request")
    sent_at = clock.now
    assert sent_at > 106.0
    assert stream.wire_bytes == 0
    assert stream.wire_idle_seconds == 0.0
    assert b"".join(raw.sent) == b"encrypted:reencrypted:quencrypted:esencrypted:t"
    assert all(timeout > 0 for timeout in raw.write_timeouts)
    with pytest.raises(TimeoutError):
        stream.recv(1024)
    assert clock.now == sent_at + 6.0
    assert raw.read_timeouts == [6.0]


def test_first_clienthello_flight_only_is_transformed_and_callback_discarded():
    transformed = []

    def transform(data):
        transformed.append(data)
        return b"split:" + data

    stream, raw, tls, _clock = stream_fixture(
        incoming=[(0.25, b"server handshake")], first_flight_transform=transform,
    )
    raw.write_limit = 3
    tls.handshake_actions.extend([
        emit_then_raise(b"clienthello", ssl.SSLWantWriteError()),
        emit_then_raise(b"client handshake continuation", ssl.SSLWantReadError()),
        None,
    ])
    stream.do_handshake()
    stream.sendall(b"request")
    assert transformed == [b"clienthello"]
    assert stream._first_flight_transform is None
    assert b"".join(raw.sent) == (
        b"split:clienthelloclient handshake continuationencrypted:request"
    )
    assert stream.wire_bytes == len(b"server handshake")


@pytest.mark.parametrize("operation", ("handshake", "send", "recv"))
def test_ssl_want_write_flushes_handshake_request_and_read_control_records(operation):
    stream, raw, tls, _clock = stream_fixture()
    retry = emit_then_raise(b"control", ssl.SSLWantWriteError())
    if operation == "handshake":
        tls.handshake_actions.extend([retry, None])
        stream.do_handshake()
    elif operation == "send":
        tls.write_actions.append(retry)
        stream.sendall(b"request")
    else:
        tls.read_actions.extend([retry, b"response"])
        assert stream.recv(1024) == b"response"
    assert b"".join(raw.sent).startswith(b"control")
    assert raw.read_timeouts == []


def test_ssl_want_read_while_sending_consumes_encrypted_input_before_retry():
    stream, raw, tls, _clock = stream_fixture(incoming=[(0.1, b"key update")])
    tls.write_actions.append(ssl.SSLWantReadError())
    stream.sendall(b"request")
    assert stream.wire_bytes == len(b"key update")
    assert b"".join(raw.sent) == b"encrypted:request"
    assert stream.wire_idle_seconds == 0.0


@pytest.mark.parametrize("operation", ("handshake", "send", "recv"))
def test_wire_eof_terminates_without_read_loop(operation):
    stream, raw, tls, _clock = stream_fixture(incoming=[(0.1, b"")])
    if operation == "handshake":
        tls.handshake_actions.extend([ssl.SSLWantReadError()] * 2)
        with pytest.raises(ssl.SSLEOFError):
            stream.do_handshake()
    elif operation == "send":
        tls.write_actions.extend([ssl.SSLWantReadError()] * 2)
        with pytest.raises(ssl.SSLEOFError):
            stream.sendall(b"request")
    else:
        assert stream.recv(1024) == b""
        assert stream.recv(1024) == b""
    assert len(raw.read_timeouts) == 1
    assert stream.wire_bytes == 0


@pytest.mark.parametrize("eof", (ssl.SSLZeroReturnError(), ssl.SSLEOFError()))
def test_tls_close_or_truncated_record_maps_to_receive_eof(eof):
    stream, raw, tls, _clock = stream_fixture()
    tls.read_actions.append(eof)
    assert stream.recv(1024) == b""
    assert raw.read_timeouts == []


@pytest.mark.parametrize("operation", ("handshake", "send", "recv"))
def test_cancelled_stream_starts_no_new_tls_or_socket_operation(operation):
    cancelled = threading.Event()
    stream, raw, tls, _clock = stream_fixture(cancel_event=cancelled)
    tls.handshake_actions.append(lambda _tls: pytest.fail("cancelled TLS was driven"))
    cancelled.set()
    with pytest.raises(InterruptedError):
        if operation == "handshake":
            stream.do_handshake()
        elif operation == "send":
            stream.sendall(b"request")
        else:
            stream.recv(1024)
    assert raw.read_timeouts == raw.write_timeouts == []


def test_cancel_after_partial_write_prevents_the_next_socket_send():
    cancelled = threading.Event()
    stream, raw, _tls, _clock = stream_fixture(cancel_event=cancelled)
    raw.write_limit = 1
    raw.after_send = cancelled.set
    with pytest.raises(InterruptedError):
        stream.sendall(b"request")
    assert raw.sent == [b"e"]
    assert raw.read_timeouts == []


def test_cancel_after_wire_progress_prevents_the_next_receive():
    cancelled = threading.Event()
    stream, raw, tls, _clock = stream_fixture(
        incoming=[(0.1, b"fragment")], cancel_event=cancelled,
    )

    def cancel_then_read(_tls):
        cancelled.set()
        raise ssl.SSLWantReadError()

    tls.read_actions.extend([ssl.SSLWantReadError(), cancel_then_read])
    with pytest.raises(InterruptedError):
        stream.recv(1024)
    assert stream.wire_bytes == 8
    assert len(raw.read_timeouts) == 1


def test_real_sslcontext_hostname_and_certificate_policy_is_preserved():
    clock = Clock()
    raw = RawSocket(clock, [(0.1, b"HTTP/1.0 400 Bad Request\r\n\r\n")])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    before = (context.check_hostname, context.verify_mode, context.minimum_version)
    stream = BootstrapTlsStream(raw, context, "synthetic.example", 120.0, monotonic=clock)
    assert stream._tls.server_hostname == "synthetic.example"
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    with pytest.raises(ssl.SSLError):
        stream.do_handshake()
    assert before == (context.check_hostname, context.verify_mode, context.minimum_version)
    assert b"synthetic.example" in b"".join(raw.sent)
    stream.close()


def test_certificate_verification_failure_is_not_converted_to_eof_or_success():
    stream, _raw, tls, _clock = stream_fixture()
    tls.handshake_actions.append(ssl.SSLCertVerificationError("synthetic mismatch"))
    with pytest.raises(ssl.SSLCertVerificationError):
        stream.do_handshake()


def test_settimeout_is_only_a_ceiling_and_does_not_reset_wire_idle():
    stream, raw, _tls, clock = stream_fixture()
    clock.now = 105.0
    stream.settimeout(20.0)
    with pytest.raises(TimeoutError):
        stream.recv(1024)
    assert raw.read_timeouts == [1.0]
    assert stream.wire_idle_seconds == 6.0


def test_close_is_idempotent_and_does_not_perform_tls_network_cleanup():
    stream, raw, _tls, _clock = stream_fixture()
    stream.close()
    stream.close()
    assert raw.close_count == 1
    assert raw.sent == raw.read_timeouts == []
    with pytest.raises(OSError):
        stream.recv(1024)


def test_zero_length_receive_starts_no_socket_io():
    stream, raw, _tls, _clock = stream_fixture()
    assert stream.recv(0) == b""
    assert raw.sent == raw.read_timeouts == []


@pytest.mark.parametrize("zero_write", ("raw", "tls"))
def test_zero_progress_write_fails_closed(zero_write):
    stream, raw, tls, _clock = stream_fixture()
    if zero_write == "raw":
        raw.write_limit = 0
    else:
        tls.write_actions.append(0)
    with pytest.raises(OSError):
        stream.sendall(b"request")


def test_raw_reset_is_not_swallowed_as_plaintext_completion():
    stream, _raw, _tls, _clock = stream_fixture(
        incoming=[(0.1, ConnectionResetError("synthetic reset"))],
    )
    with pytest.raises(ConnectionResetError):
        stream.recv(1024)


def test_first_flight_transform_rejects_empty_output_without_sending():
    stream, raw, tls, _clock = stream_fixture(first_flight_transform=lambda _data: b"")
    tls.handshake_actions.append(emit_then_raise(b"clienthello", ssl.SSLWantReadError()))
    with pytest.raises(ValueError):
        stream.do_handshake()
    assert raw.sent == []

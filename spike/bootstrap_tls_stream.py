"""One bounded TLS stream with encrypted-ingress measurement and no route state."""

import math
import ssl
import time


class BootstrapTlsStream:
    """Drive the supplied validating SSLContext on one already-connected socket."""

    wire_bytes_measured = True

    def __init__(
        self, raw_socket, context, host, deadline_monotonic, *,
        idle_timeout=6.0, first_flight_transform=None, monotonic=time.monotonic,
        cancel_event=None,
    ):
        self._deadline = float(deadline_monotonic)
        self._idle_timeout = float(idle_timeout)
        if not math.isfinite(self._deadline) or not (
            math.isfinite(self._idle_timeout) and self._idle_timeout > 0
        ):
            raise ValueError("invalid bootstrap TLS time budget")
        self._raw_socket = raw_socket
        self._monotonic = monotonic
        self._cancel_event = cancel_event
        self._timeout = None
        self._wire_bytes = 0
        self._wire_idle_origin = monotonic()
        self._wire_eof = False
        self._closed = False
        self._initial_flight_sent = False
        self._first_flight_transform = first_flight_transform
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._tls = context.wrap_bio(
            self._incoming, self._outgoing,
            server_side=False, server_hostname=host,
        )

    @property
    def wire_bytes(self):
        return self._wire_bytes

    @property
    def wire_idle_seconds(self):
        return max(0.0, self._monotonic() - self._wire_idle_origin)

    def settimeout(self, timeout):
        """Apply an optional caller ceiling without renewing either deadline."""
        if timeout is not None:
            timeout = float(timeout)
            if not math.isfinite(timeout) or timeout < 0:
                raise ValueError("invalid bootstrap TLS socket timeout")
        self._timeout = timeout

    def _check_active(self):
        if self._closed:
            raise OSError("bootstrap TLS stream is closed")
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise InterruptedError("bootstrap TLS cancelled")
        remaining = self._deadline - self._monotonic()
        if remaining <= 0:
            raise TimeoutError("bootstrap TLS deadline exceeded")
        return remaining

    def _prepare_io(self, *, receive=False):
        timeout = self._check_active()
        if receive:
            timeout = min(timeout, self._idle_timeout - self.wire_idle_seconds)
        if self._timeout is not None:
            timeout = min(timeout, self._timeout)
        if timeout <= 0:
            raise TimeoutError("bootstrap TLS receive budget exhausted")
        self._raw_socket.settimeout(timeout)

    def _flush_outgoing(self):
        flushed = 0
        while self._outgoing.pending:
            ciphertext = self._outgoing.read()
            first_flight = not self._initial_flight_sent
            if first_flight:
                transform = self._first_flight_transform
                self._first_flight_transform = None
                if transform is not None:
                    ciphertext = transform(ciphertext)
                    if not isinstance(ciphertext, bytes) or not ciphertext:
                        raise ValueError("invalid bootstrap TLS first flight")
            remaining = memoryview(ciphertext)
            while remaining:
                self._prepare_io()
                written = self._raw_socket.send(remaining)
                if written <= 0:
                    raise OSError("bootstrap TLS socket write made no progress")
                remaining = remaining[written:]
                flushed += written
            if first_flight:
                self._initial_flight_sent = True
                # Do not charge local ClientHello preparation against peer idle.
                self._wire_idle_origin = self._monotonic()
        return flushed

    def _receive_wire(self):
        if self._wire_eof:
            return
        self._prepare_io(receive=True)
        ciphertext = self._raw_socket.recv(65536)
        if ciphertext:
            self._wire_bytes += len(ciphertext)
            self._wire_idle_origin = self._monotonic()
            self._incoming.write(ciphertext)
        else:
            self._wire_eof = True
            self._incoming.write_eof()

    def do_handshake(self):
        while True:
            self._check_active()
            try:
                self._tls.do_handshake()
                self._flush_outgoing()
                return
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                if self._wire_eof:
                    raise ssl.SSLEOFError("EOF during bootstrap TLS handshake")
                self._receive_wire()
            except ssl.SSLWantWriteError:
                if not self._flush_outgoing():
                    raise ssl.SSLError("bootstrap TLS handshake made no progress")

    def sendall(self, cleartext):
        remaining = memoryview(cleartext)
        while remaining:
            self._check_active()
            try:
                written = self._tls.write(remaining)
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                if self._wire_eof:
                    raise ssl.SSLEOFError("EOF while writing bootstrap TLS request")
                self._receive_wire()
                continue
            except ssl.SSLWantWriteError:
                if not self._flush_outgoing():
                    raise ssl.SSLError("bootstrap TLS request made no progress")
                continue
            if written <= 0:
                raise OSError("bootstrap TLS request write made no progress")
            remaining = remaining[written:]
            self._flush_outgoing()
        self._check_active()
        self._flush_outgoing()
        # Request transmission is over: start the response idle window here.
        self._wire_idle_origin = self._monotonic()

    def recv(self, size):
        if size < 0:
            raise ValueError("negative bootstrap TLS receive size")
        if size == 0:
            self._check_active()
            return b""
        while True:
            self._check_active()
            try:
                cleartext = self._tls.read(size)
                self._flush_outgoing()
                return cleartext
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                if self._wire_eof:
                    return b""
                self._receive_wire()
            except ssl.SSLWantWriteError:
                if not self._flush_outgoing():
                    raise ssl.SSLError("bootstrap TLS receive made no progress")
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""

    def close(self):
        if not self._closed:
            self._closed = True
            self._first_flight_transform = None
            self._raw_socket.close()

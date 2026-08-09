"""Bounded HTTP/2 completion probes for exact routing evidence.

This module deliberately owns only one HTTP/2 stream on an already verified
TLS socket.  It does not resolve hosts, choose routes, or mutate routing state.
"""

from dataclasses import dataclass
import socket
import ssl
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import (
    DataReceived,
    InformationalResponseReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
    TrailersReceived,
)
from h2.exceptions import H2Error
from hyperframe.exceptions import HyperframeError
from hyperframe.frame import Frame, GoAwayFrame


@dataclass(frozen=True)
class Http2ProbeResult:
    status: int | None
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes
    complete: bool
    interrupted: bool
    truncated: bool
    protocol_error: bool

    @property
    def body_length(self):
        return len(self.body)

    @property
    def incomplete(self):
        """Whether a successful response stream is proven unfinished."""
        return bool(
            self.interrupted
            and not self.complete
            and not self.truncated
            and not self.protocol_error
            and self.status is not None
            and 200 <= self.status < 400
            and self.body
            and self.content_encoding_is_identity
        )

    @property
    def content_encoding_is_identity(self):
        values = [
            value.strip().lower()
            for name, value in self.headers
            if name.strip().lower() == b"content-encoding"
        ]
        return not values or all(value in {b"", b"identity"} for value in values)


def _status_from_headers(headers):
    for name, value in headers:
        if name == b":status":
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    return None


def _request_headers(host, *, bounded_range):
    authority = host.encode("idna")
    headers = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", authority),
        (b":path", b"/"),
        (b"user-agent", b"SlipstreamIncompleteResponse/1"),
        (b"accept", b"text/html,application/xhtml+xml"),
        (b"accept-encoding", b"identity"),
        (b"cache-control", b"no-cache"),
    ]
    if bounded_range:
        headers.append((b"range", b"bytes=0-262143"))
    return headers


def _pop_complete_frame(receive_buffer):
    """Pop one complete HTTP/2 frame while preserving partial socket reads."""
    if len(receive_buffer) < 9:
        return None
    frame, body_length = Frame.parse_frame_header(
        memoryview(bytes(receive_buffer[:9]))
    )
    frame_length = 9 + body_length
    if len(receive_buffer) < frame_length:
        return None
    raw_frame = bytes(receive_buffer[:frame_length])
    del receive_buffer[:frame_length]
    return frame, raw_frame


def _graceful_goaway_allows_stream(frame, raw_frame, stream_id):
    """Whether GOAWAY permits an already-open stream to finish normally."""
    frame.parse_body(memoryview(raw_frame[9:]))
    last_stream_id = frame.last_stream_id & 0x7FFFFFFF
    return bool(
        int(frame.error_code) == int(ErrorCodes.NO_ERROR)
        and last_stream_id >= stream_id
    )


def probe_http2_response(
    tls_socket,
    host,
    *,
    deadline,
    max_bytes,
    bounded_range,
    monotonic=None,
):
    """Read one HTTP/2 response without mistaking opaque TLS for completion."""
    clock = monotonic or time.monotonic
    connection = H2Connection(
        config=H2Configuration(client_side=True, header_encoding=None)
    )
    connection.initiate_connection()
    stream_id = connection.get_next_available_stream_id()
    connection.send_headers(
        stream_id,
        _request_headers(host, bounded_range=bounded_range),
        end_stream=True,
    )
    tls_socket.sendall(connection.data_to_send())

    status = None
    response_headers = ()
    body_chunks = []
    body_length = 0
    complete = False
    interrupted = False
    truncated = False
    protocol_error = False
    receive_buffer = bytearray()

    while not (
        complete or interrupted or truncated or protocol_error
    ):
        remaining = deadline - clock()
        if remaining <= 0:
            interrupted = True
            break
        tls_socket.settimeout(max(remaining, 0.001))
        try:
            data = tls_socket.recv(16384)
        except socket.timeout:
            interrupted = True
            break
        except (
            ConnectionResetError,
            ssl.SSLEOFError,
            ssl.SSLZeroReturnError,
        ):
            interrupted = True
            break
        except (ssl.SSLError, OSError):
            interrupted = True
            break
        if not data:
            interrupted = True
            break

        receive_buffer.extend(data)
        while not (
            complete or interrupted or truncated or protocol_error
        ):
            try:
                parsed_frame = _pop_complete_frame(receive_buffer)
            except HyperframeError:
                protocol_error = True
                break
            if parsed_frame is None:
                break
            frame, raw_frame = parsed_frame

            if isinstance(frame, GoAwayFrame):
                try:
                    stream_may_finish = _graceful_goaway_allows_stream(
                        frame,
                        raw_frame,
                        stream_id,
                    )
                except HyperframeError:
                    protocol_error = True
                    break
                if not stream_may_finish:
                    protocol_error = True
                    break
                # hyper-h2 closes its connection state immediately on GOAWAY,
                # although RFC 9113 permits eligible existing streams to
                # finish.  Keep its parser open for that stream.
                continue

            try:
                events = connection.receive_data(raw_frame)
            except H2Error:
                protocol_error = True
                break
            for event in events:
                if isinstance(
                    event,
                    (ResponseReceived, InformationalResponseReceived),
                ):
                    if event.stream_id == stream_id:
                        response_headers = tuple(event.headers)
                        parsed_status = _status_from_headers(response_headers)
                        if parsed_status is not None:
                            status = parsed_status
                elif isinstance(event, TrailersReceived):
                    if event.stream_id == stream_id:
                        response_headers += tuple(event.headers)
                elif isinstance(event, DataReceived):
                    connection.acknowledge_received_data(
                        event.flow_controlled_length,
                        event.stream_id,
                    )
                    if event.stream_id != stream_id:
                        continue
                    if body_length + len(event.data) > max_bytes:
                        truncated = True
                        break
                    body_chunks.append(event.data)
                    body_length += len(event.data)
                elif (
                    isinstance(event, StreamEnded)
                    and event.stream_id == stream_id
                ):
                    complete = True
                elif isinstance(event, StreamReset) and event.stream_id == stream_id:
                    interrupted = True

        pending = connection.data_to_send()
        if pending and not interrupted and not protocol_error:
            try:
                tls_socket.sendall(pending)
            except (ssl.SSLError, OSError):
                interrupted = True

    return Http2ProbeResult(
        status=status,
        headers=response_headers,
        body=b"".join(body_chunks),
        complete=complete,
        interrupted=interrupted,
        truncated=truncated,
        protocol_error=protocol_error,
    )

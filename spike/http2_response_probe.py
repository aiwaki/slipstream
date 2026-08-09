"""Bounded HTTP/2 completion probes for exact routing evidence.

This module deliberately owns only one HTTP/2 stream on an already verified
TLS socket.  It does not resolve hosts, choose routes, or mutate routing state.
"""

from dataclasses import dataclass
import re
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
from h2.settings import SettingCodes
from hyperframe.exceptions import HyperframeError
from hyperframe.frame import (
    ContinuationFrame,
    DataFrame,
    Frame,
    GoAwayFrame,
    HeadersFrame,
    PingFrame,
    PriorityFrame,
    PushPromiseFrame,
    RstStreamFrame,
    SettingsFrame,
    WindowUpdateFrame,
)


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


def _content_length_from_headers(headers):
    values = [
        value
        for name, value in headers
        if name.strip().lower() == b"content-length"
    ]
    if not values:
        return None
    if len(values) != 1 or not values[0] or not values[0].isdigit():
        raise ValueError("invalid HTTP/2 content-length")
    return int(values[0])


def _content_range_from_headers(headers):
    values = [
        value.strip().lower()
        for name, value in headers
        if name.strip().lower() == b"content-range"
    ]
    if not values:
        return None
    if len(values) != 1:
        raise ValueError("invalid HTTP/2 content-range")
    match = re.fullmatch(
        rb"bytes ([0-9]+)-([0-9]+)/([0-9]+|\*)",
        values[0],
    )
    if match is None:
        raise ValueError("invalid HTTP/2 content-range")
    start = int(match.group(1))
    end = int(match.group(2))
    total = None if match.group(3) == b"*" else int(match.group(3))
    if start != 0 or end < start or end > 262143:
        raise ValueError("unexpected HTTP/2 content-range")
    if total is not None and total <= end:
        raise ValueError("invalid HTTP/2 content-range total")
    return start, end, total


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


def _frame_header_is_valid(
    frame,
    body_length,
    *,
    active_stream_id,
    header_block_stream_id,
):
    connection_frames = (SettingsFrame, PingFrame, GoAwayFrame)
    stream_frames = (
        DataFrame,
        HeadersFrame,
        PriorityFrame,
        RstStreamFrame,
        PushPromiseFrame,
        ContinuationFrame,
    )
    if isinstance(frame, connection_frames) and frame.stream_id != 0:
        return False
    if isinstance(frame, stream_frames) and frame.stream_id == 0:
        return False
    if header_block_stream_id is not None:
        if not isinstance(frame, ContinuationFrame):
            return False
        if frame.stream_id != header_block_stream_id:
            return False
    elif isinstance(frame, ContinuationFrame):
        return False
    if isinstance(
        frame,
        (DataFrame, HeadersFrame, RstStreamFrame, ContinuationFrame),
    ) and frame.stream_id != active_stream_id:
        return False
    if isinstance(frame, WindowUpdateFrame) and frame.stream_id not in {
        0,
        active_stream_id,
    }:
        return False
    if isinstance(frame, PushPromiseFrame):
        return False
    if isinstance(frame, PriorityFrame):
        return body_length == 5
    if isinstance(frame, RstStreamFrame):
        return body_length == 4
    if isinstance(frame, SettingsFrame):
        if "ACK" in frame.flags:
            return body_length == 0
        return body_length % 6 == 0
    if isinstance(frame, PingFrame):
        return body_length == 8
    if isinstance(frame, GoAwayFrame):
        return body_length >= 8
    if isinstance(frame, WindowUpdateFrame):
        return body_length == 4
    if isinstance(frame, HeadersFrame):
        minimum = int("PADDED" in frame.flags) + 5 * int(
            "PRIORITY" in frame.flags
        )
        return body_length >= minimum
    if isinstance(frame, DataFrame) and "PADDED" in frame.flags:
        return body_length >= 1
    return True


def _available_frame_prefix_is_valid(
    frame,
    body_length,
    receive_buffer,
    *,
    active_stream_id,
    graceful_goaway_last_stream_id,
):
    """Reject disqualifying prefixes before the full frame is available."""
    if isinstance(frame, GoAwayFrame) and len(receive_buffer) >= 17:
        last_stream_id = (
            int.from_bytes(receive_buffer[9:13], "big") & 0x7FFFFFFF
        )
        error_code = int.from_bytes(receive_buffer[13:17], "big")
        if error_code != int(ErrorCodes.NO_ERROR):
            return False
        if last_stream_id < active_stream_id:
            return False
        if (
            graceful_goaway_last_stream_id is not None
            and last_stream_id > graceful_goaway_last_stream_id
        ):
            return False
    if "PADDED" not in frame.flags or not isinstance(
        frame,
        (DataFrame, HeadersFrame, PushPromiseFrame),
    ):
        return True
    if len(receive_buffer) < 10:
        return True
    fixed_prefix_length = 1
    if isinstance(frame, HeadersFrame) and "PRIORITY" in frame.flags:
        fixed_prefix_length += 5
    if isinstance(frame, PushPromiseFrame):
        fixed_prefix_length += 4
    padding_length = receive_buffer[9]
    return padding_length <= body_length - fixed_prefix_length


def _pop_complete_frame(
    receive_buffer,
    *,
    max_frame_size,
    active_stream_id,
    header_block_stream_id,
    graceful_goaway_last_stream_id,
):
    """Pop one complete HTTP/2 frame while preserving partial socket reads."""
    if len(receive_buffer) < 9:
        return None
    frame, body_length = Frame.parse_frame_header(
        memoryview(bytes(receive_buffer[:9]))
    )
    if body_length > max_frame_size:
        raise HyperframeError("frame payload exceeds local maximum")
    if not _frame_header_is_valid(
        frame,
        body_length,
        active_stream_id=active_stream_id,
        header_block_stream_id=header_block_stream_id,
    ):
        raise HyperframeError("invalid HTTP/2 frame header")
    if not _available_frame_prefix_is_valid(
        frame,
        body_length,
        receive_buffer,
        active_stream_id=active_stream_id,
        graceful_goaway_last_stream_id=graceful_goaway_last_stream_id,
    ):
        raise HyperframeError("invalid HTTP/2 frame prefix")
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
    connection.update_settings({SettingCodes.ENABLE_PUSH: 0})
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
    header_block_stream_id = None
    graceful_goaway_last_stream_id = None
    server_settings_received = False
    expected_content_length = None

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
        except ssl.SSLError:
            protocol_error = True
            break
        except OSError:
            protocol_error = True
            break
        if not data:
            interrupted = True
            break

        receive_buffer.extend(data)
        while not (
            complete or interrupted or truncated or protocol_error
        ):
            try:
                parsed_frame = _pop_complete_frame(
                    receive_buffer,
                    max_frame_size=connection.max_inbound_frame_size,
                    active_stream_id=stream_id,
                    header_block_stream_id=header_block_stream_id,
                    graceful_goaway_last_stream_id=(
                        graceful_goaway_last_stream_id
                    ),
                )
            except HyperframeError:
                protocol_error = True
                break
            if parsed_frame is None:
                break
            frame, raw_frame = parsed_frame

            if not server_settings_received:
                if (
                    not isinstance(frame, SettingsFrame)
                    or "ACK" in frame.flags
                ):
                    protocol_error = True
                    break
                server_settings_received = True

            if isinstance(frame, GoAwayFrame):
                if header_block_stream_id is not None:
                    protocol_error = True
                    break
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
                last_stream_id = frame.last_stream_id & 0x7FFFFFFF
                if (
                    graceful_goaway_last_stream_id is not None
                    and last_stream_id > graceful_goaway_last_stream_id
                ):
                    protocol_error = True
                    break
                # hyper-h2 closes its connection state immediately on GOAWAY,
                # although RFC 9113 permits eligible existing streams to
                # finish.  Keep its parser open for that stream.
                graceful_goaway_last_stream_id = last_stream_id
                continue

            if (
                graceful_goaway_last_stream_id is not None
                and isinstance(frame, PushPromiseFrame)
            ):
                protocol_error = True
                break

            try:
                events = connection.receive_data(raw_frame)
            except H2Error:
                protocol_error = True
                break
            if (
                isinstance(frame, (HeadersFrame, PushPromiseFrame))
                and "END_HEADERS" not in frame.flags
            ):
                header_block_stream_id = frame.stream_id
            elif (
                isinstance(frame, ContinuationFrame)
                and "END_HEADERS" in frame.flags
            ):
                header_block_stream_id = None
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
                        try:
                            expected_content_length = (
                                _content_length_from_headers(response_headers)
                            )
                            content_range = _content_range_from_headers(
                                response_headers
                            )
                        except ValueError:
                            protocol_error = True
                            break
                        if status == 206:
                            if not bounded_range or content_range is None:
                                protocol_error = True
                                break
                            range_length = content_range[1] - content_range[0] + 1
                            if (
                                expected_content_length is not None
                                and expected_content_length != range_length
                            ):
                                protocol_error = True
                                break
                            expected_content_length = range_length
                        elif content_range is not None:
                            protocol_error = True
                            break
                elif isinstance(event, TrailersReceived):
                    if event.stream_id == stream_id:
                        if any(
                            name.strip().lower() == b"content-length"
                            for name, _value in event.headers
                        ):
                            protocol_error = True
                            break
                        response_headers += tuple(event.headers)
                elif isinstance(event, DataReceived):
                    if status in {204, 205, 304}:
                        protocol_error = True
                        break
                    connection.acknowledge_received_data(
                        event.flow_controlled_length,
                        event.stream_id,
                    )
                    if event.stream_id != stream_id:
                        continue
                    if body_length + len(event.data) > max_bytes:
                        truncated = True
                        break
                    if (
                        expected_content_length is not None
                        and body_length + len(event.data)
                        > expected_content_length
                    ):
                        protocol_error = True
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
                protocol_error = True

    if interrupted and receive_buffer:
        interrupted = False
        protocol_error = True
    if body_length >= max_bytes and not complete:
        truncated = True
    if (
        complete
        and expected_content_length is not None
        and body_length != expected_content_length
    ):
        complete = False
        protocol_error = True

    return Http2ProbeResult(
        status=status,
        headers=response_headers,
        body=b"".join(body_chunks),
        complete=complete,
        interrupted=interrupted,
        truncated=truncated,
        protocol_error=protocol_error,
    )

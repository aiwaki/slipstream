from collections import deque
import ssl
import time

import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import RequestReceived
from hpack import Encoder
from hyperframe.frame import (
    ContinuationFrame,
    DataFrame,
    GoAwayFrame,
    HeadersFrame,
    PushPromiseFrame,
)

from http2_response_probe import probe_http2_response


class FakeHttp2ServerSocket:
    def __init__(
        self,
        *,
        status=200,
        body=b"response body",
        complete=True,
        content_encoding=b"identity",
        graceful_goaway=False,
        goaway_error_code=ErrorCodes.NO_ERROR,
        goaway_last_stream_id=None,
        goaway_last_stream_ids=None,
        protocol_error_after_body=False,
        goaway_during_headers=False,
        push_promise_after_goaway=False,
        recv_error_after_response=None,
        oversized_frame_header_after_body=False,
        goaway_before_settings=False,
        declared_content_length=None,
        invalid_stream_frame_header_after_body=False,
        idle_stream_frame_header_after_body=False,
        impossible_padding_after_body=False,
        orphan_continuation_header_after_body=False,
        invalid_ping_length_header_after_body=False,
        goaway_stream_id_after_body=None,
    ):
        self._server = H2Connection(
            config=H2Configuration(client_side=False, header_encoding=None)
        )
        self._server.initiate_connection()
        server_preface = self._server.data_to_send()
        if goaway_before_settings:
            goaway = GoAwayFrame(0)
            goaway.error_code = int(ErrorCodes.NO_ERROR)
            goaway.last_stream_id = 1
            server_preface = goaway.serialize() + server_preface
        self._chunks = deque([server_preface])
        self._status = status
        self._body = body
        self._complete = complete
        self._content_encoding = content_encoding
        self._graceful_goaway = graceful_goaway
        self._goaway_error_code = goaway_error_code
        self._goaway_last_stream_id = goaway_last_stream_id
        self._goaway_last_stream_ids = (
            None
            if goaway_last_stream_ids is None
            else tuple(goaway_last_stream_ids)
        )
        self._protocol_error_after_body = protocol_error_after_body
        self._goaway_during_headers = goaway_during_headers
        self._push_promise_after_goaway = push_promise_after_goaway
        self._recv_error_after_response = recv_error_after_response
        self._oversized_frame_header_after_body = oversized_frame_header_after_body
        self._declared_content_length = declared_content_length
        self._invalid_stream_frame_header_after_body = (
            invalid_stream_frame_header_after_body
        )
        self._idle_stream_frame_header_after_body = (
            idle_stream_frame_header_after_body
        )
        self._impossible_padding_after_body = impossible_padding_after_body
        self._orphan_continuation_header_after_body = (
            orphan_continuation_header_after_body
        )
        self._invalid_ping_length_header_after_body = (
            invalid_ping_length_header_after_body
        )
        self._goaway_stream_id_after_body = goaway_stream_id_after_body
        self.request_headers = ()
        self.closed = False

    def settimeout(self, _timeout):
        return None

    def sendall(self, data):
        for event in self._server.receive_data(data):
            if not isinstance(event, RequestReceived):
                continue
            self.request_headers = tuple(event.headers)
            response_headers = [
                (b":status", str(self._status).encode("ascii")),
                (b"content-type", b"text/html"),
                (b"content-encoding", self._content_encoding),
            ]
            if self._declared_content_length is not None:
                response_headers.append(
                    (
                        b"content-length",
                        str(self._declared_content_length).encode("ascii"),
                    )
                )
                headers = HeadersFrame(event.stream_id)
                headers.data = Encoder().encode(response_headers)
                headers.flags.add("END_HEADERS")
                response_data = DataFrame(event.stream_id)
                response_data.data = self._body
                if self._complete:
                    response_data.flags.add("END_STREAM")
                self._chunks.append(headers.serialize() + response_data.serialize())
                continue

            if self._goaway_during_headers:
                header_block = Encoder().encode(response_headers)
                split_at = max(1, len(header_block) // 2)
                headers = HeadersFrame(event.stream_id)
                headers.data = header_block[:split_at]
                goaway = GoAwayFrame(0)
                goaway.error_code = int(ErrorCodes.NO_ERROR)
                goaway.last_stream_id = event.stream_id
                continuation = ContinuationFrame(event.stream_id)
                continuation.data = header_block[split_at:]
                continuation.flags.add("END_HEADERS")
                response_data = DataFrame(event.stream_id)
                response_data.data = self._body
                self._chunks.append(
                    self._server.data_to_send()
                    + headers.serialize()
                    + goaway.serialize()
                    + continuation.serialize()
                    + response_data.serialize()
                )
                continue

            if self._push_promise_after_goaway:
                self._server.send_headers(event.stream_id, response_headers)
                self._server.send_data(
                    event.stream_id,
                    self._body,
                    end_stream=False,
                )
                goaway = GoAwayFrame(0)
                goaway.error_code = int(ErrorCodes.NO_ERROR)
                goaway.last_stream_id = event.stream_id
                push = PushPromiseFrame(event.stream_id)
                push.promised_stream_id = 2
                push.data = Encoder().encode(
                    [
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":authority", b"partial-response.example"),
                        (b":path", b"/pushed"),
                    ]
                )
                push.flags.add("END_HEADERS")
                self._chunks.append(
                    self._server.data_to_send()
                    + goaway.serialize()
                    + push.serialize()
                )
                continue

            self._server.send_headers(event.stream_id, response_headers)

            if self._graceful_goaway:
                split_at = max(1, len(self._body) // 2)
                self._server.send_data(
                    event.stream_id,
                    self._body[:split_at],
                    end_stream=False,
                )
                goaway_last_stream_ids = self._goaway_last_stream_ids or (
                    event.stream_id
                    if self._goaway_last_stream_id is None
                    else self._goaway_last_stream_id,
                )
                goaways = []
                for goaway_last_stream_id in goaway_last_stream_ids:
                    goaway = GoAwayFrame(0)
                    goaway.error_code = int(self._goaway_error_code)
                    goaway.last_stream_id = goaway_last_stream_id
                    goaways.append(goaway)
                self._chunks.append(
                    self._server.data_to_send()
                    + b"".join(goaway.serialize() for goaway in goaways)
                )
                if (
                    self._complete
                    and all(
                        goaway.error_code == int(ErrorCodes.NO_ERROR)
                        and goaway.last_stream_id >= event.stream_id
                        for goaway in goaways
                    )
                ):
                    self._server.send_data(
                        event.stream_id,
                        self._body[split_at:],
                        end_stream=True,
                    )
                    self._chunks.append(self._server.data_to_send())
                continue

            self._server.send_data(
                event.stream_id,
                self._body,
                end_stream=self._complete,
            )
            response = self._server.data_to_send()
            if self._protocol_error_after_body:
                invalid_data = DataFrame(event.stream_id + 2)
                invalid_data.data = b"invalid stream"
                response += invalid_data.serialize()
            if self._oversized_frame_header_after_body:
                response += (
                    (16385).to_bytes(3, "big")
                    + b"\x00\x00"
                    + event.stream_id.to_bytes(4, "big")
                )
            if self._invalid_stream_frame_header_after_body:
                response += (1).to_bytes(3, "big") + b"\x00\x00" + b"\x00" * 4
            if self._idle_stream_frame_header_after_body:
                response += (1).to_bytes(3, "big") + b"\x00\x00" + (3).to_bytes(
                    4,
                    "big",
                )
            if self._impossible_padding_after_body:
                response += (
                    (2).to_bytes(3, "big")
                    + b"\x00\x08"
                    + event.stream_id.to_bytes(4, "big")
                    + b"\x02"
                )
            if self._orphan_continuation_header_after_body:
                response += (
                    (1).to_bytes(3, "big")
                    + b"\x09\x00"
                    + event.stream_id.to_bytes(4, "big")
                )
            if self._invalid_ping_length_header_after_body:
                response += (7).to_bytes(3, "big") + b"\x06\x00" + b"\x00" * 4
            if self._goaway_stream_id_after_body is not None:
                response += (
                    (8).to_bytes(3, "big")
                    + b"\x07\x00"
                    + self._goaway_stream_id_after_body.to_bytes(4, "big")
                    + event.stream_id.to_bytes(4, "big")
                    + int(ErrorCodes.NO_ERROR).to_bytes(4, "big")
                )
            self._chunks.append(response)

    def recv(self, _size):
        if self._chunks:
            return self._chunks.popleft()
        if self._recv_error_after_response is not None:
            error = self._recv_error_after_response
            self._recv_error_after_response = None
            raise error
        return b""

    def close(self):
        self.closed = True


def _probe(sock, *, bounded_range=False, max_bytes=4096):
    return probe_http2_response(
        sock,
        "partial-response.example",
        deadline=time.monotonic() + 5,
        max_bytes=max_bytes,
        bounded_range=bounded_range,
    )


def test_complete_http2_stream_is_not_incomplete():
    sock = FakeHttp2ServerSocket(body=b"x" * 512, complete=True)

    result = _probe(sock)

    assert result.complete
    assert not result.incomplete
    assert result.status == 200
    assert result.body_length == 512


def test_interrupted_http2_stream_is_proven_incomplete():
    sock = FakeHttp2ServerSocket(body=b"x" * 512, complete=False)

    result = _probe(sock)

    assert not result.complete
    assert result.incomplete
    assert result.status == 200
    assert result.body_length == 512


def test_graceful_goaway_allows_eligible_stream_to_finish():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=True,
        graceful_goaway=True,
    )

    result = _probe(sock)

    assert result.complete
    assert not result.protocol_error
    assert not result.incomplete
    assert result.body_length == 512


def test_goaway_excluding_stream_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        graceful_goaway=True,
        goaway_last_stream_id=0,
    )

    result = _probe(sock)

    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_error_goaway_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        graceful_goaway=True,
        goaway_error_code=ErrorCodes.INTERNAL_ERROR,
    )

    result = _probe(sock)

    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_protocol_error_after_payload_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        protocol_error_after_body=True,
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_oversized_frame_header_after_payload_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        oversized_frame_header_after_body=True,
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_invalid_stream_id_header_after_payload_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        invalid_stream_frame_header_after_body=True,
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_idle_stream_header_after_payload_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        idle_stream_frame_header_after_body=True,
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_impossible_padding_after_payload_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        impossible_padding_after_body=True,
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_orphan_continuation_header_after_payload_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        orphan_continuation_header_after_body=True,
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_invalid_fixed_frame_length_after_payload_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        invalid_ping_length_header_after_body=True,
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_goaway_on_nonzero_stream_after_payload_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        goaway_stream_id_after_body=1,
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_tls_protocol_error_after_payload_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        recv_error_after_response=ssl.SSLError("bad record mac"),
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_generic_receive_error_after_payload_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        recv_error_after_response=OSError("bad file descriptor"),
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_body_exceeding_declared_content_length_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 64,
        complete=False,
        declared_content_length=32,
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_goaway_during_header_block_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        goaway_during_headers=True,
    )

    result = _probe(sock)

    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_goaway_before_server_settings_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        goaway_before_settings=True,
    )

    result = _probe(sock)

    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_new_push_promise_after_goaway_is_unknown():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        push_promise_after_goaway=True,
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.body_length == 512
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_goaway_stream_boundary_cannot_increase():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        graceful_goaway=True,
        goaway_last_stream_ids=(1, 3),
    )

    result = _probe(sock)

    assert result.protocol_error
    assert not result.incomplete


def test_goaway_stream_boundary_may_decrease_for_active_stream():
    sock = FakeHttp2ServerSocket(
        body=b"x" * 512,
        complete=False,
        graceful_goaway=True,
        goaway_last_stream_ids=(3, 1),
    )

    result = _probe(sock)

    assert not result.protocol_error
    assert result.interrupted
    assert result.incomplete


def test_http2_probe_sends_bounded_range_only_when_requested():
    sock = FakeHttp2ServerSocket()

    result = _probe(sock, bounded_range=True)

    assert result.complete
    assert (b"range", b"bytes=0-262143") in sock.request_headers
    assert (b"accept-encoding", b"identity") in sock.request_headers


def test_truncated_http2_stream_is_not_called_incomplete():
    sock = FakeHttp2ServerSocket(body=b"x" * 128, complete=False)

    result = _probe(sock, max_bytes=64)

    assert result.truncated
    assert not result.incomplete


def test_exact_cap_unfinished_http2_stream_is_truncated():
    sock = FakeHttp2ServerSocket(body=b"x" * 64, complete=False)

    result = _probe(sock, max_bytes=64)

    assert result.truncated
    assert not result.complete
    assert not result.incomplete


def test_exact_cap_completed_http2_stream_is_complete():
    sock = FakeHttp2ServerSocket(body=b"x" * 64, complete=True)

    result = _probe(sock, max_bytes=64)

    assert result.complete
    assert not result.truncated
    assert not result.incomplete


def test_http2_non_success_is_not_called_incomplete():
    sock = FakeHttp2ServerSocket(
        status=429,
        body=b"local_rate_limited",
        complete=False,
    )

    result = _probe(sock)

    assert result.status == 429
    assert not result.incomplete


@pytest.mark.parametrize("status", [204, 205, 304])
def test_http2_no_content_status_with_data_is_unknown(status):
    sock = FakeHttp2ServerSocket(
        status=status,
        body=b"invalid response body",
        complete=False,
    )

    result = _probe(sock)

    assert result.status == status
    assert result.protocol_error
    assert not result.interrupted
    assert not result.incomplete


def test_compressed_http2_stream_is_not_called_incomplete():
    sock = FakeHttp2ServerSocket(
        body=b"compressed response bytes",
        complete=False,
        content_encoding=b"gzip",
    )

    result = _probe(sock)

    assert result.status == 200
    assert result.interrupted
    assert not result.content_encoding_is_identity
    assert not result.incomplete

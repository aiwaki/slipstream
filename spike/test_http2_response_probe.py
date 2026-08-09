from collections import deque
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived

from http2_response_probe import probe_http2_response


class FakeHttp2ServerSocket:
    def __init__(
        self,
        *,
        status=200,
        body=b"response body",
        complete=True,
        content_encoding=b"identity",
    ):
        self._server = H2Connection(
            config=H2Configuration(client_side=False, header_encoding=None)
        )
        self._server.initiate_connection()
        self._chunks = deque([self._server.data_to_send()])
        self._status = status
        self._body = body
        self._complete = complete
        self._content_encoding = content_encoding
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
            self._server.send_headers(event.stream_id, response_headers)
            self._server.send_data(
                event.stream_id,
                self._body,
                end_stream=self._complete,
            )
            self._chunks.append(self._server.data_to_send())

    def recv(self, _size):
        if self._chunks:
            return self._chunks.popleft()
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


def test_http2_non_success_is_not_called_incomplete():
    sock = FakeHttp2ServerSocket(
        status=429,
        body=b"local_rate_limited",
        complete=False,
    )

    result = _probe(sock)

    assert result.status == 429
    assert not result.incomplete

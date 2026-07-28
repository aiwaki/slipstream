from http_response_completion import http_response_complete


def _response(headers, body=b""):
    return b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n\r\n" + body


def test_content_length_requires_the_exact_complete_body():
    complete = _response(b"Content-Length: 5", b"hello")
    partial = _response(b"Content-Length: 6", b"hello")

    assert http_response_complete(
        complete,
        stream_closed=False,
        truncated=False,
    )
    assert not http_response_complete(
        partial,
        stream_closed=True,
        truncated=False,
    )


def test_chunked_response_requires_the_terminal_chunk():
    complete = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\n\r\n",
    )
    partial = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n",
    )

    assert http_response_complete(
        complete,
        stream_closed=False,
        truncated=False,
    )
    assert not http_response_complete(
        partial,
        stream_closed=True,
        truncated=False,
    )


def test_connection_delimited_response_requires_orderly_eof():
    response = _response(b"Content-Type: text/plain", b"hello")

    assert http_response_complete(
        response,
        stream_closed=True,
        truncated=False,
    )
    assert not http_response_complete(
        response,
        stream_closed=False,
        truncated=False,
    )


def test_truncated_or_unsuccessful_response_never_qualifies():
    complete = _response(b"Content-Length: 5", b"hello")
    denied = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"

    assert not http_response_complete(
        complete,
        stream_closed=True,
        truncated=True,
    )
    assert not http_response_complete(
        denied,
        stream_closed=True,
        truncated=False,
    )


def test_conflicting_content_lengths_fail_closed():
    response = _response(
        b"Content-Length: 5\r\nContent-Length: 6",
        b"hello",
    )

    assert not http_response_complete(
        response,
        stream_closed=True,
        truncated=False,
    )

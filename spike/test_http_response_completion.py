from http_response_completion import (
    http_response_body_length,
    http_response_complete,
    http_response_incomplete,
)


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
    assert http_response_body_length(
        complete,
        stream_closed=False,
        truncated=False,
    ) == 5


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
    assert http_response_body_length(
        complete,
        stream_closed=False,
        truncated=False,
    ) == 5
    assert not http_response_complete(
        partial,
        stream_closed=True,
        truncated=False,
    )
    http_10_chunked = complete.replace(b"HTTP/1.1", b"HTTP/1.0", 1)
    assert not http_response_complete(
        http_10_chunked,
        stream_closed=True,
        truncated=False,
    )

    complete_trailer = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\nX-Foo: ok\r\n\r\n",
    )
    assert not http_response_complete(
        complete_trailer,
        stream_closed=True,
        truncated=False,
    )
    assert http_response_body_length(
        complete_trailer,
        stream_closed=True,
        truncated=False,
    ) is None

    unsupported_transfer_coding = _response(
        b"Transfer-Encoding: gzip, chunked",
        b"5\r\nhello\r\n0\r\n\r\n",
    )
    conflicting_framing = _response(
        b"Transfer-Encoding: chunked\r\nContent-Length: 5",
        b"5\r\nhello\r\n0\r\n\r\n",
    )
    for response in (unsupported_transfer_coding, conflicting_framing):
        assert not http_response_complete(
            response,
            stream_closed=True,
            truncated=False,
        )

    forbidden_payload_trailer = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\nContent-Encoding: gzip\r\n\r\n",
    )
    forbidden_location_trailer = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\nLocation: https://other.example/\r\n\r\n",
    )
    for response in (forbidden_payload_trailer, forbidden_location_trailer):
        assert not http_response_complete(
            response,
            stream_closed=True,
            truncated=False,
        )

    for trailer in (
        b"Authentication-Info: nextnonce=abc",
        b"Clear-Site-Data: \"cache\"",
        b"Strict-Transport-Security: max-age=31536000",
        b"Cross-Origin-Opener-Policy: same-origin",
        b"X-Frame-Options: DENY",
        b"X-Accel-Redirect: /internal/file",
        b"X-Sendfile: /private/file",
        b"X-Status: 302",
        b"X-Location: https://other.example/",
    ):
        complete_control_trailer = _response(
            b"Transfer-Encoding: chunked",
            b"5\r\nhello\r\n0\r\n" + trailer + b"\r\n\r\n",
        )
        cutoff_control_trailer = complete_control_trailer[:-2]
        for response in (complete_control_trailer, cutoff_control_trailer):
            assert not http_response_complete(
                response,
                stream_closed=True,
                truncated=False,
            )
            assert not http_response_incomplete(
                response,
                stream_closed=True,
                idle_timed_out=False,
                truncated=False,
            )

    trailing_bytes = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\nX-Foo: ok\r\n\r\ngarbage",
    )
    assert not http_response_complete(
        trailing_bytes,
        stream_closed=True,
        truncated=False,
    )
    assert not http_response_incomplete(
        trailing_bytes,
        stream_closed=True,
        idle_timed_out=False,
        truncated=False,
    )
    assert http_response_body_length(
        trailing_bytes,
        stream_closed=True,
        truncated=False,
    ) is None


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


def test_declared_body_shortfall_is_proven_at_eof_or_idle_timeout():
    partial = _response(b"Content-Length: 6", b"hello")

    assert http_response_incomplete(
        partial,
        stream_closed=True,
        idle_timed_out=False,
        truncated=False,
    )
    assert http_response_incomplete(
        partial,
        stream_closed=False,
        idle_timed_out=True,
        truncated=False,
    )


def test_complete_or_unframed_response_is_not_called_incomplete():
    complete = _response(b"Content-Length: 5", b"hello")
    connection_delimited = _response(b"Content-Type: text/plain", b"hello")

    for response in (complete, connection_delimited):
        assert not http_response_incomplete(
            response,
            stream_closed=True,
            idle_timed_out=False,
            truncated=False,
        )


def test_partial_chunked_body_is_proven_only_after_the_stream_stops():
    partial = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n",
    )

    assert http_response_incomplete(
        partial,
        stream_closed=True,
        idle_timed_out=False,
        truncated=False,
    )
    assert not http_response_incomplete(
        partial,
        stream_closed=False,
        idle_timed_out=False,
        truncated=False,
    )

    headers_only = _response(b"Transfer-Encoding: chunked")
    assert http_response_incomplete(
        headers_only,
        stream_closed=True,
        idle_timed_out=False,
        truncated=False,
    )

    partial_trailer = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\nX-Foo: ok\r\n",
    )
    assert not http_response_incomplete(
        partial_trailer,
        stream_closed=True,
        idle_timed_out=False,
        truncated=False,
    )
    partial_final_delimiter = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\n\r",
    )
    assert http_response_incomplete(
        partial_final_delimiter,
        stream_closed=True,
        idle_timed_out=False,
        truncated=False,
    )


def test_unsuccessful_malformed_or_locally_truncated_response_stays_unknown():
    denied = b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 5\r\n\r\nno"
    conflicting = _response(
        b"Content-Length: 5\r\nContent-Length: 6",
        b"hey",
    )
    malformed_chunked = _response(
        b"Transfer-Encoding: chunked",
        b"not-a-size\r\nhello\r\n",
    )
    malformed_version = (
        b"HTTP/garbage 200 OK\r\nContent-Length: 100\r\n\r\nabc"
    )
    missing_reason_separator = b"HTTP/1.1 200\r\nContent-Length: 5\r\n\r\nx"
    malformed_header = _response(b"Bad Header: value\r\nContent-Length: 6", b"x")
    chunk_extension = _response(
        b"Transfer-Encoding: chunked",
        b"5;foo=bar\r\nhello\r\n",
    )
    compressed = _response(
        b"Content-Encoding: gzip\r\nContent-Length: 6",
        b"x",
    )
    transfer_coded = _response(
        b"Transfer-Encoding: gzip, chunked",
        b"5\r\nhello\r\n",
    )
    http_10_chunked = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n",
    ).replace(b"HTTP/1.1", b"HTTP/1.0", 1)
    signed_content_length = _response(b"Content-Length: +6", b"x")
    underscored_content_length = _response(b"Content-Length: 1_0", b"x")
    leading_space_chunk_size = _response(
        b"Transfer-Encoding: chunked",
        b" 5\r\nhello\r\n",
    )
    trailing_space_chunk_size = _response(
        b"Transfer-Encoding: chunked",
        b"5 \r\nhello\r\n",
    )
    malformed_trailer = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\nBad Trailer\r\n",
    )
    content_length_trailer = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\nContent-Length: 5\r\n",
    )
    transfer_encoding_trailer = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\nTransfer-Encoding: chunked\r\n",
    )
    content_encoding_trailer = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\nContent-Encoding: gzip\r\n",
    )
    location_trailer = _response(
        b"Transfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\nLocation: https://other.example/\r\n",
    )
    reset_content = (
        b"HTTP/1.1 205 Reset Content\r\nContent-Length: 5\r\n\r\nx"
    )
    partial = _response(b"Content-Length: 6", b"hello")

    for response, truncated in (
        (denied, False),
        (conflicting, False),
        (malformed_chunked, False),
        (malformed_version, False),
        (missing_reason_separator, False),
        (malformed_header, False),
        (chunk_extension, False),
        (compressed, False),
        (transfer_coded, False),
        (http_10_chunked, False),
        (signed_content_length, False),
        (underscored_content_length, False),
        (leading_space_chunk_size, False),
        (trailing_space_chunk_size, False),
        (malformed_trailer, False),
        (content_length_trailer, False),
        (transfer_encoding_trailer, False),
        (content_encoding_trailer, False),
        (location_trailer, False),
        (reset_content, False),
        (partial, True),
    ):
        assert not http_response_incomplete(
            response,
            stream_closed=True,
            idle_timed_out=False,
            truncated=truncated,
        )

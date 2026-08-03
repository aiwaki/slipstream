"""Pure bounded HTTP/1 response-completion checks for route qualification."""


_NO_BODY_STATUSES = frozenset((204, 205, 304))
_TOKEN_BYTES = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
def _header_value_valid(value):
    return not any(byte < 0x20 and byte != 0x09 or byte == 0x7F for byte in value)


def _parse_header_line(line):
    if not line or line.startswith((b" ", b"\t")):
        return None
    name, separator, value = line.partition(b":")
    if (
        not separator
        or not name
        or any(byte not in _TOKEN_BYTES for byte in name)
        or not _header_value_valid(value)
    ):
        return None
    return name.lower(), value.strip()


def _parse_headers(block):
    lines = block.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    if (
        len(parts) != 3
        or parts[0] not in (b"HTTP/1.0", b"HTTP/1.1")
        or len(parts[1]) != 3
        or not parts[1].isdigit()
        or not _header_value_valid(parts[2])
    ):
        return None
    version = parts[0]
    status = int(parts[1])
    headers = {}
    for line in lines[1:]:
        parsed = _parse_header_line(line)
        if parsed is None:
            return None
        name, value = parsed
        headers.setdefault(name, []).append(value)
    return version, status, headers


def _content_length(headers):
    values = headers.get(b"content-length", ())
    if not values:
        return None
    normalized = {value for value in values}
    if len(normalized) != 1:
        return False
    value = next(iter(normalized))
    if not value or any(byte not in b"0123456789" for byte in value):
        return False
    try:
        length = int(value)
    except ValueError:
        return False
    return length


def _chunked_trailer_state(trailer):
    if trailer == b"\r\n":
        return "complete"
    if trailer in (b"", b"\r"):
        return "incomplete"
    return "invalid"


def _chunked_body_state(body):
    cursor = 0
    while True:
        line_end = body.find(b"\r\n", cursor)
        if line_end < 0:
            pending = body[cursor:]
            if not pending:
                return "incomplete"
            if b";" in pending:
                return "invalid"
            if all(
                byte in b"0123456789abcdefABCDEF" for byte in pending
            ):
                return "incomplete"
            return "invalid"
        size_line = body[cursor:line_end]
        if b";" in size_line:
            return "invalid"
        if not size_line or any(
            byte not in b"0123456789abcdefABCDEF" for byte in size_line
        ):
            return "invalid"
        try:
            size = int(size_line, 16)
        except ValueError:
            return "invalid"
        cursor = line_end + 2
        if size == 0:
            return _chunked_trailer_state(body[cursor:])
        chunk_end = cursor + size
        if chunk_end > len(body):
            return "incomplete"
        terminator = body[chunk_end : chunk_end + 2]
        if len(terminator) < 2:
            return "incomplete" if b"\r\n".startswith(terminator) else "invalid"
        if terminator != b"\r\n":
            return "invalid"
        cursor = chunk_end + 2


def _chunked_body_complete(body):
    return _chunked_body_state(body) == "complete"


def _chunked_body_bytes(body):
    if not _chunked_body_complete(body):
        return None
    cursor = 0
    chunks = []
    while True:
        line_end = body.find(b"\r\n", cursor)
        if line_end < 0:
            return None
        try:
            size = int(body[cursor:line_end], 16)
        except ValueError:
            return None
        cursor = line_end + 2
        if size == 0:
            return b"".join(chunks)
        chunks.append(body[cursor : cursor + size])
        cursor += size + 2


def _http_response_framing_complete(
    data,
    *,
    stream_closed,
    truncated,
    allow_error_status,
):
    if not isinstance(data, bytes) or not data.startswith(b"HTTP/") or truncated:
        return False
    boundary = data.find(b"\r\n\r\n")
    if boundary < 0:
        return False
    parsed = _parse_headers(data[:boundary])
    if parsed is None:
        return False
    version, status, headers = parsed
    if status < 200 or status >= 600:
        return False
    if not allow_error_status and status >= 400:
        return False
    body = data[boundary + 4 :]
    if status in _NO_BODY_STATUSES:
        return True

    transfer_encodings = headers.get(b"transfer-encoding", ())
    if transfer_encodings:
        if version != b"HTTP/1.1":
            return False
        tokens = [
            token.strip().lower()
            for value in transfer_encodings
            for token in value.split(b",")
        ]
        if tokens != [b"chunked"] or b"content-length" in headers:
            return False
        return _chunked_body_complete(body)

    length = _content_length(headers)
    if length is False:
        return False
    if length is not None:
        return len(body) == length
    return bool(stream_closed)


def http_response_framing_complete(data, *, stream_closed, truncated):
    """Return whether one bounded final HTTP/1 response is fully framed."""

    return _http_response_framing_complete(
        data,
        stream_closed=stream_closed,
        truncated=truncated,
        allow_error_status=True,
    )


def http_response_complete(data, *, stream_closed, truncated):
    """Return whether one bounded successful HTTP/1 response is complete."""

    return _http_response_framing_complete(
        data,
        stream_closed=stream_closed,
        truncated=truncated,
        allow_error_status=False,
    )


def http_response_body(
    data,
    *,
    stream_closed,
    truncated,
    allow_error_status=False,
):
    """Return the decoded body of one proven-complete HTTP/1 response."""

    if not _http_response_framing_complete(
        data,
        stream_closed=stream_closed,
        truncated=truncated,
        allow_error_status=allow_error_status,
    ):
        return None
    boundary = data.find(b"\r\n\r\n")
    parsed = _parse_headers(data[:boundary])
    if parsed is None:
        return None
    _version, status, headers = parsed
    if status in _NO_BODY_STATUSES:
        return b""
    body = data[boundary + 4 :]
    if headers.get(b"transfer-encoding", ()):
        return _chunked_body_bytes(body)
    length = _content_length(headers)
    if length is False:
        return None
    return body if length is None else body[:length]


def http_response_body_length(data, *, stream_closed, truncated):
    """Return representation-body bytes for one proven-complete response."""

    body = http_response_body(
        data,
        stream_closed=stream_closed,
        truncated=truncated,
        allow_error_status=False,
    )
    return None if body is None else len(body)


def http_response_incomplete(data, *, stream_closed, idle_timed_out, truncated):
    """Return whether a bounded HTTP/1 body is proven unfinished.

    A timeout or EOF is evidence only after a complete successful response
    header declares framing that has not arrived. Connection-delimited,
    malformed, unsuccessful, or locally truncated responses remain unknown.
    """

    if not (stream_closed or idle_timed_out):
        return False
    if not isinstance(data, bytes) or not data.startswith(b"HTTP/") or truncated:
        return False
    boundary = data.find(b"\r\n\r\n")
    if boundary < 0:
        return False
    parsed = _parse_headers(data[:boundary])
    if parsed is None:
        return False
    version, status, headers = parsed
    if status < 200 or status >= 400 or status in _NO_BODY_STATUSES:
        return False
    body = data[boundary + 4 :]

    content_encodings = [
        token.strip().lower()
        for value in headers.get(b"content-encoding", ())
        for token in value.split(b",")
    ]
    if content_encodings and any(token != b"identity" for token in content_encodings):
        return False

    transfer_encodings = headers.get(b"transfer-encoding", ())
    if transfer_encodings:
        if version != b"HTTP/1.1":
            return False
        tokens = [
            token.strip().lower()
            for value in transfer_encodings
            for token in value.split(b",")
        ]
        if tokens != [b"chunked"] or b"content-length" in headers:
            return False
        return _chunked_body_state(body) == "incomplete"

    length = _content_length(headers)
    if length is False or length is None:
        return False
    return len(body) < length

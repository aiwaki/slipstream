"""Pure bounded HTTP/1 response-completion checks for route qualification."""


_NO_BODY_STATUSES = frozenset((204, 304))


def _parse_headers(block):
    lines = block.split(b"\r\n")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        return None
    try:
        status = int(parts[1])
    except ValueError:
        return None
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator:
            return None
        key = name.strip().lower()
        if not key:
            return None
        headers.setdefault(key, []).append(value.strip())
    return status, headers


def _content_length(headers):
    values = headers.get(b"content-length", ())
    if not values:
        return None
    normalized = {value for value in values}
    if len(normalized) != 1:
        return False
    try:
        length = int(next(iter(normalized)))
    except ValueError:
        return False
    return length if length >= 0 else False


def _chunked_body_complete(body):
    cursor = 0
    while True:
        line_end = body.find(b"\r\n", cursor)
        if line_end < 0:
            return False
        size_token = body[cursor:line_end].split(b";", 1)[0].strip()
        if not size_token:
            return False
        try:
            size = int(size_token, 16)
        except ValueError:
            return False
        cursor = line_end + 2
        if size == 0:
            trailer_end = body.find(b"\r\n\r\n", cursor)
            return trailer_end >= 0 or body[cursor:] == b"\r\n"
        chunk_end = cursor + size
        if chunk_end + 2 > len(body) or body[chunk_end : chunk_end + 2] != b"\r\n":
            return False
        cursor = chunk_end + 2


def http_response_complete(data, *, stream_closed, truncated):
    """Return whether one bounded HTTP/1 response is proven complete."""

    if not isinstance(data, bytes) or not data.startswith(b"HTTP/") or truncated:
        return False
    boundary = data.find(b"\r\n\r\n")
    if boundary < 0:
        return False
    parsed = _parse_headers(data[:boundary])
    if parsed is None:
        return False
    status, headers = parsed
    if status < 200 or status >= 400:
        return False
    body = data[boundary + 4 :]
    if status in _NO_BODY_STATUSES:
        return True

    transfer_encodings = headers.get(b"transfer-encoding", ())
    if transfer_encodings:
        tokens = [
            token.strip().lower()
            for value in transfer_encodings
            for token in value.split(b",")
        ]
        if not tokens or tokens[-1] != b"chunked":
            return False
        return _chunked_body_complete(body)

    length = _content_length(headers)
    if length is False:
        return False
    if length is not None:
        return len(body) == length
    return bool(stream_closed)

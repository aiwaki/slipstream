"""Bounded bootstrap-asset discovery for exact-host route preflight.

The public target object intentionally exposes only the exact hostname.  Its
request path and query are retained only long enough to build one probe
request; callers must not place the object or the emitted request in status,
logs, or caches.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
from html.parser import HTMLParser
import ipaddress
import re
import time
from urllib.parse import quote, urljoin, urlsplit

from http_response_completion import (
    http_response_body,
    http_response_complete,
    http_response_incomplete,
)


MAX_ROOT_RESPONSE_BYTES = 262_144
MAX_RESPONSE_HEAD_BYTES = 32_768
MAX_CRITICAL_ASSETS = 4
MAX_ASSET_URL_LENGTH = 2_048
DEFAULT_RANGE_END = 65_535
MAX_RANGE_END = 262_143
MAX_RANGE_RESPONSE_BYTES = MAX_RESPONSE_HEAD_BYTES + 4 + MAX_RANGE_END + 1

_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_STATUS_LINE = re.compile(rb"^HTTP/1\.[01] ([0-9]{3})(?: [\x20-\x7e]*)?$")
_CONTENT_RANGE = re.compile(r"^bytes ([0-9]+)-([0-9]+)/([0-9]+|\*)$", re.I)
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_JAVASCRIPT_TYPES = frozenset(
    {
        "application/ecmascript",
        "application/javascript",
        "application/x-javascript",
        "text/ecmascript",
        "text/javascript",
    }
)
_OBJECT_PREFIX_BYTES = 1_024
_MAX_ETAG_BYTES = 512


class RangeProbeOutcome(str, Enum):
    """Fixed, non-sensitive result of one bounded bootstrap range probe."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNKNOWN = "unknown"
    DEADLINE_EXCEEDED = "deadline_exceeded"


@dataclass(frozen=True, slots=True)
class RangeProbeEvidence:
    """Non-sensitive proof metadata for one exact ranged JS object.

    The request target and response bytes never enter this value.  A strong
    validator is hashed, as is a fixed-size entity prefix used only when an
    origin omits validators.
    """

    outcome: RangeProbeOutcome
    total_length: int | None = None
    range_end: int | None = None
    validator_digest: str = ""
    prefix_digest: str = ""
    received_body_bytes: int = 0

    def proves_same_object_as(self, other):
        if not isinstance(other, RangeProbeEvidence):
            return False
        if (
            self.outcome is not RangeProbeOutcome.INCOMPLETE
            or other.outcome is not RangeProbeOutcome.COMPLETE
            or self.total_length is None
            or self.total_length != other.total_length
            or self.range_end is None
            or self.range_end != other.range_end
        ):
            return False
        if self.validator_digest and self.validator_digest == other.validator_digest:
            return True
        return bool(
            self.prefix_digest
            and self.prefix_digest == other.prefix_digest
        )


class EphemeralBootstrapAsset:
    """An exact host plus a deliberately non-serializable request target."""

    __slots__ = ("_exact_host", "_host_header", "_request_target")

    def __init__(self, *, exact_host, host_header, request_target):
        self._exact_host = exact_host
        self._host_header = host_header
        self._request_target = request_target

    @property
    def exact_host(self):
        """Return the only value that may be used as a routing/cache key."""

        return self._exact_host

    def build_range_request(self, *, range_end=DEFAULT_RANGE_END):
        """Consume the target and build one transient identity range GET."""

        if self._request_target is None:
            raise RuntimeError("bootstrap asset target has already been forgotten")
        if not isinstance(range_end, int) or isinstance(range_end, bool):
            raise ValueError("range_end must be an integer")
        if range_end < 0 or range_end > MAX_RANGE_END:
            raise ValueError("range_end exceeds the bounded probe limit")
        request = (
            f"GET {self._request_target} HTTP/1.1\r\n"
            f"Host: {self._host_header}\r\n"
            "User-Agent: SlipstreamBootstrapPreflight/1\r\n"
            "Accept: application/javascript,text/javascript,*/*;q=0.1\r\n"
            "Accept-Encoding: identity\r\n"
            f"Range: bytes=0-{range_end}\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        self._request_target = None
        return request

    def forget(self):
        """Drop the path/query without constructing a request."""

        self._request_target = None

    def __repr__(self):
        state = "forgotten" if self._request_target is None else "ephemeral"
        return (
            f"<EphemeralBootstrapAsset exact_host={self._exact_host!r} "
            f"state={state}>"
        )

    def __reduce_ex__(self, _protocol):
        raise TypeError("ephemeral bootstrap targets must not be serialized")


def extract_critical_bootstrap_assets(
    root_url,
    response,
    *,
    stream_closed,
    truncated,
    deadline,
    clock=time.monotonic,
    max_assets=MAX_CRITICAL_ASSETS,
):
    """Extract a few critical JS targets from one complete HTTPS root page.

    The return values are one-shot, non-serializable objects.  The function is
    fail-closed for non-HTML, compressed, partial, oversized, or expired input.
    """

    if not _deadline_open(deadline, clock):
        return ()
    if (
        not isinstance(response, bytes)
        or len(response) > MAX_ROOT_RESPONSE_BYTES
        or not isinstance(max_assets, int)
        or isinstance(max_assets, bool)
        or max_assets < 0
        or max_assets > MAX_CRITICAL_ASSETS
    ):
        return ()
    normalized_root = _normalize_https_url(root_url, require_root=True)
    if normalized_root is None:
        return ()
    parsed_head = _response_head(response)
    if parsed_head is None:
        return ()
    status, headers = parsed_head
    if status != 200 or not _identity_encoded(headers) or not _html_content(headers):
        return ()
    body = http_response_body(
        response,
        stream_closed=stream_closed,
        truncated=truncated,
    )
    if body is None or len(body) > MAX_ROOT_RESPONSE_BYTES:
        return ()

    parser = _CriticalAssetParser(normalized_root[3], max_assets=max_assets)
    decoded = body.decode("utf-8", "replace")
    for offset in range(0, len(decoded), 16_384):
        if not _deadline_open(deadline, clock):
            return ()
        parser.feed(decoded[offset : offset + 16_384])
    parser.close()
    if not _deadline_open(deadline, clock):
        return ()
    return tuple(
        EphemeralBootstrapAsset(
            exact_host=candidate[0],
            host_header=candidate[1],
            request_target=candidate[2],
        )
        for candidate in parser.candidates
    )


def classify_range_response(
    response,
    *,
    stream_closed,
    idle_timed_out,
    truncated,
    deadline,
    requested_range_end=DEFAULT_RANGE_END,
    clock=time.monotonic,
):
    """Return the fixed outcome for a strict ranged-JavaScript observation."""

    return inspect_range_response(
        response,
        stream_closed=stream_closed,
        idle_timed_out=idle_timed_out,
        truncated=truncated,
        deadline=deadline,
        requested_range_end=requested_range_end,
        clock=clock,
    ).outcome


def inspect_range_response(
    response,
    *,
    stream_closed,
    idle_timed_out,
    truncated,
    deadline,
    requested_range_end=DEFAULT_RANGE_END,
    clock=time.monotonic,
):
    """Return bounded evidence without mistaking a different 200 page for JS.

    ``INCOMPLETE`` requires complete successful headers plus declared framing
    that did not arrive before EOF/idle timeout.  Both candidates must be a
    206 identity response for JavaScript, name the same total object length,
    and later bind via a strong ETag or an identical fixed-size entity prefix.
    Generic 200 HTML/JSON, redirects, compression, local truncation, and
    connection-delimited responses remain ``UNKNOWN``.
    """

    if not _deadline_open(deadline, clock):
        return RangeProbeEvidence(RangeProbeOutcome.DEADLINE_EXCEEDED)
    if (
        not isinstance(response, bytes)
        or len(response) > MAX_RANGE_RESPONSE_BYTES
        or not isinstance(requested_range_end, int)
        or isinstance(requested_range_end, bool)
        or requested_range_end < 0
        or requested_range_end > MAX_RANGE_END
    ):
        return _evidence_before_deadline(
            RangeProbeEvidence(RangeProbeOutcome.UNKNOWN), deadline, clock
        )
    parsed_head = _response_head(response)
    if parsed_head is None:
        return _evidence_before_deadline(
            RangeProbeEvidence(RangeProbeOutcome.UNKNOWN), deadline, clock
        )
    status, headers = parsed_head
    range_descriptor = _content_range(headers, requested_range_end)
    if (
        status != 206
        or not _identity_encoded(headers)
        or not _javascript_content(headers)
        or range_descriptor is None
    ):
        return _evidence_before_deadline(
            RangeProbeEvidence(RangeProbeOutcome.UNKNOWN), deadline, clock
        )
    range_end, total_length = range_descriptor
    expected_range_length = range_end + 1
    if not _range_length_consistent(headers, expected_range_length):
        return _evidence_before_deadline(
            RangeProbeEvidence(RangeProbeOutcome.UNKNOWN), deadline, clock
        )

    validator_digest = _strong_validator_digest(headers)
    prefix_digest, received_body_bytes = _entity_prefix_binding(
        response,
        headers,
        stream_closed=stream_closed,
        truncated=truncated,
    )

    if http_response_complete(
        response,
        stream_closed=stream_closed,
        truncated=truncated,
    ):
        body = http_response_body(
            response,
            stream_closed=stream_closed,
            truncated=truncated,
        )
        if body is None or len(body) != expected_range_length:
            return _evidence_before_deadline(
                RangeProbeEvidence(RangeProbeOutcome.UNKNOWN), deadline, clock
            )
        return _evidence_before_deadline(
            RangeProbeEvidence(
                RangeProbeOutcome.COMPLETE,
                total_length=total_length,
                range_end=range_end,
                validator_digest=validator_digest,
                prefix_digest=prefix_digest,
                received_body_bytes=len(body),
            ),
            deadline,
            clock,
        )
    if http_response_incomplete(
        response,
        stream_closed=stream_closed,
        idle_timed_out=idle_timed_out,
        truncated=truncated,
    ):
        return _evidence_before_deadline(
            RangeProbeEvidence(
                RangeProbeOutcome.INCOMPLETE,
                total_length=total_length,
                range_end=range_end,
                validator_digest=validator_digest,
                prefix_digest=prefix_digest,
                received_body_bytes=received_body_bytes,
            ),
            deadline,
            clock,
        )
    return _evidence_before_deadline(
        RangeProbeEvidence(RangeProbeOutcome.UNKNOWN), deadline, clock
    )


class _CriticalAssetParser(HTMLParser):
    def __init__(self, root_url, *, max_assets):
        super().__init__(convert_charrefs=True)
        self._document_url = root_url
        self._base_url = root_url
        self._base_seen = False
        self._max_assets = max_assets
        self._seen = set()
        self.candidates = []

    def handle_starttag(self, tag, attrs):
        attributes = {
            str(name).lower(): value
            for name, value in attrs
            if name and value is not None
        }
        lowered_tag = tag.lower()
        if lowered_tag == "base" and not self._base_seen:
            self._base_seen = True
            candidate = _normalize_https_url(
                attributes.get("href", ""),
                base_url=self._document_url,
            )
            if candidate is not None:
                self._base_url = candidate[3]
            return
        if len(self.candidates) >= self._max_assets:
            return

        raw_url = None
        if lowered_tag == "script" and _is_javascript_script(attributes):
            raw_url = attributes.get("src")
        elif lowered_tag == "link":
            rel = frozenset(attributes.get("rel", "").lower().split())
            resource_as = attributes.get("as", "").strip().lower()
            if "modulepreload" in rel or ("preload" in rel and resource_as == "script"):
                raw_url = attributes.get("href")
        if not raw_url:
            return

        candidate = _normalize_https_url(raw_url, base_url=self._base_url)
        if candidate is None or candidate[3] in self._seen:
            return
        self._seen.add(candidate[3])
        self.candidates.append(candidate[:3])


def _is_javascript_script(attributes):
    if "src" not in attributes:
        return False
    script_type = attributes.get("type", "").strip().lower().split(";", 1)[0]
    return not script_type or script_type == "module" or script_type in _JAVASCRIPT_TYPES


def _normalize_https_url(raw_url, *, base_url=None, require_root=False):
    if not isinstance(raw_url, str):
        return None
    raw_url = raw_url.strip()
    if (
        not raw_url
        or len(raw_url) > MAX_ASSET_URL_LENGTH
        or _CONTROL_OR_SPACE.search(raw_url)
    ):
        return None
    try:
        absolute = urljoin(base_url, raw_url) if base_url is not None else raw_url
        if len(absolute) > MAX_ASSET_URL_LENGTH or _CONTROL_OR_SPACE.search(absolute):
            return None
        parsed = urlsplit(absolute)
        if parsed.scheme.lower() != "https" or parsed.username is not None:
            return None
        if parsed.password is not None or not parsed.hostname:
            return None
        port = parsed.port
    except (TypeError, ValueError, UnicodeError):
        return None
    if port not in (None, 443) or (require_root and (parsed.path not in ("", "/") or parsed.query)):
        return None

    exact_host = _canonical_host(parsed.hostname)
    if exact_host is None:
        return None
    if require_root and parsed.fragment:
        return None
    host_header = f"[{exact_host}]" if ":" in exact_host else exact_host
    path = quote(
        parsed.path or "/",
        safe="/%:@!$&'()*+,;=-._~",
    )
    query = quote(
        parsed.query,
        safe="/%?:@!$&'()*+,;=-._~",
    )
    request_target = path + (f"?{query}" if query else "")
    normalized = f"https://{host_header}{request_target}"
    if len(normalized) > MAX_ASSET_URL_LENGTH:
        return None
    return exact_host, host_header, request_target, normalized


def _canonical_host(host):
    if not isinstance(host, str) or not host or host.endswith("."):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            canonical = host.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            return None
        if len(canonical) > 253:
            return None
        labels = canonical.split(".")
        if any(not _DNS_LABEL.fullmatch(label) for label in labels):
            return None
        return canonical
    return address.compressed.lower()


def _response_head(response):
    boundary = response.find(b"\r\n\r\n")
    if boundary < 0 or boundary > MAX_RESPONSE_HEAD_BYTES:
        return None
    lines = response[:boundary].split(b"\r\n")
    match = _STATUS_LINE.fullmatch(lines[0]) if lines else None
    if match is None:
        return None
    headers = {}
    for line in lines[1:]:
        if not line or line[:1] in b" \t" or b":" not in line:
            return None
        name, value = line.split(b":", 1)
        if not _HEADER_NAME.fullmatch(name) or any(
            byte < 32 and byte != 9 or byte == 127 for byte in value
        ):
            return None
        try:
            decoded_value = value.decode("latin-1").strip()
        except UnicodeDecodeError:
            return None
        headers.setdefault(name.decode("ascii").lower(), []).append(decoded_value)
    return int(match.group(1)), headers


def _identity_encoded(headers):
    values = headers.get("content-encoding", ())
    tokens = [token.strip().lower() for value in values for token in value.split(",")]
    return not tokens or all(token == "identity" for token in tokens)


def _html_content(headers):
    values = headers.get("content-type", ())
    if len(values) != 1:
        return False
    media_type = values[0].split(";", 1)[0].strip().lower()
    return media_type in ("text/html", "application/xhtml+xml")


def _javascript_content(headers):
    values = headers.get("content-type", ())
    if len(values) != 1:
        return False
    media_type = values[0].split(";", 1)[0].strip().lower()
    return media_type in _JAVASCRIPT_TYPES


def _content_range(headers, requested_range_end):
    values = headers.get("content-range", ())
    if len(values) != 1:
        return None
    match = _CONTENT_RANGE.fullmatch(values[0].strip())
    if match is None:
        return None
    try:
        start = int(match.group(1))
        end = int(match.group(2))
        total_length = (
            None if match.group(3) == "*" else int(match.group(3))
        )
    except (ValueError, OverflowError):
        return None
    total_text = match.group(3)
    if (
        start != 0
        or end < start
        or end > requested_range_end
        or total_text == "*"
    ):
        return None
    assert total_length is not None
    if total_length <= end:
        return None
    return end, total_length


def _range_length_consistent(headers, expected_range_length):
    transfer_encodings = headers.get("transfer-encoding", ())
    lengths = headers.get("content-length", ())
    if transfer_encodings:
        return not lengths
    if not lengths:
        return True
    if len(lengths) != 1 or not lengths[0].isdigit():
        return False
    try:
        return int(lengths[0]) == expected_range_length
    except (ValueError, OverflowError):
        return False


def _strong_validator_digest(headers):
    values = headers.get("etag", ())
    if len(values) != 1:
        return ""
    value = values[0].strip()
    if (
        not value
        or len(value.encode("latin-1", "ignore")) > _MAX_ETAG_BYTES
        or value.lower().startswith("w/")
        or not (value.startswith('"') and value.endswith('"'))
    ):
        return ""
    return hashlib.sha256(("etag\0" + value).encode("latin-1")).hexdigest()


def _entity_prefix_binding(response, headers, *, stream_closed, truncated):
    transfer_encodings = headers.get("transfer-encoding", ())
    body = None
    if not transfer_encodings:
        boundary = response.find(b"\r\n\r\n")
        if boundary >= 0:
            body = response[boundary + 4 :]
    elif http_response_complete(
        response,
        stream_closed=stream_closed,
        truncated=truncated,
    ):
        body = http_response_body(
            response,
            stream_closed=stream_closed,
            truncated=truncated,
        )
    received = len(body) if body is not None else 0
    if body is None or len(body) < _OBJECT_PREFIX_BYTES:
        return "", received
    return hashlib.sha256(body[:_OBJECT_PREFIX_BYTES]).hexdigest(), received


def _deadline_open(deadline, clock):
    try:
        return clock() < float(deadline)
    except (TypeError, ValueError, OverflowError):
        return False


def _evidence_before_deadline(evidence, deadline, clock):
    if not _deadline_open(deadline, clock):
        return RangeProbeEvidence(RangeProbeOutcome.DEADLINE_EXCEEDED)
    return evidence

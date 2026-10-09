"""Bounded, direct RFC 8484 lookup for Slipstream's local app-owned DNS fallback.

This module never changes macOS DNS configuration. It connects to public
resolvers by fixed IP with verified TLS, independently of the system resolver
and cache. Only an exact host with prior local failure reaches this fallback.
"""
from collections import OrderedDict
import math
import os
import secrets
import socket
import ssl
import struct
import threading
import time

from bootstrap_tls_stream import BootstrapTlsStream
import http_response_completion


APP_DOH_ENDPOINTS = (
    ("1.1.1.1", "cloudflare-dns.com"),
    ("8.8.8.8", "dns.google"),
)
APP_DOH_PATH = "/dns-query"
APP_DOH_TIMEOUT = 3.0
APP_DOH_TTL = 300.0
APP_DOH_NEGATIVE_TTL = 30.0
APP_DOH_CACHE_MAX = 512
APP_DOH_MAX_RESPONSE = 64 * 1024
APP_DOH_MAX_HEADERS = 8 * 1024
SYSTEM_CA_BUNDLE = "/etc/ssl/cert.pem"

_cache = OrderedDict()
_cache_lock = threading.Lock()


def _tls_context():
    """Use macOS's bundled CA file while preserving hostname verification."""
    try:
        if os.path.isfile(SYSTEM_CA_BUNDLE):
            return ssl.create_default_context(cafile=SYSTEM_CA_BUNDLE)
    except Exception:
        pass
    return ssl.create_default_context()


def _normalize_host(host):
    if not isinstance(host, str):
        return ""
    host = host.strip().strip(".").lower()
    if not host or len(host) > 253:
        return ""
    labels = host.split(".")
    try:
        encoded = [label.encode("idna").decode("ascii") for label in labels]
    except UnicodeError:
        return ""
    if any(not label or len(label) > 63 for label in encoded):
        return ""
    return ".".join(encoded)


def build_a_query(host, query_id):
    """Build one standard recursive IN/A DNS query."""
    host = _normalize_host(host)
    if not host or not 0 <= query_id <= 0xFFFF:
        raise ValueError("invalid DNS query")
    labels = host.encode("ascii").split(b".")
    qname = b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def _skip_name(packet, offset):
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            return offset + 2
        if length & 0xC0 or length > 63:
            raise ValueError("invalid DNS label")
        offset += 1 + length


def parse_a_response(packet, query_id):
    """Return A records only when the response matches the original query."""
    if len(packet) < 12:
        return []
    response_id, flags, questions, answers, _authority, _additional = struct.unpack(
        "!HHHHHH", packet[:12]
    )
    if response_id != query_id or not (flags & 0x8000) or flags & 0x000F:
        return []
    try:
        offset = 12
        for _ in range(questions):
            offset = _skip_name(packet, offset)
            offset += 4
            if offset > len(packet):
                return []
        ips = []
        for _ in range(answers):
            offset = _skip_name(packet, offset)
            if offset + 10 > len(packet):
                return []
            record_type, record_class, _ttl, size = struct.unpack(
                "!HHIH", packet[offset:offset + 10]
            )
            offset += 10
            if offset + size > len(packet):
                return []
            if record_type == 1 and record_class == 1 and size == 4:
                ip = socket.inet_ntoa(packet[offset:offset + size])
                if ip not in ips:
                    ips.append(ip)
            offset += size
        return ips
    except (ValueError, struct.error, OSError):
        return []


def _query_endpoint(connect_ip, server_name, host, timeout):
    # Both ordinary async lookups and shared-deadline probes require the same
    # complete HTTP framing, untruncated DNS answer and verified TLS identity.
    try:
        timeout = float(timeout)
        if not math.isfinite(timeout) or timeout <= 0:
            return []
        return _query_endpoint_bounded(
            connect_ip, server_name, host, time.monotonic() + timeout, None,
        )
    except (TypeError, ValueError, OSError):
        return []


def _deadline_remaining(deadline, cancel_event):
    if cancel_event is not None and cancel_event.is_set():
        raise InterruptedError("DNS lookup cancelled")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("DNS lookup deadline exceeded")
    return remaining


def _query_endpoint_bounded(connect_ip, server_name, host, deadline, cancel_event):
    """One fixed-IP DoH request whose connect and every TLS I/O share a deadline."""
    raw_socket = None
    stream = None
    try:
        _deadline_remaining(deadline, cancel_event)
        query_id = secrets.randbits(16)
        query = build_a_query(host, query_id)
        context = _tls_context()
        _deadline_remaining(deadline, cancel_event)
        # The published endpoints are numeric IPv4: no system resolver or proxy.
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(_deadline_remaining(deadline, cancel_event))
        raw_socket.connect((connect_ip, 443))
        _deadline_remaining(deadline, cancel_event)
        stream = BootstrapTlsStream(
            raw_socket, context, server_name, deadline,
            idle_timeout=_deadline_remaining(deadline, cancel_event),
            monotonic=time.monotonic, cancel_event=cancel_event,
        )
        stream.do_handshake()
        request = (
            f"POST {APP_DOH_PATH} HTTP/1.1\r\n"
            f"Host: {server_name}\r\n"
            "Accept: application/dns-message\r\n"
            "Content-Type: application/dns-message\r\n"
            "Accept-Encoding: identity\r\n"
            f"Content-Length: {len(query)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + query
        _deadline_remaining(deadline, cancel_event)
        stream.sendall(request)
        response = b""
        headers_checked = False
        max_input = APP_DOH_MAX_HEADERS + 4 + APP_DOH_MAX_RESPONSE
        while True:
            _deadline_remaining(deadline, cancel_event)
            chunk = stream.recv(min(4096, max_input + 1 - len(response)))
            _deadline_remaining(deadline, cancel_event)
            response += chunk
            if len(response) > max_input:
                return []
            boundary = response.find(b"\r\n\r\n")
            if boundary < 0:
                if not chunk or len(response) > APP_DOH_MAX_HEADERS:
                    return []
                continue
            if boundary > APP_DOH_MAX_HEADERS:
                return []
            if not headers_checked:
                parsed = http_response_completion._parse_headers(response[:boundary])
                if parsed is None:
                    return []
                _version, status, headers = parsed
                content_types = headers.get(b"content-type", ())
                encodings = headers.get(b"content-encoding", ())
                if (
                    status != 200
                    or len(content_types) != 1
                    or content_types[0].split(b";", 1)[0].strip().lower()
                    != b"application/dns-message"
                    or (encodings and encodings != [b"identity"])
                    or not (b"content-length" in headers or b"transfer-encoding" in headers)
                ):
                    return []
                headers_checked = True
            if http_response_completion.http_response_framing_complete(
                response, stream_closed=not chunk, truncated=False,
            ):
                # Decode chunk framing once, only after full HTTP framing proof.
                packet = http_response_completion.http_response_body(
                    response, stream_closed=not chunk, truncated=False,
                )
                _deadline_remaining(deadline, cancel_event)
                if (
                    packet is None or len(packet) > APP_DOH_MAX_RESPONSE
                    or len(packet) < 12 or packet[2] & 0x02  # DNS TC flag
                ):
                    return []
                ips = parse_a_response(packet, query_id)
                _deadline_remaining(deadline, cancel_event)
                return ips
            if not chunk:
                return []
    except (OSError, ValueError, ssl.SSLError):
        return []
    finally:
        if stream is not None:
            stream.close()
        elif raw_socket is not None:
            raw_socket.close()


def _resolve_bounded(host, timeout, deadline, cancel_event):
    try:
        now = time.monotonic()
        timeout = float(timeout)
        deadline = now + timeout if deadline is None else float(deadline)
        if not math.isfinite(timeout) or timeout <= 0 or not math.isfinite(deadline):
            return []
        deadline = min(deadline, now + timeout)
        _deadline_remaining(deadline, cancel_event)
        with _cache_lock:
            _deadline_remaining(deadline, cancel_event)
            cached = _cache.get(host)
            if cached and cached[1] > time.monotonic():
                _cache.move_to_end(host)
                return list(cached[0])
        ips = []
        for connect_ip, server_name in APP_DOH_ENDPOINTS:
            _deadline_remaining(deadline, cancel_event)
            ips = _query_endpoint_bounded(
                connect_ip, server_name, host, deadline, cancel_event,
            )
            _deadline_remaining(deadline, cancel_event)
            if ips:
                break
        with _cache_lock:
            _deadline_remaining(deadline, cancel_event)
            ttl = APP_DOH_TTL if ips else APP_DOH_NEGATIVE_TTL
            _cache[host] = (tuple(ips), time.monotonic() + ttl)
            _cache.move_to_end(host)
            while len(_cache) > APP_DOH_CACHE_MAX:
                _cache.popitem(last=False)
        return ips
    except (OSError, TypeError, ValueError):
        # Expiry/cancellation is not a negative DNS observation and is not cached.
        return []


def resolve(host, timeout=APP_DOH_TIMEOUT, *, deadline=None, cancel_event=None):
    """Resolve an exact hostname through app-owned DNS without touching system DNS."""
    host = _normalize_host(host)
    if not host:
        return []
    if deadline is not None or cancel_event is not None:
        return _resolve_bounded(host, timeout, deadline, cancel_event)
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(host)
        if cached and cached[1] > now:
            _cache.move_to_end(host)
            return list(cached[0])

    ips = []
    for connect_ip, server_name in APP_DOH_ENDPOINTS:
        ips = _query_endpoint(connect_ip, server_name, host, timeout)
        if ips:
            break

    with _cache_lock:
        ttl = APP_DOH_TTL if ips else APP_DOH_NEGATIVE_TTL
        _cache[host] = (tuple(ips), now + ttl)
        _cache.move_to_end(host)
        while len(_cache) > APP_DOH_CACHE_MAX:
            _cache.popitem(last=False)
    return ips

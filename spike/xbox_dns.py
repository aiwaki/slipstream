"""Bounded, direct RFC 8484 lookup for Slipstream's local Xbox DNS fallback.

This module never changes macOS DNS configuration. It connects to the resolver's
published IP addresses with verified TLS for ``xbox-dns.ru`` and is called only
for an exact host after the ordinary local route has shown a real failure.
"""
from collections import OrderedDict
import http.client
import os
import secrets
import socket
import ssl
import struct
import threading
import time


XBOX_DOH_ENDPOINTS = (
    ("111.88.96.50", "xbox-dns.ru"),
    ("111.88.96.51", "xbox-dns.ru"),
)
XBOX_DOH_PATH = "/dns-query"
XBOX_DOH_TIMEOUT = 3.0
XBOX_DOH_TTL = 300.0
XBOX_DOH_NEGATIVE_TTL = 30.0
XBOX_DOH_CACHE_MAX = 512
XBOX_DOH_MAX_RESPONSE = 64 * 1024
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


class _DirectHttpsConnection(http.client.HTTPSConnection):
    """HTTPSConnection with a fixed IP but a verified DNS hostname/SNI."""

    def __init__(self, connect_ip, server_name, timeout):
        self._connect_ip = connect_ip
        super().__init__(server_name, 443, timeout=timeout, context=_tls_context())

    def connect(self):
        raw = socket.create_connection((self._connect_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


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
    query_id = secrets.randbits(16)
    query = build_a_query(host, query_id)
    connection = _DirectHttpsConnection(connect_ip, server_name, timeout)
    try:
        connection.request(
            "POST",
            XBOX_DOH_PATH,
            body=query,
            headers={
                "Accept": "application/dns-message",
                "Content-Type": "application/dns-message",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            return []
        content_type = (response.getheader("content-type") or "").lower()
        if "application/dns-message" not in content_type:
            return []
        packet = response.read(XBOX_DOH_MAX_RESPONSE + 1)
        if len(packet) > XBOX_DOH_MAX_RESPONSE:
            return []
        return parse_a_response(packet, query_id)
    except (OSError, ValueError, http.client.HTTPException, ssl.SSLError):
        return []
    finally:
        connection.close()


def resolve(host, timeout=XBOX_DOH_TIMEOUT):
    """Resolve an exact hostname through Xbox DNS without touching system DNS."""
    host = _normalize_host(host)
    if not host:
        return []
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(host)
        if cached and cached[1] > now:
            _cache.move_to_end(host)
            return list(cached[0])

    ips = []
    for connect_ip, server_name in XBOX_DOH_ENDPOINTS:
        ips = _query_endpoint(connect_ip, server_name, host, timeout)
        if ips:
            break

    with _cache_lock:
        ttl = XBOX_DOH_TTL if ips else XBOX_DOH_NEGATIVE_TTL
        _cache[host] = (tuple(ips), now + ttl)
        _cache.move_to_end(host)
        while len(_cache) > XBOX_DOH_CACHE_MAX:
            _cache.popitem(last=False)
    return ips

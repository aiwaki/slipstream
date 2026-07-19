"""Fail-safe HTTPS qualification for Slipstream's private PF anchor.

The guard proves that a small, neutral system-route baseline works before PF is
loaded, then replays the exact successful numeric destinations after PF is
loaded. It never changes DNS, proxy, VPN, or routing policy.
"""

from dataclasses import dataclass
import ipaddress
import re
import socket
import ssl


DEFAULT_TARGETS = (
    ("example.com", "/"),
    ("www.apple.com", "/library/test/success.html"),
    ("www.microsoft.com", "/"),
)
DEFAULT_TIMEOUT = 2.5
MAX_RESPONSE_BYTES = 8192
MAX_CANDIDATES = 4
MAX_SUCCESSES = 2


@dataclass(frozen=True)
class BaselineCandidate:
    host: str
    ip: str
    path: str


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    reason: str
    status_code: int = 0
    bytes_received: int = 0


@dataclass(frozen=True)
class QualificationResult:
    ok: bool
    reason: str
    candidates: tuple[BaselineCandidate, ...] = ()


def _default_ssl_context():
    # python.org framework builds do not automatically read the macOS Keychain.
    # certifi is already pinned in Slipstream's runtime and frozen bundle.
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def _valid_candidate(candidate):
    if (
        not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", candidate.host)
        or not candidate.path.startswith("/")
        or any(ord(char) < 0x20 or ord(char) > 0x7E for char in candidate.path)
    ):
        return False
    try:
        address = ipaddress.ip_address(candidate.ip)
    except ValueError:
        return False
    return (
        address.version == 4
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_multicast
    )


def resolve_candidates(
    targets=DEFAULT_TARGETS,
    *,
    resolver=socket.getaddrinfo,
    max_candidates=MAX_CANDIDATES,
):
    """Resolve a bounded ordered set of IPv4 candidates through system DNS."""
    per_target = []
    seen = set()
    for host, path in targets:
        resolved = []
        try:
            answers = resolver(
                host,
                443,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except OSError:
            continue
        for answer in answers:
            try:
                ip = str(answer[4][0])
            except (IndexError, TypeError):
                continue
            candidate = BaselineCandidate(host=host, ip=ip, path=path)
            key = (candidate.host, candidate.ip, candidate.path)
            if key in seen or not _valid_candidate(candidate):
                continue
            seen.add(key)
            resolved.append(candidate)
        if resolved:
            per_target.append(resolved)
    candidates = []
    offset = 0
    while len(candidates) < max_candidates:
        added = False
        for resolved in per_target:
            if offset >= len(resolved):
                continue
            candidates.append(resolved[offset])
            added = True
            if len(candidates) >= max_candidates:
                break
        if not added:
            break
        offset += 1
    return tuple(candidates)


def _request_bytes(candidate):
    host = candidate.host.encode("idna").decode("ascii")
    path = candidate.path.encode("ascii", "strict").decode("ascii")
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Accept: */*\r\n"
        "Range: bytes=0-0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def probe_https(
    candidate,
    *,
    timeout=DEFAULT_TIMEOUT,
    socket_factory=socket.create_connection,
    context_factory=_default_ssl_context,
):
    """Require a verified TLS session and a syntactically valid HTTP response."""
    if not _valid_candidate(candidate):
        return ProbeResult(False, "invalid_candidate")
    raw_socket = None
    tls_socket = None
    try:
        request = _request_bytes(candidate)
        raw_socket = socket_factory((candidate.ip, 443), timeout=timeout)
        raw_socket.settimeout(timeout)
        context = context_factory()
        tls_socket = context.wrap_socket(raw_socket, server_hostname=candidate.host)
        tls_socket.settimeout(timeout)
        tls_socket.sendall(request)
        response = bytearray()
        while len(response) < MAX_RESPONSE_BYTES:
            chunk = tls_socket.recv(min(2048, MAX_RESPONSE_BYTES - len(response)))
            if not chunk:
                break
            response.extend(chunk)
            if b"\r\n" in response:
                break
        first_line = bytes(response).partition(b"\r\n")[0]
        match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9][0-9])(?: .*)?", first_line)
        if not match:
            return ProbeResult(False, "no_http_response", bytes_received=len(response))
        return ProbeResult(
            True,
            "ok",
            status_code=int(match.group(1)),
            bytes_received=len(response),
        )
    except (OSError, ssl.SSLError, UnicodeError, ValueError):
        return ProbeResult(False, "connection_unavailable")
    finally:
        if tls_socket is not None:
            try:
                tls_socket.close()
            except OSError:
                pass
        elif raw_socket is not None:
            try:
                raw_socket.close()
            except OSError:
                pass


def qualify_before_arm(
    probe,
    *,
    resolver=socket.getaddrinfo,
    targets=DEFAULT_TARGETS,
):
    """Return only exact numeric destinations proven before PF is loaded."""
    candidates = resolve_candidates(targets, resolver=resolver)
    if not candidates:
        return QualificationResult(False, "baseline_resolution_unavailable")
    successful = []
    for candidate in candidates:
        result = probe(candidate)
        if result.ok:
            successful.append(candidate)
            if len(successful) >= MAX_SUCCESSES:
                break
    if not successful:
        return QualificationResult(False, "baseline_preflight_unavailable")
    return QualificationResult(True, "ok", tuple(successful))


def qualify_after_arm(candidates, probe):
    """Replay the exact pre-PF destinations through the active private anchor."""
    exact = tuple(candidate for candidate in candidates if _valid_candidate(candidate))
    if not exact:
        return QualificationResult(False, "baseline_proof_missing")
    for candidate in exact:
        if probe(candidate).ok:
            return QualificationResult(True, "ok", exact)
    return QualificationResult(False, "baseline_https_unavailable", exact)

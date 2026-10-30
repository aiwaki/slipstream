import struct

import app_dns


def _response(query, address="203.0.113.42"):
    query_id, _flags, questions, _answers, _authority, _additional = struct.unpack(
        "!HHHHHH", query[:12]
    )
    question = query[12:]
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + bytes(int(part) for part in address.split("."))
    )
    return struct.pack("!HHHHHH", query_id, 0x8180, questions, 1, 0, 0) + question + answer


def test_build_and_parse_a_query_response():
    query = app_dns.build_a_query("Example.COM.", 0x1234)

    assert struct.unpack("!H", query[:2])[0] == 0x1234
    assert app_dns.parse_a_response(_response(query), 0x1234) == ["203.0.113.42"]


def test_tls_context_prefers_system_ca_bundle_without_disabling_verification(monkeypatch):
    calls = []

    monkeypatch.setattr(app_dns.os.path, "isfile", lambda path: path == "/tmp/ca.pem")
    monkeypatch.setattr(app_dns, "SYSTEM_CA_BUNDLE", "/tmp/ca.pem")
    monkeypatch.setattr(
        app_dns.ssl,
        "create_default_context",
        lambda **kwargs: calls.append(kwargs) or object(),
    )

    app_dns._tls_context()

    assert calls == [{"cafile": "/tmp/ca.pem"}]


def test_parse_rejects_mismatched_or_failed_response():
    query = app_dns.build_a_query("example.com", 0x1234)
    packet = bytearray(_response(query))

    assert app_dns.parse_a_response(packet, 0x4321) == []

    packet[3] = 0x83
    assert app_dns.parse_a_response(packet, 0x1234) == []


def test_resolver_falls_back_to_secondary_and_caches(monkeypatch):
    original_cache = app_dns._cache.copy()
    calls = []

    def query(connect_ip, server_name, host, timeout):
        calls.append((connect_ip, server_name, host, timeout))
        return [] if len(calls) == 1 else ["203.0.113.42"]

    monkeypatch.setattr(app_dns, "_query_endpoint", query)
    app_dns._cache.clear()
    try:
        assert app_dns.resolve("example.com", timeout=1.5) == ["203.0.113.42"]
        assert app_dns.resolve("example.com", timeout=1.5) == ["203.0.113.42"]
        assert [call[0] for call in calls] == ["1.1.1.1", "8.8.8.8"]
    finally:
        app_dns._cache.clear()
        app_dns._cache.update(original_cache)


def test_direct_connection_keeps_verified_tls_hostname_separate_from_ip(monkeypatch):
    context = app_dns.ssl.create_default_context()
    assert context.check_hostname is True
    assert context.verify_mode == app_dns.ssl.CERT_REQUIRED
    raw, secured = object(), object()
    calls = []
    monkeypatch.setattr(app_dns, "_tls_context", lambda: context)
    monkeypatch.setattr(
        app_dns.socket, "create_connection",
        lambda address, timeout: calls.append(("connect", address, timeout)) or raw,
    )
    monkeypatch.setattr(
        context, "wrap_socket",
        lambda sock, server_hostname: calls.append(("tls", sock, server_hostname)) or secured,
    )
    connection = app_dns._DirectHttpsConnection("8.8.8.8", "dns.google", 1.5)
    connection.connect()
    assert connection.host == "dns.google"
    assert connection.sock is secured
    assert calls == [("connect", ("8.8.8.8", 443), 1.5), ("tls", raw, "dns.google")]


def test_endpoint_uses_bounded_wire_post_and_closes_on_rejected_replies(monkeypatch):
    query = app_dns.build_a_query("example.com", 0x1234)
    cases = (
        (200, "application/dns-message", _response(query), ["203.0.113.42"]),
        (503, "application/dns-message", _response(query), []),
        (302, "application/dns-message", _response(query), []),
        (200, "text/html", b"not DNS", []),
        (200, "application/dns-message", b"x" * (app_dns.APP_DOH_MAX_RESPONSE + 1), []),
    )
    monkeypatch.setattr(app_dns.secrets, "randbits", lambda bits: 0x1234)
    for status, content_type, packet, expected in cases:
        calls = []

        class Connection:
            def __init__(self, ip, name, timeout):
                calls.append((ip, name, timeout))

            def request(self, method, path, *, body, headers):
                calls.append((method, path, body, headers))

            def getresponse(self):
                return self

            def getheader(self, _name):
                return content_type

            def read(self, limit):
                assert limit == app_dns.APP_DOH_MAX_RESPONSE + 1
                return packet

            def close(self):
                calls.append("closed")

        Connection.status = status
        monkeypatch.setattr(app_dns, "_DirectHttpsConnection", Connection)
        assert app_dns._query_endpoint("1.1.1.1", "cloudflare-dns.com", "example.com", 1.5) == expected
        assert calls == [
            ("1.1.1.1", "cloudflare-dns.com", 1.5),
            ("POST", "/dns-query", query, {
                "Accept": "application/dns-message", "Content-Type": "application/dns-message",
            }),
            "closed",
        ]


def test_both_provider_failures_are_bounded_and_negatively_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(app_dns, "_cache", app_dns.OrderedDict())
    monkeypatch.setattr(
        app_dns, "_query_endpoint",
        lambda ip, name, host, timeout: calls.append((ip, name, host, timeout)) or [],
    )
    assert app_dns.resolve("Example.COM.", timeout=1.5) == []
    assert app_dns.resolve("example.com", timeout=1.5) == []
    assert calls == [
        ("1.1.1.1", "cloudflare-dns.com", "example.com", 1.5),
        ("8.8.8.8", "dns.google", "example.com", 1.5),
    ]


def test_cache_expiry_and_capacity_remain_bounded(monkeypatch):
    calls = []
    now = [100.0]
    monkeypatch.setattr(app_dns, "_cache", app_dns.OrderedDict())
    monkeypatch.setattr(app_dns, "APP_DOH_CACHE_MAX", 2)
    monkeypatch.setattr(app_dns.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        app_dns, "_query_endpoint",
        lambda _ip, _name, host, _timeout: calls.append(host) or ["203.0.113.42"],
    )
    for host in ("one.example", "two.example", "three.example"):
        assert app_dns.resolve(host) == ["203.0.113.42"]
    assert list(app_dns._cache) == ["two.example", "three.example"]
    assert app_dns.resolve("two.example") == ["203.0.113.42"]
    assert len(calls) == 3
    now[0] += app_dns.APP_DOH_TTL + 1
    assert app_dns.resolve("two.example") == ["203.0.113.42"]
    assert calls == ["one.example", "two.example", "three.example", "two.example"]
    assert len(app_dns._cache) == 2

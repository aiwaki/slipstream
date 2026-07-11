import struct

import xbox_dns


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
    query = xbox_dns.build_a_query("Example.COM.", 0x1234)

    assert struct.unpack("!H", query[:2])[0] == 0x1234
    assert xbox_dns.parse_a_response(_response(query), 0x1234) == ["203.0.113.42"]


def test_tls_context_prefers_system_ca_bundle_without_disabling_verification(monkeypatch):
    calls = []

    monkeypatch.setattr(xbox_dns.os.path, "isfile", lambda path: path == "/tmp/ca.pem")
    monkeypatch.setattr(xbox_dns, "SYSTEM_CA_BUNDLE", "/tmp/ca.pem")
    monkeypatch.setattr(
        xbox_dns.ssl,
        "create_default_context",
        lambda **kwargs: calls.append(kwargs) or object(),
    )

    xbox_dns._tls_context()

    assert calls == [{"cafile": "/tmp/ca.pem"}]


def test_parse_rejects_mismatched_or_failed_response():
    query = xbox_dns.build_a_query("example.com", 0x1234)
    packet = bytearray(_response(query))

    assert xbox_dns.parse_a_response(packet, 0x4321) == []

    packet[3] = 0x83
    assert xbox_dns.parse_a_response(packet, 0x1234) == []


def test_resolver_falls_back_to_secondary_and_caches(monkeypatch):
    original_cache = xbox_dns._cache.copy()
    calls = []

    def query(connect_ip, server_name, host, timeout):
        calls.append((connect_ip, server_name, host, timeout))
        return [] if len(calls) == 1 else ["203.0.113.42"]

    monkeypatch.setattr(xbox_dns, "_query_endpoint", query)
    xbox_dns._cache.clear()
    try:
        assert xbox_dns.resolve("example.com", timeout=1.5) == ["203.0.113.42"]
        assert xbox_dns.resolve("example.com", timeout=1.5) == ["203.0.113.42"]
        assert [call[0] for call in calls] == ["111.88.96.50", "111.88.96.51"]
    finally:
        xbox_dns._cache.clear()
        xbox_dns._cache.update(original_cache)

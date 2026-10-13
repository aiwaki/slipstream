"""The local Googlevideo reserve must preserve TLS and stay host-scoped."""
import ssl

import pytest
import tproxy


HOST = "rr18---sn-n8v7znse.googlevideo.com"
MODE = "youtube_record256"


def hello(host=HOST):
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"] + [str(i) + "x" * 199 for i in range(6)])
    outgoing = ssl.MemoryBIO()
    client = context.wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname=host)
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    return outgoing.read()


def test_large_clienthello_preserves_complete_transcript():
    flight = hello()
    parts = tproxy._reserve_flight_parts(flight, HOST, MODE)
    assert len(parts) > 1
    assert all(0 < len(part) <= 512 for part in parts)
    wire = b"".join(parts)
    bodies = []
    while wire:
        assert wire[:3] == flight[:3]
        length = int.from_bytes(wire[3:5], "big")
        assert 0 < length <= 256
        bodies.append(wire[5:5 + length])
        wire = wire[5 + length:]
    assert b"".join(bodies) == flight[5:]


@pytest.mark.parametrize("host", ["discord.com", "youtube.com", "example.com",
                                  "googlevideo.com.example.com"])
def test_reserve_does_not_apply_to_other_hosts(host):
    flight = hello(host)
    assert tproxy._reserve_flight_parts(flight, host, MODE) == (flight,)
    assert "youtube_record256_fake" not in [s["name"] for s in tproxy.strategy_order(host)]


def test_reserve_keeps_direct_first_and_remains_local(monkeypatch):
    monkeypatch.setattr(tproxy, "_direct_first_local_fallback_active", lambda h: False)
    monkeypatch.setattr(tproxy, "_rank_strategy_names", lambda h, names: names)
    monkeypatch.setattr(tproxy, "_strat_cache", {})
    order = tproxy.strategy_order(HOST)
    assert order[0]["name"] == "plain"
    assert order[1]["name"] == "youtube_record256_fake"
    assert order[1]["fake"] is True
    assert order[1]["cap"] is None


def test_unknown_fragmented_or_trailing_records_pass_unchanged():
    flight = hello()
    variants = [flight[:3], flight[:-1], flight + b"\x14\x03\x03\x00\x01\x01",
                b"\x17" + flight[1:], flight[:5] + b"\x02" + flight[6:]]
    for malformed in variants:
        assert tproxy._reserve_flight_parts(malformed, HOST, MODE) == (malformed,)
    assert tproxy._reserve_flight_parts(flight, "other.googlevideo.com", MODE) == (flight,)

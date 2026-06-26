import struct

from primes import (
    classify, build_fake_stun, build_fake_discord_prime, STUN_MAGIC_COOKIE,
)


def test_classify_stun():
    p = struct.pack("!HHI", 0x0001, 0, STUN_MAGIC_COOKIE) + b"\x00" * 12
    assert classify(p) == "stun"


def test_classify_ip_discovery():
    p = b"\x00\x01\x00\x46" + b"\x00" * 70
    assert len(p) == 74
    assert classify(p) == "ip-discovery"


def test_classify_rtp():
    p = bytes([0x80, 0x78]) + b"\x00" * 20
    assert classify(p) == "rtp"


def test_classify_other():
    assert classify(b"hello") == "other"


def test_build_fake_stun_has_magic_cookie():
    p = build_fake_stun()
    assert p[4:8] == struct.pack("!I", STUN_MAGIC_COOKIE)
    assert classify(p) == "stun"


def test_build_fake_stun_is_binding_request():
    p = build_fake_stun()
    msg_type, length = struct.unpack("!HH", p[:4])
    assert msg_type == 0x0001  # Binding Request
    assert length == 0
    assert len(p) == 20


def test_build_fake_discord_prime_size_and_deterministic():
    a = build_fake_discord_prime(70)
    b = build_fake_discord_prime(70)
    assert len(a) == 70
    assert a == b  # deterministic, so tests/golden vectors are stable

"""Pure packet-building + classification logic for the voice de-risk spike.
Byte-exact and unit-tested; becomes the Rust `bypass-engine` golden vectors.
No I/O here."""

import struct

STUN_MAGIC_COOKIE = 0x2112A442


def classify(payload: bytes) -> str:
    """Classify a UDP payload: 'stun' | 'ip-discovery' | 'rtp' | 'other'.

    Heuristics from sonicdpi (transport-agnostic). Order matters:
    ip-discovery is checked before rtp because both are short.
    """
    n = len(payload)
    if n == 74 and payload[:4] == b"\x00\x01\x00\x46":
        return "ip-discovery"
    if n >= 20 and payload[4:8] == struct.pack("!I", STUN_MAGIC_COOKIE):
        return "stun"
    if n >= 12 and payload[0] in (0x80, 0x90) and payload[1] in (0x78, 0xF8):
        return "rtp"
    return "other"


def build_fake_stun(txn_id: bytes = b"\x00" * 12) -> bytes:
    """Minimal STUN Binding Request decoy: type=0x0001, len=0, magic cookie,
    12-byte transaction id. 20 bytes total."""
    assert len(txn_id) == 12
    return struct.pack("!HHI", 0x0001, 0x0000, STUN_MAGIC_COOKIE) + txn_id


def build_fake_discord_prime(size: int = 70) -> bytes:
    """Opaque decoy datagram resembling an early Discord voice-setup packet.
    Deterministic content (stable golden vector). TSPU only needs a plausible
    early-flow datagram to mis-track the connection."""
    assert size >= 4
    head = b"\x00\x01\x00\x46"
    return head + bytes((i * 7) & 0xFF for i in range(size - 4))

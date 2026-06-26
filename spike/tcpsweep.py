#!/usr/bin/env python3
"""tcpsweep — TCP DPI-desync auto-sweep probe (Spike 1, THROWAWAY).

Proves, with NO root / NO VPN / NO pf, that the network's Discord-gateway block
is beatable from macOS userland, and finds WHICH desync strategy beats it. This
is the prototype of the product's launch-time auto-strategy picker.

How: for each (host, strategy) we open a plain TCP socket and drive a real TLS
handshake via `ssl.MemoryBIO`, but we control the wire writes of the ClientHello
so we can fragment it (DPI can't read the SNI -> can't block). If the TLS
handshake completes, the strategy beats the DPI for that host.

`baseline` (no desync) is the control: it should FAIL on a truly blocked host,
which proves the probe actually detects the block.

Run (no sudo needed):
    python3 tcpsweep.py
    python3 tcpsweep.py gateway.discord.gg discord.com www.youtube.com
"""
import socket
import ssl
import struct
import sys
import time

DEFAULT_HOSTS = [
    "gateway.discord.gg",   # the blocked WSS gateway — primary signal
    "discord.com",          # web/api
    "cdn.discordapp.com",   # cdn
    "www.youtube.com",      # note: YouTube is throttled, not hard-blocked
]
PORT = 443
TIMEOUT = 6.0


# --- ClientHello transforms (applied to the first outbound TLS flight) ---

def _host_pos(data: bytes, host: str) -> int:
    """Byte offset to cut at: middle of the SNI hostname inside the record."""
    i = data.find(host.encode())
    if i < 0:
        i = len(data) // 2
    return i + max(1, len(host) // 2)


def t_baseline(sock, data, host):
    sock.sendall(data)


def t_split_sni(sock, data, host):
    pos = _host_pos(data, host)
    sock.sendall(data[:pos])
    sock.sendall(data[pos:])


def t_split2(sock, data, host):
    sock.sendall(data[:2])
    sock.sendall(data[2:])


def t_multisplit(sock, data, host):
    pos = _host_pos(data, host)
    cuts = sorted({2, pos // 2, pos, min(len(data) - 1, pos + 8)})
    prev = 0
    for c in cuts:
        if c <= prev or c >= len(data):
            continue
        sock.sendall(data[prev:c])
        prev = c
    sock.sendall(data[prev:])


def t_tlsrec_sni(sock, data, host):
    """Split the single ClientHello TLS record into TWO records, cut inside the
    SNI. Pure application-layer; very high-yield, zero privilege."""
    if data[0:1] != b"\x16" or len(data) < 6:
        return t_split_sni(sock, data, host)  # not a TLS record; fall back
    typ, ver, body = data[0:1], data[1:3], data[5:]
    pos = max(1, min(len(body) - 1, _host_pos(data, host) - 5))
    a, b = body[:pos], body[pos:]

    def rec(payload):
        return typ + ver + struct.pack("!H", len(payload)) + payload

    sock.sendall(rec(a) + rec(b))


STRATEGIES = {
    "baseline": t_baseline,
    "split_sni": t_split_sni,
    "split2": t_split2,
    "multisplit": t_multisplit,
    "tlsrec_sni": t_tlsrec_sni,
}


def probe(host: str, transform, timeout: float = TIMEOUT) -> str:
    """Return 'ok' | 'fail' | 'timeout' | 'refused' | 'err:<x>'."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inbio, outbio = ssl.MemoryBIO(), ssl.MemoryBIO()
    sslobj = ctx.wrap_bio(inbio, outbio, server_hostname=host)
    try:
        s = socket.create_connection((host, PORT), timeout=timeout)
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError as e:
        return f"err:{e.errno}"
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(timeout)
    sent_ch = [False]
    try:
        while True:
            try:
                sslobj.do_handshake()
                return "ok"
            except ssl.SSLWantReadError:
                out = outbio.read()
                if out:
                    if not sent_ch[0]:
                        transform(s, out, host)
                        sent_ch[0] = True
                    else:
                        s.sendall(out)
                try:
                    resp = s.recv(65536)
                except socket.timeout:
                    return "timeout"
                if not resp:
                    return "fail"
                inbio.write(resp)
            except ssl.SSLError:
                return "fail"
            except (ConnectionResetError, BrokenPipeError, OSError):
                return "fail"
    finally:
        s.close()


def main():
    hosts = sys.argv[1:] or DEFAULT_HOSTS
    names = list(STRATEGIES)
    print(f"tcpsweep: {len(hosts)} hosts x {len(names)} strategies "
          f"(no root/VPN). port {PORT}, timeout {TIMEOUT}s\n")
    header = f"{'host':24}" + "".join(f"{n:12}" for n in names)
    print(header)
    print("-" * len(header))
    winners = {}
    for host in hosts:
        row = f"{host:24}"
        for name in names:
            t0 = time.time()
            r = probe(host, STRATEGIES[name])
            dt = int((time.time() - t0) * 1000)
            row += f"{(r + f'/{dt}ms'):12}"
            if name != "baseline" and r == "ok" and host not in winners:
                winners[host] = name
        print(row)
    print("\n=== winners (first non-baseline strategy that completed TLS) ===")
    for host in hosts:
        base = probe(host, STRATEGIES["baseline"])
        w = winners.get(host)
        verdict = (f"WIN via '{w}'" if w else "no strategy worked")
        print(f"{host:24} baseline={base:10} -> {verdict}")
    print("\nIf baseline=ok on a host, it is NOT blocked (DPI not on that path).")
    print("If baseline=fail but a strategy=ok, that strategy beats the DPI here.")


if __name__ == "__main__":
    sys.exit(main())

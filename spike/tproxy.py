#!/usr/bin/env python3
"""tproxy — TRANSPARENT tlsrec proxy via pf rdr (Spike 4, needs root).

A SOCKS proxy cannot catch the Discord desktop UPDATER (Squirrel ignores
--proxy-server and the system SOCKS proxy), and browsers slip past it over QUIC.
A transparent pf redirect catches ALL local TCP/443 from every app — browser,
Discord, the updater — with no per-app config, and blocks QUIC (UDP/443) so
nothing escapes over HTTP/3. Reuses the proven tlsrec engine.

Run:   sudo python3 tproxy.py [--verbose]
Stop:  Ctrl-C  (auto-restores pf + connectivity)

ESCAPE HATCH (if connectivity ever breaks): run in another terminal
    sudo pfctl -f /etc/pf.conf ; sudo pfctl -d
"""
import argparse
import asyncio
import atexit
import fcntl
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile

PROXY_PORT = 1080
DIOCNATLOOK = 0xC0544417          # _IOWR('D',23,struct pfioc_natlook), macOS
PF_OUT = 2
VERBOSE = False

PF_RULES = """\
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port {port}
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 443 user != root
block drop quick inet proto udp from any to any port 443
"""

_pf_applied = False
_pf_fd = None


def _run(*args):
    return subprocess.run(list(args), capture_output=True, text=True)


def pf_setup(port):
    global _pf_applied
    # Always start from a clean default ruleset (in case a prior crash left ours).
    _run("pfctl", "-f", "/etc/pf.conf")
    f = tempfile.NamedTemporaryFile("w", suffix=".slipstream.pf.conf", delete=False)
    f.write(PF_RULES.format(port=port))
    f.close()
    _run("pfctl", "-E")
    r = _run("pfctl", "-f", f.name)
    if r.returncode != 0:
        print("pfctl load failed:\n" + r.stderr, file=sys.stderr)
        sys.exit(1)
    _pf_applied = True
    print(f">> pf active: all TCP/443 -> 127.0.0.1:{port}; QUIC (UDP/443) blocked")


def pf_teardown():
    global _pf_applied
    if not _pf_applied:
        return
    _run("pfctl", "-f", "/etc/pf.conf")
    _run("pfctl", "-d")
    _pf_applied = False
    print(">> pf restored")


def orig_dst(sock):
    """Recover the original destination of a pf-rdr'd connection via DIOCNATLOOK.

    struct pfioc_natlook (macOS, 84 bytes):
      0  saddr  pf_addr(16)   16 daddr pf_addr(16)
      32 rsaddr pf_addr(16)   48 rdaddr pf_addr(16)   <- result we want
      64 sxport 68 dxport 72 rsxport 76 rdxport (each 4)
      80 af  81 proto  82 proto_variant  83 direction
    """
    peer = sock.getpeername()    # client source ip:port
    local = sock.getsockname()   # 127.0.0.1 : proxy_port (rdr target)
    buf = bytearray(84)
    buf[0:4] = socket.inet_aton(peer[0])
    buf[16:20] = socket.inet_aton(local[0])
    struct.pack_into("!H", buf, 64, peer[1])
    struct.pack_into("!H", buf, 68, local[1])
    buf[80] = socket.AF_INET
    buf[81] = socket.IPPROTO_TCP
    buf[83] = PF_OUT
    fcntl.ioctl(_pf_fd, DIOCNATLOOK, buf, True)
    ip = socket.inet_ntoa(bytes(buf[48:52]))
    port = struct.unpack_from("!H", buf, 76)[0]
    return ip, port


def parse_sni(body: bytes):
    """Extract SNI hostname from a ClientHello handshake body (after the 5-byte
    TLS record header). Returns hostname or None."""
    try:
        p = 4 + 2 + 32                       # hs header + version + random
        p += 1 + body[p]                     # session id
        p += 2 + struct.unpack_from("!H", body, p)[0]   # cipher suites
        p += 1 + body[p]                     # compression methods
        ext_end = p + 2 + struct.unpack_from("!H", body, p)[0]
        p += 2
        while p + 4 <= ext_end:
            etype, elen = struct.unpack_from("!HH", body, p)
            p += 4
            if etype == 0:                   # server_name
                np = p + 2 + 1               # list len + name type
                nlen = struct.unpack_from("!H", body, np)[0]
                np += 2
                return body[np:np + nlen].decode("ascii", "replace")
            p += elen
    except Exception:
        pass
    return None


FIRST_REC_CAP = 64


def tlsrec_records(head: bytes, body: bytes, host):
    """Tiny first record (defeats this TSPU) + a cut inside the SNI if known."""
    typ, ver = head[0:1], head[1:3]
    n = len(body)
    i = body.find(host.encode()) if host else -1
    if i < 0:
        i = max(2, n // 3)
    c1 = min(FIRST_REC_CAP, max(1, i - 1))
    c2 = min(n - 1, i + (max(1, len(host) // 2) if host else 8))
    cuts = sorted(c for c in {c1, c2} if 0 < c < n)
    parts, prev = [], 0
    for c in cuts:
        if c > prev:
            parts.append(body[prev:c])
            prev = c
    parts.append(body[prev:])
    mk = lambda p: typ + ver + struct.pack("!H", len(p)) + p
    return b"".join(mk(p) for p in parts), [len(p) for p in parts]


async def client_to_upstream(reader, up_w):
    try:
        head = await reader.readexactly(5)
        if head[0] == 0x16:
            body = await reader.readexactly(struct.unpack("!H", head[3:5])[0])
            host = parse_sni(body)
            blob, sizes = tlsrec_records(head, body, host)
            if VERBOSE:
                print(f"  tlsrec {host}: -> {sizes}", file=sys.stderr)
            up_w.write(blob)
        else:
            up_w.write(head)
        await up_w.drain()
        while True:
            data = await reader.read(65536)
            if not data:
                break
            up_w.write(data)
            await up_w.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            up_w.close()
        except Exception:
            pass


async def splice(src, dst):
    total = 0
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            total += len(data)
            dst.write(data)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass
    return total


async def handle(reader, writer):
    sock = writer.get_extra_info("socket")
    try:
        dst_ip, dst_port = orig_dst(sock)
    except OSError as e:
        if VERBOSE:
            print(f"  DIOCNATLOOK failed: {e}", file=sys.stderr)
        writer.close()
        return
    # loop guard: never re-proxy to ourselves
    if dst_port == PROXY_PORT and dst_ip.startswith("127."):
        writer.close()
        return
    try:
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(dst_ip, dst_port, family=socket.AF_INET),
            timeout=10)
    except Exception as e:
        if VERBOSE:
            print(f"  upstream {dst_ip}:{dst_port} failed: {e}", file=sys.stderr)
        writer.close()
        return
    if VERBOSE:
        print(f"CONNECT {dst_ip}:{dst_port}", file=sys.stderr)
    res = await asyncio.gather(client_to_upstream(reader, up_w), splice(up_r, writer))
    if VERBOSE:
        srv = res[1] or 0
        print(f"  {dst_ip}:{dst_port} server_bytes={srv} "
              f"{'OK' if srv > 0 else 'NO RESPONSE'}", file=sys.stderr)


async def amain(port):
    server = await asyncio.start_server(handle, "127.0.0.1", port)
    print(f">> transparent tlsrec proxy on 127.0.0.1:{port}  (root)")
    print(">> launch/quit Discord normally — its updater is now captured too")
    print(">> Ctrl-C to stop and restore pf")
    async with server:
        await server.serve_forever()


def main():
    global VERBOSE, _pf_fd
    if os.geteuid() != 0:
        print("must run as root:  sudo python3 tproxy.py", file=sys.stderr)
        sys.exit(1)
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PROXY_PORT)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    atexit.register(pf_teardown)
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: (pf_teardown(), sys.exit(0)))

    _pf_fd = os.open("/dev/pf", os.O_RDWR)
    pf_setup(args.port)
    try:
        asyncio.run(amain(args.port))
    except KeyboardInterrupt:
        pass
    finally:
        pf_teardown()


if __name__ == "__main__":
    main()

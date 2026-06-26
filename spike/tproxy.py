#!/usr/bin/env python3
"""tproxy — TRANSPARENT tlsrec proxy + DoH via pf rdr (Spike 4, needs root).

Two blocks were found on the target network:
  1. SNI DPI  -> beaten by tlsrec (tiny first TLS record).
  2. DNS poisoning -> blocked domains resolve to a stub IP (87.228.47.x) with no
     real server, so desync is useless. Beaten by re-resolving the SNI over DoH
     (DNS-over-HTTPS) and connecting to the REAL IP.

A transparent pf redirect captures ALL local TCP/443 (browser, Discord, the
updater) with no per-app config and blocks QUIC. For each connection we read the
ClientHello, parse the SNI, DoH-resolve it to the real IP, then forward a
tlsrec-split ClientHello to that real IP.

Run:   sudo python3 tproxy.py [--verbose]
Stop:  Ctrl-C  (auto-restores pf + connectivity)
ESCAPE HATCH if connectivity breaks (other terminal):
    sudo pfctl -f /etc/pf.conf ; sudo pfctl -d
"""
import argparse
import asyncio
import atexit
import fcntl
import json
import os
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

PROXY_PORT = 1080
DIOCNATLOOK = 0xC0544417
PF_OUT = 2
FIRST_REC_CAP = 64
VERBOSE = False

# DoH resolvers (connect by IP, no bootstrap DNS needed). SNI may itself be
# DPI-blocked -> we tlsrec its ClientHello too.
DOH = [("1.1.1.1", "cloudflare-dns.com"), ("8.8.8.8", "dns.google")]

PF_RULES = """\
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port {port}
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 443 user != root
block drop quick inet proto udp from any to any port 443
"""

_pf_applied = False
_pf_fd = None
_doh_cache = {}


# ---------------------------------------------------------------- pf plumbing
def _run(*args):
    return subprocess.run(list(args), capture_output=True, text=True)


def pf_setup(port):
    global _pf_applied
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
    peer = sock.getpeername()
    local = sock.getsockname()
    buf = bytearray(84)
    buf[0:4] = socket.inet_aton(peer[0])
    buf[16:20] = socket.inet_aton(local[0])
    struct.pack_into("!H", buf, 64, peer[1])
    struct.pack_into("!H", buf, 68, local[1])
    buf[80] = socket.AF_INET
    buf[81] = socket.IPPROTO_TCP
    buf[83] = PF_OUT
    fcntl.ioctl(_pf_fd, DIOCNATLOOK, buf, True)
    return socket.inet_ntoa(bytes(buf[48:52])), struct.unpack_from("!H", buf, 76)[0]


# ------------------------------------------------------------- TLS / desync
def parse_sni(body: bytes):
    try:
        p = 4 + 2 + 32
        p += 1 + body[p]
        p += 2 + struct.unpack_from("!H", body, p)[0]
        p += 1 + body[p]
        ext_end = p + 2 + struct.unpack_from("!H", body, p)[0]
        p += 2
        while p + 4 <= ext_end:
            etype, elen = struct.unpack_from("!HH", body, p)
            p += 4
            if etype == 0:
                np = p + 2 + 1
                nlen = struct.unpack_from("!H", body, np)[0]
                return body[np + 2:np + 2 + nlen].decode("ascii", "replace")
            p += elen
    except Exception:
        pass
    return None


def tlsrec_blob(head: bytes, body: bytes, host):
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
    return b"".join(mk(p) for p in parts)


# ------------------------------------------------------------- DoH (blocking)
def _doh_query(doh_ip, doh_sni, host, timeout=6):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inbio, outbio = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inbio, outbio, server_hostname=doh_sni)
    s = socket.create_connection((doh_ip, 443), timeout=timeout)
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sent = [False]
    try:
        while True:                                   # handshake (tlsrec first flight)
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                out = outbio.read()
                if out:
                    if not sent[0]:
                        s.sendall(tlsrec_blob(out[:5], out[5:], doh_sni)
                                  if out[:1] == b"\x16" else out)
                        sent[0] = True
                    else:
                        s.sendall(out)
                data = s.recv(65536)
                if not data:
                    raise IOError("eof in handshake")
                inbio.write(data)
        req = (f"GET /dns-query?name={host}&type=A HTTP/1.1\r\n"
               f"Host: {doh_sni}\r\naccept: application/dns-json\r\n"
               f"connection: close\r\n\r\n").encode()
        obj.write(req)
        while True:
            out = outbio.read()
            if not out:
                break
            s.sendall(out)
        buf = b""
        while True:
            try:
                data = s.recv(65536)
            except socket.timeout:
                break
            if data:
                inbio.write(data)
            while True:
                try:
                    dec = obj.read(65536)
                except ssl.SSLWantReadError:
                    break
                except ssl.SSLError:
                    dec = b""
                if not dec:
                    break
                buf += dec
            if not data:
                break
        s.close()
        j = buf.find(b"{")
        doc = json.loads(buf[j:buf.rfind(b"}") + 1])
        for ans in doc.get("Answer", []):
            if ans.get("type") == 1:
                return ans["data"]
    except Exception:
        try:
            s.close()
        except Exception:
            pass
    return None


def doh_resolve(host):
    if host in _doh_cache:
        return _doh_cache[host]
    for ip, sni in DOH:
        r = _doh_query(ip, sni, host)
        if r:
            _doh_cache[host] = r
            return r
    _doh_cache[host] = None
    return None


# ------------------------------------------------------------- relay
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


async def pump(reader, up_w):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            up_w.write(data)
            await up_w.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            up_w.close()
        except Exception:
            pass


async def handle(reader, writer):
    sock = writer.get_extra_info("socket")
    try:
        dst_ip, dst_port = orig_dst(sock)
    except OSError as e:
        if VERBOSE:
            print(f"  DIOCNATLOOK failed: {e}", file=sys.stderr)
        writer.close()
        return
    if dst_port == PROXY_PORT and dst_ip.startswith("127."):
        writer.close()
        return

    # read the client's first flight to learn the SNI BEFORE dialing upstream
    host = None
    first = b""
    try:
        head = await asyncio.wait_for(reader.readexactly(5), timeout=15)
        if head[0] == 0x16:
            body = await reader.readexactly(struct.unpack("!H", head[3:5])[0])
            host = parse_sni(body)
            first = tlsrec_blob(head, body, host)
        else:
            first = head + await reader.read(65536)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        writer.close()
        return

    # de-poison: resolve the SNI over DoH, connect to the REAL ip (fallback dst_ip)
    real_ip = dst_ip
    if host:
        r = await asyncio.to_thread(doh_resolve, host)
        if r:
            real_ip = r

    try:
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(real_ip, dst_port, family=socket.AF_INET),
            timeout=10)
    except Exception as e:
        if VERBOSE:
            print(f"  upstream {host or dst_ip} {real_ip}:{dst_port} failed: {e}",
                  file=sys.stderr)
        writer.close()
        return

    poisoned = host and real_ip != dst_ip
    if VERBOSE:
        tag = f" (de-poisoned {dst_ip}->{real_ip})" if poisoned else ""
        print(f"CONNECT {host or dst_ip}:{dst_port}{tag}", file=sys.stderr)

    up_w.write(first)
    try:
        await up_w.drain()
    except OSError:
        writer.close()
        return
    res = await asyncio.gather(pump(reader, up_w), splice(up_r, writer))
    if VERBOSE:
        srv = res[1] or 0
        print(f"  {host or dst_ip} server_bytes={srv} "
              f"{'OK' if srv > 0 else 'NO RESPONSE'}", file=sys.stderr)


async def amain(port):
    server = await asyncio.start_server(handle, "127.0.0.1", port)
    print(f">> transparent tlsrec+DoH proxy on 127.0.0.1:{port}  (root)")
    print(">> quit + reopen Discord normally; its updater is captured too")
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

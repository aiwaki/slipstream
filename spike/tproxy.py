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
import threading
import time

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


def cleanup_stale():
    """Self-heal: kill any leftover tproxy instances (e.g. a Ctrl+Z-suspended
    one still holding the port) and reset pf to the clean default, so a fresh
    start always works without manual lsof/kill/escape."""
    me, parent = os.getpid(), os.getppid()
    res = _run("pgrep", "-f", "tproxy.py")
    killed = 0
    for line in res.stdout.split():
        try:
            pid = int(line)
        except ValueError:
            continue
        if pid not in (me, parent):
            _run("kill", "-9", str(pid))
            killed += 1
    _run("pfctl", "-f", "/etc/pf.conf")     # drop any stale rules from a crash
    if killed:
        print(f">> self-heal: killed {killed} stale tproxy instance(s), reset pf")


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


def tlsrec_blob(head: bytes, body: bytes, host, variant: int = 0):
    """Tiny first record (defeats this TSPU) + a cut inside the SNI if known.

    `variant` changes the geometry so retries try a different split (the DPI is
    probabilistic; a second geometry often succeeds where the first failed)."""
    typ, ver = head[0:1], head[1:3]
    n = len(body)
    i = body.find(host.encode()) if host else -1
    if i < 0:
        i = max(2, n // 3)
    cap = (64, 16, 5)[variant % 3]              # progressively tinier first record
    c1 = min(cap, max(1, i - 1))
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


# --------------------------------------------------- fake ClientHello (decoy)
FAKE_DECOY_SNI = "vk.com"   # RU whitelisted host the TSPU never blocks


def build_fake_clienthello(sni: str) -> bytes:
    """Minimal but parseable TLS1.2 ClientHello carrying a decoy SNI. Sent at a
    low TTL so it dies before the server but the in-country DPI ingests it and
    whitelists the flow, letting the real (hard-blocked-SNI) ClientHello pass."""
    name = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(name)) + name      # host_name entry
    sni_list = struct.pack("!H", len(server_name)) + server_name
    sni_ext = b"\x00\x00" + struct.pack("!H", len(sni_list)) + sni_list
    ext_block = struct.pack("!H", len(sni_ext)) + sni_ext
    ciphers = b"\x00\x2f"
    cl_body = (b"\x03\x03" + os.urandom(32) + b"\x00"
               + struct.pack("!H", len(ciphers)) + ciphers
               + b"\x01\x00" + ext_block)
    hs = b"\x01" + struct.pack("!I", len(cl_body))[1:] + cl_body      # 3-byte length
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


_FAKE_CH = build_fake_clienthello(FAKE_DECOY_SNI)


def inject_fake(src_ip, src_port, dst_ip, dst_port, ttl=4, repeats=3):
    """Spray a few decoy-SNI ClientHello packets at low TTL on the real 4-tuple.
    Needs scapy (run via the venv python). No-op with a warning if unavailable."""
    try:
        from scapy.all import IP, TCP, Raw, send
    except Exception:
        print("  fake-mode needs scapy: run with sudo .venv/bin/python tproxy.py",
              file=sys.stderr)
        return
    pkt = (IP(src=src_ip, dst=dst_ip, ttl=ttl)
           / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1, ack=1)
           / Raw(_FAKE_CH))
    for _ in range(repeats):
        send(pkt, verbose=0)


# ------------------------------------------------------- UDP voice plane
VOICE_LO, VOICE_HI = 50000, 65535   # Discord voice server UDP port range
VOICE_TTL = 4
VOICE_REPEAT = 6
VOICE_CUTOFF = 5                    # prime the first N datagrams of each flow


def _fake_stun(txn=b"\x00" * 12):
    return struct.pack("!HHI", 0x0001, 0x0000, 0x2112A442) + txn   # STUN binding req


def voice_plane(iface):
    """Discord voice is UDP RTP to *.discord.media:50000-65535 — it bypasses the
    TCP pf-rdr and the TSPU drops it. We can't sit inline on UDP without a NE, so
    (Spike 0 model) passively sniff outbound voice via BPF and raw-inject low-TTL
    decoy STUN datagrams on the same 5-tuple to poison the DPI's classification,
    leaving the real flow untouched."""
    try:
        from scapy.all import sniff, send, IP, UDP, Raw, get_if_addr
    except Exception as e:
        print(f">> voice plane disabled (scapy: {e})", file=sys.stderr)
        return
    try:
        localip = get_if_addr(iface)
    except Exception:
        print(">> voice plane disabled (no iface addr)", file=sys.stderr)
        return
    fake = _fake_stun()
    flows = {}
    bpf = (f"udp and src host {localip} and dst portrange {VOICE_LO}-{VOICE_HI} "
           "and not dst net 192.168.0.0/16 and not dst net 10.0.0.0/8 "
           "and not dst net 172.16.0.0/12 and not dst net 169.254.0.0/16 "
           "and not dst net 224.0.0.0/4 and not dst host 255.255.255.255")

    def on_pkt(p):
        if not (p.haslayer(IP) and p.haslayer(UDP)):
            return
        ip, udp = p[IP], p[UDP]
        key = (ip.src, udp.sport, ip.dst, udp.dport)
        n = flows.get(key, 0)
        if n >= VOICE_CUTOFF:
            return
        flows[key] = n + 1
        pkt = (IP(src=ip.src, dst=ip.dst, ttl=VOICE_TTL)
               / UDP(sport=udp.sport, dport=udp.dport) / Raw(fake))
        for _ in range(VOICE_REPEAT):
            send(pkt, verbose=0)
        if VERBOSE and n == 0:
            print(f"  voice: priming {ip.dst}:{udp.dport}", file=sys.stderr)

    print(f">> voice plane: priming UDP {VOICE_LO}-{VOICE_HI} on {iface}")
    sniff(iface=iface, filter=bpf, prn=on_pkt, store=0)


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
        ips = [a["data"] for a in doc.get("Answer", []) if a.get("type") == 1]
        if ips:
            return ips
    except Exception:
        try:
            s.close()
        except Exception:
            pass
    return None


def doh_resolve(host):
    """Return a LIST of real A-record IPs (so we can try several — some specific
    Cloudflare IPs are IP-blocked on the target network while others aren't)."""
    if host in _doh_cache:
        return _doh_cache[host]
    for ip, sni in DOH:
        r = _doh_query(ip, sni, host)
        if r:
            _doh_cache[host] = r
            return r
    _doh_cache[host] = []
    return []


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
    total = 0
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            total += len(data)
            up_w.write(data)
            await up_w.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            up_w.close()
        except Exception:
            pass
    return total


async def dial_and_probe(real_ip, port, first_blob, probe_timeout=2.5):
    """Connect, send the (split) first flight, wait for the first server bytes.
    Returns (up_r, up_w, server_first) or None if no response in time."""
    try:
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(real_ip, port, family=socket.AF_INET), timeout=5)
    except Exception:
        return None
    try:
        up_w.write(first_blob)
        await up_w.drain()
        data = await asyncio.wait_for(up_r.read(65536), probe_timeout)
        if data:
            return up_r, up_w, data
    except (asyncio.TimeoutError, OSError):
        pass
    try:
        up_w.close()
    except Exception:
        pass
    return None


async def dial_and_probe_fake(real_ip, port, first_blob, probe_timeout=3.0):
    """Like dial_and_probe but injects a low-TTL decoy ClientHello on the real
    4-tuple BEFORE the real flight (zapret 'fake' — for deep-reassembly SNIs)."""
    try:
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(real_ip, port, family=socket.AF_INET), timeout=5)
    except Exception:
        return None
    try:
        s = up_w.get_extra_info("socket")
        src_ip, src_port = s.getsockname()
        await asyncio.to_thread(inject_fake, src_ip, src_port, real_ip, port)
        up_w.write(first_blob)
        await up_w.drain()
        data = await asyncio.wait_for(up_r.read(65536), probe_timeout)
        if data:
            return up_r, up_w, data
    except (asyncio.TimeoutError, OSError):
        pass
    try:
        up_w.close()
    except Exception:
        pass
    return None


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
    is_tls = False
    head = body = b""
    try:
        head = await asyncio.wait_for(reader.readexactly(5), timeout=15)
        if head[0] == 0x16:
            is_tls = True
            body = await reader.readexactly(struct.unpack("!H", head[3:5])[0])
            host = parse_sni(body)
        else:
            body = await reader.read(65536)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        writer.close()
        return

    # de-poison: resolve the SNI over DoH -> LIST of real IPs (fallback dst_ip)
    real_ips = []
    if host:
        real_ips = await asyncio.to_thread(doh_resolve, host)
    if not real_ips:
        real_ips = [dst_ip]

    # Try several (ip, split-geometry) combos. Some specific Cloudflare IPs are
    # IP-blocked on this network while others (same SNI) work, and the DPI is also
    # probabilistic — so rotate IP first, then split geometry.
    nvar = 3 if is_tls else 1
    combos = [(ip, v) for v in range(nvar) for ip in real_ips[:3]][:5]
    result = None
    chosen = real_ips[0]
    # Discord flows are also SNI-classified by a *throttler* (deep reassembly that
    # tlsrec doesn't hide from) — so always poison the first attempt with a decoy
    # ClientHello, not just as a block fallback. Stops the download throttle that
    # leaves history/profile/notifications "never loading".
    is_discord = is_tls and bool(host) and "discord" in host
    for idx, (ip, v) in enumerate(combos):
        blob = tlsrec_blob(head, body, host, variant=v) if is_tls else head + body
        dial = dial_and_probe_fake if (is_discord and idx == 0) else dial_and_probe
        result = await dial(ip, dst_port, blob)
        if result:
            chosen = ip
            break

    # last resort for deep-reassembly SNIs (updates.discord.com etc.): fake-mode
    # — inject a decoy-SNI ClientHello at low TTL, then the real one.
    if not result and is_tls:
        for ip in real_ips[:2]:
            result = await dial_and_probe_fake(
                ip, dst_port, tlsrec_blob(head, body, host, 0))
            if result:
                chosen = ip
                if VERBOSE:
                    print(f"  {host} won via FAKE-MODE", file=sys.stderr)
                break

    if not result:
        if VERBOSE:
            print(f"  {host or dst_ip} NO RESPONSE (tried {len(combos)} combos + fake, "
                  f"ips={real_ips[:3]})", file=sys.stderr)
        writer.close()
        return

    up_r, up_w, server_first = result
    if VERBOSE:
        tag = f" via {chosen}" + (" de-poisoned" if host and chosen != dst_ip else "")
        print(f"OK {host or dst_ip}:{dst_port}{tag}", file=sys.stderr)

    try:
        writer.write(server_first)
        await writer.drain()
    except OSError:
        try:
            up_w.close()
        except Exception:
            pass
        writer.close()
        return
    t0 = time.monotonic()
    res = await asyncio.gather(pump(reader, up_w), splice(up_r, writer))
    if VERBOSE and host and "discord" in host:
        up_b, down_b = res[0] or 0, len(server_first) + (res[1] or 0)
        print(f"  closed {host}: up={up_b} down={down_b} "
              f"dur={time.monotonic() - t0:.1f}s", file=sys.stderr)


async def amain(port):
    try:
        server = await asyncio.start_server(
            handle, "127.0.0.1", port, reuse_address=True)
    except OSError as e:
        if e.errno == 48:
            print(f"\nport {port} already in use — another tproxy is still running.\n"
                  f"kill it and retry:\n  sudo lsof -ti tcp:{port} | xargs sudo kill\n",
                  file=sys.stderr)
        raise
    pf_setup(port)                       # grab pf only AFTER we hold the port
    print(f">> transparent tlsrec+DoH proxy on 127.0.0.1:{port}  (root)")
    print(">> quit + reopen Discord normally; its updater is captured too")
    print(">> Ctrl-C (or close terminal) to stop and restore pf")
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
    ap.add_argument("--no-voice", action="store_true",
                    help="disable the UDP voice plane")
    args = ap.parse_args()
    VERBOSE = args.verbose

    cleanup_stale()        # kill leftover instances + reset pf before we start

    if not args.no_voice:
        dev = None
        for line in _run("route", "get", "default").stdout.splitlines():
            line = line.strip()
            if line.startswith("interface:"):
                dev = line.split()[1]
                break
        if dev:
            threading.Thread(target=voice_plane, args=(dev,), daemon=True).start()

    atexit.register(pf_teardown)
    # Catch close-terminal (SIGHUP) and suspend (SIGTSTP, i.e. Ctrl+Z) too — a
    # network tool holding pf must never be left half-alive in the background.
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGTSTP):
        signal.signal(s, lambda *_: (pf_teardown(), os._exit(0)))

    _pf_fd = os.open("/dev/pf", os.O_RDWR)
    try:
        asyncio.run(amain(args.port))
    except KeyboardInterrupt:
        pass
    finally:
        pf_teardown()


if __name__ == "__main__":
    main()

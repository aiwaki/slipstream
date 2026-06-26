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
from collections import OrderedDict
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
_doh_cache = OrderedDict()      # host -> (ips, expiry_monotonic)


# ---------------------------------------------------------------- pf plumbing
def _run(*args):
    return subprocess.run(list(args), capture_output=True, text=True)


def _pf_load(port):
    f = tempfile.NamedTemporaryFile("w", suffix=".slipstream.pf.conf", delete=False)
    f.write(PF_RULES.format(port=port))
    f.close()
    r = _run("pfctl", "-f", f.name)
    try:
        os.unlink(f.name)
    except Exception:
        pass
    return r


def pf_setup(port):
    global _pf_applied
    _run("pfctl", "-f", "/etc/pf.conf")
    _run("pfctl", "-E")                 # enable pf (ref-counted) — once
    r = _pf_load(port)
    if r.returncode != 0:
        print("pfctl load failed:\n" + r.stderr, file=sys.stderr)
        sys.exit(1)
    _pf_applied = True
    print(f">> pf active: all TCP/443 -> 127.0.0.1:{port}; QUIC (UDP/443) blocked")


def pf_has_rules(port):
    """Are our rdr rules still loaded? (sleep/wake or another tool may flush pf)"""
    return f"port {port}" in _run("pfctl", "-sn").stdout


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


def make_blob(head: bytes, body: bytes, host, cap):
    """Build the first-flight bytes for one strategy.

    cap=None -> plain (no desync, for unblocked hosts). Otherwise split the
    ClientHello into TLS records with a tiny first record (<=cap) plus a cut
    inside the SNI hostname, which defeats this TSPU's first-record SNI check."""
    if cap is None:
        return head + body
    typ, ver = head[0:1], head[1:3]
    n = len(body)
    i = body.find(host.encode()) if host else -1
    if i < 0:
        i = max(2, n // 3)
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


# --------------------------------------------------- adaptive strategy ladder
# Tried in order, cached winner first. The first that completes TLS is cached
# per host; when the TSPU changes and the cached one stops working, connections
# climb the ladder to the next working strategy and re-cache it. Self-tuning,
# no manual re-tuning, survives strategy decay.
STRATEGIES = [
    {"name": "split64",      "cap": 64,   "fake": False},
    {"name": "split64+fake", "cap": 64,   "fake": True},
    {"name": "split16",      "cap": 16,   "fake": False},
    {"name": "split16+fake", "cap": 16,   "fake": True},
    {"name": "fake5",        "cap": 5,    "fake": True},
    {"name": "plain",        "cap": None, "fake": False},
]
STRAT_BY_NAME = {s["name"]: s for s in STRATEGIES}
_STRAT_PATH = "/var/run/slipstream-strat.json"
STRAT_CACHE_MAX = 2048
_strat_cache = OrderedDict()       # host -> winning strategy name


def load_strat_cache():
    global _strat_cache
    try:
        with open(_STRAT_PATH) as f:
            _strat_cache = OrderedDict(json.load(f))
    except Exception:
        _strat_cache = OrderedDict()


def remember_strategy(host, name):
    _strat_cache[host] = name
    _strat_cache.move_to_end(host)
    while len(_strat_cache) > STRAT_CACHE_MAX:
        _strat_cache.popitem(last=False)
    save_strat_cache()


def save_strat_cache():
    try:
        with open(_STRAT_PATH, "w") as f:
            json.dump(_strat_cache, f)
    except Exception:
        pass


def strategy_order(host):
    win = _strat_cache.get(host)
    if win in STRAT_BY_NAME:
        return [STRAT_BY_NAME[win]] + [s for s in STRATEGIES if s["name"] != win]
    # Prior: Discord flows are throttled by SNI even when the block is beaten, and
    # the probe (TLS handshake) can't see the throttle — so start Discord on a
    # fake strategy (beats block AND throttle) instead of plain split.
    if host and "discord" in host:
        order = ["split64+fake", "split16+fake", "fake5", "split64", "split16", "plain"]
        return [STRAT_BY_NAME[n] for n in order]
    return STRATEGIES


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
VOICE_FLOWS_MAX = 8192             # bound the per-flow table (re-priming is harmless)


def _fake_stun(txn=b"\x00" * 12):
    return struct.pack("!HHI", 0x0001, 0x0000, 0x2112A442) + txn   # STUN binding req


def default_iface():
    for line in _run("route", "get", "default").stdout.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split()[1]
    return None


def _voice_bpf(localip):
    return (f"udp and src host {localip} and dst portrange {VOICE_LO}-{VOICE_HI} "
            "and not dst net 192.168.0.0/16 and not dst net 10.0.0.0/8 "
            "and not dst net 172.16.0.0/12 and not dst net 169.254.0.0/16 "
            "and not dst net 224.0.0.0/4 and not dst host 255.255.255.255")


def network_monitor(port, voice=True):
    """Long-running guard thread. (1) Keeps the voice sniffer bound to the CURRENT
    default interface so voice survives Wi-Fi/Ethernet/sleep changes. (2) Re-applies
    pf if it ever gets flushed (sleep/wake or another tool). Voice itself: Discord
    RTP is UDP to *.discord.media:50000-65535, bypassing the TCP pf-rdr, so we
    BPF-observe it and raw-inject low-TTL decoy STUN primes on the 5-tuple, leaving
    the real flow untouched."""
    AsyncSniffer = send = IP = UDP = Raw = get_if_addr = None
    if voice:
        try:
            from scapy.all import AsyncSniffer, send, IP, UDP, Raw, get_if_addr
        except Exception as e:
            print(f">> voice disabled (scapy: {e})", file=sys.stderr)
    fake = _fake_stun()
    flows = {}
    sniffer = None
    cur_iface = None

    def on_pkt(p):
        if not (p.haslayer(IP) and p.haslayer(UDP)):
            return
        ip, udp = p[IP], p[UDP]
        key = (ip.src, udp.sport, ip.dst, udp.dport)
        n = flows.get(key, 0)
        if n >= VOICE_CUTOFF:
            return
        if len(flows) > VOICE_FLOWS_MAX:
            flows.clear()
        flows[key] = n + 1
        pkt = (IP(src=ip.src, dst=ip.dst, ttl=VOICE_TTL)
               / UDP(sport=udp.sport, dport=udp.dport) / Raw(fake))
        for _ in range(VOICE_REPEAT):
            send(pkt, verbose=0)
        if VERBOSE and n == 0:
            print(f"  voice: priming {ip.dst}:{udp.dport}", file=sys.stderr)

    while True:
        if _pf_applied and not pf_has_rules(port):
            print(">> pf rules vanished — re-applying", file=sys.stderr)
            _pf_load(port)
        if send is not None:                       # scapy available
            iface = default_iface()
            if iface and iface != cur_iface:
                if sniffer is not None:
                    try:
                        sniffer.stop()
                    except Exception:
                        pass
                    sniffer = None
                try:
                    localip = get_if_addr(iface)
                    sniffer = AsyncSniffer(iface=iface, filter=_voice_bpf(localip),
                                           prn=on_pkt, store=0)
                    sniffer.start()
                    cur_iface = iface
                    print(f">> voice plane: priming UDP {VOICE_LO}-{VOICE_HI} "
                          f"on {iface}")
                except Exception as e:
                    print(f">> voice sniffer failed on {iface}: {e}", file=sys.stderr)
                    cur_iface = None
        time.sleep(5)


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
                        s.sendall(make_blob(out[:5], out[5:], doh_sni, FIRST_REC_CAP)
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


DOH_TTL = 300.0          # re-resolve every 5 min — Cloudflare rotates IPs, a
                         # forever-cache silently breaks over hours (the sneaky one)
DOH_TTL_NEG = 30.0       # short negative cache so failures don't hammer the resolver
DOH_CACHE_MAX = 1024
_doh_lock = threading.Lock()


def doh_resolve(host):
    """Return a LIST of real A-record IPs (try several — some specific Cloudflare
    IPs are IP-blocked while others aren't). TTL'd + bounded so stale rotated IPs
    don't silently break it, and the cache can't grow without limit."""
    now = time.monotonic()
    with _doh_lock:
        ent = _doh_cache.get(host)
        if ent and ent[1] > now:
            _doh_cache.move_to_end(host)
            return ent[0]
    ips = []
    for ip, sni in DOH:
        r = _doh_query(ip, sni, host)
        if r:
            ips = r
            break
    with _doh_lock:
        _doh_cache[host] = (ips, now + (DOH_TTL if ips else DOH_TTL_NEG))
        _doh_cache.move_to_end(host)
        while len(_doh_cache) > DOH_CACHE_MAX:
            _doh_cache.popitem(last=False)
    return ips


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


async def dial_strategy(ip, port, head, body, host, strat):
    blob = make_blob(head, body, host, strat["cap"])
    if strat["fake"]:
        return await dial_and_probe_fake(ip, port, blob)
    return await dial_and_probe(ip, port, blob)


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

    # Adaptive strategy ladder (auto-sweep / self-tuning). Try strategies in
    # order — cached winner for this host first — across up to a couple of real
    # IPs (some Cloudflare IPs are IP-blocked while others work). First success
    # is cached per host so a decayed strategy auto-rolls to the next that works.
    result = None
    chosen = real_ips[0]
    chosen_name = None
    if not is_tls:
        for ip in real_ips[:2]:
            result = await dial_and_probe(ip, dst_port, head + body)
            if result:
                chosen = ip
                break
    else:
        attempts = 0
        for strat in strategy_order(host):
            for ip in real_ips[:2]:
                attempts += 1
                result = await dial_strategy(ip, dst_port, head, body, host, strat)
                if result:
                    chosen, chosen_name = ip, strat["name"]
                    break
                if attempts >= 7:
                    break
            if result or attempts >= 7:
                break
        if result and host and _strat_cache.get(host) != chosen_name:
            remember_strategy(host, chosen_name)

    if not result:
        if VERBOSE:
            print(f"  {host or dst_ip} NO RESPONSE ({len(real_ips)} ips)",
                  file=sys.stderr)
        writer.close()
        return

    up_r, up_w, server_first = result
    if VERBOSE:
        tag = f" [{chosen_name}]" if chosen_name else ""
        tag += " de-poisoned" if host and chosen != dst_ip else ""
        print(f"OK {host or dst_ip}:{dst_port} via {chosen}{tag}", file=sys.stderr)

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


LAUNCHD_LABEL = "dev.slipstream.tproxy"
LAUNCHD_PLIST = f"/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"
LOG_PATH = "/var/log/slipstream.log"


def do_install(port):
    py = sys.executable
    script = os.path.abspath(__file__)
    workdir = os.path.dirname(script)
    plist = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        f'  <key>Label</key><string>{LAUNCHD_LABEL}</string>\n'
        '  <key>ProgramArguments</key><array>'
        f'<string>{py}</string><string>{script}</string>'
        f'<string>--port</string><string>{port}</string></array>\n'
        '  <key>RunAtLoad</key><true/>\n'
        '  <key>KeepAlive</key><true/>\n'
        f'  <key>WorkingDirectory</key><string>{workdir}</string>\n'
        f'  <key>StandardOutPath</key><string>{LOG_PATH}</string>\n'
        f'  <key>StandardErrorPath</key><string>{LOG_PATH}</string>\n'
        '</dict></plist>\n'
    )
    with open(LAUNCHD_PLIST, "w") as f:
        f.write(plist)
    os.chmod(LAUNCHD_PLIST, 0o644)
    _run("launchctl", "bootout", "system", LAUNCHD_PLIST)      # if already loaded
    r = _run("launchctl", "bootstrap", "system", LAUNCHD_PLIST)
    if r.returncode != 0:
        _run("launchctl", "load", "-w", LAUNCHD_PLIST)         # older macOS fallback
    print(f"installed -> {LAUNCHD_PLIST}")
    print(f"runs now + at every boot as root, auto-restarts on crash.")
    print(f"logs:      tail -f {LOG_PATH}")
    print(f"uninstall: sudo {py} {script} --uninstall")


def do_uninstall():
    _run("launchctl", "bootout", "system", LAUNCHD_PLIST)
    _run("launchctl", "unload", "-w", LAUNCHD_PLIST)
    try:
        os.remove(LAUNCHD_PLIST)
    except Exception:
        pass
    _run("pfctl", "-f", "/etc/pf.conf")
    _run("pfctl", "-d")
    print("uninstalled + pf restored")


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
    ap.add_argument("--install", action="store_true",
                    help="install as a LaunchDaemon (starts at boot, auto-restarts)")
    ap.add_argument("--uninstall", action="store_true",
                    help="remove the LaunchDaemon and restore pf")
    args = ap.parse_args()
    VERBOSE = args.verbose

    if args.install:
        do_install(args.port)
        return
    if args.uninstall:
        do_uninstall()
        return

    cleanup_stale()        # kill leftover instances + reset pf before we start
    load_strat_cache()     # remember per-host winning strategies across restarts

    # guard thread: voice sniffer follows the default iface + pf self-heal
    threading.Thread(target=network_monitor, args=(args.port,),
                     kwargs={"voice": not args.no_voice}, daemon=True).start()

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

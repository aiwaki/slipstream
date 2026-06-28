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
from concurrent.futures import ThreadPoolExecutor
import os
import resource
import signal
import socket
import ssl
import shutil
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
block return quick inet proto udp from any to any port 443
"""

_pf_applied = False
_pf_fd = None
_doh_cache = OrderedDict()      # host -> (ips, expiry_monotonic)
# Dedicated pool for the blocking off-loop work (DoH resolves, fake injection).
# The default asyncio executor is tiny (~cpu+4); a browser opening many new hosts
# floods it with slow DoH queries and the whole proxy stalls. 64 workers + DoH
# de-dup keeps the app responsive under a browser's connection burst.
_POOL = ThreadPoolExecutor(max_workers=64, thread_name_prefix="slip")
_doh_inflight = {}             # host -> asyncio.Future (collapse concurrent DoH)
# Negative cache: a host that failed the whole ladder is "dead" for a cooldown,
# during which it gets ONE fast-fail attempt instead of 7 — stops retry-storms
# from a persistently-blocked host (e.g. Telegram DC sockets hammering forever).
DEAD_TTL = 60.0
_dead = {}                     # host -> expiry_monotonic

# Status the menu-bar app polls (atomic write; ts lets the app detect a dead daemon).
STATUS_PATH = "/var/run/slipstream.status"
_conn_count = 0                # live proxied connections

# --------------------------------------------------- Geph split-tunnel (hybrid)
# The elegant hybrid (not a blunt VPN toggle): MOST traffic uses our local desync;
# only the handful of services that hard-block Russian IPs server-side (OpenAI,
# Anthropic, ...) are tunnelled through geph's local SOCKS5 — and ONLY when geph is
# actually running. Russian services are split-tunnel-EXCLUDED: they must never
# enter the tunnel (privacy + they'd break, geph exits abroad). geph absent ->
# _geph_up stays False -> this whole path is inert and behaviour is unchanged.
GEPH_ENABLED = os.environ.get("SLIP_GEPH", "1") != "0"
# Prefer Slipstream's OWN bundled geph5-client (:9954, started by the menu-bar app
# with the user's account secret); fall back to a separately-running Geph.app
# (:9909). SLIP_GEPH_PORT overrides with a single explicit port.
_env_geph_port = os.environ.get("SLIP_GEPH_PORT")
GEPH_PORTS = [int(_env_geph_port)] if _env_geph_port else [9954, 9909]
_geph_up = False               # set by network_monitor's periodic probe
_geph_port = None              # the live SOCKS port (set by probe_geph)

# Services that refuse Russian IPs at the application layer (desync can't help —
# only an exit abroad does). Suffix match. Telegram is deliberately ABSENT: it is
# DPI-blocked, not geo-blocked, so local desync handles it (keep it off the tunnel).
GEPH_HOSTS = (
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "anthropic.com", "claude.ai", "claudeusercontent.com",
    "intercomcdn.com",            # OpenAI/Anthropic support widget assets
)

# Russian services — NEVER tunnelled (split-tunnel exclusion "for the VPN").
# Primary rule is the national TLDs; the set covers big RU services on .com/.net.
RU_TLDS = (".ru", ".su", ".xn--p1ai", ".moscow", ".tatar", ".xn--80adxhks")
RU_HOSTS = (
    "vk.com", "vk.cc", "vkvideo.ru", "userapi.com", "vk-cdn.net", "vkuser.net",
    "yandex.com", "yandex.net", "yastatic.net", "yandexcloud.net", "ya.ru",
    "mail.ru", "mycdn.me", "imgsmail.ru",
    "sberbank.com", "sber.ru", "sberdevices.ru",
    "ozon.com", "ozon.ru", "wildberries.ru", "wb.ru", "avito.ru",
    "gosuslugi.ru", "nalog.ru", "gov.ru",
    "tinkoff.ru", "tbank.ru", "gazprombank.ru", "vtb.ru", "alfabank.ru",
    "rutube.ru", "ok.ru", "dzen.ru", "kinopoisk.ru", "2gis.com", "2gis.ru",
    "kaspersky.com", "kaspersky.ru", "aliexpress.ru",
)


def is_russian(host):
    """True for any Russian service — excluded from the geph tunnel."""
    if not host:
        return False
    h = host.lower().rstrip(".")
    if h.endswith(RU_TLDS):
        return True
    return any(h == d or h.endswith("." + d) for d in RU_HOSTS)


# Adaptive auto-routing: learn geo-blocked hosts the way the engine learns desync
# strategies. A host the app keeps reconnecting to that returns NO real content
# over local desync (TLS ok, but a 403 / challenge / RST — the "reconnecting…"
# symptom) is geo-blocked → promote it to the geph tunnel and remember it (TTL'd).
# We count low-content CLOSES, not raw connects, so a normal page's parallel burst
# (which transfers real data) never trips it. Guard: if MANY distinct hosts fail
# at once it's a network problem, not a per-host geo-block, so don't promote.
AUTO_GEPH_WINDOW = 60.0       # seconds to accumulate a host's failures over
AUTO_GEPH_HANG = 5.0          # a connection held this long with no content = STUCK
AUTO_GEPH_STORM = 3           # stuck retries in the window = geo-blocked
AUTO_GEPH_FAIL_BYTES = 8192   # a local reply under this = "no real content"
AUTO_GEPH_NET_BAD = 5         # this many hosts failing at once = network problem
AUTO_GEPH_TTL = 7 * 86400.0   # remember a learned host for a week
_auto_fail = {}               # host -> list[monotonic] recent stuck closes
_auto_geph = {}               # host -> wall-clock expiry (learned geph hosts)
_AUTO_GEPH_PATH = "/var/run/slipstream-autogeph.json"

# geph's own broker-fronting domains — NEVER desync/auto-route these (our daemon
# would otherwise mangle geph's broker access or route geph through itself).
GEPH_INFRA = ("kubernetes.io", "cdn77.org", "cdn77.com", "netlify.app", "vuejs.org")


def _is_geph_infra(host):
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in GEPH_INFRA)


def geph_route(host):
    """Should this host go through geph's tunnel? Geo-blocked (listed OR learned)
    AND not Russian."""
    if not host or is_russian(host):
        return False
    h = host.lower().rstrip(".")
    if any(h == d or h.endswith("." + d) for d in GEPH_HOSTS):
        return True
    return _auto_geph.get(h, 0) > time.time()


def load_auto_geph():
    global _auto_geph
    try:
        with open(_AUTO_GEPH_PATH) as f:
            data = json.load(f)
        now = time.time()
        _auto_geph = {h: e for h, e in data.items()
                      if isinstance(e, (int, float)) and e > now}
    except Exception:
        _auto_geph = {}


def save_auto_geph():
    try:
        with open(_AUTO_GEPH_PATH, "w") as f:
            json.dump(_auto_geph, f)
    except Exception:
        pass


def note_local_result(host, down_bytes, duration):
    """Called after a NON-geph local-desync close. A "stuck" close — the
    connection was held a long time but returned no real content (the
    "reconnecting…" hang) — is the geo-block signal; a storm of them for one host
    learns it for the geph tunnel. FAST low-content closes (redirects / 204 /
    beacons, e.g. google) are normal and must NOT count, or they'd be falsely
    tunnelled. Real content resets the host's failure noise."""
    if not host or is_russian(host) or geph_route(host) or _is_geph_infra(host):
        return                                  # RU, already tunnelled, or geph's own
    if down_bytes >= AUTO_GEPH_FAIL_BYTES:
        _auto_fail.pop(host, None)              # got real content -> not blocked
        return
    if duration < AUTO_GEPH_HANG:
        return                                  # fast + low content = normal, ignore
    now = time.monotonic()
    q = _auto_fail.setdefault(host, [])
    q.append(now)
    cutoff = now - AUTO_GEPH_WINDOW
    while q and q[0] < cutoff:
        q.pop(0)
    if len(_auto_fail) > 4096:
        for k in [k for k, v in list(_auto_fail.items()) if not v or v[-1] < cutoff]:
            _auto_fail.pop(k, None)
    if len(q) < AUTO_GEPH_STORM or not _geph_up:
        return
    # network-fine guard: if many DISTINCT hosts are failing at once it's the
    # network, not a per-host geo-block — don't sweep everything into the tunnel.
    # (Count hosts with >=2 recent low-content closes; this accumulates before any
    # single host crosses the storm threshold, so a network-wide outage is caught.)
    failing = sum(1 for v in _auto_fail.values()
                  if sum(1 for t in v if t >= cutoff) >= 2)
    if failing >= AUTO_GEPH_NET_BAD:
        return
    h = host.lower().rstrip(".")
    _auto_geph[h] = time.time() + AUTO_GEPH_TTL
    save_auto_geph()
    print(f">> auto-route: {host} keeps failing locally -> geph tunnel "
          f"(remembered {AUTO_GEPH_TTL / 86400:.0f}d)", file=sys.stderr)


def write_status(state, iface, voice_iface):
    try:
        st = {
            "state": state,            # "active" | "dormant"
            "pid": os.getpid(),
            "ts": time.time(),
            "conns": _conn_count,
            "iface": iface or "",
            "voice": voice_iface or "",
            "hosts_learned": len(_strat_cache),
            "dead": len(_dead),
            "geph": "up" if _geph_up else ("off" if not GEPH_ENABLED else "down"),
            "geph_learned": len(_auto_geph),
        }
        tmp = STATUS_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, STATUS_PATH)
    except Exception:
        pass


# ---------------------------------------------------------------- pf plumbing
# LaunchDaemons start with an empty PATH, so bare 'pfctl'/'route'/'pgrep' aren't
# found and the daemon silently does nothing — force the system dirs onto PATH.
_RUN_ENV = dict(os.environ)
_RUN_ENV["PATH"] = "/sbin:/usr/sbin:/bin:/usr/bin:" + _RUN_ENV.get("PATH", "")


def _run(*args):
    try:
        return subprocess.run(list(args), capture_output=True, text=True, env=_RUN_ENV)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, "", f"not found: {args[0]}")


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
    try:
        os.remove(STATUS_PATH)        # daemon is going away -> app shows "off"
    except Exception:
        pass
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
    # A MANUAL run (from the repo, not the installed daemon) must stop the daemon
    # first: launchd KeepAlive would instantly restart a kill-9'd daemon and
    # re-grab :1080. The daemon itself runs from INSTALL_DIR -> never boots itself.
    if os.path.abspath(__file__) != os.path.join(INSTALL_DIR, "tproxy.py"):
        _run("launchctl", "bootout", "system", LAUNCHD_PLIST)
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
STRAT_CACHE_VERSION = 2             # bump on strategy-logic changes -> discard stale
_strat_cache = OrderedDict()       # host -> winning strategy name


def load_strat_cache():
    global _strat_cache
    try:
        with open(_STRAT_PATH) as f:
            data = json.load(f)
        if data.get("__v__") != STRAT_CACHE_VERSION:
            data = {}                # logic changed -> old winners may be wrong
        data.pop("__v__", None)
        _strat_cache = OrderedDict(data)
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
        d = dict(_strat_cache)
        d["__v__"] = STRAT_CACHE_VERSION
        with open(_STRAT_PATH, "w") as f:
            json.dump(d, f)
    except Exception:
        pass


DISCORD_STRATS = ["split64+fake", "split16+fake", "fake5"]   # fake-ONLY
# Default order is FAKE-FIRST for every host: the TSPU throttles many services by
# SNI (Discord, Anthropic, Shopify stores, ...) even when the block is beaten, and
# the TLS probe can't see the throttle — so try fake first everywhere (the decoy
# hides the SNI from the throttler). Non-fake variants remain as fallbacks for the
# rare host the decoy upsets. Inject is cheap (not DoH); the pool absorbs it.
GENERAL_STRATS = ["split64+fake", "split16+fake", "fake5", "split64", "split16", "plain"]


def strategy_order(host):
    # Discord must NEVER fall to a non-fake strategy (its throttle is relentless),
    # so it uses the fake-only set and ignores any stale non-fake cache entry.
    if host and "discord" in host:
        win = _strat_cache.get(host)
        names = ([win] + [n for n in DISCORD_STRATS if n != win]
                 if win in DISCORD_STRATS else DISCORD_STRATS)
        return [STRAT_BY_NAME[n] for n in names]
    win = _strat_cache.get(host)
    if win in STRAT_BY_NAME:
        return [STRAT_BY_NAME[win]] + [s for s in STRATEGIES if s["name"] != win]
    return [STRAT_BY_NAME[n] for n in GENERAL_STRATS]


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


# Reuse ONE scapy L3 socket per thread instead of send()-per-packet. scapy's
# send() opens (and under load leaks) a socket each call, and the voice plane
# primes 6x per packet -> FD exhaustion ("Too many open files"). A thread-local
# socket is safe across the sniffer thread and the asyncio executor workers.
_l3_tls = threading.local()


def _l3send(pkt):
    s = getattr(_l3_tls, "sock", None)
    if s is None:
        from scapy.all import conf
        s = _l3_tls.sock = conf.L3socket()
    s.send(pkt)


def inject_fake(src_ip, src_port, dst_ip, dst_port, ttl=4, repeats=3):
    """Spray a few decoy-SNI ClientHello packets at low TTL on the real 4-tuple.
    Needs scapy (run via the venv python). No-op with a warning if unavailable."""
    try:
        from scapy.all import IP, TCP, Raw
    except Exception:
        print("  fake-mode needs scapy: run with sudo .venv/bin/python tproxy.py",
              file=sys.stderr)
        return
    pkt = (IP(src=src_ip, dst=dst_ip, ttl=ttl)
           / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1, ack=1)
           / Raw(_FAKE_CH))
    for _ in range(repeats):
        _l3send(pkt)


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
    global _pf_applied, _geph_up
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
            _l3send(pkt)
        if VERBOSE and n == 0:
            print(f"  voice: priming {ip.dst}:{udp.dport}", file=sys.stderr)

    geph_strikes = 0
    while True:
        iface = default_iface()
        # Hysteresis: a single failed probe (geph busy under load) must NOT flip us
        # to "down" — that would drop geo-blocked hosts to local desync for 5s.
        # Only declare down after 2 consecutive misses.
        if probe_geph():
            geph_strikes = 0
            up = True
        else:
            geph_strikes += 1
            up = geph_strikes < 2
        was_geph, _geph_up = _geph_up, up
        if _geph_up != was_geph:
            print(f">> geph SOCKS {'up' if _geph_up else 'down'} "
                  f"(:{_geph_port if _geph_up else GEPH_PORTS}) — geo-blocked hosts "
                  f"{'tunnelled' if _geph_up else 'on local desync'}", file=sys.stderr)
        # Coexist with the user's own VPN: when a full-tunnel VPN owns the default
        # route (utun*) it already bypasses DPI, so drop our pf rules to avoid any
        # conflict; re-arm automatically when the VPN drops.
        vpn = bool(iface) and iface.startswith("utun")
        if vpn:
            if _pf_applied:
                print(f">> VPN up (default via {iface}) -> Slipstream dormant",
                      file=sys.stderr)
                _run("pfctl", "-f", "/etc/pf.conf")
                _pf_applied = False
        else:
            if not _pf_applied:
                print(">> no VPN -> Slipstream active", file=sys.stderr)
                _pf_load(port)
                _pf_applied = True
            elif not pf_has_rules(port):
                print(">> pf rules vanished — re-applying", file=sys.stderr)
                _pf_load(port)
        if send is not None:                       # scapy available
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
        write_status("dormant" if vpn else "active", iface, cur_iface)
        time.sleep(5)


# ------------------------------------------------------------- DoH (blocking)
def _doh_query(doh_ip, doh_sni, host, timeout=3):
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


async def doh_resolve_async(host):
    """Resolve on the dedicated pool, collapsing concurrent first-time lookups
    for the same host into a single query (no await between get+set -> race-free
    on the single-threaded loop)."""
    fut = _doh_inflight.get(host)
    if fut is not None:
        return await fut
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    _doh_inflight[host] = fut
    try:
        ips = await loop.run_in_executor(_POOL, doh_resolve, host)
    except Exception:
        ips = []
    finally:
        _doh_inflight.pop(host, None)
        if not fut.done():
            fut.set_result(ips)
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


def probe_geph():
    """Is geph's SOCKS5 listener accepting? (cheap TCP connect; called every 5s
    by the monitor thread). A successful connect doesn't prove geph reached its
    exit — dial_via_geph keeps tight timeouts and falls back if CONNECT fails."""
    global _geph_port
    if not GEPH_ENABLED:
        _geph_port = None
        return False
    for p in GEPH_PORTS:
        try:
            # generous timeout: under load geph's accept() can lag, and a false
            # "down" drops geo-blocked hosts to local desync (claude.ai "retrying").
            socket.create_connection(("127.0.0.1", p), timeout=1.5).close()
            _geph_port = p
            return True
        except Exception:
            continue
    return False    # transient miss -> keep last good _geph_port; hysteresis decides


async def dial_via_geph(host, port, first_flight):
    """Open a SOCKS5 CONNECT to host:port through geph's local listener and send
    the buffered first flight PLAIN (the tunnel handles censorship — no desync).
    CONNECT-by-domain lets geph resolve + exit abroad, sidestepping RU DNS poison
    and the geo-block entirely. Returns (reader, writer) to geph or None on any
    failure (caller then falls back to local desync)."""
    port_socks = _geph_port
    if not port_socks:
        return None
    try:
        gr, gw = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port_socks), timeout=3)
    except Exception:
        return None
    try:
        gw.write(b"\x05\x01\x00")                      # VER5, 1 method, no-auth
        await gw.drain()
        greet = await asyncio.wait_for(gr.readexactly(2), 3)
        if greet[0] != 0x05 or greet[1] != 0x00:
            raise IOError("socks5 no-auth refused")
        hb = host.encode("ascii", "ignore")[:255]
        gw.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", port))
        await gw.drain()
        rep = await asyncio.wait_for(gr.readexactly(4), 8)   # VER REP RSV ATYP
        if rep[1] != 0x00:
            raise IOError(f"socks5 connect rep={rep[1]}")
        atyp = rep[3]
        if atyp == 0x01:
            await gr.readexactly(4)
        elif atyp == 0x03:
            ln = await gr.readexactly(1)
            await gr.readexactly(ln[0])
        elif atyp == 0x04:
            await gr.readexactly(16)
        await gr.readexactly(2)                        # bound port
        gw.write(first_flight)                         # original ClientHello, plain
        await gw.drain()
        return gr, gw
    except Exception:
        try:
            gw.close()
        except Exception:
            pass
        return None


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
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(_POOL, inject_fake, src_ip, src_port, real_ip, port)
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
    global _conn_count
    _conn_count += 1
    try:
        await _handle_impl(reader, writer)
    finally:
        _conn_count -= 1


async def _handle_impl(reader, writer):
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

    # Split-tunnel: a geo-blocked service (refuses RU IPs) goes through geph's
    # SOCKS5 tunnel when geph is up; Russian services are excluded by geph_route;
    # on any geph failure we fall through to local desync (no worse than today).
    if is_tls and _geph_up and geph_route(host):
        g = await dial_via_geph(host, dst_port, head + body)
        if g:
            gr, gw = g
            if VERBOSE:
                print(f"OK {host}:{dst_port} via geph tunnel", file=sys.stderr)
            await asyncio.gather(pump(reader, gw), splice(gr, writer))
            return
        if VERBOSE:
            print(f"  geph CONNECT failed for {host} -> local desync",
                  file=sys.stderr)

    # de-poison: resolve the SNI over DoH -> LIST of real IPs (fallback dst_ip)
    real_ips = []
    if host:
        real_ips = await doh_resolve_async(host)
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
        now = time.monotonic()
        # known-dead host -> 1 fast-fail attempt instead of the full 7-attempt ladder
        max_attempts = 1 if (host and _dead.get(host, 0) > now) else 7
        attempts = 0
        for strat in strategy_order(host):
            for ip in real_ips[:2]:
                attempts += 1
                result = await dial_strategy(ip, dst_port, head, body, host, strat)
                if result:
                    chosen, chosen_name = ip, strat["name"]
                    break
                if attempts >= max_attempts:
                    break
            if result or attempts >= max_attempts:
                break
        if result:
            if host:
                _dead.pop(host, None)
                if _strat_cache.get(host) != chosen_name:
                    remember_strategy(host, chosen_name)
        elif host:
            _dead[host] = now + DEAD_TTL        # arm the negative cache
            if len(_dead) > 4096:
                _dead.clear()

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
    # adaptive: a host that keeps closing with no real content is geo-blocked ->
    # learn it for the geph tunnel (this connection went local; the next routes).
    if is_tls and host:
        note_local_result(host, len(server_first) + (res[1] or 0),
                          time.monotonic() - t0)
    if VERBOSE and host and "discord" in host:
        up_b, down_b = res[0] or 0, len(server_first) + (res[1] or 0)
        print(f"  closed {host}: up={up_b} down={down_b} "
              f"dur={time.monotonic() - t0:.1f}s", file=sys.stderr)


LAUNCHD_LABEL = "dev.slipstream.tproxy"
LAUNCHD_PLIST = f"/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"
LOG_PATH = "/var/log/slipstream.log"
INSTALL_DIR = "/usr/local/slipstream"   # NOT under ~/Documents (TCC-protected)


def do_install(port):
    # Install a self-contained copy under /usr/local (a root LaunchDaemon has NO
    # TCC access to ~/Documents). Two modes:
    #  - frozen (PyInstaller onedir): copy the self-contained bundle, run the binary
    #  - script (dev): copy tproxy.py + build a venv with scapy
    if getattr(sys, "frozen", False):
        src = os.path.dirname(os.path.abspath(sys.executable))
        shutil.rmtree(INSTALL_DIR, ignore_errors=True)
        shutil.copytree(src, INSTALL_DIR)
        binary = os.path.join(INSTALL_DIR, os.path.basename(sys.executable))
        prog_args = [binary, "--port", str(port)]
        uninstall_hint = f"sudo {binary} --uninstall"
    else:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        script = os.path.join(INSTALL_DIR, "tproxy.py")
        shutil.copy(os.path.abspath(__file__), script)
        venv = os.path.join(INSTALL_DIR, "venv")
        py = os.path.join(venv, "bin", "python3")
        if not os.path.exists(py):
            base = getattr(sys, "_base_executable", None) or sys.executable
            print(">> building self-contained venv + scapy (needs network, ~20s)...")
            if _run(base, "-m", "venv", venv).returncode != 0:
                print("venv create failed", file=sys.stderr)
                return
            r = _run(py, "-m", "pip", "install", "--quiet",
                     "--disable-pip-version-check", "scapy")
            if r.returncode != 0:
                print("scapy install failed (pypi reachable?):\n" + r.stderr[-400:],
                      file=sys.stderr)
                return
        prog_args = [py, script, "--port", str(port)]
        uninstall_hint = f"sudo {py} {script} --uninstall"
    workdir = INSTALL_DIR
    prog_xml = "".join(f"<string>{a}</string>" for a in prog_args)
    plist = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        f'  <key>Label</key><string>{LAUNCHD_LABEL}</string>\n'
        f'  <key>ProgramArguments</key><array>{prog_xml}</array>\n'
        '  <key>RunAtLoad</key><true/>\n'
        '  <key>KeepAlive</key><true/>\n'
        '  <key>EnvironmentVariables</key><dict>'
        '<key>PATH</key><string>/sbin:/usr/sbin:/bin:/usr/bin</string>'
        '<key>PYTHONUNBUFFERED</key><string>1</string></dict>\n'
        '  <key>SoftResourceLimits</key><dict>'
        '<key>NumberOfFiles</key><integer>16384</integer></dict>\n'
        '  <key>HardResourceLimits</key><dict>'
        '<key>NumberOfFiles</key><integer>16384</integer></dict>\n'
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
    print(f"uninstall: {uninstall_hint}")


def do_uninstall():
    _run("launchctl", "bootout", "system", LAUNCHD_PLIST)
    _run("launchctl", "unload", "-w", LAUNCHD_PLIST)
    try:
        os.remove(LAUNCHD_PLIST)
    except Exception:
        pass
    _run("pfctl", "-f", "/etc/pf.conf")
    _run("pfctl", "-d")
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    try:
        os.remove(_STRAT_PATH)             # drop any stale strategy cache
    except Exception:
        pass
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
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PROXY_PORT)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--no-voice", action="store_true",
                    help="disable the UDP voice plane")
    ap.add_argument("--install", action="store_true",
                    help="install as a LaunchDaemon (starts at boot, auto-restarts)")
    ap.add_argument("--uninstall", action="store_true",
                    help="remove the LaunchDaemon and restore pf")
    ap.add_argument("--status", action="store_true",
                    help="print daemon status JSON and exit (no root needed)")
    args = ap.parse_args()
    VERBOSE = args.verbose

    if args.status:
        try:
            with open(STATUS_PATH) as f:
                line = f.read().strip()
            # treat a stale file (>15s) as off — the daemon writes every 5s
            st = json.loads(line)
            if time.time() - st.get("ts", 0) > 15:
                line = '{"state": "off"}'
            print(line)
        except Exception:
            print('{"state": "off"}')
        return

    if os.geteuid() != 0:
        print("must run as root:  sudo python3 tproxy.py", file=sys.stderr)
        sys.exit(1)

    if args.install:
        do_install(args.port)
        return
    if args.uninstall:
        do_uninstall()
        return

    # A transparent proxy carries ALL system TCP/443 — hundreds of concurrent FDs.
    # The default 256-fd soft limit is far too low ("Too many open files"); raise it.
    try:
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        for target in (65536, 32768, 16384, 10240, 8192):
            cap = target if hard == resource.RLIM_INFINITY else min(target, hard)
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (cap, hard))
                break
            except (ValueError, OSError):
                continue
    except Exception:
        pass

    cleanup_stale()        # kill leftover instances + reset pf before we start
    load_strat_cache()     # remember per-host winning strategies across restarts
    load_auto_geph()       # remember hosts learned to need the geph tunnel

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

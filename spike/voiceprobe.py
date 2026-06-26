#!/usr/bin/env python3
"""voiceprobe — THROWAWAY de-risk spike for Slipstream's voice plane.

Run as root (scapy uses libpcap):
    sudo python3 voiceprobe.py <selftest|capture|live> --iface en0

Only sniffs and emits decoy packets. Never touches pf, routes, or Discord's
sockets. Ctrl-C stops; nothing persists.
"""
import argparse
import sys
import time

from scapy.all import (
    AsyncSniffer, sniff, send, IP, UDP, Raw, get_if_addr,
)
from primes import classify, build_fake_stun, build_fake_discord_prime

VOICE_LO, VOICE_HI = 50000, 65535   # Discord voice UDP server-port range
TTL_FAKE = 4                        # primes die in-country, never reach server
REPEAT = 6                          # primes per (kind) per primed datagram
CUTOFF = 4                          # only prime the first N datagrams of a flow


def selftest(iface: str) -> int:
    dst = "1.1.1.1"            # unreachable at ttl=4; just needs to egress
    sport, dport = 54321, 3478
    payload = build_fake_stun()

    sniffer = AsyncSniffer(
        iface=iface,
        filter=f"udp and dst host {dst} and dst port {dport}",
        count=1, timeout=5,
    )
    sniffer.start()
    time.sleep(0.3)
    pkt = IP(dst=dst, ttl=TTL_FAKE) / UDP(sport=sport, dport=dport) / Raw(payload)
    send(pkt, iface=iface, verbose=0)
    sniffer.join()

    got = sniffer.results
    if got and got[0].haslayer(IP) and got[0].haslayer(UDP) \
            and got[0][IP].ttl == TTL_FAKE and got[0][UDP].dport == dport:
        print(f"PASS: fake left {iface} ttl={TTL_FAKE} dport={dport} 5-tuple intact")
        return 0
    print("FAIL: injected packet not seen on egress "
          "(raw inject blocked, wrong --iface, or offload rewrote ttl?)")
    return 1


def capture(iface: str) -> int:
    localip = get_if_addr(iface)
    print(f"CAPTURE on {iface} (local {localip}). Join a Discord voice call. "
          f"Ctrl-C to stop.")
    flows = {}

    def on_pkt(p):
        if not (p.haslayer(IP) and p.haslayer(UDP)):
            return
        ip, udp = p[IP], p[UDP]
        if ip.src != localip:
            return  # outbound only
        key = (ip.src, udp.sport, ip.dst, udp.dport)
        payload = bytes(udp.payload)
        kind = classify(payload)
        f = flows.setdefault(key, {"n": 0, "kinds": set()})
        f["n"] += 1
        f["kinds"].add(kind)
        if f["n"] <= 3:
            print(f"flow {key} pkt#{f['n']} len={len(payload)} class={kind}")

    sniff(iface=iface,
          filter=f"udp and src host {localip} and dst portrange {VOICE_LO}-{VOICE_HI}",
          prn=on_pkt, store=0)
    return 0


def inject_primes(iface, src, sport, dst, dport):
    # Inject the WHOLE burst (not just the first packet — sonicdpi's NE bug).
    # 12 primes per call: REPEAT x {fake_stun, fake_discord}.
    for _ in range(REPEAT):
        for payload in (build_fake_stun(), build_fake_discord_prime()):
            pkt = IP(src=src, dst=dst, ttl=TTL_FAKE) \
                / UDP(sport=sport, dport=dport) / Raw(payload)
            send(pkt, iface=iface, verbose=0)


def live(iface: str) -> int:
    localip = get_if_addr(iface)
    print(f"LIVE on {iface} (local {localip}). Voice should be BLOCKED otherwise. "
          f"Join a Discord call now. Ctrl-C to stop.")
    flows = {}

    def on_pkt(p):
        if not (p.haslayer(IP) and p.haslayer(UDP)):
            return
        ip, udp = p[IP], p[UDP]
        if ip.src != localip:
            return  # outbound only
        key = (ip.src, udp.sport, ip.dst, udp.dport)
        f = flows.setdefault(key, {"primed": 0})
        if f["primed"] < CUTOFF:
            inject_primes(iface, ip.src, udp.sport, ip.dst, udp.dport)
            f["primed"] += 1
            print(f"primed flow {key} ({f['primed']}/{CUTOFF})")

    sniff(iface=iface,
          filter=f"udp and src host {localip} and dst portrange {VOICE_LO}-{VOICE_HI}",
          prn=on_pkt, store=0)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["selftest", "capture", "live"])
    ap.add_argument("--iface", required=True)
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest(args.iface)
    if args.mode == "capture":
        return capture(args.iface)
    if args.mode == "live":
        return live(args.iface)
    print(f"mode {args.mode} not yet implemented")
    return 2


if __name__ == "__main__":
    sys.exit(main())

# Spike 0 Results

## Run 1 — 2026-06-26 — INVALID (VPN confound + filter bug)

- macOS: (user, MacBook-Pro), iface en0, local 192.168.31.70
- **selftest: PASS** — `fake left en0 ttl=4 dport=3478 5-tuple intact`. The
  entitlement-free inject primitive works on macOS as root. (Only valid signal.)
- **capture / live: INVALID.** VPN was ON for the whole run → all Discord traffic
  went through the VPN tunnel (utun), invisible to the en0 sniffer. The only flow
  seen was `192.168.31.70:57621 → 192.168.31.255:57621` = **Spotify LAN broadcast**,
  which the too-broad filter (`dst portrange 50000-65535`) matched and primed. The
  `MAC address not found, using broadcast` spam was scapy L3-sending to `.255`.
- With VPN on, voice worked — **the VPN did that, not voiceprobe** (which never
  touched Discord). With VPN off, Discord died completely and voiceprobe only
  primed Spotify → no effect. **Our approach remains untested.**

### Fixes applied (commit after this entry)
- `voice_filter()` now excludes LAN / link-local / broadcast / multicast dst, so
  Spotify (57621→.255) and mDNS can no longer be mistaken for Discord voice.
- Dropped the no-op `iface=` from `send()` (L3 routes itself) — removes the warning.

### Key learning — ordering changes
User reports Discord is "completely dead" without VPN → the **TCP gateway** is
blocked too, not just UDP voice. A voice UDP flow cannot form until the gateway
connects. So **TCP desync (gateway + YouTube) is the prerequisite** and must be
validated/built before the voice plane can even be tested. Spec §10 build order
should put the TCP plane first; voice priming is tested only once Discord can
connect and actually emits voice datagrams to a public discord.media IP.

### Re-test protocol (Run 2) — MUST be VPN OFF
1. Turn VPN OFF. Confirm Discord is dead.
2. `sudo .venv/bin/python voiceprobe.py capture --iface en0`, open Discord, try to
   join voice. Question: do we see ANY outbound flow to a **public** IP on
   50000–65535? Report the dst IP + classes.
   - Flow appears → voice UDP forms; proceed to `live` priming test.
   - Nothing appears → gateway is blocked; Discord never reaches a voice server →
     build the TCP plane first, then revisit voice.

## Confirmed 2026-06-26 — gateway/API is TCP-blocked (not just voice)

User screenshot (VPN OFF): discord.com web loads the static shell but shows no
servers/content (empty "Знаете ли вы?"), and the desktop launcher hangs on
"checking for updates" forever. => `gateway.discord.gg` (WSS) + API + updater are
DPI-blocked at the TCP/TLS layer. Voice cannot form until this is beaten. The TCP
desync plane is the real foundation. User wants a launch-time AUTO-SWEEP (try
strategies, pick the winner) rather than a fixed config — resilient, ISP-agnostic.

## Spike 1 — TCP desync auto-sweep (`tcpsweep.py`) — RUN THIS NEXT (no root, no VPN)

Engine validated locally against a non-blocked host (baseline + all 5 strategies
complete TLS in ~80–140ms). On the blocked network it will show which strategy
beats the DPI.

```bash
cd slipstream/spike && source .venv/bin/activate   # (no sudo)
python3 tcpsweep.py
```
Read the table + the "winners" block. Expected on the blocked network:
- `gateway.discord.gg` baseline=**fail** (proves the probe detects the block), and
  ideally one of `split_sni / split2 / multisplit / tlsrec_sni` = **ok** (the
  winning strategy for this ISP → goes straight into the engine).
- If ALL strategies fail on gateway: the userspace-only set is insufficient here →
  we add `fake`/low-TTL (needs root raw socket) to the sweep next.
- `www.youtube.com` is throttled, not hard-blocked, so baseline may be `ok` there;
  YouTube needs a bandwidth test, not a handshake test (separate probe later).

Report the full table. The winning strategy + the per-host baseline verdicts
define Phase 1 (the TCP plane + its auto-picker).

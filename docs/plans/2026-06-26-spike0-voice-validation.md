# Spike 0 — Voice Plane Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove (or disprove) that on macOS, without a NetworkExtension entitlement, we can passively observe Discord's outbound voice UDP via libpcap and inject low-TTL fake primes on the same 5-tuple via raw/L3 send — leaving Discord's real socket untouched — and thereby unblock voice on a DPI-throttled network.

**Architecture:** A throwaway Python+scapy harness (`voiceprobe`). Pure byte-builders/classifiers (`primes.py`) are unit-tested and become the golden vectors for the future Rust `bypass-engine`. The harness has three modes: `selftest` (prove the entitlement-free inject primitive works on macOS as root), `capture` (prove we observe+classify real voice packets), `live` (the make-or-break: observe + inject primes during a real, otherwise-blocked Discord call).

**Tech Stack:** Python 3, scapy (libpcap capture + L3 raw inject), pytest. Run as root. macOS.

**Scope note:** This plan covers Spike 0 ONLY — the de-risk gate from the design spec (`docs/specs/2026-06-26-slipstream-design.md` §10). It produces a working, self-contained validation harness. The product engine (Rust `bypass-engine` + `bypassd` + SwiftUI app) is planned separately AFTER this spike passes, or the voice plane pivots to the utun fallback if it fails. The pure functions built here (`classify`, `build_fake_*`) port directly to Rust with their golden vectors.

**Reality note on live steps:** Tasks 5 and 6 must be run by the user (the human on the DPI-blocked RU network, in a real Discord voice channel). Claude cannot join a voice call or be on that network. Those steps give exact run commands + pass/fail criteria; the user runs them and reports back. Tasks 1–4 are fully verifiable by the implementer.

---

## File Structure

All spike code lives under `slipstream/spike/` (throwaway, isolated from future product code):

- `spike/primes.py` — pure logic: `classify(payload)`, `build_fake_stun()`, `build_fake_discord_prime()`. No I/O. Unit-tested. **Future Rust golden-vector source.**
- `spike/test_primes.py` — pytest golden-vector tests for `primes.py`.
- `spike/voiceprobe.py` — root CLI harness: `selftest` | `capture` | `live` modes. scapy I/O only.
- `spike/requirements.txt` — `scapy`, `pytest`.
- `spike/README.md` — run instructions, safety notes, pass/fail criteria.
- `spike/RESULTS.md` — filled after live runs; records the decision (proceed vs pivot to utun).
- `slipstream/.gitignore` — ignore `__pycache__`, `.venv`.

---

## Task 1: Scaffold spike directory

**Files:**
- Create: `slipstream/.gitignore`
- Create: `slipstream/spike/requirements.txt`
- Create: `slipstream/spike/README.md`

- [ ] **Step 1: Create `.gitignore`**

```
__pycache__/
*.pyc
.venv/
spike/.venv/
```

- [ ] **Step 2: Create `spike/requirements.txt`**

```
scapy>=2.5.0
pytest>=8.0.0
```

- [ ] **Step 3: Create `spike/README.md`**

````markdown
# voiceprobe — Slipstream voice-plane de-risk spike (THROWAWAY)

Validates: on macOS, entitlement-free, can we observe Discord voice UDP (libpcap)
and inject low-TTL fake primes on the same 5-tuple (raw/L3 send) to unblock voice
on a DPI-throttled network, without touching Discord's own socket?

NOT production. Becomes Rust `bypass-engine` + `bypassd` once validated.

## Setup
```bash
cd slipstream/spike
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Unit tests (no root, no network)
```bash
pytest -v
```

## Run (needs root; scapy uses libpcap)
```bash
sudo .venv/bin/python voiceprobe.py selftest --iface en0
sudo .venv/bin/python voiceprobe.py capture  --iface en0   # join a Discord call
sudo .venv/bin/python voiceprobe.py live     --iface en0   # join a call; voice must be blocked otherwise
```
Find your interface with `route get default | grep interface`.

## Safety
This tool ONLY sniffs and emits extra decoy UDP datagrams. It does NOT modify pf,
routes, DNS, or Discord's sockets. Ctrl-C stops it instantly; nothing persists.
Blast radius is minimal — that is why this is the first step.

## Pass/Fail
- selftest PASS: injected fake observed leaving the iface with ttl=4 and the exact
  5-tuple we set.
- capture PASS: we see and correctly classify (stun / ip-discovery / rtp) outbound
  voice datagrams during a call.
- live PASS: with voice otherwise blocked, running `live` lets a Discord call
  connect and you hear other people.
- live FAIL: voice still dead → pivot voice plane to the utun fallback (spec §3).
````

- [ ] **Step 4: Commit**

```bash
cd slipstream
git add .gitignore spike/requirements.txt spike/README.md
git commit -m "spike: scaffold voiceprobe de-risk harness"
```

---

## Task 2: `classify()` — voice packet classifier (TDD)

**Files:**
- Create: `slipstream/spike/test_primes.py`
- Create: `slipstream/spike/primes.py`

- [ ] **Step 1: Write the failing tests**

Create `spike/test_primes.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd slipstream/spike && pytest test_primes.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'primes'`

- [ ] **Step 3: Write minimal implementation**

Create `spike/primes.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify classify passes (builders still fail import)**

Run: `cd slipstream/spike && pytest test_primes.py -v`
Expected: the 4 `test_classify_*` PASS. Import of `build_fake_*` still resolves (names not yet defined → `ImportError`). If the whole file errors on import, that is expected until Task 3 adds the builders. To check just classify now:
Run: `pytest test_primes.py -v -k classify` after temporarily importing only `classify` — OR proceed to Task 3 which adds the builders so the import line resolves fully.

- [ ] **Step 5: Commit**

```bash
cd slipstream
git add spike/primes.py spike/test_primes.py
git commit -m "spike: voice packet classifier with golden-vector tests"
```

---

## Task 3: Fake prime builders (TDD)

**Files:**
- Modify: `slipstream/spike/test_primes.py` (add builder tests)
- Modify: `slipstream/spike/primes.py` (add builders)

- [ ] **Step 1: Write the failing tests**

Append to `spike/test_primes.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd slipstream/spike && pytest test_primes.py -v`
Expected: FAIL — `ImportError: cannot import name 'build_fake_stun'`

- [ ] **Step 3: Write minimal implementation**

Append to `spike/primes.py`:

```python
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
```

- [ ] **Step 4: Run all tests to verify they pass**

Run: `cd slipstream/spike && pytest test_primes.py -v`
Expected: all 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd slipstream
git add spike/primes.py spike/test_primes.py
git commit -m "spike: fake STUN + Discord prime builders (golden vectors)"
```

---

## Task 4: `voiceprobe` CLI + `selftest` mode

Proves the entitlement-free inject primitive: as root, we can put a crafted UDP
datagram with an arbitrary 5-tuple and TTL=4 onto the wire, and observe it leaving.

**Files:**
- Create: `slipstream/spike/voiceprobe.py`

- [ ] **Step 1: Write the harness with `selftest`**

Create `spike/voiceprobe.py`:

```python
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["selftest", "capture", "live"])
    ap.add_argument("--iface", required=True)
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest(args.iface)
    print(f"mode {args.mode} not yet implemented")
    return 2


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Verify unit tests still pass (no regression)**

Run: `cd slipstream/spike && pytest -v`
Expected: all 7 `primes` tests PASS (voiceprobe imports cleanly).

- [ ] **Step 3: Run selftest as root and observe**

Run:
```bash
cd slipstream/spike
IFACE=$(route get default | awk '/interface:/{print $2}')
sudo .venv/bin/python voiceprobe.py selftest --iface "$IFACE"
```
Expected: `PASS: fake left <iface> ttl=4 dport=3478 5-tuple intact`

If FAIL: try the real Wi-Fi/Ethernet iface explicitly; if egress capture never
shows the packet, the L3 raw-inject primitive is the problem — record it; the
voice plane will need the utun fallback regardless. This is a key data point.

- [ ] **Step 4: Commit**

```bash
cd slipstream
git add spike/voiceprobe.py
git commit -m "spike: voiceprobe CLI + selftest (entitlement-free inject primitive)"
```

---

## Task 5: `capture` mode — observe + classify real voice (user-run)

Proves the observe half: during a real call we see outbound voice datagrams and
classify them. No injection. Confirms our BPF filter + classifier match reality.

**Files:**
- Modify: `slipstream/spike/voiceprobe.py`

- [ ] **Step 1: Add `capture`**

In `spike/voiceprobe.py`, replace the `capture`/`live` fallback branch by adding
this function and wiring it in `main()`:

```python
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
```

Wire it in `main()` — change the fallback to:

```python
    if args.mode == "selftest":
        return selftest(args.iface)
    if args.mode == "capture":
        return capture(args.iface)
    print(f"mode {args.mode} not yet implemented")
    return 2
```

- [ ] **Step 2: Verify unit tests still pass**

Run: `cd slipstream/spike && pytest -v`
Expected: all 7 tests PASS.

- [ ] **Step 3: USER RUN — capture during a call**

Run:
```bash
cd slipstream/spike
IFACE=$(route get default | awk '/interface:/{print $2}')
sudo .venv/bin/python voiceprobe.py capture --iface "$IFACE"
```
Then join any Discord voice channel.
Expected: lines like `flow (<localip>,<sport>,<discordip>,<dport>) pkt#1 len=74 class=ip-discovery` then `class=stun` / `class=rtp`.
PASS: we see outbound voice flows and at least `ip-discovery` + `rtp` get classified (not all `other`). Report the observed `dport` range — if voice uses ports outside 50000–65535, record them to widen the filter.

- [ ] **Step 4: Commit**

```bash
cd slipstream
git add spike/voiceprobe.py
git commit -m "spike: capture mode — observe + classify outbound voice"
```

---

## Task 6: `live` mode — observe + inject (THE de-risk, user-run)

The make-or-break. With voice otherwise blocked, observe new voice flows and inject
the full prime burst (TTL=4) on the same 5-tuple. Discord's real socket is never
touched.

**Files:**
- Modify: `slipstream/spike/voiceprobe.py`

- [ ] **Step 1: Add `inject_primes` + `live`**

Append to `spike/voiceprobe.py`:

```python
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
```

Wire it in `main()` — change the fallback to:

```python
    if args.mode == "capture":
        return capture(args.iface)
    if args.mode == "live":
        return live(args.iface)
    print(f"mode {args.mode} not yet implemented")
    return 2
```

- [ ] **Step 2: Verify unit tests still pass**

Run: `cd slipstream/spike && pytest -v`
Expected: all 7 tests PASS.

- [ ] **Step 3: USER RUN — live during a blocked call**

Pre-condition: Discord voice is currently BROKEN on this Mac (no other bypass running).
Run:
```bash
cd slipstream/spike
IFACE=$(route get default | awk '/interface:/{print $2}')
sudo .venv/bin/python voiceprobe.py live --iface "$IFACE"
```
Then join a Discord voice channel and try to talk/listen.
- PASS: the call connects and you hear other people while only `voiceprobe live` is running. → Observe-Inject works. Proceed to Phase 1 (Rust engine + bypassd).
- PARTIAL: connects intermittently / one-way audio. → Record; try raising `REPEAT`/`CUTOFF` and re-run. Note the winning values.
- FAIL: voice stays dead. → Observe-Inject timing is too weak; pivot voice plane to the utun fallback (spec §3 Plan B). This is still a successful spike — it answered the question.

- [ ] **Step 4: Commit**

```bash
cd slipstream
git add spike/voiceprobe.py
git commit -m "spike: live mode — observe + inject primes (voice de-risk)"
```

---

## Task 7: Record results + decision gate

**Files:**
- Create: `slipstream/spike/RESULTS.md`

- [ ] **Step 1: Write `RESULTS.md` from the live runs**

Create `spike/RESULTS.md` and fill in the real observations:

```markdown
# Spike 0 Results

- macOS version:
- Interface / ISP / region:
- selftest: PASS / FAIL (notes)
- capture: voice dport range observed = ____ ; classes seen = ____
- live: PASS / PARTIAL / FAIL
  - winning REPEAT / CUTOFF / TTL if tuned:
  - notes:

## Decision
- [ ] Observe-Inject validated → proceed to Phase 1 (Rust `bypass-engine` + `bypassd`)
- [ ] Observe-Inject failed → voice plane pivots to utun fallback (spec §3); write Phase 1 around utun
```

- [ ] **Step 2: Commit**

```bash
cd slipstream
git add spike/RESULTS.md
git commit -m "spike: record voice de-risk results + decision"
```

---

## Self-Review (done by author)

- **Spec coverage:** This plan covers spec §10 "Spike 0" and validates §3 voice plane (observe-inject) with the §3 utun fallback as the documented failure branch. The other phases (1–5) are intentionally out of scope and planned after this gate.
- **Placeholders:** None — all code is complete. `RESULTS.md` is a fill-in artifact by design (its values come from live hardware runs, not from the plan).
- **Type consistency:** `classify`, `build_fake_stun`, `build_fake_discord_prime`, `STUN_MAGIC_COOKIE` names are identical across `primes.py`, `test_primes.py`, and `voiceprobe.py`. `inject_primes(iface, src, sport, dst, dport)` signature matches its call site. Constants `VOICE_LO/VOICE_HI/TTL_FAKE/REPEAT/CUTOFF` defined once, used consistently.
- **Live-step honesty:** Tasks 5–6 are explicitly user-run with pass/fail criteria; the implementer cannot self-verify them (no access to the blocked network / a voice call).

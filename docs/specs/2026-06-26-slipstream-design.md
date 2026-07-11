# Slipstream — Design Spec

Date: 2026-06-26
Status: Approved (design), pre-implementation
Working name: **Slipstream**

A native macOS menu-bar app that bypasses DPI-based throttling/blocking (Russian
TSPU and similar carrier-grade DPI) for **Discord (including voice)** first, then
**YouTube** and other services. Own independent desync engine. One-click UX.
Open-source (MIT). No paid Apple Developer account required.

---

## 1. Goals / Non-goals

### Goals
- Restore **Discord** on macOS: text, servers, gateway, API, updater, **and voice (UDP/RTP)**.
- Restore **YouTube** (remove DPI throttle) as the second target.
- Extensible to other services (Instagram, etc.) via profiles/hostlists.
- **One-click**: a single master toggle. After a one-time admin prompt, enabling/disabling is silent.
- Native, calm, Apple-grade menu-bar UX.
- **Own engine**, not a wrapper. Borrow *algorithms/ideas* from MIT/Apache sources; depend on none.
- Ship without a paid Apple Developer account: ad-hoc signing + Gatekeeper `xattr` flow.

### Non-goals
- Not a VPN, not a relay, not a proxy service. No third-party servers in the normal path.
- Not a full traffic tunnel. We desync the minimum needed and leave everything else alone.
- We do **not** attempt to defeat a full IP null-route (see Honest Constraint).

---

## 2. Honest Constraint (read first)

Local DPI bypass works **only while the block is DPI/SNI/pattern-based**. If a
provider/TSPU fully **IP null-routes** the target's servers, packets never arrive
and **no local tool on any OS** can help — only an external relay (VPN/VLESS) works.

Validated assumption for this project: the target user's Windows `zapret` setup
restores Discord **voice** on their network → the block is DPI, not IP → a local
macOS approach is viable. The README ships this caveat plainly.

---

## 3. Chosen Architecture: "Observe-Inject" (Approach C)

Two earlier candidates both *intercepted and re-originated* the real voice
datagrams (pf-rdr→relay, or utun→re-origin), changing the externally-visible
5-tuple → high risk of breaking Discord's STUN/IP-discovery / symmetric-NAT voice
path. **Observe-Inject avoids this entirely**: the real Discord UDP socket is never
touched; we only *observe* it (BPF) and *inject* low-TTL decoys on the same 5-tuple
(raw socket). This is the zapret/GoodbyeDPI model (WinDivert/nfqueue) ported to
macOS via `/dev/bpf` + `SOCK_RAW`, with no NetworkExtension entitlement.

### TCP plane (Discord text/gateway/API, YouTube web)
`pf rdr` on `lo0` for ports 80/443 → local transparent proxy in `bypassd` →
recover original destination via `DIOCNATLOOK` on `/dev/pf` → apply userspace
desync to the ClientHello/HTTP bytes → `connect()` upstream → splice.
This half is battle-proven verbatim by zapret/tpws and PunchThrough.

### Voice plane (Discord UDP/RTP) — the novel part
Discord opens its UDP socket **untouched**. `bypassd` runs a passive **BPF**
observer (`/dev/bpf`) on outbound UDP to Discord voice ranges. On the first
datagrams of a new flow it classifies the packet, then **injects ~6 low-TTL
(TTL≈4) fake primes** (fake STUN / fake Discord / optional fake QUIC-Initial) on
the *same 5-tuple* via a raw socket (`SOCK_RAW` + `IP_HDRINCL`). The fakes die
in-country (TTL too low to reach the server) but the TSPU ingests them and
mis-tracks the flow. The real RTP stream continues, **NAT mapping preserved**.

Classifiers (from sonicdpi, transport-agnostic):
- RTP: `len>=12 && byte0 in {0x80,0x90} && byte1 in {0x78,0xF8}`
- Discord IP-discovery: `len==74 && bytes[0..4]==00 01 00 46`
- STUN: magic cookie `0x2112A442`

Tunables: cutoff ≈ first 4 datagrams, repeat ≈ 6, optional `udplen` +2 padding.

### YouTube QUIC
Default: `pf`-drop UDP/443 to verified Google prefixes → Chrome falls back to TCP
→ handled by the TCP plane (simple, robust). Optional: QUIC-Initial low-TTL prime.

### Fallback
If Observe-Inject timing proves too weak vs current TSPU (the fake arrives slightly
*after* the real first datagram, unlike inline WinDivert/nfqueue), escalate the
voice plane to **utun re-origination** (the SplitPath Plane B design): root utun via
`socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` + `com.apple.net.utun_control`
(root-gated, entitlement-free), route only the voice UDP range in, desync, re-inject.
This is the documented Plan B — validated by Spike 0 before any commitment.

### Why this is original work (no reference implementation)

No existing project ships **entitlement-free macOS Discord-voice desync**. Verified
from source, not READMEs:
- **SonicDPI** markets "returns voice channels" — but that claim is cross-platform
  aggregate, true only on Windows (WinDivert) / Linux (NFQUEUE). Its **shipping
  macOS backend** (`crates/sonicdpi-platform/src/macos.rs`, pf rdr-to transparent
  proxy) is **TCP-only**; its docs call Discord voice on macOS "completely broken"
  there. Its only macOS UDP path is a `NEFilterPacketProvider` System Extension that
  **requires** a paid Apple Developer Program membership + the hand-reviewed
  `com.apple.developer.networking.networkextension` entitlement + Developer ID +
  notarization ("Without entitlement the System Extension simply will not load.
  There is no workaround that ships to end users") — and is itself untested/aspirational
  with a known burst-injection bug (sends only the first of 12 primes).
- **zapret/tpws** on macOS is TCP-only (pf rdr + DIOCNATLOOK). **byedpi** README
  states it cannot do Discord voice.

So Slipstream's voice plane is **original R&D**, not a port. We reuse only the
**desync logic** (voice-prime fake STUN/Discord burst, classifiers); the **transport**
(entitlement-free UDP capture/inject via BPF + raw socket) is the gap we fill. Avoid
SonicDPI's bug: inject the **entire** prime burst, not the first packet. This is the
single reason Spike 0 leads the build order.

---

## 4. Components (clean isolation, independently testable)

### 4.1 `bypass-engine` — Rust library (pure logic, zero IO)
The OS-independent desync core. Input: bytes + flow metadata. Output: byte
operations / packets to inject. No sockets, no syscalls → fully unit-testable
off-host with golden vectors.

Strategy set:
- TCP/TLS: `multisplit` (at SNI/midsld offsets), `multidisorder` (TTL=1 send trick),
  `tlsrec` (split ClientHello into 2 TLS records), `oob` (MSG_OOB), `fake`
  (low-TTL fake ClientHello + fooling: `badseq`/`badsum`), `seqovl`.
- UDP voice: prime builder (fake STUN/Discord/QUIC-Initial), TTL/cutoff/repeat policy,
  classifiers.
- Profile + hostlist matching; offset grammar relative to parsed SNI/Host.

### 4.2 `bypassd` — Rust binary (root LaunchDaemon, all IO/privilege)
- pf anchor management: load rdr rules into a private anchor (`pfctl -a slipstream`),
  patch idempotently, `pfctl -E`; **crash-safe teardown**.
- TCP transparent proxy: accept redirected conns, `DIOCNATLOOK` original dst,
  call `bypass-engine`, splice to upstream.
- Voice engine: BPF observer + raw-socket injector driven by `bypass-engine`.
- Control socket: root-owned unix socket, **fixed verb set** only.
- Ships its own `net/pfvar.h` (Apple removed `DIOCNATLOOK` + `struct pfioc_natlook`
  from the SDK); runtime-probes the ioctl number with a version table + fallback.

### 4.3 Slipstream.app — SwiftUI menu-bar (unprivileged)
`LSUIElement=true`, sandbox off, entitlements = `network.client` + `network.server`
only (no NetworkExtension). Master on/off, per-service rows (Discord/YouTube),
status, strategy/profile popover. Depends only on the socket protocol. Performs the
one-time privileged install.

---

## 5. Privilege & Install Model

- First "Enable" → `osascript ... with administrator privileges` (one GUI password)
  → copy `bypassd` to `/usr/local/slipstream/` `root:wheel 0755`, write
  `/Library/LaunchDaemons/dev.slipstream.helper.plist`, `launchctl bootstrap`.
- App ↔ helper: root-owned socket `/var/run/slipstream.sock` (restricted to admin
  group). Protocol = **fixed verbs**: `enable`, `disable`, `status`,
  `set-profile <name>`, `reload-hostlist`. No arbitrary args, no shell.
- **Security:** NOT a NOPASSWD-sudoers-on-a-script design (the LPE footgun shipped by
  darkware/PunchThrough). Whole `/usr/local/slipstream` tree `root:wheel`,
  non-world-writable. Helper reads config only from a root-owned path; never sources
  user-writable files in root context.
- Root is unavoidable (pf/pfctl, `/dev/pf` DIOCNATLOOK, `/dev/bpf`, raw socket) but
  none of it needs the paid NetworkExtension entitlement.

---

## 6. Technique Matrix (MVP: Discord-first)

| Target | Strategy | Layer | Idea source |
|---|---|---|---|
| Discord TCP (gateway/API/web) | multisplit@SNI + multidisorder(TTL=1) + tlsrec; aggressive: fake-CH low-TTL | TCP/TLS | zapret / byedpi / SpoofDPI |
| Discord voice | observe + inject fake STUN/Discord prime, TTL=4, cutoff≈4, repeat≈6 | UDP | sonicdpi |
| YouTube web | multisplit@SNI + tlsrec | TCP/TLS | byedpi / SpoofDPI |
| YouTube QUIC | pf-drop UDP/443 → TCP fallback (default); opt QUIC-Initial prime | UDP | custom / sonicdpi |

Profiles: per-target TOML. `autohostlist` learns blocked SNIs by redirecting all
80/443 and deciding per-SNI. `blockcheck` sweep retunes strategies (TSPU is a
per-ISP moving target; e.g. `badseq` currently beats PAWS/timestamp on some RU ISPs).

License hygiene: reimplement techniques from MIT/Apache sources (zapret MIT,
byedpi MIT, sonicdpi MIT/Apache). Do **not** copy GPL SpoofDPI source — reimplement
its TTL trick from the algorithm.

---

## 7. Crash-safety (the #1 reliability detail)

This early design is superseded by private-anchor ownership. Current teardown
flushes only `rules` and `nat` from `com.apple/slipstream`, releases its own PF
enable token, and never restores or replaces `/etc/pf.conf`. `-F all` is forbidden
because it includes the shared PF state table. **A crash must never strand the
user offline or mutate unrelated network state.**

---

## 8. Distribution

- Universal build: Rust `cargo build --release` arm64 + x86_64 → `lipo`; Swift via
  SwiftPM/Xcode. Ad-hoc `codesign --force --deep --sign -`.
- DMG. First launch: right-click→Open or `xattr -cr /Applications/Slipstream.app`
  (documented; installer also clears quarantine on the `/usr/local/slipstream` payload).
- App-Translocation workaround: copy bundled payload to a writable temp dir before
  the privileged install.
- No notarization, no paid account. Expect ongoing support burden: unsigned + pf +
  DIOCNATLOOK are fragile across macOS point releases.

---

## 9. Testing

- `bypass-engine`: unit tests on byte transforms (split offsets, tlsrec records,
  fake-packet construction) + golden vectors; voice classifiers on captured samples.
- Integration: a loopback DPI-simulator asserting desync changed the wire bytes as expected.
- Manual hardware matrix on a real RU network: Discord text / Discord voice / YouTube,
  per macOS version (Sequoia 15, Tahoe 26).

---

## 10. Build Order

- **Spike 0 — DE-RISK FIRST (before any UI).** Throwaway script: BPF-sniff a real
  Discord voice call + raw-inject primes; confirm the call connects. If it fails →
  pivot the voice plane to the utun fallback. This validates the single make-or-break
  assumption before building anything else.
- **Phase 1:** `bypass-engine` + `bypassd` TCP plane (pf-rdr + proxy + DIOCNATLOOK +
  desync) → Discord text + YouTube web on macOS.
- **Phase 2:** voice plane (BPF + raw socket) → Discord voice.
- **Phase 3:** SwiftUI menu-bar + privileged installer + one-click toggle.
- **Phase 4:** profiles / autohostlist / blockcheck + DMG polish + crash-safety hardening.
- **Phase 5:** additional services.

---

## 11. Top Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| 1 | Observe-Inject timing weaker than inline (fake arrives after real) | high | tune repeat/cutoff; utun fallback; **validate in Spike 0** |
| 2 | `DIOCNATLOOK` ioctl/struct fragile across macOS releases | medium | runtime probe + version table + ship own `pfvar.h` |
| 3 | NIC TSO/checksum offload "fixes" low-TTL/badsum fakes | medium | detect; `ifconfig -tso`; or rely on TTL only |
| 4 | Unsigned Gatekeeper friction | medium | documented `xattr` + installer clears quarantine |
| 5 | pf.conf patch conflicts with Little Snitch / LuLu / MDM | medium | private anchor; detect conflicts; document |
| 6 | UDP relay/inject jitter at ~50pps voice | low | keep injector lean; real flow is untouched in Observe-Inject |

---

## 12. Open Questions (resolve during planning)

- Exact Discord voice UDP port ranges + current `discord.media` prefixes to scope BPF/pf.
- Whether QUIC default should be drop-to-TCP or prime (decide after Phase 1 YouTube data).
- Helper auto-update channel (out of MVP scope).

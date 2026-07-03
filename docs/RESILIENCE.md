# Slipstream — Resilience Design ("install once, never touch")

Goal: a zero-touch system. After one install the user does nothing — it survives
every routine failure automatically. The only allowed manual events are shipping
bugfixes / new desync strategies (and even those we minimise via auto-update).

## Two honest limits (cannot be fully zero-touch)

1. **TSPU evolution.** When the Russian DPI upgrades past *all* of our current
   strategies, genuinely new ones are needed — a shipped update. Mitigations push
   this horizon far out but can't remove it:
   - **auto-sweep** adapts within the known strategy set (done),
   - **auto-update of the strategy list** pulls new community recipes without a
     code change (planned, P2).
2. **IP null-route.** If Discord's server IPs are fully blocked (not DPI/SNI/DNS),
   no local technique works — only an external relay. Optional **auto-fallback to
   a relay/VPN** when local desync fails entirely. Out of pure-local scope; needs
   a server.

Everything below this line *can* be made automatic.

## Failure-mode taxonomy — current state → what's needed

Legend: ✅ done · 🟡 partial · ❌ missing

### A. Availability — is the daemon running?
| Mode | State | Needed |
|---|---|---|
| Start at boot | ✅ LaunchDaemon `RunAtLoad` via `--install` | — |
| Restart on crash | ✅ launchd `KeepAlive` | — |
| Hard-kill (SIGKILL) leaves pf rules | 🟡 self-heal on next start + pf re-apply monitor | tiny watchdog that resets pf if the daemon vanishes and stays down |
| Survive logout/login | ✅ system-level LaunchDaemon (not Agent) | — |

### B. Bypass correctness — is it still beating the DPI?
| Mode | State | Needed |
|---|---|---|
| Block strategy decays (TLS starts failing) | ✅ auto-sweep climbs the ladder, re-caches | — |
| **Throttle decays** (TLS ok but download crawls) | ❌ probe only checks handshake | throughput probe on a canary; if slow, escalate strategy (fake variants) |
| Detect decay *before* the user notices | ❌ reactive only | periodic canary against `gateway.discord.gg`; re-sweep on failure |
| **All** strategies fail (TSPU leap) | ❌ | auto-update strategy list (P2); then relay fallback |
| DoH resolver blocked | 🟡 1.1.1.1 → 8.8.8.8, verified TLS, short negative cache | more resolvers + ECH; rotate on failure |

### C. Network transitions — does it survive change?
| Mode | State | Needed |
|---|---|---|
| Wi-Fi ↔ Ethernet ↔ cellular | ✅ monitor re-detects default iface, restarts voice sniffer, re-applies pf | — |
| Sleep / wake | 🟡 monitor detects long tick gaps and re-arms pf/voice sockets | re-validate canary on wake (`NSWorkspace`/`pmset` hook) |
| Join a *different* network (café, no TSPU) | 🟡 auto-sweep finds "plain" works | re-sweep on network change; don't keep stale per-host strategies across networks |
| User toggles a VPN | ✅ default route via `utun*` makes Slipstream dormant | scope the QUIC block to bypassed destinations for non-full-tunnel edge cases |

### D. Long-running stability — does it last days/weeks?
| Mode | State | Needed |
|---|---|---|
| **DoH cache never expires** (Cloudflare IPs rotate) | ✅ per-entry TTL + bounded cache | — |
| Strategy cache unbounded | ✅ LRU cap + versioned cache invalidation | — |
| Voice `flows` dict unbounded | 🟡 bounded table; full-table clear on cap | TTL/LRU eviction of idle flows |
| FD / task leaks | 🟡 likely ok | audit under day-long load |

### E. Safety — never strand the user offline
| Mode | State | Needed |
|---|---|---|
| Clean exit restores pf | ✅ SIGINT/TERM/HUP/TSTP + atexit | — |
| SIGKILL / panic leaves pf | 🟡 next start resets + monitor re-applies when active | watchdog (E/A) |
| QUIC block breaks all UDP/443 always-on | 🟡 avoided for full-tunnel VPN via dormant mode; broad otherwise | scope to bypassed dests; or only block QUIC for hosts we desync |
| Self-heal stale instances on start | ✅ | — |

### F. Observability — know it's working
| Mode | State | Needed |
|---|---|---|
| Status indicator | ✅ menu-bar state/detail from `/var/run/slipstream.status` | add throughput/quality details |
| Persistent logs | 🟡 launchd writes `/var/log/slipstream.log` | rotating log file for post-mortem |
| Health metric | 🟡 live conns, learned hosts, dead cache, geph state | rolling success-rate + canary result; surface in UI |

### G. Updates — the maintenance horizon
| Mode | State | Needed |
|---|---|---|
| New strategies without a rebuild | ❌ | signed strategy-list fetched periodically (community recipes) |
| Update the app itself | ✅ Tauri signed updater + release appcast | Apple notarization for first install trust |

## Prioritised build order

**P0 — close the remaining "set and forget" basics:**
1. Watchdog: a second tiny launchd job that resets pf if the daemon disappears and does not come back.
2. Wake/network canary: after sleep or route change, verify one known host and re-sweep if it fails.
3. Voice-flow TTL/LRU eviction instead of full-table clear.

**P1 — true adaptivity + safety polish:**
4. Throughput canary → detect throttle decay, not just block decay.
5. Proactive periodic canary re-sweep.
6. Scope the QUIC block (don't break non-full-tunnel VPN/all UDP-443).
7. Rotating logs.

**P2 — product + maintenance horizon (Rust + SwiftUI phase):**
8. Strategy-list auto-update (signed, community recipes).
9. Richer menu-bar diagnostics: current strategy, canary result, throughput.
10. Optional relay fallback for the IP-null-route case.
11. Apple Developer ID signing + notarization for first-install trust.

## Verdict

Today: a **working, self-tuning bypass** with the core "install once" mechanics in
place: LaunchDaemon install, crash restart, status polling, DoH TTL/caps, bounded
strategy cache, pf/voice re-arm, full-tunnel VPN dormancy, and signed app updates.
The remaining resilience work is narrower: watchdog cleanup if the daemon stays
dead, canaries that detect block/throttle decay before the user notices, scoped
QUIC handling, rotating logs, and signed strategy updates. The only events that
ever require a human after P2: a TSPU leap past all strategies (→ auto-update
usually covers it) or a full Discord IP block (→ relay).

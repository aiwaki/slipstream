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
| Start at boot | ❌ manual `sudo python` | LaunchDaemon `RunAtLoad` |
| Restart on crash | ❌ | launchd `KeepAlive` |
| Hard-kill (SIGKILL) leaves pf rules | 🟡 self-heal on next start | boot-time pf reset (LaunchDaemon) + a tiny watchdog that resets pf if the daemon vanishes |
| Survive logout/login | ❌ | system-level LaunchDaemon (not Agent) |

### B. Bypass correctness — is it still beating the DPI?
| Mode | State | Needed |
|---|---|---|
| Block strategy decays (TLS starts failing) | ✅ auto-sweep climbs the ladder, re-caches | — |
| **Throttle decays** (TLS ok but download crawls) | ❌ probe only checks handshake | throughput probe on a canary; if slow, escalate strategy (fake variants) |
| Detect decay *before* the user notices | ❌ reactive only | periodic canary against `gateway.discord.gg`; re-sweep on failure |
| **All** strategies fail (TSPU leap) | ❌ | auto-update strategy list (P2); then relay fallback |
| DoH resolver blocked | 🟡 1.1.1.1 → 8.8.8.8 | more resolvers + ECH; rotate on failure |

### C. Network transitions — does it survive change?
| Mode | State | Needed |
|---|---|---|
| Wi-Fi ↔ Ethernet ↔ cellular | 🟡 pf survives; **voice iface detected once** | watch for default-route change → re-detect iface, restart voice sniffer, re-apply pf |
| Sleep / wake | ❓ untested | re-validate canary + re-apply pf on wake (`NSWorkspace`/`pmset` hook) |
| Join a *different* network (café, no TSPU) | 🟡 auto-sweep finds "plain" works | re-sweep on network change; don't keep stale per-host strategies across networks |
| User toggles a VPN | ❌ our `block UDP/443` kills VPN-on-443 | scope the QUIC block to bypassed destinations only, or pause when a VPN tunnel is up |

### D. Long-running stability — does it last days/weeks?
| Mode | State | Needed |
|---|---|---|
| **DoH cache never expires** (Cloudflare IPs rotate) | ❌ cached forever | per-entry TTL (~5–10 min) + re-resolve; the sneakiest decay — stale IPs silently break over hours |
| Strategy cache unbounded | ❌ | LRU cap (e.g. 512 hosts) |
| Voice `flows` dict unbounded | ❌ memory leak | TTL/LRU eviction of idle flows |
| FD / task leaks | 🟡 likely ok | audit under day-long load |

### E. Safety — never strand the user offline
| Mode | State | Needed |
|---|---|---|
| Clean exit restores pf | ✅ SIGINT/TERM/HUP/TSTP + atexit | — |
| SIGKILL / panic leaves pf | 🟡 next start resets | boot-time reset + watchdog (E/A) |
| QUIC block breaks all UDP/443 always-on | ❌ too broad | scope to bypassed dests; or only block QUIC for hosts we desync |
| Self-heal stale instances on start | ✅ | — |

### F. Observability — know it's working
| Mode | State | Needed |
|---|---|---|
| Status indicator | ❌ (stderr only) | menu-bar app (product): green/working, current strategy, throughput |
| Persistent logs | ❌ | rotating log file for post-mortem |
| Health metric | ❌ | rolling success-rate; surface in UI |

### G. Updates — the maintenance horizon
| Mode | State | Needed |
|---|---|---|
| New strategies without a rebuild | ❌ | signed strategy-list fetched periodically (community recipes) |
| Update the app itself | ❌ | Sparkle-style updater (product) |

## Prioritised build order

**P0 — close the "set and forget" basics (prototype, do next):**
1. `--install` / `--uninstall`: LaunchDaemon with `RunAtLoad` + `KeepAlive`, runs at boot, restarts on crash, resets pf at boot.
2. DoH cache TTL + cap (stops the silent stale-IP decay).
3. Voice iface + pf re-detect on default-route change (survive Wi-Fi/Ethernet/sleep).
4. Bounded caches + voice-flow eviction (day-long stability).
5. Watchdog: a second tiny launchd job that resets pf if the daemon disappears.

**P1 — true adaptivity + safety polish:**
6. Throughput canary → detect throttle decay, not just block decay.
7. Proactive periodic canary re-sweep.
8. Scope the QUIC block (don't break VPN/all UDP-443).
9. Rotating logs.

**P2 — product + maintenance horizon (Rust + SwiftUI phase):**
10. Strategy-list auto-update (signed, community recipes).
11. SwiftUI menu-bar: status, current strategy, one-click, throughput.
12. Optional relay fallback for the IP-null-route case.
13. App self-update (Sparkle-style).

## Verdict

Today: a **working, self-tuning bypass** — not yet a fully uninterrupted system.
After **P0** it becomes genuinely "install once, runs at boot, survives crashes,
network changes and IP/strategy decay on its own." **P1** makes the adaptivity
complete (throttle-aware, proactive). **P2** is the polished product + the
auto-update that pushes the manual-bugfix horizon as far out as physically
possible. The only events that ever require a human after P2: a TSPU leap past all
strategies (→ auto-update usually covers it) or a full Discord IP block (→ relay).

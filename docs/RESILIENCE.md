# Slipstream Resilience Design

Goal: install once, then require as little manual intervention as possible. The
daemon should recover from routine macOS and network changes automatically.

## Routing Boundaries

Slipstream separates local DPI bypass from foreign-exit routing.

Local DPI bypass is for services affected by DPI/SNI interference. Discord and
YouTube/googlevideo are in this category. They stay on the normal route and use
local desync/fake strategies.

Geph is for application-layer geo-blocks, where the service rejects the user's
Russian IP address. It is intentionally not the fallback for Discord or
YouTube/googlevideo.

## Honest Limits

1. TSPU strategy decay. If the DPI stops being fooled by all known strategies,
   Slipstream needs a strategy update.
2. Full IP null-route. If a service IP is unreachable at the network layer, local
   desync cannot fix it. A relay or VPN exit is required.
3. Platform policy. Mobile routing must use system VPN/Network Extension APIs and
   cannot be a direct port of the macOS daemon.

## Current Coverage

| Area | Current state | Remaining work |
|---|---|---|
| Start at boot | LaunchDaemon `RunAtLoad` | none |
| Crash restart | launchd `KeepAlive` | none |
| Clean exit | restores `pf` on normal termination | non-tray watchdog for app-not-running cases |
| Stale `pf` recovery | daemon re-applies rules while active; tray watchdog kickstarts daemon and resets `pf` if recovery fails | non-tray watchdog if both app and daemon are gone |
| Network transitions | detects default interface and re-arms pf/voice capture/canaries | broader endpoint-safe throughput canaries |
| Full-tunnel VPN | daemon becomes dormant on `utun*` default route | more visible tray detail |
| Local bypass strategy decay | strategy ladder, per-host cache, runtime failure-triggered recheck, route-health HTTPS payload canaries, and Discord CDN throughput threshold | signed strategy updates, broader endpoint-safe throughput checks |
| CDN edge failure | local-bypass hosts can try more A records | rolling success metrics |
| DoH cache | bounded TTL cache | resolver rotation metrics |
| Endpoint gates | repeated failure of important secondary geo-exit endpoints can degrade their group after a grace threshold | expand only from evidence-backed user workflows |
| Strategy cache and policy | bounded/versioned cache plus explicit policy tables, diagnostic policy hash, signed-bundle validator, local persist, rollback, and explicit opt-in remote fetch scheduler with health gates | production key distribution and release-channel policy hosting |
| Voice flows | TTL/LRU cleanup | long-run load audit |
| Logs | rotating daemon log, tray snapshot, route-health failure summaries, and copied diagnostic summary | attachable diagnostic file/export UX |
| App updates | signed Tauri updater | Apple notarization for first install trust |

## Priority Order

### P0 - Release Hygiene

- Keep the installed daemon and app-bundled daemon identical after releases.
- Keep log snapshot/open-log behavior reliable.
- Keep version, appcast, and release artifacts consistent.
- Keep hard-kill/stale-`pf` cleanup visible in diagnostics.

### P1 - Routing Quality

- Extend local-bypass payload canaries into endpoint-safe throughput checks where response size and method are predictable.
- Extend runtime/canary failures into signed strategy update flows.
- Keep local-bypass, Geph, Telegram proxy, and last-failure state visible in the tray.
- Move explicit host policy, attempt limits, and policy hash into production
  signed policy hosting using the opt-in scheduler, local rollback, and
  health-gate path.

### P2 - Maintenance Horizon

- Fetch signed strategy-list updates.
- Track strategy success rates without storing sensitive traffic data.
- Add optional relay handling only for confirmed IP null-route cases.

## Notes

QUIC is not globally blocked. YouTube/googlevideo playback depends on preserving
working HTTP/3 paths where available. Any future QUIC intervention must be scoped
to a clearly identified failure mode and must not become a global UDP/443 block.

Routing research and external implementation notes are tracked in
[ROUTING_RESEARCH.md](ROUTING_RESEARCH.md).

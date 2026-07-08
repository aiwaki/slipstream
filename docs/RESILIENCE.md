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
| Clean exit | restores `pf` on normal termination | watchdog for hard-kill cases |
| Stale `pf` recovery | daemon re-applies rules while active | second watchdog if daemon stays dead |
| Network transitions | detects default interface and re-arms pf/voice capture/canaries | throughput canary |
| Full-tunnel VPN | daemon becomes dormant on `utun*` default route | more visible tray detail |
| Local bypass strategy decay | strategy ladder, per-host cache, and route-health canaries | throughput canary, signed strategy updates |
| CDN edge failure | local-bypass hosts can try more A records | rolling success metrics |
| DoH cache | bounded TTL cache | resolver rotation metrics |
| Strategy cache | bounded and versioned | signed remote strategy list |
| Voice flows | TTL/LRU cleanup | long-run load audit |
| Logs | rotating daemon log, tray snapshot, and route-health failure summaries | richer diagnostic export |
| App updates | signed Tauri updater | Apple notarization for first install trust |

## Priority Order

### P0 - Release Hygiene

- Keep the installed daemon and app-bundled daemon identical after releases.
- Keep log snapshot/open-log behavior reliable.
- Keep version, appcast, and release artifacts consistent.
- Add a watchdog for hard-kill/stale-`pf` cleanup.

### P1 - Routing Quality

- Add throughput canary for Discord/YouTube-style local-bypass hosts.
- Extend canary failures into broader re-sweep and signed strategy update flows.
- Keep local-bypass, Geph, Telegram proxy, and last-failure state visible in the tray.
- Move host policy and attempt limits into a signed policy update format.

### P2 - Maintenance Horizon

- Fetch signed strategy-list updates.
- Track strategy success rates without storing sensitive traffic data.
- Add optional relay handling only for confirmed IP null-route cases.

## Notes

QUIC is not globally blocked. YouTube/googlevideo playback depends on preserving
working HTTP/3 paths where available. Any future QUIC intervention must be scoped
to a clearly identified failure mode and must not become a global UDP/443 block.

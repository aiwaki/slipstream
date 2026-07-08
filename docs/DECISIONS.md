# Decisions

Stable decisions and invariants for Slipstream. Add entries when a rule should
survive across sessions and agents.

| Date | Decision | Status |
|---|---|---|
| 2026-07-07 | Discord traffic stays on local bypass/desync, including `updates.discord.com` and `gateway.discord.gg`. It must not route through Geph. | Active |
| 2026-07-07 | YouTube/googlevideo video delivery stays on local bypass. Geph is not the fallback for video playback. | Active |
| 2026-07-07 | QUIC/UDP must not be blocked globally. Any future QUIC handling must be scoped to verified host/IP evidence and a concrete failure mode. | Active |
| 2026-07-08 | Geph is reserved for geo-exit cases where the service rejects the user's Russian IP address. | Active |
| 2026-07-08 | Slipstream must not mutate external DNS, VPN, PAC, or proxy settings. It may detect and warn about them. | Active |
| 2026-07-08 | Repo docs are the primary source of project knowledge. Codex memory stores durable agent/user preferences and pointers, not long investigations. | Active |

## Notes

- `docs/ROUTING_RESEARCH.md` records supporting investigations and references.
- `docs/TROUBLESHOOTING.md` records operational checks for repeated symptoms.
- Root README files should stay short and user-facing.

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
| 2026-07-09 | GitHub developer/download endpoints use direct passthrough and plain TLS; they should not route through Geph or the generic desync ladder. | Active |
| 2026-07-09 | Human-facing runtime logs should avoid `failed` for expected transient retry/fallback events; reserve alarming wording for action-required errors. | Active |
| 2026-07-10 | Slipstream owns only the `com.apple/slipstream` PF anchor. It must not load Slipstream rules into the global ruleset, edit `/etc/pf.conf`, or disable PF globally. | Active |
| 2026-07-10 | PF enablement is reference-counted with the token returned by `pfctl -E`; cleanup flushes only the private anchor and releases only that token. | Active |
| 2026-07-10 | The bundled Geph listener on `127.0.0.1:9954` is usable only when PID, executable, config path, and listener ownership agree. An unknown listener is a fail-closed conflict. | Active |
| 2026-07-10 | A separately managed Geph listener on `127.0.0.1:9909` is diagnostic-only unless the user explicitly opts into that port. Slipstream never stops it. | Active |
| 2026-07-10 | Geph configuration directories are owner-only (`0700`); secret-bearing config, cache, and ownership files are `0600` and written atomically. | Active |
| 2026-07-10 | A transparent HTTPS PF redirect loaded before `com.apple/*` owns the real traffic path because PF uses the first matching translation. Slipstream must pause, report the conflicting anchor, and recover automatically when it disappears; it must not flush, stop, or rewrite the other product. | Active |
| 2026-07-10 | Runtime recovery is selected by a pure reducer. Discord/YouTube outcomes can produce only local strategy invalidation, exact-host re-sweep, and recheck; only a verified owned Geph backend can produce a restart action; external state produces a warning only. | Active |

## Notes

- `docs/ROUTING_RESEARCH.md` records supporting investigations and references.
- `docs/TROUBLESHOOTING.md` records operational checks for repeated symptoms.
- Root README files should stay short and user-facing.

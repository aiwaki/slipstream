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
| 2026-07-11 | Transparent PF interception is armed only after the local listener and the enabled geo-exit backend have a verified usable port. A runtime geo-exit failure pauses only `com.apple/slipstream`; retries use the native path until a bounded hold expires and backend readiness is re-established. | Active |
| 2026-07-11 | Geph health hysteresis may preserve a previously verified port, but it must never invent an `up` state on cold start. Endpoint failures do not let the tray restart a live Geph process; LaunchAgent `KeepAlive` handles process death, and any future live-process restart must be daemon-coordinated after routing is idle. | Active |
| 2026-07-11 | `Quit Slipstream` keeps its existing non-disruptive meaning: the daemon and owned Geph LaunchAgent may continue. A separately confirmed tray uninstall removes the root daemon first, then only the verified owned Geph LaunchAgent, private runtime, and its Keychain entry. It never touches external Geph, DNS, proxy, PAC, VPN, or PF state. | Active |
| 2026-07-11 | Diagnostics may distinguish `sidecar_only` when Slipstream's root daemon is absent but its own user Geph LaunchAgent remains loaded. This is a lifecycle fact, not a claim about PF; it contains no PID, paths, hostnames, or secrets. | Active |
| 2026-07-11 | Packaged lifecycle qualification installs the frozen daemon from the built `.app` and preserves an independent PF connection/state through reinstall, restart, and uninstall. Cross-version rollback may begin only from the first release that passes this safety gate; pre-anchor releases are not executable rollback fixtures. | Active |
| 2026-07-11 | World-readable daemon status uses privacy-bounded StatusV2. It exposes aggregate route, backend, environment, and recovery state, never hostname, IP, secret, or raw failure evidence. The tray accepts V1 and V2 during the transition release. | Active |
| 2026-07-11 | Geph exit locations are selectable only from a cached or live city catalog. When neither is available, the tray shows an explicit unavailable state and never invents country-level exits. | Active |
| 2026-07-11 | A geo-exit connection that closes before delivering any payload is a backend failure even if SOCKS CONNECT succeeded. Slipstream pauses only `com.apple/slipstream` before the next client retry; it does not change DNS, proxies, VPNs, or local-bypass routing. | Active |
| 2026-07-12 | An abnormal client-side transport abort or failed downstream write after a local stream pause demotes only the exact generic strategy. A lone orderly EOF remains non-actionable, but two client-first orderly EOFs after at least 15 seconds without downstream progress for the same unknown host within five minutes may take the same exact-host recovery. The next retry may query Xbox DNS directly through its verified DoH endpoint and try the result locally with plain TLS; it also requires two matching clean-EOF signals before being discarded. Discord, YouTube, and other protected classes stay outside this path; it changes no macOS DNS setting and never learns or routes the host through Geph. | Active |
| 2026-07-12 | A generic non-geo local relay must settle when either direction completes. If the client ends first, cancel the undeliverable upstream read and record the client-first outcome before policy runs; if the server ends first, do not treat cancellation of the client pump as a clean EOF. This lifecycle rule does not alter geo-exit routing or the protected service classes' route policy. | Active |
| 2026-07-12 | Local-bypass health canaries must use a modern TLS payload handshake with the same scoped fake/desync strategy as a real client. They must not treat rejection of an intentionally minimal synthetic ClientHello as service degradation. Payload timeouts must accommodate measured endpoint latency; this affects health evidence only and never moves Discord or YouTube to Geph. | Active |
| 2026-07-11 | Manual release builds publish only uniquely tagged GitHub prereleases. They are manual-download artifacts and must not replace the stable `releases/latest` updater feed. Stable releases require an exact `v<version>` tag. | Active |
| 2026-07-11 | Preview releases omit remote policy trust keys and signed policy artifacts. Remote policy remains disabled; a stable release must supply and verify the signed policy channel. | Active |
| 2026-07-11 | A preview is offered for installation only after the release workflow runs the privileged PF lifecycle sentinel against that exact built `.app` on a disposable GitHub macOS runner. | Active |
| 2026-07-12 | The tray watchdog does not kickstart a newly installed daemon until it has seen one fresh status snapshot or a bounded startup grace expires. This prevents a healthy daemon from being restarted while it is publishing its first StatusV2 snapshot. | Active |
| 2026-07-12 | A missing durable PF enable token plus a definitively disabled PF state proves an in-memory-only token is stale after owned recovery. Slipstream may clear only that memory and acquire a new private token; persisted, enabled, or indeterminate token states remain fail-closed. | Active |
| 2026-07-12 | Routing changes must pass deterministic data-plane traffic contracts through the real daemon handler. Each contract asserts the intended backend, prohibited backends, and first-plus-streamed payload delivery; it does not mutate PF, DNS, proxy, PAC, VPN, or the live network. | Active |

## Notes

- `docs/ROUTING_RESEARCH.md` records supporting investigations and references.
- `docs/TROUBLESHOOTING.md` records operational checks for repeated symptoms.
- Root README files should stay short and user-facing.

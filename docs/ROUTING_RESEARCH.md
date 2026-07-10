# Routing Research Notes

Updated: 2026-07-11

Purpose: keep a compact record of routing research, graph-tool status, and
safe follow-ups. This is an engineering note, not user-facing documentation.

## Findings Index

| Date | Topic | Status | Decision | Next action |
|---|---|---|---|---|
| 2026-07-11 | OpenAI/Codex transparent-proxy incident | Implemented in this branch | `chatgpt.com` and related OpenAI hosts are explicit geo-exit routes; a Geph miss previously closed the captured client socket while PF remained active, creating reconnect loops. PF now stays dormant at startup until the local backend is live; a later miss clears only `com.apple/slipstream` and pauses re-arm until a fresh OpenAI canary succeeds. Tray no longer force-stops Geph from a health hint. | Add a privileged install/restart/uninstall integration fixture before the next app release. |
| 2026-07-10 | Unified runtime recovery reducer | Implemented | Normalize local, geo-exit, and unknown-host evidence as `ConnectionOutcome`; a pure reducer may invalidate only the relevant strategy, re-sweep an exact local host, restart only verified owned Geph, recheck, or warn about external state. | Move owned Geph lifecycle into a user LaunchAgent and expose a privacy-bounded action summary in `StatusV2`. |
| 2026-07-10 | Competing transparent PF interceptors | Fixed and live-verified | An active HTTPS `rdr`/`route-to` before `com.apple/*` receives real app traffic first. Detect nested anchors, pause without mutation, and auto-rearm when clear instead of trusting internal canaries. | Keep a two-interceptor integration fixture and surface the exact paused reason. |
| 2026-07-10 | Global PF ruleset ownership | Fixed and live-verified | Slipstream now loads only `com.apple/slipstream` below the existing `com.apple/*` anchor point; global reload/disable is forbidden during normal lifecycle and recovery. | Keep the privileged sentinel cycle in release qualification. |
| 2026-07-10 | PF reference ownership | Fixed and live-verified | Store the token returned by `pfctl -E` in a root-only runtime file and release it with `pfctl -X`; never infer that Slipstream owns global PF state. | Preserve restart/uninstall/reinstall coverage. |
| 2026-07-10 | Bundled Geph listener ownership | Fixed and live-verified | PID, exact executable, config path, and `:9954` listener must match the private ownership record; unknown listeners fail closed immediately. | Preserve the unknown-listener integration gate. |
| 2026-07-10 | External Geph coexistence | Fixed and live-verified | `:9909` is detected for diagnostics only and is never adopted or stopped without explicit port opt-in. | Preserve this constraint when Geph moves to a user LaunchAgent. |
| 2026-07-10 | Geph secret permissions | Fixed and live-verified | Config directory is `0700`; secret-bearing files and runtime ownership state are atomically written as `0600`, including migration of existing files. | Move the account secret to Keychain in a later hardening PR. |
| 2026-07-10 | PyInstaller spec working directory | Fixed in M0 | Resolve daemon, policy keys, and vendored Telegram proxy from `SPECPATH`; invoking PyInstaller from the repo root must not silently omit `proxy.*`. | Keep the path-stability assertion and frozen Telegram readiness smoke test. |
| 2026-07-08 | Codebase graph MCP transport | Workaround active | Graph backend is healthy; use `codebase-memory-mcp cli` when the live MCP transport is stale. | Recheck native MCP tool after a new Codex session reloads tools. |
| 2026-07-08 | SonicDPI target identity | Reference only | Copy the principle of verified host/IP identity, not raw packet interception. | Use this when designing any future UDP/QUIC handling. |
| 2026-07-08 | Discord domain family | Partially adopted | Keep Discord on local bypass and cover the broad brand family. | Add only evidence-backed host expansions. |
| 2026-07-08 | Discord voice UDP | Future platform work | Full UDP handling needs packet-level filtering, not broad pf redirects. | Revisit under Network Extension or platform adapter work. |
| 2026-07-08 | SonicDPI adaptive probing | Partially adopted | Strategy health is scored from real endpoint outcomes, not exposed as a manual picker. | Observe real logs and tune score weights only from evidence. |
| 2026-07-08 | SonicDPI forged RST detection | Future platform work | TTL-baseline RST filtering is useful only with inbound packet visibility. | Revisit with Network Extension, WinDivert, or another packet adapter. |
| 2026-07-08 | SonicDPI passive DNS cache | Future platform work | DNS-observed IP binding is the right way to classify hidden-SNI/QUIC targets without global guesses. | Use for future packet adapters; add read-only DNS diagnostics first. |
| 2026-07-08 | SonicDPI MSS clamp | Future platform work | MSS clamp can help Cloudflare-fronted Discord mid-stream resets, but only with SYN visibility and tight target gating. | Revisit under packet adapters; never clamp broadly. |
| 2026-07-08 | SonicDPI macOS Network Extension | Future platform work | Full UDP/voice handling on macOS belongs in a System Extension path, not the current pf/TCP layer. | Keep routing core adapter-independent. |
| 2026-07-08 | Read-only DNS diagnostics | Implemented | Status now records active resolvers and cached sentinel resolution checks for null/private/poison-stub answers. | Keep it diagnostic-only; do not mutate DNS. |
| 2026-07-08 | Unblock-Pro connectivity probes | Adopted where safe | Use real Gateway WebSocket-style probing for Discord readiness. | Keep canaries autonomous and non-mutating. |
| 2026-07-08 | Unblock-Pro endpoint gates | Partially adopted | A route is healthy only when both UI shell and delivery endpoints work. | Keep expanding canary coverage by evidence-backed service class. |
| 2026-07-08 | Slipstream canary check details | Implemented | Group health must not let a passing sibling endpoint hide a failing gateway/CDN/video check. | Use `canaries.checks` in diagnostics; keep tray summary compact. |
| 2026-07-08 | Unblock-Pro Flowseal bundle policy | Backlog | Pinned upstream strategy bundles are useful only with checksums/signatures and regression fixtures. | Consider signed remote policy updates, not raw script sync. |
| 2026-07-08 | Unblock-Pro exclusion lists | Reference only | Broad bypass tools need negative lists to avoid breaking banks, games, and local services. | Use as a reminder for direct-passthrough tests; do not copy wholesale. |
| 2026-07-08 | Unblock-Pro GitHub mirrors | Backlog | App-owned downloads may try mirror URLs only with integrity validation. | Consider for updater/binary fetch reliability. |
| 2026-07-08 | Unblock-Pro DNS/hosts/proxy mutations | Rejected | Do not mutate `/etc/hosts`, system DNS, system proxy, PAC, or external VPN configuration. | Detect and warn only. |
| 2026-07-08 | Unblock-Pro global UDP block | Rejected | Do not block UDP/443 or Discord voice ranges globally. | Keep QUIC/UDP handling scoped to verified host/IP evidence. |
| 2026-07-08 | Install hygiene ideas | Adopted where safe | Safe-copy and binary-format validation are useful for daemon install reliability. | Keep monitoring real reinstall logs for locked-file edge cases. |
| 2026-07-08 | `xbox-dns.ru` external DNS | Reference only | Treat user-managed DNS as external state, not something Slipstream enables or rewrites. | Detect in diagnostics if useful; never auto-configure it. |
| 2026-07-09 | Darkware Zapret UI | Reference only | Borrow the compact MenuBarExtra-style status layout, not its manual strategy workflow. | Redesign tray diagnostics as short status rows with details behind a button. |
| 2026-07-09 | Darkware Zapret system mutations | Rejected | Do not copy system SOCKS proxy toggles or broad sudoers `NOPASSWD` service control. | Keep Slipstream-owned state scoped to its daemon, pf rules, and status files. |
| 2026-07-09 | Darkware Zapret bruteforce probe | Backlog | Headless re-sweep can borrow the temporary-proxy probing idea without exposing a picker. | Consider only for autonomous local-bypass recovery. |
| 2026-07-09 | Context Mode | Agent tooling | Installed for Codex session context hygiene; not a Slipstream runtime dependency. | Keep out of project code and docs except this research note. |
| 2026-07-09 | Superpowers | Agent tooling | Installed as a general Codex workflow aid; not a Slipstream runtime dependency. | Use opportunistically after session reload exposes its skills. |
| 2026-07-09 | ECC | Not installed | Current Codex plugin path is broad and upstream-doc-fragile for this repo. | Revisit only for a focused workflow need. |
| 2026-07-09 | Ruflo | Not installed | Too much global agent harness behavior for current Slipstream work. | Mine health-check and ADR ideas only. |
| 2026-07-09 | Steam Store web | Adopted narrowly | Route Steam Store web hosts through geo-exit; keep Steam CM/game/download paths out until separately proven. | Watch real Steam logs before widening host coverage. |
| 2026-07-09 | Runtime local-bypass recheck | Implemented | Full local-bypass runtime strategy failure clears only that route group's strategy cache and force-schedules canary recheck. | Keep observing real failures before changing thresholds. |
| 2026-07-09 | Explicit route policy tables | Implemented | Static direct, local-bypass, geo-exit, and attempt-limit policy now lives in inspectable tables instead of a hand-written route-policy branch chain. | Use this shape for signed policy updates and OS adapters. |
| 2026-07-09 | Policy metadata in diagnostics | Implemented | Daemon status and copied diagnostics expose bundled policy version, source, hash, domain counts, and attempt limits. | Use this as the base for signed remote policy verification. |
| 2026-07-09 | Signed policy bundle validator | Implemented | Future policy bundles must pass manifest validation and Ed25519 signature verification; Discord/YouTube are protected from geo-exit policy. | Add remote fetch/apply only after key management and rollback rules are explicit. |
| 2026-07-09 | Policy apply path | Implemented | A verified manifest can be activated in memory and reflected in route lookup/status; default runtime remains bundled until explicit apply. | Add persistence/rollback before any remote fetch is enabled. |
| 2026-07-09 | Policy persistence and rollback | Implemented | Verified policy bundles can be saved under Slipstream-owned state, loaded on daemon start, and rolled back to the previous bundle or bundled policy. | Add remote fetch only after signing keys and post-apply health gates are explicit. |
| 2026-07-09 | Remote policy health gate | Implemented | Remote policy helper is disabled by default, requires HTTPS, trusted Ed25519 keys, and a passing health gate before persisting an update. | Add a scheduler only after cadence, backoff, and production key distribution are explicit. |
| 2026-07-09 | Remote policy scheduler | Implemented | Remote policy fetch is explicit opt-in via `SLIP_ROUTE_POLICY_URL`, uses retry backoff, skips while canaries run, and only persists after the health gate passes. | Define production signing-key distribution and release-channel hosting before enabling for users. |
| 2026-07-09 | Signed policy release tooling | Implemented | `scripts/make_route_policy_bundle.py` generates Ed25519 keypairs, builds and verifies signed policy bundles, signs the bundled manifest directly, writes trusted public-key maps, and includes verifier-checked hashes. | Create real production keys outside git and host the release channel before user enablement. |
| 2026-07-09 | Bundled policy key distribution | Implemented | The daemon loads trusted policy keys from embedded constants, an optional bundled `route-policy-keys.json`, and a root-owned state override; PyInstaller includes the bundled key map only when release tooling provides it. | Generate and protect real production keys outside git before hosting policies. |
| 2026-07-09 | Remote policy channel index | Implemented | `SLIP_ROUTE_POLICY_URL` may point to a stable HTTPS channel index with bundle URL and sha256; the daemon verifies the bundle digest before signature and health-gate checks. | Host this only after real production keys and rollback notes exist. |
| 2026-07-09 | Release policy channel packaging | Implemented | `build-app.yml` now requires production policy key secrets, embeds the public key map in the daemon bundle, signs the bundled policy, verifies it, and publishes `route-policy.json` plus `route-policy-latest.json` release assets. | Configure the real GitHub secrets and publish a release before user enablement. |
| 2026-07-09 | Release artifact preflight | Implemented | `scripts/verify_release_artifacts.py` checks the release dir before publishing: updater appcast URL/signature, signed route-policy bundle, trusted keys, channel URL, and channel hash must agree. | Keep adding release artifact checks when new published files become update-critical. |
| 2026-07-09 | Discord CDN throughput canary | Implemented | Discord CDN local-bypass canary now uses a scoped GET payload threshold, while warning before degrading and leaving YouTube/QUIC/global UDP untouched. | Add throughput thresholds only for endpoints with predictable small payloads. |
| 2026-07-09 | Geo-exit endpoint gates | Implemented | Repeated failure of important secondary geo-exit endpoints, such as OpenAI billing, can degrade the group after a grace threshold instead of being hidden by a passing core endpoint. | Keep adding endpoint gates only where user-visible workflows are proven to fail independently. |
| 2026-07-09 | GitHub developer endpoints | Implemented | GitHub HTTPS/Git endpoints are direct-passthrough and plain-only; generic desync can break longer smart-HTTP transfers even when short API calls succeed. | Use direct-passthrough for similar developer/download endpoints only with evidence, not as a broad allowlist. |
| 2026-07-09 | Steam Store payload canary | Implemented | Steam Store geo-exit health now requires a real HTTPS GET payload through Geph, not just SOCKS CONNECT or TLS first bytes. | Add payload probes for other geo-exit flows only when TLS success can hide a user-visible stalled page. |
| 2026-07-09 | Lid-close wake recovery | Implemented | Adrafinil keeps idle sleep away but does not prevent macOS lid-close SleepService/DarkWake cycles; repeated post-wake geo-exit failures now recommend a rate-limited restart of Slipstream's owned Geph process. | Move more Geph lifecycle ownership into the daemon when keychain/config constraints are solved. |
| 2026-07-09 | Stale proxy exceptions | Implemented | External proxy tools can leave disabled `ExceptionsList` entries after proxy autoconfigure is turned off; Slipstream reports them in status without treating the proxy as active or mutating settings. | Use diagnostics to explain stale browser/network behavior; do not auto-delete user-owned proxy state. |
| 2026-07-09 | Runtime re-arm visibility | Implemented | Daemon status now records the last wake/network re-arm reason, interface, gap, count, and age so sleep-related recovery is visible without reading logs first. | Keep using logs for full `pmset` correlation; status is a compact runtime snapshot. |
| 2026-07-10 | Auto geo-exit stale learned hosts | Implemented | Repeated Geph runtime retries now reset only exact hosts that were learned by auto geo-exit; explicit geo-exit and local-bypass routes are preserved. | Watch logs for new retry reasons before widening the reset trigger. |
| 2026-07-10 | Wake canary recovery rerun | Implemented | Forced canary triggers that arrive during an in-flight wake check are queued for a short rerun instead of being dropped by the force cooldown. | Keep wake recovery event-driven; do not lengthen normal canary cadence. |
| 2026-07-10 | Exact-host local-bypass re-sweep | Implemented | A real Discord/YouTube runtime miss starts a deduplicated background strategy sweep for that exact host and clears its negative cache only after a fake/desync strategy succeeds. | Tune cooldowns only from observed runtime evidence. |
| 2026-07-10 | Geph-down log semantics | Corrected | Geo-exit routes already fail closed while Geph is down; the old log text incorrectly claimed they used local desync. | Keep runtime messages aligned with route behavior so diagnostics do not imply an RU-IP leak. |

## Codebase Graph

- Observed on 2026-07-08: the configured `mcp__codebase_memory_mcp` tool failed
  in the active Codex session with `Transport closed`.
- The graph backend itself is healthy. `codebase-memory-mcp cli list_projects`
  works, and manual JSON-RPC over stdio works for `initialize`, `tools/list`,
  and `tools/call list_projects`.
- `/Users/aiwaki/.codex/config.toml` now sets `CBM_LOG_LEVEL=error` for
  `codebase-memory-mcp`.
- `/Users/aiwaki/.local/bin/codebase-memory-mcp` is a wrapper that forces
  `CBM_LOG_LEVEL=error` and executes the original binary at
  `/Users/aiwaki/.local/bin/codebase-memory-mcp.bin`.
- The active Codex session appeared to keep a stale failed MCP transport and did
  not invoke the wrapper. Until a session reloads tools, use
  `codebase-memory-mcp cli` as the graph-backed discovery path.

Indexed routing projects:

- `Users-aiwaki-Documents-Codex-2026-04-30-github-plugin-github-openai-curated-https-slipstream`
- `tmp-slipstream-research-sonic-sonicdpi`
- `tmp-slipstream-research-unblock-unblock-pro`
- `tmp-slipstream-research-sonic-20260708-sonicdpi`
- `tmp-slipstream-research-unblock-20260708-unblock-pro`

Fresh external snapshots checked on 2026-07-08:

- `by-sonic/sonicdpi` at `ebd08f71d33ce8cbeb671742b06054471adbdfd5`
- `by-sonic/unblock-pro` at `a075902efca70392cf7e07f97c85a8b280cb571c`

Fresh external snapshots checked on 2026-07-09:

- `roninreilly/darkware-zapret` at `1d9834a5716d65b6140df24dd64fec350d461bb9`
- `mksglu/context-mode` at `43a2066da943572546ff316ceca79026163be0b1`
- `obra/superpowers` at `d884ae04edebef577e82ff7c4e143debd0bbec99`
- `affaan-m/ECC` at `4130457d674d2180c5af2c5f634f3cae4cbc6c4f`
- `ruvnet/ruflo` at `a444930d88d753e04793f55bd38861e82d9cb062`

## SonicDPI Findings

- The most useful idea is cautious target identity, not a direct strategy copy.
  SonicDPI classifies by TLS SNI, verified QUIC destination, Discord voice
  packet shape, IP-prefix fallback, and sticky flow inheritance.
- SonicDPI explicitly avoids treating every UDP/443 QUIC Initial as YouTube.
  It only upgrades QUIC to YouTube when the destination is verified by prefix
  or DNS evidence. This matches Slipstream's rule: no global UDP/443 handling.
- SonicDPI's default target set covers a broad Discord domain family, including
  updater, status, CDN, auxiliary brand domains, and `discord.media`.
- The engine always observes DNS responses first and uses a DNS cache to
  classify later packets whose SNI is no longer visible. This is a useful model
  for local-bypass health: do not guess UDP/QUIC identity globally, correlate
  it with recent DNS or other host/IP evidence.
- The DNS cache is bounded and time-limited. The useful transferable idea is
  not "own DNS", but "remember verified host-to-IP evidence briefly." The
  current macOS pf/TCP daemon cannot passively observe UDP/53, so this belongs
  either in read-only diagnostics now or in a future packet adapter.
- Slipstream now adds read-only DNS diagnostics to status: active resolver
  detection, `xbox-dns.ru` provider detection, and cached sentinel resolutions
  for Discord/YouTube hosts that flag null, private, or known poison-stub
  answers. This records evidence without changing DNS settings.
- SonicDPI has a lightweight probing model that records wins/losses, ranks
  profiles by a Wilson lower-bound, and gives old entries a small age bonus so
  alternatives get re-tested. Slipstream can borrow this shape for autonomous
  route-health scoring without adding a manual strategy picker to the UI.
- Slipstream now keeps an in-memory local-bypass strategy score per host and
  strategy. Runtime and canary outcomes record wins/losses, cached winners get a
  small bias, stale entries get a small age bonus, and fake-only policies remain
  fake-only.
- 2026-07-09: GitHub API requests were reachable, but Git smart-HTTP transfer
  could hang after the initial refs response while `github.com` and
  `objects.githubusercontent.com` were still classified as `unknown/generic`.
  The safer route is direct-passthrough, plain-only, because these developer
  endpoints do not need local DPI desync or Geph.
- 2026-07-09: Steam Store's original geo-exit canary only proved that Geph could
  open a SOCKS/TLS stream. It now performs a small HTTPS GET for `/` and requires
  a minimum payload so "page shell starts, then stalls" is visible to autonomous
  health instead of requiring manual browser testing.
- 2026-07-10: Browser symptoms where the main page loads but some subresources
  stall can come from a stale exact-host entry in auto geo-exit. Logs showed
  repeated Geph route retries such as `remote closed without response` for
  learned generic/static hosts. Slipstream now resets only those auto-learned
  exact hosts after repeated runtime retries, so the next request can return to
  the local route and re-learn only if a fresh Geph payload proof succeeds.
- 2026-07-10: After wake, route canaries can run before Geph/DNS are fully back.
  If `geph_up` arrives while that wake check is still running, the force cooldown
  used to drop the recovery recheck and leave the tray in `needs attention` until
  the next periodic run. Forced recovery triggers now queue a short pending rerun
  and preserve the original reason.
- 2026-07-10: `darkware-zapret` was simultaneously active through root anchor
  `zapret`, nested `zapret-v4`, and `tpws` on `127.0.0.1:988`. Its root anchor
  precedes `com.apple/*`, so PF's first matching `rdr` sent all real HTTPS there
  while Slipstream's internal Discord canaries still reported healthy. Discord
  updater then failed TLS with macOS error `-9806`; stopping only Darkware's
  runtime moved connections to Slipstream `:1080`, completed the update check in
  about six seconds, and reached Gateway `READY`. This is an interceptor
  ownership conflict, not a reason to route Discord through Geph.
- SonicDPI detects likely forged inbound TCP RST packets by learning a target
  flow's baseline server TTL and dropping early RSTs with a large TTL delta.
  This is useful research for packet-level adapters, but it cannot be copied
  into the current macOS pf/TCP transparent-proxy layer.
- SonicDPI has a TCP MSS clamp strategy for Cloudflare-fronted Discord where
  mid-stream classifiers reset update/download flows after the initial TLS
  handshake. It rewrites outbound SYN MSS and carries a throughput cost, so it
  is future packet-adapter research only and must be gated to verified target
  IPs if adopted.
- SonicDPI covers Discord voice UDP ranges `19294-19344` and `50000-50100`.
  That depends on packet-level filtering. It should not be copied into
  Slipstream as a broad pf redirect.
- SonicDPI's QUIC fake Initial and Discord voice fake payloads are randomized.
  This is useful future research only if Slipstream starts touching those
  packet classes directly.
- SonicDPI contains a macOS Network Extension prototype around
  `NEFilterPacketProvider`, with Rust packet logic behind a Swift System
  Extension harness. That confirms the right long-term Apple path for
  per-packet UDP/voice handling. It is not a small change to the current pf/TCP
  daemon.

## Unblock-Pro Findings

- The useful connectivity probe is a real Discord Gateway WebSocket handshake
  against `gateway.discord.gg`. Slipstream already has an equivalent payload
  canary.
- The Discord Gateway WebSocket canary now generates a fresh
  `Sec-WebSocket-Key` for every probe, so it behaves like a real handshake
  rather than replaying a static sample nonce.
- Unblock-Pro avoids false positives by requiring both service shell and
  delivery endpoints: YouTube web plus `redirector.googlevideo.com`; Discord
  API plus CDN; and a real Gateway WebSocket upgrade. This is a good canary
  structure for Slipstream's route health because a homepage or thumbnail can
  work while playback or app login still fails.
- Slipstream now keeps per-check canary health in `canaries.checks` and reduces
  it into the backward-compatible group-level `route_health`. A passing
  `discord_cdn` canary no longer hides a failing `discord_gateway` canary.
- Discord local-bypass health now has separate API, Gateway WebSocket, CDN, and
  updater canaries, matching the endpoint split that Unblock-Pro used to avoid
  false positives.
- YouTube local-bypass health now splits the web shell canary from the
  `googlevideo`/redirector QUIC video-delivery canary.
- Flowseal-style rules include Discord voice UDP ranges and `discord.media`
  alternate TCP ports `2053,2083,2087,2096,8443`. These are useful references,
  but should only be used with host/IP evidence. No global alternate-port
  capture.
- Unblock-Pro tries a remembered last-working strategy first and then a fixed
  Flowseal priority order. Slipstream can use a private route-health cache for
  ordering autonomous checks, but should not expose or require a manual strategy
  picker.
- Unblock-Pro pins a Flowseal release, records a bundle checksum, and tests the
  generated strategy snapshot. That is the right shape for any future
  remote-policy import: signed or checksummed data plus fixtures, not live
  execution of unreviewed scripts.
- Unblock-Pro also ships broad exclusion lists for banks, government sites,
  games, stores, and local/private networks. Treat this as a warning that
  bypass rules need direct-passthrough regression tests; the exact lists should
  not be copied without evidence.
- `safe-copy` and binary-format checks are useful for release/install hygiene:
  retry locked files, skip identical files, and validate Mach-O headers before
  installing local binaries.
- Slipstream now validates that the bundled daemon is an executable Mach-O before
  asking launchd to install it, and reports the validation result in diagnostic
  snapshots.
- Frozen daemon and vendored proxy installs now copy into a temporary path before
  swapping into `/usr/local/slipstream`, and script installs skip identical files
  while replacing changed files atomically.
- GitHub mirror URL fallback could help updater reliability, but only as an
  app-owned download fallback. It must not mutate global proxy, DNS, or VPN
  settings.
- Unblock-Pro's macOS global UDP block writes pf rules for `udp/443`,
  `19294:19344`, and `50000:50100`. Do not copy this. It conflicts with
  Slipstream's invariant that QUIC/UDP must stay open unless a narrow,
  evidence-backed host/IP rule exists.
- Do not copy Unblock-Pro's `/etc/hosts`, system DNS, or system proxy mutation
  behavior into Slipstream.
- Do not copy its static `/etc/hosts` fallback for Discord voice or Telegram:
  stale IPs can create worse failures than the original DPI block, and this
  violates Slipstream's rule that external DNS/hosts state is read-only.
- Neither SonicDPI nor Unblock-Pro uses `xbox-dns.ru` directly in the inspected
  code. If users configure it at the OS/router level, Slipstream should treat it
  like other external DNS state: report it in diagnostics if relevant, but never
  enable, replace, or restore it automatically.

## Darkware Zapret Findings

- The pleasant menu is a SwiftUI `MenuBarExtra` with `.menuBarExtraStyle(.window)`,
  a fixed-width material popover, a title row, a large toggle, one status row,
  compact picker rows, and icon-only footer actions with tooltips.
- This is a useful reference for Slipstream's future tray diagnostics: a calm
  compact popover can show "working", "needs attention", and a small details
  action without stretching the native menu line.
- Do not copy the visible engine/strategy picker as the main workflow.
  Slipstream should keep strategy selection autonomous and evidence-driven.
- Darkware's `tpws` path is a transparent TCP proxy. Its `ciadpi` path uses a
  system SOCKS proxy for TCP and UDP. The system SOCKS mutation is not suitable
  for Slipstream because external proxy/PAC/VPN state is user-owned.
- Do not copy the installer sudoers pattern that grants `NOPASSWD` for a service
  control script. Slipstream should keep privilege boundaries tighter and auditable.
- The bruteforce helper is useful as a diagnostic pattern: start a temporary
  local proxy, try candidate strategies with real endpoint requests, then record
  winners. Slipstream can adapt that as a headless re-sweep after local-bypass
  failures, not as a manual picker.

## Agent Tooling Findings

- `context-mode@context-mode` is installed and its doctor passes for Codex hooks,
  MCP server startup, SQLite/FTS5, and plugin registration. It required using the
  bundled Codex Node runtime because the system Node was too old for the plugin.
- `superpowers@openai-curated` is installed and enabled. It is a process-skill
  bundle for planning, debugging, verification, and branch finishing. It should
  remain agent-side tooling, not a Slipstream dependency.
- `affaan-m/ECC` was inspected but not installed. The repo's own Codex plugin
  notes describe the current Codex plugin path as fragile, and the skill bundle
  is too broad for this project without a focused need.
- `ruvnet/ruflo` was inspected but not installed. It brings a large meta-harness,
  swarms, MCP behavior, hooks, and daemon-style features. Useful ideas are ADRs,
  health checks, witness manifests, and tool-description audits; the harness is
  too much global behavior for Slipstream right now.

## Steam Store Findings

- Runtime status on 2026-07-09 showed Slipstream active, pf applied, system proxy
  off, `xbox_dns` detected as external DNS, and existing route-health groups OK.
- Direct endpoint probes showed `store.steampowered.com` returning HTTP 200 but
  stalling while transferring the page body: about 13 KB in 25 seconds. The same
  URL through Slipstream's bundled Geph SOCKS on `127.0.0.1:9954` transferred
  about 1.37 MB in about 2 seconds.
- Steam's own logs showed WebSocket CM attempts timing out before a later
  successful UDP connection. Keep CM/gaming/download paths separate from the
  Store web fix.
- Slipstream now treats the Steam Store web family as `steam_store`/`geo_exit`:
  `steampowered.com`, `steamcommunity.com`, `steamstatic.com`,
  `steamusercontent.com`, and the narrow Steam-owned Akamai hostnames
  `steamcdn-a.akamaihd.net` and `steamcommunity-a.akamaihd.net`.
- Steam Store skips Smart DNS even when `xbox-dns.ru` is active because the
  observed failure was an application-data stall on the direct path, not just
  DNS poisoning. Runtime uses the bundled Geph tunnel for this group.
- Do not route `steamserver.net`, Steam CM, game traffic, or broad Akamai/Fastly
  hostnames through Geph without endpoint-level evidence.

## Auto Geo-Exit Learning

- The old adaptive `AUTO_GEPH` path is now proof-gated and enabled by default.
  Local low-content hangs only make an unknown HTTPS host a candidate; promotion
  requires a separate HTTPS payload probe through Slipstream's Geph tunnel.
- Learned entries are exact-host, TTL-bound, and persisted in
  `/var/run/slipstream-autogeph.json`. Runtime status exposes a compact
  `auto_geo_exit` snapshot with enabled/learned/pending and last proof state.
- Exclusions remain hard-coded: Discord and YouTube/googlevideo stay
  `local_bypass`; Telegram and Russian services stay out of Geph; Geph
  infrastructure is never auto-routed through itself.
- YouTube web-shell probing is warning-only; the hard YouTube health signal is
  the `youtube_video`/googlevideo path because browsers can reach the web shell
  through IPv6/QUIC while daemon-side IPv4/TCP probes are noisy.
- This is intended to cover Steam-like future cases without adding a manual
  service rule first. Static policy is still preferred when a service class is
  well understood and has multiple endpoint families.

## Runtime Local-Bypass Recheck

- Periodic canaries were already able to clear stale local-bypass strategy
  cache and re-sweep candidates, but runtime connection failures could stay
  invisible until the next scheduled canary.
- Slipstream now reports full runtime local-bypass strategy failures into route
  health, clears only the affected local-bypass route group's strategy cache,
  and force-schedules route canaries with the existing cooldown.
- The same failure also schedules a private exact-host re-sweep. It tries only
  the host's allowed local-bypass fake/desync strategies, caches the first
  working strategy, and then clears that host's negative cache. The scheduler
  is deduplicated and does not expose a visited-host history in status.
- Runtime success marks the affected local-bypass group healthy. Discord and
  YouTube/googlevideo remain local-bypass only; this path never promotes them
  to Geph.

## Explicit Route Policy Tables

- Static direct/local-bypass/geo-exit routing now uses `ROUTE_POLICY_TABLE`,
  `GEO_EXIT_POLICY_TABLE`, and `IP_ATTEMPT_LIMIT_BY_ROUTE` instead of embedding
  every group decision directly in `route_policy`.
- This does not change runtime behavior. Discord and YouTube/googlevideo remain
  fake-only local-bypass groups; Telegram stays direct; OpenAI/Anthropic/Steam
  Store stay geo-exit where listed.
- The shape is intentionally close to a future signed policy payload while
  keeping the current source-controlled policy as the only active authority.
- `scripts/make_route_policy_bundle.py` can turn a reviewed manifest or the
  current bundled manifest into a signed JSON bundle and matching public-key map
  for release hosting. It also verifies generated bundles against the key map.
  The daemon verifier accepts legacy bundles without a hash, but any provided
  `sha256` must match the canonical manifest hash.
- The same helper can generate a raw Ed25519 release keypair. Private keys are
  created with `0600` permissions and existing key files are not overwritten.
  Real production private keys must stay outside git.
- Trusted public keys can be embedded in code, bundled as `route-policy-keys.json`
  next to the frozen daemon, or overridden from Slipstream-owned state under
  `/var/db/slipstream`. The repo does not contain real production keys.
- Remote policy fetch can read either a direct signed bundle URL or a stable
  channel index. Channel indexes use `kind: slipstream.route_policy_channel`,
  `schema: 1`, `bundle_url`, and `sha256`; the bundle payload hash is checked
  before signature verification and health gates.

## Transfer Backlog

Safe candidates:

- Keep policy tests for the broad Discord family and every Discord host on
  `local_bypass`.
- Add narrow YouTube-family policy coverage for `youtu.be` and `ggpht.com`.
  Broader Google domains such as `googleapis.com` and `googleusercontent.com`
  need observed evidence before they join local bypass.
- Continue adding service-class canaries only when there is evidence that a
  separate endpoint class can fail independently.
- Continue refining read-only DNS diagnostics only from evidence; keep resolver
  settings immutable.
- Keep tuning autonomous strategy scoring from real logs; do not expose a manual
  strategy picker in the tray.
- Consider a compact tray diagnostic popover inspired by Darkware's layout, but
  keep Slipstream's native-menu simplicity and autonomous routing model.
- Keep Steam Store geo-exit narrow; add direct-passthrough diagnostics before
  widening Steam CM, game, or download routing.
- For future packet adapters, evaluate MSS clamp only for verified
  Cloudflare-fronted Discord update/download flows.
- Watch reinstall logs for any remaining locked-file or permission edge cases.
- Add app-owned GitHub download mirror fallback only behind checksum/signature
  validation.
- Define production signing-key storage and release-channel hosting for signed
  route-policy bundles before enabling remote fetch for users.
- Keep external DNS, VPN, PAC, and proxy settings read-only: detect and warn,
  never rewrite.

Unsafe candidates:

- Routing Discord or YouTube through Geph.
- Global QUIC/UDP blocking.
- Blocking `udp/443`, `19294-19344`, or `50000-50100` globally to force a
  fallback path.
- Global alternate-port capture without verified host/IP ownership.
- Mutating `/etc/hosts`.
- Rewriting system DNS, system proxy, PAC, or external VPN configuration.
- Auto-configuring third-party DNS such as `xbox-dns.ru`.
- Auto-configuring system SOCKS proxy to support an engine.
- Granting broad `NOPASSWD` sudoers entries for service control.
- Adding Steam CM/game/download traffic to Geph or local bypass without
  endpoint-level evidence.
- Global MSS clamp or MSS clamp on broad Cloudflare/Google traffic.
- Importing upstream strategy scripts without a pinned, verified, and reviewed
  policy bundle.

# Routing Research Notes

Updated: 2026-07-08

Purpose: keep a compact record of routing research, graph-tool status, and
safe follow-ups. This is an engineering note, not user-facing documentation.

## Findings Index

| Date | Topic | Status | Decision | Next action |
|---|---|---|---|---|
| 2026-07-08 | Codebase graph MCP transport | Workaround active | Graph backend is healthy; use `codebase-memory-mcp cli` when the live MCP transport is stale. | Recheck native MCP tool after a new Codex session reloads tools. |
| 2026-07-08 | SonicDPI target identity | Reference only | Copy the principle of verified host/IP identity, not raw packet interception. | Use this when designing any future UDP/QUIC handling. |
| 2026-07-08 | Discord domain family | Partially adopted | Keep Discord on local bypass and cover the broad brand family. | Add only evidence-backed host expansions. |
| 2026-07-08 | Discord voice UDP | Future platform work | Full UDP handling needs packet-level filtering, not broad pf redirects. | Revisit under Network Extension or platform adapter work. |
| 2026-07-08 | SonicDPI adaptive probing | Backlog | Strategy health should be scored from real endpoint outcomes, not exposed as a manual picker. | Design per-policy-group scoring for canary results. |
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
- Add autonomous route-health scoring based on wins/losses with exploration
  over time, similar to SonicDPI's Wilson-rank plus age-bonus model.
- For future packet adapters, evaluate MSS clamp only for verified
  Cloudflare-fronted Discord update/download flows.
- Watch reinstall logs for any remaining locked-file or permission edge cases.
- Add app-owned GitHub download mirror fallback only behind checksum/signature
  validation.
- Consider a signed remote policy/strategy update format.
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
- Global MSS clamp or MSS clamp on broad Cloudflare/Google traffic.
- Importing upstream strategy scripts without a pinned, verified, and reviewed
  policy bundle.

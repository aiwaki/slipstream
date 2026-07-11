# Roadmap

Roadmap is informational and not a release promise. Each milestone lands as a
small PR with tests and matching documentation.

## Baseline

The July 2026 audit found the existing routing layer ahead of the previous
roadmap: routing health, canaries, signed policy bundles, rollback, auto
geo-exit, and exact-host recovery already exist. The baseline passed 152 Python
tests and 30 Rust tests.

The main risks were below routing policy: global PF ownership, broad process
recovery, Geph secret permissions and listener identity, unversioned status,
large lifecycle modules, and a non-reproducible release pipeline.

## M0 - Safe Base

Target: before `v0.1.5`.

- Keep Slipstream rules in the private `com.apple/slipstream` anchor.
- Never load Slipstream rules into the global PF ruleset, edit `/etc/pf.conf`,
  or call `pfctl -d`.
- Pair `pfctl -E` with its owned token and `pfctl -X`.
- Manage daemon and Geph by launchd label plus verified PID/executable identity;
  never use broad process-pattern kills.
- Require ownership proof for bundled Geph on `:9954`; treat external `:9909` as
  read-only diagnostics unless explicitly selected.
- Keep Geph config owner-only and secret-bearing files at `0600`.
- Detect active transparent HTTPS interceptors that precede `com.apple/*`;
  pause without touching their anchors and re-arm when the conflict clears.
- Keep `LICENSE` canonical, list bundled licenses separately, and remove unused
  README assets.
- Make scheduled vendor updates open PRs; require a passing `checks` job before
  merging to `main`.

Gate: install, restart, update, and uninstall leave an external PF sentinel and
`zapret` anchor unchanged; unknown processes are never signalled; secrets are
not readable outside the owning user.

CI covers both script-mode and packaged-app cold install, same-artifact
reinstall, restart, and uninstall with a sibling anchor and a long-lived
sentinel PF state. Cross-version rollback starts only after a safety-qualified
release exists; stable distribution remains a separate M3 gate.

## M1 - Autonomous Routing V1

- Normalize runtime evidence as `ConnectionOutcome`: service group, route
  class, backend, failure phase, bytes, duration, and reason.
- Select rate-limited safe actions through a pure `RecoveryAction` reducer.
- Keep Discord and YouTube on local bypass with exact-host re-sweep. They never
  fall through to Geph.
- Never fall an intercepted geo-exit connection through local desync. If the
  required backend is unavailable, pause the private PF anchor and enter dormant
  mode so Slipstream no longer owns system HTTPS. Restarting a live Geph process
  must be daemon-coordinated after routing is idle.
- Let unknown hosts try the local adaptive ladder first. Temporary geo-exit
  requires repeated local misses plus a successful Geph payload proof.
- Move Geph to a user LaunchAgent with `KeepAlive`; the tray becomes a settings
  client rather than a lifecycle dependency.
- Keep external DNS, VPN, PAC, and proxy state read-only.

Progress: runtime local-bypass misses, geo-exit failures, and repeated unknown
host stalls now enter one normalized reducer. Cold-start and runtime backend
failure also gate or pause the private PF anchor. The remaining M1 lifecycle
step is moving owned Geph out of the tray and into a user LaunchAgent without
reintroducing live-stream restarts.

Gate: routing and Geph recover after tray crash, browser restart, network
change, and sleep/wake without manual buttons.

## M2 - Contracts And Code

- Introduce privacy-bounded `StatusV2` sections for daemon, routes, backends,
  environment, and recovery state. Done in the transition release.
- Keep hostname-level and detailed network events out of world-readable status.
  Done for StatusV2; raw logs `0600` remains pending. Diagnostic exports stay
  sanitized and user-owned.
- Let the tray read V1 and V2 for one transition release. Done.
- Split the Python daemon into policy, reducer, probes, Geph backend, macOS PF
  adapter, and lifecycle modules.
- Split the Rust tray into status client, diagnostics, installer, Geph config,
  and menu orchestration.
- Keep Python transport; avoid a big-bang rewrite.
- Add language-neutral policy fixtures and recovery vectors.

## M3 - Release-Grade macOS

- Pin Python/PyInstaller dependencies with hashes.
- Fetch exactly the Geph version recorded in `vendor/geph/VERSION`; verify
  checksum, architecture, and provenance.
- Set an explicit Tauri target and publish an artifact manifest plus SBOM.
- Run full tests and a privileged PF-anchor sentinel test in release CI.
- Separate preview and stable channels. Stable requires Developer ID, hardened
  runtime, notarization, and stapling.
- Define production custody and rotation for policy-signing keys. Remote policy
  stays off by default until that workflow and rollback are reviewed.

Gate: clean install, update, rollback, and uninstall need no manual PF, proxy,
or file cleanup.

## M4 - Cross-Platform Core

- Extract a pure Rust `slipstream-core` for policy parsing, classification,
  recovery reduction, signed updates, and StatusV2 types.
- Keep sockets and OS calls in adapters; run Python and Rust against identical
  golden vectors.
- Adapter order: Windows, Android, Linux, then an iOS feasibility gate.
- Treat Tauri as the shared shell only. Networking remains native per platform.
- External VPN coexistence remains explicit and non-mutating, especially where
  Android permits only one active VPN service.

## M5 - Packet-Level Capabilities

Only after adapters stabilize:

- bounded DNS-observed host/IP evidence;
- scoped QUIC/UDP handling;
- Discord voice classification;
- forged RST detection;
- target-specific MSS clamp;
- relay fallback for proven IP null-route cases.

No global UDP/443 block, broad IP guessing, or manual strategy picker.

## Milestone Checks

- Unit tests and cross-language golden vectors.
- Fake DNS/SOCKS/TLS endpoints for stall, reset, empty response, and partial
  payload.
- PF sentinel and process-ownership integration tests.
- Install/update/uninstall integration test.
- Safari, Chrome, Discord, YouTube, OpenAI files/billing, Telegram, and Steam
  Store smoke matrix.
- Sleep/wake and network-change soak.
- Assertion that Discord and YouTube never appear in Geph route events.

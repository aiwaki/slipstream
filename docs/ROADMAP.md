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
- Treat daemon install and upgrade as a transaction: a fresh owned status,
  exact listener, and matching private-PF state are required before success.
  Failure disables the label and removes only owned plist/runtime/PF state.
- Treat an absent or disabled daemon label as durable stop intent. Startup and
  watchdog recovery do nothing until the user explicitly requests restart.
- Require ownership proof for bundled Geph on `:9954`; treat external `:9909` as
  read-only diagnostics unless explicitly selected.
- Keep Geph config owner-only and secret-bearing files at `0600`.
- Detect active transparent HTTPS interceptors that precede `com.apple/*`;
  pause without touching their anchors and re-arm when the conflict clears.
- Keep `LICENSE` canonical, list bundled licenses separately, and remove unused
  README assets.
- Make scheduled vendor updates open PRs; require a passing `checks` job before
  merging to `main`.

Gate: install, restart, update, failed install, and uninstall leave an external
PF sentinel and `zapret` anchor unchanged; no detached owned listener remains;
unknown processes are never signalled; secrets are not readable outside the
owning user.

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
- Let unknown hosts try only the local adaptive ladder. A successful Geph
  payload proves tunnel health, not that a host requires a foreign exit;
  geo-exit remains explicit reviewed policy.
- Move Geph to a user LaunchAgent with `KeepAlive`; the tray becomes a settings
  client rather than a lifecycle dependency.
- Keep external DNS, VPN, PAC, and proxy state read-only.

Progress: runtime local-bypass misses, geo-exit failures, and repeated unknown
host stalls now enter one normalized reducer. Cold-start and runtime backend
failure also gate or pause the private PF anchor. Owned Geph runs in a user
LaunchAgent with `KeepAlive`; after repeated post-wake failures, the daemon can
pause its private PF anchor, wait for active tunnel sessions to drain, verify
the exact user job and listener identity, and kickstart that job without the
tray. Disposable CI runs two installed-daemon suspend/resume and network-change
re-arm cycles for both the source installer and the frozen daemon from the
packaged app. It also launches the exact packaged tray as the original user,
crashes and restarts only that verified process, and opens fresh non-root HTTPS
clients, clean-profile Google Chrome processes, and fresh UID/path-verified
Safari processes with isolated WebDriver sessions before and after the crash.
The same daemon PID and private anchor must survive while an unrelated PF
anchor, state entry, and live connection remain unchanged. A protected,
main-only account-backed gate now exercises the packaged tray, exact owned
Geph listener, a real Steam HTTPS payload, tray-independent operation, and
LaunchAgent `KeepAlive` PID replacement while preserving an unrelated `:9909`
listener. The first protected passing run and a physical default-route/lid-close
transition on a disposable Mac remain before the M1 gate is complete.

Gate: routing and Geph recover after tray crash, browser restart, network
change, and sleep/wake without manual buttons.

Every routing change also passes the deterministic data-plane traffic-contract
matrix: local bypass, geo exit, direct Telegram, generic local traffic, and
geo-backend fail-closed behavior. The matrix exercises the production handler
with fake endpoints; it complements, rather than replaces, live canaries and
PF lifecycle qualification.

## M2 - Contracts And Code

- Introduce privacy-bounded `StatusV2` sections for daemon, routes, backends,
  environment, and recovery state. Done in the transition release.
- Keep hostname-level and detailed network events out of world-readable status.
  Done for StatusV2 and root-owned raw logs at `0600`. Diagnostic exports stay
  sanitized and user-owned.
- Let the tray read V1 and V2 for one transition release. Done.
- Split the Python daemon into policy, reducer, probes, Geph backend, macOS PF
  adapter, and lifecycle modules. The pure policy classifier, recovery
  model/reducer, low-level macOS PF adapter, and owned-Geph identity adapter are
  now isolated; PF/Geph runtime orchestration and the remaining adapters are
  pending.
- Split the Rust tray into status client, diagnostics, installer, Geph config,
  and menu orchestration. Status freshness and the V1/V2 compatibility
  projection now live in an isolated status client. Diagnostic redaction, log
  tailing, recovery-state parsing, and owner-only export primitives are also
  isolated. Geph user settings, Keychain ownership, and legacy-secret migration
  now live behind a separate configuration adapter; runtime/LaunchAgent control,
  summary construction, installer facts, and UI orchestration remain.
- Keep Python transport; avoid a big-bang rewrite.
- Add language-neutral policy fixtures and recovery vectors. Done for contract
  v1. Deterministic address-attempt planning and route-scoped circuit breaking
  now have isolated v1 contracts executed by both Python and Rust. A pure
  connection-race state machine now
  circuit-gates before resolution and drives the address planner through
  language-neutral commands/events. Scripted resolver and connector adapters
  cover stalls, resets, family fallback, deadlines, circuit isolation, and
  late completion without network I/O. The Python socket adapter executes those
  commands against numeric candidates, transfers only the winning stream, and
  closes every loser or cancelled task. A policy-preserving runtime wrapper now
  races the existing first-payload probes inside already-selected local, Xbox
  DNS, and proven Smart DNS backends. It does not race routes or backend classes.
  A separate v1 runtime-registry contract now persists only complete backend
  outcomes across requests: one full protected local ladder is one local-engine
  result, while proven Smart DNS and verified owned Geph have independent
  geo-exit keys. The registry is bounded by idle TTL and deterministic LRU;
  eviction only forgets suppression and cannot select a different route.
  Unknown and direct traffic never enter persistent circuit state, and protected
  local groups still have no Geph edge. Fake handler endpoints cover
  stalled-first/healthy-second address races, per-ladder failure accounting,
  backend isolation, and unknown-host non-promotion. IPv6 use in the current
  daemon dialers and other platform adapters remain pending and require separate
  evidence.

## M3 - Release-Grade macOS

- Keep the Rust tray warning-free with strict Clippy in the required macOS
  checks job. Done.
- Pin every external GitHub Action to a reviewed immutable commit, build
  JavaScript with Node 24 LTS, and make macOS dependency installation explicit
  and fail-closed. Done.
- Keep stable app, preview app, and internal Geph releases visibly distinct;
  only stable app releases may update GitHub's latest pointer. Done.
- Pin Python/PyInstaller dependencies with hashes. Done for separate runtime,
  test, and build graphs on Python 3.13.14; CI, release, and legacy source
  installs require hashes and binary wheels.
- Fetch exactly the Geph version recorded in `vendor/geph/VERSION`; verify
  the matching asset version, checksum, and arm64 architecture. Done for the
  release workflow. App payloads now receive GitHub OIDC/Sigstore SLSA
  provenance and SPDX attestations after internal verification.
- Set an explicit Tauri target and publish an artifact manifest plus SBOM. Done
  for `aarch64-apple-darwin`: app releases carry a deterministic, target-resolved
  SPDX 2.3 inventory and a source-bound SHA-256 manifest for the complete
  payload set.
- Audit the exact application SBOM on pull requests, `main`, a weekly schedule,
  and before every release. Done with a checksum-pinned OSV Scanner and an
  expiring, fail-closed review policy; the published report is bound into the
  artifact manifest. The separately built Geph binary now has an exact
  crates.io digest, reviewed `Cargo.lock`, two-target SPDX inventory, full
  transitive audit, and verified provenance/SBOM attestations. New Geph versions
  pass through a source-contract PR before any binary is published.
- Run full tests and a privileged PF-anchor sentinel test in release CI. The
  release workflow now runs the sentinel against the exact signed `.app` before
  publishing; broader release test coverage remains pending.
- Separate preview and stable channels. Manual builds now create non-updating
  GitHub prereleases. Stable tag events fail before checkout until Developer ID,
  hardened runtime, notarization, and stapling are implemented as a fail-closed
  publication gate.
- Define production custody and rotation for policy-signing keys. Remote policy
  stays off by default; preview releases omit its channel until stable custody
  and rollback are reviewed.

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

Progress: `crates/slipstream-core` now owns the deterministic address-attempt,
route-circuit, bounded registry, connection-race, routing-policy, and recovery
modules. Python and Rust run the same frozen policy and recovery v1 vectors,
including the protected Discord/YouTube no-Geph invariant. Policy parsing,
signed updates, typed StatusV2, and runtime adapter migration remain.

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
- Deterministic data-plane traffic contracts through the production handler,
  asserting both the required and prohibited route backends.
- Fake DNS/SOCKS/TLS endpoints for stall, reset, empty response, and partial
  payload.
- PF sentinel and process-ownership integration tests.
- Install/update/uninstall integration test.
- Safari, Chrome, Discord, YouTube, OpenAI files/billing, Telegram, and Steam
  Store smoke matrix.
- Sleep/wake and network-change soak.
- Assertion that Discord and YouTube never appear in Geph route events.

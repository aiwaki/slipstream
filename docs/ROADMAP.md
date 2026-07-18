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
- Make daemon shutdown a one-way transition: stop status publication before
  cleanup and serialize final status removal with every in-flight writer.
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
including the protected Discord/YouTube no-Geph invariant. The core also owns a
privacy-bounded, forward-compatible StatusV2 model; a language-neutral fixture
freezes its exact legacy tray projection while V1 remains accepted. A separate
manifest contract now gives Python and Rust the same normalization, bounded
hostname validation, structured failures, first-match protection, and
static/geo table separation. Signed-bundle contract v1 now also freezes
Python-compatible canonical bytes, SHA-256 identity, Ed25519 verification, and
structured envelope failures in both languages. Activation contract v1 now
freezes compare-and-swap trial, health, rejection restore, stale-event, and
single-slot rollback transitions as ordered data-only actions. Health evidence
is bound to both policy content and a monotonic trial generation, preventing a
late result from an aborted attempt from committing a retry of the same SHA-256.
The existing Python daemon now runs verified apply, health, persistence,
rejection restore, startup load, and rollback through that reducer. Its owned
policy files use compensating transactions, legacy persisted state remains
readable, and every consumed trial generation is made durable before candidate
activation. Persisted signed provenance survives content equality with the
bundled manifest, while a new envelope for the already-active canonical hash
remains a v1 no-op. The remote channel remains disabled and no production trust
key is present. `crates/slipstream-windows-adapter` is now the first platform
boundary. Its isolated v1 harness consumes all frozen policy, recovery,
StatusV2, bundle, and activation contracts through an injected effects trait.
The recording implementation proves effect ordering and compensation without
native APIs, processes, files, services, DNS, proxy, VPN, sockets, or packets.
An isolated service-lifecycle v1 contract now adds exact content-addressed
ownership, transactional install compensation, intent-first start/stop and
uninstall, bounded crash recovery, final-state proofs, and fail-closed handling
when compensation cannot be verified. Its recording executor never calls a
native service manager or touches the host. A target-scoped read-only SCM
observer now queries only the exact Slipstream service name, maps native status
conservatively, preserves the configured binary command, and treats only the
service-not-found result as absence. It does not infer ownership or expose a
mutating API. A separate pure ownership contract now requires an owner-only
record, canonical SCM command, exact executable path and SHA-256, positive
generation, and stable SCM state before producing an owned identity. Missing or
inaccessible evidence remains unknown and mismatches are foreign. A Windows-only
read-only collector now resolves the machine record through the system
`ProgramData` known folder, proves the opened file's final path, non-reparse
regular-file identity, owner and restrictive DACL, parses bounded strict-v1
JSON, and hashes the exact opened executable handle. Its disposable Windows
smoke combines those native proofs with the frozen reducer. A separate native
payload effect now stages only a source whose opened-handle SHA-256 matches the
content-addressed identity. It creates owner-only pending files, flushes and
renames the executable before the owner record commit marker, reopens both
through the collector, and compensates only transaction-owned handles. A
separate lifecycle-state transaction persists strict bounded intent and
active-install records under the same protected machine directory. Pending
files are durable interruption evidence; inaccessible, invalid, permissive, or
identity-inconsistent records block mutation. Active install commit requires
the exact running intent and already-proven staged payload, while removal
requires an absent tombstone and preserves it. Stable state is only input to a
later action-specific ownership gate, not SCM authorization. Neither filesystem
effect has an SCM, process, DNS, proxy, VPN, socket, or packet API. A shared,
bounded, machine-wide operation lock now serializes durable-state, staged-payload,
and SCM effects so authorization evidence cannot change during a native mutation.
The returned kernel object is accepted only after its owner and DACL independently
prove that no untrusted principal can wait, acquire, or rewrite it.
A separate pure v1 SCM gate
now binds each register, start, stop, or unregister action to compatible durable
intent, exact staged payload, and exact read evidence. Its native effect opens
only `dev.slipstream.service`, requests one mutation right plus query rights,
and rechecks the same service handle before acting. An accepted stop keeps that
handle and waits to an exact bounded `Stopped` observation before cleanup may
continue; it never enumerates or
reconfigures services and has no process or networking surface. Disposable CI
qualifies exact registration and removal. A single native compositor now holds
the shared operation lock across each complete action, verifies readiness and
terminal states against the same content-addressed identity, waits for actual
SCM absence after deletion before payload removal, and defers active-record
clearing when post-commit compensation still has owned SCM or payload state.
The disposable full-lifecycle gate builds a minimal real Windows service and
exercises install, stop, start, bounded crash recovery, uninstall, and an
injected failure after durable install commit. PR #152 qualifies that gate in
Windows CI. PR #153 adds the production-facing controller: it acquires the
shared lock before reading durable intent or live SCM/ownership evidence,
reconstructs actionable state only from an exact committed owned identity, and
holds the lock through the complete reducer command and native compositor.
Repeated identical install and terminal uninstall are idempotent; foreign,
unknown, interrupted, and inconsistent evidence remains non-mutating. A second
disposable gate proves that a failed crash restart persists its bounded attempt
and a later controller process resumes recovery before uninstalling exactly.
PR #154 adds the production no-network service host and management binary. Exact
`--service` is the only SCM mode; explicit management commands hash the current
executable and consume the qualified controller. The host reports bounded
start, running, stop-pending, and stopped states, accepts stop and shutdown, and
emits versioned management results. Separate-process Windows CI proves
idempotent install, stop, start, and uninstall against the real SCM, including
PID replacement after restart. Windows data-plane contract v1 now freezes the
request/session and worker lifecycle as pure commands and events. Deterministic
fake effects cover readiness, first-payload stalls, reset before payload,
partial-payload stream failure, caller cancellation, shutdown cancellation,
bounded forced close, resource ownership, and late completion. Route, strategy,
service group, and backend must agree with a fresh classification through the
active validated policy tables before a session starts; Discord and YouTube
cannot hide behind caller-supplied `generic` metadata and have no Geph edge.
External DNS, proxy, PAC, and VPN state remains untouched. Effect commands are
failure-atomic, and a partially completed batch resumes from an exact cursor
without replaying an opened or closed resource. Monotonic session IDs and
bounded terminal retention also prevent a stale completion from targeting a
reused request ID without allowing service state to grow forever. The pure
worker-host composition now orders those data-plane effects with SCM: readiness
gates `RUNNING`, startup failure is terminal, `STOP_PENDING` precedes bounded
cancellation, and `STOPPED` follows only worker termination. The production
host consumes the same contract through an injected no-network effect.
Deterministic vectors cover normal stop, forced deadline, late completion, and
interrupted mixed effect batches. The first native socket primitive is direct
connector v1: it accepts only an opaque, active-policy-validated direct plan
with a canonical numeric endpoint, bounds every buffer,
queue, connect, and first-payload interval, and maps connect, payload, reset,
close, cancellation, deadline, and shutdown back into the frozen data-plane
events. A native effect stages the plan before `StartSession`, owns the socket
until `CloseSession`, retains bounded terminal evidence, and rejects every
non-direct backend. Loopback CI exercises the real reducer/effect chain plus a
reset after partial payload. The production SCM host deliberately remains
no-network until a separate ingress can provide trusted numeric endpoint
evidence and an adapter-owned client stream; no resolver or multi-backend
transport was added.
Windows direct ingress v1 now binds that numeric endpoint to fresh
`original_destination` evidence, the reducer-issued request/session identity,
and one non-cloneable accepted client stream. Preloaded bytes are rejected and
backend payload is reported only after client delivery. The relay bounds client
and backend reads, channels, connector buffering, retained state, and both
backpressure intervals. Client-first close cancels without fabricating a
backend failure; upstream stall is an explicit reset. A native loopback gate
drives multi-megabyte traffic in both directions plus reset, cancellation,
deadline, and shutdown paths. Deterministic relay-state tests qualify the exact
first-delivery and no-progress boundaries without depending on platform TCP
buffer sizing or autotuning. This still does not activate production traffic:
the SCM host stays no-network until an independently reviewed Windows
interception source can provide the owned stream and original-destination
evidence without adding DNS or route selection to the relay.

Windows capture source v1 now freezes the lifecycle immediately above that
ingress without choosing an interception technology. A native adapter may
stage one accepted stream under an opaque one-shot resource ID and expose only
fresh canonical numeric original-destination evidence to an external admission
authority. The source allocates monotonic connection IDs, retains every stream
until an independently admitted direct request is handed off, and closes
invalid, rejected, expired, startup-racing, or shutdown-racing resources. A
failed handoff is failure-atomic and keeps source ownership for retry or
explicit compensation. Admission stop precedes bounded drain, effect batches
resume from exact cursors, terminal retention is bounded, and late events
cannot resurrect the source. The pure recording harness has no resolver,
backend selection, native interception API, or system-network mutation. The
production SCM host still does not compose it and remains no-network.

Native TCP capture v1 now selects a minimal WFP callout at
`ALE_CONNECT_REDIRECT_V4/V6` plus the exact owned Rust service. The driver
registers the kernel classify callout first. Runtime provider, sublayer,
`FWPM_CALLOUT` management object, provider context, and filters must then be
non-persistent, non-boot objects committed together in one dynamic engine
transaction only after listener and service/driver identity are ready. Closing
that session is the first stop and crash fail-safe; kernel callout unregister
and driver unload follow only after exact filter absence. The callout must
target the exact listener PID, preserve strict versioned original-destination
context, inspect redirect state to prevent self-loops, and preserve opaque
redirect records so another WFP proxy can coexist. WinDivert, system proxy/PAC,
and TUN are not capture-v1 implementations.

The first implementation phase is now frozen as
`contracts/windows-wfp-capture-v1.json` and pure `wfp_capture::v1`. The fixed
128-byte driver/service context binds original IPv4/IPv6 endpoints to the exact
active service generation, PID, instance and executable hash. The service-side
validator requires an exact owned loopback listener and bounded opaque redirect
records. Each validated capture carries the monotonic source-issued connection
ID; handoff revalidates a complete direct-ingress request and requires the same
connection identity and endpoint. Admission mismatch preserves the
non-cloneable capture, while the opaque ingress/connect plan appears only after
the redirect-record plan is marked applied. This phase calls no WFP or socket
API, does not change direct connector v1, and is not composed into the
production host.

The second pure phase is now frozen as
`contracts/windows-wfp-runtime-v1.json` and `wfp_runtime::v1`. The lifecycle
binds every completion and timer to the exact service/capture identity,
reducer-issued monotonic runtime attempt, and session generation. Kernel
callouts precede listener readiness and one atomic dynamic-session commit.
Session close is the sole first stop effect. Exact filter absence gates
listener stop, bounded stream drain and kernel unregister; observed filter
presence retains the listener and callouts while scheduling a recheck. Effect
batches resume from exact cursors. This phase still invokes no WFP, Winsock or
driver API and remains disconnected from the production host.

The management-session phase is now frozen as
`contracts/windows-wfp-session-v1.json` and `wfp_session::v1`. Seven fixed
owned keys identify the provider, sublayer, V4/V6 management callouts,
provider context, and filters. A separate 128-byte provider context binds the
exact service/runtime/session identity, target PID, executable hash,
dual-stack loopback listeners, and TCP/443 scope. The controller requires
same-binding kernel-registration and listener-readiness proofs before calling
the transaction and refuses teardown until both filter keys are proven absent.
The native Windows effect uses one dynamic engine transaction and compensates
every partial failure with transaction abort and session close; it never uses
broad delete-by-key recovery. Disposable CI opens an empty dynamic session,
begins and aborts an empty transaction, closes it, and proves both filter keys
absent. It does not commit live filters without a registered disposable kernel
callout, and the production host remains disconnected.

Remaining implementation stays phased and closed to production traffic:

1. Implement the minimal kernel V4/V6 connect-redirect callout and disposable
   registrar, then qualify the already-frozen controller with a real full
   management-object/filter commit. Prove kernel registration before the
   transaction, listener readiness before filters, loop prevention, and exact
   filter removal before listener drain or kernel unregister.
2. Implement the native WFP-specific socket effect that consumes the frozen
   one-shot record plan, applies accepted redirect records, and only then binds
   or connects. Keep direct connector v1 frozen.
3. Qualify exact ownership, loop prevention, another redirector, crash, reboot,
   bounded shutdown, update, uninstall, and external VPN/DNS/proxy coexistence
   on disposable x64 and ARM64 Windows.
4. Add architecture-complete signed-driver packaging. Only then may the capture
   source be composed into the production SCM host.

Resolver choice, local/geo backends, and installer UI remain outside this
sequence.

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

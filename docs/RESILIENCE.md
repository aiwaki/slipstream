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
| Startup qualification | publishes a probe-free `dormant` snapshot before network probes; system-DNS lookups run in killable console-user child processes under per-host and total preflight deadlines; packaged CI blackholes the first neutral resolver target and requires a later target to activate | require the exact packaged gate to pass before the next workstation install |
| Crash restart | launchd `KeepAlive` | none |
| PF ownership | private `com.apple/slipstream` anchor below the system `com.apple/*` anchor point; earlier transparent HTTPS interceptors or an unavailable enabled geo-exit backend pause Slipstream without mutating external state | keep both privileged sentinel jobs required in CI and add cross-version rollback after the first safety-qualified release |
| Clean exit | flushes only private filter/NAT rules and releases Slipstream's PF enable token; script and frozen packaged payloads share the same install/reinstall/restart/uninstall sentinel gate | stable release artifact qualification |
| Stale PF recovery | tray kickstarts the daemon, then clears only the private anchor and owned enable token | non-tray watchdog if both app and daemon are gone |
| Network transitions | detects wake gaps and default-interface changes, re-arms PF/voice capture/canaries, and exposes last re-arm in status; installed script and packaged-daemon CI repeat suspend/resume and the shared network-change path without replacing real network state | physical default-route and lid-close soak on a disposable Mac plus broader endpoint-safe payload canaries |
| Tray independence | packaged CI launches the exact tray as the original user, verifies fresh non-root HTTPS clients, clean-profile Chrome processes, and fresh UID/path-verified Safari processes with isolated WebDriver sessions, crashes and restarts only verified processes, and requires the same daemon PID, private PF anchor, sibling anchor, and live sentinel connection to survive; a protected main-only workflow adds account-backed owned-Geph payload and `KeepAlive` recovery | complete the first protected account-backed run and the physical transition soak |
| Full-tunnel VPN | daemon becomes dormant on `utun*` default route | more visible tray detail |
| Local bypass strategy decay | strategy ladder, per-host cache, runtime failure-triggered recheck, route-health HTTPS payload canaries, and Discord CDN throughput threshold | signed strategy updates, broader endpoint-safe local-bypass checks |
| Geo-exit payload stalls | Steam Store canary verifies real HTTPS payload through Geph; backend loss pauses the private PF anchor so clients do not retry through a dead local path; owned Geph runs as a user LaunchAgent and live restart is daemon-coordinated after the private anchor is paused and sessions drain; the protected qualification gate repeats a real Steam payload after tray crash and owned PID replacement | first protected run plus account-backed physical sleep/wake soak on a disposable Mac |
| Recovery decisions | normalized `ConnectionOutcome` evidence and a pure reducer keep local re-sweep, learned-route reset, owned-Geph restart evidence, unknown-host recheck, and external warnings separate; the bounded aggregate action is exposed through `StatusV2` | retain language-neutral vectors while splitting runtime adapters |
| Geph coexistence | owned `:9954` listener requires PID/executable/config/listener proof; external `:9909` is diagnostics-only | explicit user opt-in contract for any external backend |
| Secret storage | account secret in Keychain; Geph directory `0700`; config/cache/ownership files `0600` and atomic | verify the same contract in the protected disposable account-backed gate |
| CDN edge failure | local-bypass hosts can try more A records | rolling success metrics |
| DoH cache | bounded TTL cache | resolver rotation metrics |
| Endpoint gates | repeated failure of important secondary geo-exit endpoints can degrade their group after a grace threshold | expand only from evidence-backed user workflows |
| Strategy cache and policy | bounded/versioned cache plus explicit policy tables, diagnostic policy hash, signed-bundle builder/validator, trusted-key distribution path, local persist, rollback, explicit opt-in remote fetch scheduler with health gates, release workflow packaging, and release artifact preflight for signed channel assets | configure real production key custody and publish a release-channel policy asset |
| Voice flows | TTL/LRU cleanup | long-run load audit |
| Logs | rotating daemon log, tray snapshot, route-health failure summaries, stale external proxy exception reporting, and copied plus file-backed diagnostic summary | attachable diagnostic export polish |
| App updates | signed Tauri updater | Apple notarization for first install trust |

The privileged PF gate is `scripts/pf_anchor_smoke.py`. CI runs it on a
disposable macOS runner. It uses the real private anchor with a high test port,
never TCP/443, and verifies cold-start dormancy, runtime suspension, an unchanged
sibling sentinel anchor, and an identical global PF snapshot after cleanup.
Cleanup uses separate `-F rules` and `-F nat` operations; `-F all` is forbidden
because macOS includes the shared state table in that modifier.

`scripts/pf_installed_lifecycle_smoke.py` is the second disposable gate. Its
fast job installs the script-mode LaunchDaemon; a separate job builds the real
arm64 Tauri `.app` and installs the frozen daemon embedded in its resources.
Both modes prove a missing Geph backend leaves PF dormant, repeat installation,
briefly activate the existing local-only mode, restart the daemon, and uninstall
it. They then run two bounded lifecycle cycles: `SIGSTOP`/`SIGCONT` crosses a
CI-only shortened wake threshold through the production cadence detector, while
a root-only diagnostic signal queues the same network-change handler used by
default-interface detection. Production keeps its 30-second wake threshold.
Before any signal, the harness verifies the exact installed daemon command. A
non-root TCP connection and its PF state must survive the entire cycle, the
sibling sentinel rules must remain byte-for-byte unchanged, and the global PF
snapshot must match after cleanup. In packaged mode it also starts a fresh
headless Google Chrome process with a new owner-only profile and a fresh Safari
process with an isolated WebDriver session before tray start and after tray crash
and restart.
Chrome runs as the original user with process-local proxy and QUIC disabled so
its request uses TCP/443. SafariDriver is enabled and started only by the
disposable wrapper, listens on an explicit IPv4 loopback port, and uses Safari's
isolated automation window instead of the user's profile. The harness refuses a
pre-existing Safari process, verifies the process created for the session by UID
and executable path, requires the loaded page to report `h2` or `http/1.1`, and
may signal only that PID before the next stage. HTTP/3 is rejected as insufficient
evidence rather than blocked. Neither probe changes system DNS, proxy, PAC, or
VPN configuration. The script refuses to run unless GitHub Actions and
`SLIPSTREAM_DISPOSABLE_CI=1` are both present. The packaged job uploads only the
exact `.app` that passed this qualification.

The startup path is independently bounded before either lifecycle gate can arm
PF. A fresh `dormant` status is written as soon as the exact local listener is
owned. Baseline system-DNS resolution then occurs in short-lived child
processes under the console user's identity; a stuck resolver is killed and the
next neutral target is attempted within one total preflight budget. Status
rendering consumes cached DNS diagnostics, while the background refresh uses
the same bounded child mechanism. Tests use a real sleeping child and prove both
bounded return and process disappearance. The packaged disposable gate also
creates a scoped `/etc/resolver` blackhole for the first neutral target, observes
the safe status at the incoming DNS query, requires a later target to activate,
checks that no resolver helper survived, and restores the resolver configuration
before continuing the browser and uninstall lifecycle.

`scripts/geph_owned_lifecycle_smoke.py` is a separate user-level qualification.
It is invoked only by the protected, main-only `owned-geph-qualification`
manual workflow, so account credentials are never available to pull-request
code. The repository environment must allow deployments only from `main` and
provide the `SLIPSTREAM_GEPH_ACCOUNT_SECRET` secret; the workflow fails closed
when it is absent. The root daemon must be absent and durably disabled before
the packaged tray starts. The harness writes a disposable Keychain item and private config,
verifies the exact LaunchAgent label, UID, PID, executable, config, listener,
and file modes, then requires a real Steam HTTPS payload through SOCKS `:9954`.
It crashes the tray and repeats the payload, signals only the revalidated owned
Geph PID, and requires `KeepAlive` to replace that PID and carry another
payload. A test-owned listener on external port `:9909` must remain alive
throughout. Cleanup removes only the disposable user-level state; the workflow
verifies that no daemon, private PF rule, token, status file, listener,
LaunchAgent, or Keychain item remains.

## Priority Order

### M0 - Safe Base

- Establish the first safety-qualified release as the cross-version rollback
  baseline; do not execute older global-PF releases as rollback fixtures.
- Prove unknown listeners and PID reuse cannot cause unrelated process signals.
- Keep secrets owner-only and remove direct-to-main automation.

### M1 - Autonomous Routing

- Normalize connection outcomes and safe recovery actions in one reducer. Done
  for local runtime misses, geo-exit failures, and unknown-host payload rechecks.
- Keep local bypass and geo-exit recovery strictly separated. Enforced by
  reducer tests for Discord, YouTube, owned Geph, and external state.
- Keep owned Geph in its user LaunchAgent so the tray is optional. Packaged CI
  qualifies the real tray executable crash against a local-only daemon. The
  protected account-backed gate is implemented; complete its first passing run
  and the physical default-route/lid-close soak on a disposable Mac.

### M2+ - Contracts And Platforms

- Introduce a privacy-bounded, versioned `StatusV2` contract.
- Split policy/reducer/probes/backends/adapters without rewriting transport.
- Make releases reproducible before extracting a shared Rust core and OS adapters.

## Notes

QUIC is not globally blocked. YouTube/googlevideo playback depends on preserving
working HTTP/3 paths where available. Any future QUIC intervention must be scoped
to a clearly identified failure mode and must not become a global UDP/443 block.

Routing research and external implementation notes are tracked in
[ROUTING_RESEARCH.md](ROUTING_RESEARCH.md).

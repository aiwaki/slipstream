# Slipstream Resilience Design

Goal: install once, then require as little manual intervention as possible. The
daemon should recover from routine macOS and network changes automatically.

## Routing Boundaries

Slipstream separates local DPI bypass from foreign-exit routing.

Local DPI bypass is for services affected by DPI/SNI interference. Discord and
YouTube web/control traffic stay on the normal route and use local desync/fake
strategies. Googlevideo media remains protected from Geph but uses reviewed
direct passthrough because its former fake-only path broke real media payload.

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
| Startup qualification | publishes a probe-free `dormant` snapshot before network probes; system DNS and HTTPS checks run in killable console-user `/usr/bin/dscacheutil` and `/usr/bin/curl` child processes under per-host and total preflight deadlines, without executing the installed daemon; the privileged installer verifies the root-only daemon's exact path, SHA-256, owner, mode, launchd PID, listener, StatusV2, and private-PF state before atomically publishing persistent bounded evidence plus a root-only hard-link inode witness for the tray; the unprivileged tray never opens the installed binary, and a removed or replaced runtime invalidates the witness | prove successful commit and injected attestation-failure rollback in packaged disposable CI, repeat exact-main and protected exact-artifact gates, then complete one user-present workstation smoke |
| Crash restart | launchd `KeepAlive` | none |
| PF ownership | private `com.apple/slipstream` anchor below the system `com.apple/*` anchor point; earlier transparent HTTPS interceptors or an unavailable enabled geo-exit backend pause Slipstream without mutating external state | keep both privileged sentinel jobs required in CI and add cross-version rollback after the first safety-qualified release |
| Clean exit | flushes only private filter/NAT rules and releases Slipstream's PF enable token; script and frozen packaged payloads share the same install/reinstall/restart/uninstall sentinel gate | stable release artifact qualification |
| Stale PF recovery | tray kickstarts the daemon, then clears only the private anchor and owned enable token | non-tray watchdog if both app and daemon are gone |
| Network transitions | detects wake gaps and default-interface changes, re-arms PF/voice capture/canaries, and exposes last re-arm in status; installed script and packaged-daemon CI repeat suspend/resume and the shared network-change path without replacing real network state | physical default-route and lid-close soak on a disposable Mac plus broader endpoint-safe payload canaries |
| Tray independence | packaged CI launches the exact tray as the original user, verifies fresh non-root HTTPS clients, clean-profile Chrome processes, and fresh UID/path-verified Safari processes with isolated WebDriver sessions, crashes and restarts only verified processes, and requires the same daemon PID, private PF anchor, sibling anchor, and live sentinel connection to survive; protected run `30318687293` also passed account-backed owned-Geph payload, `KeepAlive` recovery, sandboxed Chromium semantic routing, and complete cleanup | complete the physical transition soak |
| Full-tunnel VPN | daemon becomes dormant on `utun*` default route | more visible tray detail |
| Local bypass strategy decay | strategy ladder, per-host cache, runtime failure-triggered recheck, route-health HTTPS payload canaries, and Discord CDN throughput threshold | signed strategy updates, broader endpoint-safe local-bypass checks |
| Unknown-host authorization ordering | eligibility, confirmation-token reservation, every noise producer, and route persistence share one lock; noise revokes active semantic/plain and transport-incomplete precursor probes, while a spent exact proof survives bounded owned-Geph recovery only for its current request | exact-artifact browser qualification plus adversarial concurrency soak |
| Generic unknown-host recovery | unknown hosts retain the exact system destination, then app-owned Xbox DNS and distinct local strategies; before any server byte reaches the client, explicit EOF or an owned bounded first-payload timeout may advance a complete stage, while cancellation, connect failure, generic error, and incomplete address-race evidence cannot; once system, Xbox DNS, and two distinct strategies complete the replay-safe proof, remaining local strategies do not postpone owned Geph; a clear network-wide guard plus independent exact HTTPS confirmation remain mandatory for a private expiring overlay, while network-wide noise immediately invalidates all pre-noise learning/deferred authority and permits only one consumed current-request attempt through verified owned Geph with no confirmation or learning; candidate-backed requests consume the exact proof before waiting, every semantic persistence path rechecks revoked authority under the final lock, and every production noise writer uses that same lock; partial streams use the stricter framed-record path | exact-artifact Safari/Chrome qualification and longer false-positive soak |
| Geo-exit payload stalls | Steam Store canary verifies real HTTPS payload through Geph; backend loss cools only the failed owned Geph path while local bypass remains active; owned Geph runs as a user LaunchAgent and live restart is daemon-coordinated after new owned sessions are blocked and existing sessions drain; the protected qualification gate repeats a real Steam payload after tray crash and owned PID replacement | first protected run plus account-backed physical sleep/wake soak on a disposable Mac |
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
Before the packaged cold install, the gate injects a failure after privileged
identity verification and requires the installer to return nonzero, remove the
exact launchd label, plist, private PF state, enable token, status, socket,
attestation record, and root runtime, and restore the exact global PF snapshot.
The successful path then requires a root-owned mode-`0644` evidence record whose
source and installed hashes match the packaged daemon, whose installed identity
is root-only mode `0700`, and whose launchd PID, listener, StatusV2 state, and PF
state agree. The bounded console-user baseline children use fixed macOS system
tools and never execute or read the installed daemon. The tray validates only
that bounded record against its bundled daemon.
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

### Windows Production Host Evidence

Terms used below:

- **active-install record**: the durable record binding the currently admitted
  service identity to its installed payload;
- **crash budget**: the durable bounded counter that limits automatic
  crash-recovery attempts;
- **independent sentinel**: a test-owned file inside the secured runtime root
  that Slipstream does not own and therefore must preserve.

The production-host generation gate exercises the public
`slipstream-windows-service.exe manage install/uninstall` path on native AMD64
and ARM64 runners. It proves that a byte-distinct second generation cannot
reuse the exact SCM name and machine runtime root until the first generation's
SCM registration, payload, owner record, and active-install record are absent.
An independently owned sentinel inside the secured runtime root must survive
both uninstall cycles.

The first coexistence-sentinel revision failed safely: the fixture pre-created
the production runtime root, leaving an ACL that the lifecycle-state writer
correctly rejected as untrusted on both architectures. The accepted gate lets
the real installer create and secure the root before placing the independent
sentinel. This preserves the ACL guard instead of weakening it to accommodate
the test.

The production-host crash gate uses the same public `manage install`,
`manage recover`, and `manage uninstall` surface. Before termination it
revalidates the SCM PID, canonical image path, executable SHA-256, owner
record, and active-install record, then retains one exact process handle with
termination and synchronization rights. Recovery must replace that process
instance and reset the crash budget while preserving an independent sentinel.
Instance replacement is identified by PID plus Windows process creation time;
PID inequality alone is not evidence because Windows may reuse a numeric PID.
A second recovery must leave the exact recovered instance unchanged, and final
uninstall must prove the service, payload, and durable active records absent.

The first native revision failed on both architectures because the process
handle omitted `SYNCHRONIZE`, making `WaitForSingleObject` return
`WAIT_FAILED`. The corrected PR head passed native execution, but review
rejected its PID-inequality assertion before merge. The final RAII handle and
creation-time identity passed native AMD64 and ARM64 plus exact-main CI and
audit in PR #277. This gate terminates only the exact verified process and
does not compose production networking or mutate routes, DNS, proxy/PAC/VPN,
drivers, or external processes and services.

The production-host reboot-admission gate is the prerequisite for a later
physical reboot test. It registers the exact owned service as
`SERVICE_AUTO_START` with `SERVICE_WIN32_OWN_PROCESS` and
`SERVICE_ERROR_NORMAL`, then re-reads all three values from SCM before
`install`, `start`, or crash recovery may be accepted, including reducer
no-change paths. Service boot entry separately requires matching durable
`Running` intent and active-install evidence plus the same exact SCM
configuration. The controller-owned initial start is the sole exception:
SCM passes the exact `--slipstream-managed-start-v1` argument so the worker can
reach readiness before the lifecycle commits active-install evidence. An
ordinary automatic boot has no marker and cannot use that pre-commit path.
Durable `Stopped` intent exits cleanly without starting the worker, while
missing, interrupted, unknown, or inconsistent evidence fails closed; only the
public management start may deliberately resume it. The
disposable native test stops the service, invokes the SCM start path directly,
requires the stopped intent to remain authoritative, then proves an explicit
management start can resume it. It also changes only the owned service back to
demand-start and requires running-state commands to fail closed. Exact `stop`
and `uninstall` remain available despite that drift so a broken configuration
cannot make the service unremovable; final absence and preservation of an
independent sentinel are mandatory. This gate does not reboot a runner and
therefore does not claim physical boot-time execution, post-boot readiness, or
production networking.

PR #279 merged the admission gate as
`0d4bf269a3261c5f8263da051de805e32b8f030f`. Exact-main native run
`30511021761` passed jobs `90770963824` (AMD64) and `90770963857` (ARM64);
CI `30511021763` and audit `30511021766` passed on the same SHA. Both native
jobs completed the target reboot-admission test and every later packet,
cleanup, and lint step. The next gate must perform an actual reboot and prove
post-boot readiness; this evidence does not substitute for that test.

The physical reboot gate is implemented as
`scripts/qualify_windows_production_host_reboot.ps1` with a frozen
`windows-production-host-physical-reboot-v1` contract. It deliberately has no
reboot command. An elevated operator first runs `prepare` against the exact
built production host. The phase refuses pre-existing SCM or active ownership,
installs through the public management CLI, verifies the committed
owner/intent/active-install records, automatic-start service, exact process
path and SHA-256, then atomically writes an Administrator/SYSTEM-only
transaction beside an independent sentinel. The operator performs a real
Windows restart separately. `resume` then requires a changed
`Win32_OperatingSystem.LastBootUpTime`, post-boot `Running` service evidence,
a process creation time inside that boot, unchanged sentinel, and an identical
read-only DNS/proxy/PAC snapshot. Success uninstalls through the same exact
owned executable and proves the SCM service, owner record, active-install
record, payload, and process absent while retaining the durable absent intent.
Failure attempts that exact rollback only while the protected transaction,
current owner record, generation, executable path, and SHA-256 still agree;
otherwise it refuses mutation. `cleanup` is the explicit recovery phase for an
interrupted operator session.

Exact-main run `30541625059` on
`1f9e9768cb554d08a4ac888a842ee44c06897444` proved the PowerShell
`REG_BINARY` snapshot correction and reached release-host `prepare` on native
AMD64 and ARM64. Both jobs then timed out in the independent terminal-absence
observer after the exact public uninstall returned accepted. No bundle was
packaged or uploaded. The harness now reports a bounded, non-secret observation
of the exact SCM service, owner record, active-install record, payload, and
last known service process, and the release-host `prepare -> cleanup` preflight
runs on PR native jobs as well as main. This changes no product lifecycle or
network state; it narrows the next correction to evidence from the real
architectures before merge.

PR #285 run `30543502731` narrowed the result identically on AMD64 and ARM64:
the SCM service, owner record, and last service process were absent, while the
active-install record and installed executable remained visible for the full
bounded deadline. The management command had been launched from that installed
executable, so its internal delete-pending state was not terminal external
absence. Product management now refuses uninstall when its controller source
is the installed payload. The physical-reboot harness retains the original
source artifact in its protected transaction, re-verifies its SHA-256 and
distinct path, and uses that exact external controller for cleanup and resume.
This makes accepted uninstall mean observable terminal absence without a broad
process kill, reboot-delayed deletion, or mutation of unrelated files.

PR #285 merged as `be460249494da8439ca0a4787cc1465263a06a91`.
Exact-main run `30546036086` passed both native architectures, including the
external-controller release preflight, and published the exact ARM64 bundle.
After the bundle manifest, sizes, and SHA-256 values matched on the host and
inside the disposable Parallels Windows 11 ARM64 guest, the guest's first
`prepare` failed before installation with status `0xC0000135`. The clean guest
does not contain `vcruntime140.dll`; GitHub's native runners do, so their green
preflight did not prove fresh-machine portability. The harness left only its
state-root ownership marker: the SCM service, product root, owner and
active-install records, installed payload, transaction, and sentinel were
absent, while DNS and proxy observations remained unchanged. Windows MSVC
production binaries therefore use the statically linked CRT, and the
production service entry point refuses to compile on Windows MSVC without
`target_feature = "crt-static"`. A new exact-main artifact and a full physical
reboot transaction are still required before this gate can pass.

PR #286 merged the static CRT correction as
`19f2a263d3ccb686128675d1ff387fde771a3846`. Exact-main CI
`30548867352`, audit `30548869879`, and native run `30548867249` passed on
that SHA; native jobs `90892002017` (AMD64) and `90892002053` (ARM64)
published the commit-bound bundles. The exact ARM64 artifact `8762073225`
matched its manifest, sizes, and SHA-256 values before and after transfer to
the clean Parallels Windows 11 ARM64 guest.

The guest passed `prepare`, then a real Windows restart changed the exact
service process from PID `2352` to PID `3344`. `resume` proved the new process
belonged to the new boot but exposed a payload-removal race during uninstall.
SCM can report `Stopped` and remove the exact service before the service
process releases its executable image. The previous removal order deleted the
owner record first, then failed to mark the still-used executable for deletion,
leaving an active-install record and exact payload with durable `Absent`
intent. The controller refused that incomplete cross-evidence. Exact rollback
re-verified the active record and payload hash, removed only those two owned
remnants, retained the independent sentinel and absent intent, and left guest
DNS/proxy plus host DNS unchanged.

Payload removal now waits for bounded `ERROR_ACCESS_DENIED` or
`ERROR_SHARING_VIOLATION` release of the exact hash-verified executable before
deleting the owner record. A native regression holds the staged executable
without delete sharing, releases it after a delay, and requires complete
payload plus owner-record absence. This does not enumerate or terminate
processes and has no networking surface.

PR #287 merged that correction as
`8ef9fb3d3d4643f056793578511b693ef68b3fe5`. Exact-main CI
`30554495633`, audit `30554495985`, and native run `30554494634` passed.
Native jobs `90911349617` (AMD64) and `90911349663` (ARM64) both ran the
delayed image-release regression and exact release-host cleanup preflight.
Exact ARM64 artifact `8764371538` matched its commit-bound manifest, sizes,
and SHA-256 values on the host and inside the disposable guest.

The physical gate then passed from clean snapshot
`{2bb76695-9612-4180-ad43-9e19f0fcc11d}`. Transaction
`2ba05071-ac83-44a7-ad5f-259f35579962` installed generation `30554494634`
with exact payload SHA-256
`02a4e1b6b1c5cdebed5c794c05ade0f166eb2e78f9046b0b526b9fb60b828440`.
A real restart changed boot identity and service PID from `5984` to `3348`;
the replacement process was created after the new boot. `resume` returned
`outcome=passed` with `exact_uninstall_verified=true`. The harness verified
the unchanged network snapshot and independent sentinel SHA-256
`049a55607e7921e71a954200b3219272634a53b72d597e36d2b9cdde368bc044`
before deleting its temporary sentinel. Independent post-run checks found the
SCM service, owner record, active-install record, and exact payload absent, an
empty payload directory, and durable `Absent` intent bound to the same
identity. Guest DNS remained `10.211.55.1`, WinHTTP remained direct, host DNS
remained `111.88.96.50` / `111.88.96.51`, and host PAC remained disabled.
This closes the physical reboot service-lifecycle gate only; sleep/wake,
updater orchestration, production networking, and broader coexistence remain
separate gates.

The intended disposable-host sequence is:

```powershell
pwsh -File scripts/qualify_windows_production_host_reboot.ps1 `
  -Phase prepare `
  -ServiceHost crates/slipstream-windows-adapter/target/release/slipstream-windows-service.exe `
  -Generation 1

# Restart Windows explicitly, then return to the same checkout.

pwsh -File scripts/qualify_windows_production_host_reboot.ps1 -Phase resume
```

GitHub-hosted Windows jobs parse the script on both native architectures and
run its static contract tests, but they do not reboot and cannot publish the
runtime result. After every successful `main` push, each native job emits a
14-day `slipstream-windows-physical-reboot-<architecture>-<commit>` bundle.
Before upload, the job separately builds the release production host without
fixture features and runs that exact binary through the harness's real
`prepare -> cleanup` lifecycle. Upload occurs only after exact uninstall and
terminal absence are proven. The bundle contains that release executable, the
harness, the frozen contract, and `artifact-manifest-v1.json` with the source
commit, workflow run, architecture, size, and SHA-256 of every file. PR jobs
never build or publish this bundle. A disposable host must verify the manifest
and use only the bundle matching the intended `main` commit and guest
architecture.

PR #283 merged this publication gate as
`3fad7d49de41eac41d3babb835828ccaed7642f1`. Its first exact-main run
`30539745019` passed every earlier native qualification on AMD64 and ARM64 but
failed before release-host installation while taking the read-only network
snapshot. PowerShell pipeline enumeration changed the registry
`DefaultConnectionSettings` value from `System.Byte[]` to `System.Object[]`
when the helper returned it. The harness rejected the changed type, skipped
packaging and upload on both architectures, and therefore authorized neither
artifact selection nor a physical-host transaction. A read-only reproduction
on the disposable Parallels Windows 11 ARM64 host confirmed direct
`System.Byte[]`, pipeline-captured `System.Object[]`, and comma-preserved
`System.Byte[]`. The correction preserves only binary registry values as one
pipeline object; scalar proxy/PAC values retain their existing behavior.

The first successful physical result must come from a disposable Windows host.
This gate does not compose Wintun or production networking, and it does not
prove sleep/wake, updater orchestration, default route behavior, or broad VPN
coexistence.

`scripts/geph_owned_lifecycle_smoke.py` is a separate user-level qualification.
The release-critical invocation lives only in the protected, main-only
`release-readiness` manual workflow, so account credentials are never available
to pull-request code. The legacy standalone workflow requires an explicit
diagnostic-only input and cannot emit release evidence. The repository
environment must allow deployments only from `main` and provide the
`SLIPSTREAM_GEPH_ACCOUNT_SECRET` secret; either workflow fails closed when it is
absent. The root daemon must be absent and durably disabled before the packaged
tray starts. The harness writes a disposable Keychain item and private config,
verifies the exact LaunchAgent label, UID, PID, executable, config, listener,
and file modes, then requires a real Steam HTTPS payload through SOCKS `:9954`.
It crashes the tray and repeats the payload, signals only the revalidated owned
Geph PID, and requires `KeepAlive` to replace that PID and carry another
payload. A test-owned listener on external port `:9909` must remain alive
throughout. Cleanup removes only the disposable user-level state; the workflow
verifies that no daemon, private PF rule, token, status file, listener,
LaunchAgent, or Keychain item remains. Cleanup stages are independent: failure
to delete or verify one resource is recorded but cannot skip the remaining
tray, LaunchAgent, listener, Keychain, runtime, sentinel, and root-boundary
checks.

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

QUIC is not globally blocked. YouTube/googlevideo preserves working HTTP/3 paths
where available; intercepted TCP media tries plain TLS first and may fall back
only to bounded local desync. Any future QUIC intervention must be scoped to a
clearly identified failure mode and must not become a global UDP/443 block.

Routing research and external implementation notes are tracked in
[ROUTING_RESEARCH.md](ROUTING_RESEARCH.md).

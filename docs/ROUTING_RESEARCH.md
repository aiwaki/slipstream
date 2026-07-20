# Routing Research Notes

Updated: 2026-07-20

Purpose: keep a compact record of routing research, graph-tool status, and
safe follow-ups. This is an engineering note, not user-facing documentation.

## Findings Index

| Date | Topic | Status | Decision | Next action |
|---|---|---|---|---|
| 2026-07-20 | Packaged qualification used a superseded Geph release | Root cause proven; workflow fix under CI | `ci.yml` and `owned-geph-qualification.yml` derived only `geph-vendor-0.3.0`, while `vendor/geph/SOURCE.json` records revision `1` and `build-app.yml` correctly uses `geph-vendor-0.3.0-r1`. GitHub labels the unrevisioned release superseded; its `geph5-client` SHA-256 is `a1df14cb...`, while r1 is `3299d20f...`. The previous packaged lifecycle therefore qualified the macOS/PF lifecycle around a different Geph binary than the release path. A coincident GitHub `503` exposed the mismatch. Every workflow download now derives the immutable revisioned tag and uses one bounded retry helper that publishes no partial output. | Disqualify the downloaded `140598b` app from workstation testing. Require the exact corrected merge commit to pass packaged lifecycle with r1, then download that artifact without launching it. |
| 2026-07-20 | Packaged daemon blocked before first StatusV2 during controlled install | Root cause reproduced; workstation rollback clean; bounded startup fix under qualification | Exact artifact `c07ade34` started its listener and standalone Telegram-proxy check, then emitted no later session line before the installer reported `status missing`. The private anchor had not armed. Workstation evidence showed synchronous system DNS could stall on the first neutral target while a later target was directly reachable. The resolver ran in the daemon process with no timeout, and `amain()` wrote its first status only after awaiting the whole PF qualification. System-DNS lookups now run under the console user in killable child processes with per-target limits and one monotonic preflight budget. Startup publishes a probe-free `dormant` snapshot immediately after listener creation; regular status consumes cached DNS diagnostics, whose background refresh uses the same bounded resolver helper. A real sleeping child proves timeout and process disappearance. The packaged lifecycle now blackholes the first neutral target at the macOS resolver layer, captures the already-published status at that query, requires a later target to activate, and rejects a surviving helper. | Pass full Python/Rust checks and the exact packaged lifecycle before any new workstation install; do not use the primary workstation as the first privileged gate. |
| 2026-07-19 | Private PF traffic never reached the listener on the primary Mac | Root cause proven; scoped high-port smoke passed; packaged qualification pending | The anchor and listener were individually healthy, but the live kernel interface table contained `lo0 (skip)`. That state was not declared in `/etc/pf.conf`; therefore source inspection and anchor listings could not explain why post-arm probes failed. XNU defines `PFI_IFLAG_SKIP`, `DIOCSETIFFLAG`, and `DIOCCLRIFFLAG`. A bounded probe cleared only that bit, used the four-rule `route-to`/`rdr`/`no state`/`reply-to` topology on TCP/18443 -> 19443, recovered the original destination, then restored the exact flag. The production path now records a durable root-owned lease before clearing the bit and restores it before token release. A separate privileged smoke passed with both owned anchors empty afterward, the external sentinel and global rules unchanged, `lo0 (skip)` restored, no token/lease/status residue, and no test listener. Control-D was rejected because it reloads global PF state even though it also changes loopback visibility. | Run the exact branch through script and packaged lifecycle CI. Keep the primary workstation dormant and do not install until the PR merges with all safety gates green. |
| 2026-07-19 | Automatic macOS HTTPS baseline rollback | Implemented locally; disposable packaged qualification pending | A small neutral canary set is resolved through the console user's current system route, then verified with TLS and an HTTP response before PF. After arming, the same console-user helper replays only the exact pre-proven numeric destinations through the installed daemon. One successful post-arm proof is sufficient; no target hostname or address enters public status. Preflight failure leaves PF dormant and retries after a bounded delay. Postflight failure clears only `com.apple/slipstream`, releases only its enable token, and blocks automatic re-arm until an actual wake/network change. If pfctl cleanup fails, the daemon retains the listener and runtime and retries cleanup; force-stop and install rollback refuse to create a redirect-to-dead-listener state. Local execution proved the hidden helper against the user's unchanged current route, where system DNS selected `8.6.112.0` for `example.com`; the probe received HTTP `206`. | Run the exact packaged branch through the disposable Safari/Chrome/PF-sentinel lifecycle. Do not install it on the primary workstation before that required job passes and the reviewed merge commit is requalified. |
| 2026-07-19 | Clean install left every local-bypass service inactive | Fixed in code; packaged qualification pending | Exact-main `0.1.8` installed successfully but reported `dormant` with `local_engine=inactive` when no owned Geph listener existed, so Discord and YouTube received no local bypass. `pf_setup_if_ready()` incorrectly gated the whole private anchor on geo-exit readiness, while the packaged lifecycle smoke hid the defect by rewriting the installed LaunchDaemon with `SLIP_GEPH=0` before expecting `active`. Local PF readiness is now separate from optional Geph readiness. A geo-exit request with no app-owned backend keeps its reviewed route class and tries only the original pre-PF destination; it performs no alternate DNS lookup and never enters Discord/YouTube desync policy. A full-tunnel `utun*` default route still makes Slipstream yield its own anchor, while split/per-app VPN equivalence remains unqualified. | Require clean install and reinstall to become `active` with no Geph account, listener, or test-only environment patch. Keep the workstation uninstalled until the disposable packaged lifecycle passes, then verify Discord and YouTube locally before resuming M4. |
| 2026-07-18 | Fixed ChatGPT retry burst after uninstall | Owned teardown fixed; Smart-DNS HTTP/3 fallback remains external evidence | The old tray stopped owned Geph before the root daemon, and the daemon handled `SIGTERM` with immediate `os._exit`, so accepted TCP streams were cut. In the same incident, user-managed Smart DNS mapped OpenAI names to `87.228.47.204`; macOS recorded a viable HTTP/3 flow timing out after about 180 seconds and Chromium recorded repeated broken QUIC attempts before stable TCP fallback. PF did not intercept QUIC. Uninstall now closes the listener and private anchor first, drains accepted streams under a deadline while Geph stays alive, then removes the exact Geph job. Only that successful user cleanup authorizes the privileged helper to stage and delete the validated app bundle. Root cleanup fails visibly if a verified daemon survives. | Keep the primary workstation uninstalled. Qualify the exact packaged lifecycle on disposable CI, including absent daemon/Geph PIDs, listeners, app bundle, and preserved external DNS/PF state. Do not hide the external fallback by changing DNS or globally blocking UDP/443. |
| 2026-07-20 | Windows exact-route completeness feasibility | v1 frozen; premise rejected | Read-only system-DNS observation cannot enumerate every concrete hostname sharing an address: policy suffixes cover an unbounded set, applications may use DoH, and Wintun carries packets rather than hostname-bearing accepted streams. Therefore the existing complete-boundary evidence type is useful only as a conservative pure test gate; no honest native issuer can satisfy it as designed. | Define a separate capture-only v2 contract. Exact routes may select packets for inspection but must never authorize a backend; unknown, ECH, or otherwise unattributable flows remain direct. No native effects before loop, activation, expiry, and VPN-coexistence proofs pass on disposable Windows. |
| 2026-07-18 | Windows shared-destination conflict admission | Pure v1 gate implemented; native path abandoned | An exact IP route can capture unrelated domains on the same CDN address. A partial resolver cache or absence of a known conflict is insufficient. The pure gate requires opaque complete-boundary evidence for one exact destination and rejects mixed routing policy. Its admission remains non-authorizing. | Preserve the gate and fixtures as a record of the rejected assumption; do not implement a native issuer or route from it. |
| 2026-07-18 | Native Wintun artifact evidence | Implemented and qualified read-only | The native collector hashes bounded non-reparse archive, license, and DLL handles, parses the exact PE machine, and gives `WinVerifyTrust` the same held DLL handle. It performs no UI or network retrieval, extracts the exact certificate organization and SHA-256, requires a trusted timestamp countersigner, and retains the DLL handle in an opaque admission. Windows CI admitted both official AMD64 and ARM64 DLLs and rejected a tampered copy without loading Wintun or creating adapters/routes. | Keep the collector frozen and offline. It does not justify DLL loading or route mutation; any future use depends on a separately reviewed v2 capture contract. |
| 2026-07-18 | Windows packet-route evidence review | Pure host/address binding fixed; v1 frozen | A policy result and a caller-labeled DNS source did not prove that the selected destination came from resolving the policy host; reserved IPv6 such as `::2` could also pass the former denylist. Route requests now consume opaque host/address evidence and conservatively admit only reviewed global-unicast destinations. This still cannot prove every co-tenant on a shared address. | Retain the non-authorizing fixtures. Do not infer backend safety from a partial DNS view. |
| 2026-07-18 | Windows production signing and packet-adapter pivot | Artifact collection retained; exact-route authorization rejected | Do not ship a Slipstream-owned kernel driver. The official signed Wintun package remains the only reviewed packet primitive, but Wintun is L3 rather than an accepted-stream source. Candidate `/32` and `/128` plans cannot authorize local-bypass or geo-exit and cannot mutate default routes or external DNS/proxy/PAC/VPN. | Evaluate only a capture-only v2 boundary with per-flow reclassification and direct fallback. Keep DLL loading, adapter creation, routes, and production composition disabled. |
| 2026-07-18 | Native Windows TCP capture mechanism | Superseded shipping path; frozen research contracts remain | The WFP wire, runtime, and management-session contracts still document a safe connect-redirect lifecycle, but implementing it requires a separately signed Slipstream kernel driver. Do not build or package that driver. | Preserve v1 fixtures without composing them. Continue through the no-own-driver Wintun packet boundary. |
| 2026-07-17 | Python signed-policy activation adapter | Implemented with parity and effect-failure coverage | The daemon's verified candidate apply, health gate, persistence, rejection restore, startup load, and single-slot rollback now execute behind activation contract v1 under one lock. Current and previous policy files are updated as one compensating transaction; corrupt rollback slots, candidate-write failure, and runtime activation failure preserve the prior files and active manifest. Every consumed generation is written to an owner-only activation sidecar before candidate activation, so rejection followed by daemon restart cannot reuse it; successful policy files also retain backward-compatible generation metadata. Persisted signed provenance remains signed even when a legacy bundle contains the exact bundled manifest. A new signed envelope with the already-active canonical SHA-256 is intentionally the frozen v1 content-addressed `no_change` case and is not persisted. The old direct signed apply/save entry points are removed, while the remote URL remains opt-in and no production trust material is present. | Keep the Python adapter and reducer contract frozen under failure injection. Build the first no-network Windows adapter harness against `slipstream-core` before adding any platform networking effects. |
| 2026-07-17 | Cross-language signed policy activation | Implemented in shared Python/Rust contract v1 | The existing daemon temporarily applied a verified candidate, ran a health callback, then restored or persisted it through one imperative path. That path did not give future adapters a shared transition model or explicit stale-event guard. `route-policy-activation-v1.json` now binds trial start and rollback to the expected active SHA-256 and binds health to both the exact candidate SHA-256 and a reducer-issued monotonic trial generation. The generation persists after abort or rejection, so a delayed result cannot commit a later retry of identical policy content. Only one verified signed candidate may be in trial. A completed gate commits only with at least one success and no degraded or blocked checks; every rejection restores the stable active identity. One previous identity is retained per successful commit, rollback consumes it before falling back to bundled policy, and rollback during trial aborts only that candidate. The reducer emits ordered data-only actions and performs no fetch, signature verification, persistence, runtime apply, PF, DNS, proxy, PAC, VPN, or routing work. | Keep activation contract v1 frozen; the Python runtime migration is recorded in the adapter finding above. |
| 2026-07-16 | Cross-language signed policy canonicalization | Implemented in shared Python/Rust contract v1 | The former signature verifier lived only inside `tproxy.py`, so a future adapter could normalize the same manifest but sign different bytes, especially when `source` contained Unicode. `route-policy-bundle-v1.json` now freezes canonical hashes for ASCII, Unicode, quotes, backslashes, and controls, plus Ed25519 envelope success and structured failure vectors. Rust emits the same sorted compact JSON as Python `json.dumps(..., ensure_ascii=True)`, uses strict verification, and keeps v1 isolated. The pinned crypto graph remains compatible with the core's Rust 1.77 floor. The only committed key is an explicit deterministic fixture key. No production trust, fetch, apply, PF, DNS, proxy, PAC, VPN, or routing behavior changed. | Keep bundle contract v1 frozen. Define the pure signed-policy activation/rollback state transition next; runtime storage and transport remain adapter effects. |
| 2026-07-16 | Public status resurrection during daemon shutdown | Fixed with a deterministic concurrent regression | The first packaged lifecycle attempt in CI run `29523214490` cleared the private PF anchor but still observed `/var/run/slipstream.status`. `pf_teardown()` removed the file without coordinating with `network_monitor`; an in-flight `write_status()` could subsequently complete its atomic replace and recreate stale `active` state. Shutdown now sets a one-way event before cleanup and uses the same reentrant lock as status publication. Teardown removes both the final and temporary paths after any in-flight writer completes; later writers return without touching disk. No PF, DNS, proxy, PAC, VPN, or routing behavior changes. | Keep the concurrent regression in the daemon suite and the packaged lifecycle disappearance assertion required. Treat a surviving status file after daemon exit as a lifecycle defect, not proof that routing is still active. |
| 2026-07-16 | Route-policy manifest first-match validation | Implemented in shared Python/Rust contract v1 | The former validator required a Discord/YouTube group entry and the direct-first suffix strings somewhere in `static_routes`, but classification uses the first matching entry. An earlier generic entry could therefore shadow a later correct entry, including a narrower rule such as `updates.discord.com` before `discord.com`; a `geo_exit` entry placed in `static_routes` would also run before the Russian direct guard. The v1 validators now normalize bounded DNS hostnames, reject static-table geo exit and protected geo overlaps, and classify every bundled protected suffix plus every explicitly listed subdomain inside that family through the normalized table to prove its exact route, service group, and strategy. | Keep manifest contract v1 frozen and require every signed-bundle implementation to consume its normalized result. |
| 2026-07-15 | Bounded persistent route-circuit state | Implemented in shared Python/Rust contracts and the production handler | Injecting one persistent `local_engine` state into each address race would be incorrect: two failed strategies inside one request could open the circuit, and unrelated unknown hosts would suppress one another. Persistence therefore sits above the transport race. A full Discord/YouTube local ladder records one outcome; freshly proven Smart DNS and verified owned Geph record separate geo-exit backend outcomes. Owned Geph closes a half-open circuit on the first downstream payload delivered to the client rather than waiting for a long-lived WebSocket relay to end; zero-payload early close still reopens it. Unknown/direct traffic and external Geph stay one-shot. The registry keeps at most 256 non-default states for five idle minutes, uses deterministic LRU eviction, and fails open to the already-selected route if its own state becomes invalid. Eviction only forgets backend suppression. It cannot promote a host, change policy, or move protected local traffic to Geph. Shared vectors cover TTL, LRU, half-open concurrency, backend isolation, success reset, and protected-key rejection; handler contracts prove per-ladder accounting, long-lived half-open recovery, Smart DNS-to-owned-Geph same-route fallback, and unknown-host non-persistence. | Keep reducer and registry contract v1 frozen. Add any new backend or longer suppression window only with a traffic contract proving that it cannot broaden routing or strand transparent traffic. |
| 2026-07-15 | SafariDriver server startup denied on one hosted worker | Fixed; packaged qualification passed | The final docs-SHA run for PR #112 failed before Slipstream, PF, the daemon, tray, or Geph started because `/usr/bin/safaridriver` could not open the fixed `127.0.0.1:19445` server: `Unable to start the server: Operation not permitted`. Two earlier runs of the exact cleanup code passed on the same macOS 14.8.7 runner image, while the denial occurred on a different worker. `safaridriver(1)` defines immediate startup failure when the requested port is occupied or otherwise unavailable. The disposable-CI wrapper now asks the kernel for an available IPv4 loopback port, enables SafariDriver diagnostics, and permits one fresh-port retry only for the explicit server-start `EPERM` or address-in-use messages. Unknown startup failures remain fatal, and no retry can occur after the privileged lifecycle begins. The hardened wrapper then passed the full packaged lifecycle, including all Chrome and Safari stages, tray crash/restart, PF sentinel preservation, and uninstall. | Keep SafariDriver infrastructure failure distinct from routing failure. If the bounded fresh-port attempt also fails, preserve its diagnostics and fail the release gate rather than skipping Safari coverage. |
| 2026-07-15 | Script installer dependency closure after runtime adapter wiring | Fixed after CI caught the omission | The first PR run passed unit tests but its script-mode lifecycle daemon produced no StatusV2 because `_script_runtime_payload()` copied the older local module set and omitted `connection_probe.py` plus its address-race dependencies. Transactional install rolled back safely and left no daemon/PF log evidence. The payload manifest now includes the complete local dependency closure, and preflight tests remove each new module in turn to require failure before any partial install directory is created. The frozen packaged daemon resolves direct imports separately. | Keep script and frozen lifecycle jobs required whenever a new local runtime import is added; do not infer routing failure from a daemon that never reached module import completion. |
| 2026-07-15 | First-payload address race in the transparent handler | Implemented behind a policy-preserving wrapper | `spike/connection_probe.py` adapts the existing per-IP dialers to the owned connection-race I/O layer. Policy, route class, strategy, and backend are fixed before a race begins; a candidate succeeds only after the existing dialer receives first server bytes. The runtime handler now races resolved local addresses per strategy, app-owned Xbox DNS answers, and freshly proven Smart DNS answers. It does not race or reorder strategies, enter the Geph branch, or mutate system DNS. Fake handler tests prove that a stalled first Discord or Smart DNS edge is cancelled when a second edge returns payload, while Geph is forbidden. Cross-request circuit state now lives in the separate backend-outcome registry above, not inside this address adapter. | Keep connection-race contract v1 frozen. Qualify this exact packaged daemon on disposable CI; add daemon IPv6 dialers only in a separate evidence-backed change. |
| 2026-07-15 | Packaged lifecycle Chrome mixed-UID process-group `EPERM` | Fixed; repeated packaged qualification passed | An earlier PR #107 run and the first two packaged runs for PR #109 ended with a bare `[Errno 1] Operation not permitted` after the private anchor became active, while adjacent `main` runs were green. Stage and operation instrumentation reproduced the denial specifically at `killpg(chrome_pgid, SIGTERM)` after the expected DOM had already loaded; spawn, profile ownership, the daemon, and PF were not failing. Delegating the same group signal to the browser UID still failed intermittently. macOS `kill(2)` documents that signaling a process group returns `EPERM` when any member cannot be signaled, and a Chrome session may contain protected OS/XPC members. The harness therefore enumerates the exact PGID, selects only members with the original browser UID, and delegates those exact PIDs to an isolated helper that rechecks every PID's PGID immediately before signaling it. Different-UID members are never passed to the helper. Missing/reused PIDs are benign; permission denial and every other inspection/helper failure remain fatal. No retry or `EPERM` suppression was added. The exact code revision passed the full packaged lifecycle twice consecutively, including all four Chrome and Safari stages per run, tray crash/restart, PF sentinel preservation, and uninstall. | Preserve exact PID/PGID/UID checks; never replace this with broad process matching or alter routing/PF in response to a browser-cleanup denial. |
| 2026-07-15 | Safari cleanup identity after WebDriver session deletion | Fixed; repeated packaged qualification passed | A post-merge packaged run reached `before-tray-start:safari`, loaded the expected page, deleted its isolated WebDriver session, and then observed the exact Safari PID as `identity=(501, '(Safari)')`. macOS `ps` renders a zombie command in parentheses, so executable-path matching correctly rejected it as unowned but cleanup incorrectly treated the already-exited process as live. Safari inspection now reads UID, process state, and command together. Only a `Z*` state with the expected browser UID is considered stopped without a signal; live unexpected commands, different UIDs, and malformed identities remain fatal. The exact code revision passed the full packaged lifecycle twice, including Safari before tray start and after tray crash/restart. | Keep exact PID/UID/executable checks for live Safari. Never signal a zombie or relax identity matching based on a parenthesized command alone. |
| 2026-07-14 | Address racing and scoped circuit breaking | Scripted cross-language adapters implemented; Python loopback adapter added 2026-07-15 | A resolver result is an ordered set of expiring candidates, not one address. The planner interleaves the preferred and alternate families, bounds concurrent attempts under one deadline, and deterministically cancels losers. The new connection-race state machine gates a route circuit before resolver work, emits only resolver/start/cancel/wake commands, records one result for the whole logical request, and ignores late adapter completions. A deadline wake defers one deterministic turn when an attempt is still running, so an exact-deadline completion wins even if the timer was dequeued first; success after the deadline is rejected. Python and Rust execute the same fake resolver/socket vectors for stalls, resets, family fallback, deadlines, route isolation, half-open recovery, and Discord's no-Geph invariant. No reducer or scripted adapter performs network I/O or changes routing policy, PF, DNS, proxy, PAC, or VPN state. | Keep contract v1 frozen and define any production call site as a separate reviewed change. Never make a circuit opening imply Geph fallback. |
| 2026-07-14 | File-descriptor exhaustion and incomplete uninstall | Relay/FD fixes retained; uninstall ordering revised 2026-07-18 | The daemon log contained 2,115 `Too many open files` entries after roughly 8.5 hours, preceded by half-open relay tasks and repeated geo-exit closes. Direct, Telegram, Smart DNS, and Geph branches did not share the generic relay's first-completion lifecycle; failed async dials and restarted embedded Telegram loops also had incomplete cleanup. Once `accept()` reached `EMFILE`, the listener and private PF redirect remained present although the daemon could no longer serve traffic. All backends now use one bounded relay lifecycle, every opened async writer is closed and awaited on failure, replaced Telegram loops close their selector, and FD pressure releases an emergency reserve then pauses only `com.apple/slipstream` until the low watermark. The earlier user-Geph-first uninstall order was later proven disruptive and is superseded by the 2026-07-18 drain finding above. User DNS remained unchanged throughout diagnosis and cleanup. | Keep the FD and relay regressions. The disposable packaged soak must also prove the revised daemon-first quiesce/drain order and complete process/app removal. |
| 2026-07-13 | Real Safari restart qualification | Implemented; disposable CI required | The macOS runner includes matching Safari and SafariDriver builds. A guarded wrapper enables WebDriver only on disposable CI, starts the exact system driver as the original user on IPv4 loopback, and passes that endpoint explicitly to the privileged lifecycle harness. The WebDriver control connection is direct localhost and cannot inherit proxy settings. Every stage requires no pre-existing Safari process, creates a new isolated automation session, verifies the resulting browser PID by exact UID and executable path, requires the expected HTTPS page source over `h2` or `http/1.1`, deletes the session even after failure, and signals only that verified PID if Safari remains alive. HTTP/3 is rejected as insufficient TCP/PF evidence instead of being blocked. Normal Safari data and external DNS/proxy/PAC/VPN remain untouched. | Keep SafariDriver startup failure distinct from routing failure; add physical default-route/lid transitions and account-backed owned Geph on a disposable Mac. |
| 2026-07-13 | Real Chrome restart qualification | Implemented; disposable CI required | Start the runner's exact Google Chrome binary as the original user, including its real supplementary groups, with a new `0700` profile for each request before tray start and after tray crash/restart. Disable proxy use, background traffic, and QUIC only for that process so a successful DOM load proves a fresh browser TCP/443 path without changing system DNS/proxy/PAC/VPN or a real profile. Hosted macOS runners can emit the valid DOM and then keep helpers alive after repeated `com.apple.backupd.sandbox.xpc` errors, so the harness accepts only the expected page marker and then terminates its dedicated Chrome process group instead of waiting for unrelated runner XPC cleanup. | Keep the exact executable and owned process-group cleanup mandatory in CI; add physical route/lid transitions and account-backed owned Geph on a disposable Mac. |
| 2026-07-13 | Packaged tray-crash independence | Disposable CI implemented | Run the real packaged tray as the original user, kill only an exact UID/path-owned PID, and prove that fresh non-root HTTPS clients plus the same daemon/PF lifecycle survive tray crash and restart. Do not forward proxy or CI-secret environment into either child process. | Keep Chrome and Safari process qualification in this gate; add physical route/lid transitions and account-backed owned Geph on a disposable Mac. |
| 2026-07-13 | Installed wake/network lifecycle soak | Implemented; disposable CI required | The existing monitor already recovered from a cadence gap and default-interface change, but installed qualification only covered daemon restart. Script and packaged-daemon jobs now run two exact-PID cycles: an uncatchable process suspension crosses a CI-only six-second wake threshold through the production cadence detector (the production default remains 30 seconds), and a bounded diagnostic signal queues the same network-change helper used by interface detection. Every cycle requires a fresh StatusV2 recovery count, the original daemon PID, an active private anchor, and an unchanged sibling anchor, PF state, and live connection. The signal handler itself performs no PF or network work. | Keep workstation installation prohibited. Add physical default-route/lid-close and account-backed Geph soak on a sacrificial user session. |
| 2026-07-13 | Transparent lifecycle recurrence and respawning processes | Fixed in this PR; workstation install prohibited | ChatGPT/Codex recovered only after the root job was absent and disabled, the private anchor and token were gone, and no owned daemon or Geph process remained; user DNS was unchanged. `KeepAlive` explained process respawn, while the old installer could report success without verifying status/listener/PF and could leave a half-installed job. Installation is now transactional, failure disables and removes only owned state, startup/watchdog honor absent or disabled launchd state, missing status falls back to exact listener-PID ownership checks, and tray uninstall can use its bundled daemon when `/usr/local/slipstream` was already deleted. | Run packaged install/failure/reinstall/uninstall and PF-sentinel qualification on disposable CI only. Do not install or re-arm this branch on the primary workstation before that gate passes. |
| 2026-07-13 | False generic auto-Geph promotion | Fixed in this PR | `www.google.com` was recorded as a seven-day `geo_exit` after repeated local stalls and a successful Geph payload probe. That observation cannot distinguish IP geo-restriction from an incorrect local strategy, transient edge issue, or normal browser behavior. Generic stalls retain only the bounded exact-host Xbox DNS local retry; they never select or persist Geph. Legacy learned entries are discarded on daemon start. | Keep foreign-exit routes explicit and reviewed; treat a successful Geph payload only as tunnel health evidence. |
| 2026-07-13 | Google and Spotify direct-first local fallback | Fixed in this PR | Runtime strategy cache showed Spotify endpoints using cached `split64+fake` even though the service works natively. `google.com`, `spotify.com`, `spotifycdn.com`, and `scdn.co` now always try direct/plain TLS first, then may use only bounded local desync; Geph is excluded and a signed policy cannot silently omit those protected suffixes. YouTube/googlevideo remains independently local-bypass/fake-only. | Add another direct-first family only from observed native-success evidence; do not turn this into a broad allowlist. |
| 2026-07-13 | OpenAI billing synthetic canary | Fixed in this PR | `billing.openai.com` repeatedly closed a Geph SOCKS connection while `chatgpt.com`, `claude.ai`, and Steam Store passed through the same owned tunnel. The billing probe exercised an edge-specific anti-abuse/exit behavior rather than a dependable primary user flow, so it could falsely turn the whole geo-exit route into `Needs attention`. Billing stays geo-exit when a browser actually uses it, but is removed from canonical health canaries. | Keep health transitions tied to primary end-to-end flows; add a new secondary endpoint only with evidence that its synthetic probe predicts a real user-visible failure. |
| 2026-07-12 | Smart DNS capability path and Telegram proxy semantics | Backend ordering retained; PF pause superseded 2026-07-19 | A user-managed Xbox DNS route is eligible only after a fresh local payload proof, then may be the first geo backend with Geph fallback when owned Geph is ready. The earlier whole-anchor pause is no longer used when those optional backends are absent: the exact pre-PF destination gets a bounded plain probe while local bypass remains active. Raw Telegram DC passthrough is only non-interference; a network that blocks direct MTProto needs the bundled local proxy. | Keep Smart DNS proof and runtime fallback scoped to OpenAI/Anthropic; do not promote Telegram raw DC to a user-facing success state. |
| 2026-07-12 | Deterministic data-plane traffic contracts | Implemented | Routing regressions must cross the real `_handle_impl` with deterministic TLS, DNS, and upstream fixtures. Each named journey asserts its required backend, forbidden backend, and delivered response payload, so a passing isolated canary cannot hide a wrong decision or relay branch. | Add a contract before changing routing for any new incident class; keep PF/lifecycle and live endpoint qualification separate. |
| 2026-07-12 | Stale PF token after false daemon recovery | Fixed in this PR | The old StatusV2 reader could label a fresh V2 snapshot `off`, then recovery cleared the private anchor and released its PF token immediately after daemon boot. The daemon still held that token only in memory, so re-arm attempts stopped after a failed release and repeated `pf anchor vanished` every five seconds. When the token file is absent and PF is definitively disabled, clear only that stale memory reference and acquire a fresh private token. | Preserve the stale-token and enabled-PF fail-closed regression tests. |
| 2026-07-12 | Discord local-bypass canary false negative | Fixed in this PR | The local canary preflight used `build_fake_clienthello()`, an intentionally minimal TLS 1.2 `AES128-SHA` offer. `updates.discord.com` rejects that offer with a handshake-failure alert even while modern browser/curl traffic succeeds, so four Discord endpoint checks could falsely degrade the whole local-bypass route. The canary now starts directly with its existing modern `ssl.MemoryBIO` payload probe, applying the same local fake/desync to that real first flight; its bounded payload budget is eight seconds because the Discord gateway API consistently responded in about 5.18 seconds on the affected network. This never changes route class or uses Geph. | Preserve the no-synthetic-preflight regression; validate a packaged canary run with Discord and YouTube remaining local only. |
| 2026-07-12 | Partial local stream stall after clean client EOF | Fixed; preview and live-verified | A local TLS route can return an initial payload above the former 8 KiB success threshold and then stop. On the affected network, `crystalidea.com` returned HTTP 200 with 16,366 of 21,726 bytes before a 25 s client timeout. The clean-EOF reducer was correct but unreachable: `_handle_impl` used `asyncio.gather`, so after the client timed out it waited forever for a stalled server-to-client `splice`, never recording the exact-host outcome. The generic non-geo local relay now records which direction completed first and cancels the useless peer task; only two client-first EOFs after at least 15 s without downstream progress for the same unknown host in five minutes demote the exact strategy. The next retry makes an app-owned RFC 8484 Xbox DNS query and tries its answer locally with plain TLS. The current resolver and Xbox DNS both returned `173.230.144.164` for this host, so DNS is an exact local attempt, not a promise of an alternate edge. Preview.14 passed packaged lifecycle qualification; three subsequent installed-daemon requests retrieved the complete `crystalidea.com` payload (HTTP 200, 21,726 bytes) in about one second each. Server-first completion clears pending evidence. This path never selects or learns Geph. | Preserve the relay-direction, repeated-EOF, and protected-host regression tests; observe a future genuine partial stall before changing thresholds. |
| 2026-07-11 | Sidecar-only diagnostics | Fixed in this PR | A root daemon can be removed while the independent user Geph LaunchAgent remains. The user job does not by itself prove active transparent routing, but the previous diagnostic snapshot hid the distinction. | Preserve the bounded `summary.geph_lifecycle` signal; do not infer PF without privileged evidence. |
| 2026-07-14 | User Geph lifecycle teardown | Revised in this PR | Removing the root daemon manually leaves the independent user LaunchAgent alive by design. Confirmed uninstall must therefore stop and remove only the verified user-owned Geph state before the root prompt, then remove the exact validated app bundle after the tray exits. A root failure leaves the app available for retry but cannot leave bundled Geph running. | Preserve exact label/PID/executable/config/listener checks and packaged uninstall coverage; never replace them with broad process matching. |
| 2026-07-11 | Geo-exit early payload close | Original whole-anchor recovery superseded 2026-07-19 | Logs showed `chatgpt.com` returning `remote closed without response` after a successful Geph SOCKS connect. The original fix paused the private PF anchor for a native retry. Current behavior instead cools only Geph so Discord/YouTube local bypass remains available; because the consumed stream cannot be replayed, its next client retry may use the exact pre-PF system destination. | Keep the zero-byte early-close and system-destination regressions in the real handler contracts. |
| 2026-07-11 | Geph exit catalog fallback | Fixed | A cold tray launch could expose a hardcoded country-only menu before Geph's live city catalog or cache became available. The cache subsequently contained the correct city entries, but the temporary choices were misleading. | Keep the explicit unavailable state until cache/live data exists; the background refresh replaces it automatically. |
| 2026-07-11 | LaunchAgent ownership record rendering | Fixed in 0.1.6 follow-up | A literal patch marker in the generated shell continuation shifted printf arguments, leaving geph-owned.json invalid although launchd ran. The daemon correctly treats invalid ownership as unowned; it must never guess. | Regression-test the generated ownership write line and requalify a packaged app after launcher-template changes. |
| 2026-07-11 | Packaged-app installed lifecycle | Disposable CI passed | Build the real arm64 Tauri `.app`, install its embedded frozen daemon, and run cold install, same-artifact reinstall, active restart, and uninstall while preserving a non-root sentinel connection, its PF state, the sibling anchor, and the global PF snapshot. Upload only the qualified `.app`. Do not use `v0.1.4` as a rollback fixture because it predates the private-anchor safety fixes. | Make the first safety-qualified release the baseline for a later cross-version update/rollback gate. |
| 2026-07-11 | Live private anchor misread as legacy global PF | Global reload removed 2026-07-16; qualification pending | A forced restart can leave the owned child anchor populated for the next daemon. The former migration treated an exact-looking root listing as ownership evidence and could run `pfctl -f /etc/pf.conf`, replacing unrelated PF state. Root listings cannot prove ownership, so legacy-signature detection is now read-only. A conflict disables only the owned launchd label, clears only the private anchor/token, reports the condition, and exits. Its terminal status survives the live-status TTL in both daemon CLI and tray readers. | Keep the source-level no-global-PF contract and long-lived sentinel restart checks; require the full packaged lifecycle gate before merge. |
| 2026-07-11 | Script-mode installed lifecycle | Disposable CI passed | The dev installer omitted `primes.py`, so a source-installed LaunchDaemon could crash-loop before reaching routing. Copy the complete local Python payload, remove status/TGWS runtime artifacts on uninstall, and qualify cold install, reinstall, active restart, uninstall, sentinel rules, and a long-lived sentinel PF state on a disposable runner only. | Keep this destructive lifecycle smoke restricted to disposable CI. |
| 2026-07-11 | Anchor-scoped `pfctl -F all` | Fixed; disposable privileged smoke passed | macOS documents `-F all` as including the shared state table. An anchor argument scopes rulesets, but it does not make a global state flush acceptable. Flush only `rules` and `nat` in `com.apple/slipstream`; forbid `all` and `states` in daemon recovery, tray recovery, tests, and operator docs. | Keep the disposable sentinel smoke as a required CI gate; extend release qualification to installed restart/uninstall. |
| 2026-07-11 | OpenAI/Codex reconnect incident | Geph-up guard retained; PF dependency superseded 2026-07-19 | Cold-start Geph hysteresis reported `up` after a failed first probe while `_geph_port` was still `None`; PF had already captured all TCP/443, so `chatgpt.com`, `chat.openai.com`, and `ws.chatgpt.com` entered the geo-exit fail-close branch repeatedly. A verified port remains mandatory before reporting Geph `up`, but local PF arm no longer depends on Geph. Runtime failure cools only the verified owned backend and tray polling still cannot restart a live process from endpoint failures. | Keep the regression fixtures and CI sentinel; require packaged clean install to activate local routing without a Geph listener. |
| 2026-07-11 | Geo-exit payload probe shadowing | Fixed in M1 integration | The general canary `_geph_payload_probe` silently overwrote the bounded auto-geo confirmation probe of the same name. Use `_auto_geph_payload_probe` for temporary route learning and keep the general probe for health canaries. | Keep the targeted source-level duplicate-definition guard. |
| 2026-07-10 | Unified runtime recovery reducer | Implemented | Normalize local, geo-exit, and unknown-host evidence as `ConnectionOutcome`; a pure reducer may invalidate only the relevant strategy, re-sweep an exact local host, restart only verified owned Geph, recheck, or warn about external state. | Move owned Geph lifecycle into a user LaunchAgent and expose a privacy-bounded action summary in `StatusV2`. |
| 2026-07-10 | Competing transparent PF interceptors | Fixed and live-verified | An active HTTPS `rdr`/`route-to` before `com.apple/*` receives real app traffic first. Detect nested anchors, pause without mutation, and auto-rearm when clear instead of trusting internal canaries. | Keep a two-interceptor integration fixture and surface the exact paused reason. |
| 2026-07-10 | Global PF ruleset ownership | Fixed and live-verified | Slipstream now loads only `com.apple/slipstream` below the existing `com.apple/*` anchor point; global reload/disable is forbidden during normal lifecycle and recovery. | Keep the privileged sentinel cycle in release qualification. |
| 2026-07-10 | PF reference ownership | Fixed and live-verified | Store the token returned by `pfctl -E` in a root-only runtime file and release it with `pfctl -X`; never infer that Slipstream owns global PF state. | Preserve restart/uninstall/reinstall coverage. |
| 2026-07-10 | Bundled Geph listener ownership | Fixed and live-verified | PID, exact executable, config path, and `:9954` listener must match the private ownership record; unknown listeners fail closed immediately. | Preserve the unknown-listener integration gate. |
| 2026-07-10 | External Geph coexistence | Fixed and live-verified | `:9909` is detected for diagnostics only and is never adopted or stopped without explicit port opt-in. | Preserve this constraint when Geph moves to a user LaunchAgent. |
| 2026-07-10 | Geph secret permissions | Fixed and live-verified | Config directory is `0700`; secret-bearing files and runtime ownership state are atomically written as `0600`, including migration of existing files. | Move the account secret to Keychain in a later hardening PR. |
| 2026-07-10 | PyInstaller spec working directory | Fixed in M0 | Resolve daemon, policy keys, and vendored Telegram proxy from `SPECPATH`; invoking PyInstaller from the repo root must not silently omit `proxy.*`. | Keep the path-stability assertion and frozen Telegram readiness smoke test. |
| 2026-07-18 | Codebase graph MCP transport | Workaround active; repeated during Wintun collector work | Fresh-clone indexing and the later project-list request both returned `Transport closed`; discovery used the audited source plus narrow searches rather than assuming the graph was current. | Repair or restart the MCP transport before relying on graph freshness; keep the documented narrow-search fallback. |
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
| 2026-07-08 | `xbox-dns.ru` external DNS | Active | User-managed resolver settings remain external state that Slipstream never enables or rewrites. Separately, the daemon may make a direct, verified DoH query for one failed generic hostname. | Keep the direct backend exact-host, local-only, and independent from system resolver settings. |
| 2026-07-09 | Darkware Zapret UI | Reference only | Borrow the compact MenuBarExtra-style status layout, not its manual strategy workflow. | Redesign tray diagnostics as short status rows with details behind a button. |
| 2026-07-09 | Darkware Zapret system mutations | Rejected | Do not copy system SOCKS proxy toggles or broad sudoers `NOPASSWD` service control. | Keep Slipstream-owned state scoped to its daemon, pf rules, and status files. |
| 2026-07-09 | Darkware Zapret bruteforce probe | Backlog | Headless re-sweep can borrow the temporary-proxy probing idea without exposing a picker. | Consider only for autonomous local-bypass recovery. |
| 2026-07-09 | Context Mode | Agent tooling | Installed for Codex session context hygiene; not a Slipstream runtime dependency. | Keep out of project code and docs except this research note. |
| 2026-07-09 | Superpowers | Agent tooling | Installed as a general Codex workflow aid; not a Slipstream runtime dependency. | Use opportunistically after session reload exposes its skills. |
| 2026-07-12 | Graphify | Agent tooling | Audited and installed as a local AST graph CLI. Use its explicit user-local binary for scoped symbol explanations; do not run its Codex installer because it appends a broad `PreToolUse` hook to `AGENTS.md`/`.codex/hooks.json`. Existing codebase-memory MCP remains the primary code-discovery tool. | Reuse only for exact-symbol graphs when it adds signal; do not make it a runtime dependency or mutate repository agent hooks. |
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
| 2026-07-09 | Lid-close wake recovery | Revised 2026-07-11 | Adrafinil keeps idle sleep away but does not prevent macOS lid-close SleepService/DarkWake cycles. Repeated post-wake failures remain diagnostic evidence; tray polling must not restart a live Geph process because it can tear down streaming sessions. | Move lifecycle ownership into the daemon before adding coordinated restart of a live backend. |
| 2026-07-09 | Stale proxy exceptions | Implemented | External proxy tools can leave disabled `ExceptionsList` entries after proxy autoconfigure is turned off; Slipstream reports them in status without treating the proxy as active or mutating settings. | Use diagnostics to explain stale browser/network behavior; do not auto-delete user-owned proxy state. |
| 2026-07-09 | Runtime re-arm visibility | Implemented | Daemon status now records the last wake/network re-arm reason, interface, gap, count, and age so sleep-related recovery is visible without reading logs first. | Keep using logs for full `pmset` correlation; status is a compact runtime snapshot. |
| 2026-07-10 | Auto geo-exit stale learned hosts | Superseded 2026-07-13 | The old runtime reset avoided some bad learned routes, but the learning premise was still unsound: a working Geph payload does not prove geo-restriction. | Unknown hosts no longer learn Geo-exit; retain only exact local recovery. |
| 2026-07-10 | Wake canary recovery rerun | Implemented | Forced canary triggers that arrive during an in-flight wake check are queued for a short rerun instead of being dropped by the force cooldown. | Keep wake recovery event-driven; do not lengthen normal canary cadence. |
| 2026-07-10 | Exact-host local-bypass re-sweep | Implemented | A real Discord/YouTube runtime miss starts a deduplicated background strategy sweep for that exact host and clears its negative cache only after a fake/desync strategy succeeds. | Tune cooldowns only from observed runtime evidence. |
| 2026-07-10 | Geph-down log semantics | Superseded 2026-07-11 | A proxied geo-exit attempt still never falls through local desync, but persistent fail-close under an active global redirect was unsafe. Backend loss now pauses only the private PF anchor and leaves native networking in control. | Keep runtime messages aligned with dormant/active PF state. |

## Windows Packet Capture Selection (2026-07-18)

### Why Slipstream will not own a kernel driver

Microsoft requires a driver submission to be certificate-signed and requires
an EV certificate associated with the Hardware Dev Center account for
attestation or WHCP submission. The alternative development path enables
Windows test-signing mode, may require disabling Secure Boot, and is not an
acceptable user installation model:

- [Driver code signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
- [Loading test-signed drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)

Slipstream therefore will not build, distribute, or seek production signing
for its own WFP callout. The already-frozen `windows-wfp-*` fixtures remain
useful records of safe stream-redirection ownership and teardown, but they are
dormant research contracts rather than the Windows shipping architecture.
This removes the kernel-driver certificate blocker; optional signing and
reputation for the userspace application remain a separate release concern.

### Selected primitive: official Wintun

[Wintun](https://www.wintun.net/) publishes precompiled, signed DLLs that may
be distributed unchanged with software. Version 0.14.1 includes AMD64 and
ARM64 builds and exposes an L3 adapter for userspace IPv4/IPv6 packet handling.
It is a local adapter API, not the WireGuard network protocol: this choice adds
no WireGuard tunnel, peer, endpoint, or wire traffic.
It therefore avoids a Slipstream-owned driver certificate, but it is not a
drop-in replacement for the old WFP stream boundary: Wintun supplies packets,
not an accepted TCP socket or original-destination context.

`vendor/wintun/SOURCE.json` pins the official archive URL, archive and license
hashes, publisher and signing-certificate identity, plus the exact AMD64 and
ARM64 DLL sizes, SHA-256 hashes, and PE machine values. The official archive is
`750540` bytes with SHA-256
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.
Its architecture DLLs are not committed to this repository.

Static inspection of both PE certificate tables produced the same WireGuard
LLC signer-certificate SHA-256,
`c9e1b3127c2f1312056d49a93ac4bd700393fd323d2bf3b2235aff52bea8d136`.
The disposable Windows 11 ARM64 VM also exposed the embedded PKCS#7 signer and
DigiCert timestamp chain with `certutil` without loading the DLL. This is
provenance evidence, not a substitute for the next native `WinVerifyTrust`
qualification; an expired leaf can remain valid only when Windows accepts its
trusted timestamp.

`contracts/windows-packet-adapter-v1.json` and pure Rust
`packet_adapter::v1` currently do only three things:

- admit caller-provided artifact evidence when every pinned package, DLL,
  architecture, Authenticode publisher, signer, and timestamp field matches;
- prepare a non-authorizing candidate only when fresh resolver evidence binds
  the canonical policy host to an observed public exact `/32` or `/128`
  destination whose active classification is `local_bypass` or `geo_exit`;
- reject that candidate unless opaque, complete, generation-bound evidence for
  the destination contains only canonical hosts with the same active route
  class and strategy.

IPv6 admission is frozen against the
[IANA IPv6 Global Unicast Address Space](https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml)
snapshot dated 2025-10-10. IANA states that unlisted space within `2000::/3`
is reserved; the contract therefore uses the allocated-prefix list rather than
treating the whole assignable block as globally routable. Special-purpose
exceptions also follow the
[IANA IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml).

No current code downloads or loads `wintun.dll`, creates an adapter, installs a
route, handles a packet, changes the default route, or composes network effects
into the production Windows service. External DNS, proxy, PAC, and VPN state
remain read-only.

### Native artifact collector

The Windows collector opens the already-staged archive, license, and DLL with
`FILE_FLAG_OPEN_REPARSE_POINT` and read-only sharing, verifies each final path,
and hashes each exact handle. It parses only the bounded DOS and PE headers for
the machine value. The DLL stays open while its same handle is supplied through
`WINTRUST_FILE_INFO.hFile` to
[`WinVerifyTrust`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust),
which prevents a path replacement between hashing and signature validation.

The Authenticode operation uses no UI and
`WTD_CACHE_ONLY_URL_RETRIEVAL`; it does not perform hidden online revocation
lookups. A result is valid only when Windows returns exact success, the leaf
certificate organization is `WireGuard LLC`, its SHA-256 matches the pinned
certificate, and the provider exposes a successful timestamp countersigner.
Every verification state is closed through `WTD_STATEACTION_CLOSE`. Microsoft
documents both the optional held handle in
[`WINTRUST_FILE_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info)
and the required verify/close lifecycle in
[`WINTRUST_DATA`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data).

The returned native admission is non-cloneable and retains the read-only DLL
handle. No loader exists in this change. CI first verifies the official archive
length and SHA-256 before extraction, then asks the collector to admit both the
AMD64 and ARM64 DLLs and reject a changed copy. Adapter creation, exact-route
ownership, packet processing, and production composition remain absent.

### Shared-destination conflict admission

A system exact route is wider than the hostname that motivated it. The same
CDN address can concurrently serve Discord, OpenAI, Google, or an unrelated
direct destination, so one successful DNS answer cannot authorize capture.
The pure conflict gate accepts only an opaque snapshot claiming a complete
owned resolution boundary for that exact address. A partial observation fails
closed. The snapshot is limited to 256 canonical policy hostnames, must be
strictly sorted and unique, must contain the candidate host, and may live for no
more than 30 seconds. Every host is reclassified against the active policy and
must select the same route class and strategy set.

The resulting admission carries the collector generation and expires at the
earlier route or conflict-evidence deadline. It is intentionally not native
authorization.

A later feasibility review rejected the planned native issuer. System DNS is
not a complete observation boundary: Windows supports
[encrypted DNS](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-encryption-dns-over-https),
applications may own their resolver path, and a suffix policy represents an
unbounded set of concrete hostnames.
[Wintun](https://git.zx2c4.com/wintun/about/) exposes L3 packets rather than an
accepted stream with trusted hostname or original-destination context.
Advancing a generation whenever the *observed* cache changes would therefore
measure cache freshness, not shared-destination completeness.

Packet-adapter v1 remains frozen with no route effect. Any successor must use
exact routes only as a capture mechanism and reclassify each flow from bounded
in-band evidence. A flow with missing, encrypted, or otherwise ambiguous
hostname evidence must remain direct passthrough. That design must also prove
that Slipstream's outbound sockets cannot re-enter its own adapter, that route
activation does not strand pre-existing flows, that capture expires and is
removed promptly, and that an external VPN remains unmodified and usable.
Windows exposes explicit per-socket interface selection such as
[`IP_UNICAST_IF`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options),
but the v2 feasibility gate must prove the complete IPv4/IPv6 behavior rather
than assume that one socket option solves loop avoidance.

### Remaining safety gates

An exact IP route is still broader than a hostname because CDN destinations
can be shared. A candidate plan is therefore not sufficient authorization for
a route-table mutation. Native work remains ordered as follows:

1. Completed: collect artifact evidence through read-only Windows APIs and
   qualify the official package plus tamper rejection on disposable AMD64 and
   ARM64 Windows without loading the DLL or creating an adapter.
2. Freeze packet-route v1 and specify a capture-only v2 contract. Backend
   authorization must come from bounded per-flow evidence; missing or opaque
   hostname evidence stays direct.
3. Before loading a DLL or changing a route, prove outbound loop avoidance,
   activation safety for existing flows, bounded capture expiry/removal, and
   explicit coexistence with an already-active external VPN on disposable
   Windows.
4. Only if that feasibility gate passes, define owned adapter and exact-route
   transactions with crash-safe rollback, then select and bound a userspace
   IPv4/IPv6 and TCP/UDP stack. Prove that direct,
   local-bypass, and geo-exit packet flows retain the shared policy invariants;
   Discord and YouTube must never acquire a Geph edge.
5. Qualify crash, reboot, sleep/wake, update, uninstall, route churn, and
   external DNS/proxy/PAC/VPN coexistence on disposable AMD64 and ARM64 hosts.
6. Compose the adapter into the production service only after every earlier
   gate passes and teardown leaves no adapter, route, process, or durable
   ownership residue.

WinDivert remains unsuitable for the current ARM64 gate and would also require
packet reinjection/NAT ownership. System proxy/PAC would mutate user settings.
Npcap, ETW, and pktmon are observation tools rather than a controlled routing
primitive. None is a production fallback for a failed Wintun qualification.

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
- Observed again on 2026-07-13: indexing the fresh daemon-recovery worktree
  timed out after 300 seconds, and the following graph search also stalled.
  The CLI `list_projects` path remained healthy. Discovery continued from the
  current `main` graph plus narrow `rtk` source searches. Re-index after the MCP
  process or Codex session is restarted.
- Observed again on 2026-07-18 while indexing the clean Windows-controller
  clone: the MCP transport returned `Transport closed`. The controller audit
  continued from exact `main` source and narrow symbol/string searches; no stale
  graph result was treated as current evidence. A later `list_projects` call in
  the Wintun continuation failed with the same transport error, so that work
  retained the same fallback rather than assuming the graph had recovered.

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
  stall exposed that an exact host can be incorrectly learned as geo-exit.
  This remediation was superseded on 2026-07-13: generic hosts no longer learn
  Geph at all, so the failure class cannot recur from a stale auto-Geph entry.
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
  code. If users configure it at the OS/router level, Slipstream treats that
  setting like other external DNS state: report it in diagnostics if relevant,
  but never enable, replace, or restore it automatically. This does not preclude
  Slipstream's separate exact-host DoH fallback, which does not read or modify
  the user's resolver configuration.

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

## Unknown-Host Local Recovery

- Generic local stalls never learn `geo_exit`: a foreign tunnel working for a
  host is not evidence that the host rejects Russian IPs.
- An unknown host may receive one exact, local retry through a Slipstream-issued
  Xbox DNS query. This does not inspect or alter the system resolver and does not
  select Geph.
- Legacy `/var/run/slipstream-autogeph.json` entries are discarded on daemon
  start. The compatibility status field remains disabled for one transition
  release so older tray clients can read it safely.
- Google and Spotify families that are known to work natively use explicit
  `direct_first` policy: plain TLS is always first, bounded local desync is the
  only fallback, and Geph is excluded. Discord and YouTube/googlevideo remain
  independent `local_bypass` routes.
- YouTube web-shell probing is warning-only; the hard YouTube health signal is
  the `youtube_video`/googlevideo path because browsers can reach the web shell
  through IPv6/QUIC while daemon-side IPv4/TCP probes are noisy.
- New foreign-exit routes require explicit, reviewed policy evidence. Static
  policy is preferred when a service class is well understood and has multiple
  endpoint families.

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

## Daemon-Owned Geph Recovery

- The recovery reducer already produced `restart_owned_geph` after repeated
  post-wake failures across multiple geo-exit hosts, but the action previously
  stopped at a status hint. A running tray was still required to perform any
  live-process restart.
- The Geph launcher now records its numeric user ID together with PID,
  executable, config, and LaunchAgent label. The daemon accepts the claim only
  when that ID also owns the claim file and the current listener still matches
  the recorded process identity.
- Recovery pauses only `com.apple/slipstream`, waits for the aggregate active
  Geph-session count to reach zero, and calls `launchctl kickstart -k` for the
  exact `gui/<uid>/dev.slipstream.geph` target. LaunchAgent `KeepAlive` continues
  to handle ordinary process death.
- A busy tunnel defers the action. A missing or mismatched claim, unknown
  listener, external Geph, or unexpected label produces no signal and no PF,
  DNS, proxy, PAC, or VPN mutation.

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

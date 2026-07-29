# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

Last exact-main evidence audit: 2026-07-30, through product merge
`7f265549d727db93b8c0a7861808cc5f59784527` (PR #273). Exact-main native
AMD64/ARM64 run `30497886810`, CI `30497886818`, and audit `30497886814`
passed on that SHA. Native jobs `90730822239` and `90730822057` proved
disposable same-name Windows service-generation recovery: generation 1 and
generation 2 used the same exact owned SCM name and runtime root but
byte-distinct payloads. Generation 2 started only after generation 1 proved
SCM, installed payload, and durable lifecycle records absent; an independent
sentinel survived both cycles. CI jobs `90730821810`, `90730821828`, and
`90730821876` repeated the full Windows contract, packaged macOS lifecycle,
and common checks.

The first reviewed PR head was correctly rejected on both native architectures:
the exact-absence helper matched the struct-like
`WindowsServiceObservation::Absent` as a unit variant. PR #273 changed the
helper to compare against the canonical `WindowsServiceObservation::absent()`
value and then passed both native architectures without reruns. The gate did
not compose production networking or mutate routes, DNS, proxy/PAC/VPN,
drivers, or external services.

Previous exact-main evidence audit: 2026-07-30, through product merge
`3a26653a2b221d757834cdb8ceb53f95c4589906` (PR #271). Exact-main native
AMD64/ARM64 run `30494843668`, CI `30494843656`, and audit `30494843671`
passed on that SHA. The merge freezes a disposable same-name Wintun
capture-generation contract: generation 1 must remove its exact route,
address, session, and adapter before generation 2 may reuse that owned name,
while the pre-existing system route remains identical before, between, and
after both cycles. The native run proved this on both architectures together
with the earlier route-churn, independent VPN-like owner, packet handoff, and
exact-cleanup gates. CI repeated the complete Windows contract suite and the
packaged macOS lifecycle. The gate did not reinstall the driver, mutate default
routes, DNS, proxy/PAC/VPN, or external network owners, and did not compose
production Windows networking.

The first PR attempt exposed a fixture defect before product evidence was
accepted: `WindowsOwnedRouteTransitionIssuer::new` received the fixed route
epoch where it expected the capture generation, so the generation-2 proof
failed with `capture-generation issuer changed its generation`. PR #271
corrected the argument order and added a static regression for the exact
constructor call. The final PR head and exact-main AMD64/ARM64 jobs passed
without reruns.

The next M4 work is the remaining disposable Windows resilience
qualification: reboot, sleep/wake, update, uninstall, and broader external
network-tool coexistence, plus any crash scenarios not already covered by the
current child-termination gates.
Each gate must prove exact cleanup and preserve independently owned network
state before production service-host composition can begin. That later
composition must reuse the frozen capture, flow-binding, byte-owner,
selected-stack, connector, and Wintun ownership contracts rather than bypassing
them, remain disabled by default, and prove exact compensation before any
user-facing Windows preview is allowed.

Protected owned-Geph run `30429690683` was dispatched exactly once for previous
main `3b9075d8b63e12e9ce93b2a3ac973005f3d43c13`. Packaged resources, the
daemon-free boundary, owned-Geph initial, trayless, and KeepAlive-recovered
payload, and final cleanup all passed. Every
payload phase returned HTTP 200 over TLS 1.3 with `67973` bytes, and system
network state was not mutated. The second Chromium scenario timed out after one
root request with no reload or subresource request, so no qualified artifact
was published and no workstation installation was attempted.

The failure was in the disposable incomplete-response fixture, not Geph or
product routing. Its HTTP/1.1 handler advertised `Connection: close` and a
larger `Content-Length`, but `BaseHTTPRequestHandler` does not infer
`close_connection` from response headers. A keep-alive client therefore waited
on an open socket instead of receiving EOF and emitting the expected
incomplete-response event. PR #258 now closes the handler connection explicitly
and freezes the real TLS/HTTP regression. The next authorized protected action
is one run after the next UTC-day account reset. Installation remains
prohibited until that run passes both Chromium scenarios and publishes its
exact artifact.

Earlier protected run `30397332251` exposed a coordination defect rather than a
routing regression. The owned-Geph producer published `ready`, then a late
broker abort made it clean user resources while the Chromium consumer still
owned the root daemon and native-host manifest. This produced secondary
boundary and missing-manifest errors. PR #252 now retains a late abort until
the consumer publishes the exact private `release`, then reports the original
fail-closed reason and begins producer cleanup. Its PR gates passed, and
exact-main CI `30399287525` plus audit `30399287465` passed for
`c9d3117fe2ab37946522ddcd16cddb64efe4b55d`.

After the UTC-day reset, protected run `30411915972` was dispatched exactly once
on docs checkpoint main `bebb6776b554a01a7885b889d6d98c2a405d570c`.
Packaged-resource and daemon-free boundaries passed. Owned Geph returned the
same complete Steam payload initially, without the tray, and after KeepAlive
recovery: HTTP 200, TLS 1.3, and `68103` bytes in each phase. The frozen
regional-denial browser scenario completed before the harness entered
`incomplete_response`.

The second scenario made one root request and no reload or subresource request.
Chrome's documented `webRequest.onErrorOccurred` details omit `method` and
`parentFrameId`, while the v2 builder required both fields directly on that
final event. Synthetic unit tests had supplied an impossible event shape, so
the real event was silently rejected before native messaging. The exact
correction correlates a browser-owned top-level GET from `onBeforeRequest` to
the final event by opaque request ID, tab, and normalized hostname, using only
ephemeral `storage.session` state without path or query. The always-run cleanup
passed, system network state was not mutated, no artifact was published, and no
workstation install was attempted.

PR #254 merged that evidence-scoped browser correction plus redirect-safe
candidate cleanup as `45db4321bafe244c87986c4c08daf1c3afaf8bf2`, and both
its PR gates and exact-main gates passed. Protected run `30411915972` already
used the current UTC-day account-backed cycle before exposing the corrected
defect. Repeating the finite upstream authentication path before the next UTC
reset would be a prohibited hot-loop. The next authorized action is therefore
exactly one protected run after that reset for the then-current live `main`,
after verifying that it contains product merge
`45db4321bafe244c87986c4c08daf1c3afaf8bf2` and has green exact-main CI/audit.
No workstation install is authorized until the full run proves owned-Geph
payload, both Chromium semantic scenarios, exact cleanup, and publishes its
exact qualified artifact.

The full local suite passed with `840` Python tests and `32` subtests before
PR #248 merged. Exact-main CI run `30378302132` and audit run `30378302209`
passed. The one protected run `30379005119` then passed on the exact main SHA:
real owned-Geph Steam payload completed initially, without the tray, and after
LaunchAgent recovery; sandboxed Chromium produced one semantic callback and
one reload with complete CSS, JavaScript, image, and styled-DOM evidence; final
cleanup removed every owned user and system component without changing system
network state.

Protected artifact `8696275919`,
`Slipstream-owned-geph-qualified-8436ddfcfda6d3657912ec05674fb16ad17750d3`,
matched GitHub SHA-256
`d1929ddfc190450bc390026fc4af73bfc71b0510de110b288a363b6e42d0c1ec`.
Its inner app archive matched SHA-256
`fc6b974d544b43ee8335251a5fdf3ecec30a8171a9d9d9a400438260ae22f6bf`.

A controlled workstation transaction installed that exact app after preserving
the previous app, user runtime, LaunchAgent, owned-Geph identity, and external
network state. The installed root daemon matched the bundle SHA-256, StatusV2
was active with all ten canaries healthy, and DNS `111.88.96.50/51`, proxy/PAC,
default route, global PF rules, and the existing owned-Geph PID/hash remained
unchanged. Discord updater returned HTTP 200 with payload; Discord gateway
completed TLS/HTTP; YouTube control returned a 1.33 MB page and `yt-dlp`
downloaded a real Googlevideo media fragment; ChatGPT returned HTTP; and
CrystalIDEA, Modrinth, and Weather returned complete payloads.

The first `xpersonatoy.com` request nevertheless ended with curl error 18,
`Transferred a partial file`. The transaction immediately rolled back. A
post-rollback direct request reproduced the underlying network failure more
severely: it timed out after 35 seconds with only 13,672 bytes. This proves the
host needs alternate-route recovery. Once response bytes have reached the
client, however, the encrypted request cannot be assumed replay-safe and the
same connection cannot be moved to another backend. The runtime may retain this
evidence only for a subsequent client connection; a browser companion may
request one bounded reload only through an explicit replay-safe signal.

Main contains additive semantic-signal v2 without a hostname rule or a frozen
v1 change. Protected run `30393151116` showed that
`webNavigation.onErrorOccurred` did not expose the fixture's post-commit body
truncation. PR #251 replaced the Chromium and macOS Safari event sources with
read-only `webRequest.onErrorOccurred`,
scoped to HTTPS `main_frame` GET requests with frame ID `0` and no parent. The
same two exact incomplete-response error values, fixed v2 payload, owned-Geph
complete HTTP proof, static-policy precedence, Discord/YouTube exclusion, and
one same-host reload remain unchanged. The harness now identifies the failing
scenario and its bounded request counters. Local, PR, and exact-main gates
passed. The upstream broker rate limit blocked its sole account-backed
protected run before the two browser scenarios could qualify, so no exact
artifact was published or installed.

Rollback removed and disabled the exact root daemon, removed its plist,
listener, runtime, token, status, socket, attestation, and witness, and emptied
only `com.apple/slipstream`. The previous app was restored at SHA-256
`3931c16e158a223c0cdcb533bf77698e89e5df3f80015ead153dace86ff2a710`
and relaunched without reinstalling the daemon. Owned Geph remains PID `52893`
with its previous hash. DNS, proxy/PAC, default route, global PF rules, and
external anchors match the preflight snapshot. The next product gap is generic
incomplete-response evidence that advances a subsequent connection, plus an
explicit replay-safe companion path where available. No host-specific rule is
authorized by this evidence.

The following paragraphs retain earlier transaction history.

The single protected run `30318687293` then passed on that exact main SHA. It
proved account-backed owned-Geph initial, trayless, and recovered HTTPS payload;
sandboxed Chrome for Testing in the console user's Aqua session; one semantic
signal, one reload, CSS, JavaScript, image, styled DOM, and browser-ready
callback; and complete final cleanup. The run left no root daemon, private PF
state, token, loopback lease, status, semantic socket, learned route, Chrome
profile, native-host manifest, owned-Geph process or LaunchAgent, Keychain item,
or app runtime. System network state was unchanged.

Artifact `8673106618`,
`Slipstream-packaged-lifecycle-dde722435887154632dc4a0d9ba69ec9fc1f9f17`,
was downloaded by exact artifact ID and matched GitHub's SHA-256
`1cee7cbd6c825e133522b9fbe2d56e9b60c13aefc5c6ecd30299b4037497e347`.
A controlled workstation preflight found the earlier `0.1.9` app, root daemon,
and owned-Geph LaunchAgent already active. It preserved the existing app before
staging the qualified bundle and confirmed user DNS `111.88.96.50/51`, proxy
and PAC off, no active VPN default route, and healthy StatusV2. The first
bounded prompt expired while the user was away and performed no privileged
mutation. Two later user-present attempts exposed defects in the temporary
workstation transaction rather than a protected-gate or product-route failure.
The first privileged attempt had not copied the previous bundled daemon into
its rollback snapshot. It removed the newly installed daemon and restored the
old app, but could not reinstall the previous root daemon. The second attempt
started from that safe daemon-free baseline and installed the exact qualified
daemon, but the unprivileged coordinator tried to hash its deliberately
unreadable installed binary and received `Permission denied`.

The second attempt immediately requested rollback. The privileged transaction
uninstalled the new daemon, cleared only `com.apple/slipstream`, disabled the
exact launchd label, removed the plist, token, status, socket, and root runtime,
restored and relaunched the previous app exactly, and published
`root-rolled-back`. There was no rollback-failed marker. User DNS remained
`111.88.96.50/51`, proxy/PAC remained off, the existing owned-Geph PID and hash
were unchanged, and the restored tray executable matched the previous SHA-256.
Post-rollback direct probes received HTTP from ChatGPT and CrystalIDEA; Discord
timed out directly, as expected without Slipstream local bypass. The qualified
app is not installed, no root daemon or private PF runtime remains, and no
further workstation retry is permitted until privileged artifact attestation is
performed inside a disposable privileged transaction.

The current root-attestation change moves installed-daemon hashing and identity
verification into the privileged installer. It atomically publishes a bounded,
root-owned evidence record only after the installed path, SHA-256, owner, mode,
launchd PID, exclusive listener, fresh StatusV2 state, and private-PF state
agree. The tray validates that record against its bundled daemon without
opening the root-owned installed binary. Injected attestation failure enters
the same exact uninstall path and must leave a daemon-free baseline. This
change is not qualified until its pull-request packaged lifecycle and
exact-main gates pass; it has not been installed on the primary workstation.
PR #245 CI run
`30349298867` rejected the first implementation because mode `0700` also
prevented the intentionally console-user baseline child from traversing and
executing the frozen daemon. Both lifecycle jobs kept PF dormant and the
workstation was untouched. Follow-up run `30350707555` rejected execute-only
mode `0711` because the PyInstaller bootloader reads its own executable while
starting. It also kept PF dormant and touched no workstation. The current
follow-up restores root-only `0700/0600` installed identities and moves
console-user DNS and HTTPS qualification to fixed macOS `dscacheutil` and
`curl` children, so baseline health no longer depends on executing or reading
the installed daemon. Run `30352115171` proved those fixed children and the
before/after-PF HTTPS baseline in both lifecycle jobs, but rejected the
attestation harness after a legitimate `dormant` to `active` transition: the
root evidence retained its coherent time-of-install `dormant` snapshot while
the later lifecycle assertion incorrectly required it to equal the current
`active` status. Both jobs completed exact cleanup and the workstation remained
untouched. The current patch retries only an incoherent transition snapshot and
checks later daemon/PF state independently from the immutable install evidence.
That follow-up passed all PR jobs in CI run `30353331745` and dependency audit
run `30353331739`, including successful privileged commit, daemon-free injected
rollback, browser restarts, tray crash/restart, two wake/network-change cycles,
and exact sentinel/global-PF preservation. Merge then remained correctly
blocked by two unresolved review findings: reboot would erase evidence stored
under `/var/run`, and stale evidence could outlive a manually removed installed
runtime. The current review follow-up moves schema-v2 evidence to persistent
root-owned system Application Support and creates a sibling root-only hard-link
witness for the installed inode. The tray validates its exact device, inode,
mode, owner, and minimum link count without reading daemon bytes; removal or
replacement of the installed path therefore forces reinstall. This follow-up
must repeat the full PR gates before review resolution or merge. No workstation
component has been launched or changed.

PR #245 subsequently merged and all exact-main/protected gates listed above
passed. A bounded workstation transaction then preserved the previous app and
owned Geph, installed and attested the exact qualified daemon, reached fresh
active StatusV2, and proved private-PF commit without changing global PF owners,
DNS `111.88.96.50/51`, proxy, PAC, or VPN state. Discord gateway/updater,
YouTube control and real media, ChatGPT transport, and CrystalIDEA returned
payload.

The first generic unknown-host smoke, Modrinth, timed out during TLS. Root-log
evidence showed `geo-exit backend unavailable` at `17:31:20` and the exact
owned SOCKS backend up again at `17:31:23`. Complete exact-host evidence and
current backend readiness were conflated: the request could not survive that
transition, and the previous 30-second backend hold could still reject page
resources after an independent exact-host payload proof. No host rule was
added.

The transaction immediately performed exact rollback on that first failure.
The root daemon, launchd service, plist, private PF state, token, status, socket,
attestation, witness, and installed root runtime are absent; the service label
is disabled. The previous `0.1.9` app executable is restored at SHA-256
`3931c16e158a223c0cdcb533bf77698e89e5df3f80015ead153dace86ff2a710`.
The pre-existing owned-Geph LaunchAgent remains running as PID `52893`. Current
DNS is still `111.88.96.50/51`, and proxy/PAC remain off. No root daemon or
qualified new tray is running.

PR #246 implemented the generic re-admission correction. Only an
unknown host with the already-complete frozen local proof may wait up to five
seconds for a transient exact-owned `:9954` recovery. It actively probes that
owner-exact backend rather than depending on the five-second network monitor,
and rechecks listener conflicts throughout the wait. Its replay-safe request
may perform a bounded payload qualification during an older global hold; a
successful real payload clears that hold for following page resources. The
request also survives a concurrent background confirmation. Ordinary timeout,
missing or expired proof, protected/direct/static policy, external Geph,
listener conflict, failed payload, and network-wide failure remain
non-authorizing. Its PR, exact-main, and protected account-backed gates passed;
the later controlled workstation attempt and exact rollback are recorded in
the current section above.

## Resume Protocol

Before continuing existing work, including after context compaction or a bare
"continue" request:

1. Inspect the current worktree, branch, HEAD, and remote tracking state.
2. Inspect open and recently merged PRs plus the required CI jobs for the
   current HEAD.
3. Read this file, [ROADMAP.md](ROADMAP.md), and
   [DECISIONS.md](DECISIONS.md).
4. If commits landed after the evidence audit, inspect their diff and update
   the checkpoint before relying on its milestone labels.
5. Derive the next action from a concrete missing invariant or gate. Do not
   accept a milestone number from conversation or an old compaction summary as
   proof.
6. Prefer taking the verified action over repeating the roadmap. Update this
   file in the same PR whenever the milestone status or next action changes.

## Verified Checkpoint

| Milestone | Status | Evidence and remaining gap |
|---|---|---|
| M0 - Safe Base | Root daemon, private PF ownership, and exact launchd cleanup qualified on main | PR #220 closed the retained KeepAlive uninstall boundary with exact service-target bootout, plist fallback, bounded absence polling, and the prohibition on signalling any PID while launchd remains loaded. Packaged lifecycle passed on PR and exact main. Physical lid/default-route and broader split/per-app VPN qualification remain external gates. |
| M1 - Autonomous Routing V1 | Ordinary v1/v2 gates pass; one account-backed protected qualification remains | PRs #219-#258 cover generic transport recovery, strict semantic qualification, owner-only daemon IPC, exact-host owned-Geph confirmation and re-admission, browser-origin authentication, bounded reload, cleanup, persistent privileged artifact attestation, Googlevideo local-only fallback, exact protected-artifact publication, generic semantic-signal v2, read-only Chromium/macOS Safari incomplete-response observation, and serialized protected-gate cleanup. Protected run `30429690683` passed packaged resources, the daemon-free boundary, all three owned-Geph payload phases, unchanged system network state, and final cleanup. Its second browser scenario did not receive EOF because the disposable HTTP/1.1 fixture kept the socket alive after a deliberately short body; no artifact or install followed. PR #258 fixed that fixture and added a real TLS keep-alive `IncompleteRead` regression, then merged as `90c07771babfd32e797fdb8250911ca922274b4d`; exact-main CI `30431655863` and audit `30431655851` pass. Exactly one protected two-scenario run remains after the next UTC-day account budget reset for the then-current live `main`; Discord/YouTube and external DNS/proxy/PAC/VPN/PF owners remain untouched, and installation remains prohibited before that run publishes its exact artifact. |
| M2 - Contracts And Code | Partial | `slipstream-core` now owns policy classification, recovery, StatusV2, route-policy manifests and bundles, plus activation and rollback reducers. Python executes signed policy activation through that contract. Python PF/Geph orchestration and Rust tray runtime, installer, summary, and menu orchestration remain coupled. |
| M3 - Release-Grade macOS | Partial | Pinned dependencies, strict Clippy, explicit target, SBOM, manifest, audit, attestations, and preview releases are implemented. Stable publication is intentionally closed until Developer ID signing, hardened runtime, notarization, stapling, key custody, and rollback qualification exist. |
| M4 - Cross-Platform Core | Windows packet handoff plus bounded route, capture, and service-generation resilience are exact-main green | Pure policy, recovery, StatusV2, signed-policy, activation, packet-flow, capture, flow-binding, byte-owner, selected-stack, connector, Wintun ownership, exact-route, coexistence, and cleanup contracts are qualified. PR #267 merged packet handoff as `0a787ee284c6e12fe9394a707ceaaff9e13deacf`; PR #269 added exact route-change invalidation as `66f0bb697aa60b4387d4e4544d6ea06d2fffbae5`; PR #271 added same-name Wintun capture-generation recovery as `3a26653a2b221d757834cdb8ceb53f95c4589906`; and PR #273 added same-name SCM service-generation recovery as `7f265549d727db93b8c0a7861808cc5f59784527`. The latest exact-main native AMD64/ARM64 run is `30497886810`, with CI `30497886818` and audit `30497886814`. The evaluation stack remains development-only and the production SCM host remains no-network. Reboot, sleep/wake, broader crash recovery, production-host generation replacement and uninstall orchestration, and broader external network-tool coexistence remain required before production service-host networking composition. Android/Linux adapters and the iOS feasibility gate remain later. |

The exact-main
[CI run 30230210126](https://github.com/aiwaki/slipstream/actions/runs/30230210126)
passed the ordinary checks but failed the Safari build's retained
LaunchServices-registration gate after compilation. PR #227 repaired that
bounded cleanup proof, and the exact merged commit passed `checks`,
`windows-adapter-contract`, and `packaged-app-lifecycle` in
[CI run 30231226271](https://github.com/aiwaki/slipstream/actions/runs/30231226271).
Its dependency and vendored-Geph audits passed in
[audit run 30231226301](https://github.com/aiwaki/slipstream/actions/runs/30231226301).
The following entries retain historical gate evidence for the components they
describe; they are not the current-main locator.
The Windows ownership collector and its disposable owner-only fixture passed in
[PR #147 CI run 29592866727](https://github.com/aiwaki/slipstream/actions/runs/29592866727),
alongside the required checks and packaged lifecycle job; its dependency audit
passed in
[run 29592866706](https://github.com/aiwaki/slipstream/actions/runs/29592866706).
The merged collector passed again on main in
[CI run 29594236053](https://github.com/aiwaki/slipstream/actions/runs/29594236053),
and its dependency audit passed in
[run 29594235966](https://github.com/aiwaki/slipstream/actions/runs/29594235966).
The native Windows payload transaction, disposable rollback cases, and strict
lint passed in
[PR #148 CI run 29597856734](https://github.com/aiwaki/slipstream/actions/runs/29597856734).
The merged payload transaction passed again on main in
[CI run 29598632346](https://github.com/aiwaki/slipstream/actions/runs/29598632346),
and its dependency audit passed in
[run 29598632248](https://github.com/aiwaki/slipstream/actions/runs/29598632248).
The lifecycle-state contract, protected filesystem transaction, disposable
interruption/compensation cases, and strict Windows lint passed in
[PR #149 CI run 29603653185](https://github.com/aiwaki/slipstream/actions/runs/29603653185).
The merged lifecycle-state implementation passed again on main in
[CI run 29605608961](https://github.com/aiwaki/slipstream/actions/runs/29605608961),
and its dependency audit passed in
[run 29605608707](https://github.com/aiwaki/slipstream/actions/runs/29605608707).
The exiting-Safari lifecycle regression and packaged smoke passed in
[PR #150 CI run 29604297728](https://github.com/aiwaki/slipstream/actions/runs/29604297728).
The action-specific Windows SCM gate, exact native registration/removal,
machine-wide lifecycle serialization, bounded stop wait, strict lint, required
checks, and packaged lifecycle passed in
[PR #151 CI run 29612116541](https://github.com/aiwaki/slipstream/actions/runs/29612116541).
That run also qualified independent owner/DACL verification for every returned
kernel-object handle and rejection of a permissive pre-created mutex.
Its dependency and vendored-Geph audits passed in
[run 29612116544](https://github.com/aiwaki/slipstream/actions/runs/29612116544).
The merged SCM implementation passed again on main in
[CI run 29612504541](https://github.com/aiwaki/slipstream/actions/runs/29612504541),
and its dependency audit passed in
[run 29612504538](https://github.com/aiwaki/slipstream/actions/runs/29612504538).
The single-lock native compositor, disposable real-service lifecycle, bounded
crash recovery, exact uninstall ordering, and injected post-commit compensation
passed in
[PR #152 CI run 29614734338](https://github.com/aiwaki/slipstream/actions/runs/29614734338).
That run executed the gated full-lifecycle test as one real Windows test rather
than filtering or skipping it. The dependency and vendored-Geph audits passed
in
[run 29614734358](https://github.com/aiwaki/slipstream/actions/runs/29614734358).
The command-wide Windows controller, exact evidence reconstruction, idempotent
same-identity install, and failed-then-resumed crash recovery across separate
controller processes passed in
[PR #153 CI run 29618202282](https://github.com/aiwaki/slipstream/actions/runs/29618202282).
Its dependency and vendored-Geph audits passed in
[run 29618202290](https://github.com/aiwaki/slipstream/actions/runs/29618202290).
The production Windows service host, exact command/result contract, bounded SCM
stop/shutdown state machine, current-executable staging, repeatable management
commands from separate processes, PID replacement after restart, exact terminal
uninstall, and strict Windows lint passed in
[PR #154 CI run 29620298459](https://github.com/aiwaki/slipstream/actions/runs/29620298459).
Its dependency and vendored-Geph audits passed in
[run 29620298461](https://github.com/aiwaki/slipstream/actions/runs/29620298461).
The exact merged PR #154 commit passed again on main in
[CI run 29620781624](https://github.com/aiwaki/slipstream/actions/runs/29620781624),
and its dependency and vendored-Geph audits passed in
[run 29620781600](https://github.com/aiwaki/slipstream/actions/runs/29620781600).
The active-table request admission, protected-host reclassification, and exact
data-plane effect recovery cursors passed in
[PR #155 CI run 29623740312](https://github.com/aiwaki/slipstream/actions/runs/29623740312).
The exact merged PR #155 commit passed all required jobs in that same main run,
and its dependency and vendored-Geph audits passed in
[run 29623740325](https://github.com/aiwaki/slipstream/actions/runs/29623740325).
The worker-host composition, Windows-only production build, deterministic
startup/drain/deadline vectors, and real SCM stop path passed in
[PR #156 CI run 29625004279](https://github.com/aiwaki/slipstream/actions/runs/29625004279).
The exact merged PR #156 commit passed again on main in
[CI run 29625340050](https://github.com/aiwaki/slipstream/actions/runs/29625340050),
and its dependency and vendored-Geph audits passed in
[run 29625340061](https://github.com/aiwaki/slipstream/actions/runs/29625340061).
The active-policy-bound direct connector, exact data-plane effect bridge, and
real Windows loopback connect/payload/reset/cancel/deadline/shutdown fixture
passed in
[PR #157 CI run 29627204384](https://github.com/aiwaki/slipstream/actions/runs/29627204384).
Its dependency and vendored-Geph audits passed in
[run 29627204387](https://github.com/aiwaki/slipstream/actions/runs/29627204387).
The exact merged PR #157 commit passed again on main in
[CI run 29627636788](https://github.com/aiwaki/slipstream/actions/runs/29627636788),
and its dependency and vendored-Geph audits passed in
[run 29627636787](https://github.com/aiwaki/slipstream/actions/runs/29627636787).
The owned-client ingress, deterministic first-delivery/no-progress boundaries,
and exact native Windows relay passed in
[PR #158 CI run 29630565455](https://github.com/aiwaki/slipstream/actions/runs/29630565455).
The exact merged PR #158 commit passed all required jobs again on main in
[CI run 29630725442](https://github.com/aiwaki/slipstream/actions/runs/29630725442),
and its dependency and vendored-Geph audits passed in
[run 29630725439](https://github.com/aiwaki/slipstream/actions/runs/29630725439).
The technology-neutral capture-source lifecycle, one-shot resource ownership,
absolute deadline preservation, duplicate-resource rejection, failure-atomic
handoff, and bounded shutdown passed in
[PR #160 CI run 29632297457](https://github.com/aiwaki/slipstream/actions/runs/29632297457).
Its dependency and vendored-Geph audits passed in
[run 29632297449](https://github.com/aiwaki/slipstream/actions/runs/29632297449).
The exact merged PR #160 commit passed all required jobs again on main in
[CI run 29632468996](https://github.com/aiwaki/slipstream/actions/runs/29632468996),
and its dependency and vendored-Geph audits passed in
[run 29632468994](https://github.com/aiwaki/slipstream/actions/runs/29632468994).
The checkpoint commit in PR #161 passed all required jobs again on main in
[CI run 29632983193](https://github.com/aiwaki/slipstream/actions/runs/29632983193),
and its dependency and vendored-Geph audits passed in
[run 29632983199](https://github.com/aiwaki/slipstream/actions/runs/29632983199).
The WFP mechanism decision, management-callout ownership correction, and
filter-first fail-open ordering in PR #162 passed all required jobs again on
main in
[CI run 29633994824](https://github.com/aiwaki/slipstream/actions/runs/29633994824),
and its dependency and vendored-Geph audits passed in
[run 29633994821](https://github.com/aiwaki/slipstream/actions/runs/29633994821).
The exact WFP wire/handoff merge in PR #163 passed all required jobs again on
main in
[CI run 29635704622](https://github.com/aiwaki/slipstream/actions/runs/29635704622),
and its dependency and vendored-Geph audits passed in
[run 29635704616](https://github.com/aiwaki/slipstream/actions/runs/29635704616).
The pure WFP runtime lifecycle, monotonic attempt binding, over-capacity stream
rejection, retained-resource teardown, and non-replaying effect recovery in
PR #164 passed all required jobs in
[CI run 29637212615](https://github.com/aiwaki/slipstream/actions/runs/29637212615),
and its dependency and vendored-Geph audits passed in
[run 29637212612](https://github.com/aiwaki/slipstream/actions/runs/29637212612).
The exact merged PR #164 commit passed again on main in
[CI run 29637402421](https://github.com/aiwaki/slipstream/actions/runs/29637402421),
and its dependency and vendored-Geph audits passed in
[run 29637402397](https://github.com/aiwaki/slipstream/actions/runs/29637402397).
The WFP management-session contract, same-generation proof invalidation,
failure-atomic dynamic transaction, Windows native compile/lint, and exact
empty-session qualification in PR #165 passed all required jobs in
[CI run 29639374347](https://github.com/aiwaki/slipstream/actions/runs/29639374347),
and its dependency and vendored-Geph audits passed in
[run 29639374357](https://github.com/aiwaki/slipstream/actions/runs/29639374357).
The exact merged PR #165 commit passed again on main in
[CI run 29639553087](https://github.com/aiwaki/slipstream/actions/runs/29639553087),
including one explicitly asserted WFP qualification test, and its dependency
and vendored-Geph audits passed in
[run 29639553086](https://github.com/aiwaki/slipstream/actions/runs/29639553086).
The PR #166 checkpoint commit passed all required jobs again on main in
[CI run 29640104120](https://github.com/aiwaki/slipstream/actions/runs/29640104120),
and its dependency and vendored-Geph audits passed in
[run 29640104123](https://github.com/aiwaki/slipstream/actions/runs/29640104123).
The official signed Wintun artifact admission, opaque resolver-evidence
binding, frozen IANA IPv6 allocation snapshot, and non-authorizing exact-route
contract in PR #167 passed all required jobs again on the exact merge commit in
[CI run 29646370056](https://github.com/aiwaki/slipstream/actions/runs/29646370056),
and its dependency and vendored-Geph audits passed in
[run 29646370093](https://github.com/aiwaki/slipstream/actions/runs/29646370093).
The PR #168 checkpoint merge passed all required jobs again on the exact main
commit in
[CI run 29646801180](https://github.com/aiwaki/slipstream/actions/runs/29646801180),
and its dependency and vendored-Geph audits passed in
[run 29646801183](https://github.com/aiwaki/slipstream/actions/runs/29646801183).
The native Wintun collector admitted both official AMD64 and ARM64 artifacts,
rejected a tampered DLL, and retained the read-only handle without loading the
adapter in
[PR #169 CI run 29648242778](https://github.com/aiwaki/slipstream/actions/runs/29648242778).
Its dependency and vendored-Geph audits passed in
[run 29648242770](https://github.com/aiwaki/slipstream/actions/runs/29648242770).
The exact merged PR #169 commit passed all required jobs again on main in
[CI run 29648441001](https://github.com/aiwaki/slipstream/actions/runs/29648441001),
and its dependency and vendored-Geph audits passed in
[run 29648440999](https://github.com/aiwaki/slipstream/actions/runs/29648440999).
The complete shared-destination conflict gate from PR #170 passed `checks`,
`windows-adapter-contract`, and `packaged-app-lifecycle` on the exact merge
commit in
[CI run 29650142948](https://github.com/aiwaki/slipstream/actions/runs/29650142948),
and its dependency and vendored-Geph audits passed in
[run 29650142955](https://github.com/aiwaki/slipstream/actions/runs/29650142955).
The macOS uninstall/drain safety change in PR #171 passed `checks`,
`windows-adapter-contract`, and the disposable `packaged-app-lifecycle` gate in
[CI run 29656556574](https://github.com/aiwaki/slipstream/actions/runs/29656556574).
Its dependency and vendored-Geph audits passed in
[run 29656556559](https://github.com/aiwaki/slipstream/actions/runs/29656556559).
The primary workstation remained uninstalled throughout that qualification.

The clean-install local-bypass repair and optional-backend state guards in
[PR #172](https://github.com/aiwaki/slipstream/pull/172) passed `checks`,
`windows-adapter-contract`, and `packaged-app-lifecycle` on the exact merge
commit in
[CI run 29663263685](https://github.com/aiwaki/slipstream/actions/runs/29663263685).
Its dependency and vendored-Geph audits passed in
[run 29663263691](https://github.com/aiwaki/slipstream/actions/runs/29663263691).
The packaged gate proved active local bypass without a Geph account or
listener and preserved the independent PF sentinel.

The exact artifact from that run was then installed twice on the primary
workstation. Both installs immediately coincided with broad HTTPS failures
before the tray was launched, while app-owned Geph was disabled. Both manual
uninstalls restored a process-free daemon state with no listener, runtime
install, or PF token and left the user's `111.88.96.50` / `111.88.96.51` DNS
and system proxy settings unchanged. The app bundle itself was not removed.
`Reconnecting 5/5` was also observed after cleanup, so that symptom is not yet
attributed exclusively to an active Slipstream PF path; the reproducible
install trigger still makes this build unsafe to reinstall.

The doc-only checkpoint rerun then reproduced the same class of failure in the
disposable packaged gate: Safari reported `You Are Not Connected to the
Internet` at `before-tray-start` while the private PF anchor was active in
[CI run 29666303800](https://github.com/aiwaki/slipstream/actions/runs/29666303800).
This confirms that the unsafe baseline is in the daemon data plane rather than
the tray, Geph account state, or the workstation's DNS configuration.

[PR #174](https://github.com/aiwaki/slipstream/pull/174) fixed the independent
tray-uninstall defect by moving app-bundle removal into a validated one-shot
launchd worker. Its complete CI, including `packaged-app-lifecycle`, passed in
[run 29665174375](https://github.com/aiwaki/slipstream/actions/runs/29665174375).

[PR #175](https://github.com/aiwaki/slipstream/pull/175) repaired the daemon
baseline without changing protected routing policy. Direct, unknown, non-TLS,
and no-SNI/ECH connections now relay the exact pre-PF destination without
alternate DNS, desync, or a first-payload gate. Recovery is deferred to a later
client retry and is armed only by an observed stall, repeated clean EOF, or
server-first zero-byte close; healthy low-volume streams do not feed it.
Orderly client EOF is preserved as a bounded TCP half-close. All required
checks passed on the exact reviewed head, including the packaged Safari,
Chrome, PF-sentinel, and lifecycle gate in
[CI run 29667950857](https://github.com/aiwaki/slipstream/actions/runs/29667950857).
The formerly failing `before-tray-start` Safari stage passed. The repair was
squash-merged as `a26e467`; that exact main commit passed
[CI run 29668308779](https://github.com/aiwaki/slipstream/actions/runs/29668308779)
and
[dependency-audit run 29668308760](https://github.com/aiwaki/slipstream/actions/runs/29668308760).
It has not been installed on the primary workstation.

[PR #176](https://github.com/aiwaki/slipstream/pull/176) recorded that
qualification boundary without changing runtime behavior and was merged as
`1f4cdd0`; its exact main commit passed CI and dependency audit.

[PR #177](https://github.com/aiwaki/slipstream/pull/177) then added the
automatic startup guard. It proves a small neutral HTTPS baseline through the
console user's current system route before PF and repeats only the same proven
numeric destinations after PF. A failed post-arm proof rolls back only
Slipstream-owned state. If PF cleanup itself is temporarily unavailable, the
daemon keeps its listener and runtime alive while retrying cleanup instead of
leaving a redirect to a dead listener. Install, reinstall, and uninstall also
use failure-atomic ordering. The exact merge commit `f5541a0` passed the full
disposable Safari, Chrome, PF-sentinel, and packaged lifecycle gate.

[PR #178](https://github.com/aiwaki/slipstream/pull/178) closed the remaining
macOS loopback gap. It clears only `PFI_IFLAG_SKIP` under a durable root-owned
`0600` lease, restores and verifies the original `lo0 (skip)` state before
releasing the owned PF token, quiesces the `KeepAlive` daemon before signalling
verified owned processes, and moves tray recovery behind the installed daemon
ownership boundary. The redirect excludes `127.0.0.0/8`, and the active monitor
revalidates loopback visibility if another PF reload changes it. Both the PR and
the exact main commit `162cc8e` passed the disposable private-PF sentinel and
packaged lifecycle. The primary workstation had remained uninstalled since the
unsafe baseline incident until the controlled validation below.

[PR #179](https://github.com/aiwaki/slipstream/pull/179) refreshed this
checkpoint without changing runtime behavior and merged as `c07ade34`; the
exact main commit passed required CI and dependency audit. Its packaged artifact
was then used for one controlled workstation validation. Preflight proved the
daemon job, owned Geph job, listeners, status, PF token, loopback lease, and
private anchor absent; the user's DNS and proxy settings were left unchanged.
The app bundle was replaced atomically with the exact signed artifact, but the
first daemon install timed out with `status missing`. The session log reached
the standalone Telegram-proxy check and no later startup line. Live diagnosis
showed the first synchronous system resolver call could stall while a later
neutral target remained reachable. The prepared rollback removed every owned
root runtime artifact and listener without a connection outage. The app bundle
remains present but unlaunched and inert; the root daemon is absent and
disabled, owned Geph is absent, and Slipstream PF is not active.

[PR #180](https://github.com/aiwaki/slipstream/pull/180) bounded that startup
path and merged as `140598b`. The daemon now publishes an atomic, probe-free
`dormant` StatusV2 snapshot after binding its listener and before Geph, DNS, or
PF qualification. System-DNS lookups run as the console user in killable child
processes under one total preflight budget; diagnostic refresh uses the same
bounded helper. The packaged lifecycle installs a scoped resolver blackhole for
the first neutral target and proves that status precedes the stalled query, a
later target can activate routing, no helper survives, and cleanup preserves
the independent PF sentinel. The exact main commit passed all required jobs in
[CI run 29707822352](https://github.com/aiwaki/slipstream/actions/runs/29707822352)
and dependency audit in
[run 29707822353](https://github.com/aiwaki/slipstream/actions/runs/29707822353).
That exact artifact is downloaded and signature-verified, but it has not been
launched or installed on the primary workstation. It was later disqualified
because this workflow had downloaded the superseded `geph-vendor-0.3.0`
artifact rather than the release revision recorded in the repository.

[PR #181](https://github.com/aiwaki/slipstream/pull/181) made all build,
qualification, and release workflows derive the immutable Geph tag from
`vendor/geph/VERSION` and `vendor/geph/SOURCE.json.release_revision`. Release
asset downloads now use bounded retries, require a complete requested asset
set, and never publish partial output. The exact merge commit `27363cd3` passed
all required jobs, including the disposable packaged lifecycle with
`geph-vendor-0.3.0-r1`, in
[CI run 29709766877](https://github.com/aiwaki/slipstream/actions/runs/29709766877),
and its dependency and vendored-Geph audits passed in
[run 29709766891](https://github.com/aiwaki/slipstream/actions/runs/29709766891).
No application or privileged component was launched on the primary workstation.

[PR #182](https://github.com/aiwaki/slipstream/pull/182) refreshed this
checkpoint after the revisioned artifact correction. [PR
#183](https://github.com/aiwaki/slipstream/pull/183) added the pure capture-only
Windows v2 classifier, and its exact merge commit passed all required jobs in
[CI run 29710542922](https://github.com/aiwaki/slipstream/actions/runs/29710542922)
plus dependency audit in
[run 29710542945](https://github.com/aiwaki/slipstream/actions/runs/29710542945).
[PR #184](https://github.com/aiwaki/slipstream/pull/184) made every owned-Geph
cleanup stage independent so a Keychain error cannot skip later runtime,
listener, sentinel, or root-boundary cleanup. Its exact main commit passed all
required jobs in
[CI run 29711400231](https://github.com/aiwaki/slipstream/actions/runs/29711400231)
and dependency audit in
[run 29711400215](https://github.com/aiwaki/slipstream/actions/runs/29711400215).
The protected `geph-qualification` environment now exists and is limited to
protected branches, but it has no `SLIPSTREAM_GEPH_ACCOUNT_SECRET`; the manual
account-backed gate must not be triggered until the user supplies that secret.

[PR #185](https://github.com/aiwaki/slipstream/pull/185) added the first native
Wintun lifecycle subgate. The exact admitted 0.14.1 DLL, unique adapter, minimum
128 KiB session, and adapter-removal proof passed on both native x64 and ARM64
Windows runners in
[run 29712583287](https://github.com/aiwaki/slipstream/actions/runs/29712583287).
The fixture configured no address or route and did not touch DNS, proxy, PAC,
VPN, or the Wintun driver. Its exact merge commit `d35ab35` passed the same
native x64 and ARM64 gate in
[run 29713033740](https://github.com/aiwaki/slipstream/actions/runs/29713033740),
all required checks and packaged lifecycle in
[run 29713033745](https://github.com/aiwaki/slipstream/actions/runs/29713033745),
and dependency audit in
[run 29713033754](https://github.com/aiwaki/slipstream/actions/runs/29713033754).

[PR #186](https://github.com/aiwaki/slipstream/pull/186) added the separate
abrupt-owner cleanup proof. The exact child-process adapter/session fixture
passed on native x64 and ARM64 runners in
[run 29713791755](https://github.com/aiwaki/slipstream/actions/runs/29713791755).
It used no process-name search, adapter or driver deletion, address, route, DNS,
proxy, PAC, VPN, or production-host composition. Its exact merge commit
`6c3759e` passed the same native gate in
[run 29714575179](https://github.com/aiwaki/slipstream/actions/runs/29714575179),
all required checks and packaged lifecycle in
[run 29714575187](https://github.com/aiwaki/slipstream/actions/runs/29714575187),
and dependency audit in
[run 29714575209](https://github.com/aiwaki/slipstream/actions/runs/29714575209).

The pure Windows packet-egress v1 contract now freezes the admission boundary
needed before a native loop-avoidance fixture. A plan requires short-lived
route evidence collected before capture plus an exact owned capture-route
activation from that baseline epoch to the current epoch. The transition must
retain the capture generation, destination, exact host prefix, and capture
interface identity; any later route-epoch change invalidates the plan. The
egress LUID/index identity and currently selected source address must still
match the baseline, alongside the public destination, source family, and
containing baseline route prefix. The capture interface is rejected. The plan
records the Windows IPv4/IPv6
per-socket interface value but performs no route query, socket operation,
adapter effect, route mutation, backend choice, or production composition.
The exact merge commit `1765398` passed the native x64 and ARM64 lifecycle gate
in
[run 29718757015](https://github.com/aiwaki/slipstream/actions/runs/29718757015),
all required checks and packaged lifecycle in
[run 29718757005](https://github.com/aiwaki/slipstream/actions/runs/29718757005),
and dependency audit in
[run 29718756994](https://github.com/aiwaki/slipstream/actions/runs/29718756994).

One earlier ARM64 attempt in
[run 29715892426](https://github.com/aiwaki/slipstream/actions/runs/29715892426)
reached the broad 20-minute job timeout inside the abrupt-owner cleanup step
without phase output. Later exact-head and exact-main runs passed, so this is
recorded as a flaky, insufficiently bounded qualification gate rather than
routing-runtime evidence. [PR #188](https://github.com/aiwaki/slipstream/pull/188)
bounds the exact-child wait, removes blocking cleanup from `Drop`, streams phase
output, and gives that step its own four-minute ceiling. Its exact merge commit
`f373339` passed native x64 and ARM64 qualification in
[run 29719510753](https://github.com/aiwaki/slipstream/actions/runs/29719510753),
all required checks and packaged lifecycle in
[run 29719510754](https://github.com/aiwaki/slipstream/actions/runs/29719510754),
and dependency audit in
[run 29719510744](https://github.com/aiwaki/slipstream/actions/runs/29719510744).
[PR #189](https://github.com/aiwaki/slipstream/pull/189) added the isolated
read-only Windows route/source observer. Its exact merge commit `b71042b` passed
the observer step and the existing Wintun lifecycle on native x64 and ARM64 in
[run 29721672134](https://github.com/aiwaki/slipstream/actions/runs/29721672134),
all required checks and packaged lifecycle in
[run 29721672179](https://github.com/aiwaki/slipstream/actions/runs/29721672179),
and dependency audit in
[run 29721672104](https://github.com/aiwaki/slipstream/actions/runs/29721672104).

[PR #190](https://github.com/aiwaki/slipstream/pull/190) sealed the
Windows route-transition issuer behind opaque, native-timestamped route
observations. Its exact merge commit `44afffc` passed the issuer and existing
Wintun lifecycle gates on native x64 and ARM64 in
[run 29726460677](https://github.com/aiwaki/slipstream/actions/runs/29726460677),
all required checks and packaged lifecycle in
[run 29726460692](https://github.com/aiwaki/slipstream/actions/runs/29726460692),
and dependency audit in
[run 29726460674](https://github.com/aiwaki/slipstream/actions/runs/29726460674).
The first ARM64 attempt for the PR in
[run 29725545540](https://github.com/aiwaki/slipstream/actions/runs/29725545540)
printed the exact crash-cleanup test's passing result, then remained inside the
PowerShell `Tee-Object` pipeline until the four-minute step timeout. Attempt 2
and exact-main both passed. This is a repeated qualification-harness failure,
not packet-runtime evidence; the current follow-up replaces that object
pipeline with a retained exact process handle, file-backed live output, and an
inner monotonic deadline before route-owner work resumes.

[PR #191](https://github.com/aiwaki/slipstream/pull/191) replaced that fragile
pipeline with the retained-process harness. Its exact merge commit `8d00c2a`
passed native AMD64/ARM64 packet qualification in
[run 29729362857](https://github.com/aiwaki/slipstream/actions/runs/29729362857),
all required checks and packaged lifecycle in
[run 29729362904](https://github.com/aiwaki/slipstream/actions/runs/29729362904),
and dependency audit in
[run 29729362872](https://github.com/aiwaki/slipstream/actions/runs/29729362872).

[PR #192](https://github.com/aiwaki/slipstream/pull/192) is the first
feature-gated exact-route ownership qualification. Its initial native run
[29730828356](https://github.com/aiwaki/slipstream/actions/runs/29730828356)
created the retained route on both AMD64 and ARM64, but the fresh
`GetBestRoute2` observation then failed with Win32 code `1232`: the unique bare
Wintun adapter had no usable source address. The correction keeps address
ownership outside the route owner and production host. The native fixture now
creates only `192.0.2.1/32` on its unique disposable adapter and polls the exact
row until its DAD state is `Preferred`, its `/32` and interface/address key are
unchanged, and `SkipAsSource` is false. It then runs the route qualification,
explicitly removes the address, and requires bounded absence before accepting
the route result. Its exact code head passed native AMD64 and ARM64 in
[run 29734712632](https://github.com/aiwaki/slipstream/actions/runs/29734712632),
all required checks and packaged lifecycle in
[run 29734712671](https://github.com/aiwaki/slipstream/actions/runs/29734712671),
and dependency audit in
[run 29734712698](https://github.com/aiwaki/slipstream/actions/runs/29734712698).
Both architectures proved route, address, adapter, and session cleanup.

[PR #193](https://github.com/aiwaki/slipstream/pull/193) adds the first
feature-gated socket-selection effect without adding production networking. Its
IPv4 UDP fixture proves that ordinary route selection points at the competing
Wintun `/32`, then sets `IP_UNICAST_IF` to the retained baseline interface,
reads the same host-order index back, binds the retained baseline source, and
connects without calling a send or receive API. Probe failure still runs the
owned exact-route cleanup and baseline recovery observation before it is
returned. The active-probe entrypoint itself requires the third socket-binding
CI gate; the probe-free exact-route wrapper retains the original two-gate
admission. The exact PR head passed the selected fixture and
all existing packet gates on native AMD64 and ARM64 in
[run 29739433700](https://github.com/aiwaki/slipstream/actions/runs/29739433700),
all required checks and packaged lifecycle in
[run 29739433665](https://github.com/aiwaki/slipstream/actions/runs/29739433665),
and dependency audit in
[run 29739433660](https://github.com/aiwaki/slipstream/actions/runs/29739433660).
Its exact merge commit `b3572863` passed again on native AMD64 and ARM64 in
[run 29741495033](https://github.com/aiwaki/slipstream/actions/runs/29741495033),
all required checks and packaged lifecycle in
[run 29741495030](https://github.com/aiwaki/slipstream/actions/runs/29741495030),
and dependency audit in
[run 29741495046](https://github.com/aiwaki/slipstream/actions/runs/29741495046).

## Next Verified Action

Do not retry the controlled transaction on the primary workstation yet. After
the next UTC-day Geph authentication reset, verify the physical repository,
the then-current live `main`, its worktree, merged PRs, and exact-main CI and
audit. The live SHA must contain product merge
`45db4321bafe244c87986c4c08daf1c3afaf8bf2`, and no protected
owned-Geph qualification may already exist for it. Dispatch the protected
workflow exactly once for that live SHA. Require complete account-backed Geph
payload initially, without the tray, and after KeepAlive recovery; both frozen
Chromium semantic scenarios; exact cleanup; artifact identity; and no system
network mutation.

If any gate is blocked or fails, do not install and continue only from the
exact evidenced defect in a small PR. If the full gate passes, download only
that run's exact qualified artifact. A user-present workstation transaction
may then use the existing snapshot and immediate rollback boundary, preserving
DNS `111.88.96.50/51` and all external proxy, PAC, VPN, and PF owners. Do not
reuse an older artifact, substitute a release or local build, or repeat a
failed workstation attempt in the same session.

Safari may advance through deterministic source, Swift contract tests, and
unsigned packaging, but the signed app-extension sandbox/socket path must be
proven on a disposable build before it is bundled, enabled, or described as
runtime-ready.

Continue M4 on disposable systems. PRs #193 and #194 proved no-payload IPv4
and IPv6 socket selection under competing exact Wintun routes on exact main,
native AMD64 and ARM64, while removing every owned route, address, session,
and adapter. PR #195's exact main passed one synthetic IPv4 UDP datagram into
the owned capture ring and one synthetic response injected back to the same
socket under one strict deadline on native AMD64 and ARM64. It has no external
endpoint, backend, default route, production host, DNS, proxy, PAC, or VPN
effect. PR #196's exact main passed the equivalent closed IPv6 proof with its
mandatory UDP checksum in the audited runs recorded above. PR #197's exact main
then constrained `GetBestRoute2` to the retained baseline source/LUID while the
owned exact route was active, preserved kernel-selected synthetic VPN evidence,
and exposed field-specific mismatch codes before any active probe. PR #198's
exact main commit `c036fa1cad5bb95439f2ce98ad095267dfdd34a0` passed the bounded
pre-existing IPv4 UDP flow gate on native AMD64 and ARM64 in
[run 29962673071](https://github.com/aiwaki/slipstream/actions/runs/29962673071),
all required checks and packaged lifecycle in
[run 29962673111](https://github.com/aiwaki/slipstream/actions/runs/29962673111),
and dependency audit in
[run 29962673054](https://github.com/aiwaki/slipstream/actions/runs/29962673054).
The gate uses two owned IPv4 Wintun adapters, one owned non-default `/24`
baseline route, and one exact `/32` capture route. A connected UDP socket first
completes a checksum-valid closed baseline round trip. Under activation it must
either keep using that baseline path, or cause the active probe to fail so the
owner removes only the exact route and the same socket completes a bounded
baseline retry. Every acquired route and address reaches explicit verified
cleanup before any result is accepted. This closes only the first IPv4 UDP
subgate; PR #200 below subsequently closes TCP pre-existing-flow activation.
Crash-safe capture removal is closed by PR #202. At that checkpoint,
independent external-network-owner coexistence remained separate; PR #204 below
closes one bounded VPN-like route-owner case. Broader physical, full-tunnel,
split, and per-app vendor VPN qualification remains separate from the next
packet-to-flow contract and from production composition. A partial DNS cache is
never treated as complete attribution.
External DNS, VPN, proxy, PAC, and unrelated PF state remain read-only.

PR #200 is the independent IPv4 TCP pre-existing-flow gate. Its qualified code
head `d384817c7e64d79806c6ac18eab9a6f4803f3092` passed native AMD64 and ARM64
twice in
[run 29965217892](https://github.com/aiwaki/slipstream/actions/runs/29965217892),
all required checks and packaged lifecycle in
[run 29965217886](https://github.com/aiwaki/slipstream/actions/runs/29965217886),
and dependency audit in
[run 29965217897](https://github.com/aiwaki/slipstream/actions/runs/29965217897).
The final PR head repeated the native proof on both architectures before merge.
The exact main commit `8cac5602eaccd992a1f2a5e86bb2510aac789a9a` then passed native AMD64 and
ARM64 in
[run 29966086550](https://github.com/aiwaki/slipstream/actions/runs/29966086550),
all required checks and packaged lifecycle in
[run 29966086559](https://github.com/aiwaki/slipstream/actions/runs/29966086559),
and dependency audit in
[run 29966086558](https://github.com/aiwaki/slipstream/actions/runs/29966086558).
The gate establishes one real Windows TCP stream through the owned baseline Wintun ring,
requires a checksum-valid SYN/SYN-ACK/final-ACK exchange and a payload round
trip before activation, then accepts only baseline continuity or fail-closed
exact-route rollback followed by retransmission recovery. The same stream must
also complete another baseline exchange after route removal. Its first native
revision exposed that `peer_addr()` alone can become observable before Windows
has completed the handshake; the corrected candidate requires the captured
final ACK with exact sequence and acknowledgment numbers before treating the
stream as established. TCP pre-existing-flow activation is now closed. PR #202
subsequently closed bounded crash-safe removal of capture ownership without
inferring external-VPN coexistence from that result.

PR #202's crash-removal gate keeps the baseline adapter, exact source, and
non-default `/24` in the parent while an exact child process owns the
capture adapter, source, and production-gated `/32`. An atomic marker is
published only from the active probe. The parent independently observes the
active capture identity, terminates only that retained child handle, and then
requires bounded adapter, address, and `/32` absence plus exact baseline route
recovery. It uses no external endpoint, backend, default route, production-host
composition, DNS, proxy, PAC, VPN, broad process kill, or driver mutation.
PR #202 head passed this proof on native AMD64 and ARM64 in
[run 29967959561](https://github.com/aiwaki/slipstream/actions/runs/29967959561),
all required checks and packaged lifecycle in
[run 29967959616](https://github.com/aiwaki/slipstream/actions/runs/29967959616),
and dependency audit in
[run 29967959553](https://github.com/aiwaki/slipstream/actions/runs/29967959553).
The exact merge commit `ebe9f9c70b378f688badf6ba35cd96dd200d0bb4`
repeated native AMD64 and ARM64 qualification in
[run 29968586744](https://github.com/aiwaki/slipstream/actions/runs/29968586744),
all required checks and packaged lifecycle in
[run 29968586745](https://github.com/aiwaki/slipstream/actions/runs/29968586745),
and dependency audit in
[run 29968586782](https://github.com/aiwaki/slipstream/actions/runs/29968586782).
Crash-safe capture removal is closed. At that merge boundary, independent
external-network-owner coexistence was the next native gate; PR #204 below
closes its bounded synthetic route-owner case.

PR #204 narrowed that gate to independently owned route state. An exact
child process owns a uniquely named Wintun adapter,
the synthetic VPN-like source `198.18.0.2/32`, and a non-default public `/24`.
The parent owns a separate capture adapter and only the production-gated
destination `/32`. It must prove the child, adapter, address, and broader route
remain unchanged during activation, exact-route recovery, and Slipstream's own
capture cleanup. Ordinary route selection must return to the child-owned source
and interface before the parent releases it; the child then removes only its
own resources. No default route, real VPN endpoint or protocol, external
payload, backend, production-host composition, DNS, proxy, PAC, driver, or
broad process effect is present. Exact merge commit
`8c1addbcfeb93f6cbd64cac07b29b98f7aae4bbb` passed native AMD64 and ARM64 in
[run 29971683285](https://github.com/aiwaki/slipstream/actions/runs/29971683285),
all required checks and packaged lifecycle in
[run 29971683270](https://github.com/aiwaki/slipstream/actions/runs/29971683270),
and dependency audit in
[run 29971683269](https://github.com/aiwaki/slipstream/actions/runs/29971683269).
The independent VPN-like route-owner gate is closed. It does not qualify every
physical, full-tunnel, split, or per-app vendor VPN.

The versioned pure packet-to-flow v1 contract now lives after isolated capture
classification and egress admission in merged PR #206 at exact main commit
`e8cb475fc65a375d0dd57f757e2f5bc575a4fcde`. It keeps bounded TCP/UDP flow
ownership, backpressure, half-close/reset, timeout, route-class dispatch, and
cleanup outside the production SCM host and performs no socket, route, adapter,
DNS, proxy, PAC, VPN, or packet effect. Capture v3 preserves the client's
original destination port without changing frozen v2 policy semantics. Keyed
events update only one bounded flow, data-plane session/request ownership is
unique until generation retirement, admission consumes a binding minted from
the still-opening accepted data-plane session rather than an unrelated raw ID,
backend opening revalidates a fresh capability for that same current session,
retained command batches resume from an exact failure cursor without replay,
and a rejected reused request cancels only its exact new data-plane session.
Required CI and the disposable native AMD64/ARM64 workflow run this complete
packet-flow contract before the existing Wintun gates. Exact main
`c154f2d880d1d4aad34c83c813a03f11006b5d4e` passed that matrix in
[run 30465700678](https://github.com/aiwaki/slipstream/actions/runs/30465700678).
Capture v4 and userspace-flow-binding v1 now retain and validate the original
client source address/port without patching frozen capture v3 or packet-flow
v1. The binding requires exact generation, flow ID, transport, destination
address/port, IP family, active policy, and expiry agreement, and explicitly
keeps the original client source separate from the outbound egress source. It
also retains the exact admission capability, so byte ownership cannot open from
an independently valid same-key transition for another destination or request;
the complete backend-open and idle-deadline command set must match as well.
The bounded byte-owner bridge now retains exact flow, direction, sequence, and
payload bytes after successful packet-flow-v1 acceptance. Every active
transition must preserve the complete admission capability retained by the
immutable tuple binding and exactly equal a fresh reduction from its supplied
full predecessor and configuration. A bounded full-registry cursor advances on
exact unrelated transitions too, preventing a stale target-only snapshot from
rolling back another flow. It releases bytes
only after one injected atomic effect succeeds, retains the exact suffix on
failure, and accepts staging only from the exact current packet-flow predecessor
with the matching queue delta and transition-issued forwarding authorization.
Client payload queued before backend readiness remains non-forwardable until an
exact one-to-one `BackendReady` command set authorizes it. Ordinary terminal
cleanup removes only its exact flow; explicit generation retirement is
high-watermark bounded. Before either path releases bytes, its transition must
exactly equal a fresh reduction from the supplied full registry. Delivery preflights the exact acknowledgement from the
current full registry before invoking the effect, including its global
monotonic watermark. Generic reconciliation rejects `Forwarded` while an owner
exists, so it cannot skip the effect. A final acknowledgement that makes a
gracefully closed flow terminal also releases its empty owner immediately,
including when bounded terminal-history pruning removes that exact flow from
the reducer output. A separate test-only effect-evaluation crate now exercises
that owner against pinned `smoltcp` through a deterministic in-memory Layer 3
pair. IPv4/IPv6 TCP/UDP payloads cross in both directions, and an injected
pre-mutation failure retains the exact payload for one successful retry without
linking `smoltcp` into the Windows adapter. Bounded IPv6 fragment input is now
qualified separately in that isolated stack-selection harness. Its additive
capture-fragment composition classifies before state, binds assemblies to exact
capture identity and tuple, and expires them no later than the five-second
evidence deadline. An additive native connector contract now transfers one
exact client frame atomically into a bounded connector queue. Numeric loopback
TCP proves complete retention after failure-before-progress and exact suffix
retention after partial writes; numeric loopback UDP proves one complete
datagram. Every write revalidates the exact flow key, backend, and transport, while Discord,
YouTube, and UDP remain excluded from Geph. An additive composition now proves
selected-stack output reaches the connector queue and retains bounded native
backend reads until the selected stack accepts one exact frame. Flow, backend,
transport, and reverse sequence identity are revalidated before mutation, and
pre-mutation failures preserve the current byte owner. PR #263 added the first
test-only Wintun-to-stack packet handoff: a real OS IPv4 UDP request crosses an
exact owned route into Wintun, enters the pinned selected stack as the exact
captured Layer 3 packet, and returns to the OS only from the stack-emitted
response packet. The boundary is fixed-MTU, fixed-queue, bounded-poll, and
fail-closed. It merged as `105551ec27f8139e455783b7ae2bf89d63812166`;
exact-main native run `30472082661` passed on both AMD64 and ARM64, CI
`30472083693` passed including the packaged lifecycle, and audit `30472083055`
passed. The implementation remains a development-only qualification dependency
and does not compose networking into the production SCM host.

PR #265 completed the additive IPv6 UDP gate without changing frozen IPv4 v1.
A separate `raw_packet_udp_ipv6_v1` boundary validates one raw IPv6 UDP request
through pinned `smoltcp`, emits one checksum-valid fixed-MTU response, and
exposes bounded structured failures. The disposable Windows `/128` route proof
retains the exact captured packet and injects only that selected-stack response;
its manual IPv6 response builder is removed. It merged as
`9979889d82316f21701f1ef8304ffe3b8a11bb7d`; exact-main native run
`30476588359` passed on AMD64 and ARM64, CI `30476589552` passed including the
packaged lifecycle, and audit `30476588735` passed. The dependency remains
qualification-only and the production SCM host remains closed.

PR #267 completed the additive IPv4 TCP Wintun-to-selected-stack gate. A real
Windows TCP socket supplies the SYN, handshake ACK, and request payload; the
selected stack emits the SYN-ACK and response packets injected through the same
owned Wintun session. The proof contains no manual handshake or response packet
builder and preserves the exact route, address, session, and adapter cleanup
requirements. It merged as `0a787ee284c6e12fe9394a707ceaaff9e13deacf`;
exact-main native run `30481891835` passed on AMD64 and ARM64, CI
`30481892061` passed including packaged lifecycle, and audit `30481891839`
passed. The next independent M4 gate is bounded production service-host
composition; the existing production host remains no-network until that gate
passes.

## External Gates

- Add `SLIPSTREAM_GEPH_ACCOUNT_SECRET` to the protected
  `geph-qualification` environment, then run the account-backed owned-Geph
  qualification successfully from `main`.
- Qualify a physical default-route change and lid-close/wake cycle on a
  disposable Mac.
- Add Developer ID signing, hardened runtime, notarization, stapling, policy-key
  custody, and cross-version rollback before opening the stable channel.
- The local Parallels Windows 11 ARM64 VM has minimal Rust 1.97.1 but no Windows
  SDK or Visual Studio Build Tools; native compilation therefore remains a CI
  gate until that disposable VM is provisioned deliberately. The official
  ARM64 Wintun DLL hash and embedded signature were inspected there without
  loading it. A Fedora VM is also available for the later Linux adapter.

## Update Rule

Keep this file short and current. A PR that closes a listed gap, changes the
next verified action, or adds a new release/safety gate must update this
checkpoint. If live evidence contradicts it, stop, investigate the difference,
and correct the file rather than improvising a narrative.

# Current Project State

## Verified Checkpoint

### Active: PR426 transport fixes and dependency-admission blockers, 2026-10-30

Active checkout: `/Users/aiwaki/.codex/worktrees/geph-route-continuity/slipstream-codebase-audit-20260905`,
branch `codex/post-preview31-recovery`, based on documentation main `a37cb6c5`. Published source is
`3eb32bd3029d6acd88b380a8c767c19c7abc76a4` (PR424), tree
`37981d7723c73d74b99ab86faf00f494c8c0c030`. Documentation follow-up PR425 merged normally as
`a37cb6c5e3ccce805af46b7b1c4b72d7be6a041c`; its tree equals tested head
`e2afc02630cc0cf56257c34fe8381e1b27de5e71`. PR CI41044074098/audit41044074284
and main CI41044257786/audit41044257543 passed. That follow-up changed only three
documentation files. The new transport changes below are not in the published binary.
The previous tested documentation branch is retained; preserve private output.
Preserve the user's working external Geph. No workstation service/account/browser/build/install action in this continuation.

**Initial blocker:** exact-head audit41046195000 failed: the app's Chromium155
integrity-only admission expired October 29; Geph newly reports block-buffer0.9/0.10
under GHSA-qwgh-2vcv-g2f7. Independent exact-source review finds the documented
inline-cursor mechanism absent in those two versions; scoped policy dispositions
are prepared, with no RSA renewal. Browser156.0.8078.80 passed official archive
identity, sandbox DOM and cleanup in evidence-only review41048890989/1 at
head7930fb61e; exact pins and a new artifact review through November 13 are prepared.
OSV still cannot map the generic browser to a supported ecosystem, so no CVE clearance
is claimed. Small artifact12973786970 and its run/merge-tree binding are verified.
36 runtime/audit/SBOM tests and 38 subcases passed. Its companion
product/audit runs41048891135/41048890862 were cancelled because this intermediate
head deliberately retains old Chromium155; final production CI remains mandatory.

Version metadata is synchronized to `.32` for the upcoming candidate; no `.32`
binary has been built or published yet. The .31 publisher and manual preflight
missed Chromium's expiry. Its public notes
have been corrected; all 12 assets/tag remain unchanged. Publication-time admission is now implemented for the application and selected
exact-run/attempt full Geph audit before every draft-publication PATCH. Historical
verification remains separate. Independent final review passed; 74 tests/65
subcases and 16 workflow checks passed, including causal refusal of expired vendor
evidence and UTC rollover. Receipt: `output/continuation-20261030/release-audit-admission/`.
The complete .32 candidate needs fresh exact-head CI/audit before merge.
Do not describe .31's historical audit as current policy acceptance. Details and
causal evidence: `output/continuation-20261030/` and ROUTING_RESEARCH.md.

[Preview .31](https://github.com/aiwaki/slipstream/releases/tag/v0.1.9-preview.31)
was published October 30 at 10:47 UTC by
[publisher41042305259](https://github.com/aiwaki/slipstream/actions/runs/41042305259),
attempt 1, release ID428916042. Independent verification passed all 24 conditions:
exact tag/source, signed manifest, all 12 asset sizes/digests, unchanged candidate,
previous `.30` archived by title only, and unchanged stable/latest identity/assets.
Actual release notes were updated and read back: manual DMG installation; public
preview auto-update and public upgrade/rollback explicitly remain unverified.
No new build, protected retry, or workstation installation was needed.

Exact-candidate evidence (all attempt 1; revalidated October 30):

| Gate | Result |
|---|---|
| CI40366566525 / audit40366566435 | Both passed on published source. Seven native Stop/Quit cases passed, four confirmed authorizations, no uncertain submissions or cleanup errors. |
| Readiness40370438338 | All five report attestations verified against the exact workflow/run/source. Four sites usable in Chrome/Safari; 1800-second background soak, stable daemon, advancing heartbeat and clean teardown. |
| Installed owned-Geph outage | Three requests closed without reaching the alternate system-route sentinel; owned HTTP 200 recovered. Disabled positive control reached the sentinel; settings restored and unrelated listener preserved. |
| Native-root40370445166 | Commit and crash-before-commit passed. OLD daemon restored after crash; late commit refused; terminal worker quiescent. |
| Packaged40372943574 | Real successor ACK commits. Pre-ACK stop/kill restores OLD app and daemon; watchdog exits and transaction paths are absent. All ten input pins and root prerequisite hashes match. |

Candidate artifact12670738202 remains available until November 9; manifest SHA-256
`9fcf9be84f199eed9dd178fa82333ae0bbc4cd2a4660df36052ef9513163a874`.
The OLD origin is the corrected **private** `.30`, source5385b89, run39465376685;
it is not the immutable public `.30`. These checks do not qualify public discovery,
ordinary tray/admin activation, sustained video/calls, or this new build on the user's Mac.
The historical Codex403 Ray remains unattributed.

Receipts: `output/readiness-preflight-20261026/post-pr424-main40366566525/`,
including each gate's `verification.json` and publisher notes/remote metadata.
Only small reports/manifests were downloaded locally. All full candidate authentication,
real network mechanics, and native update cases ran on disposable CI Macs.
The two used RSA exceptions were valid through October 30 UTC inclusive; future
release/audit work must revalidate policy rather than carry this preflight across expiry.

PR424 merged normally with tested/merged tree equality after PR/main CI. Its repair
accepts Darwin's legal initial `?` state without weakening ownership checks and retries
one fresh full census only for an otherwise validated ambiguous root basename. Unknown
still cannot authorize a signal or successful absence. Scoped checks: 98 root-stop,
12 affected cleanup/identity, 8 docs. Earlier main423 failed and is ineligible; its
exact historical census reason remains unknown. Details: ROUTING_RESEARCH.md and
`output/readiness-preflight-20261026/root-stop-census/verification.json`.

The continuation selected two unmerged PR376 repairs against current main:
the connection-race adapter could orphan its winner or skip later owned writers
when cancelled during cleanup; the HTTP completion parser treated a valid chunk-size
prefix ending in CR as unknown after EOF/timeout. Both now have causal failing tests
against the old source. The fix retains one shielded cleanup owner, transfers the
winner only after cleanup, and classifies a valid hex-plus-CR prefix as incomplete.
Malformed input stays unknown; no routing policy or cleanup deadline changes.
Focused results: 17 adapter/probe tests (including real loopback TCP), 11 parser
tests and 30 bootstrap classifier tests passed. Independent review found no blocker.
PR426 is open at `a1b1cf32df7c958a0323c18f69171585b52a092b`; GitHub checks
initial full CI41046195098 passed (including packaged browser/lifecycle), but
the dependency audit is blocked as recorded above. Eight documentation checks
also passed (66 focused checks total).
No new installed or live-site claim is made. Wait for exact-head checks before merge.

PR reconciliation is complete: all three old heads conflict with main, but all
13 Geph session/SQLite edits from PR384 already shipped via PR388. Its remaining
scope is source/build/audit tooling, with a separate RSA-only candidate requiring
fresh review and qualification; native SQLite research is not its prerequisite.
Telegram 1.11.2/H2 remains unmerged in PR386. PR376 also still contains pending
removal of the bundled xbox-dns.ru provider and broader response-recovery changes.
Do not reimport any old branch wholesale. Reports and red/green logs are retained in
`output/continuation-20261030/`; see ROUTING_RESEARCH.md for the two concrete repairs.
No graph tool is available, so discovery uses bounded direct diffs and source reads.

Next: finish the selected transport PR, then continue the reconciled candidate work
and separate public-update/workstation gates. Do not repeat unchanged release gates
or mutate the working connection.

### Owned Geph route continuity, 2026-10-25 (merged; installed-path regression next)

The installed-source geo handler allowed system-route fallback during owned
Geph cooldown/circuit/drain/unready states, explicitly covered by the old test.
The new policy retains persisted owned opt-in through those health transitions,
including temporary ownership loss, and closes the new connection rather than
changing its route. Explicitly disabled/unconfigured/global-off/external cases
keep the existing fallback. Existing bounded recovery and committed-stream
handling remain; Discord/YouTube stay local. See the October 25 decision and
routing research section for scope and superseded historical rows.

Causal evidence: the final regression cases against the original `8979935f6`
`tproxy.py` give **9 failed / 4 passed**; failures demonstrate the alternate
route, including identity loss during an awaited Smart DNS attempt. The initial fixed
traffic/config/documentation selection gave **117 passed**, and the initial
Geph/geo/monitor run gave **129 passed / 452 deselected**. After integrating
PR415, the current traffic/config/documentation selection gives **118 passed**
and Geph/geo/monitor plus affected DNS gives **147 passed / 445 deselected**.
The merge retains neutral Smart DNS admission and samples Geph identity after
the Smart DNS await. Tests include real
loopback TCP first flights through success → failure → cooldown → recovery,
no replay after committed payload, optional fallback, saved config transitions,
private bounded reads and no cross-user intent inheritance. Evidence:
`output/geph-route-continuity-20261025/` (`verification.json`, red and green
logs, original source copy). Independent review found no blocker and its 27
selected cases passed. A follow-up malformed-config case reproduces an
uncaught JSON `RecursionError` below the file-size cap (1 red), now treated as
unknown intent; all 20 configuration/ownership tests pass after that repair.

Independent merge review of `c6860b31b` passed: seven DNS/Smart DNS functions
remain AST-identical to main, route continuity is preserved, and no unrelated
source edits remain. Both README updates are published through PR417/418.
The requested third-party adaptive module is deferred in ROADMAP until the
cross-platform application is ready; no SDK or licensing work starts now.

PR419 merged through normal branch protection on October 25 at 17:35 UTC.
Exact head `35bcda44cdc5b82a34fabc8abc3937f93ed61c47` passed CI40215981048
and audit40215981047; merged tree `28b3659f90fb02787cbf5a2ea73bb8d9c3176d20`
equals the tested tree. Main audit40217202497 passed. Main CI40217202470 failed
at the native `root_lock_failure` authorization stage, before the expected
privileged lock failure. SecurityAgent remained open; the harness recorded
197 button submissions as confirmations. The root service remained active and
Geph was disabled in this scenario. The same Git tree passed all seven native
cases in PR CI, but PR and main packages are not byte-identical artifacts.
The underlying reason for unaccepted authorization is not established. Repair
the harness's submission/acceptance distinction and repeated-submit loop before
another run; do not weaken the deadline or infer a routing regression.
Receipts: `output/geph-route-continuity-20261025/merged-419.json` and
`output/geph-route-continuity-20261025/main-ci-failure/result.json`.

Coverage audit found that the real owned-Geph lifecycle kills and restores its
client only after the installed-daemon browser phase; it sends no new geo
request during that outage. The current branch adds a scenario
to the existing account-backed installed-daemon phase: successful owned
payload, backend outage, repeated requests with a separately observed system
destination, then owned recovery. A disabled-preference positive control must
prove that the system-destination observation works. Use the real staged Geph
client and a local original-destination sentinel. A synthetic Geph replacement
would fail production TLS canaries and distort recovery, so it is not used.
No production hook or daemon trust change is part of this test.

The branch also replaces repeated SecurityAgent submissions with one submission
and read-only observation. A dismissed prompt is insufficient: each case still
requires its fresh operation-specific completion within the original deadline.
The auth failure's original cause remains unknown; the harness now distinguishes
submission, rejection, disappearance and completion without exposing dialog text.

Scoped verification: the changed route/coordinator/semantic/auth harnesses plus
documentation passed **164 tests and 24 subtests**. Final deadline review then
added a remaining-budget subprocess bound and rejects payloads arriving after
the 90-second recovery deadline; its focused rerun passed **21 tests and 3
subtests**. Changed Python files compile, actionlint and diff whitespace pass.
Independent review covered ownership/cleanup and macOS PF ordering. Actual PF
controls and account-backed recovery remain unexecuted and required in CI.
No production code is changed by this harness branch. Reuse PR419's green
production regressions; do not rerun the local full suite or native build.

PR420 merged normally on October 26 at 07:59 UTC as
`27262b3b8c4c2874cfea815e982691aab5f667f0`. Head
`001a485f10f78df0de7c93c6d818a76cd1321dba` passed CI40287460303 and
audit40287460319; merged tree `e226dfe9ddcb4f0d3bd59e193f189ad7c0784faf`
equals the tested tree. All required checks and independent review passed.
The new single-submit authorization scenario and full native lifecycle passed.
Main audit40289194471 passed. Main CI40289194469 failed its Rust tray unit
step: `terminal_refresh_resets_only_for_a_verified_process_birth` expected an
error at virtual time 1730, but the nonblocking wrapper returned `Ok(_)`.
The captured log does not distinguish `Ok(false)` (busy lock) from `Ok(true)`.
Product source is unchanged in PR420. The wrapper explicitly skips a busy flock
before checking the episode deadline; the neighbouring virtual-clock test
already holds one lock to avoid fork inheritance from parallel tests. A bounded
real Darwin probe reproduced a CLOEXEC descriptor inherited before exec: after
parent close the lock stayed busy until child exit. This proves the reachable
skip, not the historical result's exact value. The current branch isolates only
the generation/budget test under one verified lock and preserves separate
nonblocking concurrency coverage. No product behavior or deadline change.
PR421 merged normally on October 26 at 08:37 UTC as
`94e48878598c2a2382cee7a368a6b69c62130d49`. Tested head
`a8be84a7943c0859f1f6948f92ccd0ead59961bd` passed CI40291991178 and
audit40291991175, including the repaired test, all 243 Rust tray tests and the
native lifecycle. Tested and merged tree are identical:
`1655b867fb2fc831ab93eda26d68cc32107042fa`. Main CI40293622775 and
audit40293622651 passed on that exact source; current main was rechecked equal.
Both authenticated manifest/provenance and all required checks passed.
Receipt: `output/geph-route-continuity-20261025/pr-readiness/merged-421.json`.
Receipt: `output/geph-route-continuity-20261025/pr-readiness/fork-flock-reproduction.json`.
The test-only repair is independently reviewed: a held lock now isolates the
seven generation/budget steps. An additional public-wrapper call at the expired
virtual time explicitly proves `Ok(false)` with unchanged marker bytes while
the lock is busy; the locked path must then return the specific `exhausted`
error. Setup skips unrelated real-time refresh. The separate concurrency test
is untouched. Everything outside this one Rust test is byte-identical to main;
rustfmt parsed the file and diff whitespace passed. No local Cargo/Tauri build
was run; the changed Rust test passed in PR CI.

Main CI40289194469 is terminal failure solely from that unit test (242 passed,
1 failed in the tray target). Native lifecycle, browser qualification, signed
candidate assembly and update notification passed. Do not use the failed run's
otherwise-built candidate. No account-backed dispatch yet.

The exact successful main candidate is source
`94e48878598c2a2382cee7a368a6b69c62130d49`, CI40293622775 attempt1,
artifact12637133533, manifest SHA256
`17b649e6adbb046d35132ea978bce97221b2eb6237e88459e75b389abbe0635e`.
Exact ci.yml/source/ref/run/attempt attestation passed; only 1499 archive bytes
were transferred to obtain the small manifest, not the full application.
At 08:55 UTC daily account budget was 0/3 with no active runs. One combined
`release-readiness.yml` was dispatched as **40295745334**; this is the first
account-backed attempt today. Do not duplicate or rerun it. Native root update
qualification **40295788607** runs independently on the same exact candidate
and authenticated private OLD5385b89add415c531276ba43f5c06c50293ffb17/run39465376685.
Both commit and crash-before-commit must pass with clean teardown, then dispatch
packaged app qualification with the same eight pins and successful root run.
Root does not depend on the readiness receipt, so these run in parallel;
publication waits for all required gates.
Readiness40295745334 failed at the fixture's first root-to-local-origin positive
control: zero sentinel TCP connections and requests; the failure receipt omitted
whether the returned route was owned or closed. No actual backend-outage probe
ran. Fixture/coordinator cleanup passed; soak was skipped. Do not rerun unchanged.
One of three account-backed attempts is consumed today. The current branch
replaces unqualified UID/tag isolation with an exact source/destination/port
exception shared by protected and no-account fixtures. Console clients bind
`::1`; unbound root controls must observe the owned alias as the kernel-selected
source. Root route/source/counts are preserved before assertions. The existing
CI PF smoke now requires direct sentinel delivery, console capture with exact
production NATLOOK, and root forwarding through a second sentinel connection,
with unchanged rules and exact cleanup. Its IPv4/IPv6 baseline is unchanged.
Only test harnesses and docs change. Independent reviews found no blocker;
47 route/PF-harness tests and 8 documentation checks passed.
Two new regressions fail against the old helper (missing control receipt and
acceptance of a wrong default source); both pass after repair. This does not
prove the exact historical tag/UID failure cause.
PR422 merged normally at 09:44 UTC as
`e1ae2c6e6f7cb639e260467bd743f0b9025c0cc0`. Tested head
`d6b67b81ed69ef89aac127dd28ab92d84b8bf1b4` passed CI40299464400 and
audit40299464376, including all packaged native lifecycle/browser gates.
Merged tree `409f1509c71ab5eb7207992b7a14cbd21d65c409` equals the tested tree.
Receipt: `output/readiness-preflight-20261026/pr422/merged-422.json`.
Its actual no-account Darwin PF preflight passed in CI40299464400: unbound root
direct and forwarded controls both reached the sentinel from the owned alias;
the console client was captured from `::1`, production NATLOOK recovered the
exact alias/18443 destination, and exactly two sentinel connections arrived.
Anchor snapshots were unchanged; the private isolation anchor was removed,
lo0 alias/skip restored and global PF unchanged. IPv4/IPv6 baseline probes also
passed. Receipt: `output/readiness-preflight-20261026/pr422/native-pf-proof.json`.
New exact-main CI40301843338 failed at the packaged native Stop-and-Quit/
admin-cancellation/partial-stop/reopen step; audit40301843379 passed. Product/PF,
build/signing/candidate assembly/attestation, browser and update notification
passed, but the overall failed run cannot qualify the candidate. Exact native
case/report is under investigation; no unchanged rerun or protected dispatch.
No local PF/build/runtime action. Account-backed outage/recovery is not yet
qualified. After full main CI success, authenticate the new small manifest,
recheck the complete daily attempt budget, then dispatch one combined readiness
and the native-root exact-pair gate in parallel. Packaged follows successful
root; publication waits for all gates. Do not reuse the older archive as NEW.
Publisher review confirmed that build-app.yml itself only consumes CI/audit/
combined-readiness pins, not root/packaged receipts. The operator must verify
both fresh root cases and both packaged cases with the same exact OLD/NEW pair
and clean teardown before dispatch. This existing release condition is not
satisfied by the old 94e488 root receipt. The private corrected .30 pair does
not prove the public .30 discovery/tray/admin/rollback path; release notes keep
manual DMG installation and the absence of Apple notarization explicit.
After normal merge, require the new exact-main CI candidate; preserve successful
94e488 native-root evidence as a functional baseline, not proof of a new archive.
Native-root40295788607 attempt1 passed both cases with exact pair pins and clean
teardown: committed NEW with progressing same-PID heartbeat, and forced-worker
crash restoring exact OLD; late commit preserves aborted. Packaged follow-up is
held until fixture repair/candidate choice settles, to avoid obsolete work.
Receipts/input maps: `output/readiness-preflight-20261026/`.
The standalone owned Geph workflow remains diagnostic only; no duplicate run. Do not install or switch the user's
external Geph during this source/CI step. Native/browser and account-backed
behavior are not qualified by handler fixtures; the exact reported HTTP403
remains unattributed.

### Network and updater observer follow-up, 2026-10-25

Source qualification checkout:
`/Users/aiwaki/.codex/worktrees/readme-humanizer/slipstream-codebase-audit-20260905`,
branch `codex/network-updater-followup`, with merged dependency PR416
`8979935f6afa60ba90025d925127d7b997fbc58f` (tree-identical to reviewed
`1661c15e5fb147036aaba94f829567d4702b36e8`). PR416 CI39994944972 and
audit39994944831 passed. The installed private preview31 remains source
`1f3ddcfb6ed912a22fb4d0d1502e3879aee9ee36` (the exact source is recorded in the
completed lifecycle section below); follow-up source is not installed yet.

PR415 contains the follow-up. Initial head
`4d9af272df6dcef799e7abc45572d33db1a1514c` passed all CI39953414580 jobs.
DNS/observer head `58a655ecc5ecf8dfe0624f1662c9d91807b1226a` passed product checks,
the packaged build and browser qualification in CI39958585602, but its heavy
lifecycle job timed out at `after-tray-restart:chrome` after the existing
45-second observation. The same-stage HTTPS/status/PF checks and all seven
native Stop-and-Quit cases passed. GitHub uses the unchanged exact system
passthrough. Missing failure-time navigation/status evidence prevents assigning
the cause; cleanup stderr is not proof of a preceding browser crash. One
failed-job rerun on this same head passed as CI39958585602 attempt2. This
establishes a non-reproducing failure, not its cause. No timeout or gate was
relaxed. Evidence:
`output/network-followup-20261023/lifecycle-current/triage-receipt.json`.

Audit39953414800 and pre-integration audit39958585705 failed only the Geph vendor
gate: a new October 23 advisory, RUSTSEC-2026-0385, affects ctutils0.4.3.
Existing RSA exceptions remain accepted; this is not an expiry or an error
introduced by the DNS patch. Merged PR416 repairs the dependency without a
waiver. Main producer39996042090 passed at source
`8979935f6afa60ba90025d925127d7b997fbc58f` and published immutable
`geph-vendor-0.4.3-r3` on October 23 at 17:47 UTC. On October 25, its lightweight
tag, all eight downloaded assets, strict manifest, reviewed source/lock/license,
SBOM, historical audit and stored SLSA/SPDX attestations were verified against
that exact source. Both universal architectures passed. Receipt:
`output/network-followup-20261025/geph-r3-verification/receipt.json`.
Integrated consumer `658b3018f06937822baf862034ec436c0347835d` passed
CI40191917905 (including the authenticated r3 build, browser qualification and
heavy lifecycle) and dependency-audit40191917902. All review threads were
resolved. After README PR417/418 merged, branch protection rejected the merge
solely because the branch was behind main. One update to main
`59576368b8b84bd36aac8c384d3a9a3cd3ba7f89` brings only both README changes;
the application and tests are unchanged. The green 658b results remain the reused
functional baseline. The final head `112068961b570b79531c64ed488bb08a0439fa70`
passed CI40195315520 and dependency-audit40195315455, then PR415 merged normally
as `2210366fadeab258f614135c8b933ed28ed14d9a`, tree-identical to that tested head.
README PR417/418 are also merged. Evidence:
`output/network-followup-20261025/integrated-ci-state.json`.
No old r2 binary is substituted.

Two causal repairs are in source, with independent reviews clear:
- Supplemental system DNS can stall even with ready DoH/original addresses.
  Reuse the bounded child and existing 1.5-second budget/64-worker capacity;
  retain admission through actual worker completion after timeout/cancellation.
  Old-path and queue-growth regressions fail before the fix; 34 related tests
  pass. Receipt: `output/network-followup-20261023/dns-stall-receipt.json`.
  PR review then exposed shared Smart DNS callers treating capacity exhaustion
  as a backend failure. The neutral/unobserved result now preserves their health
  and half-open permit. Causal failure reproduced; 38 resolver/canary checks and
  19 traffic contracts pass, with one test-only state-isolation recheck passing.
  Receipt: `output/network-followup-20261023/smart-dns-admission-receipt.json`.
- The pre-ACK observer rejected a transient real flock after an earlier OLD
  proof. Wait only inside existing deadlines, retain the exact false snapshot
  and recheck OLD before cleanup. 181 focused and 124 adjacent checks pass.
  Receipt: `output/updater-daemon-identity/watchdog-observer-race-20261023/receipt.json`.
  This does not prove the cause of the historical missing-diagnostic run.

The following runtime observation is historical (October 23): daemon PID2853
was active, with heartbeat advancing through2424. Physical Safari navigation
loaded YouTube including visible thumbnails;
a short played with seek position24%→54%. External Geph remained present and
untouched. The new DNS patch is not installed, and this current observation
neither isolates the backend nor proves the historical DNS/HTTP403 incidents
fixed. See `output/network-incidents-20261023/browser-observation.json` and
[ROUTING_RESEARCH.md](ROUTING_RESEARCH.md). Browser automation had first been
blocked by the locked Mac; the user unlocked it. No login/logout was attempted.

On October 24, the user reported another ChatGPT HTTP403 with Ray
`a4f85e142883efdb-ARN` while owned Geph was working, then quit Slipstream and
enabled external Geph. Fresh read-only checks on October 25 positively found
both owned launchd jobs absent, no Slipstream processes and only external Geph.
Preserve that working route. Owned Geph logs from October 24, 10:34:47–10:42:59
UTC, record ChatGPT tunnels and later broker/tunnel timeouts; the HTTP403 cause
is not established. This ARN Ray is separate from the earlier FRA incident and
the historical DNS failure. The October 23 PID/runtime snapshot is not current.
Investigation evidence: `output/network-incidents-20261025/` (receipt in progress).

The completed installed full-Quit/reopen qualification below is reusable.
Next: bind any new candidate to canonical bundle/install verification before
browser qualification; PR415 source integration is complete. No application was
built or installed locally, and no live service was changed for the integration.
Public updater transition/forced rollback and the HTTP403 incidents remain open.

### Geph ctutils dependency source repair, 2026-10-23

Separate source branch `codex/ctutils-constant-time-fix`, physical checkout
`/Users/aiwaki/.codex/worktrees/geph-rustls-02345/slipstream-codebase-audit-20260905`,
starts from main `934476dab7c5ff2e0a50bbee47641483c25ef465`.
PR415 audit39953414800 found newly published RUSTSEC-2026-0385 on unchanged
ctutils 0.4.3. The r3 source contract pins minimum fixed 0.4.4, changing only
its lock version/checksum, SOURCE lock digest/revision and the two existing
RSA reason identities. No exception or expiry is added or extended.
Both Apple-target locked metadata resolutions, canonical extraction/transition
and 70 focused tests pass. One bounded local scan of all 423 identities passes
with zero blocking findings, two existing RSA exceptions and three informational
notices, including new tokio RUSTSEC-2026-0386. This is local input evidence,
not exact-head CI or a native build. The independent source/policy review found
no blocker. Full evidence: `output/ctutils-constant-time-20261023/`; details and
source hashes: `docs/ROUTING_RESEARCH.md`, ctutils constant-time repair.

PR416 merged as `8979935f6afa60ba90025d925127d7b997fbc58f`, with the same tree
as reviewed `1661c15e5fb147036aaba94f829567d4702b36e8`. CI39994944972 and
audit39994944831 passed. Producer39996042090 also passed and published r3; the
complete downloaded release and stored attestations are verified as recorded
above. The authenticated integrated PR415 consumer remains to be qualified.
No new application installation or live service action has been performed;
this dependency repair does not establish the cause of Safari/Codex failures.

### Full Stop-and-Quit continuation, 2026-10-23

Latest verification: PR412 merged normally as
`1f3ddcfb6ed912a22fb4d0d1502e3879aee9ee36`, tree-identical to tested
`cf5f51fffa86c8558a78f328b897e5526d26a19b`. PR CI39919315756 and
audit39919315789 passed; all five review threads were reconciled and resolved.
Main CI39921259477 and audit39921259555 also passed in full, including the
signed/attested candidate, seven native Quit cases, previous packaged lifecycle,
browser and update-notification gates. The exact-main candidate was authenticated
(production updater signature, exact GitHub provenance, canonical tree/modes and
codesign) and copied to `/Applications/Slipstream.app` as `0.1.9-preview.31`.
Installed canonical verification and strict codesign passed; retained Geph
configuration is byte-identical. Authentication and install receipts are in
`output/stop-quit-20261023/candidate-verification/authenticated-1f3ddcfb6ed912a22fb4d0d1502e3879aee9ee36/`
and `output/stop-quit-20261023/local-install-1f3ddcfb6/`.
The checkbox crash regression fails three cases on the old block and passes
all four after saving/readback of enabled=0 before cleanup. All 25 observer
tests and eight documentation checks pass. Evidence:
`output/stop-quit-20261023/geph-disable-crash-receipt.json` and `seventh-native/`.

Checkout at that completed qualification: `/Users/aiwaki/.codex/worktrees/readme-humanizer/slipstream-codebase-audit-20260905`,
then branch `codex/geph-quit-install-verification`, based on the merge above. The user
quit and deleted the old app because Geph remained. The private `.31` candidate
is installed and the real workstation lifecycle now passes:
- User selected Restart Proxy and confirmed macOS; `started-userland.json`
  validates the production userland attestation/witness, root PID91870 and fresh
  active health with heartbeat 683→685.
- User selected the real full Stop-and-Quit and confirmed macOS;
  `stopped.json` proves both owned launchd jobs absent, no owned-path processes,
  no stop residue, and durable `stopped` intent. No CLI stop or disposable
  harness was substituted for the actual menu action.
- Ordinary opening of the canonical Applications app resumed it;
  `reopened.json` validates a new root PID2853, fresh advancing heartbeat,
  the production attestation/witness and cleared stop intent.
- All four external Geph PID/UID/path identities were preserved throughout.
  Owned Geph was explicitly off; this local sequence does not qualify an
  account-backed owned Geph tunnel or its live shutdown. Disposable native CI
  separately covers owned listener and pre-listener cleanup.

Retained Geph configuration is byte-identical after the full cycle. Combined
receipt: `output/stop-quit-20261023/local-install-1f3ddcfb6/lifecycle-result.json`;
individual observations are in the same directory.
The root-only CI attestation function cannot resolve the protected runtime
path as the console user; the read-only observer instead uses the production
userland root receipt/hardlink-witness contract. CUA can launch the exact app,
but accessibility selection still times out (-10005); the user supplied both
real menu actions. That installed UI gate is now complete. Preserve state,
private evidence and backups; do not stop external Geph.
Historical Safari DNS and Codex HTTP403/reconnecting remain separate,
unresolved incidents; these lifecycle results do not establish their cause or
repair. The private `.31` installation is not a public release, public updater
transition/rollback qualification, or completion of the broader AUD-17 work.

### Completed implementation evidence (historical sequence)

The intermediate failures and follow-up actions below are retained history.
Current qualification and remaining work are recorded above and in
Next Verified Action / External Gates, not in those intermediate instructions.

Dependency PR413 merged as `922973ef38d5d6d7ae2659bb9c12dc96af6f3b94` with the
same tree as tested `e8d03e2aeb0d3a6ac853a804e41c39840353613d`.
CI39896354602 and audit39896354628 passed; independent patch review found no
blockers. Main producer39897443338 published immutable `geph-vendor-0.4.3-r2`.
Main audit39897443478 passed. Main CI39897443322 attempt1 reached package
fetch before the new release existed (HTTP404); only failed jobs were rerun
after producer success. Attempt2 passed, including the authenticated consumer,
native packaging, browser and lifecycle checks. Its consumer verifies
assets/provenance/SBOM/audit.
The source repair updates certifi and both WebPKI dependencies; it is not a
claim that the historical DNS/HTTP403 incidents were caused by certificates.

PR412 adds preserving root `--stop` under the existing lock, exact launchd and
owned-process absence checks (including pre-listener orphans), and bounded
post-KILL confirmation. Its ordinary Quit now waits for root then Geph stop,
records stopping/stopped intent, retains settings, and resumes on ordinary
opening after a completed stop. Login keeps the stopped state. Source review
caught and repaired dormant/VPN readiness and old login registration handling.
Root checks: 69 focused, 23 teardown compatibility and 11 updater cases passed;
12 isolated Rust lifecycle cases passed. Graph tools were unavailable; bounded
direct reads were used. Evidence: `output/root-stop-20261023/` and
`output/stop-quit-20261023/`. Integrated source `2b38afd2370aa7d53f6debff2c626033caf0e9a5`
passed CI39899304752 and audit39899304760, including native compilation,
packaged browser and the existing lifecycle checks. The new disposable native
smoke adds actual tray Quit, SecurityAgent Cancel, installer-lock failure,
partial cleanup failure, successful retry, stopped login and ordinary reopen.
First native run39901792294 at `ae35257fb` passed build, browser and the
previous lifecycle smoke, but failed the new case: native Cancel was not
observed. The report has no confirmed cases and cleanup passed; it does not
establish whether the product or accessibility observer failed. Preserve
`output/stop-quit-20261023/first-native/`; add bounded phase/UI diagnostics
before retrying. Audit39901792141 passed.
The diagnostic head `22a5fc27233971acffda6ab66302df59216bd3dd` passed
build/browser/previous lifecycle checks in run39904820801, but native Cancel
still failed. This time the receipt proves intent=stopping, a live owned tray,
one owned administrator osascript, and one SecurityAgent window with the exact
prompt plus unique Cancel and confirmation controls. The observer returned
absent despite that UI. Repair its traversal/matching to use the proven bounded
snapshot; do not call this a product failure or successful Quit. Evidence:
`output/stop-quit-20261023/second-native/`. Cleanup passed.
The observer now shares explicit indexed AX traversal and separated static
value/name collection with that snapshot, with exact prompt, unique window and
unique button guards. All 23 observer/containment tests, Python compilation,
three generated AppleScript syntax compilations and bounded review passed.
Native Stop-and-Quit runs before the unchanged packaged lifecycle smoke; both
remain mandatory. Run39906999203 at `7d593267614b0f17199424b73f867715c3158452`
passed native Cancel, real installer-lock failure, partial Geph failure, actual
menu Quit, native pre-listener orphan cleanup with the external sentinel alive,
and stopped login. It failed ordinary reopen: root `--install` returned success,
but production `wait_ready(false)` rejected readiness; the app retained the
pending intent and stayed open. No Geph restart was attempted. The receipt does
not identify the rejected predicate, so retain the same readiness requirements
and 45-second bound while adding a bounded final rejection reason. Evidence:
`output/stop-quit-20261023/third-native/`; cleanup passed. Other applicable
product/build/browser checks and audit39906999405 passed. The previous packaged
lifecycle smoke was skipped after the native failure, not newly qualified.
The next head adds a fixed readiness rejection label and bounded state/PID/seq
context to the final Resume error, preserving all predicates and the 45-second
bound. Failure-only snapshots retain selected status/attestation metadata before
cleanup; a fresh terminal Resume error ends the observer wait immediately.
Three actual-source isolated Rust cases, 24 observer tests, eight documentation
checks and focused formatting/compilation passed.
Run39910205318 at `fdfa52d25f43b76546d8ae1b74d9b75e237824fa` establishes the
reopen cause: `live-attested-state-mismatch`, retained dormant/PF=false versus
live active/phase=active on the same PID6218 with sequence28, then30. The six
preceding native cases and cleanup passed again. Product/build/browser checks
and audit39910205319 passed. Evidence: `output/stop-quit-20261023/fourth-native/`.
The targeted repair uses the existing root-published PF health sample and its
separate `health_updated_at`, rather than comparing live health to the frozen
install receipt. Runtime identity, label, heartbeat progression and the original
45-second bound remain required. The old helper failed the causal transition
case; the repair passes 18 actual-source isolated Rust cases, including both
health transitions, cached heartbeat rejection and missing PF/health through the
real projection. Eight documentation checks and focused formatting passed;
bounded independent review found no blockers. Evidence:
`output/stop-quit-20261023/health-transition-{red,green}.log`.
Run39912212960 at `531c1abd25f485e1548b896c504684a349e0a476` passes all seven
native cases, including ordinary reopen with a fresh daemon and retained
preferences; cleanup is empty. Product/build/browser checks and audit39912212924
pass. The following pre-existing packaged lifecycle smoke fails before spawning
Chrome: `ValueError: too many extra_groups` at pending-navigation:composed-original.
The harness passes the full `os.getgrouplist` result to CPython's bounded
`Popen(extra_groups=...)` API. The runner's before/after group membership was not
recorded, so do not attribute this to the temporary native-test administrator.
Product probe launches use an empty supplementary-group tuple and are outside
this failure. Evidence: `output/stop-quit-20261023/fifth-native/`.
The harness now explicitly clears supplemental groups, matching its tray and
production probe launches, while retaining the original UID and primary GID.
Its profiles belong to that UID, its password store is basic, and its signal
permissions depend on UID; directory group membership is not required. No
root trampoline or group slicing was added. The causal oversized-membership
regression and all 193 affected lifecycle/Chromium/live-site cases pass; Python
compilation and diff-check pass. Evidence:
`output/stop-quit-20261023/group-limit-{red,green}.log` and
`group-limit-receipt.json`. The later complete exact-main lifecycle gate
passed; see the current verification at the top. No repeat is pending.

Review then confirmed a separate pre-listener Geph orphan defect: the private
record exists before bind, but stop required the SOCKS listener. Stop now checks
fresh PID/UID/executable/config instead; the old guard failed its causal test,
then all 27 Geph lifecycle tests passed. A read-only native probe confirmed the
macOS process format. The smoke now also stops a real inert owned native child
without any listener through actual Quit; its 17 containment tests passed.
Evidence: `output/geph-orphan-stop-20261023/`. Geph networking is disabled in
this fixture, so it does not qualify an account-backed tunnel.

The native Stop-and-Quit smoke and the installed application cycle above are
complete for source `1f3ddcfb6ed912a22fb4d0d1502e3879aee9ee36`. Reuse them.
Public preview30 stays immutable. The old preview31 candidates with outdated
trust dependencies remain unsuitable; the new authenticated, privately installed
preview31 includes merged PR413 and its passing audit. This does not publish it
or close ordinary public update/rollback and remaining packaged observer gates.
The historical DNS error and Codex403 remain unresolved without live evidence.

### Earlier incident evidence (superseded status; retained for traceability)

2026-10-22: current incident work is in the physical checkout
`/Users/aiwaki/.codex/worktrees/readme-humanizer/slipstream-codebase-audit-20260905`,
branch `codex/geph-stop-doh-fallback`, based on
`e918906069dddc722aa0c6283b94c1a16af8954e`.
The user removed Slipstream after ordinary Quit left background processes.
Live read-only checks confirmed that `/Applications/Slipstream.app`, the owned
root and user launchd jobs, their plists, and StatusV2 are absent. Only the
separate Geph application was running. Do not reinstall or stop that external
application as part of diagnosis. Prior app/state backups remain retained.

Safari initially had a blank loading YouTube page and subsequently rendered
the homepage without an agent refresh. System resolution of the exact hostname
was successful at observation time. This does not establish the cause of the
earlier "Cannot Find Server" screenshot. Codex logs contain generic HTTP403
responses, but neither the block rule nor the historical route is established;
the screenshot's exact Ray ID was not found. Root daemon logs need administrator
access. Read-only evidence and focused DoH red/green receipts are under
`output/incidents-20261022/`. See troubleshooting notes for the separate failure
boundaries. Source fixes cover a failed DoH endpoint aborting the fallback loop
and unverified Geph shutdown being reported as off. DoH regressions reproduced
five failures before repair; all 11 focused Python cases then passed. Two old
Geph false-absence cases reproduced; the initial pure Rust boundary passed 11 tests.
PR412's initial head is `b95447010296f61e60ce39216c04992fd9557623`.
CI39828244399 passed product checks, native packaging, browser qualification
and packaged lifecycle. The independent audit39828244341 failed on newly
published emSign advisories in unchanged dependencies: `certifi 2026.6.17`,
`rustls-webpki 0.103.15` and `webpki-roots 1.0.9`; the latter two also affect
the pinned Geph source. Fixed versions are `2026.10.19`, `0.103.16` and
`1.0.10`, respectively. RSA exceptions were accepted on the evaluation date.
Do not repeat this unchanged audit or waive it. A separate coordinated
dependency/vendor update is required; the current source-bootstrap contract
does not yet admit the exact transition. The retained `.31` candidate contains
the same affected versions; its older green audit is not a review of these new
advisories and is not sufficient to resume publication. Evidence:
`output/incidents-20261022/ci-audit/analysis-receipt.json` and
`output/incidents-20261022/pr412-first-head-ci.json`.
Review follow-up adds the final process observation after its last wait and
guarded quarantine of malformed legacy ownership records. It covers both old
and current client layouts, preserves exact bytes and rejects unknown/live
process state, changed files and symlinks. The final-wait regressions reproduced
two failures before repair; all 23 Rust helper/filesystem tests pass, along with
formatting, diff whitespace and independent review. Logs are in
`output/geph-disable-20261022/`. A read-only native process census exposed
Darwin's signed rendering of some system UID values. The parser now normalizes
the signed 32-bit representation without skipping identity or completeness
checks. The same native probe then returned `Clear` across 544 process rows;
no process arguments were logged and no live cleanup was performed. Fixtures
also cover signed bounds, overflow and the current-process identity witness.
The unchanged DoH subset remains 11/11 green.
CI39835124312 also passed native product, packaged browser and lifecycle checks
at `3bac4b075850cac514b101c6a76c29a1238150e0`; receipt:
`output/incidents-20261022/pr412-second-head-ci.json`. The final signed-UID
correction at `a51383ba8b6b36b1186c1e8b71b7186eee090388` passed CI39837144364
(native product, packaging, browser and lifecycle checks). Its receipt is
`output/incidents-20261022/pr412-final-head-ci.json`. Audit39837144381 still
reports the same three affected dependencies, with both Rust dependencies also
in Geph; exact reports and summary are retained under
`output/incidents-20261022/final-head-audit/`. Installed
UI and the historical screenshots remain unqualified. Crash interruption before
the final preference save can retain enabled intent; no crash-atomic disable
transaction was introduced.
The menu-only exit now explicitly says routing continues; no full-stop action
was added. These fixes are not installed. Graph tools were unavailable;
discovery used bounded direct reads. PR412 is open and unmerged: required audit
remains red despite green product CI. Next: a separate coordinated dependency
update, preserving the Geph source and lock provenance contracts. Keep the
retained `.31` candidate and its outstanding observer gate separate. This final
post-CI checkpoint is local and uncommitted; production source is the pushed
`a51383b` head. Do not repeat unchanged green product checks merely to commit
this status update.

PR411 merged at `e918906069dddc722aa0c6283b94c1a16af8954e`; its tree matches
tested head `5fd85aa9dbe2176c3f2788fd5b3f60aad1d23174`.
CI39472457430/1 and audit39472457537/1 passed all required checks; review
threads were empty. CI receipt SHA256
`81debb249ae1834e9cdf43204c0e8fbccaf268fa8ccf0cabdf8c7c520b9bbf7e`,
merge receipt SHA256
`92c17eb5d972f706bd1cff1a638da2af45f162af3eccdc284b6284a531bd2734`,
both under `output/updater-daemon-identity/preview31-preparation/pr411-verification/`.
Exact-main CI39474188992/1 and audit39474189024/1 passed. The signed
`.31` candidate authenticated with full-tree verification and codesign; receipt
`main411-preview31-verification/receipt.json` SHA256
`6fe5cc986c42dcaabea871a7ce336994c6df8b780a14f937bee8f4e3f3434cf5`.
Manifest SHA256 `c972c8f3b731ad997fa9f6ace7155e639116808bc74a913ac2f7f617232d6d83`.
Native root run39477202342/1 and protected readiness39477208645/1 were
dispatched once from exact main at18:43Z. Inputs and the refreshed daily budget
are recorded in `output/updater-daemon-identity/preview31-pair/dispatch-receipt.json`.
The readiness run is the second account-backed dispatch of2026-10-20UTC.
Native root both cases passed and their authenticated proof receipt is
`preview31-pair/root/receipt.json`, SHA256
`52cdbd89180bbc488f49e22c6a992e384be2b29fdbcbad8ba469dff28c53ef1d`.
Packaged app run39478010009/1 failed its successor-kill cleanup with
`rollback watchdog is not terminal`; its commit case passed. Earlier events
showed terminal watchdog, restored OLD tree and progressing OLD heartbeat,
but the final false predicate was not persisted. Do not relabel this failure
as a pass or claim the proposed transient lock contention as its proven cause.
Authenticated receipt: `preview31-pair/app/receipt.json`, SHA256
`6f4f534d47a9a91a92745c94dea9e561c4178821281c00466b8b16efe231cb57`.
Protected readiness39477208645/1 completed successfully at2026-10-20T19:18:50Z,
confirmed through GitHub on October22. Its final artifact authentication is
still pending; do not repeat the account-backed run. No watchers remain active.
No publisher or packaged-pair retry has been dispatched. Publication remains
pending. Reuse retained candidates and unchanged proofs. Observer-only fixes
and production changes need separate evidence; do not overwrite the candidate.
Post-install runtime receipt:
`output/updater-daemon-identity/main410-fixed-origin-verification/installed-runtime-receipt.json`,
SHA256 `6be7b031348fa86fd54a94c2e56051dd6cc4b07a0ccbee3c0649b0eac3d4068f`.
It binds canonical installed verification to root attestation and its hardlink
witness, exact tray/daemon identities and active heartbeat202 -> 204.
This receipt records the October20 installation, not the current workstation:
the application was removed by the user on October22. The earlier tray CUA
timeout is historical; Safari UI access worked during the October22 diagnosis.

### Historical dependency-source checkpoint before PR413 merge

The active dependency checkout is
`/Users/aiwaki/.codex/worktrees/geph-rustls-02345/slipstream-codebase-audit-20260905`,
branch `codex/emsign-dependency-update`, based on main
`e918906069dddc722aa0c6283b94c1a16af8954e`. Earlier installed-state paragraphs
below are historical: the user quit and removed Slipstream on October 22
because its Geph processes remained. Last read-only observation found no
installed app or owned root/user jobs; standalone Geph is external and untouched.
PF absence was not established. Preserve all previous apps, state and evidence.

PR412 remains open at `a51383ba8b6b36b1186c1e8b71b7186eee090388` in the
separate `readme-humanizer` checkout. CI39837144364 passed native product,
packaging, browser and lifecycle checks. Audit39837144381 found new emSign
trust-store advisories in certifi, rustls-webpki and webpki-roots. Its code
fixes confirmed Geph shutdown and a DoH fallback exception boundary, but its
Quit label change does not implement full shutdown. Full Stop-and-Quit work
is separate and unfinished; neither that behavior nor PR412 is installed.

This source-bootstrap repair changes certifi 2026.6.17 to 2026.10.19 in all
three Python locks, rustls-webpki 0.103.15 to 0.103.16 and webpki-roots 1.0.9
to 1.0.10 in both affected Rust locks. Geph remains 0.4.3 with the same crate,
13 source edits, features and targets, advancing only to immutable revision 2.
Registry archives/hashes and the fixed certifi trust bundle were checked.
Locked metadata passed for the app and both Geph Apple targets. Five focused
TLS/context tests passed using the fixed wheel. An old-bundle control accepts
emSign ECC Root CA-G3; the fixed bundle rejects it while retaining three
unaffected emSign roots. These are local checks, not installed qualification.

Fresh static RSA review supports only the two existing rsa 0.8.2 client-path
exceptions through 2026-10-30, bound to exact r1/r2 SOURCE, locks and policies.
See ROUTING_RESEARCH.md. All163 focused source/audit/build-contract checks
passed, and the canonical source-transition verifier accepts the actual
base/current files. Fresh dependency audits, patch review and source PR
checks remain pending. After merge, authenticate `geph-vendor-0.4.3-r2` from
the main-only producer before packaging. The public preview30 stays immutable;
preview31 delivery, ordinary update/rollback and full shutdown remain open.

### Historical delivery checkpoint

### Historical delivery checkpoint


Delivery resumed on branch `codex/preview31-updater-delivery`, based on main
`5385b89add415c531276ba43f5c06c50293ffb17`, in the physical checkout below.
Its exact-main CI39465376685/1 and audit39465376697/1 are already green.
CI produced signed candidate `release-candidate-5385b89add415c531276ba43f5c06c50293ffb17`
(artifact12285485917). Authentication passed: pinned canonical verifier,
production updater signature, GitHub provenance, complete staged app tree,
archive modes and codesign. Receipt:
`output/updater-daemon-identity/main410-fixed-origin-verification/receipt.json`,
SHA256 `0db64df877713f51efc2e9d22bf521aea40caff70aed01847aa312a867b94caa`.
Manifest SHA256 `f73109946205e4b0ad11568850473feafe502ff46e8c523c30eecaa0d2983696`;
daemon SHA256 `e1eca39ef0b07f6b7890f35e86e225c03d32f6fcdcc294cbf7fe8ec685968e96`.
The ordinary `.31` successor changes version metadata, publisher admission
and the exact packaged pair admission (`.30 -> .31`) with matching reviewed
observer-source pins. Three version contracts and111 pair/source-proof tests
passed. No production behavior change beyond the daemon version constant.
No local native build.
The fixed origin is now manually installed at `/Applications/Slipstream.app`;
the copied canonical bundle verifier and codesign passed. Normal app startup
replaced the owned daemon. Fresh StatusV2 reported active PID80303,
heartbeat39; root attestation matched the fixed daemon SHA above. Tray PID80188
runs at the canonical path as uid502. These PIDs are observations only.
The actual previous public `.30` app and user state are retained at
`output/updater-daemon-identity/main410-fixed-origin-verification/local-install-backup/`.
Installation receipt: `main410-fixed-origin-verification/manual-install.json`
under the same evidence base. The ordinary updater transaction was absent;
the earlier root operation was durably aborted/quiescent with its worker exited.
This was a manual bridge install, not ordinary updater or normal Quit proof.
Next: qualify the exact pair and publish/test `.31` under the recorded release
gates. Private-bridge and public-pair evidence remain distinct. Preserve every
previous app/state backup and private receipt.

PR410 is merged at `5385b89add415c531276ba43f5c06c50293ffb17`, with the same
Git tree `4bfa0a784fc05d06985ab73a9c7cdd1001723591` as tested head
`f24dd9cc1f2fedb96044df976e6f69786173df4a`. CI39463378717/1 and
audit39463378736/1 passed all three required contexts, including packaged
browser/lifecycle and11 Rust adapter tests (all six new regressions passed).
Final independent review had no blockers; all three PR review threads were
resolved. Local evidence directory below contains `pr410-final-ci-receipt.json`,
SHA256 `e7dab40c2fe3c9e498f60a7d7413282b10f59d4a346c1bef034e4ce38a4a6f67`,
and `pr410-merge-receipt.json`, SHA256
`b1af8d9a14943f5ae810623658241231ded3309961f41780269a505bee535778`.
This final post-merge checkpoint is local; no further product change or repeat
of the green suite is needed merely to publish the checkpoint.

Public [preview .30](https://github.com/aiwaki/slipstream/releases/tag/v0.1.9-preview.30)
was previously installed at `/Applications/Slipstream.app` on the user's Mac by manual
replacement from its verified public artifact. Normal launch installed the
matching root daemon. Fresh StatusV2 reported version `.30`, active daemon
PID46244 and increasing heartbeat; launchd and the root attestation/witness
matched daemon SHA256 `364a138776fc4ffa0872426c105dfc5f8ffd86118442a1b20de4219ef6210069`.
Canonical full-tree verification and codesign passed. The tray is PID45868,
uid502, at the canonical path. Recheck live state before a new action; PIDs are
observations, not permanent identities. This is manual delivery, not successful
automatic update or physical browser qualification.

Private local evidence:
`output/updater-daemon-identity/local-attended-20261020-204654/installed30-runtime-receipt.json`,
SHA256 `ba9b27a5afaa006a2ab03d5f76f833771a904764c2b15e771070803f33e160e6`.
Direct root-runtime bytes were not reread as the console user; the proof binds
the verified app payload to root attestation, hardlink witness metadata,
launchd identity and two fresh heartbeat samples.

The public release source is `86dd9393f671120f9ad6adb887ebb0e29d56467b`.
CI39414812044/1, audit39414812025/1, root commit/rollback39417619778/1,
packaged app39418547089/1 and publisher39422953280/1 passed.
Readiness39417627050/1 passed eight Safari/Chrome cases, transport3/3 and a
measured1800.114-second soak with cleanup. All12 public assets passed canonical
hashes/signatures/archive/appcast checks; seven candidate files matched CI.
Public receipt: `output/updater-daemon-identity/preview30-public-verification/public-verification-receipt.json`,
SHA256 `1dd881ff2d34847b045a65d8717daa75ed7eb2f54732168ecf9dc622806590c0`.

PR409 is merged at `6ce1534714ba570eb374901c517bfb740c72c5fb`, with the same
tree as tested head `c16a2f901c21f380251a4b29ac331d404e1f33a2`.
CI39447367306/1 and audit39447367341/1 passed all three required contexts,
199 tray tests, packaged browser and lifecycle/crash checks. Reuse this baseline
for unchanged components. Receipt:
`output/updater-daemon-identity/archive-modes-fix/pr409-c16a2f901-ci-receipt.json`,
SHA256 `6890e2d547c0bcd262bb7eeccc157edec29cd077f4b5c2aa95830f9bc95a2da3`.
PR409's extraction-permission fix and the startup repair below are not in `.30`.

## Current Change

### Attended update and worker startup, 2026-10-20

Active physical checkout:
`/Users/aiwaki/.codex/worktrees/readme-humanizer/slipstream-codebase-audit-20260905`.
Branch `codex/updater-worker-startup-lease`, based on merged PR409 above.
The historical root checkout remains a locator with its dirty files preserved.
The user explicitly authorized this local attended check. No local native build.
Standalone Geph remains external and untouched. Original `.23`, actual `.29`,
user app-state and all earlier private backups are retained under the local
evidence directory above and at their previous locations.

The user's ordinary `.29 -> .30` update/admin attempt failed safely:

| UTC event | Observation |
|---|---|
| 16:05:07.281 | Root prepared operation, worker PID0. Administrator authorization succeeded. |
| 16:05:17.263 | App selected abort, sequence1, after about10 seconds. |
| 16:05:22.783 | Validated worker PID40061 appeared and accepted the abort. |
| 16:05:22.986 | Root terminal aborted, writer quiescent; `.29` daemon remained active. |
| 16:05:25.226 | App journal cleaned. No successor ACK or replacement occurred. |

Operation `7e495bea6b34a9ce8bfa8790bade5758` had an original deadline of
16:09:47Z: about270 seconds still remained when cancellation was sent. Source
confirms that prepare waited only10 seconds, while the worker publishes its
PID after sealed-runtime/app validation. The observed publication took15.5
seconds; individual hashing/signature costs were not profiled. No worker crash
or restart loop was observed. Retain `events.jsonl` and `observations/` in the
private local evidence directory. Its observer ended before manual `.30` launch;
the separate runtime receipt above uses fresh post-install samples.

The source fix gives preparation and validated worker startup the remaining
original lease, bounded by both its wall deadline and a monotonic deadline
anchored before sealing. It does not publish PID early, bypass signature/hash
checks or alter production Rust uncertain-authorization/abort handling.
Regression evidence: old source6 expected failures; repaired module115 passing,
adjacent lock/mailbox/native-root tests59 passing; strengthened terminal cases2
passing. Results were captured in tool output, not standalone log files.
Initial independent review found no blockers. [PR410](https://github.com/aiwaki/slipstream/pull/410)
head `06651c55f4462c7c8a5a7d17b985247b094ba173` passed CI39458986680/1 and
audit39458986897/1, including all three required contexts. Receipt in the same
private directory: `pr410-ci-receipt.json`, SHA256
`e83d0083fbe80325680e84ec591b4fbc9784eabcce69c1435e0b08dfaf2a8f38`.

PR review then found that the local monotonic bound did not survive handoff to
the worker: it recomputed a deadline after validation, allowing a backward wall
clock change to extend an undecided operation. Sealing could also publish after
the original monotonic budget expired. The follow-up persists a root-generated,
manifest-bound boot-session identity and monotonic deadline in the private
journal, checks them before publication and first activation mutation, and
preserves them across retries. A changed boot session or invalid/missing lease
aborts an undecided operation; durable commit/abort still completes. Legacy
terminal manifest hashes remain unchanged. Boot identity is not polled per tick.
The disposable packaged trigger also replaces its separate90-second timeout
with the remaining original lease and a distinct five-second cleanup bound.
Final focused verification passed136 daemon-update tests plus59 adjacent tests
(195 total,2.37s), with12 existing packaged-trigger Python tests and rustfmt
passing. Six new inert Rust trigger tests run in the existing CI adapter job.
The focused log is `output/updater-daemon-identity/worker-startup-lease-fix/private-lease-final-tests.log`,
SHA256 `3e958e5e479d537f8a7545ddaee9b0e8ae77cc4fefa336e38163f0cce8f5e4e7`.
Independent review of both follow-ups found no blockers. Final exact-source CI
passed and PR410 merged as recorded above; the initial-head receipt is retained.

The old `.23 --quit` returned without ending its process; only its verified PID
was terminated after owned service absence was established. `.29` was later
terminated only after its failed transaction was proven aborted/quiescent.
Neither action qualifies normal Quit. Native UI automation timed out; the user
performed Restart Proxy and the ordinary update/admin action. Do not repeat the
known-stalled unattended hosted authorization path. Public update/forced rollback
and normal Quit remain open; manual `.30` installation does not close them.

Next: carry merged PR409 and PR410 into a normally built originating
candidate before qualifying another public update. A successor alone cannot
repair the worker sealed from an older origin. Do not start another workstation
replacement or broad suite merely to restate these limits.

### Retained preparation record

PR403 merged the PF/status observation repair at
`01fcd4c7d91043e58d7c777ebfc4a94264caa5fa`. Its tree is identical to tested
head `8959af1bc75a896c1fea91dbd8e9719c12487c31`; whole CI39384063074 and
audit39384063098 passed, including installed lifecycle and packaged browser
qualification. All three required checks passed; review threads were empty.
Receipt `pr403-verification/receipt.json`, SHA256
`ed6e6f8edd49951065e4964ba66e1f908ccae02747381572f5ba427da9405c62`;
merge receipt SHA256
`2fec23ac4afecb4b16d83b8e7129e59a524b6a391343dbbaa8a74a5ede424307`.
Evidence paths here are relative to `output/updater-daemon-identity/`.

The corrected `.28` exact-main CI39385463713 and audit39385463601 are running.
One owner watches them and authenticates the signed candidate using source
helpers pinned to `01fcd4c7`, not the mutable checkout. Its final receipt is
not available yet. The earlier `.28` artifact from main400 predates this fix.

This change prepares the ordinary `.29` successor with `scripts/sync_version.py`:
VERSION plus the existing tray/daemon version inputs and generated metadata.
It changes no routing logic or dependencies. Preparing its PR and CI in parallel
saves a serial build wait; merge remains conditional on a fully qualified
corrected `.28` origin. Version equality or a green PR is not a signed-candidate
proof. Authenticate the `.29` exact-main candidate after merge, then run both
root modes followed by both app modes on the same complete pair at NEW source.
No native transition has passed for the corrected pair yet.

Retain the older candidates and authenticated receipts, without redownloading:
- corrected mailbox `.27`, `main402-verification/receipt.json`, SHA256
  `b2c031ec2e6eff9958b0d555e14e96452c1f92c5d48829c77e7282898fb43264`;
- pre-readiness-fix `.28`, `main400-union-verification/receipt.json`, SHA256
  `c43da2633929a249b27a61363524b916e119e72629157ada8317811fa6b3fc58`.

Native root run39381512115 attempt1 used this exact `.27 -> .28` pair at
pre-repair main `6eac5d34`. Crash-before-commit passed; commit failed in the read-only
observer after NEW readiness, before any commit request. Both cases cleaned
up without errors. The commit observer reported `daemon PF state mismatch`;
the run did not retain the two sampled values, so their direction is unknown.
Receipt `root27-to28-qualification/receipt.json`, SHA256
`763b8ab0d7cd01305e7278a35c1a69a00f0838087a1e581d61d37925ddc82585`.
This failed run does not authorize the app gate. Do not retry it unchanged.

Source review found a real observation race: status publication and PF changes
are separate, but both the observer and `_daemon_update_runtime_proof` reject
the first mismatched sample. A fresh cached status can describe the preceding
PF state. In the updater this can cause unnecessary abort/restore or a redundant
reinstall during committed recovery; this is a source-proven possibility, not
proof that every historical network interruption had this cause.

Merged PR403 repairs both readers. Only PF/status
mismatch may be resampled within the existing five-second readiness budget;
identity, ownership, witness, hash, listener and recovery failures still fail.
PID, root UID, process birth and command remain pinned across observations.
No transaction retry or lease extension is introduced. The observer retains
sampled health evidence and rejects permanent mismatch or late convergence.
Its 51 focused tests passed, including both transition directions, identity
change and permanent failure; independent observer review found no blockers.
The product regression file passed 108 tests; 11 existing installer/attestation
tests and 94 pair/workflow tests also passed. Project-state contract, actionlint
and whitespace checks passed. Independent product and observer review found
no blockers. The default installer keeps its prior slow-first-read semantics;
the updater also accepts a healthy first sample, but never late convergence
after a retry. Evidence: `readiness-product-fix/final-retry-budget.log`,
`readiness-product-fix/default-attestation.log`,
`root27-to28-qualification/readiness-after.log`,
`next-pair-admission-tests.log`. These focused results reuse the unchanged
green baseline. Exact-head PR403 CI also passed; corrected-origin main
qualification and successor CI remain pending.

The corrected originating product now needs a new normal `.28` main candidate,
followed by a normal `.29` successor. The previous no-`.29` plan applied only to
a harness change; the newly found product defect also lives in OLD's sealed
worker and cannot be fixed by substituting NEW. Include the observer, product,
pair admission and both app modes before building the corrected origin. Both
root cases and then both app cases must use the same complete `.28 -> .29`
pins at NEW source. Signed older candidates remain unchanged evidence.

No local Rust/native execution, workstation installation or routing change was
performed. Public `.24`, its signed assets, settings and learning are unchanged.

### Previous .27 implementation evidence

[PR398](https://github.com/aiwaki/slipstream/pull/398) merged at
`ddfca43ff9d34e8d917bab5cb68cec2b8ff9203b`. Its tested head
`df43790048123e8d709e99c33de7be5f8c408f94` has the same Git tree. Full
CI39264508089 and audit39264508049 passed, including packaged browser and
lifecycle checks; independent review found no blockers and review threads are
resolved. Receipt `output/updater-daemon-identity/pr398-verification/receipt.json`
SHA256: `a2a61efd6298edff4904284cbfa1a9a35d0db9d08a006b76dd63ec4a7b7b80de`.
Exact-main CI39266691016 and audit39266690990 passed. Its repaired originating
`.26` candidate (artifact12193253991) passed all seven file hashes, GitHub
attestation, updater signature and 897 archive mode checks; Geph is `0755`.
Manifest SHA256: `f81c42054519ab75a176ba279c70af67df52a0647671110e42c17fcde290ed63`.
Receipt `main398-verification/receipt.json` SHA256:
`b8d6d38c29ce9f2a0ccc2c4777768dcdda1f116eb256c8fc1e76e42ec9d873ab`.
The app payload was neither extracted nor executed locally.
This change bumps the normal source version to `.27`
using `scripts/sync_version.py`, so the successor has different compiled tray
and frozen-daemon version inputs. Neither candidate is a public release.
The older PR395/PR396 `.25`/`.26` pair remains retained evidence, but it cannot
qualify PR398: its originating daemon still contains the rejected comparison.
Five untracked adapter/observer drafts remain excluded. No workstation runtime
or privileged state is changed.

The `.27` change also repairs the initial app watchdog handoff. Production
preparation held its transaction flock while `RunAtLoad` could immediately start
the helper; a busy helper exits successfully and launchd need not restart it.
The handoff function now consumes the real lock guard, writes the LaunchAgent and retires
the old registration while locked, then releases the guard before bootstrap.
After handoff, a rejected or uncertain launch preserves the durable journal and
original root lease for normal recovery instead of cancelling from a stale
snapshot. LaunchAgent write failure also retains that evidence. Three hermetic
Rust regressions cover immediate launch, publication failure and all three
bootstrap-inspection outcomes. Hosted CI39270118315 compiled and passed all
three regressions (194 app tests total). Source review and rustfmt passed. The scheduling defect is established in source,
but no native occurrence has been attributed to it yet.
The same run passed packaged build and browser qualification, but failed at
`active-worker-uninstall:active`: the aggregate status-cleanup error did not
identify its component. Audit39270118342 passed. Retained receipt under
`pr399-handoff-verification/receipt.json` SHA256:
`f0f27ed0b2da6ea6946dd279a3a5a8014aad3873db8efbe537e29c619671c9c8`.
No unchanged rerun was requested. Hermetic reproductions then demonstrated
worker-cleanup rejection when a one-shot worker exits between launchd and `ps`,
or completes naturally while SIGTERM is sent. Cleanup now checks a fresh
terminal job result, accepts exit zero or an explicit known cleanup-safe worker
error, and retains evidence for unknown, changed or unclean states. Five fixed
component labels identify future status/attestation/socket/worker failures
without exposing paths or exception text. This is a source-proven repair;
the old native failure cannot be attributed to one of these branches.
Independent review and 32 integrated focused Python tests passed in 1.00s;
new exact-head packaged qualification is required before merge. The unchanged
194-test Rust result is retained; no local Rust build or native operation ran. The existing root `.26 -> .27` cases
have no active browser worker and keep their original scope; active-worker
teardown is covered by packaged lifecycle, not inferred from the root gate.

PR399's original version-only head `80fe59ffa2eb86380e4b4f36a028fde4af3ea79d`
passed CI39267467781 and audit39267467740; that baseline does not qualify the
new handoff repair. Receipt `pr399-verification/receipt.json` SHA256:
`c12231a62647c35d378bf565b4910490dd4b05c53552f813d8986f69c087e6f2`.

PR391 merged at `77ac92713760cd4996aa74204233889b7a77f8c6` after final-head
CI38768966095 / audit38768965965 passed. Its 14 updater tests and packaged checks
passed. Main CI38770908107 and audit38770908316 passed. The
pagination repair is not in the published `.23` or `.24` binaries.

The real public `.23 -> .24` attempt (run38763822390) stopped before activation
because no offer appeared; cleanup passed. Public upgrade/rollback remains
unqualified; use the published DMG. Evidence and separate source diagnosis are
in [TROUBLESHOOTING.md](TROUBLESHOOTING.md#a-new-version-notification-does-not-appear).

[PR392](https://github.com/aiwaki/slipstream/pull/392) merged at
`2640fc451be279997d8d59ed63e3ca59e4c32f1f`. Exact-head CI38776833865 and
audit38776833749 passed; main CI38779030007 and audit38779029971 passed too.
The latter includes 166 app tests, 40 focused updater tests, browser/lifecycle,
signing, assembly, attestation and notification checks. Its 17 retained files
were rehashed on 2026-10-19; receipt SHA256:
`ab87e4f2662d7b1f3a76a19d286da50e3de5faa65c78ea5013f185b422ae3a8a`, under
`output/updater-daemon-identity/main-2640/`. Reuse this baseline; it does not
qualify the coordinated work below or change the published `.24` binary.

[PR393](https://github.com/aiwaki/slipstream/pull/393) merged at
`e2f728b006c22d0fcb233cadc834ce29c7d32fa8`. Final head
`b06299cc535120c7d279d4aed5a93d51b5d5b92d` passed CI39239577378 and
audit39239577363, including 191 app tests, Rust lint, Python/Windows checks,
packaged build, browser qualification and packaged lifecycle. The terminal
receipt P1 is resolved. Retained receipt
`output/updater-daemon-identity/pr393-green-b062-receipt.json` SHA256:
`7aebe7cb8d46b66219cbd843c98c6cc0057cac592f1c48dccbc64d3218a1cdd2`.
Main audit39241525729 passed. CI39241525733 exposed a timing-dependent test
failure: 190 app tests passed, while the virtual refresh-budget loop received a
valid transient lock-busy result. A bounded macOS fork fixture demonstrated that
a close-on-exec descriptor can retain its flock in a forked child after the
parent closes it. The exact CI child PID was not retained. Evidence:
`output/updater-daemon-identity/main393-product.log` and
`refresh-lock-inheritance-20261019.json` in the same directory. The test now holds
one lock across virtual time; the separate concurrency test still covers the
public nonblocking path. That fixture explicitly releases its own test lock and
waits at most two seconds only for inherited-FD contention. The required single
write and budget assertions remain intact. Independent source review passed.
Production lock/skip behavior is unchanged. All 191 app tests passed in hosted
CI39243566954 at `7300671f895ee529ee966229753ca4238f1a5bc4`; no local Rust
build/test ran. The failed main attempt
cannot qualify the old candidate. Full exact-source attempt2 of CI39241525733
passed and produced the verified bridge candidate. Its manifest SHA256 is
`2e0dfe677325376e9d9d6bdd34ca9289a4bd8146e0824d3d9e61ea220364d3ba`;
the seven retained files passed canonical manifest and exact-main hosted GitHub
attestation verification. Receipt
`output/updater-daemon-identity/main393-attempt2-verification/receipt.json`
SHA256: `e1225430bf8151afff68528ce96a05355181cc26f079a735cb65f2b098e9d521`.
No candidate payload was executed locally.

After daemon PID rollover, the exact mailbox can wake the exited root worker
without changing the durable decision. Its 330-second/33-attempt consumer budget
survives automatic watchdog restart and resets only for a verified new process
birth. Root tests passed 44 cases locally; seven new Rust regressions passed
in hosted CI. The same PR fixed a reproduced BSD `tail -c` concurrent-append
race in Geph log rotation; fixed-count copy now bounds the archive and preserves
the live log if publication fails. The unchanged Rust live-process test passed.

[PR394](https://github.com/aiwaki/slipstream/pull/394) merged at
`1fc6130ddecfde06895cf0102f5cb9d007bd4e04` after exact-head CI39243566954 and
audit39243567046 passed, including packaged browser and lifecycle checks.
The retained `output/updater-daemon-identity/pr394-green-730-receipt.json` has
SHA256 `61bf6de7de42c3b07d45671b21890c5ab9f2b7686ca80fc812e304da7939c87c`.
Main CI39245442918 attempt1 and audit39245442978 passed. The active
`readme-humanizer` checkout is now on `codex/packaged-update-observation`.
The merged change incorporates the reviewed disposable native driver,
materializer, workflow and 45 hermetic tests. Its normal source version is
`0.1.9-preview.25`; synchronization and scoped integration review passed.
The new source supplies a successor whose compiled tray and frozen daemon differ
from the main393 bridge candidate. Initial CI39240828886 was deliberately stopped
before packaging because strict main-base refresh required new exact-head CI;
audit39240828853 passed. The base refresh passed audit39241690945; CI39241690927
was superseded by the runner correction. Review found that GitHub is retiring
`macos-14`; the new native workflow now uses supported ARM64 `macos-15` while
retaining its architecture guard. Scoped workflow tests (8) and actionlint passed;
independent review found no macOS-14-only assumption. CI39242530303 is superseded
by the deterministic-test repair; audit39242530364 passed.
Native run39248727837 (attempt1, source1fc6130d) failed in both `commit` and
`crash-before-commit` before installation: `unsafe update file mode`. Both
results contain no transaction events and no cleanup errors. Read-only archive
inspection found the same single offending file in both ZIP/TAR candidates:
`Contents/MacOS/geph5-client`, mode `0700`. Under the build's `umask 077`, `cp`
followed by `chmod +x` creates that mode. The root updater correctly rejects it;
a root-owned retained executable must remain accessible to the console user.
The fix uses explicit `0755` before packaging and adds mode validation to the
existing `scripts/verify_updater_artifacts.py` boundary and early build check.
It does not alter candidate bytes, retained artifacts or production validation.
Evidence: `output/updater-daemon-identity/native-pair-file-modes.json` and
`native-root-39248727837/receipt.json`, receipt SHA256:
`309e87b195c445a9a23d1663db0ce46b7985bb50305245aeccb1f8bef9c6687e`.
Focused verification passed: 56 build-config tests with three mode subcases,
29 updater/release-verifier tests with 21 subcases, actionlint and whitespace
checks. An independent review found no blocking issue. Only the packaging-mode
fix, shared verifier, their tests and these docs belong to this change.
The old candidates remain intact but cannot qualify the native update. A new
normally built pair is required. No preview.25 release is published, and the
installed workstation app and public preview.24 remain unchanged.

[PR395](https://github.com/aiwaki/slipstream/pull/395) merged at
`d3efc1891cd501db1af40b7e21352dd1106b947c`. Final head
`74cdcfe2d9ba133d589b5c430e9721157e8a6e8b` passed CI39250716497 and
audit39250716533, including the new bundle-mode gate, packaged browser and
lifecycle checks. Receipt `output/updater-daemon-identity/pr395-green-74c-receipt.json`
SHA256: `8d07fe1de4c7390c4593ed7020c91ebd3bb3c3178fe7b5b3fa64ba4692abb656`.
Main CI39252308451 attempt1 and audit39252308394 passed for the fixed `.25`
bridge. Its seven candidate files passed manifest, hosted attestation, updater
signature and read-only archive-mode verification (897 entries; Geph `0755`).
Artifact ID: `12187190345`; manifest SHA256:
`6da2a455bac8f952f0e226e5811d2f1c6b33ba2b9aa7a1269ff3bc85159abc87`.
Receipt `output/updater-daemon-identity/main395-verification/receipt.json` SHA256:
`b36be15d555672d41928fd78c574d194960a10b5df2a6596e33dc5757303e426`.
The payload was not extracted or executed on the workstation.
[PR396](https://github.com/aiwaki/slipstream/pull/396) merged at
`0f26a274a5d26b778be470bc4ed5c73c65c32f03` after CI39252751017 and
audit39252750901 passed at `85cf8a6cd98a22805856479a0993bc02e2fdfacf`.
Receipt `output/updater-daemon-identity/pr396-green-85c-receipt.json` SHA256:
`0fc979f2cfe1ce417b04c272f398a6787ccfcd1601b96a1cb0982bb119bb4ae7`.
Main successor CI39254420455 attempt1 and audit39254420270 passed. Its seven
files, hosted attestation, updater signature and all 897 archive-mode entries
passed verification. Artifact ID `12186723921`; manifest SHA256:
`cdb58cf988035c72e3e7953b84a4294991b5d3cfefa82d6a4351a6da0514dd35`.
Receipt `output/updater-daemon-identity/main396-verification/receipt.json` SHA256:
`cf1f8851730948b6142f3bc428aec70deec3948cc89471d7d1d2a5673082bb11`.
Streaming the actual tray and daemon members proved both pairs differ. Pair
receipt `native-root-25-26-pair-receipt.json` SHA256:
`d609ca2d90a5ec4e18c175db597b7ba404a9646ebb1312b2182f58926bfe1ca1`.
The exact eight dispatch pins are retained in
`output/updater-daemon-identity/native-root-25-26-dispatch.json`; SHA256:
`87cb0987d21029889fadcb7e26476d465b6c30ef80bead3549f73a3e44ea789b`.
Parent verified main still matches `0f26a274` before dispatch. The merged
change contains only the normal `.26` version bump through
`scripts/sync_version.py` plus this checkpoint. It changes compiled tray and
frozen-daemon inputs; actual binary inequality passed as recorded above.
Version synchronization and the existing daemon-version regression passed.
The adapter/observer drafts remain untracked and excluded. The read-only commit
observer passed 67 hermetic tests and independent review; it cannot install,
launch, signal or clean up the transaction, and refuses fault mode. Native
execution and adapter compilation remain unverified. The test log is
`output/updater-daemon-identity/packaged-observer-tests.log`. Neither `.25` nor
`.26` is published; no workstation operation is requested by this change.

Native run39256896555 attempt1 at `0f26a274` authenticated and unpacked both
fresh candidates, then failed in both cases with `Refused: command failed: sudo`.
Only the two artifact-identity events were retained; there is no root-status
observation and both cleanup-error lists are empty. The driver captured but
discarded the failing command's return code/stdout/stderr, so the current
result does not distinguish installation from root preparation. This is not
sufficient evidence to change production behavior or claim rollback coverage.
Receipt `output/updater-daemon-identity/native-root-39256896555/receipt.json`
SHA256: `8117d8e25ed2f2120e930d1c3767d7b09496bd833da427b8bbdb475a3b1b4cb2`.
The driver change adds bounded native-command diagnostics and install/prepare
stage observations, preserving the primary failure separately from cleanup.
Authenticated GitHub commands, unknown commands and custom environments omit
output; only the exact generated root-proof command has its own explicit
allowlist entry. Forty hermetic driver tests passed in 0.08 seconds; log:
`output/updater-daemon-identity/native-root-39256896555/diagnostic-tests.log`.
No native command ran locally. Independent review found no blocking issue.
[PR397](https://github.com/aiwaki/slipstream/pull/397) merged at
`2f3b214e648e1e20e86e496f5c75ec8cf717cee7` after CI39259110244 and audit39259110230
passed on `18db0f2cf122ee79635fd6af3cb16ff2814db6d3`. Their Git trees are equal.
Receipt `output/updater-daemon-identity/pr397-verification/receipt.json` SHA256:
`6daaa75989c5a76de93e953445f04b5d48274bb764f6e564b50adff96bc68c11`.
No unresolved review threads remain. The five untracked adapter/observer drafts
are excluded. Active branch is now `codex/native-update-qualification`.
Reuse the unchanged signed `.25`/`.26` pair;
there is no reason to rebuild or modify these candidates for that change.

Native run39261398050 attempt1 failed in both cases at `prepare-update`:
the installed frozen daemon exited 77 with `daemon_update_no_operation`.
Old-daemon installation completed; no root operation was published and both
cleanup-error lists are empty. Retained receipt
`output/updater-daemon-identity/native-root-39261398050/receipt.json` SHA256:
`46dcb9a4c5d7dbefdcf120f7c497268353e1cbc72bfce4fbce88fcb0e6b83bc5`.
The originating source catches runtime preflight and bundle-sealing errors into
that code, so the native failure's precise cause is not yet established.
Source review found a concrete mismatch: the installed attestation records
historical `state`/`pf_active`, but the root runtime proof requires whole-record
equality after a healthy same-PID state transition. The Rust consumer already
separates historical health from stable identity. The production repair validates both historical and fresh health pairs, then
compares every other attestation field. Fresh OS readiness remains mandatory,
and the stored receipt is never rewritten to hide an identity change. The
readonly native observer uses the same pure comparison after its own OS checks.
Both same-PID transitions failed before repair; 89 root tests and 42 observer
tests now pass. The root tests include malformed health, stable identity drift,
actual temporary-file changes and injected CLI refusals. Independent identity
review passed. Logs: `attestation-health-red.log`,
`attestation-health-stage-green.log` and
`native-root-39261398050/observer-health-before.log` under
`output/updater-daemon-identity/`. Exit77 and its original stderr token are
preserved; a second line now identifies an allowlisted preparation stage without
exception text, paths or credentials. No native retry or local runtime operation
has been performed. Immutable `.25`/`.26` still contain the old comparison; they
cannot qualify a production repair in the originating daemon.

The implementation seals full app trees and the installed worker runtime in
root-owned storage, preserves the original authorization deadline, and waits
for verified new-daemon readiness before replacing the app. Rollback stops the
exact successor, restores and verifies the daemon, then restores the old app.
After durable root commit, recovery relaunches the new app and requires its
fresh ACK; it never rolls back to the old daemon. Both languages consume shared
full-tree and actual Python status vectors under `contracts/`.

Focused verification on 2026-10-19 passed: 38 new hermetic root-worker cases,
49 existing installer/launchd/attestation cases, 2 existing tree-replacement
cases, 2 real process-lock inheritance cases, and the existing system-command
runner case. Logs are retained under `output/updater-daemon-identity/`.
The process-lock test kills the lock owner and proves its still-running child
retains the installer lock; a no-inheritance control demonstrates the race.
Eighteen new Rust regression tests passed in hosted CI at head2462 and again
at head996e (the latter failed only the existing Geph rotation test). They were
not executed locally; format and whitespace checks passed. The reviewed cleanup crash window is closed by
a durable intent that pins each validated directory device/inode before removal.
Retries accept a partial original directory but reject a substituted slot.
PR393 passed full exact-head and main CI. Disposable native qualification
has not passed the native gate described above and remains open. The new workflow's 45 integrated hermetic tests,
actionlint and source/path wiring review passed. No local Rust build, privileged runtime test or workstation
installation ran. The unchanged release checks are not repeated.

| Milestone | Current boundary |
|---|---|
| M0 - Safe Base | Candidate cleanup passed; public update/rollback unqualified. |
| M1 - Autonomous Routing V1 | Hosted browser/soak passed; no new workstation qualification. |
| M2 - Contracts And Code | Corrected private .30 -> published .31 root/app pair passed commit and pre-ACK rollback; ordinary public transition remains open. |
| M3 - Release-Grade macOS | Preview .31 public and remotely verified; exact candidate passed hosted native/readiness gates. New workstation, stable and public updater gates remain open. |
| M4 - Cross-Platform Core | No new platform qualification in this change. |

## Next Verified Action

- Complete PR/CI/merge for the selected cancellation and chunked-prefix fixes on
  `codex/post-preview31-recovery`. Preserve the remaining PR376 scope; a source
  merge will not update the already published `.31` binary.
- First resolve current dependency admission: obtain the isolated Chromium review
  receipt, update exact runtime pins/review, verify scoped block-buffer disposition
  in fresh audit, and finish publication-time app/vendor expiry enforcement. Never
  renew a date without the required fresh evidence or overwrite published assets.
- Preview `.31` is published and remotely verified; documentation PR425 is merged
  with green PR/main checks. The exact candidate/readiness/native/packaged gates above
  are complete and reusable; do not rerun or redispatch them after resuming.
- Public preview `.30` is immutable and lacks origin-side updater repairs. The
  qualified private `.30 -> .31` pair cannot prove a public transition. Plan the
  next ordinary tray/admin and fully public update/rollback checks from compatible
  released origins; keep that gate open until observed. See [RELEASES.md](RELEASES.md).
- Historical Safari DNS and Codex403 incidents still need current user-visible
  routing/error evidence. The published lifecycle and route-continuity checks do
  not establish the cause of those earlier responses. Preserve external Geph and
  network settings; no workstation transaction in this continuation.
- PR376/384/386 remaining scope was reconciled October 30 (reports above). Verify
  new changes before the next action instead of repeating that inventory. RSA policy exceptions
  expire after October 30 UTC; do not extend or reuse them implicitly.

## External Gates

- Normal full Quit and ordinary reopen were qualified locally on the earlier private
  preview31 source1f3ddcf, with owned Geph disabled, preserving external Geph. This
  is not installed evidence for the newly published source3eb32bd. Native CI also
  qualifies owned inert listener/pre-listener cleanup. Account-backed owned
  Geph operation/shutdown is not established by that local cycle; the separate
  current hosted account-backed lifecycle and outage gate passed as recorded above.
- Ordinary public update/forced rollback remains unqualified. The earlier
  public attempt stopped on the short startup timer; source repairs and the
  later manual installation are separate evidence. Hosted updater authorization
  still lacks a successful probe. See [RELEASES.md](RELEASES.md).
- Stable publication still requires Developer ID signing, hardened runtime,
  notarization, stapling and the existing stable-channel gates.
- Native/source-owned work in PR384 and Telegram work in PR386 remain separate.
  Preserve the root checkout, user changes and all retained output.
- External DNS/proxy/PAC/VPN and PF owners are untouched. Discord, YouTube and
  Googlevideo remain on local bypass; this lifecycle checkpoint changes no rule.

## Resume Protocol

Verify physical checkout, HEAD, PR state and exact matching CI once, then take
the next action. This checkpoint is a locator, not proof. Read [DECISIONS.md](DECISIONS.md)
and [RELEASES.md](RELEASES.md).

## Update Rule

Update this file when the verified next action changes. Keep detailed
investigations in their topic docs and retained evidence.

# Current Project State

## Verified Checkpoint

### Network and updater observer follow-up, 2026-10-23

Active physical checkout:
`/Users/aiwaki/.codex/worktrees/readme-humanizer/slipstream-codebase-audit-20260905`,
branch `codex/network-updater-followup`, based on merged PR414
`934476dab7c5ff2e0a50bbee47641483c25ef465`. PR414 CI39945675797 and
audit39945675765 passed. The installed private preview31 remains source
`1f3ddcfb6ed912a22fb4d0d1502e3879aee9ee36` (the exact source is recorded in the
completed lifecycle section below); follow-up source is not installed yet.

PR415 contains the follow-up; initial head
`4d9af272df6dcef799e7abc45572d33db1a1514c` passed product checks, the packaged
build and packaged browser qualification in CI39953414580. The remaining native
job must be reconciled against current GitHub state. Audit39953414800 fails
only the Geph vendor gate: a new October 23 advisory, RUSTSEC-2026-0385, affects
ctutils0.4.3. Existing RSA exceptions remain accepted; this is not an expiry or
an error introduced by the DNS patch. A separate minimal dependency repair is
being prepared in the existing `geph-rustls-02345` checkout. Do not waive the gate.

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

The installed daemon is active (PID2853; heartbeat advanced through2424).
Fresh physical Safari navigation loaded YouTube including visible thumbnails;
a short played with seek position24%→54%. External Geph remained present and
untouched. The new DNS patch is not installed, and this current observation
neither isolates the backend nor proves the historical DNS/HTTP403 incidents
fixed. See `output/network-incidents-20261023/browser-observation.json` and
[ROUTING_RESEARCH.md](ROUTING_RESEARCH.md). Browser automation had first been
blocked by the locked Mac; the user unlocked it. No login/logout was attempted.

The completed installed full-Quit/reopen qualification below is reusable.
Next: finish PR415 review/CI and the separate ctutils dependency repair, then
bind any new candidate to canonical bundle/install verification before browser qualification.
Public updater transition/forced rollback and the historical HTTP403 remain open.

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
| M2 - Contracts And Code | Recorded .29/.30 root/app pair passed; attended public attempt exposed startup timer defect. |
| M3 - Release-Grade macOS | Preview .30 public; private .31 installed and full Quit/reopen qualified. Stable and public updater gates open. |
| M4 - Cross-Platform Core | No new platform qualification in this change. |

## Next Verified Action

- Finish PR415 (`codex/network-updater-followup`) and the separate ctutils
  dependency repair blocking its Geph audit. Supplemental DNS and pre-ACK
  observer races are causally reproduced and repaired locally. Reuse recorded
  focused checks; current-head CI and matching candidate/install proof remain
  before treating these source changes as delivered.

- PR409/410 source repairs, PR412 full Stop-and-Quit and PR413 trust-dependency
  repairs are merged. The privately installed preview31 is authenticated source
  `1f3ddcfb6ed912a22fb4d0d1502e3879aee9ee36`; it contains these repairs. Reuse
  its green CI/audit, seven native lifecycle cases and the completed workstation
  start/full-Quit/reopen receipts above. Do not reinstall or repeat these gates
  without a relevant code change or new failure.
- The next release gate is the still-unqualified ordinary public update and
  forced rollback. The observer follow-up above retains the missing false diagnostic and
  handles the reproduced transient lock; qualify current source before
  another native attempt; a successful manual install or Quit
  does not prove the updater. See [RELEASES.md](RELEASES.md). Keep public preview30
  immutable and preserve all private candidates, state and backups.
- Historical Safari DNS and Codex403 incidents remain open. Their diagnosis
  needs current routing/error evidence; the lifecycle fix alone is insufficient.
  Preserve the separately running Geph and external network configuration.

## External Gates

- Normal full Quit and ordinary reopen are qualified locally on preview31 with
  owned Geph disabled, preserving the external Geph processes. Native CI also
  qualifies owned inert listener/pre-listener cleanup. Account-backed owned
  Geph operation/shutdown is not established by that local cycle.
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

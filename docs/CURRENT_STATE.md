# Current Project State

## Current continuation — 2026-11-07, packaged Chrome startup evidence

Physical checkout: `/Users/aiwaki/.codex/worktrees/geph-route-continuity/slipstream-codebase-audit-20260905`.
Branch `codex/browser-startup-evidence-20261107`; base/main
`a9fdac98f0d07e953770097be08fe4fddc0d1f65`. Live GitHub reconciled: main unchanged,
CI42221917459/1 terminal failure, audit42221917506/1 success; no duplicate PR for
this work. Previous goal turn made progress (budget PR merged, new CI failure
preserved); this continuation is diagnosing that failure, not repeating a wait.
The dated Nov6 allowance expired; normal three/day account-backed policy applies.

Working patch: disposable-CI-only Chrome startup summary from existing readiness
observations, with child status sampled only after cleanup captures owned groups
and before TERM. Exact bounded Python sanitizer retains the summary; private raw
output remains redacted. Deadline, route/ownership decisions, cleanup precedence
and browser/release acceptance are unchanged. This fixes lost failure evidence;
it does not yet establish or repair the original Chrome/Safari failure cause.

B=output/continuation-20261107/browser-start-evidence. B/local-evidence.json binds
initial RED, 144 Python tests plus8 subtests, independent review and source hashes.
31 Rust browser-worker tests pass with command-local empty Tauri resources for
unit testing only. Initial ordinary cargo invocation stopped at missing sidecar
before tests; no app was built/installed or network/service setting changed.
Focused Clippy with warnings denied, eight docs tests, continuity and whitespace
checks pass. Earlier unchanged runtime suites are reused. New-source CI is pending.

NEXT: submit the diagnostic PR, review exact CI
and merge only with required checks. Then verify a fresh consistently bound main
candidate before one new readiness R. Do not run stale Nov6 helper pins, rerun
failed protected attempts, lower criteria or claim release readiness from unit
checks. Record actual startup observations if the packaged gate fails again.

## Previous checkpoint — 2026-11-06, budget renewed; CI browser startup blocked

Physical checkout: `/Users/aiwaki/.codex/worktrees/geph-route-continuity/slipstream-codebase-audit-20260905`.
Branch `codex/account-budget-renewal-release`; main/HEAD
`a9fdac98f0d07e953770097be08fe4fddc0d1f65`, tree
`073e65f8ab0011883eb65849316621ea14dfcb40` after merged PR474.
The owner explicitly requested a forced limit renewal. This supersedes the
budget-only blocked state and wait-until-Nov7 instructions below. Committed
policy grants three extra slots only on UTC Nov6, total six; other dates return
to three. History, first-attempt checks, complete inventory and release/browser
criteria remain. No upstream Geph quota changed. Three slots used; no additional
protected dispatch, release or workstation action was performed this turn.

Focused checks:78 tests and17 subtests PASS after initial RED, independent review,
continuity and whitespace PASS. Earlier runtime/observer tests remain reused.
PR474 CI42218340792/2 and audit42218341020/1 passed; guarded squash/fetched main
matches tested merge tree. Attempt1 failed before tray startup with dscl exit10,
zero cases and no outer cleanup errors; exact operation/cause unknown. One
failed-job retry passed, preserving unchanged green jobs. All PR observers ended.

B=output/continuation-20261106/account-budget-renewal.
B/focused-verification.json and B/pr474 contain focused/retry/pre-merge/merge proof.
Main audit42221917506/1 PASS. Main CI42221917459/1 is terminal FAILURE:
packaged-browser-qualification job127913258448 failed with worker exit1 and
chrome_start_failed; dependent lifecycle aggregate127916835845 also failed.
All other common jobs passed, including native Stop-Quit. Observer90863 exited1;
do not restart it. B/main-ci/watcher-receipt.json SHA
3661e97688175836a0f557b252b377c33789fbeee1be2dd16cead9724b4d651d
binds final run/jobs/artifacts. Browser failure is preserved in
B/main-ci/browser-qualification.log and browser-failure-evidence.json.

The worker failed before navigation: owned main plus DevTools readiness did not
arrive by the existing deadline. chrome_start_failed is a generic category from
nonempty readable UTF-8 stderr; the raw private stderr was not retained. Exact
cause (runtime versus runner condition) is unresolved. Browser source, fixture
and ci.yml are unchanged since prior green bb167. Independent review agrees no
causal timeout/source change is justified yet. Rerunning only this consumer
would set latest CI attempt2 while candidate manifest stays attempt1, rejected
by current R admission; no such rerun was made and no acceptance was relaxed.

B/qualification contains repinned private helpers and independent helper-review.
Run IDs remain0, manifest is deliberately PENDING; no intent/dispatch exists.
Fresh inventory at preparation had three Nov6 attempts, no active protected run,
no exact-source R. The three extra slots expire at 2026-11-07 00:00 UTC.
NEXT: resolve the Chrome startup failure with bounded retained launch evidence,
then obtain a fully passing, consistently bound candidate before one new R.
Do not run old Nov7-only helpers, pending pins, or repeat protected failures.
The user-requested internal budget renewal itself is complete; Safari/release
qualification remains incomplete. No .35 publication or Mac changes.

## Previous checkpoint — 2026-11-06, Safari failure diagnostics

Physical checkout: `/Users/aiwaki/.codex/worktrees/geph-route-continuity/slipstream-codebase-audit-20260905`.
Branch `codex/live-site-failure-evidence-release`; main
`bb1674130a24b725178d682d7bb73a9d91df76fd`, tree
`d7e6aacc82f047193550d191cd37d3a4a55c64e9` after merged PR473.
Diagnostic PR473 CI42157784955/1 and audit42157784999/1 passed. Guarded squash
and fetched main match the tested merge tree. D/failure-causes-pr473 has the proof;
watcher46369 exited0. Main CI42159219304/1 and audit42159219294/1 passed; all12
common consumers and4 audit jobs verified. Main observer64654 exited0.
Evidence: D/failure-causes-main-ci. Do not restart either observer, create
duplicates or repeat the accepted focused tests.
E=`output/continuation-20261105/preview35-release`;
D=E/safari-parser-control; R=D/owned-probe-qualification/readiness-r;
F=R/diagnostic-followup. No `.35` publication or workstation installation.

### Reused runtime fix at 03760fe5c and last failed native gate

PR472 fixed a reproduced ownership hysteresis defect: a negative Geph RPC probe
cleared ownership while readiness still retained the same verified PID. Owner
identity is now checked before and after the probe; a replacement cannot inherit
its result. Existing readiness/cold-start/hold rules remain unchanged. Retained
RED and focused proof are in D/owned-probe-local-verification.json, SHA
f65e3b8f743dc7125791890533a87d3aec829f796e69cd146fc47a8cae5152ec.
This defect is not established as the cause of Safari's live failure.

- PR472 CI42148664085/1 and audit42148664185/1 passed; guarded squash has the
  tested tree. D/pr472/merge-verification.json SHA
  a8394b608464b0873099c75042a4896d6ef57bfc0f6ca1aca77205253dbc6cbe.
- Main CI42150528780/1 and audit42150528788/1 passed all12 common consumers and
  all4 audit jobs. D/owned-probe-main-ci/watcher-receipt.json SHA
  0192e67e9700533b2ab0d2b17d13e6d242ee1c9e95d4541e102b8374157c4d28.
- Candidate artifact13471659846, manifest SHA
  2a0a9593351908307e71a454de25c46471113e3422c9f3437a796c29665c2d99.
  D/owned-probe-main-ci/candidate-receipt.json SHA
  95455bdad972d7accd54ff46f505d964ab5cb7c1b3e5d8e3a68395fa52c1aaa1
  binds producer metadata/full log and CI only; no app archive downloaded.
- R42152828184/1 failed before soak. Authenticated diagnostic artifact13472952760
  has four exact members, ZIP SHA
  c52bbcbe07eb06c410c0a10b0a716e4fe0b3af9e23fc7cf45b6a313bf814b6a4.
  R/failed-run-verification.json SHA
  0aeef4b533758b17a985afe5e26f6edb503b8a2e8701575844957cc239a21756.

Seven of eight browser cases passed. For xpersonatoy.com, system Safari was usable
in8060ms with absence/proxy/PF guards verified. Selected Safari failed after20140ms:
other document1205B, body164 characters, host/HTTPS false, no navigation timing.
Chrome was usable4862ms. Post-Safari PID8086/up became PID9038/down18.105s later;
controls did not restart Geph. Product recovery versus exit/KeepAlive is unresolved.
Curl HTTP200 controls prove only bounded128KiB prefixes. Hosted cleanup passed;
soak and success attestations were skipped. Initial probe precedes PF/active, so
source review rejected a speculative ordering fix. Full investigation and limits
are in ROUTING_RESEARCH.md.

### Scoped follow-up, locally verified

The observer now retains bounded Safari error-category hints, separate health and
heartbeat freshness, and fixed failure/restart enums from current daemon log plus
`.1`. No raw text/URLs/secrets are exported. This does not change runtime routing,
readiness criteria, timeouts or retry count. Log rotation and the two-second
filesystem observation budget are cooperative, not atomic/hard cancellation;
missing events cannot prove no dial or distinguish every admission denial.

Combined focused verification:140 tests and158 subtests PASS, including14 transport
and17 error-hint JavaScript VM cases. F/combined-focused.json binds command, source
hashes and log; receipt SHA
1f94454e6c589a3fa52c9d6a1083e37e2c5c9f35d0d41af9bada87b68e6cc633.
Independent review found no blocker. Eight documentation tests, continuity and
whitespace checks passed. Native Safari still fails on main; observer fixtures
are not proof of a browser fix. Graph tools unavailable; bounded direct source
reads used. F/review-and-verification.json binds these results to the committed
source (SHA ff9fe83d0e4d5e8bdc3baa1f60acdb593581e83baa61877b73cbe3b58c3321c8).
PR473 passed all8 PR consumers and4 audit jobs; watcher receipt SHA
06e7c7105c9dc71adbf3c5a9a44b64c7862b4cc20fb9825cd4068847da32c4b3.
D/failure-causes-pr473/merge-verification.json SHA
1866cd3c9e372e074d763ddc0e042b47a5c35ed52560973677f14209ac9c0b00.
Exact-main watcher receipt SHA
3fbc77633690910c5d2fb2c9124c344614048aa780437ccb400c7f5bf4ee4cf9.
Candidate artifact13476048382, manifest SHA
d1a41ef46b765cfa4d07d9e598576741d25c3a6ab62efc07e4a1ddfbc9027d7b.
D/failure-causes-main-ci/candidate-receipt.json SHA
0d1792b93db5fde3e3a48894e5a6a95be92ba887eb9aaa66aa5bc888dbbde4ef binds the full
assembly log, producer job/upload metadata, artifact inventory and terminal CI.
No app archive downloaded. Native Safari and final R/G/P remain unqualified for
this source. Code/tests/research are merged; only this checkpoint update is local.

### Budget, reused evidence and next verified action

UTC2026-11-06 account-backed slots are exhausted:42134381208/1,
42144912276/1,42152828184/1 (ranks1–3/3). All are terminal; observers18614,28016,
72012 and earlier ones exited. Do not restart observers, repeat unchanged green
suites, dispatch another protected run today, or retry an unchanged R later.
Prepared helpers: D/failure-causes-qualification (Qnew). All source/CI/manifest
pins match the candidate above; observer, dispatcher, success collector and final
verifier are prepared. Qnew/preparation-receipt.json and prepared-pins.json bind
11 effect-free guard cases (no real network/dispatch), syntax and review. The new
final budget intent input is included in evidence hashes. R remains0 in the
collector/verifier until the actual run ID is reconciled; final accepted native G
for this same source remains mandatory. Nothing has been dispatched. The latest
paginated budget observation found three terminal Nov6 attempts, no active run,
and no bb1674130 R. A fresh full inventory at2026-11-06T04:38:22Z confirms
unchanged main, the same three terminal attempts and no active/matching R.
Qnew/blocked-audit-live.json binds that observation. The previous goal turn made
preparation progress; this turn has no available live job or safe new action.
The same UTC-budget blocker has now recurred in three consecutive goal turns;
the blocked audit is satisfied. Resume only after the external budget day changes,
then revalidate it; do not spend automatic turns repeating this known condition.

User resumed the goal. Resumed audit1 at2026-11-06T12:09:50Z confirms unchanged
main/HEAD, successful exact CI/audit, an unexpired candidate, the same three
terminal account-backed attempts and no active or matching R. Open PR inventory
was reconciled; no replacement candidate is accepted. Evidence:
Qnew/resumed-audit-1-live.json, SHA
37d0408c5b01120f2cc4586ce6dd89d0eebe93b849a04817e96aac5e47515cfe.
This is the first blocked audit after resume; the earlier three-turn count does
not carry over. No new dispatch or workstation change occurred. Goal remains
active; the UTC-budget prerequisite and next action below are unchanged.

Resumed audit2 at2026-11-06T12:12:55Z again confirms unchanged main/HEAD and
three terminal attempts in the complete Nov6-or-later workflow inventory; no
new matching R or dispatch intent exists. Qnew/resumed-audit-2-live.json SHA
7abd74cc2ea0c1343c4463198c65624dd1be313afba9e36a242d4bc66655a06e.
Previous resumed turn was no progress; the same blocker has recurred twice
since resume. Goal stays active; no tests, dispatches or Mac changes were made.

Resumed audit3 at2026-11-06T12:15:59Z rechecked the complete paginated workflow
inventories: same three terminal Nov6 attempts, no active account-backed job,
no matching R, no dispatch intent, unchanged local HEAD and main. Evidence:
Qnew/resumed-audit-3-live.json SHA
a86b4974417109b1fd98974f2d89fe2cf94e65d97537a368748cd18861c063fb.
All three resumed turns found the same genuine UTC-budget blocker without a
live process to wait for or a new safe action. The fresh blocked audit is now
satisfied; mark the goal blocked rather than continue repetitive checks. Safari
completion remains unproven. The next eligible boundary is2026-11-07T00:00:00Z.

NEXT: no more account-backed work before UTC2026-11-07. When eligible, reconcile
unchanged main/candidate and the complete paginated budget/duplicate inventory;
observe any existing matching R instead of dispatching a duplicate. Review the
prepared pinned helpers, use the dispatcher with explicit --execute only on its
prepared UTC day, then bind the actual reconciled run ID before collection. Do not
rerun an old attempt, infer tomorrow's quota, relax the Safari gate, or
download/install on the Mac.
Order CI/audit → R → native G → packaged P → publication remains valid. G/P are
explicit final gates even though the publisher does not enforce them automatically.

Accepted older G42131959745/1 (75 checks) and P42132780497/1 (13 checks) qualify
b80d8aec5 bytes only. E/semantic-qualification/native-g/verification.json SHA
040638c2290443d8a11bd716568806e989cb50d3a6f8724b56ba712a73393cad;
packaged-p/verification.json SHA
ee59d0843bcb2760c6d6e9e0cd17ca911fea02a1960dcb83ed0e104d311cd631.
Earlier causal fixes and observer PR471 retain their proofs under E; do not rerun
them merely for reassurance or treat their acceptance as new-source qualification.

Restored `.31` remains the last verified local state. Temporary Safari Apple Events
JavaScript was restored OFF after the earlier one-page observation. Preserve
backups, settings/learning and external Geph. A fresh local window is needed after
a candidate is qualified; no failed workstation transaction is retried implicitly.

### Retained PR465–468 evidence (historical)

Qualified main/candidate baseline: `82b3c2a77b22657524c28678422342799fdf1745`.
Main is now `874472c952f7149206054ccb88b8e5a00e3bca17` after PR468.
The old candidate acceptance below does not cover the new source.
PR465 is merged. Exact-main CI42027514369/1 and audit42027514435/1 are
SUCCESS, including all12 required common consumers. E/main-ci/watcher-receipt.json
SHAbe23f249aefe414e3d1dc60e5ffe698556be1fd669475313298dfeb71d83bacb binds
terminal metadata. E/main35-packaged-native-proof.json confirms the real packaged
stale-receipt Stop fixture passed with global PF unchanged (initial PF disabled).
E/receipt.json SHA1ae1c002fa3c958f640d132ff565179d380726c88b23fdb6c57bb1cebc000a65
binds producer/candidate and exact CI evidence. No candidate acceptance is inferred
from a partial run.
The single .35 candidate is artifact13415420856,
`release-candidate-82b3c2a77b22657524c28678422342799fdf1745`, archive digest
`af37055810a3532ff297e88a68dcd2a0bbf432e860927650dec68a30ce413dc0`.
The successful canonical assembly job127248827787 printed manifest SHA
`ce0d63b516b9a7b4f043caf148aba1f89d15c8c5be8a43c56ed005984a546af4`
(1988 bytes,6 payload artifacts, producer42027514369/1). Its full log is retained
in E/main35-assembly.log. These are producer bindings, not release qualification.
E=`output/continuation-20261105/preview35-release`.

G42031462763/1 SUCCESS and independently ACCEPTED for exact .34 -> .35.
E/native-g/verification.json SHAcdcd848720bd307c1824e5782ad4747bf6e110b44250845738b7c125377f18ee
binds75 checks, both small report archives, source/job/upload windows, canonical
prerequisite, daemon heartbeat, durable commit and kill/abort/late-commit refusal.
Full payload authentication ran on the disposable hosted materializer; local
verification downloaded only small JSON reports. P42033637214/1 SUCCESS and
independently ACCEPTED for the same G/pair. E/packaged-p/verification.json SHAd89f278538c0d4d24246210bad2d23a6726bf7701f85efcd9d29ce9728c940bf
binds13 checks: real successor ACK/committed root, pre-ACK kill/aborted root,
restored old app/daemon, advancing heartbeats and terminal watchdog/path cleanup.
The first private collector refused because its file allowlist omitted three
workflow-declared trigger logs/receipts. Corrected to the exact8 declared members;
original refusal retained; no hosted rerun or relaxed runtime predicate.

R42031470021/1 FAILED before soak. Its authenticated diagnostics report7/8 usable
browser cases: Safari xpersonatoy.com reached the expected secure HTTPS/h2 document,
but stayed readyState=loading without DOMContentLoaded through20s. Serialized DOM
was142202bytes, visible body text length15, no visible app. Chrome passed in3684ms;
other3 sites passed both browsers. Both curl controls got HTTP200 then receive56,
so the report is inconclusive, not a confirmed origin or routing fault. All Safari
starts and their cleanup passed. E/readiness-r/failed-run-verification.json binds
run/job/artifact13416164015 and ZIP4254a76c78068354a434a60661771ffebcbc502133d5180264d91596ec84af24.
No long soak, success attestations or publication; do not retry blindly. This is
today's first combined account-backed dispatch. Check complete live budget before
any justified fresh run; never rerun R.

PR466 merged as adf6521c4bcb853e2beb5aef6a1eb9ea1cb2876b after
exact-head CI42077737545/1 and audit42077737899/1 passed at6885e0b92.
All8 required PR jobs and all4 audit jobs passed;5 expected PR skips matched.
E/safari-diagnosis/pr466-transport/verification.json
SHA784b7893739d5f4a93f7957f6b09e66255bff754ac2f732a9aac71e220376114
binds their exact terminal metadata. merge-verification.json confirms the fetched
main tree equals the reviewed source tree. The merge introduced no production routing change.
The current physical branch is recorded with PR468 below.
The prior PR observer79672 exited0 and must not be restarted.

Exact-main CI42080793003/1 FAILED; audit42080793122/1 SUCCESS.
The failed packaged-app-lifecycle-heavy step was Native Stop-and-Quit:
`native authorization observation unavailable; stage=script code=None`.
Its required aggregate also failed. The archive was produced, but this is NOT
candidate acceptance. E/main-observer-ci/lifecycle-failure.log and annotations
retain the failure. Observer39922 exited1 after terminal metadata verification;
do not restart it or rerun CI. Its watcher-receipt.json SHA
e415b947c69fa4421ef3ff6ab77e3dccadb7840aa58e6d1a99ba56687e4fa94c binds the failure.
Artifact13440838699 was authenticated against SHA
5de4bbc10176dd80f56d513a4c450fe9272ce16c2ecb48c215d596559e71cc79.
E/main-observer-ci/failed-ui-verification.json SHA
39cf47e3e19e07bcef501d3059e141a437bb1a9f42772e9f3558d35140030992
binds the report: native_cancel passed; root_lock_failure submitted once,
then176 pending observations; cleanup_errors=[]; final snapshot is post-unwind.

PR467 merged as `7a827fcbd8789b45d2ff4a280bd93b0f49e1df7c` after exact-head
CI42088386134/1 and audit42088386229/1 passed at2c2f4facd. All8 required PR
jobs and4 audit jobs passed;5 expected skips matched. The authenticated native
report has7 passing cases,4 confirmed/completed authorizations, verified fixture
credentials and no cleanup errors. Tested PR merge31c6c3d6e, reviewed head and
fetched main have the same tree. E/native-auth-pr467/verification.json SHA
952d137a63b0ead1ab79e438ab9288231a2e9ccd590afe52b7aba3f33394ee42 and
merge-verification.json bind the result. Observer83540 finished; do not restart.

Exact-main CI42092036501/1 and audit42092036658/1 are SUCCESS at7a827fcbd.
All12 required common consumers passed. E/main-native-evidence-ci/watcher-receipt.json
SHA734a43c123b72276921c561f0531f2c547c5eca20ab414c26523ecf263f827b4 binds
terminal metadata; observer31110 exited0. native-proof.json independently binds
the exact-main Stop-Quit report:7 cases,4 completed native submissions, verified
temporary credentials, no cleanup errors. E/observer-7a827fcbd/producer-receipt.json
binds artifact13447090845 / ZIP383ebb94504768755963cfa426f6346b27705a07ce5ff92cefc18a543c033087,
manifest024bdd101028be08fb0021663c07987195be1284b3a2c7f2fe528792d3938bd8,
1988bytes,6 payload artifacts. No app ZIP was downloaded locally.

R42095886020/1 FAILED at7a827fcbd, candidateCI42092036501. Safari xpersonatoy.com
passed in8036ms; Chrome rejected navigation in188ms with ERR_CONNECTION_CLOSED.
The other3 sites passed both browsers. Direct control returned a usable HTTP200
prefix; owned-Geph control returned curl7/connect/status0. Its process/listener
state at that instant was not recorded, so a restart race is not a proven cause.
E/readiness-native-r/failed-run-verification.json SHA
0be485318034e12032b6d77e025b4ab36e8acb3eef94f970c62cf3ffb76019a5 binds run/job,
successful upload, artifact13447642214 and all4 small report files. ZIP digest
faf39238f2870d3fab475de8f046f41bca0ecf6679094ea6bf3a49378d08ad60. No soak or
success attestation ran. Observer18508 exited1; do not restart it or rerun R.
This was UTC2026-11-05 account-backed position2; fresh complete budget and source
checks are required for any justified future dispatch, not an automatic repeat.

PR468 merged after CI42102833069/1 and audit42102833132/1 PASSED at
b6ad687c294e3fd2d264763a1632991ae685c8ce. All8 required PR jobs and4 audit jobs
passed;5 expected CI skips matched. Tested PR mergec68dc2867 and fetched main
have the same tree2ab61bd7c026e1c45e7217c9057ea0a496c1b58b.
E/runtime-pr468/watcher-receipt.json SHA
de53a0b476f38fa50fbc962d3838e6285c1d936c793016dddb28f0a7c8dd3b33 and
merge-verification.json bind the result. Observer43441 exited0.
Exact-main CI42106603414/1 and audit42106603334/1 are SUCCESS at
874472c952f7149206054ccb88b8e5a00e3bca17. All12 common consumers passed;
observer35930 exited0. E/main-runtime-evidence-ci/watcher-receipt.json SHA
771f902e0f9880e3a0fa54dd35127523e4e49f07b0f563f156fa7762105b9a23 binds them.
Physical branch: codex/preview35-runtime-qualified. Candidate artifact13453510219
has ZIP SHA47d2647860af8b4671418d1d14a128c6144d5e887c2cea8abbd0d5594880b455
and manifest50b9a152617a35ee754aea4b7403fadc76a690b538c58b573c1dec626fc11651
(1988bytes,6 payloads). E/observer-874472c95/producer-receipt.json SHA
1f0dfc4818064e437be9ddd24cd0c529d95ca84613b0f83c9500471d79e42e37 binds producer
metadata; no app archive was downloaded locally. This is not protected acceptance.
NEXT: one justified R with the reviewed passive runtime evidence. Full-paginated
live account-backed lists show UTC2026-11-05 positions1/2 above, no active run and
no existing dispatch for874472c95. Live main and local tracked source match;
E/readiness-runtime-r/dispatch-preflight.json SHA
651d4dc27b99fe10aef4c11125e88f1833787fea88e309b07d538b1ec38b4f38 binds the check.
R42111013665/1 was dispatched once at21:15:44UTC, exact874472c95 and
candidate42106603414. It FAILED; the authenticated result and repair are at the
compact checkpoint above. Observer54632 exited1 and must not be restarted.
This is daily position3; no further account-backed dispatch today. Never rerun
green main checks or either failed historical R. New G/P remain pair-specific follow-up gates;
their old82b evidence cannot qualify these bytes. No workstation retry authorized.
Independent review's lsof rc1/stderr ambiguity was fixed;9 tests and65 build/docs
contract cases passed. The live-site sidecar now
captures bounded passive daemon/owned-listener evidence at a browser failure
before fixture cleanup, and after its one owned control.106 focused tests passed,
then9 followups; logs E/readiness-native-r/runtime-{focused,followup}.log. The
existing immediate close of a new owned-route request during recovery is deliberate
under DECISIONS.md; changing it without attribution would not establish this
failure's cause. No production routing patch, new dispatch or workstation retry.

The patch preserves safe timeout/deadline classification and the first snapshot/
primary error before fixture cleanup, and validates temporary admin credentials
once before UI use. Focused50 tests and8 review followups passed; independent
review found no new blocker. E/main-observer-ci/auth-review/verification.json
SHAc351c442cc43d52c34f299c1981721655ec0a379c500e52fc7c9410607cc07f2
binds source hashes and checks. Runtime routing, UI actions, one-submit and90s
acceptance deadline are unchanged. The historical pending-prompt cause is still
unknown; the successful PR is not new-main candidate or Safari readiness acceptance.
The justified fresh readiness dispatch failed as recorded above; no workstation retry occurred.

E/observer-adf6521c4/producer-receipt.json records ONLY successful assembly:
artifact13440253770 / ZIP56e6a793e2b5c3a43529676486ae5a9be126d1aa9883b3d98fa6fc4e1f5de648;
manifest21d8e3ee147e72c83bf561993251bc6892caaff63ffbde41a2f1703a5b3a910f,
1988bytes,6 payloads. It does not admit a release or a protected readiness run.
No local app archive was downloaded and the restored .31 remains unchanged.

The observer retains navigation body sizes, bounded script/stylesheet evidence
and the last completed observation when a later observation times out. Focused105
Python tests, eight JS VM cases and three real Chromium loopback paths passed.
The unchanged99-test/PR baseline is reused; only the two affected followups were
rerun after review. The owned fixture browser and server exited.
E/safari-diagnosis/transport-diagnostics-verification.json binds source/test hashes
and output/playwright/transport-20261105/result.json. The `.35` Safari failure
itself remains unexplained, not fixed by this telemetry.

Protected readiness requires its observer, candidate and workflow at the same
exact main SHA. The new R above uses7a827fcbd for all three; do not detach that
binding or reinterpret old R. R precedes new pair-specific G/P so a repeated
live-site failure does not repeat already-green runtime checks. The accepted
82b3c2a77 candidate and its G/P proofs are historical and cannot qualify new bytes.
No publication or local installation has started; no user question is pending.

Safari27 on restored `.31` loaded xpersonatoy.com in one navigation: decoded
HTML838287bytes, responseEnd2746ms, DOMContentLoaded6179ms, load12466ms. At5.134s
the serialized DOM was only47662bytes despite the complete response; by10.186s
the document was interactive and all38 observed stylesheet objects were attached.
The30s screenshot visibly shows styled content and product images. This is a
successful workstation observation, NOT `.35` CI acceptance or proof of the old
stall's cause. E/safari-diagnosis/safari-observation-summary.json binds the
sanitized report, expression and screenshot. The test window was closed; JavaScript
from Apple Events was temporarily enabled with explicit user permission, restored
off and verified off after reopening settings. Remote automation stayed off.
No user tabs/cookies, applications, services, network or external Geph were changed.

The earlier SafariDriver session attempt returned500/session-not-created, made
zero navigations and left no driver. Two AppleEvents setup attempts also made
zero navigations; the first read the checkbox before its delayed change settled.
Its premature restoration claim is explicitly invalidated in the private report;
the final independent settings observation confirms off. Do not repeat these
attempts. No native CI qualification harness ran on the workstation.

Draft PR466's original revision98418b2133fa1f3869cac3db44af04127b48d8ca on
codex/safari-control-size-boundary contains the focused curl observer correction.
CI42043712587/1 and audit42043712597/1 are SUCCESS for that revision, not the
new transport diagnostics. Metadata verified the exact source, eight required CI jobs,
five expected PR skips and all terminal check contexts. Observer session69614
exited0 after observing terminal GitHub success; it must not be restarted.
E/safari-diagnosis/pr466/verification.json binds the saved run/job/PR metadata.
This is PR CI evidence, not live-site/readiness acceptance. Earlier main stayed
pinned while the workstation observation was pending. That observation is now
complete; the expanded observer is the reason for the next source change and
live measurement, not a blind rerun. One real execution of the
bounded control on the unchanged workstation returned200/exactly131072bytes with
curl56 and the exact maximum-file-size message. This exposed misclassification
of curl8.7.1's h2 size-cap exit as a receive failure. The patch admits only the
exact local message plus exact prefix length; resets/EOF and ambiguous evidence
still fail. Three new tests reproduced3 failed assertions before the fix;
99 focused live-site/readiness tests passed afterwards. Offline replay of the
captured result also passed. E/safari-diagnosis/control-fix-verification.json
records it; detailed findings/limits are in docs/ROUTING_RESEARCH.md. The retained
CI controls did not save their stderr/size, so do not reinterpret that old run.
Browser readiness still blocks release; its fresh R is listed above. At this
historical PR466 stage no protected run/publication/local install had been started.
Existing candidate acceptance here applies only to82b3c2a77.

The workstation independently downloaded full HTML and all14 early body CSS
files (each under2s), followed by the one Safari observation above. These are
another network/version observation, not `.35` reproduction/acceptance.
The old candidate's G/P/R are terminal; the current main observer is listed above.
The GitHub connector lacks workflow dispatch/listing support; normal gh is used.
No local app archive downloads, workstation installation retry, service mutation
or external Geph change is authorized by the .31 restoration approval.
OLD .34 remains the published and previously qualified source
`a0a60e080cc97214cebd7491f4ea5d56dff66e0e`, CI41634434348/1, manifest
`e71e6ea85e821c836fdd363af1989d4cac237a47586dd45c1f7a78dcc09f9deb`.
Read-only E/old34-candidate-availability.json verified release433775703 and
artifact13229144546/digest60483c70999b7986dcee9ea640456c5a4a345d65c48f4613881a02bb679151d6,
unexpired until2026-11-17. No applications were downloaded locally. Existing .34
G/P/R and .33 -> .34 public reports below qualify only those original bytes.
Published .34 assets must remain unchanged; .35 needs its own evidence and later
public-update/rollback checks. The publisher is pinned to preview_sequence35.

Accepted source changes: PR464 fixed installed-stop cleanup of a proven dead PF
receipt while holding the installer lock; ambiguous/foreign references and
unlocked foreground callers still refuse retirement. CI42017506255/1 and
audit42017505491/1 passed at final sourcef85d5c39, with real source and packaged
Stop proofs (initial PF disabled, global PF unchanged). Focused checks:130
stop/adapter,138 updater/lock,99 harness tests with64 subtests. PR464 merged as
b0e1724e5; its separate main CI42021590721/1 and audit42021591004/1 also passed.
Those proofs remain accepted. Graph tools were unavailable; bounded direct reads
were used.

PR465 synchronizes .35 metadata, publisher admission and the reviewed .34 -> .35
packaged prerequisite. Candidate authentication, transaction handling, routing,
dependencies and the verified daemon fix are unchanged. Initial b6d1158 failed
one of971 metadata tests in CI42022986292/1 because the publisher still admitted
sequence34; E/pr465-product-checks-failed.log preserves the cause. The corrected
publisher guard passed57 configuration tests. The reviewed pair/hash updates
passed140 prerequisite/source-boundary/workflow tests, including refusal of old,
reversed, identical and unreviewed pairs. Final source396ba362 passed
CI42025027322/1 and audit42025027364/1, all17 contexts green/expected skipped.
E/pr465-packaged-native-proof.json (SHA3510b654f4dd6fa27f53735aa9126ebdcbff29716615599d760b47a621c0bc8b)
binds the native packaged report and full log. The fetched merge tree matches it.

Workstation restoration is COMPLETE, not a .35 installation. With the user's
explicit approval, the one-operation guarded repair ran once at09:19:37–09:20:41
UTC and saved the invalid PF receipt privately before removing only that record.
The already-running .31 -> .34 abort then restored .31. At09:28:35 UTC,
ROOT/public-update34/workstation-check-20261105/recovery-acceptance.json reported
RESTORED_PREVIEW31 with all16 checks true: expected old app/daemon bytes, running
app PID91171 and daemon PID91087, fresh active StatusV2 and advancing heartbeat,
terminal quiescent root abort and exited0 workers. Settings, learning and external
Geph identities were unchanged; backups remain. The existing recovery cleaned
its journal/stage slots. Browser/media/Quit qualification is still open.

Cause proved: a saved token no longer existed in the kernel; successful
pfctl -s References returned No pf starter references held while PF stayed enabled.
The old worker repeatedly refused cleanup. What invalidated the reference is
unknown; discarding the original worker exception is a separate open observability
issue. The fixed code is not installed in .31, and downloading a successor cannot
retrofit its old worker. Details and evidence are retained in docs/RELEASES.md
and ROOT/public-update34/workstation-check-20261105. Do NOT run that directory's
recover_stale_receipt.py again, re-arm the failed operation or delete transaction
state. Its SHA is b74ea69d47a2d8eaa970177b450b7dc6709936e0906a93910834e790e0a521c4;
the approved restoration and its8 guard fixtures are complete.

Physical checkout: `/Users/aiwaki/.codex/worktrees/geph-route-continuity/slipstream-codebase-audit-20260905`.
Branch `codex/safari-control-size-boundary` is based on main
`82b3c2a77b22657524c28678422342799fdf1745` (PR465 merged after verified
release configuration, source, packaged lifecycle and browser checks).
The accepted .33 -> .34 public proof below binds14 observer helpers and workflow
to0a451afe6; those historical pins do not qualify the new candidate.
Published .34 qualified product source is `a0a60e080cc97214cebd7491f4ea5d56dff66e0e`,
tree79dfb9c10f9196c1b7520ba6f76bd65d0604aeb8; never substitute a new CI build.
Historical Developer checkout is different; preserve user changes.
ROOT=`output/continuation-20261101/preview34-release/post-stall-main-a0a60e080`.

Exact CI41634434348/1 and audit41634434632/1 SUCCESS; reusable candidate
artifact13229144546, digest60483c70999b7986dcee9ea640456c5a4a345d65c48f4613881a02bb679151d6,
manifest e71e6ea85e821c836fdd363af1989d4cac237a47586dd45c1f7a78dcc09f9deb.
All exact G/P/R hosted runs now terminal SUCCESS; no live qualification observers.
- G41808901780/1 accepted: native-g/verification.json SHA719b93a111280962618b513b831c24dd71c8e150ddb9bd6a2b86b824c7f10327; 12 checks.
- R41806799686/1 accepted: readiness-r/verification.json SHAba860744f32cfca9b22ac5a14b286c5ba0cbe88b56a1768a19477e32012c8193; 81 checks, authenticated six reports, 8/8 live sites, measured1800.046s soak. Daily guarded rank1/3.
- P41809745407/1 accepted: packaged-p/verification.json SHA27ac166dd91af558f8b9de9dc572aae799994035f2c658daa9df93ce6b8d8daf; 13 checks, real ACK commit and pre-ACK kill/rollback.
Each directory has root-acceptance.json. R/G retained evidence hashes rechecked.

P initially refused locally because private checker only accepted a registered
exited watchdog. Canonical unchanged observer also accepts a missing job after
observing its authenticated process, safe free transaction lock and exact five
absent paths. Actual commit returned113/no job fields; preACK retained exited0.
Original checker/refusal/execution preserved. terminal-checker-fix.diff and
17 positive/negative pure fixtures document corrected private checker. Independent
d_p_verify reviewed it. Raw absence stderr is not serialized; proof relies on
successful exact-source hosted predicate, not independently reconstructed stderr.
No production source or release policy changed; no qualification rerun.

Publication COMPLETE, verified from fresh public API and small JSON assets.
Publisher41813047079/1 SUCCESS; release433775703 is non-draft prerelease,
https://github.com/aiwaki/slipstream/releases/tag/v0.1.9-preview.34 .
Lightweight tag binds exact a0a60e080; all12 unique public asset sizes/digests
match artifact-manifest and immutable candidate manifest. Qualified manifest
hash unchanged. Publisher verified full remote bytes and current-date policy;
local verification downloaded only three small JSONs. Previous .33 release430591253
retains12assets and is now titled `Slipstream 0.1.9-preview.33 (архивная)`.
ROOT/publication/publication-verification.json SHA
0476d0a6dea80b540d4d973173a35d87a57bdc4b8088a72dde28f61bc0d9d6c9
binds run/jobs/release/tag/manifests/previous metadata. Do NOT redispatch publisher.
Earlier workflow/observer processes are terminal; new rollback41896398249 is pending below.

PR462 MERGED after all17 check contexts completed (expected Windows skip),
CI41816640607/1 and audit41816637269/1 SUCCESS; review threads empty.
Observer session2820 terminal. GitHub outage required exact-SHA Git API push;
public-update34/api-{tree,commit,ref}.json and merge-verification.json bind this.
All14 helper hashes/workflow match reviewed source. Historical .32->.33 unchanged.
315 hermetic tests plus final12 pin/source/workflow checks passed.

Public commit41818750355/1 is terminal FAILURE, not an updater transaction failure.
Fresh exact-attempt GitHub metadata and authenticated report show the anonymous
prelaunch feed returned HTTP403 with x-ratelimit-remaining=0; classification
external_rate_limited. OLD was NOT installed/launched by the trial, no transaction
occurred, cleanup_errors=[], no public commit acceptance or rollback dispatch.
Observer session66026 is terminal. Source-bound report artifact13315454267 is
109574 bytes, ZIP SHA f20c1f7dec39cb061154a1fb5271421df05f3b76583d606177c598358861e1e3.
public-update34/public-commit/artifact-authentication.json SHA
fa8e9d0df52486f3bfd59c4a2435cc49eb1bbecd3aea8ba4a5f129f525ddf8ac
verifies exact run/attempt/source/job/upload windows, ZIP bounds and source binding;
status AUTHENTICATED_FAILED_RUN_EVIDENCE, runtime_accepted=false, context_created=false.
No success context or full semantic acceptance was fabricated.
GitHub's captured reset time is 2026-11-04 11:36:37 UTC / 16:36:37 Yekaterinburg.
This is not a guarantee of available quota on another shared runner IP.
Post-reset run41823085631/1 SUCCESS and independently ACCEPTED for public
Cancel + commit. Observer session11522 and collector67662 are terminal exit0.
Anonymous feed returned200, remaining57; normal OLD background discovery and
visible Install, native Cancel preserving OLD, fresh discovery/Install/admin
confirmation, normal OLD exit, NEW acknowledgement and durable committed root
transaction before lease deadline were verified. NEW heartbeat advanced;
watchdog registered-successfully-exited; cleanup_errors=[]. No app feed override.
Report artifact13318475913,142151bytes, SHA
9eeb22316bd54c5b05c6a4470f697707d2929a434299db9c7238d769cfb0e991.
ROOT/public-update34/public-commit-after-reset/verification.json SHA
2e71cba42bccbe7102a7391499f0a3b5e8b74f24db677004a27e9a35c12d19b9;
artifact-authentication.json/context.json/metadata and root-acceptance.json bind
actual attempt/source/job/upload windows/public inventories and semantic proof.
Source remains observer0a451afe6/producta0a60e080; original refusal41818750355
retained independently. Old quota blocker is no longer the next blocking gate.
Public rollback41880503074/1 terminal FAILURE before OLD launch: anonymous
feed403, remaining0, new runnerIP13.105.117.253; reset17:56:46UTC/22:56:46local.
No transaction observed, cleanup_errors=[]. This does not qualify or disprove
rollback. Observer85644 and collector19116 are terminal. Initial cached job
snapshot remained queued after run terminal; fresh exact-attempt metadata then
confirmed completed failed UI step and successful report upload (no job restart).
ROOT/public-update34/public-rollback/artifact-authentication.json SHA
cae118112a194ddeb9d54b48b131e673bc2845486b19613f22f2063c5086dfd5;
artifact13349840109,109607bytes,SHAef17a019f227925a7afb9459b131a1201380a3dadd2bd2fcff1c6fe4c3207a87.
Exact source/run/attempt/job/upload provenance verified; failure-diagnosis.json
retains original response, no success context created. Accepted commit retained.
Post-reset rollback41882183022/1 terminal FAILURE without acquiring a hosted
Mac. Exact-attempt job126757224971 is completed/cancelled, no runner name,
steps=[], artifacts total0. GitHub failure annotation: "The job was not acquired
by Runner of type hosted even after multiple attempts"; accompanying notices
state macOS arm64 capacity constraints. No app preparation or rollback occurred.
Observer20651 is terminal. Collector8130 correctly refused missing successful
upload; no ZIP or success context was created. API metadata and annotations are
retained in ROOT/public-update34/public-rollback-after-reset/;
failure-diagnosis.json binds their hashes and exact source/run/attempt/job.
Public rollback41896398249/1 SUCCESS and root/independently ACCEPTED.
Observer67ceb1c0, producta0a60e080 unchanged. Actual successor stopped/killed
before ACK and deadlines; durable aborted decision, exact .33 app and daemon
restored, heartbeat6->7, watchdog exit0, free lock/exact5paths absent, cleanup[].
Initial/final12asset inventories and public tags unchanged; no feed override.
Artifact13355762694,131469bytes, ZIP SHA223d1fe6920534967c77f00ab4103a424108ef485506bc3701cd01a9b1bd6ca0.
Evidence ROOT/public-update34/public-rollback-capacity-recovered/:
verification SHA4b84492ba0759825b7271a4ae1bd4f5b4aba7915588a644bb0bc90719e1177bd;
independent-review SHAc1eefae7ed94ab782b02459983306fbbd82e0bd53ab557dfaad05d4276013da4;
root-acceptance.json binds these to authenticated source/run/report.
Separate offline-verifier-main67ceb changes only expected observer SHA;
pins SHAa571ff1592f82ff10fea1d120d2c0e7c570818af624cb57424680b4679ea04a8;
checker unchanged17398b90637109a90897517ae5b5ead0c49c5d5801c342b3e33e41ba98846a19.
All observers terminal; accepted commit/G/P/R/publication and failures retained.
Do not rerun any of these gates. Heartbeat slipstream-34 has delivered its result;
the one-shot automation was deleted after verification. No new workflow dispatch needed.
Previous handoff: requested ordinary Check Updates -> Install .34/admin action;
the user has now attempted it, with the failed recovery recorded above.
Window authorized today2026-11-05 Asia/Yekaterinburg; public rollback prerequisite met.
Local baseline at19:44UTC: .31 app stopped, owned service absent; external Geph active.
Durable .31 ZIP backup verified plus signed official .34 archive/sig downloaded;
verify_updater_artifacts.py and GitHub attestation PASS, canonical staged app-tree
8806356c96cdeb4ea309760e7bc654001fa561bf1d3ef37270bd38c545892d98 matches manifest.
CUA launched .31 PID50553 but app/SystemUIServer AX timed out -10005; Finder works.
At19:53UTC pre-replacement guard found owned .31 service running PID50967 and
owned Geph51120. Cause of activation not yet attributed; external Geph PIDs
574/594/738/56311 remained present. No signal, app rename or manual replacement
occurred: guard refused first. On disk remains .31. Do not rerun manual swap.
ROOT/public-update34/workstation-20261105 retains baseline, backup, signature/
attestation/staged proofs, installation preparation and baseline-change-refusal.json.
Existing root runtime /usr/local/slipstream is root-only, retained unchanged by
our file operations; no claim of full runtime backup. User now asked for ordinary
public menu update because native tool cannot click it. The subsequent check
above found failed recovery; no blind reinstall/re-arm. No CI harness on Mac.
Workstation .34 installation, ordinary Quit and sustained media/voice remain open.
Independent commit review saved public-commit-after-reset/independent-review.json
SHA58ae7badb6dc64bab4c8cb9da11dda098cf7906d0677c6b0201b8d2193213e0b.
The frozen rollback verifier already binds the root deadline to the prepare
deadline through validate_root -> validate_status, then requires fault kill
before that deadline and the successor deadline. An explicit comparison with
fault_stopped_window.root.deadline_unix would be redundant, not a missing gate.
The first independent review overstated this point; no verifier change or
qualification rerun is required.
The earlier commit heartbeat was deleted; the separate rollback follow-up was also deleted after accepted rollback.
No user Mac apps/services/network/account changes or local app downloads.
Read-only workstation snapshot in public-update34/workstation-readonly-snapshot.json:
/Applications/Slipstream.app reports preview.31; launchctl print of owned system
service returns113 with exact missing-service diagnostic. This is not canonical
installed verification of .34, nor proof about external Geph state. No native
verifier or app was launched. DECISIONS.md workstation-window rule still applies.
Current checkout does NOT provide npm verify:local-install or scripts/verify_macos_app_bundle.py;
those external instructions are stale for observer0a451afe6. Existing canonical
source paths: scripts/release_candidate.py verify (read-only package/tree proof,
requires manifest + all six candidate files and exact pins); status_client.rs +
slipstream-core/status_v2.rs parse fresh /var/run/slipstream.status;
install_attestation.rs validates root-owned schema3 record and daemon witness.
There is no combined read-only installed app/launchd/fresh StatusV2 CLI here.
Do not run build/install commands to compensate for that missing entrypoint.
Checker prepared from accepted .33 verifier; root-reviewed diff and22 pure
terminal fixtures pass. Pins now bind actual merge0a451afe6 + reviewed patch470fce858;
14source hashes and G/P/public identities retained. No fabricated run acceptance.
Watchdog absence113 permitted only by source-bound successful hosted predicate,
all5jobfields empty, no process, free safe lock, exact5paths absent; raw stderr
not serialized. Loaded exit0 branch remains strictly checked. Do not weaken UI,
Cancel/ACK/kill/deadline/visibility/final-public or cleanup evidence.
Accept real public commit BEFORE dispatching separate pre-ACK rollback.

Git post-commit sessions68613,27706,28226 ended0, but Entire PIDs25510,43091,43727 ended signal9; cause unknown,
Entire history checkpoint success unproven. Source commit intact; don't restart hook.
Pin OLD .33 CI41302269258/1/source9eccd1ddf691aef5f76d493103513f2fada2fd5c,
manifest e2e0e5432ea12208922c775c7a6d7ea5ab87f44491d45de94524df8c41193ba0;
NEW uses current candidate above, G41808901780/1. Freeze public12asset IDs from
fresh retained release metadata, not guesses; previous .33 archive title changed.
Update pair NEW_SOURCE/PAIR/PUBLIC_RELEASES/ROOT_GATE/source_binding helper names,
menu VERSION and import (its class uses its own module globals), workflowpins.
Retain eight reused helpers byteequal qualified source, with separately reviewed
observer-only descendant source binding. Add focused contract tests; PR by default.
Run public commit (ordinary discovery, Cancel->confirm) first, verify receipt,
then independently admit pre-ACK kill/rollback. Hosted UI/Accessibility preflight
must actually pass. Packaged P cannot substitute this public product path.
Physical workstation/media/Discord/sleepwake remain open. Previous intermittent
Safari stall not reproduced; cause unproven.
Green fixed-site matrix is not proof for arbitrary sites or product completion.
No Mac app/service/PF/DNS/proxy/PAC/VPN/account changes, local native builds,
app downloads or live probes. External Geph untouched; only small evidence/Git/API.
Full preceding checkpoint: publication/checkpoint-before-publication.md.

**B** = `output/continuation-20261101/preview34-release/`.
**DROOT** = B/post-observation-main-a2761595/.
**H** = B/chrome-navigation-pr458/head-49c39dc31/.
**EROOT** = B/post-chrome-main-80004f469/.
Previous complete checkpoint preserved EROOT/checkpoint-before-main.md.

### Candidate F — accepted G/R and failed original P

PR459 MERGED as f612f97a59e83688e1c7c798ecbeb77a4bbf6cc8.
F remains the immutable candidate; main H adds observer diagnostics only.
Reviewed62f6f05dd and mainF trees equal. All8 applicable PR consumers and3
required contexts passed, no unresolved review threads. PR observer11145 terminal.
Main CI41601618690/1 and audit41601618546/1 SUCCESS; all12 applicable
consumers passed. Observer6074 terminal. Root independently matched producer
125805278379 logs/API, manifest a22f671c3bed6d30a80d97936328ef8442cd4cce877c96feef63ef06e10388ff,
artifact13215890729/452662762B/digest9a30270a449bd1b6bf620d1bdf571c5299cee28060d81f136701b5b370545bf5.
FROOT = B/post-safari-evidence-main-f612f97a5. Main receipt SHA
2ca8e15edaa2138db82cf55827cd052404359a20cba3c406c906ecb4ed441135.
Root producer proof FROOT/root-producer-preflight.json; canonical candidate
bytes authentication happens in hosted R before installation, no local app download.

R41604292643/1 dispatched ONCE08:34:30Z on mainF, candidateCI41601618690.
FROOT/readiness-r/root-admission.json verified current main/CI/audit/artifact and
complete Nov3 budget lists: previous1run41593333393, prospective rank2/3.
Actual budget125810198194 confirms rank2/3; log SHA
b02da19cb14e17962d1206fcda9cf9fc0a754fcb768b0a2020cde0632c078ef8.
d_p_verify observer88503 terminal. No redispatch.
Live-site guard PASSED08:40:16Z; measured soak PASSED09:10:27Z.
R full acceptance is recorded below with authenticated reports/attestations.
Known failing site gate is now passed. While independent R soak runs, root
admitted and dispatched G41605285175/1 ONCE08:42:32Z for exact .33->F pair.
FROOT/native-g root-preflight/inputs/dispatch saved. d_r_diagnose owns one
read-only G observer and unchanged verifier; no app archive local download.
G41605285175/1 accepted12checks, raw/source hashes and live terminal jobs
independently matched. Verification SHA d53b15350bffb459cfb745930fcf5bcfebcc358397ca234315f11a5aaf6f7dd3;
root-acceptance SHA fb84af70f6e3d64c54062f51cba808bbc75824710043e2acb0dc24c8bf42e43f.
G observer18169 terminal. P41606509130/1 dispatched ONCE08:52:16Z;
d_r_diagnose owns P observer/verification, FROOT/packaged-p evidence.
P checker a10e0d368ad63f075951b1a2541a4277c05a05e9d3f50db21b71097142f68c08
is identity-only adaptation of E9595c880, exact reverse matches; no predicates changed.
R41604292643/1 is hosted SUCCESS09:11:42Z: live sites passed,
measured soak08:40:16–09:10:27, attestation and final require-passed steps passed.
Observer88503 terminal. R accepted79checks: two small proof ZIPs, exact
certificate/statement source/ref/run1 and6subjects, canonical live/soak/transport,
budgetrank2/3 and G NEW app_tree cross-binding all passed. Measured1800.15s,
3600samples,maxgap0.749s,11zero counters,stablePID/heartbeatadvance/cleanup[].
FROOT/readiness-r/verification.json SHA
4911602e4b1d41700dbcbee569a291135b7167b0ff84f0bce1439bd8308dcf06;
root independently verified retained hashes and fresh terminal jobs:
root-acceptance.json SHA8019338db9f453fca2f0a7e2feec2d030138652d169e671983e4f89b80459cb8.
This is fixed-site/mechanics/background-invisibility evidence, not user-Mac
continuous media, Discord or sleep/wake qualification.

P41606509130/1 FAILED commit at09:01:10Z; preACK rollback scenario passed.
Same-sample watchdog diagnostic: PID present, UID/state valid, command_match=false;
helper hash not evaluated. The failing command form was not retained, so launchd
pre-exec/path/argv/foreign-process causes remain unproved. No pass checker or retry.
Both small report ZIPs authenticated; FROOT/packaged-p/failure-diagnosis.json
SHA9742109fa7add6edcb426dad2866a0fac920735fb396553e8fcbdfa6407259ba.
P observer24461 terminal. Same-sample command classification and nullable
launchd identity facts are implemented; errors preserve the original booleans.
39 scoped tests PASS after old-code RED;0.126s/RSS53MB/forbidden_calls0.
Root reviewed46 source invariants; all existing functions and original guard
AST-identical except isolated best-effort enrichment in the failure handler.
FROOT/packaged-p/command-diagnostics/review-corrections/verification.json
SHAfd29a248d0949cf20f52c0659c8a686022021be063add5068ed9f5e672ca374f;
root-review.json SHAe14a2460faa0063b55627cbbf1c089ff869bea89eba9b6091f6c92e8f747d030.
This is diagnostic repair, not a claimed product fix. PR460 has passed and merged;
the one new H-harness diagnostic P is recorded at the top. Original F P remains
failed. No protected R redispatch. Root owns checkpoint/Git/PR.

All mandatory gates remain required; E G/P does not qualify F. Publication remains
blocked by F P failure, not by completed R polling. Observer-only main descendants
may diagnose unchanged candidates under docs/DECISIONS.md, but publisher .34 still
requires its exact main source; do not broaden publisher policy or silently reuse F
as a newer payload. Preserve accepted F evidence and do not rerun green suites.
User-Mac limits and .34 unpublished status remain unchanged.

### Safari evidence repair — 2026-11-03T07:15 UTC

PR459 OPEN, exact head62f6f05ddba2ed25539c732fa7472ba120640bc9.
https://github.com/aiwaki/slipstream/pull/459
CI41599663839/1 running; audit41599663739/1 SUCCESS.
At08:03Z packaged-app-build and Chromium passed; packaged browser/heavy lifecycle
executing, product lifecycle sentinel executing. Root confirmed empty review
threads and exact head/base. d_p_verify owns observer11145; root cannot poll
agent-owned tool handle directly. Do not infer termination from root Unknown ID.
Evidence B/safari-navigation-pr459/head-62f6f05dd. Do not dispatch duplicates.
Next: verify required CI/review at exact head, then merge if all gates pass.

Git commit session50232 terminal SUCCESS after auxiliary Entire post-commit
failed to finish in >17min. Root verified ownedPID62710 and sent SIGTERM, then
SIGKILL after >60s without exit. Only own hook process stopped; no hook/config
changes or checkpoint/session deletion. Commit and ordinary git push succeeded;
PIDs62676/62710 now absent. New Entire checkpoint completion is NOT asserted.
Interruption/sample evidence EROOT/readiness-r/failure-diagnostics/entire-*.
Do not restart commit or old hook; current continuation is PR459 CI.

Current branch `codex/safari-navigation-evidence`, based on exact main E.
E main CI41514778142/2 + audit41514778253/1 SUCCESS (12common consumers).
Candidate13210440053 manifest
f3de6f8af3aa2a954b8a4d940178c561e234a8f9569a84587dbc1b363058b355.
G41591766189/1 accepted,12checks; root-acceptance SHA
 d359573b271a9952f9c2e8eb31d4faeb8b5a2e012ff50e4d5265478ef927cf12.
P41593326142/1 accepted,13checks; real successor ACK and preACKSTOP+KILL
restored OLD, heartbeat/watchdog/cleanup passed. Verification SHA
4532394f5ee78cf25ee234090f6c6c9a586c756ff6ec54687f3d92899af1ecc6;
root-acceptance SHA6176cff037137cc51532ae61b35968d096b6493a001a116294b1beea77f409df.
Evidence EROOT/native-g and EROOT/packaged-p. Watchers60742/29003/6497 terminal.

R41593333393/1 FAILED live-site gate, no soak. Watcher37253 terminal exit0
(observer completion, NOT gate success). Nov3 actual budget position1/3.
Safari xpersonatoy20106ms readiness_context_invalid: https=false,
host_matches=false,secure_context=true. Chrome samehost usable6265ms; other3
hosts usable in both. Both controls HTTP200/curl56 receive failure: origin full
payload unknown. No proven routing cause and no source repair inferred.
Four-member diagnostic ZIP13211745454/1531B authenticated SHA
 e30af9ad1bff5c7fa93f6c0c7950976590165d67a6f36057176f0ca2330f3449.
R log/failure-diagnostics/failure-diagnosis.json retained EROOT/readiness-r.

Observer-only patch is ready on this branch: fixed document kind, first/final
snapshots and bounded counters within existing Safari snapshot; no raw URLs,
extra browser requests or changed gate/deadline/cleanup. New cases old-source
RED then GREEN; guarded affected module87PASS,0.090s/RSS49.8MB/forbidden0;
33 pure V8 fixtures PASS. Verification SHA
cc3c234fa23769bcc127d340365577a16b6a903fca6210de5f4aeae1678e047e;
root review/evidence in EROOT/readiness-r/failure-diagnostics. Agent frozen.
Smoke SHA c5af0185e55169942eee65597d38cdd97bb0f5ff30fa332aced4cff68efb3071;
tests SHA4162e4725e37727768ac31eb63f69dfe2e99be082b15cf86ea14e0bfc3d45701.
Root verified unchanged classifier/readiness/settle/Chrome AST and reviewed
privacy/exception/cleanup boundaries. PR459 is already open; await required
CI before merge and new exact-source qualification. Do not repeat commit/push.
Do not re-dispatch R unchanged or call it origin-down. No new P/R/publication.
Prepared publication baseline EROOT/publication/existing-publication-baseline.json
SHA cb3edcfbd13de30a14eb3ae65ba0ab7fac227690640fb4d9b317e314fca77946
preserves .33 twelve assets and stablev0.1.4 five assets; .34 absent. Prepared
inputs are NOT admitted; fresh exact-source P/R/current audit required first.
.34 UNPUBLISHED. Public update/media/Discord/sleep-wake remain unproven.
No workstation app/services/network/externalGeph changes or local native builds.

### Resumed main recovery — 2026-11-03T06:25 UTC

User reactivated goal; fresh blocked audit starts here. E/source/main unchanged.
Fresh API: CI41514778142/1 terminal failure; audit41514778253/1 success;
no active/queued repo workflows, no candidate artifacts. All three macOS jobs
have zero steps and confirmed hosted acquisition failure. About10h cooldown.
Root admits ONE --failed/dependency rerun of missing main gates, preserving
successful audit and all source/runner/gate policy. No local app/native work.
Admission and fresh snapshots EROOT/attempt-2/retry-admission.json.
Admitted rerun command accepted once; latest API attempt2 statusin_progress.
Existing d_p_verify assigned read-only observer. Do not resend rerun command.
Watcher60742 is live (d_p_verify); handle EROOT/attempt-2/watcher-handle.json.
Actual attempt2 jobs: build125763266080 runner1000013703,
product125763266265 runner1000013702, Chromium125763266313 runner1000013704.
All got runners; Chromium SUCCESS, build/product executing at last fresh poll.
Next: await same attempt2 closure, capture producer log + candidate manifest hash
and metadata without app binary download; root authenticates admission before G.
Candidate manifest/producer/attestation AND successful CI must bind attempt2;
no blind PR-style mixed-attempt admission. Stop and diagnose any new failure.
Scheduled one-shot slipstream-34 ran at20:35UTC Nov2, confirmed unchanged
capacity failure and was deleted. Old watcher81064 terminal, never restart it.
All blocked/queued/live statements below are historical, superseded here.

### Main CI external blocker — 2026-11-02T20:16 UTC

E CI41514778142/1 terminal FAILURE. Root independently verified exact source
and all three actual macOS job cancellations with zero steps and explicit
hosted runner-not-acquired annotations: product125515613762,
build125515613784, Chromium125515613830. Audit41514778253 SUCCESS.
Root evidence: EROOT/root-capacity-blocked-audit.json plus exact job/annotation
snapshots. No E candidate was built. Watcher81064 already terminal exit1;
no signals/cancel/rerun sent. Persistent macOS capacity blocker recurred over
consecutive main waiting turns; goal marked BLOCKED pending external capacity.
This is not a source/test failure and not completion. User-scheduled heartbeat
slipstream-34 remains active for01:35 local; no immediate retry, no local build.
On user resume perform fresh blocked audit; historical PR recovery is not E proof.

### User-scheduled follow-up — 2026-11-02T20:13 UTC

User requested a later check. Created one-shot thread heartbeat `slipstream-34`
for 2026-11-03 01:35 Asia/Yekaterinburg (2026-11-02 20:35 UTC), read-only status
of existing E CI41514778142/audit41514778253. No duplicate workflow dispatch.
d_p_verify instructed to stop ONLY local metadata watcher81064; GitHub workflows
continue. Scheduled check reads this checkpoint and actual API state, reports
result or active step, and performs no release/local app/network mutation.
Goal is not marked complete or paused; user asked scheduling, not goal closure.

### Next verified action

Fresh exact-E main CI41514778142/1 queued/running and audit41514778253/1
in_progress, both auto-triggered by merge. Observe THESE actual runs, no extra
workflow dispatch. EROOT/merge-source.json binds PR/tree/source/run IDs.
Read-only watcher81064 (d_p_verify), EROOT/watcher-handle.json, is live.
Audit41514778253/1 SUCCESS; CI jobs product125515613762/build125515613784/
Chromium125515613830 queued at last fresh check; no duplicate run.
Main recovery caution: Native.verified_manifest requires the SAME pinned
manifest builder attempt to have successful exact-main CI. Do not copy PR
leaf-rerun strategy blindly if main later fails: EROOT/attempt-binding-preflight.json.
Old .33 publication/artifact13081049724 and unchanged G checker verified in
EROOT/old-reference-preflight.json; no E candidate/G admission yet.
Verify actual jobs/required consumers,
attested immutable candidate artifact/manifest after CI closes. Never use
PR success as main-candidate payload proof. Retain all producer outputs.
After fresh E CI/audit acceptance: native G -> packaged P and readiness R;
use original .33 as OLD, E as NEW. D G/P cannot qualify E; D R failed and must
not be rerun. Re-read current R budget/UTC admission and source rules before
any new protected dispatch (max3/day including failures); no secret output.
After accepted E gates: publish .34, verify public assets/finalizer, real published
.33 -> .34 Cancel/commit and pre-ACK rollback. User-workstation sustained media,
Discord voice/stream and sleep/wake remain separate/unproven; do not claim done.

### Completed PR458 proof; do not repeat

Root fresh CI41490482724/5 SUCCESS, audit41490482859/1 SUCCESS; all three
required contexts green, all applicable jobs success/skipped. Actual original
execution lineage independently fetched, not GitHub copied sibling job IDs:
build2/125443004101; Chromium2/125443003971; product3/125492080660;
checks3/125501689147; browser4/125502711270; heavy5/125505126780;
required lifecycle5/125514278804. Review threadPRRT_kwDOTLueX86yx7tX resolved;
fresh head/base/source verified before protected expected-head squash merge.
Root acceptance H/merge-admission/root-acceptance.json SHA
1a4fefb910335677b005e9af8ab3ee4a246c372bcadd8e332da69b561590693a.
Heavy watcher28548 terminal exit0; receiptacc1fcd432b2bb0acbc7c04df0bdc300936d526e200526924c0fc1ea90a62b57.
All earlier watcher handles terminal; NEVER restart them. Actual product963
metadata tests plus daemon/Rust/contracts passed; local module83/83 alreadygreen.
Build artifact13165409068,453572589B,digestd1551be119876d995a7431a3bbdc03d185568e9305b5d0dbb4d6d3b790d759a3,
expiresNov9. Browser actual download ID+digest verified; packaged headless smoke
passed, not the future protected live-site matrix. Product receipt SHAaa0ecaae2497d89d4a1019d3904091bfef4cbb94e45f2524d3a0189642a6e192;
browser receiptd8f79a1cffa87a7ed17311887da37d7f73fbaa94357c6914e8b8a8c69b1bf618.
Root checked all those retained hash maps. First two attempts failed because
macOS runners never acquired jobs; only missing leaves were retried serially,
without source/runner changes or repeats of successful build/tests. This blocker
has cleared for PR458; no historical blocked status applies to current goal.

### Cause and reviewed repair

D R41349606587/1 failed before soak. Safari xpersonatoy usable8737ms;
Chrome terminal navigation_rejected10039ms, sidecar exception_class TimeoutError.
Page.navigate response timeout10s escaped the observation loop despite the
existing20s semantic host window. Timeout does not prove rejected navigation.
Both controls: HTTP200/curl56/markertrue/categoryreceive. Full payload and origin
health are unproven; no blanket transport/network explanation is claimed.
Authenticated four-member diagnostics artifact13101096744/1534B SHA
36e9ecb6cdbec50fb1e1a5068f5277e4136d0e3604353d34cab875940e92fde6.
DROOT/readiness-r/failure-diagnostics/failure-diagnosis.json SHA
a488f6d5121c8d559e9f3168f41e675eed6cf90551b133765f60b77912e1522e.

Repair catches only Page.navigate TimeoutError as pending, then observes same
owned page without navigation resend/reload, within the original deadline.
Navigation response budget min(10s, site budget); explicit errors stay terminal.
Classifiers, positive signals, HTTPS/ownership/activation confirmation and late
observation rejection unchanged (all production AST except _run_chrome identical).
This preserves semantic acceptance deadline, not a hard wall-clock cap on every
socket read: shared CDP helper has per-read timeout; no helper redesign here.
Five new guarded cases: exact-D RED3/5 -> repaired GREEN5/5; five affected existing
controls GREEN5/5. No native/network calls; no broad suite repeated locally.
Observer SHA45f884f4a470cfdb9ec875a3c32b3a6be7f552cefbed2c7ee8a9d0de492884f0;
tests SHA56d377afab2c11e4dacc11e91400e5f86a161e47f3babbbc85c9faf0b998ed13.
Independent review DROOT/readiness-r/independent-chrome-pending-review.json SHA
c1fb0792c7fcae58989d05ab6be359d6c19371db8ed895ae80c8058fe7fe7727.
All source/guarded runners/logs/diff/baseline evidence retained under readiness-r.

### Immutable D evidence

Exact-main CI41347397805/1 and audit41347397796/1 passed all12 common consumers.
DROOT/receipt.json SHA002c561df15c1b26245c453171a48ebb1e32833c1b491ffc1d7b8e27e40b319d.
Candidate manifest73b4c0d25958507cde3ac9d2bb9008b335e5bc4e4b431dfadfa7aca9ddb26d92;
artifact13099578792/452665654B/transport
9b9d62983aa1da5e520363b1cbc330896a5733f9c36c66c9b4c49a163e8db462.
G41349034621/1 accepted12 checks; verification SHA
f12b2673f9d7d0e2654fd96a30a91fb700bc4a4c1b4218efe0ead8b03d6c9559;
root acceptance efbbf118d4ec1f4f88fc29d5d1a166f3fac2a488f16d21a71c3fe1584dc4fac6.
P41349603079/1 accepted13 checks: real ACK committed NEW, pre-ACK STOP/KILL
restored OLD; both same-PID heartbeat, watchdog terminal and empty cleanup.
P verification SHA f9de617d191be683574c5c7ca8422efba4d0133665e5be7517e7eef65e12e332;
root acceptance9dd27952ebc099556c4194336016c46fdd2fbc98decd9fd80514cc0466095f50.
Pin-only P checker independently reviewed, executed once, no predicate weakening.
D R remains FAILURE/inconclusive; no soak, retry, waiver, or publication.
Budget124976746208 proved Nov1 UTC position3/3. Fresh complete admission lists
required before future changed-source R/owned-Geph dispatch; new day is not a
reason for an unchanged rerun. Old watchers16513/92809 terminal; no active watcher
remains. Bounded d_p_verify/d_r_diagnose agents finished their reviews/diagnosis.

### Reviewed diagnostic patch

P retains a fixed bounded watchdog_identity_diagnostic on the existing identity
failure: same process/hash observations and short-circuit order; no extra native
call, retry, argv, nonce or raw error. Original exceptions/refusals survive failed
evidence storage; success events are unchanged. Seventeen focused guarded cases
passed (0.10s, RSS51.3MB, forbidden calls0), including ten old-code missing-evidence
regressions. Root independently confirmed the unwrapped guard AST equals C.
B/failure-observations/P/verification.json SHA
0af4913849bed4bd8cea7462f97acf7d7a68026e13007bbfa1460dedbd4e759b;
root-review.json SHA055fd9c55dbc576b7954d6b4b514455f8153027a808e8d2eb510734feef48660.

R adds a separate --failure-report containing existing curl exit/status/category,
Chrome net-error/class and final Safari context booleans. No new network/browser
observation. Missing final signals clear stale context. Only the new sidecar write
is tolerant; existing startup/authoritative writes and schema2 remain strict.
Always-stage/upload preserves flat diagnostic ZIP members separately from attested
dist-readiness. Focused RED/GREEN, unchanged15-case baseline, five affected writer
checks and final curl metadata subcases are retained; no broad repeat.
B/failure-observations/R/receipt.json SHA
47b0fc48a10c0f2592e1b208a3aee2f2cdef5888e67a35c72d42d89c18b04f8a;
root-review.json SHA2bbf363fa29e49a0f7826ebda361a2facfa8a13107e314e1e43ef9e99687bd50.
Independent reviewer approved final source/test/workflow hashes in that receipt.

### Failed C qualification: preserved, not accepted

P41342380406/1: commit job124954948234 passed; pre-ACK job124954947986 failed
before STOP/KILL/ACK at `Refused('packaged watchdog process mismatch')`.
The process presence/UID/state/command/helper hash mismatch was not retained;
no runtime, quoting or infrastructure cause was proven. Both authenticated ZIPs
and all8 members are in B/packaged-p. failure-diagnosis.json SHA
cdaa0d94568a01f99bd6200e54747048051ec97f3728892767d46c20d8790618.
The success-only P checker is unchanged/unrun (SHA078e7ad971400d0697073b08a81878c476320663851d181f8ffeccac8f96d891).

R41342383932/1: failed before soak at Require passed live-site matrix.
xpersonatoy.com: Safari readiness_context_invalid after20s; Chrome
navigation_rejected after336ms; both direct/owned-Geph controls unavailable.
The other3 hosts passed both browsers; all Safari starts and product cleanup passed.
Control reasons were discarded; this does not prove origin outage or product bug.
The three logged SSLEOFErrors were intentional earlier closed-route probes, also
present in successful .33; do not misattribute them to the failed site.
B/readiness-r/failure-diagnostics/bounded-static-diagnosis.json SHA
0a9deba76f33008e198f730ca0917f3c9eeda7fbfa76e918f00bb68088107732.
Budget job124954957424 recorded position2/limit3 at19:34:14Z on2026-11-01;
budget-verification.json SHAc9e6127c093110ffbfee84013569aab7456849d78b05bb7f146c0a91d631edcc.
Combined watcher78446 exited1. No readiness/soak PASS or .34 publication exists.

### Accepted baseline C (not proof for future D)

C = 91d49cc04c06299aa853b80647f96ac2ba73b2c7.
C came from PR455, checked75bc0988b23a73f775b87bfbe202d10b175a359d;
merge tree1dcf44d7fc8a00318e9d429440f37470785b26b5 matches reviewed head.
Main CI41339429427/1 and audit41339429363/1 passed. All12 common CI jobs passed;
unchanged Windows adapter skipped. B/main-91d49cc04/receipt.json SHA
eb46eb4f8d2095e37b79b2c5104426f33277ac348c242c169a214f1514afbec8.
Candidate manifest454e6a0132e7e0cb02b6774080fc52bd485cad450ab8441495289674565ea059,
artifact13097336246,452662995B, transport SHA5d43b14bd1cd3cfd728e39d34c12ab4b2bcfef74ede041f5ecf48076415e22f8.
Producer assemble124948863014 passed; B/main-91d49cc04/producer-receipt.json
and root-producer-review.json retain producer evidence. No app downloaded locally.

G41341351547/1 accepted: commit and crash-before-commit native outcomes, matching
pair/source/provenance, live PID/heartbeat and cleanup all verified.
B/native-g/verification.json SHAb93064d26e43082398f45215d60cec362aa769951def4da88b749ef97eef0c32;
root-acceptance.json SHA00718e6faa8d2cb9c7228a889dc22e9c6744f55692a0f0544a78f98712825d05.
Retained initial checker refusal was corrected only for source-proven terminal
attestation refresh on unchanged old PID after rejected late commit; phases,
sequence, helper identity and within-heartbeat/final attestations remain strict.
Original checker/result and eleven trace controls remain in B/native-g.

### Product repairs already merged; do not repeat

PR453 (05c223c75ee0323d79798820ab078b1e20054e20): actual shared executor job
owns Geph recovery publication; cancelled callers/followers cannot cancel the shared
result. Three old-code regressions and eight focused tests; CI/audit passed.
PR454 (d79e78a33364800a4c702e68236ba017392fd1a9): owned restart drain releases
on every non-restarted/exception path, including successor lsof EMFILE. Five new
cases plus prior eight passed; CI/audit passed. No historical universal cause claim.
Evidence: output/continuation-20261101/geph-recovery-lifetime/ and drain-followup/.
PR455 bumps .34 and admission pins; version/admission41tests+5subtests passed.
Its one targeted PR lifecycle rerun addressed observed artifact-upload ETIMEDOUT
(after native Quit passed), not a protected R rerun. Original failure retained.

### Published baseline and remaining boundaries

Preview .33 is published at https://github.com/aiwaki/slipstream/releases/tag/v0.1.9-preview.33
(release430591253, source9eccd1ddf691aef5f76d493103513f2fada2fd5c,
CI41302269258/1, audit41302269288/1, manifest
e2e0e5432ea12208922c775c7a6d7ea5ab87f44491d45de94524df8c41193ba0).
Its G/P/R and actual public .32 -> .33 Cancel/commit/rollback are accepted under
OLD/public-next. Do not rerun that completed pair or alter its observer/checkers.
B/old33-reference.json retains candidate availability and OLD identities.
Stable v0.1.4 remains unchanged; .32 is only title-archived, not deleted.

B/publication/publisher-verification-preparation.json and B/readiness-r/acceptance-recipe.md
are preparation only. The only found old publisher checker is the .32 fallback,
with incompatible IDs/schema/timestamps/size: never execute it as a .34 proof.
After actual publication use the existing public-next source_binding contract;
it is not a private G/P/R source-override exemption.

No local native/Cargo/scanner builds, app downloads/installs, browser/live probes,
service/PF/DNS/proxy/PAC/VPN/account changes. Small authenticated report/log ZIPs,
Git/GitHub, guarded pure tests and disposable hosted CI are allowed. Preserve the
user's external Geph and workstation. Discord/YouTube remain local bypass.

## Current continuation — 2026-10-31, RSA-only remediation in progress

Draft PR433: https://github.com/aiwaki/slipstream/pull/433, first head
`0ceffd6076126c949c0547a363e34d472fcdc4d1`. Real-ref classifier replay passed:
PR source bootstrap allowed; push bootstrap refused. PR audit41154777207/1 passed; its verified merge SHA is
`8ca3359a5c4079668e4d697afbfc40b8c97cfe64`. App361 packages, Geph408 registry
+3 source-owned packages: blocking0, accepted exceptions0. The transported
review archive passes canonical current-date admission; this is not main/binary
qualification. Evidence: rsa-release-remediation/ci/41154777207-1/.
No merge or producer/publication dispatch while the new fixture gate is pending.

Main remains `9a02e262063f32415c28cb72263204168fdcb5a7` (PR432 merged;
ordinary main CI41146511419 passed). Release admission failed after the two RSA
exceptions expired at 00:00 UTC. Preview .32 is not published or installed;
protected readiness is still unqualified. This is incomplete work, not a final
product result and not an impasse while the prepared RSA-only repair is available.

The active branch is `codex/geph-rsa-only-remediation`, based on that exact main.
The separate retained candidate, rather than old PR384 wholesale, supplies three
embedded packages/20 files and three source transforms. All thirteen r3 source
edits remain identical. The tested Free/Plus auth-cache hunk is explicitly retained.
The reconciled lock preserves rustls0.23.46, rustls-webpki0.103.16,
webpki-roots1.0.10 and ctutils0.4.4. No rsa/blind-rsa-signatures package remains.
SOURCE SHA256: `69d5de39654dea018075469d20ea7892cc35f5af0466d19a7811ef3316b60df7`;
lock: `560504e697c28f2114ec16414e5dc372e1903df986ba36792aab9a12c34631cb`.
This is a static reconciliation, not fresh Cargo resolution/build evidence.

Fresh independent source review found no new concrete defect in the three packages;
all unchanged source bytes and retained causal auth evidence were checked. Two
current official OSV ancestor queries returned no findings. Registry/native AWS-LC
audit and combined-build evidence are still required. The new source-owned policy
removes the two old RSA exceptions; it does not extend them. Historical review/log
projections are labeled and cannot be mistaken for fresh test execution.

Canonical archive materialization and the production source-owned review passed:
16 transforms, 3 packages/20 files, no native SQLite descriptor. Core scoped tests:
199 passed, including five causal regressions; independent review confirmed all
23 changed core file hashes and six evidence hashes. Documentation tests: 8 passed.
The source-bootstrap classifier's 22 tests passed before its final file catalog
was frozen. Workflow commands are being checked against the actual CLI parsers.
These are static/mock checks, not a fresh Cargo build or installed-app result.
Core receipt: `output/continuation-20261031/rsa-source-owned-tooling/verification.json`
SHA256 `909e873433dacd5b44dae5256739d1cf844695f8ef4b823077c385da9c6daee1`.

Producer/consumer tests:55 passed; all ten workflow CLI callsites were checked.
Independent integration review passed and confirmed106 exact CI bindings.
Root found a separate release-coverage gap: the producer executes19 existing
session/cache fixtures but no new RSA/auth composition fixtures. The existing isolated runner now adds11 retained composition cases against an
exact current-source test copy. The legacy signing oracle has a separate lock
and synthetic public keys; it is not linked or shipped.16 static/mock tests passed,
including an old-code failure; source/lock remain unchanged after preparation.
Independent review passed. Fresh native execution of all30 cases is still required.
The separate three account-level cache regressions remain reused historical evidence.

CI41154777253 passed product/Chromium/Windows checks, but its final gate refused
seven existing blank EOF lines in immutable review source/transcripts. Exact-path
.gitattributes now preserves those bytes; trailing whitespace and ordinary EOF
checks remain enforced, verified in a disposable Git fixture. No global waiver.

NEXT: commit the fixture gate and121-file exact classifier catalog, rerun remote
checks for that head, then normal merge and producer build. Source review/audit
passes do not replace the pending fresh native and protected readiness gates.
Do not activate native SQLite, SDK/platform or
Telegram work. No local native build/browser/install/account/network-setting work;
preserve the working external Geph and workstation. No protected readiness or
publisher dispatch until the dependency and candidate gates pass.

Evidence: `output/continuation-20261031/rsa-release-remediation/`,
`rsa-only-feasibility/` and `rsa-upstream-review/` in the same continuation directory.
The old RSA-only policy/lock and PR384 remote5b80ff436 are historical inputs, not
current release authority. Source-owned helper code is ported onto current main,
preserving newer snapshot and UTC admission fixes.

## Verified Checkpoint

### Active: preserve Safari failure evidence, 2026-10-30

PR432: https://github.com/aiwaki/slipstream/pull/432. Secondary checkout
`/Users/aiwaki/.codex/worktrees/readme-humanizer/slipstream-codebase-audit-20260905`,
branch `codex/safari-startup-observation`, based on C5
`2984beb5a102930d6cede825d9ae393d680513b5`.
The final scope is seven files: four shared helper/test files, readiness workflow
sidecar retention and two documentation files. The standalone Safari experiment
is archived privately and removed from the PR; no experimental workflow ships.

R41134436278/1 failed before its long soak: Chrome4/4 opened, but Safari's first
session creation failed and three further attempts failed its process-absence
check. Navigation elapsed_ms=0 does not establish startup duration. The initial
exception was suppressed and driver log deleted, so its underlying cause remains
unknown. Owned-Geph baseline/outage/recovery, tray crash, KeepAlive and external
sentinel checks passed; partial Safari startup cleanup was not proved. The
1800-second soak and final attestations were not run. Release .32 is NOT_ADMITTED.

The retained fix preserves bounded, allowlisted startup/cleanup observations in
an optional sidecar, without changing strict live-sites schema2. Failed creation
without a recorded session ID/PID still verifies Safari absence. An inspection
failure cannot stand for successful cleanup. The default pageLoadStrategy=none,
30-second command timeout, release gates and protected budget are unchanged.
Two causal regressions failed on C5; 48 focused mocked checks passed. Receipt
`output/continuation-20261030/safari-startup-observation/verification.json`, SHA
`598226566c5c56e6d3558938b56b224ba2929a75540fd206688deadb2419227c`.

Disposable experiments created sessions and navigated about:blank with both
normal and none. They did not reproduce the original startup failure. Review
identified a separate race in the experimental harness: matching UID/executable
does not prove that a Safari PID belongs to its session. After removing Safari
signalling, run41143761559/1 refused cleanup for both modes, including the final
absence check after its own driver exited. Safe evidence does not distinguish
process residue from inspection failure. Do not call this a routing failure or
restore guessed-PID signalling to make it pass. The experiment is retained under
`output/continuation-20261030/safari-session-experiment-archive/`, archive receipt
SHA `c38aa87fb0c2d9fc03c28c0adeed070d952ecf27e3a9cc85f5e3cd97627930d2`.
The existing shared/live lifecycle helpers' UID/executable ownership assumption
remains a separate known limitation; this patch does not resolve it.

Reusable ordinary-CI baseline: PR head179fb533 passed CI41140189410/1 and
audit41140189428/1, with native Stop/Quit7/7, Chrome4/4 and Safari4/4, composed
CSS/JS/image navigation, clean uninstall, external sentinel and global PF
preservation. CI receipt SHA
`e0936f0ca4f54fccf15190d0051eaef5fc8af7ead93b3a551c4453c6a94bef1b`.
C5 main CI41128371044/1 and audit41128370866/1 also passed; its native
G41131209759/2 and packaged P41134440722/1 passed. These historical proofs do not
admit a new exact-source release or prove the public feed/tray/admin-dialog path.

Next: independent review of the narrowed seven-file scope and fresh exact-head
required CI, then normal merge. Do not repeat unchanged local suites. Protected
budget is 3/3 for October30 UTC: no additional account-backed dispatch or rerun.
Two RSA allowances expire October31 00:00 UTC; never extend or carry them forward.
No .32 publication or workstation installation. Preserve the working external
Geph and all apps/services/PF/DNS/proxy/PAC/VPN/accounts; no local native/browser/
build/live activity. Small mocked/static checks and disposable CI only.

### Previous: candidate producer readiness, 2026-10-30

Checkout: `/Users/aiwaki/.codex/worktrees/readme-humanizer/slipstream-codebase-audit-20260905`;
branch `codex/producer-readiness-job-proof`, based on main C4
`b5ce4942719055a3dc5c87268dc6bdd367b3ae3a`, tree
`9e0b4caed4d2e9e9d89a4bb10be615ed9130a35d`. PR430 merged normally after its exact-head
CI41116262592/1, audit and actual Chromium runtime review passed. Preview .32 is
not published or installed; preserve the working external Geph and workstation.

Main CI41118944722/1 exposed a readiness-observer refusal before notification UI.
After 12 polls/120.021 seconds, `last_pending_stage=run_pending`: aggregate run
metadata still said queued/null (updated20:01:10Z), while the same saved API triplet
contained a successful assembler completed20:16:43Z and the exact candidate
artifact created20:16:38Z within its verified producer window. Notification was
already in progress. Its workflow depends on successful assembly; there is no
dependency cycle or wait for the entire CI. The aggregate state alone added a
pending condition after the producer evidence had passed. The underlying cause
of GitHub's inconsistent metadata is not established.

The narrow correction treats queued/null as an unfinished aggregate, like the
already permitted in_progress/null state. Readiness still requires the unique
successful assembler and exact artifact, with all repository/source/attempt/
timing/digest checks. Incomplete producer proof stays pending; malformed or failed
proof stays invalid. The 120-second refresh budget and final complete-CI release
requirement remain unchanged. Two causal regressions failed on C4; all 158
notification-module tests passed after the fix. Independent review passed without
repeating the tests; collector and native-hook functions are AST-unchanged.
Local evidence: `output/continuation-20261030/notification-producer-job-readiness/`;
`verification.json` SHA256
`4e07533ed5233ae617a851e60b6fefcb7051e4189c163257a739d47e2cf5e934`,
`independent-review.json` SHA256
`a304d488b2ef73ac6e869158d6392b961e3d1b63199845b6c4be66021482341c`.

Evidence is in the primary qualification checkout's
`output/continuation-20261030/preview32-main/ci-corrected/`, including the saved
notification API/report files and `notification-producer-independent/verification.json`
(SHA256 `6f654c8da392911499b01477b96109a2fd3fd1c380655abb79c69edf1ef49542`).
Candidate13008956785 / manifest
`d45f22621f672921ae889d898faa9682883f54e1ee83bb3ee007d901f338a7f1` is retained,
not admitted. CI completed with failure at 20:25:18Z; signing, assembly, attestation,
source cold install and browser evidence passed. Native/lifecycle steps succeeded,
but their report bodies were not fully verified (native download returned HTTP 503).
Native/protected qualification has not been dispatched. Next: publish this reviewed
correction through a PR, then use fresh successful main
evidence. Protected budget remains 2/3 today UTC; RSA allowances expire at its end.

### Previous: PR430 release CI and observation repairs

Checkout: `/Users/aiwaki/.codex/worktrees/readme-humanizer/slipstream-codebase-audit-20260905`;
branch `codex/ci-artifact-attempt-identity`, based on main
`0860167bcb44a196fc18a2c98ccb0f67d98a95cf` (C3). PR429 merged normally;
C3 has the same tree `de281f7b388708157b1f07fafc3927289b370335` as reviewed/tested
PR head67f4c8e3. Preview .32 is not published or installed. Keep the working external
Geph and workstation unchanged. No native/protected retry is authorized by this
checkpoint.

PR430 head `e26b98470d78e7c0ab3e75b46c9a11e4b715368a` supplied new causal
evidence in CI41110796459/1. The source-only cold install timed out its hash-locked
pip command after five seconds: it inherited the short system-command deadline.
The outer lifecycle runner allowed 180 seconds. Frozen packaged installation
does not invoke this pip path. Source venv/pip now share one 90-second monotonic
budget starting at installation preparation; each command gets only its remainder.
An exhausted budget prevents another bootstrap command and follows existing
failure cleanup before launchd publication. Ordinary control commands keep five
seconds, including lock-FD inheritance and environment filtering. Two causal RED
cases and 13 focused checks passed; independent review passed without rerunning
them. Evidence: `output/continuation-20261030/source-bootstrap-timeout/`.

The retained browser record also shows Finder changing to UserNotificationCenter
at 1060–1087 ms, before worker invocation at 35585 ms. This run's focus change
therefore preceded the worker by about 34.5 seconds. Its 30-second LaunchServices
listener had already expired before invocation, so zero recorded events do not
prove worker invisibility. Fixture and broker preparation now finish before the
fresh baseline and recorder start. The unchanged 25-second worker/observation/
cleanup limit fits inside the unchanged 30-second recorder lifetime. Early recorder
exit, including status zero, is rejected before launch and after the final snapshot.
Setup, sampling and fixture-close failures still clean up owned resources. Eight
causal RED cases, 72 observer tests and one directly affected build-contract test
passed; independent review confirmed unchanged visibility acceptance conditions.
See `output/continuation-20261030/browser-observer-setup-order/`.
The earlier run without retained evidence remains unattributed. CI evidence is in
`ci-artifact-attempt-identity/pr430/diagnostic-head/` below.
Audit41110796855/1 passed actual current-UTC admission at18:57:32Z. Chromium
review41110797091/1 ran 15 helper tests and sandboxed version/DOM checks on macOS15
ARM64, with owned processes/files cleaned up. This runtime/integrity evidence is
not vulnerability clearance; Chromium OSV coverage remains unsupported.
CI41110796459/1 is terminal FAILED on the two causes above. Its seven native
Stop-and-Quit cases and packaged lifecycle checks passed with clean owned teardown
and preserved external sentinel/global PF. Lifecycle Chrome used its real binary
in headless mode; Safari used a real SafariDriver session. This is not ordinary
GUI Chrome qualification or real account-backed Geph qualification. Terminal
evidence is `diagnostic-head/terminal-verification.json` (SHA256
`3d3fd368c5cc1a1f33cc422f999a0d606eac047e26b11b78dfc6a30d1a0db7c7`).
Those two fixes subsequently passed exact-head CI41116262592/1 and were merged
normally in PR430; the current main observation above is the next unresolved gate.

PR430's first head `6660be1e8ee323f3a4100892be77f10ae6a0fc48` reached a separate
infrastructure blocker: CI41101705353/1 was cancelled on October 30 at 18:03:41Z.
Product, Chromium-contract and app-build jobs were cancelled without a runner;
their annotations identify the scheduled macOS 14 image brownout. Downstream app
qualifications did not run. Evidence: `ci-artifact-attempt-identity/pr430/` under
the output directory below. Audit41101704933 reports passed current-date admission,
but cannot turn the cancelled CI into a release gate.

This PR also moves all 13 retired runner labels in six active workflows to
`macos-15`, matching the two existing native-update workflows. GitHub documents
both old and new standard labels as ARM64; its [retirement announcement](https://github.com/actions/runner-images/issues/13518)
confirms today's 14:00–00:00 UTC brownout and November 2 removal. Application
targets/configured minimum and historical r3 inputs remain unchanged. The new
hosted runs must establish compatibility with this runner image; no existing
macOS 13 runtime qualification is implied.

After migration, PR430 head `6b898fbc557b55b4bc175771e8240dac12740bd9` ran on
macOS 15.8.2 ARM64. CI41105773284/1 passed build/product/Windows/Chromium checks
and all seven native Stop-and-Quit cases, with no cleanup errors. Lifecycle probes
using Chrome/Safari survived tray crash/restart; the external connection and global
PF state were preserved. Both app consumers downloaded the exact producer ID and
verified its digest. Audit41105773270/1 passed current-date admission. The separate
Chromium review41105773355/1 could not acquire a hosted ARM64 runner and produced
no runtime evidence; existing admission remains separate.

That CI still failed on browser visibility: before/after frontmost application
ASNs differed. The original guard discarded its in-memory snapshots/events on
failure, so the responsible process and timing could not be established. The
diagnostic correction retains a bounded, sanitized stderr record: frontmost
ASN/PID/bundle identity, observation and worker-invocation times, first differences
before/after/overlapping invocation, and owned LaunchServices event summaries.
Raw listings, paths, arguments, URLs and window titles are excluded. The same
visibility refusal and cleanup remain in force. Two causal failures and 58 focused
tests verify retained evidence and its bounds; see
`output/continuation-20261030/browser-visibility-diagnostic/`.
The next observation established the preparation-stage timing above. The
diagnostic repair alone does not close the visibility gate.

Main CI41090901062/1 failed because three macOS arm64 qualification jobs could not
acquire hosted runners. All three were cancelled without a runner or executed step;
GitHub explicitly reported capacity constraints. Build, signing, assembly and
attestation passed. Candidate artifact12994861913 has manifest
`860621073afe7c0bd73515da2bf14e702bec3fb43f16a79f649f837a91ac61df`, but its recorded
producer attempt1 did not pass the complete main gate. Do not dispatch native gates
with this candidate or treat a successful partial attempt2 as proof for attempt1.
Primary evidence is under
`/Users/aiwaki/.codex/worktrees/geph-route-continuity/slipstream-codebase-audit-20260905/output/continuation-20261030/preview32-main/observer-corrected/`:
`candidate/verification.json`, `candidate/retry-analysis/` and `queue-diagnosis/`.
No retry of this main run has been dispatched.

The retry investigation found name-only artifact selectors in CI signing/assembly
and two consumers. GitHub retains same-name artifacts across attempts; selecting
merely the newest or deleting old evidence is not acceptable. The CI repair passes
trusted upload IDs through job outputs, checks exact ID/name/digest/unexpired
source/run identity, and downloads those IDs in all ten internal consumers. Six
pre-download guards reject absent or malformed IDs because an empty action input
would download all artifacts. Existing signing-input/proof attempt checks remain;
a valid rebuild must start at the build/signing-input producer, not assembly alone.
The exact pinned download action extracts one selected ID directly into the stated
path and supports fail-closed digest verification.

Both real embedded Python verifiers first failed a two-attempt fixture. The repaired
verifiers and source-extracted shell guards passed 15 focused tests, including five
existing workflow checks. Three old text assertions were updated for exact-ID
selection and the attestation job's sole permitted data-format guard; downloaded
or repository code still cannot execute in that privileged job. Evidence:
`output/continuation-20261030/ci-artifact-attempt-identity/`.
The consumer fixes select one artifact inside the authenticated successful producer
job window, preserving source/run/attempt, malformed identity and ambiguity checks.
Their separate causal evidence is in
`output/continuation-20261030/artifact-attempt-consumers/`.
The consumer checks passed 179 tests and 54 subtests, including valid expired
records from prior attempts and rejection of expired current records. Both
independent source reviews passed; the combined review is in
`output/continuation-20261030/ci-artifact-attempt-identity-review/`.
Eight documentation tests and the project-state continuity check also passed.
Next: exact-head PR CI with retained visibility evidence, normal merge only after
required checks pass, then fresh main qualification. Product
routing, DNS, Geph, authorization and release policy are unchanged by these repairs.

Retained prior evidence: C2 main46ad4de4 passed CI41074846948/1,
current audit41074846640/1 and native-root41077842851/1. Readiness41079675772/1 failed
on the observer's stale cache shape before the browser matrix/soak; packaged
41079675441/1 passed pre-ACK rollback/cleanup but its committed case refused a busy
lock snapshot after real ACK and withheld cleanup. PR429 repaired both observers;
those failed C2 runs remain failed and its native pass does not qualify new source.
PR429 CI41084918267 attempt1's authorization failure remains unexplained. Its one
approved targeted retry passed all required checks and all seven Stop-Quit cases,
using the same immutable app artifact; this does not explain the first failure.

Two of today's three protected dispatch slots are spent: cancelled41063658872/1
on C41b946ed and failed41079675772/1 on C2. One remains. After normal review/PR/merge,
obtain a fresh exact-source main candidate and current audit, then run native-root
first. Only after native PASS may readiness and packaged gates run in parallel.
Do not reuse retired-source gates, bypass exact attempts or extend RSA allowances
(expiry October30 UTC inclusive). The earlier interrupted-soak cleanup observation
remains a separate deferred harness issue, not evidence against ordinary Quit.

Bundled Xbox-DNS retirement and historical-policy repairs are already merged.
User-managed DNS, local learning and protected Discord/YouTube routing remain
unchanged; no new live provider qualification is claimed. Broader PR376 recovery,
PR384 RSA/tooling and PR386 Telegram/H2 work remain separate. Historical workstation
403/reconnects, public auto-update and sustained workstation media remain unqualified.

### Published .31 — retained historical evidence

The .31 publisher/manual preflight missed Chromium155 admission expiring October29.
Public release notes were corrected; all twelve assets/tag remain unchanged. Historical
identity/gate evidence below does not retroactively establish current-policy admission.

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
Initial PR426 source `a1b1cf32df7c958a0323c18f69171585b52a092b` passed
CI41046195098 (including packaged browser/lifecycle); its dependency audit failed.
This initial evidence is superseded by the current checkpoint above. Eight documentation checks
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

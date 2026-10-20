# Current Project State

## Verified Checkpoint

Public [preview .30](https://github.com/aiwaki/slipstream/releases/tag/v0.1.9-preview.30)
is now installed at `/Applications/Slipstream.app` on the user's Mac by manual
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
anchored before sealing. It does not extend the lease, publish PID early, bypass
signature/hash checks or alter Rust uncertain-authorization/abort handling.
Regression evidence: old source6 expected failures; repaired module115 passing,
adjacent lock/mailbox/native-root tests59 passing; strengthened terminal cases2
passing. Results were captured in tool output, not standalone log files.
Independent review found no blockers. Exact-source required PR CI is pending.

The old `.23 --quit` returned without ending its process; only its verified PID
was terminated after owned service absence was established. `.29` was later
terminated only after its failed transaction was proven aborted/quiescent.
Neither action qualifies normal Quit. Native UI automation timed out; the user
performed Restart Proxy and the ordinary update/admin action. Do not repeat the
known-stalled unattended hosted authorization path. Public update/forced rollback
and normal Quit remain open; manual `.30` installation does not close them.

Next: publish the focused startup-lease PR, retain its exact-source required CI
receipt, and carry both unreleased repairs into a normally built originating
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
| M3 - Release-Grade macOS | Preview .30 public and manually installed; stable and public updater gates open. |
| M4 - Cross-Platform Core | No new platform qualification in this change. |

## Next Verified Action

- Submit the startup-lease repair and obtain its exact-source required CI.
  Reuse completed focused tests and the PR409 baseline where unchanged.
- The corrected originating candidate must contain both unreleased repairs
  before another public transition can qualify them. Preserve current manual
  `.30` and all private backups; no repeated local install is needed now.
- Do not reopen completed `.30` publication or repeat the stalled unattended
  hosted authorization probe. Attended authorization itself succeeded locally.

## External Gates

- Ordinary public update/forced rollback and normal Quit remain unqualified.
  The local attempt reached root preparation but cancelled on the short startup
  timer; the subsequent manual install is separate evidence. Hosted
  authorization still lacks a successful probe. See [RELEASES.md](RELEASES.md).
- Stable publication still requires Developer ID signing, hardened runtime,
  notarization, stapling and the existing stable-channel gates.
- Native/source-owned work in PR384 and Telegram work in PR386 remain separate.
  Preserve the root checkout, user changes and all retained output.
- External DNS/proxy/PAC/VPN and PF owners are untouched. Discord, YouTube and
  Googlevideo remain on local bypass; this change affects no routing rule.

## Resume Protocol

Verify physical checkout, HEAD, PR state and exact matching CI once, then take
the next action. This checkpoint is a locator, not proof. Read [DECISIONS.md](DECISIONS.md)
and [RELEASES.md](RELEASES.md).

## Update Rule

Update this file when the verified next action changes. Keep detailed
investigations in their topic docs and retained evidence.

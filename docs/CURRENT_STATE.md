# Current Project State

## Verified Checkpoint

[Preview .24](https://github.com/aiwaki/slipstream/releases/tag/v0.1.9-preview.24)
is public from `e5791a4d7f42e000bb37732f8aa4b9698e62dd9f`, release ID 413914811.
All 12 public assets passed independent size/hash, signature, bundle, appcast and
remote-identity verification. Its exact-source CI38739537809, audit38739537827,
protected readiness38745936996 and publisher38752022135 passed. Readiness covered
8 Safari/Chrome cases and a measured 1800-second soak with clean teardown.
PR390 merged at `323a4df52215f169a64df96760dc9d8838d68a34`; CI/audit passed.
These unchanged release checks are reused. No workstation installation occurred.

Release evidence is retained in the `release-delivery` worktree under
`output/publish-preview24-e5791a4d7/public-verification/`.
Receipt SHA256: `1fc311510d89b6cbb975dcb5565fdb950b147f90208ab508523066f6d84f43fe`.

## Current Change

The CI-only producer-readiness repair is on `codex/notification-producer-readiness`,
based on main `58601bfd19d6341531d84b1395e0e4f8e2fbe2b5`. Main
CI39278945059/attempt1 failed only notification producer preflight
(`candidate_producer_invalid`, before the native hook); the lifecycle aggregate
failed accordingly. Product, build, browser, heavy lifecycle and attestation
passed. The original input triplet/rejected predicate was not retained. API
readiness is a reproduced failure mode, not a proven explanation of that call.

This change keeps strict provenance checks, refreshes incomplete API readiness
for at most 120 seconds/13 polls, and retains bounded inputs plus an allowlisted
failure stage. Invalid identity/attempt/digest, duplicates and failed producers
remain terminal. The native hook is never retried.

PR401 head `d83171eb7862b725d477308b7b158bab1a82a1ab` passed whole CI39287488586
and audit39287488498, including packaged browser and lifecycle. Its 129 focused
Python checks and independent review are retained as the baseline. Two subsequent
review findings are now repaired: a failed or late API fetch preserves the
previous complete triplet, and manifest-attempt selection occurs inside the
reporting path. Native qualification still requires an explicit attempt; evidence
collection alone may select it from the strictly validated manifest. The focused
136-test suite passed in 0.49s, actionlint/diff checks passed, and independent plus
parent source review found no blockers. This does not claim an atomic three-file
transaction on filesystem write failure. Evidence is retained in
`notification-producer-refresh/pr401-p2-tests.log`. Product source and VERSION stay
`0.1.9-preview.27`. No local Rust build or native operation ran.

Evidence: `output/updater-daemon-identity/notification-producer-refresh`.
The failed-main candidate is authentic but unqualified; do not dispatch it or
relabel its failed builder attempt as successful. Its
`main399-verification/failure-receipt.json` SHA256 is
`c308e6c7c66c19125c180916f587cb88522c8a878992bc40668f394febc425c9`.
PR400 remains separately green at `0c3fc4a889845b0ddef71c87e30ce931d89fc538`
(CI39277553981/audit39277553914); app commit/rollback/public gates remain open.
Public preview .24 and workstation configuration are unchanged.

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
| M2 - Contracts And Code | Coordinated update merged; native qualification pending. |
| M3 - Release-Grade macOS | Preview .24 public; stable and public updater gates open. |
| M4 - Cross-Platform Core | No new platform qualification in this change. |

## Next Verified Action

- Complete required CI and merge the producer-readiness repair. Authenticate the
  corrected exact-main `.27` candidate, reusing the authenticated `.26` from
  CI39266691016. Verify signatures/provenance, archive modes and binary
  inequality, then dispatch native root `.26 -> .27` before main advances to `.28`.
  A partial rerun of the failed `.27` producer attempt cannot satisfy the native
  consumer's exact successful-builder-attempt requirement.
- Preserve green PR400 while this repair is integrated. After root qualification,
  merge and authenticate its `.28` candidate; run the real packaged app/watchdog
  commit and rollback gates. Source and hermetic checks do not qualify them.
- Reuse preview .24 release/readiness evidence. Public updater qualification is
  separate; signed public assets and workstation state remain unchanged.

## External Gates

- Repair pending-update daemon identity and privileged-installer lifetime before
  qualifying a future public updater pair. Preserve signed-install, rollback,
  notification and invisibility requirements; do not preinstall a new daemon to
  mask the defect or modify old published assets. See [RELEASES.md](RELEASES.md).
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

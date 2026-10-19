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
`readme-humanizer` checkout is now on `codex/packaged-geph-update-permissions`.
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
failed before installation as described above and remains open. The new workflow's 45 integrated hermetic tests,
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

- Merge the packaging-mode fix after focused tests, independent review and
  required exact-head CI. Preserve all old candidates and failure evidence.
- Retain its successful main preview.25 build as the new bridge. A subsequent
  normal preview.26 source bump must produce distinct tray and daemon bytes.
  Verify both candidate manifests and attestations, then repeat the two native
  cases with their new pins. Do not rerun the unchanged rejected pair.
- Continue the separate app/watchdog gate only after the native root gate. The
  draft transaction adapter and unfinished observer remain untracked and are
  excluded from this packaging fix. They have no native qualification yet.
- Reuse the unchanged preview.24 release/readiness baseline. Public app-update
  qualification remains separate; no public assets or workstation state change.

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

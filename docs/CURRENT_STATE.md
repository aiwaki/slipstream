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

[PR393](https://github.com/aiwaki/slipstream/pull/393), branch
`codex/coordinated-daemon-update` in the attached `readme-humanizer` worktree,
starts from that merge. Source commit `66d3f2e4151341802c415bdd54c2dfe2ef743477`
is pushed. After a test-fixture API fix, head
`2462fd7e68fbae18de67f36ccbf7ac07a01e6745` passed 184 app tests, 29 browser-probe
tests, 3 updater installer tests, Python suites, Windows checks and dependency
audit39232771857. CI39232771871 stopped at two narrow Clippy findings; those
are corrected at head `996e4aa12dc704bdd3b88f1c41f3683ba95e25a5`.
At that head, dependency audit39233841112, packaged build, browser qualification
and Windows checks passed. CI39233841163 failed one existing Geph log-rotation
test (183 app tests passed): an archive exceeded its asserted 512-byte bound.
The exact failure is retained in `pr393-product-996e.log`. A bounded native
reproduction proved BSD `tail -c` can read concurrent appends past its requested
length. The narrow correction snapshots the byte range and copies it with a
fixed count; failed archive publication now preserves the live log. Reproducible shell
checks covered appends after the snapshot, concurrent truncation, copy/chmod/mv
failures, and eight concurrent-writer bursts. Each successful burst archive
contained exactly 512 bytes. Independent scoped review found no blocker. The
existing Rust live-process test remains unchanged. Final source CI is next. The superseded failed CI runs were
cancelled after their decisive logs were retained. Rust and Python join the watchdog and
privileged daemon installer into one recoverable transaction. The installed
workstation app and the published release are unchanged.

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
Independent final source review found no remaining concrete blockers.
Compilation and tests passed at the preceding head; the final product gate and
disposable native qualification remain pending. A root-protocol driver draft
under `output/updater-daemon-identity/native-driver-draft/` is being reviewed;
it has not executed native operations and does not qualify app/public updates.
No local Rust build, privileged runtime test, or workstation installation ran.

| Milestone | Current boundary |
|---|---|
| M0 - Safe Base | Candidate cleanup passed; public update/rollback unqualified. |
| M1 - Autonomous Routing V1 | Hosted browser/soak passed; no new workstation qualification. |
| M2 - Contracts And Code | Discovery and daemon ACK repairs merged; coordinated update in progress. |
| M3 - Release-Grade macOS | Preview .24 public; stable and public updater gates open. |
| M4 - Cross-Platform Core | No new platform qualification in this change. |

## Next Verified Action

- Finish PR393 exact-head hosted CI, fix any concrete failures, and retain
  matching evidence. Reuse main2640's
  unchanged baseline; do not rebuild or republish `.24` or rerun its readiness.
- Qualify the coordinated path on disposable macOS with a supporting bridge
  build and a successor whose normal version bump changes the frozen daemon.
  A copied app with only edited metadata or an unchanged daemon is insufficient.
  No fixture may preinstall the successor daemon to conceal an updater defect.

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

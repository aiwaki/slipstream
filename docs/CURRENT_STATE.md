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
starts from main2640. Pushed head
`958949ccfd4e6ae3d3691d9cf7a67501c2317408` passed CI39236170033 and
audit39236170106, including 184 app tests, Rust lint, Python/Windows checks,
packaged build, browser qualification and packaged lifecycle. The retained
`output/updater-daemon-identity/pr393-green-9589-receipt.json` binds those runs.
Earlier compile/lint issues are fixed. A failing live Geph log test exposed BSD
`tail -c` reading concurrent appends beyond its requested length; fixed-count
copy now bounds the archive and failed publication preserves the live log.
Scoped append/truncate/failure tests and the unchanged hosted Rust test passed.

The new terminal-receipt review finding is fixed in this revision: after daemon PID rollover,
a successfully exited terminal root worker needs an explicit wake to refresh
its receipt. The root fix watches only the exact transaction mailbox, preserves
the durable decision, and exits before expensive tree hashes while the daemon
is unready. Its 44 focused Python tests passed. The app consumer persists its
330-second, 33-attempt budget under a separate nonblocking mailbox lock; an
automatic watchdog restart cannot reset it. Only a verified new PID/birth starts
another episode. Seven Rust regressions cover stale proof, persisted exhaustion,
generation changes, fresh read-only behavior, unsafe files and concurrent clients.
Independent scoped review, formatting and whitespace checks passed. Fresh
exact-head CI is pending; Rust tests were not run locally. The installed
workstation app and published preview remain unchanged.

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
The preceding head passed full CI. Fresh CI for the terminal-receipt fix
and disposable native qualification remain open. A root-protocol driver draft
under `output/updater-daemon-identity/native-driver-draft/` is being reviewed;
its 37 hermetic checks plus 8 early-failure artifact checks and actionlint passed.
It has not executed native operations and does not qualify app/public updates.
No local Rust build, privileged runtime test, or workstation installation ran.

| Milestone | Current boundary |
|---|---|
| M0 - Safe Base | Candidate cleanup passed; public update/rollback unqualified. |
| M1 - Autonomous Routing V1 | Hosted browser/soak passed; no new workstation qualification. |
| M2 - Contracts And Code | Discovery and daemon ACK repairs merged; coordinated update in progress. |
| M3 - Release-Grade macOS | Preview .24 public; stable and public updater gates open. |
| M4 - Cross-Platform Core | No new platform qualification in this change. |

## Next Verified Action

- Run PR393 exact-head hosted CI for the reviewed terminal refresh fix; resolve
  the addressed P1 after passing evidence and merge through normal protection. Reuse main2640's
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

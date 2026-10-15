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

[PR392](https://github.com/aiwaki/slipstream/pull/392), branch
`codex/updater-daemon-identity`, uses the attached `readme-humanizer` worktree.
Initial head `0da43bbdfda3aa1314c75f6258e7e822c8f3524b` passed CI38774174406
and audit38774174523, including 163 app tests (37 focused) and packaged checks.
Review then found an early daemon-install race in restored-app startup; those
checks do not qualify the correction below.

Pending successors require exact bundled-daemon attestation before any installer,
and an advancing heartbeat from the same owned PID before ACK. Both successor
and restored rollback apps block privileged mutation until the watchdog releases
its lock and completes cleanup. Rollback requires the retained nonce-bound
OldRelaunched receipt and exact old app identity, emits no successor ACK, and
resumes normal daemon installation once. Legacy transaction markers remain for
compatibility; immutable published clients do not gain the new guard.

Independent review of the follow-up source passed; fresh exact-head CI is next.
Review receipt: `output/updater-daemon-identity/independent-review-rollback-followup.json`,
SHA256 `b83df0f6989e356c5339b8b6d1e3c5b758d488afebe23c8b7b8484152bae6d82`.
Prior-head CI receipt: `output/updater-daemon-identity/ci-0da43/final-ci-receipt.json`,
SHA256 `55ee5acd6f1d2d75097a115f07b7ff1d55ab40dba572b034401cc955d868c662`.
No local Rust build or workstation mutation. This safe refusal/rollback guard
is not coordinated app-and-daemon replacement or public updater qualification.

| Milestone | Current boundary |
|---|---|
| M0 - Safe Base | Candidate cleanup passed; public update/rollback unqualified. |
| M1 - Autonomous Routing V1 | Hosted browser/soak passed; no new workstation qualification. |
| M2 - Contracts And Code | Discovery fix merged; daemon ACK repair in progress. |
| M3 - Release-Grade macOS | Preview .24 public; stable and public updater gates open. |
| M4 - Cross-Platform Core | No new platform qualification in this change. |

## Next Verified Action

- Finish focused daemon-identity and rollback regressions, independent review,
  and exact-head CI in the current PR branch. Reuse main CI38770908107.
  Do not rebuild or republish `.24` or rerun its protected readiness.

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

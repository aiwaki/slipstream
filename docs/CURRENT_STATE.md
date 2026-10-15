# Current Project State

## Verified Release

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

[PR391](https://github.com/aiwaki/slipstream/pull/391),
`codex/preview-discovery-pagination`, repairs oversized preview-discovery pages.
Worktree: `/Users/aiwaki/.codex/worktrees/readme-humanizer/slipstream-codebase-audit-20260905`.
Six new regressions, independent review, Rustfmt and fixture-integrity checks
passed. Product checks and dependency audit passed at `be5311582bdd618f216ddd77220d7aea5db7e4fb`
(CI38766921595 / audit38766921225); its remaining packaged lifecycle gate was
still running when this documentation-only follow-up was prepared. Required
checks must pass on the final PR head before normal merge. No local Rust build.

The real public `.23 -> .24` attempt (run38763822390) stopped before activation
because no offer appeared; cleanup passed. Public upgrade/rollback remains
unqualified. The discovery repair is not in the published `.23` or `.24` binaries:
use the published DMG for this transition. Cause, limits and the separate daemon
ACK defect are recorded in [TROUBLESHOOTING.md](TROUBLESHOOTING.md#a-new-version-notification-does-not-appear).
Public-run receipt: release-delivery `output/public-update-pair-prep/public-pair-38763822390/receipt.json`,
SHA256 `9ea4571838afa6931dbe2810b8f8ac594109dcf0a2c21fdaf13ca35c15b2084e`.
Focused source/live-API evidence: this worktree's `output/preview-discovery-pagination/`.

## Next Action and Open Gates

- Finish final-head PR391 CI/audit and normal merge; then follow its main checks.
  Do not rebuild or republish `.24` or rerun its protected readiness.
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

## Resume

Verify physical checkout, HEAD, PR state and exact matching CI once, then take
the next action. This checkpoint is a locator, not proof. Read [DECISIONS.md](DECISIONS.md)
and [RELEASES.md](RELEASES.md); update this file when the verified next action
changes. Keep detailed investigations in their topic docs and retained evidence.

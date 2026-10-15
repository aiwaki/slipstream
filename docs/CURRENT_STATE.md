# Current Project State

## Verified Checkpoint

`v0.1.9-preview.24` is published from exact main
`e5791a4d7f42e000bb37732f8aa4b9698e62dd9f` (merged PR389).
PR390 merged at `323a4df52215f169a64df96760dc9d8838d68a34`; its CI and audit passed.
Current change: `codex/preview-discovery-pagination`, based on that main commit.
Worktree:
`/Users/aiwaki/.codex/worktrees/readme-humanizer/slipstream-codebase-audit-20260905`.
Publication and public updater evidence remain in the separate `release-delivery`
worktree; no workstation installation has occurred.

- Exact main [CI 38739537809](https://github.com/aiwaki/slipstream/actions/runs/38739537809)
  and [dependency audit 38739537827](https://github.com/aiwaki/slipstream/actions/runs/38739537827)
  passed, both attempt 1; the candidate was reused without rebuilding.
- Protected [readiness 38745936996](https://github.com/aiwaki/slipstream/actions/runs/38745936996)
  passed on the same source/candidate, attempt 1: all 8 Safari/Chrome checks across
  four live sites passed, followed by 1800.095 seconds of measured invisibility
  soak with 3600 samples, stable daemon PID, advancing heartbeat and clean teardown.
  Candidate manifest SHA256:
  `437084c9a5b26acc358620cb336ea1b81f24637d5f950889c9d7a53a6ccc1860`.
- [Publisher 38752022135](https://github.com/aiwaki/slipstream/actions/runs/38752022135)
  passed. [Public preview .24](https://github.com/aiwaki/slipstream/releases/tag/v0.1.9-preview.24),
  release ID 413914811, was published 2026-10-15T14:33:23Z with 12 assets and the tag
  pointing to the exact source above. Preview .23 now has an archival title;
  its tag and assets remain retained.
- Independent verification of all 12 downloaded public assets passed their
  GitHub size/SHA256 bindings. The canonical release verifier passed updater
  minisign, archive/internal identity, appcast and manifests; the published-release
  verifier passed tag/source/release ID and the exact remote asset set. Its first
  failure was only a missing local release-notes file; materializing the real
  release API body allowed that verifier alone to pass. Both results are retained.
  The final public release notes explicitly mark public upgrade and rollback
  unverified; the 12 release assets are unchanged.

Release-delivery evidence: `output/main-e5791a4d7/`,
`output/readiness-e5791a4d7-38745936996/` and
`output/publish-preview24-e5791a4d7/public-verification/`.
The latter's `public-verification-receipt.json` binds 25 retained files;
receipt SHA256:
`1fc311510d89b6cbb975dcb5565fdb950b147f90208ab508523066f6d84f43fe`.
No new workstation installation has occurred. Historical investigations and
superseded actions remain in Git history and retained output, not this checkpoint.

| Milestone | Current status and remaining boundary |
|---|---|
| M0 - Safe Base | Exact candidate lifecycle and protected cleanup gates passed; public update/rollback remains unverified. |
| M1 - Autonomous Routing V1 | Current preview passed the hosted Safari/Chrome matrix and measured soak; this is not a new workstation qualification. |
| M2 - Contracts And Code | Preview discovery pagination repair in source; no routing changes. Daemon identity acknowledgement remains a separate defect. |
| M3 - Release-Grade macOS | Preview .24 is public and its files independently verified; public upgrade/rollback and stable signing/notarization remain open. |
| M4 - Cross-Platform Core | No new cross-platform qualification in this release checkpoint; prior evidence remains in Git history. |

## Resume Protocol

Verify the physical checkout, branch, HEAD, open/merged PRs and matching required
CI before continuing. Read [DECISIONS.md](DECISIONS.md) and
[RELEASES.md](RELEASES.md); source, exact run evidence and public asset identities
are authoritative. Reuse unchanged green checks rather than repeating them.

## Public Updater Attempt

[Run 38763822390](https://github.com/aiwaki/slipstream/actions/runs/38763822390)
on harness commit `aef23e3dd83f7d08e1d543946cafe412866fe723` failed before an update
was activated. The real signed public `.23` app and daemon launched, its own tray
menu opened, but 24 observations over 78.171 seconds never offered `.24`.
Cleanup errors and residue were both empty. No transaction, success ACK or forced
rollback occurred. Release-delivery receipt:
`output/public-update-pair-prep/public-pair-38763822390/receipt.json`, 80 files,
SHA256 `9ea4571838afa6931dbe2810b8f8ac594109dcf0a2c21fdaf13ca35c15b2084e`.

A separately fetched public API response contained 29 records / 417722 bytes,
which exceeds the released discovery code's 256 KiB page limit. Runtime stderr
was not captured; the API data and identical `.23`/`.24` source establish this
size blocker. The source repair uses 10 records per page, up to 30 pages, keeping
256 KiB per page, 768 KiB total and a shared 10-second deadline. A separate live
API probe fetched all three pages in 6.242 seconds; it is not a Rust-client or
installed-app qualification. Its evidence is `output/preview-discovery-pagination/`.

Source review also found that successor ACK accepts an advancing old daemon
without binding it to the new payload while privileged installation is pending.
The pagination repair does not address that issue. Details remain in delivery
`output/public-update-pair-prep/daemon-ack-gap.md` and [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
Do not preinstall the new daemon, modify old published binaries, or treat unit
mechanics as proof of the public pair.

## Next Verified Action

Six focused pagination regressions are implemented; independent source review
accepted the change. Rustfmt and exact retained-fixture verification passed.
No local Rust build was run. Next: required exact-head CI/audit and normal PR merge. Reuse the unchanged `.24`
publication/readiness evidence; do not rebuild or republish that version.
The released `.23` cannot acquire this repair through its broken discovery.
Use the published DMG for the current transition. Before qualifying a future
public updater pair, repair the independent daemon ACK/installer lifetime gap.

## External Gates

- Public upgrade and forced rollback remain unverified; use the published DMG
  for manual installation until that qualification passes.
- Stable publication remains closed pending Developer ID signing, hardened
  runtime, notarization, stapling and the existing stable-channel requirements.
- Native/source-owned migration and unrelated work in PR384/PR386 remain
  deferred. Preserve the root checkout, user changes and retained output.
- External DNS, proxy, PAC, VPN and PF owners remain untouched. Discord,
  YouTube and Googlevideo stay on local bypass; this release changes no such rule.

## Update Rule

Keep this checkpoint compact and current. Update it in the same PR when verified
state or the next action changes. Keep historical proof in Git and its retained
evidence paths; do not append obsolete action plans here. Reconcile contradictory
live evidence before changing a gate's status.

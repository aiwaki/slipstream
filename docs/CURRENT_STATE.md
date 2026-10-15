# Current Project State

## Verified Checkpoint

`v0.1.9-preview.24` is published from exact main
`e5791a4d7f42e000bb37732f8aa4b9698e62dd9f` (merged PR389).
Documentation update: PR390, branch `codex/preview24-publication-checkpoint`.
Worktree:
`/Users/aiwaki/.codex/worktrees/release-delivery/slipstream-codebase-audit-20260905`.

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

Evidence: `output/main-e5791a4d7/`,
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
| M2 - Contracts And Code | No contract or routing code changes in this documentation update; unrelated implementation work remains separate. |
| M3 - Release-Grade macOS | Preview .24 is public and its files independently verified; public upgrade/rollback and stable signing/notarization remain open. |
| M4 - Cross-Platform Core | No new cross-platform qualification in this release checkpoint; prior evidence remains in Git history. |

## Resume Protocol

Verify the physical checkout, branch, HEAD, open/merged PRs and matching required
CI before continuing. Read [DECISIONS.md](DECISIONS.md) and
[RELEASES.md](RELEASES.md); source, exact run evidence and public asset identities
are authoritative. Reuse unchanged green checks rather than repeating them.

## Next Verified Action

Branch `codex/public-update-pair-qualification` measures hosted macOS console and
Accessibility capability with a read-only, no-prompt preflight. It installs
nothing, requests no account secret and cannot publish. This replaces the
previous untested assumption that hosted UI access is unavailable. Its result
is capability evidence only, never proof of a public update. Source graph tools
are not exposed in this session; bounded direct source reads establish that the
released .23 installer requires the real tray action.

Qualify the real public `.23 -> .24` upgrade and forced rollback against the
verified published assets, retaining the existing notification, signed-install,
exact-identity, successor-health and invisibility requirements. That public pair
has not been executed; do not describe preview auto-update as verified. Publication
after the mandatory gates, followed by this public qualification, is the explicitly
authorized order. This documentation update performs no installation or retry.

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

# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

Last evidence audit: 2026-07-16, after PR #133 at
`1adc5198eb7ed0b766b7e7bf652eb6576e246378`.

## Resume Protocol

Before continuing existing work, including after context compaction or a bare
"continue" request:

1. Inspect the current worktree, branch, HEAD, and remote tracking state.
2. Inspect open and recently merged PRs plus the required CI jobs for the
   current HEAD.
3. Read this file, [ROADMAP.md](ROADMAP.md), and
   [DECISIONS.md](DECISIONS.md).
4. If commits landed after the evidence audit, inspect their diff and update
   the checkpoint before relying on its milestone labels.
5. Derive the next action from a concrete missing invariant or gate. Do not
   accept a milestone number from conversation or an old compaction summary as
   proof.
6. Prefer taking the verified action over repeating the roadmap. Update this
   file in the same PR whenever the milestone status or next action changes.

## Verified Checkpoint

| Milestone | Status | Evidence and remaining gap |
|---|---|---|
| M0 - Safe Base | CI-qualified | Private-anchor lifecycle, owned PF tokens, exact process identity, protected secrets, and script/packaged lifecycle CI are implemented. PR #133 removed the final production path that reloaded `/etc/pf.conf` from guessed legacy evidence; source, sentinel, and packaged lifecycle checks passed on the merged commit. |
| M1 - Autonomous Routing V1 | Partial | Runtime recovery, tray-independent owned Geph, browser restart, wake/network simulation, and deterministic traffic contracts exist. The protected `owned-geph-qualification` workflow has no passing run, and a physical default-route/lid-close transition on a disposable Mac is still unverified. |
| M2 - Contracts And Code | Partial | StatusV2, policy/recovery modules, PF and Geph identity adapters, plus tray status, diagnostics, and Geph configuration are isolated. Python PF/Geph orchestration and Rust runtime, installer, summary, and menu orchestration remain coupled. |
| M3 - Release-Grade macOS | Partial | Pinned dependencies, strict Clippy, explicit target, SBOM, manifest, audit, attestations, and preview releases are implemented. Stable publication is intentionally closed until Developer ID signing, hardened runtime, notarization, stapling, key custody, and rollback qualification exist. |
| M4 - Cross-Platform Core | Core crate established | `crates/slipstream-core` owns the pure Rust address-attempt, route-circuit, registry, and connection-race modules plus their unchanged language-neutral v1 contract tests. The tray re-exports those modules for compatibility. Rust policy/recovery, signed updates, and a shared typed StatusV2 model remain. |

The required `checks` and `packaged-app-lifecycle` jobs passed for the audited
main commit in [CI run 29505517858](https://github.com/aiwaki/slipstream/actions/runs/29505517858).
The dependency and vendored-Geph audits passed in
[audit run 29505514280](https://github.com/aiwaki/slipstream/actions/runs/29505514280).

## Next Verified Action

Implement the routing-policy classifier and recovery reducer in
`slipstream-core` against the existing `routing-policy-v1` and `recovery-v1`
golden vectors. Preserve the protected Discord/YouTube invariants and keep all
transport, clock, PF, launchd, and other OS effects in adapters.

## External Gates

- Run the protected account-backed owned-Geph qualification successfully from
  `main`.
- Qualify a physical default-route change and lid-close/wake cycle on a
  disposable Mac.
- Add Developer ID signing, hardened runtime, notarization, stapling, policy-key
  custody, and cross-version rollback before opening the stable channel.

## Update Rule

Keep this file short and current. A PR that closes a listed gap, changes the
next verified action, or adds a new release/safety gate must update this
checkpoint. If live evidence contradicts it, stop, investigate the difference,
and correct the file rather than improvising a narrative.

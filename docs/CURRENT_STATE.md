# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

Last evidence audit: 2026-07-16, after PR #131 at
`345fe30feac16871acf22cf22832d47e3dcbf7ed`.

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
| M0 - Safe Base | Partial | Private-anchor lifecycle, owned PF tokens, exact process identity, protected secrets, and script/packaged lifecycle CI are implemented. One production exception remains: `_restore_legacy_pf_rules()` can run `pfctl -f /etc/pf.conf` from `cleanup_stale()`, contradicting the no-global-PF invariant. |
| M1 - Autonomous Routing V1 | Partial | Runtime recovery, tray-independent owned Geph, browser restart, wake/network simulation, and deterministic traffic contracts exist. The protected `owned-geph-qualification` workflow has no passing run, and a physical default-route/lid-close transition on a disposable Mac is still unverified. |
| M2 - Contracts And Code | Partial | StatusV2, policy/recovery modules, PF and Geph identity adapters, plus tray status, diagnostics, and Geph configuration are isolated. Python PF/Geph orchestration and Rust runtime, installer, summary, and menu orchestration remain coupled. |
| M3 - Release-Grade macOS | Partial | Pinned dependencies, strict Clippy, explicit target, SBOM, manifest, audit, attestations, and preview releases are implemented. Stable publication is intentionally closed until Developer ID signing, hardened runtime, notarization, stapling, key custody, and rollback qualification exist. |
| M4 - Cross-Platform Core | Foundation only | Shared JSON contracts and pure Rust address-attempt, route-circuit, registry, and connection-race modules exist inside the tray crate. There is no `slipstream-core` crate, Rust policy/recovery implementation, signed update core, or shared typed StatusV2 model yet. |

The required `checks` and `packaged-app-lifecycle` jobs passed for the audited
main commit in [CI run 29497286804](https://github.com/aiwaki/slipstream/actions/runs/29497286804).

## Next Verified Action

Remove the production global PF reload path. Legacy-rule detection may remain
read-only, but normal startup, recovery, and cleanup must never invoke
`pfctl -f`, edit `/etc/pf.conf`, disable PF, or infer ownership of another
ruleset. Cover the resulting startup and cleanup behavior with focused unit and
packaged-lifecycle regression tests before moving pure Rust modules into a real
`slipstream-core` crate.

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

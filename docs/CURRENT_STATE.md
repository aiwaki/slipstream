# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

Last evidence audit: 2026-07-17, through main commit
`583dcb9ccfa978e05dd64db112646880c281c791` after merged
[PR #149](https://github.com/aiwaki/slipstream/pull/149), plus the current
[PR #151](https://github.com/aiwaki/slipstream/pull/151) implementation
qualified in CI and dependency-audit runs linked below.

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
| M0 - Safe Base | CI-qualified | Private-anchor lifecycle, owned PF tokens, exact process identity, protected secrets, and script/packaged lifecycle CI are implemented. PR #133 removed the final production path that reloaded `/etc/pf.conf` from guessed legacy evidence. Daemon shutdown now blocks new status publication and serializes final status cleanup with any in-flight writer, preventing stale `active` state after the private anchor is cleared. |
| M1 - Autonomous Routing V1 | Partial | Runtime recovery, tray-independent owned Geph, browser restart, wake/network simulation, and deterministic traffic contracts exist. The protected `owned-geph-qualification` workflow has no passing run, and a physical default-route/lid-close transition on a disposable Mac is still unverified. |
| M2 - Contracts And Code | Partial | `slipstream-core` now owns policy classification, recovery, StatusV2, route-policy manifests and bundles, plus activation and rollback reducers. Python executes signed policy activation through that contract. Python PF/Geph orchestration and Rust tray runtime, installer, summary, and menu orchestration remain coupled. |
| M3 - Release-Grade macOS | Partial | Pinned dependencies, strict Clippy, explicit target, SBOM, manifest, audit, attestations, and preview releases are implemented. Stable publication is intentionally closed until Developer ID signing, hardened runtime, notarization, stapling, key custody, and rollback qualification exist. |
| M4 - Cross-Platform Core | Windows SCM effects CI-qualified; full lifecycle pending | `crates/slipstream-core` owns the pure routing, recovery, StatusV2, signed-policy, and activation models. `crates/slipstream-windows-adapter` executes every frozen routing/recovery vector and owns separate service-lifecycle, query-only observer, ownership-proof, payload, durable-state, and action-specific SCM boundaries. The SCM gate requires compatible intent, exact staged payload, serialized authorization evidence, and same-handle stable ownership before the exact service may be registered, started, stopped, or removed. Every returned lifecycle-lock handle independently proves a trusted owner and DACL, so permissive or squatted named objects fail closed. Disposable Windows CI has qualified the native register/remove path and the hostile pre-created mutex fixture. Full lifecycle qualification, networking adapters, Android/Linux adapters, and the iOS feasibility gate remain. |

The required `checks`, `windows-adapter-contract`, and
`packaged-app-lifecycle` jobs passed for the audited main commit in
[CI run 29589892727](https://github.com/aiwaki/slipstream/actions/runs/29589892727).
The dependency and vendored-Geph audits passed in
[audit run 29589892711](https://github.com/aiwaki/slipstream/actions/runs/29589892711).
The Windows ownership collector and its disposable owner-only fixture passed in
[PR #147 CI run 29592866727](https://github.com/aiwaki/slipstream/actions/runs/29592866727),
alongside the required checks and packaged lifecycle job; its dependency audit
passed in
[run 29592866706](https://github.com/aiwaki/slipstream/actions/runs/29592866706).
The merged collector passed again on main in
[CI run 29594236053](https://github.com/aiwaki/slipstream/actions/runs/29594236053),
and its dependency audit passed in
[run 29594235966](https://github.com/aiwaki/slipstream/actions/runs/29594235966).
The native Windows payload transaction, disposable rollback cases, and strict
lint passed in
[PR #148 CI run 29597856734](https://github.com/aiwaki/slipstream/actions/runs/29597856734).
The merged payload transaction passed again on main in
[CI run 29598632346](https://github.com/aiwaki/slipstream/actions/runs/29598632346),
and its dependency audit passed in
[run 29598632248](https://github.com/aiwaki/slipstream/actions/runs/29598632248).
The lifecycle-state contract, protected filesystem transaction, disposable
interruption/compensation cases, and strict Windows lint passed in
[PR #149 CI run 29603653185](https://github.com/aiwaki/slipstream/actions/runs/29603653185).
The merged lifecycle-state implementation passed again on main in
[CI run 29605608961](https://github.com/aiwaki/slipstream/actions/runs/29605608961),
and its dependency audit passed in
[run 29605608707](https://github.com/aiwaki/slipstream/actions/runs/29605608707).
The exiting-Safari lifecycle regression and packaged smoke passed in
[PR #150 CI run 29604297728](https://github.com/aiwaki/slipstream/actions/runs/29604297728).
The action-specific Windows SCM gate, exact native registration/removal,
machine-wide lifecycle serialization, bounded stop wait, strict lint, required
checks, and packaged lifecycle passed in
[PR #151 CI run 29611685751](https://github.com/aiwaki/slipstream/actions/runs/29611685751).
That run also qualified independent owner/DACL verification for every returned
kernel-object handle and rejection of a permissive pre-created mutex.
Its dependency and vendored-Geph audits passed in
[run 29611685757](https://github.com/aiwaki/slipstream/actions/runs/29611685757).

## Next Verified Action

Compose payload, durable-state, and SCM effects behind a disposable
full-lifecycle harness.
Qualify install, start, stop, bounded crash recovery, uninstall, and failed-step
compensation without adding Windows networking. Unknown or foreign evidence
must remain non-mutating, and every terminal cleanup path must prove exact
service absence before removing owned payload state.

## External Gates

- Run the protected account-backed owned-Geph qualification successfully from
  `main`.
- Qualify a physical default-route change and lid-close/wake cycle on a
  disposable Mac.
- Add Developer ID signing, hardened runtime, notarization, stapling, policy-key
  custody, and cross-version rollback before opening the stable channel.
- The local Parallels Windows 11 ARM64 VM has minimal Rust 1.97.1 but no Windows
  SDK or Visual Studio Build Tools; native compilation therefore remains a CI
  gate until that disposable VM is provisioned deliberately. A Fedora VM is
  also available for the later Linux adapter.

## Update Rule

Keep this file short and current. A PR that closes a listed gap, changes the
next verified action, or adds a new release/safety gate must update this
checkpoint. If live evidence contradicts it, stop, investigate the difference,
and correct the file rather than improvising a narrative.

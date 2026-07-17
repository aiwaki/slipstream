# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

Last evidence audit: 2026-07-17, through main commit
`9448dfc868ec1a7e9a515d5c991f934f924ebfc1` after merged
[PR #151](https://github.com/aiwaki/slipstream/pull/151) and its successful
main CI and dependency-audit runs linked below, plus the green checks for open
[PR #152](https://github.com/aiwaki/slipstream/pull/152). Its implementation
commit `d21e8a0f9461c78962321d0efc47b8999b352e81` composes the native Windows
lifecycle and qualifies it against a disposable real service; the work is not
part of `main` until the PR is merged.

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
| M4 - Cross-Platform Core | Windows full lifecycle PR-qualified; controller pending | `crates/slipstream-core` owns the pure routing, recovery, StatusV2, signed-policy, and activation models. `crates/slipstream-windows-adapter` executes every frozen routing/recovery vector and owns separate service-lifecycle, query-only observer, ownership-proof, payload, durable-state, action-specific SCM, and single-lock native composition boundaries. The SCM gate requires compatible intent, exact staged payload, serialized authorization evidence, and same-handle stable ownership before the exact service may be registered, started, stopped, or removed. Every returned lifecycle-lock handle independently proves a trusted owner and DACL, so permissive or squatted named objects fail closed. Disposable Windows CI has qualified native install, stop, start, bounded crash recovery, uninstall, exact terminal cleanup, and post-commit compensation against a real service. A production-facing controller that reconstructs lifecycle state after its own process restart, Windows networking adapters, Android/Linux adapters, and the iOS feasibility gate remain. |

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
[PR #151 CI run 29612116541](https://github.com/aiwaki/slipstream/actions/runs/29612116541).
That run also qualified independent owner/DACL verification for every returned
kernel-object handle and rejection of a permissive pre-created mutex.
Its dependency and vendored-Geph audits passed in
[run 29612116544](https://github.com/aiwaki/slipstream/actions/runs/29612116544).
The merged SCM implementation passed again on main in
[CI run 29612504541](https://github.com/aiwaki/slipstream/actions/runs/29612504541),
and its dependency audit passed in
[run 29612504538](https://github.com/aiwaki/slipstream/actions/runs/29612504538).
The single-lock native compositor, disposable real-service lifecycle, bounded
crash recovery, exact uninstall ordering, and injected post-commit compensation
passed in
[PR #152 CI run 29614734338](https://github.com/aiwaki/slipstream/actions/runs/29614734338).
That run executed the gated full-lifecycle test as one real Windows test rather
than filtering or skipping it. The dependency and vendored-Geph audits passed
in
[run 29614734358](https://github.com/aiwaki/slipstream/actions/runs/29614734358).

## Next Verified Action

Add a production-facing, still non-networking Windows service controller. It
must acquire the shared machine-wide operation lock before reconstructing
`WindowsServiceState` from durable intent, the read-only SCM observation, and
exact ownership evidence, then hold that same lock through the complete reducer
command and native-compositor execution. Qualify idempotent install, crash
recovery, and uninstall retries across a controller-process restart. Unknown,
foreign, inaccessible, or inconsistent evidence must remain non-mutating; no
Windows networking effect may be added until this restart/reconciliation
boundary passes disposable CI.

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

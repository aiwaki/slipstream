# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

Last evidence audit: 2026-07-17, through
[PR #147](https://github.com/aiwaki/slipstream/pull/147), based on main at
`22a59ade20894eac1eaef9fb6c868c5b78f74451`.

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
| M4 - Cross-Platform Core | Windows read-only ownership evidence CI-qualified | `crates/slipstream-core` owns the pure routing, recovery, StatusV2, signed-policy, and activation models. `crates/slipstream-windows-adapter` executes every frozen routing/recovery vector and owns separate service-lifecycle, query-only SCM observer, and ownership-proof v1 contracts. The Windows-only collector now resolves a fixed machine record through the system `ProgramData` known folder, proves final handle paths, regular non-reparse files, owner/restrictive DACL, bounded strict JSON, and same-handle executable SHA-256 before the pure reducer can return `Owned`. It has no write, process-control, mutating SCM, DNS, proxy, VPN, socket, or packet API. Disposable native Windows CI now exercises the handle, ACL, record, hash, and ownership conjunction. Payload staging, service effects and lifecycle qualification, networking adapters, Android/Linux adapters, and the iOS feasibility gate remain. |

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

## Next Verified Action

Implement only the native `StagePayload` transaction behind the existing
lifecycle action. It must stage
the content-addressed executable and owner record atomically on one local
volume, apply the exact ACL expected by this reader, re-open both through the
collector, and compensate only those exact identities on failure. Keep service
registration, process control, networking, DNS, proxy, PAC, and VPN out of that
PR.

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

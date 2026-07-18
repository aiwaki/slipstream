# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

Last evidence audit: 2026-07-18, through merged
[PR #165](https://github.com/aiwaki/slipstream/pull/165) at main commit
`3e1195a16c0f44dd6a1faeb2d9ea8c8f5f938322`, including its successful
exact-main CI and dependency-audit runs linked below.
Live PR and `main` state still take precedence over this recorded evidence
boundary.

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
| M4 - Cross-Platform Core | Windows WFP wire/handoff, runtime lifecycle, and management-session v1 implemented; kernel driver absent | `slipstream-core` owns pure routing, recovery, StatusV2, signed-policy, and activation models. The Windows adapter has CI-qualified service lifecycle, ownership, SCM, production host, data-plane, direct connector, owned direct ingress, and technology-neutral capture-source contracts. [PR #162](https://github.com/aiwaki/slipstream/pull/162) selected WFP `ALE_CONNECT_REDIRECT_V4/V6`; [PR #163](https://github.com/aiwaki/slipstream/pull/163) froze the fixed 128-byte service/driver context, exact identity and records-before-connect handoff; [PR #164](https://github.com/aiwaki/slipstream/pull/164) froze kernel-before-listener-before-atomic-session startup and filter-absence-first teardown; [PR #165](https://github.com/aiwaki/slipstream/pull/165) added the proof-gated dynamic management-session controller and native `Fwpm*` boundary. `windows-wfp-session-v1` fixes the seven owned management keys, a separate 128-byte provider context, non-replaceable kernel/listener proofs, one failure-atomic dynamic transaction, and an exact same-generation post-close filter inspection. The native boundary remains disconnected from the production no-network SCM host; disposable CI exercises only an empty dynamic begin/abort/close until a real kernel callout is registered. The kernel callout/driver, redirect-record socket effect, local/geo backends, Android/Linux adapters, and iOS feasibility gate remain. |

The required `checks`, `windows-adapter-contract`, and
`packaged-app-lifecycle` jobs passed for the audited main commit in
[CI run 29616479709](https://github.com/aiwaki/slipstream/actions/runs/29616479709).
The dependency and vendored-Geph audits passed in
[audit run 29616479684](https://github.com/aiwaki/slipstream/actions/runs/29616479684).
The audited main commit passed the same required jobs in
[CI run 29618787071](https://github.com/aiwaki/slipstream/actions/runs/29618787071),
and its dependency and vendored-Geph audits passed in
[run 29618787086](https://github.com/aiwaki/slipstream/actions/runs/29618787086).
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
The command-wide Windows controller, exact evidence reconstruction, idempotent
same-identity install, and failed-then-resumed crash recovery across separate
controller processes passed in
[PR #153 CI run 29618202282](https://github.com/aiwaki/slipstream/actions/runs/29618202282).
Its dependency and vendored-Geph audits passed in
[run 29618202290](https://github.com/aiwaki/slipstream/actions/runs/29618202290).
The production Windows service host, exact command/result contract, bounded SCM
stop/shutdown state machine, current-executable staging, repeatable management
commands from separate processes, PID replacement after restart, exact terminal
uninstall, and strict Windows lint passed in
[PR #154 CI run 29620298459](https://github.com/aiwaki/slipstream/actions/runs/29620298459).
Its dependency and vendored-Geph audits passed in
[run 29620298461](https://github.com/aiwaki/slipstream/actions/runs/29620298461).
The exact merged PR #154 commit passed again on main in
[CI run 29620781624](https://github.com/aiwaki/slipstream/actions/runs/29620781624),
and its dependency and vendored-Geph audits passed in
[run 29620781600](https://github.com/aiwaki/slipstream/actions/runs/29620781600).
The active-table request admission, protected-host reclassification, and exact
data-plane effect recovery cursors passed in
[PR #155 CI run 29623740312](https://github.com/aiwaki/slipstream/actions/runs/29623740312).
The exact merged PR #155 commit passed all required jobs in that same main run,
and its dependency and vendored-Geph audits passed in
[run 29623740325](https://github.com/aiwaki/slipstream/actions/runs/29623740325).
The worker-host composition, Windows-only production build, deterministic
startup/drain/deadline vectors, and real SCM stop path passed in
[PR #156 CI run 29625004279](https://github.com/aiwaki/slipstream/actions/runs/29625004279).
The exact merged PR #156 commit passed again on main in
[CI run 29625340050](https://github.com/aiwaki/slipstream/actions/runs/29625340050),
and its dependency and vendored-Geph audits passed in
[run 29625340061](https://github.com/aiwaki/slipstream/actions/runs/29625340061).
The active-policy-bound direct connector, exact data-plane effect bridge, and
real Windows loopback connect/payload/reset/cancel/deadline/shutdown fixture
passed in
[PR #157 CI run 29627204384](https://github.com/aiwaki/slipstream/actions/runs/29627204384).
Its dependency and vendored-Geph audits passed in
[run 29627204387](https://github.com/aiwaki/slipstream/actions/runs/29627204387).
The exact merged PR #157 commit passed again on main in
[CI run 29627636788](https://github.com/aiwaki/slipstream/actions/runs/29627636788),
and its dependency and vendored-Geph audits passed in
[run 29627636787](https://github.com/aiwaki/slipstream/actions/runs/29627636787).
The owned-client ingress, deterministic first-delivery/no-progress boundaries,
and exact native Windows relay passed in
[PR #158 CI run 29630565455](https://github.com/aiwaki/slipstream/actions/runs/29630565455).
The exact merged PR #158 commit passed all required jobs again on main in
[CI run 29630725442](https://github.com/aiwaki/slipstream/actions/runs/29630725442),
and its dependency and vendored-Geph audits passed in
[run 29630725439](https://github.com/aiwaki/slipstream/actions/runs/29630725439).
The technology-neutral capture-source lifecycle, one-shot resource ownership,
absolute deadline preservation, duplicate-resource rejection, failure-atomic
handoff, and bounded shutdown passed in
[PR #160 CI run 29632297457](https://github.com/aiwaki/slipstream/actions/runs/29632297457).
Its dependency and vendored-Geph audits passed in
[run 29632297449](https://github.com/aiwaki/slipstream/actions/runs/29632297449).
The exact merged PR #160 commit passed all required jobs again on main in
[CI run 29632468996](https://github.com/aiwaki/slipstream/actions/runs/29632468996),
and its dependency and vendored-Geph audits passed in
[run 29632468994](https://github.com/aiwaki/slipstream/actions/runs/29632468994).
The checkpoint commit in PR #161 passed all required jobs again on main in
[CI run 29632983193](https://github.com/aiwaki/slipstream/actions/runs/29632983193),
and its dependency and vendored-Geph audits passed in
[run 29632983199](https://github.com/aiwaki/slipstream/actions/runs/29632983199).
The WFP mechanism decision, management-callout ownership correction, and
filter-first fail-open ordering in PR #162 passed all required jobs again on
main in
[CI run 29633994824](https://github.com/aiwaki/slipstream/actions/runs/29633994824),
and its dependency and vendored-Geph audits passed in
[run 29633994821](https://github.com/aiwaki/slipstream/actions/runs/29633994821).
The exact WFP wire/handoff merge in PR #163 passed all required jobs again on
main in
[CI run 29635704622](https://github.com/aiwaki/slipstream/actions/runs/29635704622),
and its dependency and vendored-Geph audits passed in
[run 29635704616](https://github.com/aiwaki/slipstream/actions/runs/29635704616).
The pure WFP runtime lifecycle, monotonic attempt binding, over-capacity stream
rejection, retained-resource teardown, and non-replaying effect recovery in
PR #164 passed all required jobs in
[CI run 29637212615](https://github.com/aiwaki/slipstream/actions/runs/29637212615),
and its dependency and vendored-Geph audits passed in
[run 29637212612](https://github.com/aiwaki/slipstream/actions/runs/29637212612).
The exact merged PR #164 commit passed again on main in
[CI run 29637402421](https://github.com/aiwaki/slipstream/actions/runs/29637402421),
and its dependency and vendored-Geph audits passed in
[run 29637402397](https://github.com/aiwaki/slipstream/actions/runs/29637402397).
The WFP management-session contract, same-generation proof invalidation,
failure-atomic dynamic transaction, Windows native compile/lint, and exact
empty-session qualification in PR #165 passed all required jobs in
[CI run 29639374347](https://github.com/aiwaki/slipstream/actions/runs/29639374347),
and its dependency and vendored-Geph audits passed in
[run 29639374357](https://github.com/aiwaki/slipstream/actions/runs/29639374357).
The exact merged PR #165 commit passed again on main in
[CI run 29639553087](https://github.com/aiwaki/slipstream/actions/runs/29639553087),
including one explicitly asserted WFP qualification test, and its dependency
and vendored-Geph audits passed in
[run 29639553086](https://github.com/aiwaki/slipstream/actions/runs/29639553086).

## Next Verified Action

Implement the minimal kernel V4/V6 WFP connect-redirect callout and disposable
registrar, then use the frozen management-session controller to qualify one
real full object/filter transaction. Prove registration before transaction,
listener readiness before filters, self-loop prevention, session-close/filter
absence before drain and unregister, and crash fail-open behavior. Do not
mutate direct connector v1 or compose capture into the production SCM host yet.

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

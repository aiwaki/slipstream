# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

Last evidence audit: 2026-07-19, through merged
[PR #172](https://github.com/aiwaki/slipstream/pull/172) at main commit
`e4249ffeacc6906034fdb319339353dd5e8897fb`, including its successful
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
| M0 - Safe Base | Blocked after primary install regression | Private-anchor lifecycle, owned PF tokens, exact process identity, protected secrets, and script/packaged lifecycle CI are implemented, but the exact PR #172 artifact failed the primary workstation smoke twice. Installing its daemon immediately coincided with broad HTTPS failures in ChatGPT/Codex and Discord while app-owned Geph was disabled. Uninstall removed the daemon, listener, runtime install, and PF token without changing user DNS or system proxy state, but left `/Applications/Slipstream.app` behind. The active transparent path and tray self-removal must be repaired and qualified before another primary install. |
| M1 - Autonomous Routing V1 | Partial | Runtime recovery, tray-independent owned Geph, browser restart, wake/network simulation, and deterministic traffic contracts exist. Local PF readiness is independent of optional Geph. Geo-exit backend loss preserves Discord/YouTube local bypass and falls back only to the exact pre-PF system destination, which may represent ordinary direct access, user DNS selection, a user VPN, or their combination. Owned-Geph cooldown and transient Keychain unavailability cannot force a Geph redial or erase opt-in state. A user full-tunnel `utun*` default route keeps Slipstream dormant and untouched; split/per-app VPN equivalence is not yet physically qualified. The protected `owned-geph-qualification` workflow has no passing run, and a physical default-route/lid-close transition on a disposable Mac is still unverified. |
| M2 - Contracts And Code | Partial | `slipstream-core` now owns policy classification, recovery, StatusV2, route-policy manifests and bundles, plus activation and rollback reducers. Python executes signed policy activation through that contract. Python PF/Geph orchestration and Rust tray runtime, installer, summary, and menu orchestration remain coupled. |
| M3 - Release-Grade macOS | Partial | Pinned dependencies, strict Clippy, explicit target, SBOM, manifest, audit, attestations, and preview releases are implemented. Stable publication is intentionally closed until Developer ID signing, hardened runtime, notarization, stapling, key custody, and rollback qualification exist. |
| M4 - Cross-Platform Core | Pure packet-route safety gates implemented; packet effects absent | `slipstream-core` owns pure routing, recovery, StatusV2, signed-policy, and activation models. The Windows adapter has CI-qualified service lifecycle, ownership, SCM, production host, data-plane, direct connector, owned direct ingress, and technology-neutral capture-source contracts. The WFP wire/runtime/session v1 work from PRs #162-#165 remains frozen research, but the shipping path no longer includes a Slipstream-owned kernel driver because production signing requires an organization-backed certificate workflow. The active `windows-packet-adapter-v1` boundary pins official signed Wintun 0.14.1 AMD64/ARM64 artifacts and admits only exact package, DLL, PE, publisher, signer, and timestamp evidence. Its native read-only collector hashes bounded non-reparse handles, validates Authenticode against the same held DLL handle without network retrieval, and retains that handle in an opaque admission. The pure route boundary prepares only non-authorizing fresh public `/32` or `/128` candidates after active-policy reclassification and host/address binding, rejects reserved IPv6, and now rejects partial, stale, malformed, oversized, or policy-incompatible shared-destination snapshots. A conflict admission is short-lived and generation-bound but still cannot authorize a native route. The complete-boundary native issuer, lifetime generation lease, DLL loading, owned adapter/routes, userspace packet stack, local/geo backends, disposable coexistence qualification, Android/Linux adapters, and the iOS feasibility gate remain. The production SCM host remains no-network. |

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
The PR #166 checkpoint commit passed all required jobs again on main in
[CI run 29640104120](https://github.com/aiwaki/slipstream/actions/runs/29640104120),
and its dependency and vendored-Geph audits passed in
[run 29640104123](https://github.com/aiwaki/slipstream/actions/runs/29640104123).
The official signed Wintun artifact admission, opaque resolver-evidence
binding, frozen IANA IPv6 allocation snapshot, and non-authorizing exact-route
contract in PR #167 passed all required jobs again on the exact merge commit in
[CI run 29646370056](https://github.com/aiwaki/slipstream/actions/runs/29646370056),
and its dependency and vendored-Geph audits passed in
[run 29646370093](https://github.com/aiwaki/slipstream/actions/runs/29646370093).
The PR #168 checkpoint merge passed all required jobs again on the exact main
commit in
[CI run 29646801180](https://github.com/aiwaki/slipstream/actions/runs/29646801180),
and its dependency and vendored-Geph audits passed in
[run 29646801183](https://github.com/aiwaki/slipstream/actions/runs/29646801183).
The native Wintun collector admitted both official AMD64 and ARM64 artifacts,
rejected a tampered DLL, and retained the read-only handle without loading the
adapter in
[PR #169 CI run 29648242778](https://github.com/aiwaki/slipstream/actions/runs/29648242778).
Its dependency and vendored-Geph audits passed in
[run 29648242770](https://github.com/aiwaki/slipstream/actions/runs/29648242770).
The exact merged PR #169 commit passed all required jobs again on main in
[CI run 29648441001](https://github.com/aiwaki/slipstream/actions/runs/29648441001),
and its dependency and vendored-Geph audits passed in
[run 29648440999](https://github.com/aiwaki/slipstream/actions/runs/29648440999).
The complete shared-destination conflict gate from PR #170 passed `checks`,
`windows-adapter-contract`, and `packaged-app-lifecycle` on the exact merge
commit in
[CI run 29650142948](https://github.com/aiwaki/slipstream/actions/runs/29650142948),
and its dependency and vendored-Geph audits passed in
[run 29650142955](https://github.com/aiwaki/slipstream/actions/runs/29650142955).
The macOS uninstall/drain safety change in PR #171 passed `checks`,
`windows-adapter-contract`, and the disposable `packaged-app-lifecycle` gate in
[CI run 29656556574](https://github.com/aiwaki/slipstream/actions/runs/29656556574).
Its dependency and vendored-Geph audits passed in
[run 29656556559](https://github.com/aiwaki/slipstream/actions/runs/29656556559).
The primary workstation remained uninstalled throughout that qualification.

The clean-install local-bypass repair and optional-backend state guards in
[PR #172](https://github.com/aiwaki/slipstream/pull/172) passed `checks`,
`windows-adapter-contract`, and `packaged-app-lifecycle` on the exact merge
commit in
[CI run 29663263685](https://github.com/aiwaki/slipstream/actions/runs/29663263685).
Its dependency and vendored-Geph audits passed in
[run 29663263691](https://github.com/aiwaki/slipstream/actions/runs/29663263691).
The packaged gate proved active local bypass without a Geph account or
listener and preserved the independent PF sentinel.

The exact artifact from that run was then installed twice on the primary
workstation. Both installs immediately coincided with broad HTTPS failures
before the tray was launched, while app-owned Geph was disabled. Both manual
uninstalls restored a process-free daemon state with no listener, runtime
install, or PF token and left the user's `111.88.96.50` / `111.88.96.51` DNS
and system proxy settings unchanged. The app bundle itself was not removed.
`Reconnecting 5/5` was also observed after cleanup, so that symptom is not yet
attributed exclusively to an active Slipstream PF path; the reproducible
install trigger still makes this build unsafe to reinstall.

The doc-only checkpoint rerun then reproduced the same class of failure in the
disposable packaged gate: Safari reported `You Are Not Connected to the
Internet` at `before-tray-start` while the private PF anchor was active in
[CI run 29666303800](https://github.com/aiwaki/slipstream/actions/runs/29666303800).
This confirms that the unsafe baseline is in the daemon data plane rather than
the tray, Geph account state, or the workstation's DNS configuration.

[PR #174](https://github.com/aiwaki/slipstream/pull/174) fixed the independent
tray-uninstall defect by moving app-bundle removal into a validated one-shot
launchd worker. Its complete CI, including `packaged-app-lifecycle`, passed in
[run 29665174375](https://github.com/aiwaki/slipstream/actions/runs/29665174375).

[PR #175](https://github.com/aiwaki/slipstream/pull/175) repaired the daemon
baseline without changing protected routing policy. Direct, unknown, non-TLS,
and no-SNI/ECH connections now relay the exact pre-PF destination without
alternate DNS, desync, or a first-payload gate. Recovery is deferred to a later
client retry and is armed only by an observed stall, repeated clean EOF, or
server-first zero-byte close; healthy low-volume streams do not feed it.
Orderly client EOF is preserved as a bounded TCP half-close. All required
checks passed on the exact reviewed head, including the packaged Safari,
Chrome, PF-sentinel, and lifecycle gate in
[CI run 29667950857](https://github.com/aiwaki/slipstream/actions/runs/29667950857).
The formerly failing `before-tray-start` Safari stage passed. The repair was
squash-merged as `a26e467` and has not been installed on the primary
workstation.

## Next Verified Action

Do not reinstall or re-arm Slipstream on the primary workstation unattended.
Prepare a new versioned preview from merged `main`, qualify that exact artifact
again on a disposable Mac, and define an automatic rollback guard that checks
baseline HTTPS, daemon/listener ownership, the private PF anchor, token cleanup,
and app-bundle removal. A primary smoke may follow only while the user is
present and the guard can remove the whole owned path without touching external
DNS, VPN, proxy, PAC, or PF state.

## External Gates

- Run the protected account-backed owned-Geph qualification successfully from
  `main`.
- Qualify a physical default-route change and lid-close/wake cycle on a
  disposable Mac.
- Add Developer ID signing, hardened runtime, notarization, stapling, policy-key
  custody, and cross-version rollback before opening the stable channel.
- The local Parallels Windows 11 ARM64 VM has minimal Rust 1.97.1 but no Windows
  SDK or Visual Studio Build Tools; native compilation therefore remains a CI
  gate until that disposable VM is provisioned deliberately. The official
  ARM64 Wintun DLL hash and embedded signature were inspected there without
  loading it. A Fedora VM is also available for the later Linux adapter.

## Update Rule

Keep this file short and current. A PR that closes a listed gap, changes the
next verified action, or adds a new release/safety gate must update this
checkpoint. If live evidence contradicts it, stop, investigate the difference,
and correct the file rather than improvising a narrative.

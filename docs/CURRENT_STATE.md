# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

Last evidence audit: 2026-07-20, through merged
[PR #184](https://github.com/aiwaki/slipstream/pull/184) at main commit
`56c37ccb680ce771ca16f7564be8cf0d37aa34b3`, including its successful
[exact-main CI run 29711400231](https://github.com/aiwaki/slipstream/actions/runs/29711400231)
and
[dependency-audit run 29711400215](https://github.com/aiwaki/slipstream/actions/runs/29711400215).
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
| M0 - Safe Base | Disposable qualification complete; one scheduled workstation smoke remains | Private-anchor lifecycle, owned PF tokens, exact process identity, protected secrets, and failure-atomic install/uninstall are implemented. PRs #174-#180 cover app removal, exact-system passthrough, baseline qualification, loopback leasing, failure-atomic lifecycle, probe-free startup status, killable console-user DNS helpers, and one total preflight budget. PR #181 corrected every packaging and qualification path to use the immutable `geph-vendor-0.3.0-r1` recorded in `vendor/geph/SOURCE.json`; the exact merge commit then passed the disposable packaged lifecycle. The older `140598b` download remains disqualified because it contains the superseded Geph binary. M0 now waits only for one short, user-scheduled workstation smoke with preflight and rollback prepared in advance. |
| M1 - Autonomous Routing V1 | Partial | Runtime recovery, tray-independent owned Geph, browser restart, wake/network simulation, and deterministic traffic contracts exist. Local PF readiness is independent of optional Geph. Geo-exit backend loss preserves Discord/YouTube local bypass and falls back only to the exact pre-PF system destination, which may represent ordinary direct access, user DNS selection, a user VPN, or their combination. Owned-Geph cooldown and transient Keychain unavailability cannot force a Geph redial or erase opt-in state. A user full-tunnel `utun*` default route keeps Slipstream dormant and untouched; split/per-app VPN equivalence is not yet physically qualified. The protected `owned-geph-qualification` workflow has no passing run, and a physical default-route/lid-close transition on a disposable Mac is still unverified. |
| M2 - Contracts And Code | Partial | `slipstream-core` now owns policy classification, recovery, StatusV2, route-policy manifests and bundles, plus activation and rollback reducers. Python executes signed policy activation through that contract. Python PF/Geph orchestration and Rust tray runtime, installer, summary, and menu orchestration remain coupled. |
| M3 - Release-Grade macOS | Partial | Pinned dependencies, strict Clippy, explicit target, SBOM, manifest, audit, attestations, and preview releases are implemented. Stable publication is intentionally closed until Developer ID signing, hardened runtime, notarization, stapling, key custody, and rollback qualification exist. |
| M4 - Cross-Platform Core | Native Wintun lifecycle qualified on main; abrupt-owner cleanup under qualification | `slipstream-core` owns pure routing, recovery, StatusV2, signed-policy, and activation models. The Windows adapter has CI-qualified service lifecycle, ownership, SCM, production host, data-plane, direct connector, owned direct ingress, and technology-neutral capture-source contracts. The WFP wire/runtime/session v1 work from PRs #162-#165 remains frozen research, and the shipping path does not include a Slipstream-owned kernel driver. The `windows-packet-adapter-v1` boundary pins official signed Wintun 0.14.1 AMD64/ARM64 artifacts and has qualified read-only package, DLL, PE, publisher, signer, and timestamp admission. Its pure exact-route gate remains frozen as non-authorizing because read-only system DNS cannot enumerate unbounded policy suffixes or application-owned DoH, and Wintun exposes no trusted hostname context. The separate `windows-packet-capture-v2` contract reclassifies each flow from bounded TLS SNI or QUIC Initial evidence and preserves direct passthrough for direct, unknown, ECH, missing, malformed, stale, unsafe, or mismatched observations. It selects no backend and is not composed into production. PR #185 loaded only the exact admitted DLL on disposable native AMD64 and ARM64 runners, created one unique test adapter, started and ended one minimum-size session, and proved that adapter was absent afterward without adding an address or route. This proves only native lifecycle compatibility and does not authorize capture or routing. The next isolated fixture keeps one unique adapter and session live in an exact child process, terminates only that process handle without Rust cleanup, and requires bounded name disappearance. Loop avoidance, pre-existing-flow activation safety, bounded removal, external-VPN coexistence, userspace packet processing, local/geo backends, Android/Linux adapters, and the iOS feasibility gate remain. The production SCM host remains no-network. |

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
squash-merged as `a26e467`; that exact main commit passed
[CI run 29668308779](https://github.com/aiwaki/slipstream/actions/runs/29668308779)
and
[dependency-audit run 29668308760](https://github.com/aiwaki/slipstream/actions/runs/29668308760).
It has not been installed on the primary workstation.

[PR #176](https://github.com/aiwaki/slipstream/pull/176) recorded that
qualification boundary without changing runtime behavior and was merged as
`1f4cdd0`; its exact main commit passed CI and dependency audit.

[PR #177](https://github.com/aiwaki/slipstream/pull/177) then added the
automatic startup guard. It proves a small neutral HTTPS baseline through the
console user's current system route before PF and repeats only the same proven
numeric destinations after PF. A failed post-arm proof rolls back only
Slipstream-owned state. If PF cleanup itself is temporarily unavailable, the
daemon keeps its listener and runtime alive while retrying cleanup instead of
leaving a redirect to a dead listener. Install, reinstall, and uninstall also
use failure-atomic ordering. The exact merge commit `f5541a0` passed the full
disposable Safari, Chrome, PF-sentinel, and packaged lifecycle gate.

[PR #178](https://github.com/aiwaki/slipstream/pull/178) closed the remaining
macOS loopback gap. It clears only `PFI_IFLAG_SKIP` under a durable root-owned
`0600` lease, restores and verifies the original `lo0 (skip)` state before
releasing the owned PF token, quiesces the `KeepAlive` daemon before signalling
verified owned processes, and moves tray recovery behind the installed daemon
ownership boundary. The redirect excludes `127.0.0.0/8`, and the active monitor
revalidates loopback visibility if another PF reload changes it. Both the PR and
the exact main commit `162cc8e` passed the disposable private-PF sentinel and
packaged lifecycle. The primary workstation had remained uninstalled since the
unsafe baseline incident until the controlled validation below.

[PR #179](https://github.com/aiwaki/slipstream/pull/179) refreshed this
checkpoint without changing runtime behavior and merged as `c07ade34`; the
exact main commit passed required CI and dependency audit. Its packaged artifact
was then used for one controlled workstation validation. Preflight proved the
daemon job, owned Geph job, listeners, status, PF token, loopback lease, and
private anchor absent; the user's DNS and proxy settings were left unchanged.
The app bundle was replaced atomically with the exact signed artifact, but the
first daemon install timed out with `status missing`. The session log reached
the standalone Telegram-proxy check and no later startup line. Live diagnosis
showed the first synchronous system resolver call could stall while a later
neutral target remained reachable. The prepared rollback removed every owned
root runtime artifact and listener without a connection outage. The app bundle
remains present but unlaunched and inert; the root daemon is absent and
disabled, owned Geph is absent, and Slipstream PF is not active.

[PR #180](https://github.com/aiwaki/slipstream/pull/180) bounded that startup
path and merged as `140598b`. The daemon now publishes an atomic, probe-free
`dormant` StatusV2 snapshot after binding its listener and before Geph, DNS, or
PF qualification. System-DNS lookups run as the console user in killable child
processes under one total preflight budget; diagnostic refresh uses the same
bounded helper. The packaged lifecycle installs a scoped resolver blackhole for
the first neutral target and proves that status precedes the stalled query, a
later target can activate routing, no helper survives, and cleanup preserves
the independent PF sentinel. The exact main commit passed all required jobs in
[CI run 29707822352](https://github.com/aiwaki/slipstream/actions/runs/29707822352)
and dependency audit in
[run 29707822353](https://github.com/aiwaki/slipstream/actions/runs/29707822353).
That exact artifact is downloaded and signature-verified, but it has not been
launched or installed on the primary workstation. It was later disqualified
because this workflow had downloaded the superseded `geph-vendor-0.3.0`
artifact rather than the release revision recorded in the repository.

[PR #181](https://github.com/aiwaki/slipstream/pull/181) made all build,
qualification, and release workflows derive the immutable Geph tag from
`vendor/geph/VERSION` and `vendor/geph/SOURCE.json.release_revision`. Release
asset downloads now use bounded retries, require a complete requested asset
set, and never publish partial output. The exact merge commit `27363cd3` passed
all required jobs, including the disposable packaged lifecycle with
`geph-vendor-0.3.0-r1`, in
[CI run 29709766877](https://github.com/aiwaki/slipstream/actions/runs/29709766877),
and its dependency and vendored-Geph audits passed in
[run 29709766891](https://github.com/aiwaki/slipstream/actions/runs/29709766891).
No application or privileged component was launched on the primary workstation.

[PR #182](https://github.com/aiwaki/slipstream/pull/182) refreshed this
checkpoint after the revisioned artifact correction. [PR
#183](https://github.com/aiwaki/slipstream/pull/183) added the pure capture-only
Windows v2 classifier, and its exact merge commit passed all required jobs in
[CI run 29710542922](https://github.com/aiwaki/slipstream/actions/runs/29710542922)
plus dependency audit in
[run 29710542945](https://github.com/aiwaki/slipstream/actions/runs/29710542945).
[PR #184](https://github.com/aiwaki/slipstream/pull/184) made every owned-Geph
cleanup stage independent so a Keychain error cannot skip later runtime,
listener, sentinel, or root-boundary cleanup. Its exact main commit passed all
required jobs in
[CI run 29711400231](https://github.com/aiwaki/slipstream/actions/runs/29711400231)
and dependency audit in
[run 29711400215](https://github.com/aiwaki/slipstream/actions/runs/29711400215).
The protected `geph-qualification` environment now exists and is limited to
protected branches, but it has no `SLIPSTREAM_GEPH_ACCOUNT_SECRET`; the manual
account-backed gate must not be triggered until the user supplies that secret.

[PR #185](https://github.com/aiwaki/slipstream/pull/185) added the first native
Wintun lifecycle subgate. The exact admitted 0.14.1 DLL, unique adapter, minimum
128 KiB session, and adapter-removal proof passed on both native x64 and ARM64
Windows runners in
[run 29712583287](https://github.com/aiwaki/slipstream/actions/runs/29712583287).
The fixture configured no address or route and did not touch DNS, proxy, PAC,
VPN, or the Wintun driver. Its exact merge commit `d35ab35` passed the same
native x64 and ARM64 gate in
[run 29713033740](https://github.com/aiwaki/slipstream/actions/runs/29713033740),
all required checks and packaged lifecycle in
[run 29713033745](https://github.com/aiwaki/slipstream/actions/runs/29713033745),
and dependency audit in
[run 29713033754](https://github.com/aiwaki/slipstream/actions/runs/29713033754).

## Next Verified Action

Do not reinstall or re-arm Slipstream on the primary workstation while the user
is away. The downloaded `140598b` app used a superseded Geph artifact and must
not be launched. The exact revisioned `f22e475` packaged app has been downloaded,
signature-verified, and inspected without launching any component. Actual
installation still waits for one short, user-scheduled smoke with preflight and
rollback prepared in advance. No repeated administrator prompts are acceptable.
If the smoke fails, uninstall immediately and preserve the first failing
evidence; do not improvise another install in the same session.

Continue M4 on disposable systems. Qualify the separate child-process
crash-cleanup gate for one uniquely owned adapter on native AMD64 and ARM64.
Follow it with outbound loop avoidance, pre-existing-flow activation safety,
bounded capture removal, and external-VPN coexistence gates before any
exact-route transaction or production composition. A partial DNS cache is never
treated as complete attribution.
External DNS, VPN, proxy, PAC, and unrelated PF state remain read-only.

## External Gates

- Add `SLIPSTREAM_GEPH_ACCOUNT_SECRET` to the protected
  `geph-qualification` environment, then run the account-backed owned-Geph
  qualification successfully from `main`.
- Pass the abrupt child-process Wintun cleanup fixture on both native AMD64 and
  ARM64 Windows runners without adapter residue.
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

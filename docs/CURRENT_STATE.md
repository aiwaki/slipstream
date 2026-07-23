# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

Last evidence audit: 2026-07-22, through merged
[PR #203](https://github.com/aiwaki/slipstream/pull/203) at main commit
`e86600fb1b326dbff8459b2e4a27b27b90a9f177`, including its successful
[required CI run 29969578575](https://github.com/aiwaki/slipstream/actions/runs/29969578575)
and
[dependency-audit run 29969578586](https://github.com/aiwaki/slipstream/actions/runs/29969578586).
The latest native AMD64/ARM64 boundary remains PR #202's successful
[run 29968586744](https://github.com/aiwaki/slipstream/actions/runs/29968586744).
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
| M4 - Cross-Platform Core | Independent route-owner coexistence candidate | `slipstream-core` owns the pure policy, recovery, StatusV2, signed-policy, and activation contracts. The Windows adapter has exact-main evidence for service ownership and lifecycle, a no-network production host, admitted signed Wintun artifacts, disposable adapter/session cleanup, exact-route ownership and recovery, no-payload IPv4/IPv6 socket selection, closed IPv4/IPv6 capture/injection round trips, constrained baseline source/LUID revalidation, bounded IPv4 UDP and TCP pre-existing-flow activation, and abrupt capture-owner termination cleanup on native AMD64 and ARM64. PR #202 proves an exact child process cannot leave its adapter, address, or `/32` behind and that route selection returns to the still-live owned baseline. The current candidate keeps an independently owned VPN-like non-default route alive before, during, and after Slipstream capture and cleanup; native AMD64/ARM64 evidence is pending. The earlier WFP path remains frozen research; `windows-packet-capture-v2` and `windows-packet-egress-v1` remain pure non-production contracts. Physical/full-tunnel/split/per-app vendor VPN qualification, userspace forwarding and backends, Android/Linux adapters, and the iOS feasibility gate remain separate. The production SCM host remains no-network. |

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

[PR #186](https://github.com/aiwaki/slipstream/pull/186) added the separate
abrupt-owner cleanup proof. The exact child-process adapter/session fixture
passed on native x64 and ARM64 runners in
[run 29713791755](https://github.com/aiwaki/slipstream/actions/runs/29713791755).
It used no process-name search, adapter or driver deletion, address, route, DNS,
proxy, PAC, VPN, or production-host composition. Its exact merge commit
`6c3759e` passed the same native gate in
[run 29714575179](https://github.com/aiwaki/slipstream/actions/runs/29714575179),
all required checks and packaged lifecycle in
[run 29714575187](https://github.com/aiwaki/slipstream/actions/runs/29714575187),
and dependency audit in
[run 29714575209](https://github.com/aiwaki/slipstream/actions/runs/29714575209).

The pure Windows packet-egress v1 contract now freezes the admission boundary
needed before a native loop-avoidance fixture. A plan requires short-lived
route evidence collected before capture plus an exact owned capture-route
activation from that baseline epoch to the current epoch. The transition must
retain the capture generation, destination, exact host prefix, and capture
interface identity; any later route-epoch change invalidates the plan. The
egress LUID/index identity and currently selected source address must still
match the baseline, alongside the public destination, source family, and
containing baseline route prefix. The capture interface is rejected. The plan
records the Windows IPv4/IPv6
per-socket interface value but performs no route query, socket operation,
adapter effect, route mutation, backend choice, or production composition.
The exact merge commit `1765398` passed the native x64 and ARM64 lifecycle gate
in
[run 29718757015](https://github.com/aiwaki/slipstream/actions/runs/29718757015),
all required checks and packaged lifecycle in
[run 29718757005](https://github.com/aiwaki/slipstream/actions/runs/29718757005),
and dependency audit in
[run 29718756994](https://github.com/aiwaki/slipstream/actions/runs/29718756994).

One earlier ARM64 attempt in
[run 29715892426](https://github.com/aiwaki/slipstream/actions/runs/29715892426)
reached the broad 20-minute job timeout inside the abrupt-owner cleanup step
without phase output. Later exact-head and exact-main runs passed, so this is
recorded as a flaky, insufficiently bounded qualification gate rather than
routing-runtime evidence. [PR #188](https://github.com/aiwaki/slipstream/pull/188)
bounds the exact-child wait, removes blocking cleanup from `Drop`, streams phase
output, and gives that step its own four-minute ceiling. Its exact merge commit
`f373339` passed native x64 and ARM64 qualification in
[run 29719510753](https://github.com/aiwaki/slipstream/actions/runs/29719510753),
all required checks and packaged lifecycle in
[run 29719510754](https://github.com/aiwaki/slipstream/actions/runs/29719510754),
and dependency audit in
[run 29719510744](https://github.com/aiwaki/slipstream/actions/runs/29719510744).
[PR #189](https://github.com/aiwaki/slipstream/pull/189) added the isolated
read-only Windows route/source observer. Its exact merge commit `b71042b` passed
the observer step and the existing Wintun lifecycle on native x64 and ARM64 in
[run 29721672134](https://github.com/aiwaki/slipstream/actions/runs/29721672134),
all required checks and packaged lifecycle in
[run 29721672179](https://github.com/aiwaki/slipstream/actions/runs/29721672179),
and dependency audit in
[run 29721672104](https://github.com/aiwaki/slipstream/actions/runs/29721672104).

[PR #190](https://github.com/aiwaki/slipstream/pull/190) sealed the
Windows route-transition issuer behind opaque, native-timestamped route
observations. Its exact merge commit `44afffc` passed the issuer and existing
Wintun lifecycle gates on native x64 and ARM64 in
[run 29726460677](https://github.com/aiwaki/slipstream/actions/runs/29726460677),
all required checks and packaged lifecycle in
[run 29726460692](https://github.com/aiwaki/slipstream/actions/runs/29726460692),
and dependency audit in
[run 29726460674](https://github.com/aiwaki/slipstream/actions/runs/29726460674).
The first ARM64 attempt for the PR in
[run 29725545540](https://github.com/aiwaki/slipstream/actions/runs/29725545540)
printed the exact crash-cleanup test's passing result, then remained inside the
PowerShell `Tee-Object` pipeline until the four-minute step timeout. Attempt 2
and exact-main both passed. This is a repeated qualification-harness failure,
not packet-runtime evidence; the current follow-up replaces that object
pipeline with a retained exact process handle, file-backed live output, and an
inner monotonic deadline before route-owner work resumes.

[PR #191](https://github.com/aiwaki/slipstream/pull/191) replaced that fragile
pipeline with the retained-process harness. Its exact merge commit `8d00c2a`
passed native AMD64/ARM64 packet qualification in
[run 29729362857](https://github.com/aiwaki/slipstream/actions/runs/29729362857),
all required checks and packaged lifecycle in
[run 29729362904](https://github.com/aiwaki/slipstream/actions/runs/29729362904),
and dependency audit in
[run 29729362872](https://github.com/aiwaki/slipstream/actions/runs/29729362872).

[PR #192](https://github.com/aiwaki/slipstream/pull/192) is the first
feature-gated exact-route ownership qualification. Its initial native run
[29730828356](https://github.com/aiwaki/slipstream/actions/runs/29730828356)
created the retained route on both AMD64 and ARM64, but the fresh
`GetBestRoute2` observation then failed with Win32 code `1232`: the unique bare
Wintun adapter had no usable source address. The correction keeps address
ownership outside the route owner and production host. The native fixture now
creates only `192.0.2.1/32` on its unique disposable adapter and polls the exact
row until its DAD state is `Preferred`, its `/32` and interface/address key are
unchanged, and `SkipAsSource` is false. It then runs the route qualification,
explicitly removes the address, and requires bounded absence before accepting
the route result. Its exact code head passed native AMD64 and ARM64 in
[run 29734712632](https://github.com/aiwaki/slipstream/actions/runs/29734712632),
all required checks and packaged lifecycle in
[run 29734712671](https://github.com/aiwaki/slipstream/actions/runs/29734712671),
and dependency audit in
[run 29734712698](https://github.com/aiwaki/slipstream/actions/runs/29734712698).
Both architectures proved route, address, adapter, and session cleanup.

[PR #193](https://github.com/aiwaki/slipstream/pull/193) adds the first
feature-gated socket-selection effect without adding production networking. Its
IPv4 UDP fixture proves that ordinary route selection points at the competing
Wintun `/32`, then sets `IP_UNICAST_IF` to the retained baseline interface,
reads the same host-order index back, binds the retained baseline source, and
connects without calling a send or receive API. Probe failure still runs the
owned exact-route cleanup and baseline recovery observation before it is
returned. The active-probe entrypoint itself requires the third socket-binding
CI gate; the probe-free exact-route wrapper retains the original two-gate
admission. The exact PR head passed the selected fixture and
all existing packet gates on native AMD64 and ARM64 in
[run 29739433700](https://github.com/aiwaki/slipstream/actions/runs/29739433700),
all required checks and packaged lifecycle in
[run 29739433665](https://github.com/aiwaki/slipstream/actions/runs/29739433665),
and dependency audit in
[run 29739433660](https://github.com/aiwaki/slipstream/actions/runs/29739433660).
Its exact merge commit `b3572863` passed again on native AMD64 and ARM64 in
[run 29741495033](https://github.com/aiwaki/slipstream/actions/runs/29741495033),
all required checks and packaged lifecycle in
[run 29741495030](https://github.com/aiwaki/slipstream/actions/runs/29741495030),
and dependency audit in
[run 29741495046](https://github.com/aiwaki/slipstream/actions/runs/29741495046).

## Next Verified Action

Do not reinstall or re-arm Slipstream on the primary workstation while the user
is away. The downloaded `140598b` app used a superseded Geph artifact and must
not be launched. The exact revisioned `f22e475` packaged app has been downloaded,
signature-verified, and inspected without launching any component. Actual
installation still waits for one short, user-scheduled smoke with preflight and
rollback prepared in advance. No repeated administrator prompts are acceptable.
If the smoke fails, uninstall immediately and preserve the first failing
evidence; do not improvise another install in the same session.

Continue M4 on disposable systems. PRs #193 and #194 proved no-payload IPv4
and IPv6 socket selection under competing exact Wintun routes on exact main,
native AMD64 and ARM64, while removing every owned route, address, session,
and adapter. PR #195's exact main passed one synthetic IPv4 UDP datagram into
the owned capture ring and one synthetic response injected back to the same
socket under one strict deadline on native AMD64 and ARM64. It has no external
endpoint, backend, default route, production host, DNS, proxy, PAC, or VPN
effect. PR #196's exact main passed the equivalent closed IPv6 proof with its
mandatory UDP checksum in the audited runs recorded above. PR #197's exact main
then constrained `GetBestRoute2` to the retained baseline source/LUID while the
owned exact route was active, preserved kernel-selected synthetic VPN evidence,
and exposed field-specific mismatch codes before any active probe. PR #198's
exact main commit `c036fa1cad5bb95439f2ce98ad095267dfdd34a0` passed the bounded
pre-existing IPv4 UDP flow gate on native AMD64 and ARM64 in
[run 29962673071](https://github.com/aiwaki/slipstream/actions/runs/29962673071),
all required checks and packaged lifecycle in
[run 29962673111](https://github.com/aiwaki/slipstream/actions/runs/29962673111),
and dependency audit in
[run 29962673054](https://github.com/aiwaki/slipstream/actions/runs/29962673054).
The gate uses two owned IPv4 Wintun adapters, one owned non-default `/24`
baseline route, and one exact `/32` capture route. A connected UDP socket first
completes a checksum-valid closed baseline round trip. Under activation it must
either keep using that baseline path, or cause the active probe to fail so the
owner removes only the exact route and the same socket completes a bounded
baseline retry. Every acquired route and address reaches explicit verified
cleanup before any result is accepted. This closes only the first IPv4 UDP
subgate; PR #200 below subsequently closes TCP pre-existing-flow activation.
Crash-safe capture removal is closed by PR #202. Explicit external-VPN
coexistence remains a separate gate before any exact-route transaction or
production composition. A partial DNS cache is never treated as complete
attribution.
External DNS, VPN, proxy, PAC, and unrelated PF state remain read-only.

PR #200 is the independent IPv4 TCP pre-existing-flow gate. Its qualified code
head `d384817c7e64d79806c6ac18eab9a6f4803f3092` passed native AMD64 and ARM64
twice in
[run 29965217892](https://github.com/aiwaki/slipstream/actions/runs/29965217892),
all required checks and packaged lifecycle in
[run 29965217886](https://github.com/aiwaki/slipstream/actions/runs/29965217886),
and dependency audit in
[run 29965217897](https://github.com/aiwaki/slipstream/actions/runs/29965217897).
The final PR head repeated the native proof on both architectures before merge.
The exact main commit `8cac5602eaccd992a1f2a5e86bb2510aac789a9a` then passed native AMD64 and
ARM64 in
[run 29966086550](https://github.com/aiwaki/slipstream/actions/runs/29966086550),
all required checks and packaged lifecycle in
[run 29966086559](https://github.com/aiwaki/slipstream/actions/runs/29966086559),
and dependency audit in
[run 29966086558](https://github.com/aiwaki/slipstream/actions/runs/29966086558).
The gate establishes one real Windows TCP stream through the owned baseline Wintun ring,
requires a checksum-valid SYN/SYN-ACK/final-ACK exchange and a payload round
trip before activation, then accepts only baseline continuity or fail-closed
exact-route rollback followed by retransmission recovery. The same stream must
also complete another baseline exchange after route removal. Its first native
revision exposed that `peer_addr()` alone can become observable before Windows
has completed the handshake; the corrected candidate requires the captured
final ACK with exact sequence and acknowledgment numbers before treating the
stream as established. TCP pre-existing-flow activation is now closed. PR #202
subsequently closed bounded crash-safe removal of capture ownership without
inferring external-VPN coexistence from that result.

The current crash-removal candidate keeps the baseline adapter, exact source,
and non-default `/24` in the parent while an exact child process owns the
capture adapter, source, and production-gated `/32`. An atomic marker is
published only from the active probe. The parent independently observes the
active capture identity, terminates only that retained child handle, and then
requires bounded adapter, address, and `/32` absence plus exact baseline route
recovery. It uses no external endpoint, backend, default route, production-host
composition, DNS, proxy, PAC, VPN, broad process kill, or driver mutation.
PR #202 head passed this proof on native AMD64 and ARM64 in
[run 29967959561](https://github.com/aiwaki/slipstream/actions/runs/29967959561),
all required checks and packaged lifecycle in
[run 29967959616](https://github.com/aiwaki/slipstream/actions/runs/29967959616),
and dependency audit in
[run 29967959553](https://github.com/aiwaki/slipstream/actions/runs/29967959553).
The exact merge commit `ebe9f9c70b378f688badf6ba35cd96dd200d0bb4`
repeated native AMD64 and ARM64 qualification in
[run 29968586744](https://github.com/aiwaki/slipstream/actions/runs/29968586744),
all required checks and packaged lifecycle in
[run 29968586745](https://github.com/aiwaki/slipstream/actions/runs/29968586745),
and dependency audit in
[run 29968586782](https://github.com/aiwaki/slipstream/actions/runs/29968586782).
Crash-safe capture removal is closed. External-VPN coexistence is the next
independent native gate.

The current coexistence candidate narrows that next gate to independently
owned route state. An exact child process owns a uniquely named Wintun adapter,
the synthetic VPN-like source `198.18.0.2/32`, and a non-default public `/24`.
The parent owns a separate capture adapter and only the production-gated
destination `/32`. It must prove the child, adapter, address, and broader route
remain unchanged during activation, exact-route recovery, and Slipstream's own
capture cleanup. Ordinary route selection must return to the child-owned source
and interface before the parent releases it; the child then removes only its
own resources. No default route, real VPN endpoint or protocol, external
payload, backend, production-host composition, DNS, proxy, PAC, driver, or
broad process effect is present. Passing native AMD64 and ARM64 will establish
this independent VPN-like route-owner case only; it will not by itself qualify
every physical, full-tunnel, split, or per-app vendor VPN.

## External Gates

- Add `SLIPSTREAM_GEPH_ACCOUNT_SECRET` to the protected
  `geph-qualification` environment, then run the account-backed owned-Geph
  qualification successfully from `main`.
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

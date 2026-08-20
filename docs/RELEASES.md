# Release Policy

Slipstream publishes three distinct kinds of GitHub release. Their tags and
purpose must remain visually and mechanically separate.

| Kind | Tag | GitHub state | Purpose |
|---|---|---|---|
| Stable app | `vX.Y.Z` | Release and latest | Signed updater feed and first installation |
| Preview app | `vX.Y.Z-preview.N` | Pre-release, never latest | Qualified build from `main`; `.23+` discovers later previews in the background |
| Geph dependency | `geph-vendor-X.Y.Z-rN` | Internal pre-release, never latest | Reviewed and attested build input, not an app release |

Preview and internal dependency releases never replace GitHub's latest pointer
or the stable updater feed. Old tags are retained as build history and never
moved; user-facing installation instructions always select the newest
compatible app release.

`v0.1.9-preview.23` is the first preview with signed background discovery of
new preview releases. Existing `.22` installations require one manual `.23`
installation because `.22` reported the stable-looking package version `0.1.9`
and cannot safely compare it with the new prerelease version. From `.23`
onward, discovery may post a native notification, but download, installation
and relaunch require an explicit tray-menu action. The first real `.23 -> .24`
release transition is itself a gate for `.24`: it must prove notification
identity/submission, the bounded signed install, successor health, rollback on
failure, and no Dock tile, window or focus change. Local MockRuntime tests are
updater mechanics evidence only and do not satisfy that future live gate.

The `.23` installer itself is transactional. After signature and bundle
validation, a separately signed non-AppKit watchdog durably records a
same-volume staged app and verified sibling backup before replacement. It
accepts the successor only when exact path, version, process identity, tray
startup, owned daemon, and advancing heartbeat agree. Otherwise it restores
the exact previous bundle. The journal and user LaunchAgent are owner-private,
restart-safe, and removed only after a terminal acknowledgement or recorded
rollback; neither path uses `open` or activates the app.

After a preview is published successfully, the immediately preceding preview
is marked as archival in its release title. Its tag and verified artifacts are
retained unchanged.

## Legacy App Releases

`v0.1.1` through `v0.1.4` predate the current channel policy and the private PF
anchor. They remain immutable, non-prerelease GitHub releases so the legacy
updater endpoint at `releases/latest/download/latest.json` continues to resolve
until a qualified stable release replaces it. GitHub may therefore label
`v0.1.4` as **Latest** even though its title and release notes mark it as an
archival build.

These legacy releases are not used for a new installation. The root README
points new users to the newest non-archival Slipstream preview. Do not delete,
retag, or convert the legacy releases to prereleases merely to change their
presentation: doing so would also change the updater endpoint.

## App Artifacts

| File | Purpose |
|---|---|
| `Slipstream_*.dmg` | Primary first-install format for macOS Apple Silicon |
| `Slipstream-macos-arm64.zip` | Alternative first-install archive |
| `Slipstream.app.tar.gz` | Tauri updater archive |
| `Slipstream.app.tar.gz.sig` | Tauri updater signature |
| `latest.json` | Tauri updater index |
| `artifact-manifest.json` | Target, source commit, byte size, and SHA-256 for every release payload asset |
| `release-candidate-manifest.json` | Exact-main CI run, source Git tree/archive digest, and every immutable candidate file digest |
| `release-qualification.json` | Protected owned-Geph result bound to the exact candidate manifest digest |
| `release-readiness.json` | Protected Safari/Chrome live-origin and measured 30-minute invisibility results bound to the exact candidate and workflow attempt |
| `transport-mechanics.json` | Protected exact-candidate dual-stack listener/PF evidence, Darwin IPv4/IPv6 NATLOOK test-port transaction, and deterministic encrypted QUIC v1/v2 mechanics; it does not claim a live origin's negotiated protocol or address family |
| `Slipstream.spdx.json` | Deterministic SPDX 2.3 inventory for the resolved `aarch64-apple-darwin` graph, pinned runtime locks, and top-level vendored components |
| `dependency-audit.json` | Source-, target-, SBOM-, policy-, and scanner-bound vulnerability audit result |

Stable releases additionally carry the signed route-policy bundle, channel
index, and public trust keys. Preview releases must not contain those assets.

The manifest and SBOM use the source commit timestamp rather than workflow wall
clock time. Release verification rejects missing, empty, unexpected, symlinked,
or modified files before publication. The macOS build target is explicitly
`aarch64-apple-darwin`.

Updater verification is additionally cryptographic and offline. Before
publication, `verify_updater_artifacts.py` verifies the exact updater archive's
minisign signature with the public key from the source-bound Tauri
configuration, confirms that the same key is compiled into the packaged main
executable, and inspects the signed tar without extracting it. The archive must
contain one `Slipstream.app` made only of regular files, directories and safe
relative links that remain inside that app, the expected bundle
identifier and executable, the exact release version in both version fields,
and `LSUIElement=true`. Path traversal, absolute or app-escaping links,
duplicate entries, unsupported types, decompression-size excess, a wrong key,
a replayed signed archive from a different version, or any byte change fail
publication. The verifier emits the archive, signature, configuration,
executable and updater-key hashes in the existing publisher report; no
Cargo/Tauri build or network call is permitted.

## Dependency Audit

Pull requests, `main`, a weekly scheduled run, and every app release scan the
target-specific SPDX inventory with a checksum-pinned OSV Scanner. The reviewed
policy in [`../security/dependency-audit-policy.json`](../security/dependency-audit-policy.json)
records informational advisories, blocks every unreviewed vulnerability, and
allows only exact package/version/advisory exceptions with an expiry date.
Scanner failures and empty inventories fail closed.

OSV Scanner 2.3.8 does not emit an ecosystem for SPDX `pkg:generic` packages.
The application policy therefore has a separate optional integrity-only list:
an incomplete scanner row is accepted only without vulnerabilities and only
when its exact name/version matches one unexpired policy entry and the SBOM has
the same exact generic purl and SHA-256. Reports count scanner-covered and
integrity-only packages separately; their sum must equal the full SBOM. Every
other incomplete row still fails closed. Geph schema-v1 reports contain no
integrity-only section and remain valid.

The published report is part of `artifact-manifest.json`, and release
verification recomputes its SBOM and policy hashes. The application inventory
lists Geph and `tg-ws-proxy` as top-level vendored applications. Geph
additionally has its own reviewed source contract, `Cargo.lock`, full
transitive SPDX inventory, and fail-closed audit in the `geph-vendor-*-r*` release.
The app workflow verifies that exact vendor payload and its attestations before
embedding it, then performs a fresh full-graph scan so newly published
advisories and expired exceptions still block a later app release.
`tg-ws-proxy` remains covered by its separate vendored-source review rather
than a Rust dependency graph.

## Geph Dependency Artifacts

| File | Purpose |
|---|---|
| `geph5-client` | Universal macOS binary built from the reviewed lock |
| `geph5-client.SOURCE.json` | Exact crates.io URL, SHA-256, features, targets, and lock digest |
| `geph5-client.Cargo.lock` | Complete reviewed Rust dependency graph |
| `geph5-client.spdx.json` | Deterministic SPDX 2.3 inventory for both macOS architectures |
| `geph5-client-dependency-audit.json` | Full-coverage, policy-bound vulnerability result |
| `geph5-client.LICENSE` | MPL-2.0 text |
| `SHA256SUMS` | SHA-256 for every Geph dependency asset |

A new upstream Geph crate cannot publish a binary immediately. Automation first
opens a source-contract PR; only the reviewed and merged contract may trigger a
locked build.

## Candidate and publication pipeline

- Required exact-main CI builds the frozen daemon, app, updater archives and
  pinned headless shell once, then assembles and attests one immutable
  `release-candidate-${SHA}`. Packaged lifecycle, browser, and native-update
  notification qualifications consume independent copies of that candidate in
  parallel; none rebuilds it. The candidate is eligible for protected
  qualification only when the entire required CI run, including all three
  consumers, succeeds. Pull requests use an equivalent sealed local-build
  bundle because updater signing secrets are unavailable there.
- JavaScript dependencies are installed with lifecycle scripts disabled and no
  production updater credential. Compilation and bundling use a disposable CI
  updater key. A separate no-checkout, no-repository-code signer job first
  verifies the frozen archive and pinned Tauri CLI tarball digests, then exposes
  the production key only to the signing command. A no-secret assembly job
  binds both GitHub service-artifact digests and reruns the offline updater
  verifier before candidate assembly. OIDC and attestation permissions live in
  another no-checkout, no-shell-command job that downloads the sealed
  candidate; build, signer, and assembly jobs do not inherit them.
- Protected owned-Geph qualification downloads that exact artifact, verifies
  its source commit, Git tree, source-archive digest, CI run ID and file hashes,
  then runs against the unpacked candidate. Its proof is bound to the candidate
  manifest digest; it does not rebuild the app.
- A manual `build-app` run creates the next explicitly validated preview only
  from `main`; for this P0 release the accepted tag is exactly
  `v0.1.9-preview.23`, and publication fails if that tag already exists.
  It verifies the exact successful main-CI, protected owned-Geph, and protected
  release-readiness runs plus their stored attestations, creates only
  `latest.json`, the public artifact manifest and release notes, and publishes
  the unchanged candidate. PyInstaller, Cargo/Tauri build and every
  qualification are prohibited in the publisher.
- The current workflow is preview-only. A pushed `v*` tag stops before checkout
  until Developer ID signing, hardened runtime, notarization, and stapling are
  implemented as a fail-closed stable-channel gate.
- Once that gate exists, a pushed tag exactly matching `v$(cat VERSION)` may
  create a stable release.
- The exact packaged app must pass disposable-CI lifecycle and protected
  account-backed qualification before either channel is published. Production
  browser recovery uses its bundled pinned headless shell, never LaunchServices
  or the user's installed browser. Final live-site Safari/Chrome and idle-soak
  checks run against the exact downloaded candidate artifact.
- Stable publication also requires the reviewed signing and route-policy
  secrets. Developer ID notarization and stapling remain a stable-channel gate.
- Release notes contain a short artifact/channel preface followed by GitHub's
  generated list of merged changes.
- Branch protection retains the exact public contexts `checks` and
  `packaged-app-lifecycle`. Their lightweight aggregators always run: a
  documentation-only change validates continuity, links, and the actual Git
  diff without invoking product builds; Windows jobs run only for Windows or
  shared-adapter paths. Product builds publish one reusable candidate so a
  failed qualification can be retried without rebuilding.

Warm performance targets are six minutes for build plus parallel qualification
without soak, two minutes for promotion of an already qualified candidate, and
three minutes for retrying one failed consumer without rebuilding. Timing is a
measured release gate, not inferred from workflow structure.

## Attestations

After exact-main candidate packaging passes browser and lifecycle verification,
GitHub Actions signs two attestations with its short-lived OIDC identity:

- SLSA provenance covers every file in the verified release payload;
- the SPDX 2.3 inventory is attached to the ZIP, updater archive, and DMG.

Both attestations are stored in GitHub's attestation service. The publisher
verifies them against the exact source commit, the `ci.yml` signer, and a
GitHub-hosted runner before publishing the release. The protected owned-Geph
workflow separately attests `release-qualification.json`; the protected
release-readiness workflow attests its live/soak reports,
`transport-mechanics.json`, and their manifest-bound aggregate proof. The
publisher verifies both protected workflow identities, exact run attempts, and
the exact candidate manifest before publication. A downloaded artifact can
be checked independently:

```bash
gh attestation verify Slipstream-macos-arm64.zip \
  --repo aiwaki/slipstream \
  --signer-workflow aiwaki/slipstream/.github/workflows/ci.yml

gh attestation verify Slipstream-macos-arm64.zip \
  --repo aiwaki/slipstream \
  --signer-workflow aiwaki/slipstream/.github/workflows/ci.yml \
  --predicate-type https://spdx.dev/Document/v2.3
```

Do not repurpose or move an existing release tag. A corrected artifact requires
a new preview tag or a new patch version.

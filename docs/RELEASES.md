# Release Policy

Slipstream publishes three distinct kinds of GitHub release. Their tags and
purpose must remain visually and mechanically separate.

| Kind | Tag | GitHub state | Purpose |
|---|---|---|---|
| Stable app | `vX.Y.Z` | Release and latest | Signed updater feed and first installation |
| Preview app | `vX.Y.Z-preview.N` | Pre-release, never latest | Manual qualification build from `main` |
| Geph dependency | `geph-vendor-X.Y.Z-rN` | Internal pre-release, never latest | Reviewed and attested build input, not an app release |

Preview and internal dependency releases never replace GitHub's latest pointer
or the stable updater feed. Old tags are retained as build history and never
moved; user-facing installation instructions always select the newest
compatible app release.

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
| `Slipstream.spdx.json` | Deterministic SPDX 2.3 inventory for the resolved `aarch64-apple-darwin` graph, pinned runtime locks, and top-level vendored components |
| `dependency-audit.json` | Source-, target-, SBOM-, policy-, and scanner-bound vulnerability audit result |

Stable releases additionally carry the signed route-policy bundle, channel
index, and public trust keys. Preview releases must not contain those assets.

The manifest and SBOM use the source commit timestamp rather than workflow wall
clock time. Release verification rejects missing, empty, unexpected, symlinked,
or modified files before publication. The macOS build target is explicitly
`aarch64-apple-darwin`.

## Dependency Audit

Pull requests, `main`, a weekly scheduled run, and every app release scan the
target-specific SPDX inventory with a checksum-pinned OSV Scanner. The reviewed
policy in [`../security/dependency-audit-policy.json`](../security/dependency-audit-policy.json)
records informational advisories, blocks every unreviewed vulnerability, and
allows only exact package/version/advisory exceptions with an expiry date.
Scanner failures and empty inventories fail closed.

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

## Publication

- A manual `build-app` run creates a uniquely numbered preview only from
  `main`; dispatches from tags or other branches stop before building.
- The current workflow is preview-only. A pushed `v*` tag stops before checkout
  until Developer ID signing, hardened runtime, notarization, and stapling are
  implemented as a fail-closed stable-channel gate.
- Once that gate exists, a pushed tag exactly matching `v$(cat VERSION)` may
  create a stable release.
- The exact packaged app must pass disposable-CI lifecycle qualification before
  either channel is published.
- Stable publication also requires the reviewed signing and route-policy
  secrets. Developer ID notarization and stapling remain a stable-channel gate.
- Release notes contain a short artifact/channel preface followed by GitHub's
  generated list of merged changes.

## Attestations

After the release payload passes manifest and lifecycle verification, GitHub
Actions signs two attestations with its short-lived OIDC identity:

- SLSA provenance covers every file in the verified release payload;
- the SPDX 2.3 inventory is attached to the ZIP, updater archive, and DMG.

Both attestations are stored in GitHub's attestation service. The workflow
verifies them against the exact source commit, the `build-app.yml` signer, and a
GitHub-hosted runner before publishing the release. A downloaded artifact can
be checked independently:

```bash
gh attestation verify Slipstream-macos-arm64.zip \
  --repo aiwaki/slipstream \
  --signer-workflow aiwaki/slipstream/.github/workflows/build-app.yml

gh attestation verify Slipstream-macos-arm64.zip \
  --repo aiwaki/slipstream \
  --signer-workflow aiwaki/slipstream/.github/workflows/build-app.yml \
  --predicate-type https://spdx.dev/Document/v2.3
```

Do not repurpose or move an existing release tag. A corrected artifact requires
a new preview tag or a new patch version.

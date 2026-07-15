# Release Policy

Slipstream publishes three distinct kinds of GitHub release. Their tags and
purpose must remain visually and mechanically separate.

| Kind | Tag | GitHub state | Purpose |
|---|---|---|---|
| Stable app | `vX.Y.Z` | Release and latest | Signed updater feed and first installation |
| Preview app | `vX.Y.Z-preview.N` | Pre-release, never latest | Manual qualification build from `main` |
| Geph dependency | `geph-vendor-X.Y.Z` | Internal pre-release, never latest | Verified build input, not an app release |

Preview and internal dependency releases never replace GitHub's latest pointer
or the stable updater feed. Old tags are retained as build history and never
moved; user-facing installation instructions always select the newest
compatible app release.

## App Artifacts

| File | Purpose |
|---|---|
| `Slipstream-macos-arm64.zip` | First installation on macOS Apple Silicon |
| `Slipstream_*.dmg` | Optional disk image |
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
verification recomputes its SBOM and policy hashes. The current inventory lists
Geph and `tg-ws-proxy` as top-level vendored applications; their transitive
dependency graphs require separate vendor-build SBOMs and are not yet claimed
as covered by the app audit.

## Publication

- A manual `build-app` run creates a uniquely numbered preview only from
  `main`; dispatches from tags or other branches stop before building.
- A pushed tag exactly matching `v$(cat VERSION)` creates a stable release.
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

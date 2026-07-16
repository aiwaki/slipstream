# Vendored geph5-client

Slipstream embeds the headless `geph5-client` for routes that require a foreign
exit. The vendored source identity is reviewable and reproducible:

- `VERSION` records the crates.io version;
- `SOURCE.json` records the canonical `.crate` URL, SHA-256, build features,
  targets, lock digest, and immutable release revision;
- `Cargo.lock` freezes the complete Rust dependency graph;
- `LICENSE` is the redistributed MPL-2.0 text.

`.github/workflows/build-geph.yml` is deliberately two-phase. A newly published
crate first opens a PR containing only the updated source contract and lock. No
binary is built until normal review and required checks merge that PR. A later
run downloads the exact archive, replaces its packaged lock with the reviewed
one, builds both macOS architectures with `--locked`, and publishes the
universal binary as `geph-vendor-<version>-r<revision>`. A new revision is
required if build inputs or policy change; an existing tag is never replaced.

Each internal dependency release contains the binary, source contract, lock,
license, SHA-256 manifest, full transitive SPDX 2.3 inventory, and a fail-closed
OSV audit. GitHub attestations bind the payload and SBOM to the exact
`build-geph.yml` run. The app workflow verifies all of these before embedding
the binary.

The reviewed `0.3.0` source currently emits an upstream deprecation warning for
`aws_config::BehaviorVersion::v2025_08_07`. Slipstream does not patch the
redistributed crate silently; the next source update should confirm that Geph
has moved to the newer AWS behavior version.

The daemon supervises only Slipstream's owned copy. Geph remains limited to
geo-exit routes; local bypass groups such as Discord and YouTube never use it.

## tg-ws-proxy

`Flowseal/tg-ws-proxy` is Python and is vendored directly into the daemon under
`vendor/tg-ws-proxy`. It has a separate update and license path.

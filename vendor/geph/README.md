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

Revisions 3 and 4 of `0.3.9` carry explicit `source_edits` in `SOURCE.json`.
Each edit binds the complete input and output file SHA-256 and exactly one
literal replacement; extraction fails on drift. The contract shipped with the
release contains both the correction and its regression test, so no unpublished
patch is needed to reproduce the source. Unedited older contracts remain valid.

The correction isolates a ten-second destination tunnel-open timeout from the
shared multiplexed session. Upstream otherwise signals `early_dead`, dropping
existing tunnels with the failed new request. Actual mux death, read errors and
protocol errors retain upstream handling. The offline two-stream regression
fails on unmodified0.3.9 and requires the existing stream to remain usable after
the new tunnel times out. The vendor build runs library tests before packaging.

Revision 4 additionally opens one reserve tunnel on a distinct live session
when the preferred opening stalls for350ms or fails. Both attempts share the
original ten-second deadline; the first success wins. A failed reserve does
not cancel a still-pending primary. Cancellation drains opening accounting and
drops only the losing stream, preserving other streams on the shared session.
The library regressions cover both race directions with real PicoMux peers.
Consumers must remove outer SOCKS opening hedges when adopting this revision.

The daemon supervises only Slipstream's owned copy. Geph remains limited to
geo-exit routes; local bypass groups such as Discord and YouTube never use it.

## tg-ws-proxy

`Flowseal/tg-ws-proxy` is Python and is vendored directly into the daemon under
`vendor/tg-ws-proxy`. It has a separate update and license path.

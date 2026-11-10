# Third-Party Notices

Slipstream bundles or redistributes the following components. Their licenses
apply to those components independently of Slipstream's MIT license.

## geph5-client

- Project: <https://github.com/geph-official/geph5>
- Crate: <https://crates.io/crates/geph5-client>
- License: Mozilla Public License 2.0
- Distribution: headless client built by Slipstream CI with reviewed source patches

Release artifacts include the MPL-2.0 text, a reference to the canonical
crates.io archive and its SHA-256, reviewed `Cargo.lock`, full transitive SPDX
inventory, vulnerability audit, SHA-256 manifest, and GitHub provenance/SBOM
attestations next to the binary. The reviewed source contract is stored in
[`vendor/geph/SOURCE.json`](vendor/geph/SOURCE.json).

The source contract includes an exact local copy of the SQLx SQLite driver
0.8.6 (MIT OR Apache-2.0). Its Rust source is unchanged; its manifest selects
the fixed official `libsqlite3-sys` 0.39.1 package and bundled SQLite 3.54.1.
Both original SQLx license texts and the upstream archive are retained in the
source/review evidence. SQLite's original public-domain notice remains in the
official wrapper archive. The release SPDX inventory records both components.

## Chromium headless shell

- Project: <https://www.chromium.org/>
- Distribution: pinned Chrome for Testing `chrome-headless-shell` for macOS arm64
- Vendored contract: [`vendor/chromium-headless-shell/SOURCE.json`](vendor/chromium-headless-shell/SOURCE.json)

The build downloads the immutable upstream archive, verifies its reviewed
SHA-256 before extraction, bundles the upstream `LICENSE.headless_shell` and
`ABOUT` files, and records the archive plus executable digests in the packaged
runtime manifest. It is reserved for Slipstream's bounded local invisible
browser probe; that production broker remains disabled until the packaged,
live-site, and idle-soak gates pass. The user's installed browser is not
redistributed or launched by this runtime.

## tg-ws-proxy

- Project: <https://github.com/Flowseal/tg-ws-proxy>
- License: MIT
- Vendored license: [`vendor/tg-ws-proxy/LICENSE`](vendor/tg-ws-proxy/LICENSE)
- Upstream source and local changes: [`SOURCE.json`](vendor/tg-ws-proxy/SOURCE.json),
  [`LOCAL_CHANGES.md`](vendor/tg-ws-proxy/LOCAL_CHANGES.md). The upstream input is
  version 1.11.2; Slipstream retains local transport lifecycle fixes.

# Vendored geph5-client

Slipstream embeds geph **without making the user install it separately**. We do
not reimplement geph (it is a whole obfuscated overlay network — broker, exits,
Mizaru auth, mutating obfuscation — not a trick you can port) and we do not ship
a pre-built blob that rots. Instead:

1. `.github/workflows/build-geph.yml` compiles the headless `geph5-client` from
   the MPL-2.0 source (`geph-official/geph5`, crate `geph5-client`) in CI — which
   has Rust + network. macOS builds are universal (arm64 + x86_64).
2. It publishes the binary as a GitHub Release asset `geph-vendor-<tag>` and
   records the built version in `VERSION` here.
3. The app-build workflow drops that binary into
   `Slipstream.app/Contents/Resources/geph5-client`.
4. A daily scheduled run watches geph upstream for a new `geph5-client-v*` tag and
   rebuilds. New geph version → CI rebuild → Slipstream release → the app's own
   auto-update delivers it. **Tracking upstream is automatic; nothing is installed
   by hand.**

The daemon spawns + supervises this binary in SOCKS mode (login + exit come from
Slipstream's tray UI, stored in the Keychain) and routes only geo-blocked hosts
through it; Russian services are split-tunnel-excluded. See `spike/tproxy.py`.

`VERSION` holds the currently-vendored upstream tag (empty = build on next run).

## tg-ws-proxy is different

`Flowseal/tg-ws-proxy` is **already Python** (a local MTProto proxy). It is
vendored as a Python module into the daemon directly — no binary, no rewrite —
and a separate watcher bumps the pinned copy. Same "CI tracks upstream" idea,
without a compile step.

## License

geph5-client is MPL-2.0. Bundling the unmodified binary inside the MIT Slipstream
app is permitted; we ship geph's LICENSE next to the binary and link the source.

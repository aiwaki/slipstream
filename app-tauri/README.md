# Slipstream tray (Tauri v2)

Cross-platform menu-bar app over the root daemon. Replaces the macOS-only Swift
app (`../app/`, archived). Chosen over Swift+Sparkle because Tauri bundles the
three things we need: **system tray**, a **first-party signed auto-updater**, and
**sidecar** binary embedding (`geph5-client`) — from one codebase for
mac/win/linux.

The engine stays Python (`../spike/tproxy.py`, root LaunchDaemon). This is only
the unprivileged UI: it reads `/var/run/slipstream.status`, controls the daemon
via `launchctl` (one admin prompt), runs the bundled geph as a sidecar, and
auto-updates the whole bundle.

## Layout

- `src/` — tiny frontend (settings window only: geph login + exit). Tray itself
  is built in Rust, no window needed.
- `src-tauri/src/main.rs` — tray, status poll (2s), menu, updater, geph sidecar.
- `src-tauri/tauri.conf.json` — bundle, `externalBin` (geph sidecar), updater.
- `src-tauri/binaries/` — CI drops `geph5-client-<target-triple>` here (built by
  `.github/workflows/build-geph.yml`). Empty in the repo.
- `src-tauri/icons/` — app `.icns` + menu-bar mark PNGs (run `./make-icons.sh`).

## Build (needs the Rust + Node toolchain — not available in the dev sandbox)

```bash
cd app-tauri
./make-icons.sh                 # SVG -> tray PNGs + app .icns (AppKit, macOS)
npm install
npm run tauri build             # -> src-tauri/target/release/bundle/{macos,dmg}/
```

`npm run tauri dev` for a live tray during development.

> Authored without a local compiler; the first `cargo build` may surface minor
> Tauri-v2 API touch-ups (handle/state generics, plugin init names). The
> structure + control flow are the deliverable.

## Auto-updater keys

```bash
npm run tauri signer generate -- -w ~/.slipstream/updater.key   # keypair
```

Put the **public** key in `tauri.conf.json` `plugins.updater.pubkey`; keep the
private key in CI secrets (`TAURI_SIGNING_PRIVATE_KEY`). The release workflow
signs the bundle and publishes `latest.json` (the appcast) the app polls.

## geph sidecar

`geph5-client` runs **unprivileged** (a local SOCKS5 proxy needs no root), so it
fits a Tauri sidecar cleanly: this app starts/supervises it with a config built
from the saved login/exit, and the root daemon just routes geo-blocked hosts to
its local port. Wiring lands once CI produces the first `geph5-client` binary.

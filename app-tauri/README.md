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

- `src/` — inert Tauri frontend placeholder. No WebView window is opened; the UI
  is a native Rust tray/menu plus native dialogs.
- `src-tauri/src/main.rs` — tray, status poll (2s), menu, updater, geph sidecar.
- `src-tauri/tauri.conf.json` — bundle, `externalBin` (geph sidecar), updater.
- `src-tauri/binaries/` — CI drops `geph5-client-<target-triple>` here (built by
  `.github/workflows/build-geph.yml`). Empty in the repo.
- `src-tauri/icons/` — app `.icns` + menu-bar mark PNGs (run `./make-icons.sh`).

## Build (needs Rust, Node, Python 3, and Xcode command-line tools)

```bash
cd app-tauri
./make-icons.sh                 # SVG -> tray PNGs + app .icns (AppKit, macOS)
npm ci
npm run build:local             # -> src-tauri/target/release/bundle/{macos,dmg}/
```

`npm run tauri dev` for a live tray during development. `npm run build:local`
uses `src-tauri/tauri.local.conf.json` and skips updater artifact signing.
`npm run build` is the release path and requires `TAURI_SIGNING_PRIVATE_KEY`.

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
its local port. The supervisor adopts an already-running bundled geph process
when the tray restarts, so live tunnel connections do not churn during updates.

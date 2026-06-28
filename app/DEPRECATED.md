# DEPRECATED — superseded by `../app-tauri/`

This macOS-only Swift/AppKit tray was the first cut. The desktop UI moved to
**Tauri v2** (`../app-tauri/`) because it bundles, from one cross-platform
codebase, the three things we need: system tray, a first-party signed
auto-updater, and sidecar embedding for `geph5-client`.

The Tauri app is verified building + running. This directory is kept only so the
currently-installed Swift `.app` keeps working until the Tauri build is bundled
and installed; it is safe to delete (source remains in git history).

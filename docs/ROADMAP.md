# Roadmap

Roadmap is informational. It describes the current implementation order; it is
not a release promise.

## Current State

| Area | Status |
|---|---|
| macOS Apple Silicon app | early build |
| Tauri tray UI | implemented |
| Root routing daemon | implemented for macOS |
| Local DPI bypass | implemented for current macOS daemon |
| Geph sidecar | implemented for selected geo-blocked hosts |
| Telegram Desktop proxy offer | implemented |
| Single version source | implemented |
| Rotating support logs | implemented |
| Voice-flow TTL/LRU cleanup | implemented |
| QUIC handling | preserved by default; no global UDP/443 block |
| Wake/network re-arm | implemented: pf, voice capture, and route-health canaries are re-armed |
| Daemon watchdog / stale `pf` recovery | implemented in tray: kickstart daemon first, reset `pf` only if recovery fails |
| Bundled daemon install hygiene | implemented: app checks bundled daemon format; daemon uses temp-copy/swap during install |
| Periodic route canaries | implemented for local-bypass, Geph, and Telegram proxy readiness |
| Runtime local-bypass recheck | implemented: full strategy failure clears local cache and schedules a canary recheck |
| Explicit route policy tables | implemented for static direct/local-bypass/geo-exit policy and attempt limits |
| Route policy metadata | implemented in daemon status and copied diagnostic snapshots |
| Signed policy bundle validation | implemented as validator/verifier, local persist/rollback, and explicit opt-in remote fetch scheduler with health gates |
| Detailed route diagnostics | implemented in daemon status, tray summary, and copied diagnostic snapshot |
| Throughput canary | partial: local-bypass canaries verify HTTPS response bytes |
| Signed auto-update | implemented |
| Apple notarization | not implemented |
| Windows | not implemented |
| Linux | not implemented |
| iOS | not implemented |
| Android | not implemented |

## Routing Model

Slipstream has two separate routing tools.

Local bypass is used for DPI/SNI interference. Discord and YouTube/googlevideo
stay on the normal network route and use local desync/fake strategies.

Geph is used only for hosts that require a foreign exit because the service
itself rejects Russian IP addresses. It is not the default answer for Discord,
YouTube, or other local-bypass hosts.

## P0 - macOS Release Hardening

Goal: keep the current macOS build safe to install, run, diagnose, and update.

- Keep install/reinstall idempotent across app relaunches.
- Keep bundled daemon resources and installed daemon in sync.
- Make log access reliable from the tray.
- Keep release versioning and appcast metadata consistent.

## P1 - Routing Quality

Goal: detect degradation before the user has to diagnose it manually.

- Continue tuning automatic re-sweep when a known strategy stops working.
- Broaden local-bypass canaries from small HTTPS payload checks to throughput
  thresholds where that is safe.
- Signed strategy-list/policy updates without rebuilding the app; the local
  verifier, rollback path, and opt-in health-gated remote fetch scheduler are
  in place.
- Move the bundled policy metadata/hash into signed policy updates and
  OS-specific adapters.

## P2 - Desktop Portability

Goal: prepare Windows and Linux without changing the product model.

- Split the daemon into shared routing policy and OS-specific adapters.
- Build and publish `geph5-client` artifacts for Windows and Linux.
- Windows adapter: service install, route/filter layer, local DPI bypass backend,
  tray integration.
- Linux adapter: systemd service, route/filter layer, local DPI bypass backend,
  tray integration.
- Keep Geph, Telegram proxy, route policy, and UI concepts consistent across
  desktop platforms.

## P3 - Mobile

Goal: define mobile as a separate platform track, not a direct port of the macOS
daemon.

- iOS: Network Extension-based design, entitlement and signing requirements,
  split-routing constraints.
- Android: `VpnService`-based design, split-routing policy, background
  lifecycle.
- Decide which features are feasible on mobile: Geph routing, Telegram proxy,
  local DPI bypass, diagnostics.
- Build mobile-specific UX around system VPN/profile constraints.

## Out Of Scope For Now

- Full Apple notarization and Developer ID distribution.
- Relay/VPN fallback for full IP null-route cases.
- Rewriting the current daemon in Rust.
- App Store distribution.

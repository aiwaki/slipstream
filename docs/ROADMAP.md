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
| Geph sidecar | implemented for macOS build |
| Telegram Desktop proxy offer | implemented |
| Single version source | implemented |
| Rotating support logs | implemented |
| Voice-flow TTL/LRU cleanup | implemented |
| Scoped QUIC handling | implemented |
| Wake/network recheck canary | implemented |
| Signed auto-update | implemented |
| Apple notarization | not implemented |
| Windows | not implemented |
| Linux | not implemented |
| iOS | not implemented |
| Android | not implemented |

## P0 — macOS Release Hardening

Goal: make the current macOS build safer to install, run, diagnose, and update.

- Watchdog or recovery path for stale `pf` state if the daemon is killed and does
  not restart.

## P1 — Routing Quality

Goal: detect degradation before the user has to diagnose it manually.

- Periodic canary checks for key routes.
- Throughput canary for throttling, not only handshake failure.
- Automatic re-sweep when a known strategy stops working.
- More detailed status: current route, strategy, Geph state, canary result.
- Signed strategy-list updates without rebuilding the app.

## P2 — Desktop Portability

Goal: prepare Windows and Linux without changing the product model.

- Split the daemon into shared routing logic and OS-specific adapters.
- Build and publish `geph5-client` artifacts for Windows and Linux.
- Windows adapter: service install, route/filter layer, local DPI bypass backend,
  tray integration.
- Linux adapter: systemd service, route/filter layer, local DPI bypass backend,
  tray integration.
- Keep Geph, Telegram proxy, route policy, and UI concepts consistent across
  desktop platforms.

## P3 — Mobile

Goal: define mobile as a separate platform track, not a direct port of the macOS
daemon.

- iOS: Network Extension-based design, entitlement and signing requirements,
  split-routing constraints.
- Android: `VpnService`-based design, split-routing policy, background lifecycle.
- Decide which features are feasible on mobile: Geph routing, Telegram proxy,
  local DPI bypass, diagnostics.
- Build mobile-specific UX around system VPN/profile constraints.

## Out Of Scope For Now

- Full Apple notarization and Developer ID distribution.
- Relay/VPN fallback for full IP null-route cases.
- Rewriting the current daemon in Rust.
- App Store distribution.

# Slipstream

<div align="center">

[Русский](README.md) · **English**

[![preview](https://img.shields.io/badge/preview-macOS%20Apple%20Silicon-000000?logo=apple)](#install)
[![ci](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

<div align="center">

## Next preview: install Slipstream — sites work

**Fast. Automatic. Invisible.**

[Download the current macOS Apple Silicon preview](https://github.com/aiwaki/slipstream/releases)

</div>

Slipstream is a split-routing app for networks affected by blocking and DPI
filtering. It selects a route for each service instead of enabling a system-wide
VPN for all traffic.

The intended user flow is simple: install the app, approve its background
service once, then open sites in an ordinary browser. Local bypass does not need
a Chrome extension, a Slipstream account, or a cloud server.

## For users

### Routes

| Route | Purpose |
|---|---|
| Direct | Services that do not need bypassing. |
| Local bypass | DPI blocking without changing the external IP. |
| Foreign exit | Explicitly reviewed services that reject Russian IPs; through the bundled Geph client. |
| Telegram | A local proxy offered when a direct connection is unavailable. |

Discord and YouTube use local bypass and are never routed through Geph. For an
unknown host, Slipstream first checks the system route, its app-owned DNS
fallback, and multiple local strategies. A temporary foreign route is allowed
only for one exact host after independent failure confirmation; it never
becomes a general VPN fallback.

### What happens automatically

- The background service starts with macOS, survives the menu-bar app closing or
  restarting, and recovers from routine process failures.
- After sleep or a Wi-Fi/Ethernet change, Slipstream rechecks the interface, its
  private rules, and route availability.
- When a reviewed foreign-exit site attempts HTTP/3, only that flow is moved to
  the same managed TCP route through bundled Geph. Other QUIC/UDP traffic is not
  blocked.
- The next candidate includes a pinned local headless engine that checks rare
  ambiguous failures only for one exact host and only after a foreground Safari
  or Chrome navigation is verified. Known and healthy routes never start it;
  the candidate can be published only after packaged, live-site, and measured
  30-minute invisibility gates. It needs no installed Chrome, extension, or
  Chrome Web Store registration, opens no window, and sends no paths, cookies,
  or page content elsewhere.
- With a full-tunnel VPN or another transparent filter active, Slipstream safely
  pauses its own interception and returns after the conflict disappears.
  External DNS, proxy, PAC, and VPN settings are detected but never changed.
- The menu reports routing, Geph, and Telegram state; it can restart the service,
  copy redacted diagnostics, check for updates, and completely remove components
  owned by Slipstream.

### Install

Available build: macOS Apple Silicon.

1. In [Releases](https://github.com/aiwaki/slipstream/releases), select the newest `Slipstream` release marked **Pre-release** and download `Slipstream_*.dmg`.
2. Open the disk image and move `Slipstream.app` to Applications.
3. Launch Slipstream and approve installation of the background service.

The ZIP archive in the same release remains available as an alternative format.

The Geph account and exit are configured from the menu only for foreign-exit
routes. The Telegram proxy offer appears automatically.

After installation, keep the app in the menu bar. Routing survives a tray-app
restart, but the menu provides visible state, Geph settings, diagnostics, and
updates.

> [!NOTE]
> Preview builds are not notarized by Apple. If macOS blocks the app, it can be
> opened from the **Open** item in the context menu.

The order for other platforms is tracked in
[`docs/ROADMAP.md`](docs/ROADMAP.md). Repeated symptoms and checks are collected
in [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

## For developers

Slipstream consists of a Tauri tray app, a Python background service, bundled
sidecars, and shared JSON contracts. There is no public CLI or API yet; the
testable cross-platform surface lives in `contracts/`.

- [Setup and build](DEVELOPMENT.md#setup)
- [Safe local checks without root](DEVELOPMENT.md#safe-local-checks)
- [Privileged checks on disposable CI only](DEVELOPMENT.md#privileged-qualification)
- [Architecture and component boundaries](docs/ARCHITECTURE.md)
- [Engineering documentation map](docs/README.md)
- [Routing and recovery contracts](contracts/README.md)
- [Contributing](CONTRIBUTING.md)
- [Report a vulnerability](SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

## Privacy and licenses

Routing decisions, rare browser observations, and diagnostics run locally. Only
traffic explicitly assigned to, or strictly confirmed for, an exact foreign
route passes through the Geph network; direct and local routes do not use Geph.
Logs and diagnostic exports are bounded and redact URLs, cookies, account
secrets, and page content.

- **Slipstream** — [MIT](LICENSE).
- **geph5-client** — MPL-2.0, © [Geph](https://geph.io).
- **tg-ws-proxy** — MIT, © [Flowseal](https://github.com/Flowseal/tg-ws-proxy).

Details: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

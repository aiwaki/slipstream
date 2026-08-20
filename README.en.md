# Slipstream

<div align="center">

<img src="app-tauri/src-tauri/icons/128x128@2x.png" width="128" height="128" alt="Slipstream app icon">

[Русский](README.md) · **English**

[![preview](https://img.shields.io/badge/preview-macOS%20Apple%20Silicon-000000?logo=apple)](#install)
[![ci](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

<div align="center">

## Slipstream 0.1.9-preview.23: install Slipstream — sites just work

**Fast. Automatic. Unobtrusive.**

**The next macOS Apple Silicon preview is undergoing final checks.**

[Available preview releases](https://github.com/aiwaki/slipstream/releases)

</div>

Slipstream is a selective-routing app for networks affected by blocking and DPI
filtering. It chooses a route for each service instead of enabling a system-wide
VPN for all traffic.

The intended user flow is simple: install the app, approve its background
service once, then open sites in an ordinary browser. Local bypass does not
require a Chrome extension, a Slipstream account, or a cloud server.

## For users

### Routes

| Route | Purpose |
|---|---|
| Direct | Services that do not need bypassing. |
| Local bypass | DPI-based blocking without changing your public IP address. |
| Foreign exit | Explicitly reviewed services that block connections from Russian IP addresses, routed through the bundled Geph client. |
| Telegram | A local proxy offered when a direct connection is unavailable. |

Discord and YouTube use local bypass and are never routed through Geph. For an
unknown host, Slipstream first checks the system route, the app's built-in DNS
fallback, and multiple local strategies. A temporary foreign route is allowed
only for a single exact hostname after independent checks confirm the failure;
it never becomes a general VPN fallback.

### What happens automatically

- The background service starts with macOS, keeps running when the menu bar app
  closes or restarts, and recovers from routine process failures.
- After sleep or a Wi-Fi/Ethernet change, Slipstream rechecks the interface, its
  private routing rules, and route availability.
- If the browser attempts HTTP/3 for a reviewed foreign-exit site, Slipstream
  moves only that flow onto the same managed TCP route through the bundled Geph
  client. Other QUIC/UDP traffic is not blocked.
- Starting with `0.1.9-preview.23`, a pinned local headless engine checks rare
  ambiguous failures for a single exact hostname, and only after confirming an
  active tab in Safari or Chrome. It stays off for known, healthy routes. A
  candidate is published only after packaged-app and live-site checks plus a
  measured 30-minute check for visible UI or focus changes. The engine runs
  without an installed copy of Chrome, a browser extension, or Chrome Web Store
  setup; it never opens a window or sends URL paths, cookies, or page content
  off the device.
- With a full-tunnel VPN or another transparent filter active, Slipstream safely
  pauses its own interception and resumes automatically once the conflict is
  gone.
  External DNS, proxy, PAC, and VPN settings are detected but never changed.
- The menu reports routing, Geph, and Telegram state; it can restart the service,
  copy redacted diagnostics, check for updates, and remove all Slipstream-owned
  components.
- Starting with `0.1.9-preview.23`, Slipstream checks its signed update channel
  automatically and shows a native macOS notification when a new version is
  available. The update installs only when you choose it from the menu; the
  current app is backed up locally and restored if the updated app fails its
  health check.

### Install

Available for: macOS on Apple silicon.

1. In [Releases](https://github.com/aiwaki/slipstream/releases), select the newest `Slipstream` release marked **Pre-release** and download `Slipstream_*.dmg`.
2. Open the disk image and drag `Slipstream.app` to the Applications folder.
3. Launch Slipstream and approve installation of the background service.

The same release also includes a ZIP archive.

A Geph account and exit location are needed only for foreign-exit routes and can
be configured from the menu. Slipstream offers the Telegram proxy automatically
when needed.

After installation, leave Slipstream running in the menu bar. The network route
stays active while the menu-bar app restarts, but the menu shows status, Geph
settings, diagnostics, and updates.

> [!NOTE]
> Preview builds are not notarized by Apple. If macOS blocks the app,
> Control-click it in Finder and choose **Open**.

Plans for other platforms are tracked in
[`docs/ROADMAP.md`](docs/ROADMAP.md). Troubleshooting for recurring symptoms is
available in [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

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

Routing decisions, rare browser checks, and diagnostics run locally. Only
traffic assigned to a reviewed foreign route—or to a strictly confirmed
exact-host fallback—passes through the Geph network; direct and local routes
never use Geph. Logs and diagnostic exports have strict size limits and redact
URLs, cookies, account secrets, and page content.

- **Slipstream** — [MIT](LICENSE).
- **geph5-client** — MPL-2.0, © [Geph](https://geph.io).
- **tg-ws-proxy** — MIT, © [Flowseal](https://github.com/Flowseal/tg-ws-proxy).

Details: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

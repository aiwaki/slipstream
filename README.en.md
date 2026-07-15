# Slipstream

<div align="center">

[Русский](README.md) · **English**

[![preview](https://img.shields.io/badge/preview-macOS%20Apple%20Silicon-000000?logo=apple)](#install)
[![ci](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

Slipstream is a split-routing app for networks affected by blocking and DPI
filtering. It selects a route for each service instead of enabling a system-wide
VPN for all traffic.

## For users

### Routes

| Route | Purpose |
|---|---|
| Direct | Services that do not need bypassing. |
| Local bypass | DPI blocking without changing the external IP. |
| Foreign exit | Explicitly reviewed services that reject Russian IPs; through the bundled Geph client. |
| Telegram | A local proxy offered when a direct connection is unavailable. |

Discord and YouTube use local bypass and are never routed through Geph. Unknown
hosts are not promoted to a foreign exit automatically. External DNS, proxy,
PAC, and VPN settings are detected but never changed.

### Install

Available build: macOS Apple Silicon.

1. In [Releases](https://github.com/aiwaki/slipstream/releases), select the newest `Slipstream` release marked **Pre-release** and download `Slipstream-macos-arm64.zip`.
2. Extract the archive and move `Slipstream.app` to Applications.
3. Launch Slipstream and approve installation of the background service.

The Geph account and exit are configured from the menu only for foreign-exit
routes. The Telegram proxy offer appears automatically.

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

Routing decisions and diagnostics run locally. Only traffic explicitly assigned
to foreign-exit routes passes through the Geph network; direct and local routes
do not use Geph.

- **Slipstream** — [MIT](LICENSE).
- **geph5-client** — MPL-2.0, © [Geph](https://geph.io).
- **tg-ws-proxy** — MIT, © [Flowseal](https://github.com/Flowseal/tg-ws-proxy).

Details: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

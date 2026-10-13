# Slipstream

<div align="center">

<img src="app-tauri/src-tauri/icons/128x128@2x.png" width="96" height="96" alt="Slipstream app icon">

**Bypass network blocks on your Mac, in browsers and apps.**

**[Download for Mac](https://github.com/aiwaki/slipstream/releases)** · [Installation](#installation) · [Русский](README.md)

**macOS 13+ · Apple silicon (M1 and later) · Free · Open source · Preview**

[![ci](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

Slipstream helps you open blocked websites and connect to services in your usual
browsers and apps. It runs from the menu bar and selects a connection method for
each service. Local bypass requires no account, separate server, or browser
extension.

> [!NOTE]
> Slipstream is a preview. Results depend on your provider and the blocking
> method: pages, video, and calls may still fail. Access to every website is not
> guaranteed. Fixes in the repository may not yet be in the downloadable build.
> See the [development status](docs/ROADMAP.md#development-status).

## What it does

- **YouTube and Discord:** local bypass of DPI, the connection filtering used by
  internet providers. Your public IP address stays the same. This traffic is
  never routed through Geph.
- **Websites with country restrictions:** the bundled Geph client provides an IP
  address abroad for supported routes. This requires a Geph account.
- **Telegram:** a local proxy the app offers to configure when a direct connection
  is unavailable.
- **Other websites:** a direct connection when no bypass is needed.

## Installation

You need a Mac with **Apple silicon (M1 or later)** and **macOS 13 or later**.

1. Open [Releases](https://github.com/aiwaki/slipstream/releases), choose the latest **Slipstream** release (currently a preview), and download the **`.dmg`** file for your Mac under Assets.
2. Open the DMG and drag **Slipstream.app** into **Applications**.
3. Launch it from Applications and approve installation of the background service.
4. Open the website or app you need. Connection status and settings are available from the Slipstream menu bar icon.

The same release includes a ZIP archive if you prefer that format.
The [releases page](https://github.com/aiwaki/slipstream/releases) also includes internal
Geph builds: choose **Slipstream**, not **Internal dependency**, to install the app.

The preview build is not notarized by Apple. If macOS blocks it, allow it to open
in **System Settings → Privacy & Security**, then launch it again.

For supported websites that need an IP address in another country, configure a
Geph account in the Slipstream menu. A separate Geph app is not required, and
you do not need to configure a VPN for local bypass.

## If something won't load

Check the service status in the Slipstream menu. You can also restart the service
and copy redacted diagnostics there. When reporting a failure, include the website
or app, browser, approximate time, and what failed: the page, images, video, or a call.

[Troubleshooting](docs/TROUBLESHOOTING.md) ·
[Report an issue](https://github.com/aiwaki/slipstream/issues)

<details>
<summary>Routing and privacy</summary>

Slipstream is not designed to anonymize all internet traffic. When it conflicts
with a full-tunnel VPN, it pauses its own traffic interception. It does not change
external DNS, proxy, PAC, or VPN settings. See the [routing policy](docs/DECISIONS.md)
for details.

Slipstream uses Tauri and a Python background service. Routing decisions run
locally; only traffic assigned to foreign routes passes through Geph.

An unknown website may also receive a temporary Geph route for its exact
hostname. This requires independent failures of the direct connection, built-in
DNS, and multiple local bypass methods, followed by a successful payload check
through the bundled Geph client. This exception never applies to YouTube or
Discord.

Diagnostic exports redact URLs, cookies, account secrets, and page content.

</details>

## Project plans

We plan to support **Windows and Android**; **iOS and Linux** are under
consideration. No dates have been announced. See the [roadmap](docs/ROADMAP.md)
for details.

We are testing fixes for incomplete page loads and connection recovery in
separate PRs, along with an update to the Telegram proxy. These changes are not
yet in the downloadable build. [Work in progress and release blockers](docs/ROADMAP.md#development-status).

[Build from source](DEVELOPMENT.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Documentation](docs/README.md) · [Contributing](CONTRIBUTING.md) ·
[Report a vulnerability](SECURITY.md) · [Routing contracts](contracts/README.md)

Slipstream is licensed under [MIT](LICENSE). Licenses for bundled components,
including Geph and the Telegram proxy, are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

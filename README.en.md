# Slipstream — bypass network blocks on Mac

<div align="center">

<img src="app-tauri/src-tauri/icons/128x128@2x.png" width="96" height="96" alt="Slipstream app icon">

**YouTube buffering? Discord won't connect? Websites won't open?**

Slipstream helps bypass network censorship in browsers and apps on macOS.

**[Download for Mac](https://github.com/aiwaki/slipstream/releases/tag/v0.1.9-preview.23)** · [Installation](#installation) · [Русский](README.md)

**Apple silicon (M1 and later) · Free · Open source · Preview**

[![ci](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

Install Slipstream, approve its background service, and use your usual browsers
and apps. It runs from the menu bar and selects a connection method for services
that need a bypass. Local bypass requires no account, separate server, or browser
extension.

## What it is for

- **YouTube and Discord:** local bypass of DPI, the connection filtering used by
  internet providers. Your public IP address stays the same.
- **Websites with country restrictions:** an exit abroad through the bundled Geph
  client for supported routes. This requires a Geph account.
- **Telegram:** a local proxy the app offers to configure when a direct connection
  is unavailable.
- **Other websites:** a direct connection when no bypass is needed.

> [!NOTE]
> Slipstream is a preview. Results depend on your provider and the blocking
> method: page loading, video, and calls may still fail. The public build may
> lag behind fixes in the repository; access to every website is not guaranteed.

## Installation

The available build is **for macOS on Apple silicon**. See the
[roadmap](docs/ROADMAP.md) for other platforms.

1. Open the [Slipstream release for Mac](https://github.com/aiwaki/slipstream/releases/tag/v0.1.9-preview.23) and download **`Slipstream_0.1.9-preview.23_aarch64.dmg`** under Assets.
2. Open the DMG and drag **Slipstream.app** into **Applications**.
3. Launch it from Applications and approve installation of the background service.
4. Open the website or app you need. Connection status and settings are available from the Slipstream menu bar icon.

The same release includes a ZIP archive if you prefer that format.
The [releases page](https://github.com/aiwaki/slipstream/releases) also includes internal
Geph builds: choose **Slipstream**, not **Internal dependency**, to install the app.

The preview build is not notarized by Apple. If macOS blocks it, allow it to open
in **System Settings → Privacy & Security**, then launch it again.

## Do I need to configure a VPN?

Not for local bypass. Slipstream selects a route separately for each service.
**YouTube and Discord are never routed through Geph.** For supported websites
that need an IP address abroad, configure a Geph account in the Slipstream menu;
a separate Geph app is not required.

Slipstream is not designed to anonymize all internet traffic. When it conflicts
with a full-tunnel VPN, it pauses its own interception. It does not change external
DNS, proxy, PAC, or VPN settings. See the [routing policy](docs/DECISIONS.md) for details.

## If something won't load

Check the service status in the Slipstream menu. You can also restart the service
and copy redacted diagnostics there. When reporting a failure, include the website
or app, browser, approximate time, and what failed: the page, images, video, or a call.

[Troubleshooting](docs/TROUBLESHOOTING.md) ·
[Report an issue](https://github.com/aiwaki/slipstream/issues)

## Development and privacy

Slipstream uses Tauri and a Python background service. Routing decisions run
locally; only traffic assigned to foreign routes passes through Geph. Diagnostic
exports redact URLs, cookies, account secrets, and page content.

[Build from source](DEVELOPMENT.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Documentation](docs/README.md) · [Contributing](CONTRIBUTING.md) ·
[Report a vulnerability](SECURITY.md)

Slipstream is licensed under [MIT](LICENSE). Licenses for bundled components,
including Geph and the Telegram proxy, are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

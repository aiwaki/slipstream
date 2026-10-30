# Slipstream

<div align="center">

<img src="app-tauri/src-tauri/icons/128x128@2x.png" width="96" height="96" alt="Slipstream app icon">

**Bypass network blocks on your Mac, in browsers and apps.**

**[Download for Mac](https://github.com/aiwaki/slipstream/releases)** · [Installation](#installation) · [Русский](README.md)

**macOS 13+ · Apple silicon (M1 and later) · Free · Open source · Preview**

[![ci](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

Open websites and apps as usual. Slipstream runs from the menu bar and
automatically selects how to reach each service: a direct connection, local
bypass, or a foreign route through the bundled Geph client.
**Slipstream also tests access methods for sites outside its built-in rules
and remembers what worked.**

This is adaptive bypass: route selection uses connection checks as well as
predefined domain lists. You don't need to sort websites into lists that
should use or bypass a VPN.

## Why Slipstream

- Direct connections and local bypass reach websites without an intermediate
  VPN server. Your public IP address stays the same.
- An unknown site starts with a direct connection. If it fails, Slipstream
  tests local bypass methods. It remembers a successful method and reconsiders
  the choice when further attempts fail.
- Local bypass works in browsers and apps without an account, a server of your
  own, or a browser extension.
- The bundled Geph client provides a foreign IP address for supported routes.
  It requires a Geph account; there is no separate client to install.

> [!NOTE]
> Slipstream is a preview. Results depend on your provider and the blocking
> method: pages, video, and calls may still fail. Access to every website is not
> guaranteed. Fixes in the repository may not yet be in the downloadable build.
> See the [development status](docs/ROADMAP.md#development-status).

## What it does

| What you open | How Slipstream connects |
|---|---|
| YouTube and Discord | Uses local bypass of ISP filtering (DPI), without Geph. |
| A supported website with country restrictions | Uses a foreign route through Geph, if configured. |
| Telegram | Offers to configure a local proxy when a direct connection is unavailable. |
| A website that needs no bypass | Uses a direct connection. |
| A site outside the built-in rules that won't load | Checks the connection and tries local bypass methods. A temporary Geph route requires separate confirmation checks. |

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

Automatic route selection combines built-in service rules with connection
checks. The app has domain groups and exceptions; you don't have to create
them yourself. Successful local bypass methods are remembered and reconsidered
when they fail.

Slipstream uses Tauri and a Python background service. Routing decisions run
locally; only traffic assigned to foreign routes passes through Geph.

An unknown website may receive a temporary Geph route for its exact hostname
only after independent checks confirm a problem on the local route and a
successful response through the bundled Geph client. The checks depend on the
type of failure. This exception never applies to YouTube or Discord.

Diagnostic exports redact URLs, cookies, account secrets, and page content.

</details>

## Project plans

We plan to support **Windows and Android**; **iOS and Linux** are under
consideration. No dates have been announced. See the [roadmap](docs/ROADMAP.md)
for details.

See the [roadmap](docs/ROADMAP.md#development-status) for work in progress and
release blockers. The [release notes](https://github.com/aiwaki/slipstream/releases)
describe what is included in each downloadable build.

[Build from source](DEVELOPMENT.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Documentation](docs/README.md) · [Contributing](CONTRIBUTING.md) ·
[Report a vulnerability](SECURITY.md) · [Routing contracts](contracts/README.md)

Slipstream is licensed under [MIT](LICENSE). Licenses for bundled components,
including Geph and the Telegram proxy, are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

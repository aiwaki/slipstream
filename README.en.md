# Slipstream

<div align="center">

[Русский](README.md) · **English**

[![preview](https://img.shields.io/badge/preview-macOS%20(Apple%20Silicon)-000000?logo=apple)](#install)
[![roadmap](https://img.shields.io/badge/roadmap-cross--platform-2f80ed)](#platforms)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![build-geph](https://github.com/aiwaki/slipstream/actions/workflows/build-geph.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/build-geph.yml)
[![build-app](https://github.com/aiwaki/slipstream/actions/workflows/build-app.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/build-app.yml)

</div>

Slipstream is a cross-platform smart-routing client for blocked and throttled
services. It keeps the internet usable without turning the whole connection into
a remote VPN: direct where possible, local DPI bypass where needed, and a chosen
Geph exit only for services that need a foreign IP.

Routes are selected automatically:

- local services stay direct;
- DPI-broken traffic uses a local bypass;
- services that need a foreign IP use Geph;
- individual apps, such as Telegram Desktop, can use the bundled proxy.

No browser extensions. No per-app proxy setup. No unnecessary remote tunnel for
everything.

> [!NOTE]
> The current early build is a macOS Apple Silicon preview tuned for RU networks.
> Windows, Linux, iOS, and Android are on the roadmap; bypass capabilities will
> depend on what each platform allows.

## macOS Preview Interface

<p align="center">
  <img src="docs/images/slipstream-menu-composite.png" alt="Slipstream menu: Geph exit selection, app proxy actions, launch at login, logs, and updates">
</p>

## What it fixes

| Service | How it goes |
|---|---|
| Discord | chat, servers, and voice through local desync |
| YouTube | locally, without endless buffering |
| ChatGPT and Claude | only these go through a foreign Geph exit |
| Telegram Desktop | through the bundled MTProto-over-WebSocket proxy |
| Everything else blocked or throttled | automatically routed through local bypass or the tunnel |

## How it's different from a regular VPN

Slipstream does not try to replace the whole internet with one remote VPN server.
It splits traffic and chooses the lightest working route:

| Traffic | Route | Why |
|---|---|---|
| Russian services | direct | banks, gov services, and local sites never see a foreign IP |
| Things the DPI breaks | local desync | your IP stays Russian and latency stays low |
| Things that refuse Russian IPs | Geph | a foreign exit is used only where there is no local fix |

Fast where it can be. A detour only where there's no other way.

On iOS and Android this may be exposed through a system VPN profile, but the goal
is still split routing, not a permanent remote tunnel for the whole device.

## How it works

| Layer | Role | Platform model |
|---|---|---|
| Route engine | decides where a domain or connection should go | shared logic |
| Local bypass | bypasses DPI locally where the OS allows it | platform adapter |
| Geph tunnel | provides a foreign exit for geo-blocked services | shared network layer |
| App adapters | connect menus, system routing, and app-specific proxies | OS-specific |

<details>
<summary>Current macOS routing diagram</summary>

```
                 ┌─────────────────────────── your Mac ───────────────────────────┐
   any app  ───► │  transparent :443 intercept (pf)                                │
   (browser,     │        │                                                        │
   Discord,      │        ├─ Russian host?     → straight out, untouched           │
   Claude…)      │        ├─ broken by DPI?    → 1) DESYNC (local, in place)       │
                 │        └─ geo-blocked?       → 2) GEPH TUNNEL (exit abroad)      │
                 │  Telegram Desktop ─────────► 3) TG-WS PROXY (local MTProto)      │
                 └────────────────────────────────────────────────────────────────┘
```

</details>

The current macOS preview is built from three parts:

1. **Desync** — fools the DPI box locally: splits the TLS handshake and fires
   low-TTL decoy packets (the zapret / byedpi idea), plus DoH against DNS
   poisoning and a separate lane for Discord voice. Never touches your IP.
2. **Geph** — it's a VPN; we picked it on price/quality (open-source,
   [geph.io](https://geph.io), `geph5-client` inside). Sends **only** the
   geo-blocked stuff abroad, through a country you choose.
3. **tg-ws-proxy** — a local proxy ([Flowseal](https://github.com/Flowseal/tg-ws-proxy))
   that carries Telegram over WebSocket, past the data-center-IP block.

Desync and the Telegram proxy run entirely on your machine. Geph is a ready-made
network — you just need an account in it.

## Platforms

| Platform | Status |
|---|---|
| macOS Apple Silicon | early preview build |
| Windows | planned |
| Linux | planned |
| iOS | planned, within Network Extension limits |
| Android | planned, through the platform VPN/split-routing layer |

## Install

1. Download `Slipstream.app` from [releases](https://github.com/aiwaki/slipstream/releases) and drop it in Applications.
2. Launch it. It asks for your password once — to install the background service. After that it does everything itself.
3. In the menu (menu-bar icon):
   - **Geph → Account…** — paste your Geph account key (a free account works).
   - **Geph → pick an exit** — a city, or **Automatic**.
   - **Connect Telegram Proxy** — points Telegram at the bundled proxy.

Done — it takes it from here.

> [!TIP]
> First-download builds are not Apple-notarized yet. If macOS blocks the app,
> open it with right-click → **Open**.

## Build it yourself

Needs Rust, Node, Python 3, and the Xcode command-line tools.

```bash
# the background service bundled into the .app
cd spike
./build_daemon.sh
cd ..
rm -rf app-tauri/src-tauri/slipstreamd
cp -R spike/dist/slipstreamd app-tauri/src-tauri/slipstreamd

# the menu-bar app
cd app-tauri
npm ci
# a clean local release build needs the geph sidecar at:
# app-tauri/src-tauri/binaries/geph5-client-aarch64-apple-darwin
npm run tauri build

# the background service (desync + routing) — the app installs it for you,
# but during development you can do it manually from the repo root:
cd ..
sudo python3 spike/tproxy.py --install
```

The bundled `geph5-client` is built from source right in CI
([`build-geph.yml`](.github/workflows/build-geph.yml)) — always fresh, no stale
binaries. CI drops it into `app-tauri/src-tauri/binaries/` automatically.

## What's where

| Path | What it is |
|------|-----------|
| `app-tauri/` | The current macOS preview: menu-bar app (Tauri + Rust). |
| `spike/tproxy.py` | The desync + split-routing service for the macOS preview (Python, root). |
| `vendor/tg-ws-proxy/` | The bundled Telegram MTProto-over-WebSocket proxy. |
| `vendor/geph/` | How the bundled `geph5-client` is built and updated. |
| `docs/` | Design and security notes. |

## Privacy

- Slipstream's client-side routing logic runs locally on your device.
- Russian services stay **off** the tunnel — they go direct, so e.g. your bank never sees a foreign IP.
- Geph is your own account on the open Geph network; its security is on them, details in their docs.

## Credits

- **Slipstream** — [MIT](LICENSE).
- **geph5-client** — MPL-2.0, © [Geph](https://geph.io). Bundled as-is, built in CI.
- **tg-ws-proxy** — MIT, © [Flowseal](https://github.com/Flowseal/tg-ws-proxy). Bundled as a module.

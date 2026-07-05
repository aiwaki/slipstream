# Slipstream

<div align="center">

[Русский](README.md) · **English**

[![preview](https://img.shields.io/badge/preview-macOS%20(Apple%20Silicon)-000000?logo=apple)](#install)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![build-geph](https://github.com/aiwaki/slipstream/actions/workflows/build-geph.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/build-geph.yml)
[![build-app](https://github.com/aiwaki/slipstream/actions/workflows/build-app.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/build-app.yml)

</div>

Slipstream is a split-routing client for networks with blocking, DPI filtering,
and services that require a foreign IP.

Routes:

- direct connection for local services;
- local DPI bypass without changing the external IP;
- Geph tunnel for services that require a foreign IP;
- bundled Telegram Desktop proxy when direct connection does not work.

No browser extensions. No per-app proxy setup.

## Components

- **Local DPI bypass**: TLS handshake splitting, low-TTL decoy packets, DoH
  against DNS poisoning, and separate handling for Discord voice.
- **Geph**: foreign exit through the bundled `geph5-client`.
- **tg-ws-proxy**: local MTProto-over-WebSocket proxy for Telegram Desktop
  ([Flowseal](https://github.com/Flowseal/tg-ws-proxy)).

Desync and the Telegram proxy run on the device. Geph requires a Geph account.

## Platforms

| Platform | Status |
|---|---|
| macOS Apple Silicon | early build |
| Windows | not implemented |
| Linux | not implemented |
| iOS | not implemented |
| Android | not implemented |

Implementation order: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Install

1. Download `Slipstream.app` from [releases](https://github.com/aiwaki/slipstream/releases) and move it to Applications.
2. Launch it. macOS asks for your password once to install the background service.
3. In the menu (menu-bar icon):
   - **Geph → Account…** — paste your Geph account key.
   - **Geph → pick an exit** — a city, or **Automatic**.

If Telegram Desktop cannot connect directly, Slipstream offers to enable the
bundled Telegram proxy automatically.

> [!TIP]
> Builds are not Apple-notarized. If macOS blocks the app,
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

The bundled `geph5-client` is built from source in CI
([`build-geph.yml`](.github/workflows/build-geph.yml)) and placed in
`app-tauri/src-tauri/binaries/`.

## What's where

| Path | What it is |
|------|-----------|
| `app-tauri/` | Menu-bar app (Tauri + Rust). |
| `spike/tproxy.py` | Desync and split-routing service for macOS (Python, root). |
| `vendor/tg-ws-proxy/` | The bundled Telegram MTProto-over-WebSocket proxy. |
| `vendor/geph/` | Build setup for the bundled `geph5-client`. |
| `docs/` | Design and security notes. |

## Privacy

- Slipstream's client-side routing logic runs locally on your device.
- Russian services are not routed through Geph.
- Geph is an account on the Geph network; Geph is responsible for that network's security.

## Credits

- **Slipstream** — [MIT](LICENSE).
- **geph5-client** — MPL-2.0, © [Geph](https://geph.io). Bundled as-is, built in CI.
- **tg-ws-proxy** — MIT, © [Flowseal](https://github.com/Flowseal/tg-ws-proxy). Bundled as a module.

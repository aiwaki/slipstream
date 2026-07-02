<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/slipstream-banner-dark.png">
  <img alt="Slipstream — quiet censorship bypass for macOS" src="docs/images/slipstream-banner-light.png" width="100%">
</picture>

[Русский](README.md) · **English**

[![platform](https://img.shields.io/badge/platform-macOS%20(Apple%20Silicon)-000000?logo=apple)](#install)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![build-geph](https://github.com/aiwaki/slipstream/actions/workflows/build-geph.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/build-geph.yml)

</div>

---

Russian ISPs break half the internet: they throttle YouTube, tear Discord apart,
hand you a fake DNS, and ChatGPT and Claude won't even open. Slipstream fixes all
of it — quietly, in the background, right on your Mac. And it doesn't push every
byte through some faraway server like a regular VPN — only what won't open any
other way goes abroad.

Install it, drop in your Geph key once — and it figures out on its own what needs
what. No extensions, no per-app proxies, no extra buttons.

> [!NOTE]
> Early version. macOS on Apple Silicon only for now, tuned for RU networks.

## What it fixes

- **Discord** — chat, servers, and **voice** (the UDP part others drop).
- **YouTube** — no endless buffering.
- **ChatGPT and Claude** — which flat-out refuse Russian IPs. We send them through an exit abroad, and they just work.
- **Telegram** — Desktop goes through a bundled proxy, past the data-center-IP block. One button.
- **Almost everything else that's blocked or throttled** — automatically.

## How it's different from a VPN

A regular VPN routes literally everything through a server — slow and pointless.
Slipstream splits the traffic:

- **Russian stuff** (banks, gov services, local sites) — direct, it shouldn't leave the country anyway;
- **things the DPI just breaks** — fixed in place, your IP stays Russian;
- **things that refuse Russian IPs** — only that takes the detour abroad.

Fast where it can be. A detour only where there's no other way.

## How it works

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

Three things, each doing its own job:

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

## Install

1. Download `Slipstream.app` from [releases](https://github.com/aiwaki/slipstream/releases) and drop it in Applications.
2. Launch it. It asks for your password once — to install the background service. After that it does everything itself.
3. In the menu (menu-bar icon):
   - **Geph → Account…** — paste your Geph account key (a free account works).
   - **Geph → pick an exit** — a city, or **Automatic**.
   - **Connect Telegram Proxy** — points Telegram at the bundled proxy.

Done — it takes it from here.

## Build it yourself

Needs Rust, Node, Python 3, and the Xcode command-line tools.

```bash
# the menu-bar app
cd app-tauri && npm install && npm run tauri build

# the background service (desync + routing) — the app installs it for you,
# but during development you can do it manually:
sudo python3 spike/tproxy.py --install
```

The bundled `geph5-client` is built from source right in CI
([`build-geph.yml`](.github/workflows/build-geph.yml)) — always fresh, no stale
binaries.

## What's where

| Path | What it is |
|------|-----------|
| `app-tauri/` | The menu-bar app — native macOS UI (Tauri + Rust). |
| `spike/tproxy.py` | The desync + split-routing service (Python, root). |
| `vendor/tg-ws-proxy/` | The bundled Telegram MTProto-over-WebSocket proxy. |
| `vendor/geph/` | How the bundled `geph5-client` is built and updated. |
| `docs/` | Design and security notes. |

## Privacy

- Slipstream is a local tool: everything runs on your machine.
- Russian services stay **off** the tunnel — they go direct, so e.g. your bank never sees a foreign IP.
- Geph is your own account on the open Geph network; its security is on them, details in their docs.

## Credits

- **Slipstream** — [MIT](LICENSE).
- **geph5-client** — MPL-2.0, © [Geph](https://geph.io). Bundled as-is, built in CI.
- **tg-ws-proxy** — MIT, © [Flowseal](https://github.com/Flowseal/tg-ws-proxy). Bundled as a module.

<div align="center"><sub>Made to just work — on its own, and like a human would!</sub></div>

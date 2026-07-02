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

Slipstream is a menu-bar app for macOS that transparently undoes the things a
censoring ISP does to your connection — the throttling, the resets, the poisoned
DNS, the geo-blocks — **without turning your whole machine into a VPN.** You
install one app, sign into a Geph account, and forget it's there. No browser
extensions, no per-app proxy fiddling, no manual on/off in normal use.

It's built for the Russian TSPU environment specifically, but the ideas apply to
any DPI-based censorship.

> [!NOTE]
> **Status:** early days. macOS on Apple Silicon, tuned for RU networks.

## What it fixes

- **Discord** — chat, servers, CDN, and **voice** (the UDP part most tools drop).
- **YouTube** — no more mid-video stalls from throttling.
- **ChatGPT & Claude** — services that hard-refuse Russian IPs are routed out
  through a real exit abroad, so they just work.
- **Telegram** — Desktop rides a bundled local proxy past the data-center-IP
  block; one click to enable.
- **Most blocked / throttled / DNS-poisoned sites** — handled automatically.

## Why it feels different

**It is not a full-tunnel VPN.** Slipstream is a *split-tunnel* by design:

- Your Russian traffic (banking, gov services, local sites) stays **direct and
  fast** — it never leaves the country.
- Sites the ISP merely *breaks* (DPI throttle / reset / DNS poison) are fixed
  **locally**, in place — your IP stays Russian, the breakage just stops.
- Only the handful of services that **geo-block Russian IPs outright** take the
  encrypted detour abroad.

So it's fast where it can be, private where it must be, and quiet the whole time.

## How it works

Three independent planes, kept strictly separate:

```
                 ┌─────────────────────────── your Mac ───────────────────────────┐
   any app  ───► │  transparent :443 intercept (pf)                                │
   (browser,     │        │                                                        │
   Discord,      │        ├─ Russian host?      → straight out, untouched          │
   Claude…)      │        ├─ DPI-blocked host?  → 1) DESYNC ENGINE (local)         │
                 │        └─ geo-blocked host?  → 2) GEPH TUNNEL (exit abroad)      │
                 │  Telegram Desktop ─────────► 3) TG-WS PROXY (local MTProto)      │
                 └────────────────────────────────────────────────────────────────┘
```

1. **Desync engine** *(local, no server)* — beats the DPI box with TLS-record
   fragmentation and low-TTL decoy packets (zapret / byedpi-style), plus DoH to
   sidestep DNS poisoning and a dedicated UDP plane for Discord voice. Your IP
   never changes.
2. **Geph tunnel** — the open-source [Geph](https://geph.io) network
   (`geph5-client`, bundled) carries only the geo-blocked services out through an
   exit country you pick. Everything else stays off the tunnel.
3. **Telegram proxy** — [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)
   (bundled) runs a local MTProto proxy that tunnels Telegram over WebSocket,
   getting past the block on Telegram's data-center IPs.

Nothing runs on our servers — there are none. Geph is your own account on an
existing open network; the desync and Telegram proxy are entirely local.

## Install

1. Download `Slipstream.app` from [Releases](https://github.com/aiwaki/slipstream/releases) and drag it to Applications.
2. Launch it. On first run it **asks for your password once** — to install the
   background service. After that it does everything itself.
3. Open the menu-bar menu:
   - **Geph → Account…** — paste your Geph account secret (a free account works).
   - **Geph → pick an exit** — a city, or **Automatic**.
   - **Connect Telegram Proxy** — points Telegram Desktop at the bundled proxy.

That's it. Nothing else to do by hand.

## Build from source

Requires Rust, Node, Python 3, and the Xcode command-line tools.

```bash
# menu-bar app
cd app-tauri && npm install && npm run tauri build

# background service (desync + routing) — the app installs it for you,
# but during development you can install it manually:
sudo python3 spike/tproxy.py --install
```

The bundled `geph5-client` is compiled from source in CI
([`build-geph.yml`](.github/workflows/build-geph.yml)) so it always tracks
upstream — nothing is a stale binary blob.

## Repo layout

| Path | What it is |
|------|-----------|
| `app-tauri/` | The menu-bar app — native macOS tray UI (Tauri + Rust). |
| `spike/tproxy.py` | The transparent desync + split-tunnel routing daemon (Python, root). |
| `vendor/tg-ws-proxy/` | Bundled Telegram MTProto-over-WebSocket proxy. |
| `vendor/geph/` | How the bundled `geph5-client` is built + tracked. |
| `docs/` | Design notes and threat model. |

## Privacy & trust

- Runs entirely on your machine; Slipstream has no backend.
- Split-tunnel keeps Russian services **off** any tunnel — they go direct, so
  your bank never sees a foreign IP.
- Geph is your own account on the public Geph network; read their docs for its
  threat model.

## Credits & license

- **Slipstream** — [MIT](LICENSE).
- **geph5-client** — MPL-2.0, © [Geph](https://geph.io). Bundled unmodified;
  source tracked via CI.
- **tg-ws-proxy** — MIT, © [Flowseal](https://github.com/Flowseal/tg-ws-proxy).
  Vendored as a Python module.

<div align="center"><sub>Made to be automatic and calm. If you notice it, something's wrong.</sub></div>

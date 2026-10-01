# Slipstream local changes

The upstream component is `Flowseal/tg-ws-proxy`; `VERSION` records the upstream
base version (currently 1.8.1). The upstream `LICENSE` is retained unchanged.
This directory contains local Slipstream changes and is not an unmodified
upstream release. The enclosing Slipstream commit identifies the actual sources.

The October 2026 transport audit adds:

- Byte-preserving WebSocket continuation handling, including empty fragments,
  and empty Fake TLS application records that do not falsely signal EOF.
- One deadline and a 64 KiB header limit for WebSocket upgrade; truncated
  response headers cannot establish an apparently usable connection.
- Transport cleanup on failed or cancelled upgrade/initial sends, peer CLOSE,
  and bounded TLS shutdown in relays and accepted clients.
- Explicit ownership of pool refill and socket-close tasks; shutdown drains
  completed but unconsumed connections and survives repeated cancellation.
- Listener/client/pool cleanup on normal stop, listener restart, and task
  cancellation; listener restart drains accepted clients before joining
  `serve_forever`, whose cancellation can itself wait for those transports.
  Stopped CF-domain refresh generations cannot publish late data.

Regression checks use fixtures and loopback sockets only:

```sh
spike/.venv/bin/python -m pytest spike/test_telegram_transport_lifecycle.py spike/test_tgws_utils.py -q
```

The changes do not alter Telegram fallback selection, fronting/TLS certificate
policy, or the upstream source URL. The blocking CF-domain fetch is allowed to
finish after stop, but cannot publish or start another refresh.

`spike/slipstreamd.spec` collects the complete `proxy` package from this directory.
These changes require rebuilding the frozen daemon; an existing staged or
installed binary does not acquire them from a tray-only rebuild. Canonical app
bundle and installed verification remain separate release gates.

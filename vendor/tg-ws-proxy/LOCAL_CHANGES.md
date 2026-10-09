# Slipstream local changes

The upstream component is `Flowseal/tg-ws-proxy`; `VERSION` records the upstream
base version (currently 1.11.1). The upstream `LICENSE` is retained unchanged.
This directory contains local Slipstream changes and is not an unmodified
upstream release. The enclosing Slipstream commit identifies the actual sources.

## Upstream update, 2026-10-09

The imported stable release is
[v1.11.1](https://github.com/Flowseal/tg-ws-proxy/releases/tag/v1.11.1), commit
`18175fb4fe567cf6aef61f9d883eff010c9e66a8`. [SOURCE.json](SOURCE.json) records
the exact official source archive hash and original hashes of all 14 imported
Python modules. Those hashes describe the upstream input, before local patches;
the enclosing Slipstream commit identifies the final patched tree. No upstream
GUI, binary release assets, worker deployment, or updater is imported.

Since the previous 1.8.1 base, upstream added direct WebSocket pool rotation and
retry backoff, revised CF-worker selection, and HTTP/2 multiplexing for media.
The 1.11.1 release fixes propagation of HTTP 404 from that media path. New
modules are `cf_h2.py`, `h2_transport.py`, and `network_debug.py`; the runtime now
also requires `httpx[http2]==0.28.1`, pinned in Slipstream's hashed Python locks.

Upstream enables experimental media H2 by default. It is active only when
`cfproxy_h2_media` and `fallback_cfproxy` are true, and both `disable_secure` and
`force_test_dc` are false. The upstream CLI switch `--no-h2` disables it.
Direct data-center connections still use the WebSocket pool; H2 belongs to the
CF media fallback. Upstream's certificate verification is retained: certifi
plus system roots, certificate-chain verification for ordinary and fronted
TLS; only fronting disables hostname comparison. Plaintext CF/worker transport
is an upstream explicit option (`disable_secure`), false by default.

## Preserved local fixes

The October 1 transport audit added:

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

Each fix was reconciled against the new upstream rather than replaced by the
new files wholesale:

| Boundary | 1.11.1 and retained Slipstream behavior |
|---|---|
| WebSocket fragments | Upstream now assembles continuations and bounds messages to 16 MiB. Slipstream keeps byte-stream delivery and empty-fragment handling, adding that same frame/message cap before oversized allocation. |
| Fake TLS EOF | Upstream still returns empty application records; the local skip preserves the stream until a real EOF. |
| HTTP upgrade | Upstream still applies a timeout to each header line. The local shared deadline covers connect, write drain and all headers; the 64 KiB cap and complete-header requirement remain. |
| Close and cancellation | Local bounded transport cleanup remains in upgrades, initial sends, WebSocket/TCP bridges, and accepted clients. The peer-CLOSE reply now also uses the close deadline; a stuck write cannot prevent relay teardown. |
| Pool ownership | Upstream pool APIs and idle rotation are adopted. Refills, rotation and expired-socket close tasks remain owned; shutdown drains unconsumed connectors even after repeated cancellation. |
| CF refresh | The local generation/stop fence prevents a stopped background fetch from publishing into a subsequent run. |
| Listener shutdown | Local stop/restart/cancellation drains accepted clients before waiting for the listener and closes all pools, including the new H2 pool. |
| H2 ownership | Local H2 transport, channel, lane and pool cleanup is coalesced and shielded against repeated cancellation. Pending connection setup and preflight cannot publish after shutdown; unclaimed writers/channels and reserved request capacity are reclaimed. |

Regression checks use fixtures and loopback sockets only:

```sh
spike/.venv/bin/python -m pytest spike/test_telegram_transport_lifecycle.py spike/test_telegram_h2_transport.py spike/test_telegram_h2_ownership.py spike/test_tgws_utils.py -q
```

The blocking CF-domain fetch is allowed to finish after stop, but cannot publish
or start another refresh. Loopback H2 tests cover concurrent requests, complete
multi-frame payloads, peer reset/EOF, cancellation, partial-response timeout, and
HTTP 404 delivery as native MTProto `-404` without replay in all three supported
framing modes. Separate deterministic ownership tests cover overlapping close,
repeated cancellation, preflight shutdown, request-capacity release and failed
connection setup/reconnect.
They do not establish live Telegram media availability or performance.

`spike/slipstreamd.spec` collects the complete `proxy` package from this directory.
These changes require rebuilding the frozen daemon; an existing staged or
installed binary does not acquire them from a tray-only rebuild. Canonical app
bundle and installed verification remain separate release gates.

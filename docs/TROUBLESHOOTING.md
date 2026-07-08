# Troubleshooting

This page keeps operational checks short and current.

## Routing Model

Use local bypass for DPI/SNI interference:

- Discord
- YouTube/googlevideo
- other hosts listed as local-bypass policy

Use Geph only for services that need a foreign exit because the service rejects
Russian IP addresses. Do not route Discord or YouTube through Geph as a fix.

## Basic Checks

Daemon status:

```bash
/usr/local/slipstream/slipstreamd --status
```

Daemon log:

```bash
tail -f /var/log/slipstream.log
```

Transparent-path curl test:

```bash
curl --noproxy '*' -I https://discord.com/api/v9/experiments
```

The `--noproxy '*'` flag matters when another local proxy is running. It keeps
the test on Slipstream's transparent `pf` path instead of a browser or shell
proxy.

## External DNS, Proxy, PAC, VPN

Slipstream does not own external DNS, proxy, PAC, or VPN settings. If one of
them is active, treat it as outside state:

1. Record it in diagnostics.
2. Warn when it may bypass Slipstream routing.
3. Do not disable, rewrite, restore, or replace it automatically.

This includes user-managed DNS services such as `xbox-dns.ru`. They may be part
of the user's working setup, but Slipstream should not silently enable or remove
them.

## Discord

Expected indicators:

- updater reaches `updates.discord.com` without TLS transport errors
- renderer log reaches `[GatewaySocket] [READY]`
- voice log reaches `RTC_CONNECTED` when joining a call

If Discord stalls:

1. Check that it is not being routed through Geph.
2. Check `/var/log/slipstream.log` for `NO RESPONSE` lines.
3. Restart Discord after the daemon is active.
4. If only one CDN edge fails, retry after DNS rotation or clear the strategy
   cache.

## YouTube

YouTube/video traffic should not require a global UDP/443 block. QUIC is left
open by default because working HTTP/3 paths are often required for playback.

If playback fails:

1. Test with browser/system proxy disabled.
2. Confirm the daemon is active.
3. Check whether external proxy/PAC settings are bypassing Slipstream.
4. Avoid global QUIC blocks unless a new scoped failure mode is proven.

## Steam

Steam Store web hosts use `geo_exit` because the direct path can return a tiny
partial page and then stall. This is intentionally narrower than "all Steam":
Steam CM, game traffic, and download paths are not routed through Geph by
default.

Useful checks:

```bash
curl --noproxy '*' -L -o /dev/null -sS \
  -w 'http=%{http_code} connect=%{time_connect} start=%{time_starttransfer} total=%{time_total} ip=%{remote_ip}\n' \
  https://store.steampowered.com/
tail -n 120 "$HOME/Library/Application Support/Steam/logs/connection_log.txt"
tail -n 120 "$HOME/Library/Application Support/Steam/logs/bootstrap_log.txt"
```

Do not widen Steam routing without endpoint-level evidence. Steam can use
store/CDN/update hosts plus CM WebSocket and UDP paths, so one working endpoint
does not prove the whole app is healthy.

## Installed Daemon

After rebuilding the daemon, keep all copies in sync:

```bash
shasum -a 256 \
  spike/dist/slipstreamd/slipstreamd \
  app-tauri/src-tauri/slipstreamd/slipstreamd \
  /Applications/Slipstream.app/Contents/Resources/slipstreamd/slipstreamd \
  /usr/local/slipstream/slipstreamd
```

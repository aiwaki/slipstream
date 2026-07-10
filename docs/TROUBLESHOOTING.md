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

`strategy_scores` in daemon status and copied diagnostics summary is
aggregate-only: it reports host counts and ok/fail totals by service group and
strategy, but does not expose hostnames.

Tray diagnostics:

- `Copy Diagnostics` copies a redacted JSON snapshot and saves the same snapshot
  as `slipstream-diagnostics.json` in the macOS temporary directory, then reveals
  it in Finder for bug reports.
- The snapshot has a short `summary` section first, followed by raw daemon
  status, install checks, and recent log lines.
- The summary includes both app version and daemon version so install drift is
  visible in bug reports.
- The snapshot includes `daemon_recovery` when the tray watchdog recently tried
  to recover the root daemon or reset stale `pf` rules.

Daemon log:

```bash
tail -f /var/log/slipstream.log
```

Administrator prompts:

Slipstream asks macOS for administrator access only for privileged maintenance:

- installing or upgrading the background daemon;
- restarting or repairing the background daemon;
- copying the root-owned daemon log for `Open Log`.

The prompt should name Slipstream and the specific action. Cancel unrelated or
unnamed `osascript` password prompts.

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

External proxy tools may also leave disabled `ExceptionsList` entries after
their proxy is turned off. Slipstream reports this as `system_proxy` stale
exceptions in status/diagnostics, but still treats the system proxy as off.

## Sleep, Lid Close, And Wake

Adrafinil-style keep-awake tools may hold `PreventUserIdleSystemSleep` without
holding `PreventSystemSleep`. With the lid closed, macOS can still enter
SleepService/DarkWake cycles. In daemon logs this appears as:

```text
>> woke from sleep (gap 903s) -> re-arming
```

After wake, a Geph process can keep its local SOCKS port open while the tunnel
inside it returns `SOCKS connect failed` or closes payload probes without a
response. Slipstream records this under `geph_detail`; repeated post-wake
geo-exit failures across multiple hosts set `restart_recommended`, and the tray
rate-limits a restart of Slipstream's own `geph5-client`.

Wake canaries may briefly run before Geph/DNS recovery is complete. If a tray
summary still says routing needs attention after the tunnel is back, check
`canaries.last_reason`, `route_health`, and recent `geph SOCKS up/down` log
lines. Forced recovery triggers should queue a short rerun instead of waiting for
the normal periodic interval.

`rearm` in daemon status records the last sleep-gap or network-change re-arm
observed by Slipstream.

Useful checks:

```bash
pmset -g assertions
pmset -g log | egrep 'Entering Sleep|Wake from|DarkWake|SleepService|Adrafinil|lid'
python3 -m json.tool /var/run/slipstream.status
tail -n 160 /var/log/slipstream.log
```

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
`youtube_video` is the hard health signal. `youtube_web` is warning-only because
the web shell can succeed over browser IPv6/QUIC even when a daemon-side IPv4/TCP
probe is noisy.

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

The `steam_store` canary checks real HTTPS payload through Geph. A passing
SOCKS/TLS connect alone is not enough to mark the store healthy, because the
browser-visible failure can happen after the page starts loading.

## GitHub

GitHub developer endpoints use `direct_passthrough`. If `gh api` works but
`git fetch` or `git push` hangs, check that `github.com`,
`objects.githubusercontent.com`, and `codeload.github.com` still resolve to the
`github` direct policy and plain-only strategy. They should not use Geph or the
generic desync ladder.

## Auto Geo-Exit Learning

Slipstream can learn an unknown HTTPS host as temporary `geo_exit` only after
both conditions are true:

- local desync repeatedly returns little or no application data for that exact
  host;
- a separate HTTPS payload probe through Slipstream's Geph tunnel succeeds.

The learned entry is exact-host only and TTL-based. It does not apply to
Discord, YouTube/googlevideo, Telegram, Russian services, Geph infrastructure,
or external DNS/proxy/PAC/VPN settings.

If a page shell loads but a payment form, video, image CDN, or static resource
keeps stalling, check daemon logs for repeated Geph route retries on the same
learned host. Slipstream resets only auto-learned exact hosts after repeated
runtime retries, then lets the normal local route and proof-based learning run
again. Explicit geo-exit hosts are not reset this way.

## Installed Daemon

After rebuilding the daemon, keep all copies in sync:

```bash
shasum -a 256 \
  spike/dist/slipstreamd/slipstreamd \
  app-tauri/src-tauri/slipstreamd/slipstreamd \
  /Applications/Slipstream.app/Contents/Resources/slipstreamd/slipstreamd \
  /usr/local/slipstream/slipstreamd
```

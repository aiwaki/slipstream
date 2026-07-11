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

The command accepts both legacy StatusV1 (`ts`) and privacy-bounded StatusV2
(`daemon.updated_at`). A fresh V2 snapshot must not be reported as `off`:
the tray recovery path relies on this check before touching Slipstream's private
PF anchor.

After install or upgrade, the tray gives the daemon a short startup grace before
watchdog recovery. Repeated missing snapshots after that grace still trigger the
normal daemon repair path.

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
  to recover the root daemon or clear Slipstream's private PF anchor.

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

## Removing Slipstream

`Quit Slipstream` closes the tray UI but intentionally leaves its background
routing service and owned Geph LaunchAgent running. This preserves routing if
the menu process exits or crashes.

`Copy Diagnostics` reports `summary.geph_lifecycle: sidecar_only` when the root
daemon is absent but Slipstream's own Geph LaunchAgent remains loaded. This does
not claim an active PF redirect; it identifies the remaining user-side job so it
is not mistaken for an external VPN or proxy.

To remove Slipstream, choose `Uninstall Slipstream…` in the tray and confirm the
native dialog. It removes the Slipstream root daemon and private PF state first,
then removes only Slipstream's verified Geph LaunchAgent, private runtime, and
its Keychain account entry. The app bundle remains in `Applications` and can be
moved to Trash afterwards.

Do not delete the app first or use broad `pkill`, `pfctl -F states`, or DNS
changes as normal removal steps. External Geph, DNS, proxy, PAC, VPN, and PF
state are never changed by this action.

## Geph Exit Locations

The Geph submenu normally lists city-level exits such as `CA / Montreal`. On a
fresh launch, Geph may not have answered its local control RPC yet; Slipstream
temporarily shows country-level fallback entries and replaces them in the open
tray menu as soon as the live catalog is available. A restart is not required.

If the menu stays country-only after Geph is connected, use `Copy Diagnostics`.
The app caches the last verified city catalog locally, so later launches should
show the city list immediately even while Geph is reconnecting.

## PF Ownership

Slipstream owns only `com.apple/slipstream`. Normal lifecycle and recovery do
not load Slipstream rules into the global PF ruleset, edit `/etc/pf.conf`, or
disable PF. This preserves macOS rules and external anchors such as `zapret`.

Inspect the private anchor:

```bash
sudo pfctl -a com.apple/slipstream -sr
sudo pfctl -a com.apple/slipstream -sn
```

Emergency cleanup is scoped to that anchor:

```bash
sudo pfctl -a com.apple/slipstream -F rules
sudo pfctl -a com.apple/slipstream -F nat
```

Do not use `pfctl -F all`, `pfctl -F states`, `pfctl -d`, or load a replacement
global ruleset as Slipstream recovery. On macOS, `-F all` includes the shared PF
state table even when `-a` is present. The daemon therefore flushes only its
private filter and NAT rulesets. It stores its own PF enable token under
`/var/run` and releases only that reference during normal teardown. An upgrade
from a legacy build may reload the canonical `/etc/pf.conf` once after detecting
old global Slipstream redirect rules; it never writes that file.

Reviewed PF changes use the disposable privileged smoke in CI instead of an
installed workstation. Its local no-root preflight is:

```bash
python3 scripts/pf_anchor_smoke.py --dry-run
```

Real mode refuses to start if Slipstream status, token, or private-anchor state
already exists. It targets a high test port and never TCP/443.

If the required `com.apple/*` parent anchor is absent from the host PF setup,
Slipstream exits safely instead of taking ownership of global PF configuration.

Only one transparent HTTPS redirect can own a connection. If another active
PF interceptor appears before `com.apple/*`, PF sends real application traffic
to it before Slipstream's private anchor is considered. Slipstream reports
`state: conflict`, shows `Paused` in the tray, clears only its own anchor, and
automatically re-arms after the conflict disappears. It does not stop or edit
the other product.

Inspect ordering and the reported conflicts:

```bash
sudo pfctl -sn
sudo pfctl -sr
python3 -m json.tool /var/run/slipstream.status
```

An anchor can remain declared in `/etc/pf.conf` without being a conflict; only
an active earlier HTTPS `rdr` plus matching `route-to` counts. If two transparent
bypass tools are installed, stop one through its own UI or service controls.

Transparent-path curl test:

```bash
curl --noproxy '*' -I https://discord.com/api/v9/experiments
```

The `--noproxy '*'` flag matters when another local proxy is running. It keeps
the test on Slipstream's transparent `pf` path instead of a browser or shell
proxy.

## ChatGPT Or Codex Reconnecting

The native ChatGPT/Codex client uses long-lived streaming connections. A loop
such as `Reconnecting 2/2` with `websocket closed by server before
response.completed` can be caused by Slipstream capturing TCP/443 before its
geo-exit backend is ready.

The July 2026 incident had this exact sequence in the daemon log:

```text
>> pf anchor com.apple/slipstream active: TCP/443 -> 127.0.0.1:1080
>> geph SOCKS up (:None)
>> geph route retry for chatgpt.com: SOCKS connect failed
>> geph SOCKS down (:[9954])
>> geph route retry for ws.chatgpt.com: tunnel down
```

`up (:None)` is invalid. The cause was cold-start hysteresis preserving two
failed probes even though no previously verified SOCKS port existed, while PF
was already active. OpenAI hosts then reached the geo-exit fail-close branch in
`_handle_impl` and the client retried into the same redirect.

Required behavior:

- do not arm PF until the proxy listener and enabled geo-exit backend are ready;
- never report Geph up without a verified port;
- on runtime geo-exit failure, including a successful SOCKS connection followed
  by an early zero-byte remote close, clear only `com.apple/slipstream` and
  enter dormant mode for a bounded hold;
- do not let tray polling restart a live Geph process from endpoint failures;
- do not modify DNS, proxy, PAC, VPN, certificates, Keychain, or network plist
  files as a workaround.

Emergency cleanup remains scoped to Slipstream:

```bash
sudo launchctl bootout system /Library/LaunchDaemons/dev.slipstream.tproxy.plist
sudo pfctl -a com.apple/slipstream -F rules
sudo pfctl -a com.apple/slipstream -F nat
```

Do not use a global `pfctl -F states`, `pfctl -d`, or replacement DNS as normal
recovery.

## External DNS, Proxy, PAC, VPN

Slipstream does not own external DNS, proxy, PAC, or VPN settings. If one of
them is active, treat it as outside state:

1. Record it in diagnostics.
2. Warn when it may bypass Slipstream routing.
3. Do not disable, rewrite, restore, or replace it automatically.

This includes user-managed DNS services such as `xbox-dns.ru`. They may be part
of the user's working setup, but Slipstream should not silently enable or remove
them.

Slipstream's on-demand Xbox DNS fallback is separate from that external state:
after a local failure for one generic hostname, it can make one verified DoH
query and try the returned address locally. It never changes the system resolver
configuration.

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
geo-exit failures across multiple hosts may set `restart_recommended` for
diagnostics. The tray does not act on that hint: the Geph LaunchAgent recovers a
dead process through `KeepAlive`, while restarting a live but stale process is
deferred until the daemon can coordinate it without tearing down active streams.

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
2. Check `pf_state.interceptor_conflicts`; a second transparent filter can
   receive Discord before Slipstream while internal canaries still look healthy.
3. Check `/var/log/slipstream.log` for `NO RESPONSE` lines.
4. Restart Discord after the daemon is active.
5. A runtime miss automatically starts a deduplicated exact-host re-sweep of
   the allowed local-bypass strategies. If the same endpoint keeps failing,
   capture diagnostics instead of selecting a strategy manually.

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

TCP local-bypass misses trigger the same exact-host re-sweep as Discord. The
recovery path remains local and never promotes YouTube/googlevideo to Geph.

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

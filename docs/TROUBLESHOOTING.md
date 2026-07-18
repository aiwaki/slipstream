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

The watchdog runs only when launchd reports the Slipstream label explicitly
enabled. A missing or disabled label is not repaired at startup. `Restart Proxy`
is the explicit action that may reinstall or re-enable it.

After the daemon stops, `/var/run/slipstream.status` must disappear. A former
shutdown race allowed the monitor thread to recreate that file after PF cleanup,
so the tray could display stale state even though the private anchor was gone.
Status publication is now serialized with teardown and permanently disabled for
the remainder of the process. A surviving file after a confirmed daemon exit is
a lifecycle defect; do not infer active routing from that file alone.

`strategy_scores` in daemon status and copied diagnostics summary is
aggregate-only: it reports host counts and ok/fail totals by service group and
strategy, but does not expose hostnames.

Tray diagnostics:

- `Open Status` opens a sanitized owner-only JSON snapshot without an
  administrator prompt. It includes StatusV2, install checks, daemon recovery,
  and the current/previous private stdout/stderr tails of Slipstream's owned
  Geph LaunchAgent, but not the root daemon log. Each current Geph log rotates
  after 1 MiB into one 256 KiB previous tail. Snapshot generation reads at most
  the final 128 KiB of each file before selecting and redacting recent lines.
- `Copy Diagnostics` copies a redacted JSON snapshot and saves the same snapshot
  as `slipstream-diagnostics.json` in the macOS temporary directory, then reveals
  it in Finder for bug reports.
- The snapshot has a short `summary` section first, followed by raw daemon
  status, install checks, and recent log lines.
- The summary includes both app version and daemon version so install drift is
  visible in bug reports.
- The snapshot includes `daemon_recovery` when the tray watchdog recently tried
  to recover the root daemon or clear Slipstream's private PF anchor.
- Because the raw daemon log is root-only, `Copy Diagnostics` may show a named
  administrator prompt to make a temporary owner-only copy. The exported tail
  is redacted and the intermediate copy is removed.

Daemon log:

```bash
sudo tail -f /var/log/slipstream.log
```

The current log and retained rotations are root-owned regular files with mode
`0600`. Each daemon start writes a `daemon session start` marker so retained
errors from an older process are not mistaken for the current session.

Administrator prompts:

Slipstream asks macOS for administrator access only for privileged maintenance:

- installing or upgrading the background daemon;
- restarting or repairing the background daemon;
- copying the root-owned daemon log for `Copy Diagnostics`.

The prompt should name Slipstream and the specific action. Cancel unrelated or
unnamed `osascript` password prompts.

Tray startup must not request administrator access when the daemon label is
missing or disabled. An automatic upgrade prompt is valid only for an existing,
explicitly enabled installation whose bundled daemon changed.

## Removing Slipstream

`Quit Slipstream` closes the tray UI but intentionally leaves its background
routing service and owned Geph LaunchAgent running. This preserves routing if
the menu process exits or crashes.

`Copy Diagnostics` reports `summary.geph_lifecycle: sidecar_only` when the root
daemon is absent but Slipstream's own Geph LaunchAgent remains loaded. This does
not claim an active PF redirect; it identifies the remaining user-side job so it
is not mistaken for an external VPN or proxy.

To remove Slipstream, choose `Uninstall Slipstream…` in the tray and confirm the
native dialog. It first disables tray autostart, stops new transparent accepts,
clears only Slipstream's private PF anchor, and gives already accepted streams a
bounded drain while the owned Geph backend is still alive. It then removes only
Slipstream's verified Geph LaunchAgent, private runtime, and Keychain account
entry. A detached privileged helper moves the validated application bundle out
of its installed path only after that user cleanup succeeds, then revalidates
the exact tray PID before deleting the staged bundle.
Cancelling the administrator prompt or failing owned-Geph cleanup does not
commit application removal.

The root uninstaller disables the launchd label before stopping any detached
listener, and signals a PID only after verifying the installed daemon command.
It reports failure if a verified daemon PID survives the bounded stop, even when
the listener has already disappeared. It then removes the plist, owned runtime,
status, and private PF rules, and releases the owned PF token. The token record
is removed only after a successful release. If the installed uninstaller was
already deleted, the tray uses the copy inside the application bundle. A
partial install follows the same rollback.

Do not delete the app first or use broad `pkill`, `pfctl -F states`, or DNS
changes as normal removal steps. External Geph, DNS, proxy, PAC, VPN, and PF
state are never changed by this action.

The 2026-07-14 incident combined two failures: half-open transparent relays
exhausted the daemon's file descriptors, leaving its listener and PF redirect in
place, while root-first uninstall could stop before the independent user Geph
LaunchAgent was reached. The log contained 2,115 `Too many open files` entries
and pending relay tasks. The tray then appeared stuck, the app remained in
`Applications`, and `geph5-client` continued under LaunchAgent `KeepAlive`.

Current required behavior is fail-open for native traffic: every backend relay
has a bounded shared lifecycle and awaits both stream closures. The daemon keeps
an emergency descriptor reserve and, at a bounded high watermark or
`EMFILE`/`ENFILE`, immediately pauses only `com.apple/slipstream`. It may re-arm
only after descriptor use falls below the low watermark and normal backend
readiness succeeds. Uninstall keeps the owned Geph process alive only while the
root daemon clears PF and drains accepted streams, then removes that exact user
job before the tray exits.

The 2026-07-19 primary smoke exposed a separate final-step failure: privileged
daemon/PF cleanup completed, but `/Applications/Slipstream.app` remained. The
tray had attempted to detach its app-removal shell through macOS
`/usr/bin/nohup`; in the administrator AppleScript execution context that
process could fail before the worker started, while all output was discarded.
App self-removal now uses a one-shot PID-scoped `launchctl submit` worker. The
worker waits for the tray's post-Geph-cleanup ready marker, validates the bundle
and exact tray PID, removes the staged bundle, and removes its own launchd label
on every exit path. The regression test must prove that the app, staged bundle,
ready marker, and submitted worker are all gone.

## Geph Exit Locations

The Geph submenu normally lists city-level exits such as `CA / Montreal`. On a
fresh launch, Geph may not have answered its local control RPC yet. Until a live
or cached verified catalog exists, Slipstream shows an unavailable state rather
than a fabricated country-level fallback list. Saving an account, enabling
Geph, or selecting `Restart Proxy` starts a fresh bounded catalog poll, so a tray
restart is not required.

If the menu remains unavailable after Geph is connected, use `Open Status` and
inspect `geph_logs`. The owned LaunchAgent writes private `0600` stdout/stderr
logs instead of discarding startup errors. The app caches the last verified city
catalog locally, so later launches should show the city list immediately even
while Geph is reconnecting.

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
`/var/run` and releases only that reference during normal teardown.

If a pre-anchor build left a global HTTPS redirect targeting Slipstream's local
port, the current daemon treats the matching signature as an unowned conflict.
It disables only its own launchd label, clears its private anchor and token,
reports the conflict, and exits. It never reloads `/etc/pf.conf`: a root ruleset
listing cannot prove which product owns those rules. Inspect and remove the
legacy rules explicitly before selecting `Restart Proxy`.

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

A recurrence on 2026-07-13 stopped only after the root launchd label was
disabled, `com.apple/slipstream` was empty, the owned PF token and all
Slipstream/Geph processes were absent, and the application retried natively.
The user-managed `111.88.96.50/111.88.96.51` DNS configuration was unchanged.
This confirms a stale transparent lifecycle path, not DNS replacement, as the
incident boundary. The source already contained the zero-byte close guard, but
the installed lifecycle did not guarantee that the fixed daemon was loaded or
that a partial install rolled back.

A separate 2026-07-18 uninstall incident produced a repeatable
`Reconnecting 5/5` followed by stable operation. Two effects overlapped:

1. The old tray stopped owned Geph before stopping the root daemon, while the
   daemon handled `SIGTERM` with immediate `os._exit`. Accepted TCP streams were
   therefore cut instead of drained.
2. The user-managed Smart DNS resolved several OpenAI hostnames to
   `87.228.47.204`. Unified networking logs showed an otherwise viable HTTP/3
   connection timing out after about 180 seconds, and Chromium's persistent
   network state recorded repeated broken QUIC attempts before the app settled
   on working TCP.

The second observation does not mean Slipstream intercepted QUIC: the macOS
adapter captures TCP only, and global UDP/443 remains untouched. It explains
why a fixed number of app retries can continue after every Slipstream process,
listener, launchd job, and private PF rule is already gone. The owned fix is to
quiesce the listener and PF first, drain accepted TCP streams within a deadline,
and stop Geph only afterward. Slipstream must not rewrite the user's DNS or add
a global QUIC block to hide an application or Smart-DNS transport fallback.

The user observed `Reconnecting 5/5` again on 2026-07-19 after confirming that
the Slipstream launchd job, listener, private PF rules, token, and processes
were absent and no system proxy was active. That symptom alone therefore does
not prove an active Slipstream interception path. Installing the affected build
still reproducibly triggered a separate broad HTTPS outage, so both facts must
remain visible instead of assigning every later reconnect to one cause.

The 2026-07-19 clean-install incident exposed a separate lifecycle defect.
Exact-main `0.1.8` installed a healthy listener but kept the daemon `dormant`
because the whole private PF anchor was gated on an owned Geph listener. With
no Geph account configured, Discord and YouTube therefore received no local
bypass at all. The packaged smoke had masked this by injecting `SLIP_GEPH=0`
after installation. Clean install and reinstall now have to become `active`
without that patch and without any Geph account or listener.

The repaired artifact then exposed a data-plane baseline defect on the primary
workstation. PF correctly redirected TCP/443 into the daemon, but direct,
unknown, non-TLS, and TLS-without-SNI connections still entered the generic
local engine. That engine could replace the original destination with a DoH
answer, select desync for an unclassified host, and wait for a first server
payload before relaying. Installing Slipstream therefore changed ordinary HTTPS
even when no policy requested a bypass. The transparent baseline now opens the
exact pre-PF numeric destination, sends the buffered bytes unchanged, and starts
bidirectional relay immediately. If an unknown connection fails, local recovery
is deferred to a later client retry so a consumed TLS first flight is not
replayed.

A later doc-only CI rerun reproduced the broad outage before this repair was
merged: packaged Safari reported `You Are Not Connected to the Internet` at
`before-tray-start` while `com.apple/slipstream` was active. That disposable
failure confirms the baseline bug without requiring another install on the
primary workstation. The same packaged browser gate must pass on the exact
repair commit before any guarded workstation smoke.

Required behavior:

- arm the private PF anchor when the proxy listener and local routing capacity
  are ready, regardless of whether optional Geph is configured;
- never report Geph up without a verified port;
- on runtime geo-exit failure, including a successful SOCKS connection followed
  by an early zero-byte remote close, cool down only Geph and keep local bypass
  active; the consumed stream closes, while the next client retry may use the
  original destination selected by the user's DNS/VPN/system route;
- never move a geo-exit host into the local desync ladder merely because an
  app-owned backend is absent;
- preserve direct, unknown, non-TLS, and no-SNI traffic on the exact pre-PF
  destination without alternate DNS, desync, or first-payload probing; an
  unknown-host recovery may begin only on a later client retry;
- do not let tray polling restart a live Geph process from endpoint failures;
- on uninstall, clear the listener/PF path before a bounded accepted-stream
  drain, and keep the verified owned Geph backend alive until that drain ends;
- on file-descriptor pressure, pause only `com.apple/slipstream` before accept
  failures can strand the machine behind a non-serving listener;
- do not modify DNS, proxy, PAC, VPN, certificates, Keychain, or network plist
  files as a workaround.

Emergency cleanup remains scoped to Slipstream. Prefer the transactional
uninstaller; the second command is the fallback when the installed copy was
already removed:

```bash
sudo /usr/local/slipstream/slipstreamd --uninstall
sudo "/Applications/Slipstream.app/Contents/Resources/slipstreamd/slipstreamd" --uninstall
```

Do not use a global `pfctl -F states`, `pfctl -d`, or replacement DNS as normal
recovery.

## External DNS, Proxy, PAC, VPN

Slipstream does not own external DNS, proxy, PAC, or VPN settings. If one of
them is active, treat it as outside state:

1. Record it in diagnostics.
2. Warn when it may bypass Slipstream routing.
3. Do not disable, rewrite, restore, or replace it automatically.

Every combination is valid: a user may have an external VPN, custom DNS, both,
or neither. Slipstream must not require or infer any one of them, and its owned
Geph backend is optional rather than a substitute for the user's environment.

This includes user-managed DNS services such as `xbox-dns.ru`. They may be part
of the user's working setup, but Slipstream should not silently enable or remove
them. A direct fallback reuses the exact destination selected before PF and
lets macOS route the new plain connection without changing external state. If a
full-tunnel VPN owns the default `utun*` route, Slipstream instead clears only
its own anchor and stays dormant. Split/per-app VPN equivalence is a separate
qualification boundary and is not inferred from full-tunnel behavior.

Slipstream's on-demand Xbox DNS fallback is separate from that external state:
after a local failure for one generic hostname, it can make one verified DoH
query and try the returned address locally. It never changes the system resolver
configuration.

For a partial page that becomes blank after a long wait, one orderly browser
close is intentionally treated as ambiguous. The generic local relay records
that the client closed first before stopping its now-undeliverable upstream read.
Two client-first closes after a long downstream silence for the same generic host
schedule that exact local DNS retry. This is process-local, expires automatically,
and does not route the host through Geph. The retry can use the same IP if Xbox
DNS and the normal resolver agree, so it is evidence-gated recovery rather than a
guaranteed alternate route.

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
geo-exit failures across multiple hosts schedule owned recovery. The daemon
blocks new owned-Geph sessions, cools only that backend, waits for active
owned-Geph streams to drain, and kickstarts the exact verified user LaunchAgent.
The private PF anchor and local bypass remain active; the tray is not required.
LaunchAgent `KeepAlive` still handles a process that exits on its own.

While a long-lived Geph stream is active, StatusV2 may briefly report
`owned_geph_restart_waiting_for_idle`. This is a bounded safe wait, not a request
for manual action. A mismatched ownership claim or unknown listener is never
restarted; diagnostics retain that distinction.

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

## Unknown-Host Recovery

Slipstream does not turn an unknown host into `geo_exit` from a local failure
plus a successful Geph probe. That result cannot prove that a foreign exit is
needed.

For a repeated exact-host local stall, Slipstream may make one local retry via a
Slipstream-issued Xbox DNS query. It neither changes the system resolver nor routes
the host through Geph. Existing legacy auto-Geph cache entries are cleared when
the daemon starts.

If a browser-only page still stalls, collect diagnostics and the exact hostname.
The appropriate next step is an evidence-backed direct, local-bypass, or
geo-exit policy change, not automatic foreign-exit promotion.

Google and Spotify use `direct_first`: the next connection always starts with
plain TLS, then can use bounded local desync only if direct did not work. They
never fall through to Geph.

## Installed Daemon

After rebuilding the daemon, keep all copies in sync:

```bash
shasum -a 256 \
  spike/dist/slipstreamd/slipstreamd \
  app-tauri/src-tauri/slipstreamd/slipstreamd \
  /Applications/Slipstream.app/Contents/Resources/slipstreamd/slipstreamd \
  /usr/local/slipstream/slipstreamd
```

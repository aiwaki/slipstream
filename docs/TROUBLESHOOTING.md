# Troubleshooting

This page keeps operational checks short and current.

## Routing Model

Use local bypass for DPI/SNI interference:

- Discord
- YouTube web and control hosts
- other hosts listed as local-bypass policy

YouTube media hosts under `googlevideo.com` use `direct_first`: an unmodified
TLS first flight is always attempted before a bounded local desync fallback.
They remain protected from Geph, Smart DNS, app-owned Xbox DNS, and generic
unknown-host promotion.

Use Geph only for services that need a foreign exit because the service rejects
Russian IP addresses. Do not route Discord or YouTube through Geph as a fix.

### A clean Chrome profile stays at `about:blank` after protected qualification

First verify that the exact Slipstream companion is installed and enabled in
the affected branded-Chrome profile. The user native-host manifest proves only
that an already installed extension with the allowed origin may start the
host; it does not install the extension. The protected qualification uses a
fresh profile with the reviewed source loaded as an unpacked extension, so its
success does not prove Chrome Web Store delivery to an ordinary clean profile.

Transaction `271C43D9-4906-4AF3-88E8-C2EF146A33ED` exposed this boundary: the
packaged daemon was active and the native-host manifest was present, but the
clean browser profile had no companion, emitted no semantic/recovery event,
and remained pending for 75 seconds. Exact rollback restored the previous
application and all network/runtime invariants. Do not compensate by weakening
the navigation signal, closing a quiet relay from byte count alone, or routing
the host through Geph without the normal independent evidence. Production
qualification requires the reviewed extension ID
`cecdingohhpfggapnlbghppcegbaciam` to be installed and enabled in that actual
profile.

### YouTube page loads but video playback fails

Check the effective packaged policy without starting or installing the daemon:

```bash
/Applications/Slipstream.app/Contents/Resources/slipstreamd/slipstreamd \
  --classify-host rr1---sn-test.googlevideo.com
/Applications/Slipstream.app/Contents/Resources/slipstreamd/slipstreamd \
  --classify-host www.youtube.com
```

The media host must report `direct_first/direct_first`; the web host must report
`local_bypass/fake_only`. Either host reporting `geo_exit/geph`, or a media host
reporting direct-only or fake-only routing, means the packaged daemon is stale
or misqualified. Do not compensate by enabling Geph for YouTube.

A successful YouTube HTML request does not prove media delivery. The controlled
2026-08-03 transaction reached the real Googlevideo host and selected an actual
media format, then all ten `yt-dlp` retries ended with
`UNEXPECTED_EOF_WHILE_READING`. The affected build had already counted the
initial TLS payload as local-route success and did not evaluate the later
server-first close because Googlevideo is `direct_first`, not literal
`local_bypass`.

Current protected-local recovery keeps valid TLS framing through the relay. A
single orderly short or medium close is provisional; one reset or incomplete
TLS record, or two matching closes for the same host, strategy, and close kind
within five minutes, demotes only that local strategy and starts an exact-host
local re-sweep. Medium means a complete-record server-first close between
`32 KiB` and `512 KiB`; it never combines with short-close evidence. If `plain`
failed for Googlevideo, the next request starts with a local desync strategy for
one minute and then rechecks direct. If that active fallback produces one
matching medium close, it is demoted immediately so a client retry can continue
through the local ladder. A provisional medium close is not enough to demote a
strategy, but it also is not recorded as local-health success. This path has no
Geph action.

The private daemon log records an armed observation as
`protected-local recovery armed` with host, service, strategy, close kind,
bytes, and duration. Repeated failures without that event indicate that the
installed daemon predates this correction or that the close is outside the
bounded signal and needs a fresh log-backed investigation.

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
watchdog recovery. A missing or stale snapshot does not authorize a restart
while the daemon's owned loopback listener is still reachable. If both status
and listener remain unavailable, repair waits for a bounded fresh-status window;
failure may clear only Slipstream's owned network state and must not write a
durable disabled override.

The watchdog runs only when launchd reports the Slipstream label explicitly
enabled. A missing or disabled label is not repaired at startup. `Restart Proxy`
is the explicit action that may reinstall or re-enable it.

### A reviewed Geph route stalls while the direct site works

A live owned SOCKS listener proves only that the local Geph process accepted a
stream. It does not prove that the selected exit has delivered the target
server's TLS response. The 2026-08-10 workstation transaction reached active
StatusV2 and passed the shared Geph canaries, but a later Steam Store session
still stalled before its first target byte; the same origin returned more than
one MiB directly after exact rollback.

Runtime geo-exit handoff therefore keeps the buffered client first flight until
one target byte arrives through that exact Geph stream. SOCKS setup and the
first target read share one four-second deadline. Timeout, EOF, or reset before
payload closes only that stream, cools only the owned geo backend, logs the
reason, and tries the frozen original system destination on the same request.
Once a target byte has reached the client, replay is forbidden and normal relay
recovery applies. This fallback never changes the route policy, DNS, PF,
proxy/PAC/VPN, or external Geph and cannot send Discord, YouTube, or
Googlevideo through Geph.

### An unknown site fails while unrelated pages are also noisy

The network-wide unknown-host guard prevents a burst of unrelated failures from
teaching Slipstream that many sites need a foreign exit. An older build also
used that guard to discard a complete proof for the exact request already in
progress. In the reproduced case, Modrinth closed before TLS payload through
the system route, app-owned DNS, and multiple local strategies while the exact
owned Geph listener independently returned a complete HTTP `200`; the daemon
never attempted it and logged no host outcome.

Current behavior keeps the guard for every learned or persisted route but may
spend the complete exact-host zero-payload proof once on the current replay-safe
request. Its authorization and any older candidate are marked spent before the
owned-Geph attempt, while the observations remain until normal expiry so the
global guard stays active. Every mandatory stage must fail again before another
one-shot is possible. A successful first-payload gate serves that request only
and logs `used one-shot owned Geph`; it does not schedule background
confirmation. Any candidate, post-drain retry, or active confirmation created
before the wider noise appeared is invalidated immediately and cannot wake up
after the noise window expires. A candidate-backed request spends the same
exact proof before waiting for Geph, so noise that appears during its dial or
first-payload read cannot make that proof reusable by another request. If the
owned backend is briefly recovering, the spent proof still authorizes only
that current request; loss of learning authority does not strand it.
Regional-denial and incomplete-response workers also recheck revoked authority
immediately before persistence, including workers still performing their plain
precursor probe when noise appears. Eligibility, confirmation-token reservation,
noise evidence, and route persistence share the same lock, so an observation
cannot appear between authorization and reservation or between the final check
and the write.
Persistent learning starts again only from a
fresh complete proof on a quiet network. A failed one-shot attempt is not
reusable. This path remains unavailable to static routes, Discord, YouTube,
Googlevideo, external Geph, and external network settings.

The first one-shot may still finish its local proof near the browser's own TLS
deadline. When owned Geph then returns real server payload but the downstream
client has already closed, current builds retain one exact-host successor for
30 seconds. The next request consumes it before any network wait and tries the
same ownership-verified Geph backend before repeating system, app-owned DNS,
and local-strategy checks. A missing first payload falls back to the normal
sequence with no token left. A consumed successor cannot create another one,
and it never learns or persists a route. A log line containing
`retained one bounded successor` followed by `successor` on the next request is
the expected recovery; repeated full local ladders without those events need a
fresh timing investigation.

### A site partially loads or owned Geph returns `local_rate_limited`

An HTTP/2 page may return status `200` and tens of kilobytes before its stream
ends without `END_STREAM`. Rechecking that host with HTTP/1.1 is not equivalent:
the origin or network can complete one protocol and truncate the other. Current
completion recovery therefore advertises `h2` plus `http/1.1` and validates the
protocol actually negotiated. HTTP/2 is incomplete only after successful
response headers and body bytes followed by reset, EOF, or deadline before
`END_STREAM`; a local byte cap is unknown, not failure.

HTTP/2 framing errors are also unknown and cannot authorize a route. A
`GOAWAY(NO_ERROR)` whose `last_stream_id` still includes the active probe stream
is a normal connection drain: Slipstream keeps reading that stream until
`END_STREAM`, a real transport interruption, or the existing deadline. A
`GOAWAY` with an error code or one that excludes the stream is unknown rather
than evidence of truncation. Once an eligible graceful drain begins, any new
`PUSH_PROMISE` is a protocol error; only streams that were already eligible may
finish. A later GOAWAY may retain or lower the accepted `last_stream_id`, but
cannot increase it.

One narrow partial-frame case is not a framing error. After valid response
headers and earlier identity body bytes, the peer may send a valid DATA header
for the active stream and then stop before that declared DATA payload is
complete. Slipstream treats this as an interrupted response only when the frame
header, negotiated size, stream identity, available payload prefix, and padding
are all valid and its declared data length does not exceed any `Content-Length`.
The complete nine-byte header is sufficient for a nonempty unpadded DATA frame;
a padded frame also requires its padding-length byte. A partial DATA frame
without earlier body bytes, or any partial header, control, wrong-stream,
oversized, malformed, or length-exceeding frame remains unknown.

The live relay's partial TLS-record watchdog expires before its longer
payload-idle observer. For an exact unknown `system/plain` connection, that
watchdog therefore preserves the exact public-IP candidate. It does not probe,
select Geph, or learn from encrypted bytes until the independent system,
app-owned DNS, and multiple local-strategy evidence ladder is complete. The
route can change only after that ladder, a direct certificate-validating probe
that independently proves incomplete, and a complete usable response through
the currently verified owned-Geph listener.

If the body reaches the probe's local byte cap without `END_STREAM`, it is
capped and unknown rather than proven incomplete. A response exactly at the cap
is accepted only when HTTP/2 also proves stream completion.

The independent owned-Geph proof must complete the same negotiated protocol.
It remains bounded to two MiB and 20 seconds because an origin may ignore a
range request and return a roughly one-MiB document. `429 local_rate_limited`,
compressed or incomplete data, regional-denial content, an unowned listener,
and protected/static routes cannot authorize an exact-host overlay. This is a
generic transport contract, not a rule for the hostname that exposed it.

A partial page can return HTTP `200` and still end with curl error `18`, a
blank browser document, or missing assets after tens or hundreds of KiB. A
successful status line, TLS handshake, or first payload is therefore not a
complete-response check. One bounded system/plain server-first close remains
ambiguous and inert. A second matching close, including a short compressed
response or an ambiguous response between 32 KiB and 512 KiB, may run one
bounded HTTP-framing probe against the first public system-selected IP. It no
longer waits for the same user-visible failure to repeat through Xbox DNS and
two local strategies. Xbox DNS remains the next local fallback, while opaque
byte count and repetition cannot select Geph or learn a route. A visible
network-wide unknown-host failure blocks this early probe. A complete response
ends the incident. Only a strictly proven local body shortfall
followed by the existing complete owned-Geph proof can learn a temporary
exact-host route.

A live owned Geph process and listener do not guarantee a usable exit session.
Workstation A/B evidence on 2026-07-30 and 2026-08-01 received partial direct
responses, then HTTP `429` with body `local_rate_limited` through the verified
owned `:9954` listener. One incident recovered after the first exact
`dev.slipstream.geph` PID replacement; the later incident required a second
replacement before the same request returned a complete HTTP `200` response.

The 2026-08-02 controlled transaction found a second form of the same problem:
a generic unknown host completed the local evidence ladder, the one-shot Geph
stream delivered encrypted payload, and Slipstream learned the route before an
independent HTTP check. The next request then received persistent HTTP `429`
with `local_rate_limited`. Encrypted TLS payload therefore no longer authorizes
a learned route. Generic learning requires two consecutive complete, usable
HTTP responses on independent owned SOCKS sessions; unsuccessful, incomplete,
or over-deadline responses cannot clear backend hold or create the route.

Current recovery drains active owned sessions once, verifies the listener and
LaunchAgent ownership before every replacement, and requires a changed live
PID. It may perform at most two replacements, repeating the same two-response
proof after each and stopping immediately on stable success. The exact host is
learned only after that proof. A new recovery incident is globally rate-limited
for ten minutes.

Listener and control-port liveness are not payload readiness. Transaction
`7D29A3E8-1B4C-4E51-A2D8-8A2E6A5164C7` observed a new exact owned listener
before Geph had completed authentication and opened a usable exit session. An
immediate semantic retry therefore failed without opening the target tunnel and
spent both replacements. After each replacement, current recovery pins the
successor PID and waits in the background for one existing portfolio HTTPS
canary to meet its payload threshold through that same PID. Only then does it
retry the target's independent semantic probe. This wait is bounded to twenty
seconds by one absolute deadline across SOCKS, TLS, request, and response
operations; PID drift, ownership conflict, listener loss, shutdown, or no payload
remains fail-closed and cannot learn a route. The target response itself and
the final route write are checked against the same pinned PID, so a KeepAlive
replacement during the target probe also fails closed.

A `launchctl kickstart -k` timeout is not evidence that the mutating command did
nothing. The 2026-08-03 workstation transaction observed the exact owned
LaunchAgent replace its listener PID after the shared five-second command bound
had already expired. Recovery therefore treats this result as indeterminate,
keeps the backend drain active, and waits only for a different listener that
passes the complete exact-ownership and readiness checks. If no such successor
appears within the bounded window, or an unknown listener appears, recovery
fails closed and does not issue a duplicate kickstart.

For a long-lived one-shot relay, the independent proof starts after its first
payload rather than after connection close. If that worker fails while the
relay prevents session drain, Slipstream retains one post-drain retry and
consumes it after the active session finishes; no unbounded retry chain is
created.

Do not work around this symptom by adding the hostname to static policy,
restarting an external Geph process, or changing system DNS, proxy, PAC, VPN, or
PF state. Discord, YouTube, and Googlevideo remain excluded from Geph.

### Steam activity is followed by broad failures and an administrator prompt

The 2026-07-26 workstation incident began with a working root daemon carrying
large Steam flows. Status publication then fell behind while the process and
listener were still alive. The tray treated three missing two-second polls as a
dead daemon, opened a privileged repair prompt, ran `kickstart -k`, waited only
three seconds, then executed `launchctl disable` and `bootout`. The daemon's
normal shutdown cleared `com.apple/slipstream`; Discord local bypass and every
other transparent route disappeared together. Slipstream's owned Geph
LaunchAgent remained alive because this was watchdog recovery, not uninstall.

The decisive launchd sequence was:

```text
osascript -> authtrampoline -> launchctl kickstart
launchctl disable system/dev.slipstream.tproxy
launchctl bootout system /Library/LaunchDaemons/dev.slipstream.tproxy.plist
```

This sequence occurred before the diagnostic log-copy prompt. Reading or copying
the root log did not disable the daemon.

Current behavior treats the listener as independent liveness evidence, bounds
every daemon system command, and strips inherited `Malloc*` debugging variables
from child commands. Automatic watchdog cleanup no longer writes
`launchctl disable`. If the same symptom returns, preserve the launchd and root
log timestamps before using `Restart Proxy`; do not infer that Steam, DNS, or
the log viewer directly disabled routing.

During exact-artifact installation on the same workstation, unprivileged
`lsof` omitted the live root-owned TCP/1080 listener while `netstat` reported
`slipstreamd:<pid>` and the socket was reachable. The tray now uses `netstat`
only as a PID fallback, then requires that PID's exact installed command to run
as root; a mapped executable returned by `lsof` must still match. Unknown or
user-owned listeners are never accepted or terminated.

### Install validator reports `Permission denied` for `slipstreamd`

The installed frozen daemon and its directory are root-only (`0700`). An
unprivileged tray or temporary coordinator must never open
`/usr/local/slipstream/slipstreamd` to compare its bytes. The 2026-07-28
workstation transaction did that after an otherwise healthy install, received
`Permission denied`, and correctly rolled back.

PR #245 CI run `30349298867` also proved that mode `0700` is too restrictive:
both installed lifecycle jobs kept the daemon safely dormant because the old
console-user baseline child tried to execute the installed runtime. Run
`30350707555` then proved that execute-only `0711` is still insufficient:
PyInstaller reads its own executable while starting. No workstation was
mutated in either run. The corrected boundary keeps the installed runtime
root-only and runs bounded console-user DNS and HTTPS qualification through
fixed `/usr/bin/dscacheutil` and `/usr/bin/curl` children instead. The curl
child ignores user configuration and proxy environment and must return a
verified HTTP status plus header bytes.

The privileged installer now hashes the source before mutation, verifies the
installed regular file after launch, and requires exact owner, mode, launchd
PID, exclusive listener, fresh StatusV2 state, and matching private-PF state.
Only then may it atomically publish
`/Library/Application Support/dev.slipstream.tray/install-attestation.json`.
That persistent root-owned record survives reboot. A sibling root-only hard-link
witness retains the installed daemon inode without exposing its bytes; deleting
or replacing the installed path reduces or changes that identity and invalidates
the record even though the tray cannot traverse the `0700` install directory.
The tray accepts the bounded record only when its source and installed SHA-256
equal the current bundled daemon and the witness still has the exact attested
device/inode with at least two links. Missing, oversized, symlinked, stale, or
mismatched evidence requests a normal privileged reinstall. Any publication
failure executes the same exact rollback and removes the evidence, witness, and
temporary artifacts.

### Install rolls back with `status missing`

The 2026-07-20 controlled workstation validation found a startup ordering bug.
The exact packaged daemon started its owned listener and reached the standalone
Telegram-proxy check, then blocked in the first synchronous system-DNS lookup
for the neutral HTTPS baseline. Because StatusV2 was published only after that
qualification, the installer timed out with `status missing` and invoked its
normal rollback. The rollback removed the launchd job, installed runtime,
listener, status, PF token, loopback lease, and private-anchor state without
changing the user's DNS or proxy settings.

Current required behavior is different: publish a probe-free `dormant` snapshot
as soon as the listener is owned, resolve each baseline target in a separate
killable console-user child with a short timeout, continue to later targets,
and enforce one total preflight deadline. Regular status publication uses only
cached DNS diagnostics; their background refresh is bounded separately. A
timeout must leave PF absent and may only schedule a later qualification
attempt. Do not repeatedly reinstall on a workstation to diagnose this symptom;
the disposable packaged lifecycle blackholes the first neutral macOS resolver
target and must prove status-before-query, later-target activation, helper exit,
and cleanup first.

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

The root uninstaller disables the launchd label, clears only the private PF
anchor, and then boots out the launchd `KeepAlive` job before signalling any
surviving process. A PID is signalled only after revalidating the installed
daemon command; an old PID that disappeared during `bootout` is already clean.
Install and reinstall use the same quiescence transaction and do not replace
the existing runtime until launchd absence, listener shutdown, private-anchor
cleanup, leased `lo0` restoration, and owned-token release are all proven.
If `bootout` fails and launchd still reports the job loaded, no process is
signalled. After launchd and every verified survivor are quiescent, cleanup
flushes the private anchor and restores the leased `lo0` state a second time so
a final monitor tick cannot re-arm during removal. It reports failure if a
verified surviving daemon PID resists the bounded stop. Only then does it remove
the plist, owned runtime, and status, and release the owned PF token. The token
record is removed only after a successful release. If the installed uninstaller
was already deleted, the tray uses the copy inside the application bundle. A
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

macOS may show `lo0 (skip)` in the live kernel PF interface table even when no
corresponding `set skip on lo0` line exists in `/etc/pf.conf`:

```bash
sudo pfctl -v -s Interfaces
```

That flag prevents a private `route-to`/`rdr on lo0` path from reaching the
listener. Slipstream loads its private rules first, atomically records a
root-owned `0600` lease, clears only `PFI_IFLAG_SKIP` with the native PF ioctl,
and verifies the result. Every rollback flushes the private anchor, restores
and verifies the original skip flag, removes the lease, and only then releases
the owned PF token. Do not clear the flag manually or use Control-D/global PF
reload as a workaround.

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

Real mode refuses to start if Slipstream status, token, loopback lease, or
private-anchor state already exists. It targets a high test port and never
TCP/443.

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
clear the private PF anchor before closing its listener, drain accepted TCP
streams within a deadline, and stop Geph only afterward. Slipstream must not
rewrite the user's DNS or add
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
even when no policy requested a bypass. The transparent baseline first tries the
exact pre-PF numeric destination. For non-TLS, no-SNI, direct, and protected
routes it remains a byte-transparent passthrough. For an eligible unknown TLS
request, a zero-server-byte close means the buffered first flight has not been
exposed downstream and is still safe to retry. That same request may therefore
continue through per-connection app-owned DNS and the local strategy ladder. It
may reach verified owned Geph only after the system route, app-owned DNS, and
two distinct local strategies have each closed or hit their owned bounded
first-payload timeout with zero server bytes, and the complete exact-host
evidence gate passes. Once that proof exists, waiting for additional local
strategies only risks client cancellation and does not add authorization. The
first server byte commits the route and forbids replay. An orderly client EOF
is still propagated as a bounded TCP half-close so a delayed server response is
delivered.

A later doc-only CI rerun reproduced the broad outage before this repair was
merged: packaged Safari reported `You Are Not Connected to the Internet` at
`before-tray-start` while `com.apple/slipstream` was active. That disposable
failure confirms the baseline bug without requiring another install on the
primary workstation. The same packaged browser gate must pass on the exact
repair commit before any guarded workstation smoke.

The automatic guard verifies a small neutral HTTPS baseline as the console user
before PF is loaded, then repeats only the exact pre-proven numeric destinations
after the private anchor is active. A preflight failure leaves PF untouched. A
postflight failure removes only `com.apple/slipstream` and blocks re-arm until a
real wake or network change. If PF cleanup is temporarily unavailable, the
listener and runtime stay alive while cleanup is retried; install, uninstall,
and force-stop paths must not create a redirect to a dead listener. Public
status exposes only the generic recovery reason, not probe hosts or addresses.

The first packaged run of this guard found an uninstall ordering regression in
disposable CI: the daemon was signalled while its loaded `KeepAlive` job could
still supervise it, and `bootout` happened only after waiting on the old PID.
The command then reported incomplete cleanup even though the private anchor had
been cleared. The lifecycle is now ordered as private-anchor clear, launchd
`bootout`, then exact-identity cleanup of any surviving PID. This prevents a
replacement process from appearing during removal and treats a process already
terminated by `bootout` as a successful outcome.

The primary-Mac post-arm failure had a lower-level cause: the kernel reported
`lo0 (skip)`, so loaded private rules could not receive the traffic redirected
back to loopback. A high-port probe, separate from installation and TCP/443,
proved that clearing only the skip bit made the exact redirect topology work
and that rollback restored the original bit, global PF rules, external
sentinel, anchors, token, lease, status, and listener state. Until the matching
packaged lifecycle gate passes, this proof is not permission to install an
unqualified build on a workstation.

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
- preserve direct, protected, non-TLS, and no-SNI traffic on the exact pre-PF
  destination without alternate DNS, desync, or first-payload probing; an
  eligible unknown TLS request may continue through the bounded recovery ladder
  only while zero server bytes have reached the client;
- do not let tray polling restart a live Geph process from endpoint failures;
- on uninstall, clear the private PF anchor before closing its listener, then
  perform a bounded accepted-stream drain while the verified owned Geph backend
  remains alive;
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
configuration. Recovery is ordered and bounded for every eligible unknown TLS
hostname; it is not a per-site list:

1. Preserve the exact destination selected by the user's current system route.
2. After evidence of a failed generic stream, try app-owned Xbox DNS locally.
3. If that route also fails, continue through the local DoH/strategy ladder.
4. Only after the exact host exhausts system, app DNS, and at least two distinct
   local strategies without receiving a server byte, confirm a real payload
   through the currently verified owned Geph and remember a temporary route.
   Explicit EOF and a bounded first-payload timeout can prove one completed
   attempt; cancellation, connect failure, generic probe error, or incomplete
   address-race evidence cannot.
5. Recheck the original system route after the bounded recovery/overlay window.

One failed route, a successful Geph probe by itself, or a network-wide outage
cannot select Geph. Discord, YouTube control, Googlevideo media, reviewed
geo-exit services, direct routes, and traffic without usable SNI keep their own
policies and never enter this generic sequence. A generic exact host advances
beyond the local ladder only under the complete zero-payload gate above or the
separate framed-record proof below.

For a partial page that becomes blank after a long wait, one orderly browser
close is intentionally treated as ambiguous. The generic local relay records
that the client closed first before stopping its now-undeliverable upstream read.
Two client-first closes after a long downstream silence for the same generic host
schedule that exact local DNS retry. This is process-local, expires automatically,
and does not route the host through Geph. If Xbox DNS produces the same broken
route or its stream later stalls, the host advances to the local strategy ladder
instead of returning immediately to the first system route. The retry can still
use the same IP when resolvers agree, so recovery is evidence-gated rather than a
guaranteed alternate route.

A synthetic uncompressed HTTP probe can stall even when a compressed main
document completes. Neither result alone proves browser health. A blank page
can be caused by mandatory same-origin CSS or JavaScript stopping after an
initial TLS record, while a bare-HTML view can also survive in browser cache
after the network path is healthy. Qualification therefore uses a fresh
owner-only profile, rejects browser error pages, and requires the main document,
mandatory CSS/JavaScript/images, and a nonblank styled DOM. Reopening the user's
existing profile is diagnostic context, not a routing pass. A successful
connect, first TLS payload, or main-document `200` is not enough.

An unknown route can also end immediately after one or more complete TLS
records. Slipstream cannot decrypt the response to compare HTTP
`Content-Length`, and it cannot safely replay a request after any server byte
has reached the browser. It therefore adapts only the next connection. An
upstream reset or incomplete TLS record inside the first 32 KiB and 10 seconds
is exact host-and-stage evidence; an orderly short server-first EOF requires
two observations for the same host and stage inside five minutes. A larger,
later, client-first, or otherwise healthy completion clears provisional state.
This advances only the existing system, app-owned Xbox DNS, and local-strategy
sequence. It is not a per-site rule and one early close cannot select Geph.

When the exact system destination, app-owned Xbox DNS route, and at least two
distinct local strategies each complete at least one TLS record but leave the
next syntactically valid framed record incomplete beyond the idle bound,
Slipstream can run one stronger confirmation for that exact unknown host. A
connection failure, attempted stage, or one orderly complete-record close is
not this proof. The bounded repeated server-first evidence above can contribute
the same stage observation without weakening the remaining gate. Confirmation
requires a clear network-wide failure guard and a real HTTPS payload through
the explicitly enabled, ownership-verified bundled Geph. Only then may the
daemon remember a private, expiring exact-host `geo_exit` overlay. The
classification remains active during an owned-Geph cooldown so the next client
retry uses the exact pre-PF system destination instead of replaying the failed
local ladder. The learned route may dial Geph only while the current listener
remains verified as Slipstream-owned on the owned port. Static policy remains
authoritative, and repeated owned-Geph runtime misses discard the overlay. This
path does not use or stop external Geph and does not change system DNS, proxy,
PAC, VPN, or PF policy.

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

After wake or an unrelated tunnel failure, a Geph process can keep its control
RPC and local SOCKS port open while payload probes stall or close without a
response. Slipstream records this under `geph_detail`; process/listener
readiness alone is not a healthy result. Repeated hard payload failures across
multiple geo-exit hosts may schedule owned recovery. Soft/optional canaries do
not. The daemon blocks new owned-Geph sessions, cools only that backend, waits
for active owned-Geph streams to drain, and kickstarts only the exact verified
user LaunchAgent. External or ownership-mismatched listeners contribute no
restart evidence. The private PF anchor and local bypass remain active; the
tray is not required. LaunchAgent `KeepAlive` still handles a process that exits
on its own.

When the owned backend becomes verified ready again, Slipstream retries only a
small bounded set of still-valid exact-host confirmations whose earlier attempt
was consumed by backend failure. It does not reset all routing evidence and it
does not admit Discord, YouTube, Googlevideo, direct routes, or static policy
into Geph.

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

Slipstream does not turn an unknown host into `geo_exit` from an ordinary local
failure plus a successful Geph probe. That result cannot prove that a foreign
exit is needed.

For a repeated exact-host local stall, Slipstream may make one local retry via a
Slipstream-issued Xbox DNS query, then continue through distinct local
strategies. It never changes the system resolver.

If a browser visibly remains on `about:blank` but copying the address produces
the requested site, the target navigation is pending and has not committed its
first document. This is not evidence that the browser opened the wrong URL.
The daemon must not infer this browser state from a quiet connection. After
eight seconds, the companion may send a privacy-bounded `navigation_pending`
signal only while the same top-level HTTPS `pendingUrl` is still loading. The
daemon then correlates its hostname and request start to one live public
unknown-host relay with valid complete TLS records, less than 8 KiB of server
data, and no recent downstream progress. Only that relay may close so the
browser can decide whether to retry; the daemon does not replay the encrypted
request. Each retry advances one local stage. After the full system, app-owned
DNS, and two-strategy ladder, the final relay remains open unless independent
direct and owned-Geph confirmation was actually scheduled and succeeded.
Direct, static, and protected routes are excluded. A curl response that consists
of a JavaScript challenge does not replace a fresh real-browser check for this
symptom.

If every required local stage completes one TLS record but then leaves the next
framed record incomplete, the daemon may confirm a real HTTPS payload through
its verified owned Geph and learn only that exact unknown hostname temporarily.
A complete quiet record, ordinary connection failure, network-wide failure, an
unavailable or unowned backend, an explicit policy, or a different failure
shape cannot authorize this overlay. This avoids per-site rules while keeping
local bypass and direct routes out of Geph.

If that complete exact-host proof coincides with a brief owned-Geph recovery,
the replay-safe request waits for at most five seconds and actively probes the
exact owned listener instead of relying on the periodic monitor. Listener
ownership and port conflicts are rechecked throughout the wait. A successful
real payload through the exact owned `:9954` listener also clears an older
backend hold so the page's following resources use the confirmed route
immediately. Missing proof, a failed payload, an external listener, or an
ownership conflict does not wait, clear the hold, or select Geph.

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

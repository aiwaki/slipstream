# Current Project State

This is Slipstream's compact continuation checkpoint. It exists so a resumed or
automatically compacted agent does not reconstruct project state from the last
chat message, an old summary, or a milestone name alone.

The checkpoint is a locator, not authority. Repository state, merged PRs,
required CI, and current source code always win when they disagree with this
file.

## Current Checkpoint

Update 2026-08-22 (current checkpoint): PR #363 merged the fail-closed semantic
readiness correction as exact product main
`c8c4c425e0488479686d76265b5eec3db133d202`. Exact-main
[CI `32589384708`](https://github.com/aiwaki/slipstream/actions/runs/32589384708)
and
[dependency audit `32589384714`](https://github.com/aiwaki/slipstream/actions/runs/32589384714)
passed. Candidate artifact `9479994821` has digest
`sha256:746b16a10f42d5e86472965b73c17afed21d3e33d5c43ba6ef26107136ec1312`.
The sequential
[owned-Geph run `32590027895`](https://github.com/aiwaki/slipstream/actions/runs/32590027895)
passed, but bound
[release-readiness `32590146466`](https://github.com/aiwaki/slipstream/actions/runs/32590146466)
failed before SafariDriver or the four-host/two-browser matrix. Its bounded
artifact `9480105795`
(`sha256:14eda77a4f71de355e159fe7e8724596be3e9dac1ae8b528ea6773b444573b95`)
contains only exit marker `125`: the second ephemeral runner requested a fresh
account token and the broker returned `cannot get token: rate limited`. The
soak, readiness proof, publisher, and `.23` release did not run.

The active correction makes `release-readiness.yml` the sole release-critical
account-backed workflow. One held owned-Geph process must pass the existing
deterministic Chromium semantic gate and the unchanged Safari/Chrome live-site
matrix before release and cleanup; the same workflow also requires transport
mechanics and, after that cleanup, the measured 30-minute invisibility soak. It
emits separate qualification/readiness proofs bound to one exact run attempt.
The legacy owned-Geph workflow becomes explicit diagnostic-only work and cannot
emit release evidence. Do not retry `c8c4c425` or persist a bearer token between
runners. Merge this correction after exact-head review/checks, obtain a new
exact-main CI/audit/candidate, then dispatch exactly one combined readiness
run. Only its complete matrix, lifecycle cleanup, soak, attestations, and
exact-SHA gates may dispatch `.23`. PR #362 remains diagnostic-only and
non-release.

### Superseded checkpoint

Update 2026-08-22 (second protected chain): PR #359 merged
the narrow Safari/Chrome observation correction as exact product main
`111000c17e0d6decf97eb1a636cf0b3bca2a1fc9`. Its
[exact-main CI `32571354600`](https://github.com/aiwaki/slipstream/actions/runs/32571354600)
and
[dependency audit `32571354592`](https://github.com/aiwaki/slipstream/actions/runs/32571354592)
passed, producing release-candidate artifact `9475493072` with digest
`sha256:4cecfa4249a693d2d7fa66865e2c6772c8d1461903aa1d24ec184c9f018877ee`.

The user explicitly authorized one second same-day protected chain. The bound
[owned-Geph qualification `32572608696`](https://github.com/aiwaki/slipstream/actions/runs/32572608696)
passed, including exact-candidate proof, cleanup, and attestation. The one
bound
[release-readiness `32572723728`](https://github.com/aiwaki/slipstream/actions/runs/32572723728)
then stopped at the strict live-site matrix before the 30-minute soak. Its
bounded
[live-site artifact `9475787712`](https://github.com/aiwaki/slipstream/actions/runs/32572723728/artifacts/9475787712)
has digest `sha256:61633782e256499698c0a28daa138393bfbb4462b1348fce33442219b4fd76f5`
and records:

- `xpersonatoy.com`: Safari and Chrome both `challenge_or_auth` at their
  20-second deadlines; controls unavailable, therefore `inconclusive`.
- `app.aikido.dev`: Safari and Chrome both `usable`.
- `weather.com`: Safari and Chrome both `readiness_document_pending` at their
  25-second deadlines; controls unavailable, therefore `inconclusive`.
- `capacitorjs.com`: Safari and Chrome both `usable`.

The matrix is not a pass, so the soak, readiness attestation, and publisher
were skipped; `.23` remains an ad-hoc-signed, unnotarized, unpublished preview.
The two affected hosts require different evidence-led handling. In one read-only
bounded direct XPersonatoy observation, the detector's generic `captcha` marker
occurred only inside a dormant script on an otherwise StarrToy-shaped document;
the harness had searched all raw source in both browsers, so that is a
confirmed false-positive surface. The active correction
retains strong challenge markers but counts generic `captcha` only from one
page-side visible-text-or-widget boolean. It changes neither routing nor the fixed
four-host/Safari-plus-Chrome matrix.

Weather remains untriaged: both browsers had valid, non-short, non-denial,
non-challenge evidence, but the existing first `readyState != complete` check
masked every later semantic predicate. The correction keeps a pending document
terminal and adds only a bounded `readiness_document_pending_semantic_ready`
reason after the existing visible title/content/protocol checks have passed.
It does not extend a deadline, make Weather pass, or change controls. A prior
local browser-only probe remains non-evidence: it did not install or run
Slipstream or activate its candidate daemon, private PF route, or owned-Geph
path.

No further account-backed or readiness run may be dispatched on 2026-08-22 UTC,
and the unchanged `111000c` candidate must not be retried. First review and
merge the narrow harness correction, then obtain a successful exact-main CI,
audit, and immutable candidate for its new SHA. Only then may the next
UTC-day's one owned-Geph qualification and one bound readiness run execute.
Only a completely passed matrix, measured 30-minute soak, attestations, and
exact-SHA gates may dispatch the publisher.

### Historical checkpoints (superseded)

The entries below preserve evidence history only. Any `next`, `active`, or
retry wording in them is superseded by the 2026-08-22 checkpoint above and
must not be used to select a candidate or spend an account-backed run.

Historical update 2026-08-21 (browser retry blocked by Geph broker quota): PR
#355 merged
its product candidate as `ced62298ceb65c948e53dafa79ec6d32acf76299`; exact-main CI
`32481509165`, dependency audit `32481509168`, and the sequential owned-Geph
qualification `32482765687` passed. The Safari harness now returns its existing
privacy-bounded readiness object through `JSON.stringify`, strictly decodes one
JSON object, and preserves `browser_observation_failed` when a later WebDriver
request fails after an earlier successful decode. Local validation included
457 script tests plus focused, compile, diff, and continuity checks.

Release-readiness `32483025885` bound exact candidate run `32481509165` but
stopped before starting SafariDriver or the browser matrix. The protected Geph
account authenticated far enough to obtain user and subkey state, then the
broker rejected `get_connect_token` as rate limited and explicitly required a
retry after the broker day resets. No live-site JSON existed, the bounded
artifact upload correctly failed rather than inventing evidence, the soak and
publisher did not run, and `.23` remained unpublished. Its proposed retry of
candidate `32481509165` is obsolete; the authoritative candidate and next
action are recorded only in the current checkpoint above.

Checkpoint PR #356 then merged as docs-only main
`9df852508b5e59d7b60ce5b2a9a7ce489df04c99`; its scoped CI `32483427423`
and dependency audit `32483427427` passed but correctly produced no release
candidate. The user authorized an immediate protected retry despite the broker
message. The completed product-scoped follow-up initialized a fixed nonzero
`live-sites.exit` marker before account-backed Geph starts, so a pre-browser
failure preserves bounded evidence without a second artifact-upload failure.
That historical follow-up is now represented by the newer exact candidate and
protected evidence in the current checkpoint above.

Update 2026-08-21 (Safari sessions now reach document observation): PR #354
merged as `5b87bb174eb8a68bb4ab038dce0fea095fafd464`; exact-main CI
`32477345215`, dependency audit `32477345253`, and owned-Geph qualification
`32478432152` passed. Readiness `32478675507` again stopped before the soak and
preserved the full matrix. Removing the originless cookie command fixed the
previous setup boundary: all four Safari sessions now configured, navigated,
and returned page source. They then reported `readiness_signals_invalid`
because SafariDriver did not expose the returned JavaScript object in the
shape assumed by the Python harness. The active fix returns only the same
privacy-bounded readiness object through `JSON.stringify`, strictly parses the
string as one JSON object, and keeps raw pages, URLs, exceptions, and driver
logs out of evidence. Chrome still passed only Aikido; its other three outcomes
remain independently release-blocking and unchanged.

Update 2026-08-21 (exact lifecycle stage identified): PR #353 merged as
`626202dee78b8bfb24f6ced0d77470f20bde3997`; exact-main CI `32473502028`,
dependency audit `32473501940`, and owned-Geph qualification `32474600766`
passed. Readiness `32474823013` stopped before the soak and preserved a full
report. All four Safari results were `session_configuration_failed`: the
driver was ready, a clean session existed, and the owned Safari process had
started. The live harness then differed from the repeatedly green packaged
lifecycle probe by issuing `DELETE /cookie` while the new session was still on
`about:blank`, which has no cookie origin and can be rejected or stalled by
SafariDriver. The active fix removes only that redundant command; disposable
CI, a fresh browser process, a fresh WebDriver session, exact teardown, and the
strict four-host/two-browser matrix remain required. Chrome separately passed
Aikido, timed out on `xpersonatoy.com`, failed observation on Weather, and
failed startup on Capacitor; those outcomes remain release-blocking evidence
rather than being retried or reclassified.

Update 2026-08-21 (readiness still blocked): PR #351 merged as
`db2ab7a2b3f79df798e112ba11f0c8dcc4384475` and its exact-main CI
`32433480829`, dependency audit `32433480861`, and sequential owned-Geph
qualification `32434336197` passed. Readiness `32434527870` preserved a full
failed report and skipped the long soak; publisher was not dispatched.

The origin-free Safari warm-up succeeded, but every immediately following live
Safari session still returned `session_unavailable`, so the warm-up did not fix
the dedicated-runner boundary and is being reverted. Chrome proved Aikido
usable; Weather's owned-Geph control was usable; Aikido and Capacitor were
usable through both route controls. Chrome nevertheless ended in
`readiness_timeout` for XPersonatoy, `browser_observation_failed` for Weather,
and `session_unavailable` for Capacitor. This is not evidence that the release
matrix passes, and `.23` remains unpublished. Do not retry the unchanged
readiness workflow or weaken the four-host/two-browser policy. The next change
must identify and repair the reusable SafariDriver/Chrome session lifecycle on
the dedicated workflow runner while retaining complete bounded diagnostics.
The active follow-up replaces the ambiguous setup result with a fixed bounded
stage enum: Safari distinguishes driver readiness, pre-existing process,
session creation, browser-process startup, and session configuration; Chrome
distinguishes browser startup, DevTools readiness, and clean-target discovery.
Navigation and document/readiness observation remain separate existing stages.
No exception text, URL, page content, process argument, or driver log enters the
report. That protected report produced the exact stage and active fix recorded
above; this earlier diagnostic step is complete.

Update 2026-08-21 (actionable protected retry): PR #349 merged as current main
`0d2e016967b1efeb204d1b687739a3435e3f255d`. Exact-main CI
`32425390228`, dependency audit `32425390226`, and owned-Geph qualification
`32426463756` are green. Readiness `32426465935` stopped before the long soak
and uploaded bounded diagnostics as designed. Safari reported
`session_unavailable` for all four hosts because the workflow accepted an HTTP
`/status` response without requiring SafariDriver's `value.ready == true`.
Chrome passed Aikido but the other sites ended after transient CDP execution-
context replacement during navigation. Direct and owned-Geph controls proved
Aikido and Capacitor reachable, so this is a qualification-harness boundary,
not a broad routing failure.

The active narrow follow-up requires SafariDriver's explicit ready state both
in the workflow and immediately before each clean session. Chrome now retries
bounded `Runtime.evaluate` context-replacement failures inside the existing
per-host deadline; navigation rejection, persistent observation failure,
document invalidity, and readiness timeout remain distinct terminal evidence.
Next: merge the narrow harness correction, obtain one exact-main candidate,
then rerun owned-Geph and readiness. A failed live matrix will again preserve
its report and skip the 30-minute soak; only a completely passed matrix may
start that soak.

Update 2026-08-21 (preview 23 readiness): PRs #347 and #348 are merged as
`13519412dab27306df43c1ce3e301bd69d778ac8` and current main
`eb5f6c1d655ec34a2bfac4774c0dd8dd599b8bc1`. Exact-main CI run
`32418702039`, dependency audit `32418702233`, and owned-Geph qualification
`32419820557` are green. Release-readiness run `32419823032` bound the exact
candidate and preserved a complete failed report after the full live-site
matrix and 30-minute soak; `.23` remains unpublished.

The report exposed two measurement defects rather than another opaque failure.
CoreGraphics counted the menu-bar UIElement once in every sample (`3604`) even
though Dock visibility, frontmost changes, GUI/headless browser processes, and
LaunchServices visible events were all zero. The unified log also recorded the
single expected menu-bar registration `PostShowProcess` because observation
started before launch. The follow-up restricts the CoreGraphics exception to
the exact OS-reported status-window layer while retaining on-screen floating
panels, alerts, overlays, and normal application windows; it starts the
unified-log stream only after high-cadence launch observation and tray
readiness, while preserving all launch-time Dock/frontmost/window/LaunchServices
checks.

The live-site report covered all four fixed hosts but exposed only generic
`terminal_error` browser outcomes: Safari failed all four and Chrome succeeded
only for Aikido. The follow-up schema adds a strict privacy-bounded reason enum
for session, navigation, document, readiness-signal, timeout, denial, and
observation failures; raw exception text, page content, and URLs remain absent.
Failed or inconclusive live sites are now uploaded per run attempt and stop the
workflow before the 30-minute soak. The next verified action is to merge this
diagnostic correction, inspect one exact protected live-site report, fix the
identified product or harness cause without weakening the two-browser policy,
then run the soak and publisher only after the complete matrix passes.

There are no Apple Developer ID/notarization credentials, and none will be
purchased for this preview. The repository must therefore describe `.23`
honestly as an ad-hoc-signed, unnotarized preview with the documented macOS
Control-click/Open first-launch path; it must not claim normal Gatekeeper or
notarization acceptance. This trust limitation is independent of the required
functional readiness gates above.

Update 2026-08-20 (release follow-up): vendor-bootstrap PR #344 merged as
`f4b0de15607a911ffba1c7a8401b35bb73ed4922`, Geph `0.3.9` PR #280 merged as
`21fcaab9d35bdfdbdaacd28bf835acf7585318c3`, and notification-diagnostics plus
transactional-publisher PR #345 merged as current main
`b1abb1e1104ba5f1c69516a294c64b69452e174e`. The exact
`geph-vendor-0.3.9-r1` release and its eight provenance/SBOM/audit/source assets
remain bound to the reviewed source. Exact-main dependency audit run
`32382675900` is green.

Exact-main CI run `32382675926` passed the reviewed Geph ingestion, application
build, isolated production updater signing, immutable candidate assembly and
attestation, Chromium contract, packaged browser qualification, and full
packaged lifecycle/Safari sentinel. Its only failed leaf was native update
notification qualification `96471868763`. The always-uploaded bounded report
survived with exact code `os_attribution_missing`; no capability, identity, or
legacy submission wrapper error occurred. The macOS 14 runner was checking the
macOS 15+ `usernoted` database path, while the legacy
`notify-rust -> NSUserNotificationCenter` return value could not confirm OS
delivery in any case. The candidate is not releasable and no protected gate or
publisher was dispatched.

The active follow-up replaces only update alerts with the supported
`UNUserNotificationCenter` API shared by production and qualification. A fresh
update may request promptless provisional authorization; exact qualification
requires the runtime bundle identity, a nil-error bounded native completion,
exactly one delivered capability-derived identifier, exact cleanup, and zero
Dock/window/frontmost/activation change. Denial proves fallback behavior but
never satisfies release delivery. Sonoma/Sequoia private notification stores
are explicitly resolved and validated only as secondary diagnostics. CI also
runs the candidate from its production `/Applications` layout and preserves
each rerun's failure artifact independently.

The root READMEs already contain the centered application icon and label `.23`
as the next preview. The bundle configuration uses ad-hoc identity `-`, and the
repository has updater signing secrets but no Developer ID/notarization
credentials. The later 2026-08-21 checkpoint records the explicit preview
boundary: no Gatekeeper/notarization claim, documented Control-click/Open first
launch, and functional publication only after exact-main owned-Geph and
release-readiness pass.

Update 2026-08-20: PR
[#343](https://github.com/aiwaki/slipstream/pull/343) merged unchanged as
`a02ba90fb65d40f14ba0b67e5f2d4b657188747e` after all `15` exact-head checks
passed. Its updated app graph removed the newly reported quick-xml
vulnerabilities; the Geph policy contains one short bridge for immutable r1,
but that bridge does not authorize publishing the app preview.

The local tree now identifies the app and release as
`0.1.9-preview.23` / `v0.1.9-preview.23`. It adds bounded background preview
discovery, bundle-attributed native notification, explicit signed installation,
and a durable non-AppKit update watchdog. Before replacement, the watchdog
fsyncs an owner-private journal, a same-volume staged app, and an independently
validated sibling backup. The successor is accepted only when its exact path,
version, process birth identity, tray startup, owned daemon, and advancing
heartbeat agree; otherwise the exact previous bundle is restored. Startup can
resume a crash between journal publication and launchd bootstrap. `.22 -> .23`
remains one manual install because `.22` reports `0.1.9`; automatic preview
discovery begins with `.23 -> .24`.

Required main CI builds the application once without the production updater
secret. A separate no-checkout/no-repository-code signer job downloads and
hash-binds the frozen updater archive, verifies pinned Tauri signer binaries,
and exposes the production key only to the signing command. A no-secret
assembler binds both service-artifact digests, cryptographically verifies the
signature and archive contents against the exact packaged public key, and
creates the immutable candidate without rebuilding. A parallel main-only
packaged notification job binds the same candidate to a root-owned one-shot
capability and requires exact `dev.slipstream.tray` macOS attribution (or an
explicitly denied notification permission) with zero Dock, window, activation,
or frontmost-app change.

Current local evidence is green: `1030` routing/platform Python tests, `459`
script tests plus `70` subtests, and `189` Rust tests pass; clippy is clean and
version/project/workflow/diff checks pass. A fresh arm64 Tauri package has
bundle identifier `dev.slipstream.tray`, version `0.1.9-preview.23`,
`LSUIElement=true`, and the exact `slipstream`,
`slipstream-browser-probe`, and `slipstream-update-watchdog` arm64 executables.
The app and helpers pass strict local ad-hoc signature checks; both helpers
link only `libiconv` and `libSystem`, never AppKit, Cocoa, or WebKit. This local
package is not a release candidate and was neither installed nor published.

The app now declares the honest Rust `1.88` floor and resolves `plist 1.10.0`
to patched `quick-xml 0.41.0`; its exact macOS ARM OSV 2.3.8 scan covers `362`
packages with `0` blockers and `0` vulnerability exceptions. Geph r1 still has
the low-severity empty-DATA-frame advisory in `h2 0.3.27` and `0.4.15`. The
unmaintained Hyper 0.14 / h2 0.3 branch has no fixed release and is accepted as
an exact expiring availability risk. Existing automated PR #280 reproducibly
updates Geph to `0.3.9`; its lock already uses fixed `h2 0.4.17`, passes dual
macOS metadata and arm64 compilation, and its 484-package audit has `0`
blockers. It is therefore preferred over rebuilding old `0.3.0-r2`.

Exact-main CI run `32368498935` built and signed the app and passed the updated
application audit, then failed while assembling the candidate: the generic
top-level artifact helper rejected a legitimate zero-length `py.typed` inside
the frozen Python runtime. The correction keeps every top-level release and
candidate artifact strictly nonempty, but permits zero-length regular files
only while hashing the complete unpacked app tree, retaining `O_NOFOLLOW` and
file-identity race checks. The current local packaged tree contains five such
Python marker files and now hashes deterministically as
`9a30b9a67d801ce0a07a3fbe30189642b4cfb9010fd73f5bd17e3fe5741d0793`;
exact CI still has to reproduce that boundary.

One pre-fix updater fault test called the production relaunch effect on its
temporary `Slipstream.app`; macOS associated that direct executable with the
fake bundle and displayed a misleading “damaged” dialog. Unified logging bound
the dialog to the `.ctx-mode` TempDir and `ELOOP`, while the installed `.22`
passed strict code-signature verification and had no quarantine attribute. The
rollback effect is now injected in unit tests: they assert one relaunch request
without executing an app, a static regression forbids any test-section
`spawn_bundle`, and the post-fix full Rust run produced zero new Gatekeeper or
CoreServicesUIAgent Slipstream records.

The next verified action is to merge the narrow vendor-bootstrap and candidate
tree-hashing corrections. The same correction now closes a discovered Geph
supply-chain gap: packaged builds no longer copy a release binary after only an
architecture check. They first require exact non-draft internal-release
metadata, a lightweight tag bound to the report's source commit, the complete
eight-file release set, strict checksums, byte-identical reviewed source, lock,
version and license, historical-policy SBOM and audit validity, SLSA provenance
for every asset, and the binary's SPDX attestation. Only then may the universal
binary enter the app bundle. Next, qualify PR #280 with the now-required
dependency-audit context, publish and
attest `geph-vendor-0.3.9-r1`, and require a new exact-main candidate that
embeds it. The bootstrap applies only to a pull request containing the required
Geph source/lock and no path outside its four-file allowlist; main and mixed
changes still fail closed and run full packaged qualification. That final candidate
must pass production signing, packaged notification qualification, protected
owned-Geph proof, Safari/Chrome live-site matrix, transport mechanics, and the
measured 30-minute invisibility soak before `v0.1.9-preview.23` is published. A
real public `.23 -> .24` notification/install/relaunch and forced rollback
remains the release gate for `.24`; it cannot be honestly claimed before both
public versions exist.

## Superseded 2026-08-13 P0 Checkpoint

Update 2026-08-13 P0 implementation is in draft PR
[#343](https://github.com/aiwaki/slipstream/pull/343) on
`codex/p0-macos-reliability`. Its second exact PR run again built the immutable
candidate and passed the corrected dependency audit, then exposed four new
packaged boundaries rather than a product pass: the PF smoke used an unroutable
documentation-prefix IPv6 destination, lifecycle still expected an artificial
scheduler stall to mean wake, the browser smoke launched the Tauri GUI
executable and therefore registered it with LaunchServices, and a Windows
checkout fed CRLF into an LF-only workflow parser. The branch fixes each cause
without weakening its gate: PF uses a transaction-owned RFC3849 `lo0` `/128`
and closes the inherited `/dev/pf` descriptor before dropping privileges; lifecycle
injects one exact root-owned `0600` disposable system marker while production
continues to use `kern.waketime`; the browser observer is a separate non-AppKit
Cargo binary signed inside the same bundle; and the Windows parser normalizes
line endings.

The next exact-head run confirmed the dependency, Chromium, Windows contract,
and complete Python suites, but also proved both attempted IPv6 targets were
invalid fixtures: `fe80::1%interface` depended on a nonexistent neighbor, while
the Mac's actually assigned scoped link-local address was a local identity and
did not traverse the inbound `rdr on lo0` path. The follow-up now owns one fixed
RFC3849 `/128` alias on `lo0`, after proving the address absent, the existing
route not `lo0`, and recording the exact pre-test `lo0` IPv6 set. Both the
high-port PF smoke and installed-candidate transport gate remove that alias in
`finally` and require the address, derived route, and IPv6 set to be restored.
This live proof covers the production-family `inet6` loopback `rdr` and
DIOCNATLOOK path. The non-`lo0` IPv6 `route-to` branch remains an exact
loaded-rule/static assertion rather than a claim based on external IPv6.

Exact PR run `31711135993` for head `2d27b7aec170829db0cacd1d5e7b359865005968`
then passed the candidate build, Windows adapter and packaged lifecycle but
failed browser qualification after the navigation completed: the visibility
sampler observed the pinned `chrome-headless-shell` in LaunchServices. A local
`lsappinfo listen` trace of that exact pinned runtime proved this was neither
the non-AppKit helper nor GUI Chrome. Chromium's macOS headless shell itself
uses `NSApplication`, registers first as `BackgroundOnly`, changes to
`UIElement`, and completes a 15-event hidden lifecycle. The corrected gate
allows that sequence only when every event binds to the exact manifest-digest
path and one observed process-group root. It still fails closed for every
unknown, show, activation, frontmost or foreground event, any other path/PID,
any Dock/CoreGraphics window or GUI Chrome sample, listener blindness, an
incomplete exit, or a surviving process/registration. Deterministic fixtures
cover each forbidden class, and the parser accepts the measured real 15-event
sequence only after complete exit. The source bundle separately has
`LSUIElement=true` before launch and runtime `Accessory`; its committed
`icon.icns` is byte-identical to the current installed copy.

The current local freeze has 1,404 Python tests plus 60 subtests, 374 script
unittests, 89 tray-library tests, 29 browser-helper tests, 41 core tests, 40
userspace-stack tests, 40 userspace-effect tests, and 241 Windows-adapter tests
green. All Rust lints, Python compilation, project-state validation, workflow
syntax, and diff checks pass. A real arm64 Tauri package contains
`Contents/MacOS/slipstream-browser-probe`, keeps `CFBundleExecutable=slipstream`,
passes helper and deep-bundle signature checks, and links the helper only to
`libiconv` and `libSystem`, never AppKit/Cocoa/WebKit. Its bundle metadata has
`LSUIElement=true`; the installed `.22` does not. Pinned OSV Scanner 2.3.8
accounts for all 352 SPDX packages as 351 vulnerability-scanned plus one exact
SHA-256/PURL/expiry-bound Chromium integrity-only entry, with zero blocking
findings. Disposable CI must still prove the unchanged real visibility sensors
and every required check on the new PR head.

Workstation evidence invalidated the preceding
headed-Chrome qualification as a production readiness claim: the installed
preview launched 271 browser workers and 184 GUI Chrome processes, including
background activity, while a 51-second status-publication gap made the tray
show `Off` although the daemon PID/listener remained alive. Safari/Chrome
reports added four generic gates: reviewed Geph first-payload recovery
(`xpersonatoy.com`), original-navigation pending (`app.aikido.dev`), complete
regional denial (`weather.com`), and independently confirmed edge denial
(`capacitorjs.com`). These are classes, not hostname exceptions.

The branch replaces production LaunchServices/branded Chrome with a pinned
app-bundled headless shell, adds the route-preflight v1 contract, separates
heartbeat from slow health publication, adds dual-stack TCP listener/PF/NATLOOK
coverage, and removes direct fallback for a reviewed required-exit
first-payload failure. Required main CI now builds the app exactly once and
creates one immutable `release-candidate-${SHA}`; packaged lifecycle and browser
qualification consume parallel copies without rebuilding. Protected
owned-Geph qualification and protected release readiness independently consume
that exact candidate. Their manifest-bound attestations cover owned-Geph,
Safari/Chrome live origins, dual-stack PF/NATLOOK plus QUIC v1/v2 mechanics, and
the measured 30-minute invisibility soak. The publisher verifies all three
exact workflow identities, attempts and digests and performs no PyInstaller,
Cargo, or Tauri rebuild. Those protected gates have not yet passed, so
`v0.1.9-preview.23` must not be published or installed. Next: push the locally
green follow-up, pass every required PR check, merge, pass the exact-main
candidate and both protected qualifications, then promote that unchanged
candidate.

The same draft moves the package version to `0.1.9-preview.23` and adds the
first honest preview updater channel. `.22 -> .23` remains a manual install
because `.22` identifies itself as `0.1.9`; automatic discovery begins only at
`.23 -> .24`. The tray now discovers a bounded immutable preview appcast in the
background, persists per-channel notification/highest-seen state, submits a
native Slipstream-identified notification, and exposes an explicit install
action. Installation rechecks tag/version/archive identity, performs a bounded
minisign-verified download, then validates the signed bundle identifier,
executable, internal version and `LSUIElement` before installing the same
bytes. Local unit and MockRuntime installer-mechanics tests pass, but they are
not product completion evidence. Durable pre-install backup, automatic rollback
with successor health acknowledgement, an OS-observed packaged
notification/no-activation gate, and a real released `.23 -> .24` transition
are still open. Until those exact gates pass, the repository must not claim
that auto-update or native delivery is end-to-end proven.

The legacy transport-idle browser broker remains disabled permanently. The
replacement exact-host pre-routing path is implemented on this branch and can
start only from an installed, sealed app bundle after signed foreground
Safari/Chrome provenance, within one eight-second deadline, through the pinned
headless shell and the owned-Geph candidate. It is not evidence that the
currently published `.22` preview has this behavior: the new path is not
release-ready until the packaged, live-site, transport, and 30-minute
invisibility gates pass for the exact candidate.

## Historical Evidence

Update 2026-08-13: the macOS release gate is complete. Preview
[`v0.1.9-preview.22`](https://github.com/aiwaki/slipstream/releases/tag/v0.1.9-preview.22)
was published by successful `build-app` run `31630147863` from exact main and
tag target `d034e99a7b97d5b0bf286f896793bc079fba5f21`. The workflow passed release
tests, signed-app lifecycle, packaging, SBOM and dependency audit, manifest
verification, stored provenance/SBOM attestations, publication, and archival
of the prior preview. The downloaded release assets were verified again off-CI:
the manifest contract passed, every GitHub SHA-256 matched, `unzip -t` passed
for the arm64 ZIP, `hdiutil verify` passed for the DMG, and provenance plus SPDX
attestations for both packages resolved to the exact source SHA and release
workflow. The arm64 ZIP digest is
`acaa409e8868e4a36c3b79a07267bbe585e3b03d8e81ad93ea353040172978e8`;
the DMG digest is
`593286ab6d7bbee1c34784a2d6ff61c1d1f871dd70a775714f0640a32ff750ba`.

Workstation transaction `71E98AF3-49AC-45BC-94D1-7F4BADE333D1` installed
that exact downloaded arm64 ZIP as `/Applications/Slipstream.app` and remains
active rather than rolled back. The installed bundle is version `0.1.9`; its
tray executable SHA-256 is
`11e1f51dc8905741a1e8346f19d5f94d1f2d4bf4a22e9707fe5aecf0cc8ed3f1`
and bundled daemon SHA-256 is
`535429539625eff97b6c3c5934a29f3c2044b182d07802dc31319e2d1ccf0a2a`.
The tray process, root LaunchDaemon, TCP listener on `127.0.0.1:1080`, private
PF rules, and app-owned Geph on `127.0.0.1:9954` are live. A prior controlled
uninstall had left the launchd label explicitly disabled, so the final
workstation install used the documented direct `Restart Proxy`/install path to
honor and then reverse that durable stop intent; this is not a clean-install
product defect.

The final headed test used ordinary installed Google Chrome 151 with a fresh
profile and no QUIC-disabling flag. `https://xpersonatoy.com/` returned HTTP
200, title `Starrtoy is where passion meets creation. – StarrToy`,
`readyState=complete`, a 1,088,420-byte DOM, and `h2`; the daemon logged the
scoped `geo-exit QUIC flow moved to TCP fallback`, and owned Geph showed active
sessions. Installed classification remains `geo_exit/geph` for
`xpersonatoy.com`, local-only for Discord and YouTube, `direct_first` for
Googlevideo, and bounded `unknown/general` for an unreviewed host. The first
post-install canary pass reported nine of ten healthy because a separately
running user-managed `TG WS Proxy` held `127.0.0.1:1443`; Slipstream correctly
did not terminate or steal that listener. After that external process exited,
the embedded Telegram proxy took over automatically and the final status is ten
of ten canaries healthy with `local_bypass`, `geo_exit`, and
`direct_passthrough` all `ok`. PF and owned Geph remain healthy, and the
user-managed system DNS remains untouched. No release gate is open. Continue from live failures observed with
this installed release; do not repeat the xpersonatoy/QUIC investigation or
install a protected artifact over it.

Update 2026-08-12: release run `31626189079` built and signed exact main
`7ed02cf2cccd56cbc3580a5ba8b53e48f6e6f160`, but two independent attempts
failed closed before packaging or publication at the same release-only browser
boundary. The runner's preinstalled branded Google Chrome never created the
isolated hidden-worker process or DevTools port through LaunchServices and
reported `chrome_launch_timeout`; the protected exact-main run had already
passed the same installed packaged path with the pinned complete Chrome for
Testing bundle. Branch `codex/release-pinned-chrome` makes `build-app` install
and pass that exact `151.0.7922.77` bundle, matching packaged CI and protected
qualification. It does not change production browser selection. Next: pass
local and PR checks, merge, repeat exact-main and protected gates, publish a new
preview from that exact SHA, then install and verify only its downloaded
artifact with ordinary branded Chrome on this Mac.

Update 2026-08-12: PR #338 merged the corrected macOS geo-exit/QUIC path and
bilingual README refresh as exact main
`6f3309c82d514b529216bcfa2735f1ef11e0f2cb`. All eight final PR checks passed.
Exact-main CI `31622844180`, native Windows `31622844165`, and dependency audit
`31622844157` passed; the audit needed one same-SHA retry after the scanner host
closed the first download without a response. Protected owned-Geph run
`31623465736` then passed the installed account-backed browser recovery and
cleanup gate. Its exact artifact `9152313333` has GitHub digest
`sha256:a4ac2330e75ca651678ffb80b3536bbc2c110c1ad495f2f4e5303455f9fd616a`.

Manual release run `31623938691` stopped before building or publishing because
the minimal release build environment runs `unittest discover` without pytest,
while the newly added `test_composed_pending_navigation_smoke.py` imported
pytest and exposed only pytest functions. Branch
`codex/release-metadata-unittest` converts that module to eight standard-library
`unittest.TestCase` methods. The exact release command now executes 296 tests in
the minimal build venv, and pytest also executes the eight methods plus three
subtests. Next: merge this small release-gate correction after required checks,
repeat exact-main and protected gates on the new SHA, publish the 0.1.9 preview,
then install and verify only the downloaded release artifact on this Mac.

The first PR CI run `31619433057` on product commit `7ddd2ba` passed every unit, Rust,
lint, and project-state step before its script-mode installed lifecycle sentinel
failed closed at the first wake cycle. The new packet observer made Scapy import
mandatory even with voice disabled; the harness could observe the already
published active status and suspend the daemon before the monitor thread set its
cadence anchor, so the eight-second gap was lost after resume. The correction
captures the monitor start time before publishing active and passes that exact
timestamp into the thread. No wake timeout or test bound is relaxed; focused
tests cover the pre-thread suspension boundary and later final-head checks
passed it.

The first Codex review on PR #338 found two actionable boundaries. A completed independent
navigation previously reset the exact client stream without rechecking whether
the original relay had resumed receiving bytes; the same-route path now repeats
the full live/idle/TLS eligibility check under the existing lock immediately
before signaling reset. The QUIC callback also now requires private PF applied,
startup baseline ready, and verified owned Geph on `:9954` before Version
Negotiation; a VPN, competing filter, dormant backend, or unowned listener stays
untouched. Focused regression covers a recovered relay plus inactive/unowned
geo-exit routing. Both threads were resolved, and all eight required PR checks
passed on published head `fcdad632d844e2c95d6bee92694dc9a725bf4d1e` in CI
runs `31620653344`, `31620653353`, and `31620653365`.

Fresh review of that exact head found two further bounded-state defects before
merge. CDP reports a redirecting `Network.requestWillBeSent` with the destination
URL while reusing the original document request ID; redirect correlation now
runs before the synthetic target-URL filter, so the later destination finish
cannot be mislabeled same-route completion. QUIC CRYPTO state also now accounts
the sum of every uniquely retained fragment, including overlapping offsets,
and drops the exact flow before the aggregate can exceed 64 KiB. Regressions for
both cases pass locally; final head
`6c1abacde32f3b9c43c52bc4db90a8507c8d2a3d` passed all eight required checks
and merged in PR #338.

Transactions `AD279B68-AE05-46D1-8BF2-E4919D7727D1`,
`76910DF2-B1D4-4DF6-AC4A-89D185ABEB50`, and
`AC4ADF6E-A636-4980-A307-9CF0C9512A70` all rolled back. They proved,
respectively, that an accepted late TCP route advance cannot replay a Chrome
navigation after response headers were delivered; installed policy correctly
classifies `xpersonatoy.com` as `geo_exit/geph`; and ordinary Chrome was instead
bypassing the TCP route over QUIC. The same owned SOCKS listener returned the
complete 1,116,446-byte HTTP 200 in 2.4 seconds, and Chrome completed only when
QUIC was disabled.

The correction adds the repeatedly qualified `xpersonatoy.com` suffix to the
shared Python/Rust reviewed geo-exit policy. It also observes only outbound
QUIC v1 Initial packets, derives their standardized public Initial keys,
reassembles bounded CRYPTO frames, extracts TLS ClientHello SNI, and reuses the
active route-policy classifier. Only `geo_exit` receives a valid Version
Negotiation response that moves the flow to TCP; unknown, direct, Discord,
YouTube, and Googlevideo QUIC is untouched. State is capped at 4,096 flows, an
aggregate 64 KiB and 128 retained CRYPTO fragments per flow, five seconds, and
one response per exact flow. There is no
global UDP/443 block, content inspection, host in the log, or DNS/proxy/PAC/VPN
mutation. A local 1,000-packet benchmark took about 219 ms total.

Transaction `AC4ADF6E-A636-4980-A307-9CF0C9512A70` launched the real tray and
a fresh headed Google Chrome without a QUIC-disabling flag. The daemon logged
`geo-exit QUIC flow moved to TCP fallback`; the same URL completed over `h2`
with the StarrToy title, `readyState=complete`, and a 1,089,537-byte DOM.
Status remained active with private PF ready, owned Geph up, and two active
sessions. Exact rollback restored prior app hashes `3931c16e...`, `8674b761...`,
and `9e61166e...`; the root daemon/TCP 1080 are absent and owned Geph remains
live. One earlier sample was discarded after startup baseline intentionally
paused PF on transient `probe_process_unavailable`; a normal network rearm
restored active state before the successful proof.

Full local verification passes `1,208` Python tests plus `57` subtests, `102`
Rust tray tests, `35` Rust core contract tests, Python compilation, Rust format,
both affected Clippy targets with warnings denied, project-state validation, and
`git diff --check`. The focused QUIC set includes public-Initial decryption,
fragmented CRYPTO/SNI reassembly, aggregate retained-byte rejection, tamper
rejection, exact policy scope, and Version Negotiation CID reversal. The merged
tree passed exact-main and protected qualification; the current open gate is the
release-metadata test-runner correction recorded at the top of this checkpoint.

macOS is the active priority. PR #337 merged the hidden ordinary-Chrome worker
as exact main `684ba0767b407a87e8a449f0999b799cee410c4d` after all six PR
checks, exact-main CI `31595061506`, audit `31595061432`, native Windows
`31595061480`, and protected run `31595643843` passed. Protected artifact
`9141025574` has GitHub digest
`sha256:25c872971855d7461b07bd8d5c581129f210d2d5b4579e226c8ff7ee386663aa`;
its inner ZIP SHA-256 is
`f12be620a9d76dd3c01233e84f983994b2ec7256e34071f9807ba4dfd0fef376`.

Controlled transaction `7CA316C7-B043-49FF-BE20-3C181B50D7CA` installed
only that artifact and reached an active root daemon, but the first required
headed-Chrome `xpersonatoy.com` smoke again remained uncommitted for 75 seconds.
Exact rollback restored prior app SHA-256
`3931c16e158a223c0cdcb533bf77698e89e5df3f80015ead153dace86ff2a710`,
removed the root daemon, listener, and private PF state, and preserved external
DNS, proxy/PAC, route, and Geph ownership. Its log reduced the failure to
`binding_invalid` rather than a worker launch or headless-rendering mismatch.

Four local source-built transactions then isolated the binding safely and each
rolled back. `9803CFE4-3FFC-4901-B858-04B101F4399F` proved the worker result
was a terminal outcome; `9372D344-5999-4214-8AC6-DBCF8AB4A955` proved the
specific event was `Network.responseReceived`: the hidden Chrome received the
top-level HTTP response headers while the document body and the original exact
relay remained unfinished. The observer incorrectly treated response headers
as completed navigation and consumed its capability, so the existing route
ladder never received `navigation_pending` and could not reach independently
confirmed owned Geph. This is the concrete workstation defect; no retry
cooldown or unchanged-stage refresh is required.

The correction now covers three independently reproduced defects. First,
`Network.responseReceived` is ignored for completion; only the exact top-level
`Network.loadingFinished` is terminal success, while the same unfinished
document reports `navigation_pending` after eight seconds. Second, one Aqua
worker drains the current job burst and waits fifteen seconds for the next
route stage instead of bootstrapping one LaunchAgent per host; it remains
bounded to one concurrent worker and a 100-second runtime. Third, the daemon
admits a complete-record payload idle through the existing 512-KiB independent
incomplete-response bound instead of discarding it above 8 KiB. Those bounded
partial-payload jobs move ahead of background jobs, may be claimed for at most
14 seconds only while their exact relay object and stage remain live, and still
require the existing system, app-owned DNS, local-strategy, content-aware, and
owned-Geph evidence chain. A fast failure, redirect, completed document, stale
relay, or response above the cap has no route effect. No hostname rule or new
IPC privacy field was added.

Transactions `36B774FF-F3D5-47D6-997F-7C268B7CD0AF`,
`1F8B6F1D-C7FC-4409-8270-7E1D5A2AC616`, and
`26918BAB-0E1C-4069-A75A-B60CF0E5E357` supplied the evidence and were rolled
back. The last rollback restored the exact prior app, daemon, and Geph binary;
owned Geph restarted under a new PID during the transaction, so PID preservation
failed even though its command, binary SHA-256, listener ownership, and app
state are valid. The root daemon and TCP/1080 are absent. Focused Rust and
Python contract/runtime verification passes. The next verified action is one
controlled build and isolated real-Chrome transaction with the final queue and
payload bounds. Only after `xpersonatoy.com` completes should the full suite,
small PR, exact-main/protected gates, exact-artifact installation, tray launch,
and final macOS smoke proceed.

PR #332 is the latest qualified product-code merge at
`b5514a693cfa412650d54878c0ccee8d8b664a07`. Its tree exactly matches reviewed
product head `0d30a3712a5d5ae069ce09076658abc4fa65ea83`. PR CI run `31579340393`
passed all six required checks; packaged job `94058618509` and its explicit
same-head repetition `94060386147` both passed. Fresh review of exact head
`0d30a371` found no major issue and every review thread is resolved. Exact-main
CI run `31580485874` passed common job `94062155133`, packaged lifecycle
`94062155231`, pinned Chromium `94062155061`, and Windows adapter
`94062155080`; dependency-audit run `31580485872` passed audit job
`94062154947` and Geph vendor job `94062155023`; Windows packet qualification
run `31580485841` passed AMD64 job `94062155131` and ARM64 job `94062155203`.
No protected artifact from this SHA has been installed on the workstation.

PR #333 is the merged documentation successor at
`ec34d7aa573b8781f06be092574316f9e1b6ae76`. Its exact reviewed head
`6b0af22604f58947ee177d2023a81b07d418966a` passed all six PR checks in run
`31582161644`; exact-main CI `31582732767`, audit `31582732781`, and native
Windows run `31582732798` also passed. Review correctly rejected the earlier
idea that the existing protected unpacked-extension scenarios could qualify
the packaged extensionless automatic worker. That path needs its own
exact-artifact `original -> worker -> original` scenario before another
protected qualification or any workstation transaction.

PR #334 merged the missing qualification slice as exact main
`a49e0fc82018569daf7cbccff0972d8408415bb7`; its tree matches reviewed head
`f4575e312629c287f7b3439e5ffbf05635fad780`. Codex Review found no major issue,
all six PR checks passed, and exact-main CI `31584859058`, audit `31584858959`,
and native Windows run `31584859039` passed. The protected harness now starts
the composed fixture, installs the exact built app, restarts its LaunchDaemon
with only the frozen disposable-browser override set, and requires the
extensionless original navigation before the existing unpacked-extension
semantic scenarios continue. Both hosted browser gates pin the qualified
complete Chrome for Testing `151.0.7922.77` bundle.

The first and only protected run for that SHA, `31585408666`, passed build,
signature, daemon-free preflight, account-backed owned-Geph payload, external
listener preservation, and final system cleanup, but failed before browser
launch with `launchd attestation mismatch`. The install attestation correctly
recorded the initial daemon PID; the qualification harness intentionally
restarted that daemon with disposable browser overrides and then incorrectly
compared the immutable install record with the replacement PID. No artifact
was packaged or installed. PR #335 validates the complete install
attestation before restart and, after restart, separately proves the new PID's
exact installed command. Production code and attestation semantics are
unchanged. Local verification passes 1,198 tests plus 54 subtests, the focused
66-test file, Python compilation, project-state validation, and
`git diff --check`. Codebase graph discovery was retried and returned
`Transport closed`, so inspection used the documented narrow source fallback.

PR #335 merged the qualification-only sequencing correction as exact main
`fcbcedaa4e812e5080a00ce3d7f4bb8e89c6aff5`; its tree matches reviewed head
`c785c812d88801e5c02fde31c855f81e4d241c0f`. Codex Review found no major issue,
all six PR checks passed, and exact-main CI `31587057669`, audit `31587057685`,
and native Windows run `31587057755` passed.

Protected run `31587594114` then passed the complete exact-artifact gate. The
extensionless automatic path observed roots `original -> worker -> original`:
the worker began at 17,087 ms, Chrome retried the unchanged original URL at
28,899 ms, and styled completion took 25,713 ms with one CSS, JavaScript,
image, and ready callback. Extensions were disabled, no manual reload occurred,
and exact worker cleanup passed. Regional-denial, incomplete-response, and
pending-navigation extension scenarios independently completed one reload and
all mandatory resources; pending-navigation emitted exactly one v3 signal.
Owned Geph returned a complete 67,973-byte Steam HTTP 200 payload initially,
trayless, and after KeepAlive replacement. The external listener was preserved,
the root daemon ended absent and disabled, system network state was not mutated,
and the final workflow residue checks passed.

Artifact `9137909918` is named
`Slipstream-owned-geph-qualified-fcbcedaa4e812e5080a00ce3d7f4bb8e89c6aff5`;
its GitHub container digest is
`sha256:9348c6a2d36e718edc4bc905bbb94b622b7c547d7605decebee6136ede7d00df`.
The contained `Slipstream-owned-geph-qualified.zip` has SHA-256
`1fbd3ff7da2143396cc45292217c5692c18783910c4897308d9e4f767103a9ab`;
the recorded checksum and `unzip -t` both pass. It was installed only in the
rolled-back transaction recorded above and no longer has installation
authority.

PR #332 is the merged product correction. Its first documentation head passed
all six required checks, including packaged job `94019999739`. A later
documentation-only head exposed a real timing race in packaged job
`94021442646`: the original request reached the fixture, the worker request
arrived, but the worker delayed its result until after Chrome cleanup. The
original relay closed in that interval, so submission was rejected; removal of
that capability then let the worker relay mint stale same-host jobs, recorded
as `claimed_job_invalid`. The correction submits the bounded observation
immediately and then always performs exact Chrome/profile cleanup before the
worker exits. An accepted result keeps its exact-host guard until the one-shot
launcher positively confirms that exact worker and Chrome/profile cleanup;
only then does the callback release that accepted guard so a legitimate next
eight-second stage stays fast. An ambiguous cleanup failure remains a worker
failure and deliberately retains the guard rather than admitting recursive
same-host work. This remains true even if cleanup crosses the original
capability expiry. The owner-only broker also records the exact job
claim before delivering it. If that claimed capability expires, is rejected,
or its relay closes while the worker remains active, its same-host guard is
promoted through the same exact cleanup callback; an unclaimed rejected or
live-invalid capability remains guarded only through its original 30-second
expiry. Static rejection classes are logged for qualification without host,
URL, content, or browser identifiers. The preceding head `349e00e` passed all
six PR checks, including packaged job `94034409872`; exact cleanup-bound guard
head `1a53d37` then passed common, Chromium, Windows, audit, and Geph checks but
packaged job `94038042816` exposed a separate disposable-fixture race. A
background unknown-host relay reached the shared worker queue before the exact
fixture job, so the closed fixture origin rejected it as `ci_origin_invalid`;
lease retries then became `claimed_job_invalid`, and the original fixture never
received a worker request. Under the already required exact disposable GitHub
Actions markers, pending-navigation admission now requires the same exact
host, public IP, and port-443 tuple accepted by the loopback fixture mapping.
Production admission is unchanged. Head
`3a87c022c65a41ee7d65f979dc0ee50b50e4694e` passed all six checks; packaged
job `94042532588` and an explicit repetition as `94044217785` both passed the
complete original-to-worker-to-original lifecycle and cleanup. Fresh review
then found that the lifecycle callback was still unconditional when launcher
cleanup raised. The current correction exposes cleanup certainty on the
launcher error and releases the guard only after positive cleanup proof; head
`0512a0bb26f559e722bd16079e95e1773d34d470` passed all six checks, including
packaged job `94047866907`. Review of that correction found a second boundary:
a later successfully cleaned launch could still invoke the global callback and
release a guard retained for an earlier ambiguously cleaned launch. Each Aqua
launch now receives one random local 64-bit ID in its exact LaunchAgent
environment. The owner-only claim and submit envelopes carry that ID, and the
daemon binds both claimed and accepted guards to the exact capability/launch
pair. Cleanup releases only that launch's entries; another launch cannot clear
an ambiguous predecessor. A nonzero worker exit releases its pair only when it
reports a bounded error after its own Chrome/profile cleanup succeeded;
`chrome_cleanup_failed`, `profile_cleanup_failed`, and an unknown/crashed exit
retain the guard even if LaunchAgent cleanup succeeds. Stale cleanup accepts
the previous release's otherwise exact owned plist only when its environment
is the precise legacy shape without the new ID; newly created workers and all
claim/submit traffic still require it. Launcher bootstrap, start, wait,
disappearance, PID replacement, and console-identity failures also never gain
cleanup authority merely because later `bootout` succeeds. Final-head packaged
qualification, fresh review, and every exact-main gate passed. The exact-main
packaged job again observed roots `original -> worker -> original`; the worker
started at 16,739 ms, Chrome retried the original navigation at 28,718 ms, and
the styled page completed in 24,727 ms with exactly one CSS, JavaScript, image,
and ready callback, with extensions disabled and no manual reload. Worker and
original-capture cleanup, uninstall, sentinel connection/state, and global PF
were clean, preserved, or unchanged. Capability
and guard state share one 32-entry bound; new jobs are rejected at capacity,
so a live worker's authority and guard are never evicted by host churn.
An enqueue rejection removes the unstarted job without a guard. After a false
notification, queue discard and the no-worker proof occur under the worker's
lifecycle lock; a claimed or restarting worker therefore keeps both job
authority and the expiry guard. Proven-unstarted retries remain fast.
No normal-path browser, broad host cooldown, route-policy change, or network
setting mutation is added.

That merge completes the active-worker uninstall ownership transaction. The
exact-main packaged job first proved one correlated worker process, exact live
Chrome profile, private runtime, and matching loaded LaunchAgent with root
channels `original -> worker`. The normal installed uninstaller then completed
the worker and original-capture cleanup, removed the installed state, preserved
the sentinel connection/state, left global PF unchanged, and reported clean
uninstall. Its three-second idle sample observed zero worker processes or
profiles, a mode-`0600` broker, and 400 ms daemon CPU.

PR #330 production-composes and qualifies the complete pending-navigation
transaction without changing PF, DNS, proxy/PAC, VPN, external Geph, Discord,
YouTube, or Googlevideo policy. One eligible public unknown-host request stays
on the installed PF/daemon path through the existing complete-TLS-record and
eight-second idle gate. The owner-only mode-`0600` broker starts at most one
lazy Aqua worker; its independently pending same-host navigation can advance
only the original relay-bound capability. Chrome then automatically repeats
the unchanged original URL and loads the styled page without an extension or
manual reload.

The exact-main packaged job observed roots `original -> worker -> original`.
On the fixture clock the worker began at 16,637 ms and Chrome's original retry
at 28,933 ms; the separately measured Chrome transaction reached styled
completion in 25,003 ms with exactly one CSS, JavaScript, image, and ready
callback. Worker cleanup, uninstall, sentinel connection/state, and global PF
were clean or unchanged. The preceding three-second idle sample observed zero
worker processes/profiles, an empty runtime, a mode-`0600` broker, and 490 ms
of daemon CPU.

That gate also exposed and corrected the packaged composition boundary: the
frozen installer now derives the exact executable in its own
`Contents/MacOS/slipstream`, rejects an absent, symlinked, non-executable, or
group/world-writable worker, and pins the XML-escaped absolute path in the
root-owned LaunchDaemon environment. The normal installed app therefore does
not depend on an assumed `/Applications` location, while the source-mode
fallback remains unchanged.

Local branded-Chrome evidence on 2026-08-12 showed the required browser
handoff without an extension or manual reload: the first exact top-level HTTPS
request remained open for 8.2 seconds and ended with
`net::ERR_EMPTY_RESPONSE`; Chrome then issued a second request to the same URL
and committed the styled page. This is compatibility evidence, not yet a
release gate. The ordinary pinned-Chromium CI job now contains the same
extension-free automatic-retry scenario so upstream retry drift will fail the
branch before merge.

Current local verification passes 1,196 Python tests plus 54 subtests, focused
Python compilation, 96 tray, 35 core, 241 Windows-adapter, 40 userspace-stack,
and 40 selected-stack/effect Rust tests, all five Rust clippy gates, contract
JSON parsing, and `git diff --check`. The required
codebase graph transport was retried and again returned `Transport closed`;
bounded source inspection used the documented fallback. Active-worker uninstall
has no remaining PR or exact-main gate.

The first two packaged attempts found two real qualification boundaries. A
hosted console-user Chrome profile is not reliably under `/tmp`, so the gate
now derives and saves the exact live worker `--user-data-dir`. Separately, an
uninstaller process retains only the three disposable CI markers while the
owned worker plist retains the complete closed fixture environment. Stale
cleanup now accepts that persisted environment only when all markers are exact,
every additional key is in the frozen browser-worker allowlist, and every value
passes the original nonempty, bounded-string, and NUL rejection rules. Normal
production cleanup still requires the exact base environment.

The next packaged attempt confirmed a second separate-process boundary: the
CLI uninstaller also does not inherit the LaunchDaemon's pinned worker
executable. Uninstall cleanup now recovers that string only from the still
present root-owned mode-`0644`, nonsymlinked, size-bounded LaunchDaemon plist
after validating its label, exact installed-daemon command/port, installed
working directory, and canonical `Contents/MacOS/slipstream` layout. The
runtime cleanup continues to validate the worker plist, UID, command, label,
and private files before signalling anything. A missing or mismatched pin
therefore still fails closed.

The final failed packaged attempt passed that uninstall boundary and removed the
LaunchAgent, worker, runtime, daemon, broker, and installed payload, but found
the worker's exact private Chrome profile still present. `SIGTERM` previously
terminated the Rust worker before its owned Chrome/profile cleanup could run.
The hidden worker now installs a termination flag, leaves its 250 ms DevTools
read loop, performs its existing exact-profile Chrome cleanup, and deletes the
profile. Stale cleanup waits at most eight seconds for this verified worker to
exit and requires its bounded `worker_terminated` result before `bootout`; a
timeout or cleanup error still fails closed rather than scanning or signalling
unrelated Chrome processes. Exact-main packaged job `94017024721` confirms the
corrected transaction and ownership invariants described at the top of this
checkpoint.

Historical protected run `31511415912` qualified earlier main
`8fe21229994e0ddc643762d0ece2203bc79313cc`. Its
`navigation_pending` scenario emitted one privacy-bounded v3 signal, performed
one reload, and reached the styled CSS/JavaScript/image-ready callback; the
incomplete-response and regional-denial scenarios passed the same
styled-resource requirement. Owned Geph returned HTTP 200 payload initially,
trayless, and after KeepAlive replacement. Cleanup preserved the external
listener, left the root daemon absent and disabled, and did not mutate system
network state. That unpacked-extension evidence and its artifact are superseded
by current run `31587594114` and artifact `9137909918` recorded at the top.

Artifact `9110154812` was the exact input to controlled workstation transaction
`271C43D9-4906-4AF3-88E8-C2EF146A33ED` and belongs to earlier main
`8fe21229994e0ddc643762d0ece2203bc79313cc`. The packaged daemon became coherent
and active, but a fresh isolated headed branded-Chrome visit to
`xpersonatoy.com` remained pending at `about:blank` for 75 seconds. The
transaction immediately performed exact rollback, restored prior app hashes,
removed Slipstream's privileged/runtime state, and preserved byte-identical
DNS, proxy/PAC, VPN, and default-route snapshots. The exact native-host manifest
was registered, but the clean browser profile did not contain the unpublished
companion; the root log therefore contained no semantic or recovery event.
Protected unpacked-extension success cannot qualify production browser
distribution.

PR #321 supplies the reviewed deterministic Chrome Web Store package and
provenance builder, frozen extension/native-host identity and source allowlist,
privacy disclosures, and store listing copy. The v0.2.1 archive
`output/chromium-store-0.2.1/slipstream-chromium-companion-0.2.1.zip` has
SHA-256
`6b2ea8a616095e26377feb77002aacc10b999e74ef1b78b8265132752956fa69`
and passes `unzip -t`.

On 2026-08-12 the publisher console was reached after manual Google sign-in,
but its one-time registration payment was declined with `OR_MIVEM_04`. No fee
was paid, ZIP uploaded, store item created, review requested, or publication
performed. Chrome Web Store publication is deferred and is not the current
implementation path.

The product invariant is `install Slipstream -> sites work`, including rare
browser-visible failures. Runtime observation and decisions must remain local;
the normal transport path remains browser-free, while any semantic/browser
worker must be lazy, bounded, performance-qualified, and capable of completing
the original user-visible navigation without separate extension setup or other
manual browser work. A successful synthetic page load alone is not completion.

PR #324 records the official macOS integration boundary and implements
the first local-worker qualification slice. The ordinary Chromium
`webRequest` CI gate now starts Chrome for Testing through LaunchServices in
unified-headless mode without a browser window, retains the sandbox and exact
owner-private profile, loads the frozen-origin companion, exercises native
messaging and styled-page completion, and fails if worker readiness exceeds 15
seconds, semantic completion exceeds 25 seconds, or de-duplicated physical
footprint exceeds 768 MiB. Aggregate RSS remains a diagnostic because macOS
counts shared mappings once per process. Local evidence is green: 278 script
tests, 850 daemon tests, 66 focused
traffic contracts, project-state validation, Python compilation, and
`git diff --check`. The first two real-browser attempts, run `31532156159` job
`93914552229` and run `31532531700` job `93915774541`, rejected direct binary
launch both outside and nominally inside the Aqua session: sandboxed Chrome
helpers could not look up the parent Mach rendezvous service and reported
bootstrap `Permission denied`, so the extension worker never appeared. The
correction keeps unified-headless mode and the sandbox but launches the app
through LaunchServices, the same macOS application boundary already proven by
the headed protected gate. The third attempt, run `31532847620` job
`93916800053`, then passed worker readiness, native messaging, the real
incomplete-response observation, reload, and styled-page completion. It failed
only because the first memory gate summed per-process RSS to 1,142,496 KiB,
which double-counts shared mappings. The corrected gate uses Apple's
multi-process `footprint` total, which de-duplicates shared objects, while
retaining aggregate RSS as a diagnostic.

Run `31533358388`, job `93918488548`, passed the corrected real-browser gate
on head `9926f4976d6de92f273e195a6e4c246a80733c72`. Chrome for Testing 151
started through LaunchServices in unified-headless mode with its sandbox and a
fresh owner-only profile. The frozen extension reached worker readiness in
5,476 ms, emitted the real incomplete-frame signal through native messaging,
reloaded exactly once, and reached the CSS/JavaScript/image-ready callback in
6,495 ms. De-duplicated physical footprint was 374,369 KiB against the
786,432 KiB budget; aggregate RSS was 1,234,672 KiB across four samples and is
diagnostic only. The job did not mutate system network state.

PR #325 implements the closed correlation seam
and freezes its cross-process shape in
`contracts/pending-navigation-probe-v1.json`. A daemon-minted random 128-bit
capability is bound directly to one already-live
eligible relay object plus its host, browser-request start, and local recovery
stage. It expires after 30 seconds, is capped at 32 process-local entries, is
revoked with relay teardown, and is consumed once. The worker result is
accepted only for the same host/start/stage after its own eight-second pending
observation; wrong-host, early, expired, malformed, rebound, and replayed
results are inert. The result invokes the existing local-stage reducer on that
bound relay without another hostname lookup. A closed async fixture starts two
equally timed same-host relays and proves that only the capability owner exits
while the other remains open. Verification passes 854 daemon tests, 278 script
tests, 24 Chromium companion tests, the 556-test focused relay/traffic set,
Python compilation, project continuity, and `git diff --check`. The seam is
deliberately not runtime-wired yet.

PR #326 implements the owner-only IPC boundary:
a dedicated versioned owner-only local job/result broker, separate from the
extension native-messaging protocol. The frozen production path is
`/var/run/slipstream-browser-probe.sock` with console-user ownership and mode
`0600`, while the current fixture proves those properties and exact cleanup on
a temporary socket without creating the production path. Requests are bounded
to 2 KiB and exact `claim`/`submit` shapes. At most 32 copied jobs exist; a job
must be freshly issued within five seconds, receives one monotonic expiry, and
a five-second claim lease allows safe redelivery after worker loss. Submit
removes the queued copy and delegates to the existing one-shot relay capability
reducer. The module is included in the script install payload but no socket,
poller, worker, browser, or routing effect is runtime-composed.
Local verification passes 861 daemon tests, 278 script tests, 24 unchanged
Chromium companion tests, Python compilation, JSON parsing, project continuity,
and `git diff --check`. Its six PR checks passed, it merged as
`2f37488d3c55f3ca29a622f6cc00455267ce1028`, and exact-main CI
`31538670468`, dependency audit `31538670392`, and Windows qualification
`31538670429` passed for that exact SHA.

PR #327 from branch `codex/lazy-pending-navigation-worker` adds a closed
one-shot worker client and lazy lifecycle controller. The client accepts only
the exact owner-owned mode-`0600` Unix socket and exact bounded claim/submit
responses.
No lifecycle thread exists before a live job; at most one blocking worker runs,
and a lost worker is retried only after the five-second claim lease while the
job remains live. Same-host capability exclusion now prevents a synthetic
worker relay from minting a recursive job; revoking the first capability makes
that host eligible again. The full daemon suite passes 866 tests. The real
browser observer and platform process launcher are deliberately not composed
by this closed lifecycle slice.

All six PR checks passed; it merged as
`86966e9e93b6344c13c5704f311e5468be17a35c`, and exact-main CI
`31541339436`, dependency audit `31541339377`, and Windows qualification
`31541339387` passed for that exact SHA. The current branch
`codex/sandboxed-browser-probe-worker` starts from that exact merge.

The historical PR #328 branch implemented that next closed slice. One exact hidden mode of
the packaged Slipstream executable claims the owner-only job, and an exact Aqua
LaunchAgent runs it as the active console user. It uses LaunchServices to open
signed Google Chrome in sandboxed unified-headless mode with extensions
disabled and a fresh owner-private profile. CDP observes only the exact
synthetic HTTPS root main document: eight seconds outstanding is
`navigation_pending`; response, redirect, load failure, or navigation failure
is `navigation_terminal` and consumes the capability without a route effect.
The result is submitted immediately after observation so bounded cleanup cannot
expire the live relay capability. Chrome, its profile-owned helper family, the
LaunchServices waiter, LaunchAgent, and profile are still removed before the
worker exits. Production paths are fixed; browser,
socket, origin, resolver, and certificate overrides exist only behind the full
disposable-GitHub-Actions gate. The ordinary path still creates no worker,
browser, thread, socket, or routing effect.

Local verification passes 869 daemon tests, 279 script tests plus 54 subtests,
93 Rust tray tests, focused Python compilation, Rust Clippy with warnings denied,
contract JSON parsing, and `git diff --check`. Required graph discovery was
attempted first and again returned `Transport closed`; fallback inspection was
limited to the existing browser launch, ownership, IPC, and cleanup seams. A
large-module context-mode review found and corrected an early cleanup exit so
the LaunchServices waiter is now stopped even when process enumeration fails;
the profile is retained rather than deleted whenever exact Chrome absence
cannot be proven.

The packaged gate exposed two current-Chrome compatibility boundaries before
route composition. Chrome for Testing `151.0.7922.138` no longer publishes the
legacy MV3 worker target, so only that superseded extension contract is pinned
to the proven `.77`. The `.138` macOS archive also has no outer bundle
`CodeResources`; a complete private copy therefore fails strict code-signature
verification and LaunchServices creates no process. Local reproduction reached
the same result. Ad-hoc signing was rejected because it no longer proves the
production identity and its DevTools endpoint died before use. Run
`31547878092` then exercised the runner's signed installed Google Chrome: the
exact profile-owned main process remained live, but silently failed to publish
DevTools within the fixed ten-second startup budget. The hosted packaged gate
therefore uses the same proven `.77` as the legacy gate, while a local run on
signed production Google Chrome 151 provides current-browser compatibility
evidence: two exact runs each produced one hanging HTTPS request, one
`navigation_pending` result after eight seconds, and complete cleanup in 10,797
and 15,785 ms. CDP HTTP reads now stop at one bounded `Content-Length` instead
of waiting for Chrome to close its persistent response connection.

Pinned packaged run `31549041776` completed the browser worker, exact fixture
request, one-shot submission, and launcher cleanup. Its final residue assertion
then matched the smoke harness's own still-live
`slipstream-browser-probe-smoke-*` temporary directory because the glob was
broader than the worker's exact 32-hex profile name. The residue gate now
matches only that exact worker shape; a focused test excludes the harness root,
non-hex suffixes, and wrong-length names.

The corrected exact head passed all six required checks. Run `31549452164`,
job `93968755542`, observed exactly one hanging main-document request and one
`navigation_pending` result in 13,009 ms, with the sandbox retained, no visible
window, and no browser-profile residue; the later packaged lifecycle stages
also passed. Jobs `93968755462`, `93968755558`, and `93968755604` passed the
common, Windows-adapter, and legacy Chromium contracts. Audit run `31549452162`
passed jobs `93968755330` and `93968755382` for dependencies and vendored Geph.

PRs #329 through #335 completed automatic original-navigation composition,
installed update, active-worker uninstall, measured idle cost, cleanup,
exact-main evidence, and protected exact-artifact qualification. Protected run
`31587594114` is the completed repetition of the extensionless transaction.
Exact extension ID `cecdingohhpfggapnlbghppcegbaciam` remains frozen for the
archival Web Store package, but it is no longer a runtime or workstation gate.
Only artifact `9137909918` may enter a later controlled workstation transaction.

## Previous Checkpoint

Current user-facing priority: Slipstream remains exactly rolled back and must
not be installed from the current development branch. PR #312 is merged as
live main `58a67d0262fc8331dae05e615aaa61ce032a41a6`. Exact-main CI
`31431925679`, dependency audit `31431925668`, Windows qualification
`31431925670`, and the single protected owned-Geph qualification
`31432845423` passed. Protected artifact `9079910704` has outer digest
`sha256:1fe5eb0791e485fc20a4ae0101bf56400cb137bf330d05130e346151ca724f83`
and inner ZIP SHA-256
`eb58df06b921fb577826796f90dda81ebc86dc6ff254ba246944252335e141fd`.

Controlled workstation transactions
`257E1EB0-1DED-4F17-8963-22550D568B9B` and
`D64565C3-A494-4C82-8C15-ABB69275C259` installed only that exact artifact.
Modrinth, Steam, Google, Spotify, Discord updater/gateway, YouTube, real
Googlevideo playback, CrystalIDEA, and ChatGPT transport passed on the first
attempt. A fresh headed Chrome navigation to `xpersonatoy.com` remained pending
for 75 seconds both normally and with QUIC disabled. The browser displayed
`about:blank`, while copying its address produced `xpersonatoy.com`: the target
navigation existed but had not committed its first document. Both transactions
performed exact rollback and preserved DNS `111.88.96.50` / `111.88.96.51`,
proxy/PAC, VPN, default route, external PF owners, and process ownership.

Read-only A/B controls separated the remaining failure from browser cache,
QUIC, IPv6, and the owned tunnel. Fresh direct Chrome used IPv4
`23.227.38.70:443` and stalled with QUIC disabled, while the same origin loaded
through the unchanged ownership-verified Geph listener. Curl received a
Cloudflare JavaScript challenge, so it is not a semantic authority for this
browser-visible case. The private daemon log contained no route event for the
host.

Code tracing found that an unknown local route committed after valid TLS server
records and then waited indefinitely when no first real document followed.
The existing idle observer recorded evidence but was deliberately excluded
from relay completion, so the browser could not retry and recovery never
advanced from system destination to app-owned DNS, local strategies, or the
independent owned-Geph proof. A local browser fixture confirmed that Chrome can
retry one top-level navigation across bounded pre-response connection closes
and commit the later response.

PR #313 on `codex/unknown-host-pre-response-retry` is open. Its pre-hardening
branch HEAD `b6be0a925359cc339ff2855c49836a47f53a0265` passed CI/audit run
`31474229009`, but two review conversations remain unresolved. Review correctly
rejected the original byte-only idle authority because a healthy quiet
WebSocket can have the same shape, and it required the final relay to remain
open when confirmation cannot be scheduled.

The current review hardening introduces frozen semantic signal v3. Chromium
or Safari source may report `navigation_pending` only after the browser still
owns one top-level HTTPS request for eight seconds and the tab remains loading
the same normalized `pendingUrl`. The signal contains no URL, path, query,
request ID, tab ID, page text, or cookie. The daemon correlates its hostname and
request start to one live public exact unknown-host relay within five seconds,
then rechecks valid complete TLS records, less than 8 KiB downstream, and no
recent progress. Relay silence alone can no longer close a connection. Each
accepted signal advances only one incomplete local stage. After system,
app-owned DNS, and two distinct local strategies, the final relay closes only
after independent direct/owned-Geph confirmation succeeds; refusal or failure
keeps it open. Static/direct/protected policy, Discord, YouTube, Googlevideo,
external Geph, and external network settings remain excluded. No hostname rule
was added.

Current verification passes Python/script `1105` plus `41` subtests, Chromium
`24`, Safari bridge `7`, Rust tray `84`, core `35`, Windows adapter `241`, and
both userspace evaluation crates `40` each. Python compilation, Rust formatting,
all five Clippy checks, project continuity, and `git diff --check` pass. The next
verified action is to complete remaining full Rust/project checks, push this
review hardening to PR #313, resolve both review conversations, and merge only
after required checks are green. Then require exact-main CI/audit/Windows and
exactly one fresh protected qualification. Only that newly qualified artifact
may enter another controlled workstation transaction, with `xpersonatoy.com`
early in the real browser smoke and immediate exact rollback on the first
failure.

## Earlier Checkpoint

Controlled transaction `C17E2DFE-CC33-4FBE-8C61-8F76418D98C5` installed only
that exact artifact and reached coherent active StatusV2. Google, Spotify,
Discord updater/gateway, YouTube plus a real Googlevideo fragment, Steam,
CrystalIDEA, ChatGPT, and Modrinth returned payload. Four
`xpersonatoy.com` HTTP/2 requests returned `200` but ended with curl error `18`
after 55-70 KiB. Immediate exact rollback restored the prior app SHA-256
`3931c16e158a223c0cdcb533bf77698e89e5df3f80015ead153dace86ff2a710`,
removed the root daemon, listener, private PF anchor, token, status, socket,
attestation, witness, and runtime, and preserved DNS `111.88.96.50` /
`111.88.96.51`, Slipstream-owned Geph PID `887`, external Geph PID `574`,
proxy/PAC, default route, and external owners. The private log contained no
recovery event for those requests.

The follow-up branch `codex/partial-response-recovery` fixed the protocol mismatch
without adding a hostname rule. PR #305 correctly records bounded HTTP/2
client-first and server-first candidates, but the independent completion probe
advertised no ALPN and sent HTTP/1.1. A complete HTTP/1.1 response could
therefore reject evidence from a genuinely truncated HTTP/2 route. Completion
probes now advertise `h2` and `http/1.1`; negotiated HTTP/2 is complete only on
`END_STREAM` and incomplete only after successful response headers plus body
bytes followed by reset, EOF, or deadline. HTTP/1.1 remains the fallback when
HTTP/2 is not negotiated.

PR review found two authorization edge cases in that new parser. A protocol
parse error after valid headers and payload is now explicitly unknown instead
of proven incomplete. A `GOAWAY(NO_ERROR)` whose `last_stream_id` includes the
active stream is treated as a graceful drain and the stream is read through
`END_STREAM`; an error GOAWAY or one that excludes the stream is unknown. The
probe intercepts only GOAWAY at the frame boundary because `hyper-h2` otherwise
closes its connection state before an eligible existing stream can finish. A
compressed response is also unknown even when status and payload preceded the
interruption; neither direct nor owned-Geph evidence may authorize from it. A
GOAWAY interleaved inside an unfinished HEADERS/CONTINUATION block is a protocol
error and cannot be hidden by graceful-drain handling. Once graceful drain has
started, a newly received `PUSH_PROMISE` is also a protocol error; existing
eligible streams may finish, but the peer cannot create new work after GOAWAY.
Repeated graceful GOAWAY frames may only retain or lower the accepted
`last_stream_id`; an increase is a protocol error. Generic TLS protocol errors
or local acknowledgement-write failures after payload remain unknown rather
than proving that the remote HTTP/2 stream was incomplete. An oversized frame
header is rejected before its missing payload can turn into apparent EOF
evidence, and DATA on `204`, `205`, or `304` is also a protocol error. The
server preface must begin with non-ACK SETTINGS; generic local socket errors
remain unknown, and a declared `Content-Length` is validated before body bytes
can exceed it. Standard frame stream-ID and fixed-length constraints are also
validated from the header before an absent payload can resemble an EOF. Frames
that carry response state must target the probe's sole active stream;
idle-stream targets are rejected from the frame header before their missing
payload can resemble an interruption. Server push is disabled in the client
settings and any `PUSH_PROMISE` remains a protocol error. An available padded
frame prefix is also checked immediately, so impossible padding cannot turn a
missing remainder into interruption evidence. Header-block sequencing is
validated at the frame header too: only the matching `CONTINUATION` may follow
an open block, and an orphaned `CONTINUATION` is rejected. A GOAWAY mandatory
prefix is validated as soon as it is available. More generally, interruption
may prove an unfinished HTTP/2 response only at an exact frame boundary; any
partial frame left in the receive buffer remains unknown. An unfinished body
that reaches the local byte cap is capped evidence and
remains unknown; an exact-cap body is complete only when `END_STREAM` arrives.
An unsolicited `206` is rejected; a ranged `206` requires one syntactically
valid `Content-Range` that begins at zero, remains inside the requested bound,
and agrees with any `Content-Length` and the completed body length. A stream
that reached `END_STREAM` but also recorded a later local protocol or
acknowledgement-write error remains unknown and cannot confirm owned Geph.

A non-mutating live control on the rolled-back workstation proved the corrected
direct HTTP/2 probe incomplete for the affected origin. The first owned-Geph
control exposed two additional bounded false negatives: the origin ignored the
requested range and completed at 1,045,719 identity-encoded bytes, above the old
512-KiB cap, while the six-second probe stopped after 470,846 bytes. Reusing the
existing two-MiB semantic cap and a background-only 20-second deadline produced
a complete 1,045,719-byte owned-Geph response through the unchanged verified
listener. Route learning still requires both independent proofs and applies
only to a later request. Opaque bytes, local truncation, `429`, compressed or
denial content, unowned Geph, static policy, Discord, YouTube, Googlevideo, and
external DNS/proxy/PAC/VPN/PF remain non-authorizing.

`weather.com` is the separate complete-page semantic class. Its observed text
`This content is no longer available in your area` already passes the generic
`regional_access_denied` detector without a hostname rule, and the protected
Chromium fixture proves confirmation plus one bounded reload. Ordinary Chrome
and Safari still do not receive that mechanism in production: Chromium needs a
reviewed store distribution and Safari needs a signed, enabled container plus
sandbox-to-owner-socket proof. Transport code must not pretend it can infer
rendered page meaning from encrypted TLS.

The correction adds the pure-Python `h2` stack as a hashed runtime dependency
and copies the protocol helper into the root script runtime. Local verification
passes with `1047` Python tests plus `41` subtests, `255` script tests, `21`
Chromium companion tests, `83` Rust tray tests, and `32` Rust core tests;
version continuity, project-state continuity, and `git diff --check` also pass.
A clean Python 3.13 PyInstaller build succeeds, its frozen `--status` command
runs daemon-free, and the archive contains the new protocol helper. The review
hardening still requires fresh PR checks. After merge, exact-main
CI/audit/native gates and one fresh protected account-backed qualification must
pass before another workstation install. That controlled smoke must pass the
partial HTTP/2 case before checking the separate Weather regional-denial
scenario; the first failure triggers exact rollback.

Historical checkpoint for exact main
`f8fb0c099c41f7e3bbd810042c8990a49febd665`: the protected run
`30764174229` passed, but controlled workstation transaction
`C3CDCD9F-F3A1-4733-9164-3C0A4A3FF5CB` exposed a generic incomplete-response
recovery gap and completed its exact rollback. The correction on
`codex/large-incomplete-response-recovery` had to pass full local checks, PR
CI/audit, exact-main CI/audit, and one fresh protected account-backed
qualification before another workstation installation.

The qualified artifact was `8838433677`, with inner ZIP SHA-256
`4e46c2c367c67335c60310ce69eeee07be8a628ec3c248559c2e5e62dd9e2c97`.
The corrected installer transaction reached coherent active StatusV2 and
preserved DNS `111.88.96.50` / `111.88.96.51`, proxy/PAC, default route,
global PF, the pre-existing owned Geph process, and Telegram proxy. Google,
Spotify, Discord, YouTube, Steam, CrystalIDEA, and the ChatGPT HTTP path
returned payload. Modrinth and `xpersonatoy.com` then returned HTTP `200` but
ended with curl error `18` after roughly 55-116 KiB. Immediate rollback
restored the prior app SHA-256
`3931c16e158a223c0cdcb533bf77698e89e5df3f80015ead153dace86ff2a710`,
removed every root-owned daemon/PF/runtime artifact, and left owned Geph PID
`71668`, Telegram PID `49694`, DNS, and proxy/PAC unchanged.

Code tracing found that the existing browser-independent detector cleared any
orderly server-first TLS close above 32 KiB as a completed response, while its
content-aware exact HTTP probe already supported bounded bodies up to 512 KiB.
The current correction introduces no host rule and does not raise the old
short-close threshold. Two repeated exact system/plain closes between those
bounds may schedule the existing certificate-validating HTTP completion probe;
opaque byte count cannot advance Xbox DNS, local strategies, or Geph. A
complete or otherwise unproven response stops. Only strict local incomplete
framing plus the independently complete owned-Geph proof may learn the exact
host. Discord, YouTube, Googlevideo, static routes, external Geph, and external
DNS/proxy/PAC/VPN/PF state remain excluded.

The chronological checkpoints below predate the live `3d40ce7` workstation
transaction unless they explicitly name a later main SHA.

Historical checkpoint for main `1be02bc8a4a410989b59ec601821e2bd6a9f1b19`:
protected run `30729228620` passed its only job
`91446387268`. It proved account-backed owned-Geph payload before tray exit,
after tray exit, and after a KeepAlive replacement; both Chromium semantic
scenarios (`incomplete_response` and `regional_denial`) completed one reload
with CSS, JavaScript, image, and ready-callback evidence. The daemon-free
boundary, every cleanup assertion, and system/network non-mutation also passed.

Artifact `8827417897`,
`Slipstream-owned-geph-qualified-1be02bc8a4a410989b59ec601821e2bd6a9f1b19`,
has GitHub digest
`sha256:4672cdc4e60137220230b917f96aefad04dc9ff09a8087551383ecd52ce545da`;
the downloaded exact ZIP has SHA-256
`a215f1f05037e01c3786a85cc388f5839a0a141d2c768e5a413bc162ff1b8391`.
The exact app installed successfully and reached active StatusV2. Google,
Spotify, Discord updater/gateway, YouTube plus a real Googlevideo fragment,
ChatGPT, CrystalIDEA, and Modrinth returned payload. Modrinth recovered from one
partial first response on retry. The first three `xpersonatoy.com` attempts
ended with curl error 18 after about 21.5 KiB. The daemon then retained an
exact-host Geph route for one hour, but the next transparent request returned
HTTP `429`, body `local_rate_limited`, and `Retry-After: 60`; the same result
remained after the advertised wait.

Immediate rollback restored the previous app SHA-256
`3931c16e158a223c0cdcb533bf77698e89e5df3f80015ead153dace86ff2a710`
and preserved the pre-existing owned Geph PID `10139`, Telegram proxy PID
`49694`, DNS `111.88.96.50` / `111.88.96.51`, proxy/PAC state, default route,
global PF, and every external anchor. The root launchd label is absent and
disabled; TCP/1080, the private anchor, PF token, status, socket, attestation,
witness, and hidden application swap paths are absent. Direct post-rollback
CrystalIDEA returned HTTP 200 and ChatGPT returned a complete Cloudflare HTTP
response, confirming that transparent interception is no longer active.

Code tracing found that `_try_unknown_owned_geph_route()` treated the first
opaque TLS record as both permission to serve the current request and proof for
a one-hour learned route. `_auto_geph_payload_probe()` separately accepted any
HTTP status from one `HEAD` response. Neither contract could reject a live SOCKS
listener whose next session returned `429 local_rate_limited`. The current
correction retains the one-shot Geph attempt after the complete local proof but
does not learn from encrypted bytes. Generic route learning now requires two
consecutive complete, usable HTTP responses on independent owned SOCKS
sessions; a failed second response enters the existing ownership-verified,
at-most-two-replacement recovery. The route remains unlearned and backend hold
remains intact until that independent proof succeeds. No hostname rule or PF,
DNS, proxy/PAC/VPN,
external-Geph, Discord, YouTube, or Googlevideo behavior changes.
For a long-lived one-shot connection, independent confirmation is scheduled as
soon as the first owned-Geph payload arrives, before the relay can outlive the
candidate window; session-draining replacement remains blocked until that
active relay has finished. If the early worker cannot complete confirmation
while the relay is active, one pending retry is consumed after the active
session count reaches zero; it cannot loop into another post-drain retry. A
live confirmation owns a unique worker token and cannot be evicted by elapsed
time while its bounded replacement sequence is still running. The post-drain
retry reserves the idle Geph session drain before consuming its marker, so a
new route cannot enter between the zero-session observation and confirmation.
That marker captures authorization while the original candidate is live and
survives candidate expiry until its one reserved retry is consumed, so a relay
lasting beyond the candidate TTL cannot cancel the recovery it deferred. If a
confirmation thread cannot start, its exact token and probe cooldown are
released immediately; the host cannot remain permanently wedged as active. The
fallback marker is taken before the early worker releases its lifecycle session
or attempts recovery, preventing the idle hook from launching a concurrent
post-drain worker for the same host, and restored only when an active session
blocks its drain. It is retained while owned Geph is unavailable, restored if
the post-drain worker cannot start, and retried by the monitor only after the
backend is ready. Retained authorization is insertion-ordered and capped by
the shared routing-state bound; learned or policy-invalid hosts are pruned and
the oldest authorization is evicted if the bound is exceeded. The two stable
HTTP probes share one lifecycle reservation and pin the exact owned listener
PID. Ownership and PID equality are checked before and after each response and
again at route commit; KeepAlive or external PID drift rejects the proof. The
learned route is committed before that reservation is released, and a recovery
worker reuses its already-held drain through proof and commit. Loss of verified
listener ownership, an unavailable restart, or a replacement that misses its
bounded recovery window is treated as backend unavailability, so an
already-consumed deferred authorization is restored and waits for a verified
monitor recovery instead of being immediately consumed again. Confirmation
requests ask for a bounded byte range and retain a two-MiB hard cap plus the
single end-to-end deadline, allowing a complete large response when an origin
ignores the range without accepting an unbounded stream.

After the Mac correction is qualified, the M4 next action remains
production-host sleep/wake recovery on disposable Windows, without production
networking composition. Updater/uninstall orchestration remains the following
bounded gate. The exact ARM64 physical reboot lifecycle gate is complete.

PR #293 merged the bounded two-replacement owned-Geph correction as exact main
`62aabd64d3f9dd0fd5f08401b198fc2ee35ae37d`. Exact-main CI `30693565371`,
audit `30693565390`, and Windows native qualification `30693565372` passed.
The sole protected run `30711121048` passed account-backed owned-Geph initial,
trayless, and KeepAlive-recovered payload, both Chromium semantic scenarios,
every cleanup assertion, and system-network non-mutation. Artifact
`8821938264`,
`Slipstream-owned-geph-qualified-62aabd64d3f9dd0fd5f08401b198fc2ee35ae37d`,
matched inner ZIP SHA-256
`e50bd77ca4fa94ea8077c5c105bc58ac34463945c50f3d0d29160f5b0f3a64d9`.

The controlled primary-Mac transaction installed only that exact artifact.
Its tray, daemon, and Geph hashes matched the qualified bundle; StatusV2 became
active; the private PF anchor contained only the expected loopback TCP/443
rules; `/etc/pf.conf`, global PF, DNS `111.88.96.50` / `111.88.96.51`,
proxy/PAC, default route, owned Geph PID/hash, and Telegram proxy remained
unchanged. Discord updater returned HTTP 200, Discord gateway completed
TLS/HTTP, YouTube returned a complete page, `yt-dlp` downloaded a real
Googlevideo fragment, and ChatGPT, CrystalIDEA, Modrinth, and Weather completed
TLS/HTTP payloads.

The next required generic smoke, `xpersonatoy.com`, returned HTTP 200 but ended
with curl error 18 after 16,401 bytes. Immediate rollback removed and disabled
the exact root daemon, listener, private anchor, token, status, socket,
attestation, witness, and root runtime; restored the prior app SHA-256
`3931c16e158a223c0cdcb533bf77698e89e5df3f80015ead153dace86ff2a710`;
and left owned Geph PID `55818` running. PF is disabled, the private anchor is
empty, proxy/PAC is off, and DNS/default route match preflight.

Post-rollback A/B confirms that the origin path is genuinely degraded rather
than made healthy by removal: direct traffic timed out after 50 seconds with
13,672 bytes. The unchanged owned `:9954` Geph session returned HTTP 429 with
an 18-byte response. Unlike the prior fixture-backed semantic scenario, the
curl gate cannot emit Chromium's exact incomplete-response signal, and the
user's ordinary Chrome/Safari installation has no production-delivered
companion that could do so. The current two-replacement recovery therefore had
no authorized trigger. This is a product delivery/recovery boundary, not
evidence for a per-site policy entry.

PR #292 merged the first semantic owned-Geph recovery as exact main
`3126f8404419403aee0eac0585a112c20b66cb78`. The sole protected run
`30591636334` passed owned-Geph initial, trayless, and KeepAlive-recovered
payload, both Chromium semantic scenarios, cleanup, and system-state
non-mutation. Artifact `8778619390` matched archive SHA-256
`3ca16e9303530a0ee288e1803196cd51bcb24146b399beea42a9cd5e674eb879`
and inner ZIP SHA-256
`f705c9063108e4d08e070093a4a97f4e0a9d9c235f404b2a24f4a49ac914efaa`.
Controlled transaction `C84FCEB4-DBB1-43C9-AA44-B0AF4243B6F7` reached fresh
active StatusV2 and preserved DNS `111.88.96.50` / `111.88.96.51`, proxy/PAC,
global PF, and external owners. Modrinth returned 1,959,739 bytes. The next
`xpersonatoy.com` smoke ended with curl error 18 after 19,139 bytes, so the
transaction immediately restored the previous app and exact user-owned Geph
runtime and removed the root daemon, listener, private PF anchor, token, status,
socket, attestation, and witness. Post-rollback DNS, proxy/PAC, and global PF
matched the pre-install snapshot.

Post-rollback A/B proved that one owned-Geph replacement is not always enough.
Direct `xpersonatoy.com` remained partial. The exact owned `:9954` listener
returned HTTP `429 local_rate_limited`; one ownership-verified LaunchAgent PID
replacement remained `429`, while a second replacement returned HTTP `200` and
a complete 1,058,817-byte response. The current correction permits at most two
sequential replacements inside one session drain and one ten-minute incident
cooldown, revalidates exact listener ownership and changed PID before each
probe, stops on first complete response, and otherwise fails closed. It adds no
hostname rule and changes no PF, DNS, proxy/PAC/VPN, external Geph, static
policy, Discord, YouTube, or Googlevideo behavior.

PR #291 merged the complete-proof convergence correction as exact main
`b29be61e554f5ad3ec71d2864e487fabbdb014cf`. CI `30586625792`, audit
`30586625648`, native Windows packet run `30586625811`, and the sole protected
account-backed qualification `30587085951` passed. Protected artifact
`8776982805` matched its GitHub SHA-256
`83522d4cc9b7064f96d8a942858f869f8550034a676e49be43d176f41a409669`,
inner ZIP SHA-256
`c9e5aa78169cc47c767e09b0148458d2141ea7da7c08326007dfec39d48c1439`,
and exact bundled executable identities. Transaction
`5B152F0D-7CC2-4160-80B6-10719A14FEB2` installed that exact app, reached fresh
active StatusV2, and preserved DNS `111.88.96.50` / `111.88.96.51`,
proxy/PAC, global PF, and external anchors. Modrinth returned a complete
1,941,091-byte response. The next required `xpersonatoy.com` smoke received a
partial response and triggered immediate exact rollback. The prior app/runtime
and owned-Geph LaunchAgent were restored; the root daemon, listener, private
anchor, token, status, socket, attestation, and witness are absent.

Post-rollback A/B evidence isolated a generic backend-session defect. Direct
`xpersonatoy.com` returned 20,169 bytes and then stalled. The exact owned
`:9954` Geph listener returned HTTP `429`, body `local_rate_limited`, and
`Retry-After: 60`. An ownership-verified `launchctl kickstart -k` changed only
the `dev.slipstream.geph` PID; the same SOCKS request then returned HTTP `200`
and a complete 1,060,480-byte response. The correction permits one such
restart only after an exact browser semantic failure and unusable complete
owned-Geph probe, requires the owned listener and a changed replacement PID,
waits for a live exact listener, and retries the exact probe once. A ten-minute
global restart cooldown, active-session drain, shutdown guard, static policy,
and exact ownership remain mandatory. External Geph, external network state,
Discord, YouTube, and Googlevideo remain untouched. No hostname rule is added.

PR #290 merged the bounded unknown-route timeout correction as exact main
`a4628c7301eee187c2dbc300b62adac05ff29846`. CI `30581889243`, audit
`30581889244`, and the sole protected account-backed qualification
`30582540761` passed. Artifact `8775261865` matched its GitHub and inner ZIP
SHA-256 values and was eligible for one controlled workstation transaction.
Transaction `1FD68287-13D3-44EF-9E58-AF0B25617C80` installed the exact daemon
SHA-256 `4ad1f755a81d690d1f065d568a97eaad9da49fd26f040b243f83134219c88b5a`,
reached active StatusV2 with owned Geph up, and preserved DNS
`111.88.96.50` / `111.88.96.51`, proxy/PAC, global PF, and external anchors
through installation. The first mandatory Modrinth smoke then reached the
original numeric destination but produced zero TLS bytes before the client's
15-second connect bound. Immediate exact rollback removed the root daemon,
listener, private anchor, token, status, socket, attestation, and witness,
restored the previous app/runtime and owned Geph LaunchAgent, and proved DNS
and proxy/PAC byte-identical to the pre-install snapshot.

Code tracing found a second generic convergence defect. The complete safe
promotion proof requires system, app-owned Xbox DNS, and two distinct local
strategy zero-payload outcomes. Production `GENERAL_STRATS` contains six
strategies, but `_handle_impl` kept running the remaining four after
`note_zero_payload_route_failure()` had already completed the proof, delaying
the owned-Geph attempt beyond the client bound. The prior regression replaced
the production order with exactly two strategies and masked that delay. The
current correction stops only the remaining unknown-host local probes when the
complete proof is returned, then uses the existing ownership, network-wide,
payload, and exact-host Geph gates. Protected/direct/static routes, partial
race evidence, cancellation, Discord, and YouTube remain non-promoting. The old
qualified artifact must not be reinstalled after this source change.

Exact main `60811c1ddeccecb15687978f3bca62d15f4b882c` passed CI
`30573765421`, audit `30573765030`, and protected account-backed qualification
`30574330659`. Artifact `8772158225` was therefore eligible for one controlled
workstation transaction. The install reached a fresh active StatusV2 while
preserving DNS `111.88.96.50` / `111.88.96.51`, proxy/PAC, global PF, and
external anchors. Discord gateway, YouTube control, and CrystalIDEA returned
payload, but the first generic Modrinth smoke timed out during TLS. Transaction
`1111DA3F-CFD4-4601-A2A5-A26372E4449D` immediately restored the previous app
and runtime and proved the exact root daemon, listener, private PF anchor,
token, and status absent. The previous tray and its separately owned Geph
LaunchAgent were restored; no root transparent interception remains.

The preceding defect was in the generic unknown-host pre-payload ladder. A
bounded direct or local read timeout published `pending`, the handler committed
that silent stream, and the same request could not continue to the next route.
The correction treats an owned bounded timeout as replay-safe only while zero
server bytes have reached the client, closes that attempt, and continues through
the existing system, app-owned Xbox DNS, distinct local strategies, and finally
verified owned Geph sequence. Cancellation, incomplete race evidence, protected
policy, direct policy, Discord, and YouTube remain non-promoting. The old
qualified artifact must not be reinstalled after this source change.

PR #287 merged the bounded payload image-release correction as
`8ef9fb3d3d4643f056793578511b693ef68b3fe5`. Exact-main CI
`30554495633`, audit `30554495985`, and native run `30554494634` passed.
Native jobs `90911349617` (AMD64) and `90911349663` (ARM64) both ran the
delayed exact-payload-release regression and the release-host
`prepare -> cleanup` preflight. ARM64 artifact `8764371538`, selected by that
run, commit, and architecture, matched its manifest, sizes, and SHA-256 values
on the host and inside the guest.

From clean snapshot `{2bb76695-9612-4180-ad43-9e19f0fcc11d}`, protected
transaction `2ba05071-ac83-44a7-ad5f-259f35579962` installed generation
`30554494634` with exact executable SHA-256
`02a4e1b6b1c5cdebed5c794c05ade0f166eb2e78f9046b0b526b9fb60b828440`.
A real restart changed boot identity and service PID from `5984` to `3348`;
the new process was created inside the new boot. `resume` returned
`outcome=passed` and `exact_uninstall_verified=true`. Independent checks found
the SCM service, owner record, active-install record, and exact payload absent;
the payload directory was empty and durable intent was `absent` for the same
identity. The harness verified sentinel SHA-256
`049a55607e7921e71a954200b3219272634a53b72d597e36d2b9cdde368bc044`
before removing its temporary sentinel. Guest DNS remained `10.211.55.1`,
WinHTTP remained direct, host DNS remained `111.88.96.50` /
`111.88.96.51`, and host PAC remained disabled. This proves the production
service lifecycle across a real reboot, not production Windows networking.

Every `main` push runs the unfiltered native workflow; PR jobs never publish a
bundle. Before upload, the exact release production host is built without
fixture features and proves `prepare -> cleanup` with terminal absence on the
native runner. The disposable host's `prepare` phase then requires a clean
exact service name, installs that same artifact through its public CLI,
verifies committed active-install evidence plus automatic-start readiness, and
writes an owner-protected transaction without rebooting the machine. After an
explicit real Windows restart, `resume` requires a changed boot identity, a
service process created inside the new boot, matching SCM/path/SHA/generation
evidence, an unchanged independent sentinel and read-only DNS/proxy/PAC
snapshot, then performs exact uninstall and proves terminal product absence.
Failure attempts the same exact owned rollback; identity mismatch refuses
mutation. CI preflight cannot claim the physical runtime result. Sleep/wake,
updater orchestration, production networking, and broader VPN coexistence
remain separate unproven gates.

PR #284 merged the bounded PowerShell `REG_BINARY` preservation correction as
`1f9e9768cb554d08a4ac888a842ee44c06897444`. Exact-main run
`30541625059` proved that correction on AMD64 and ARM64: all prior lifecycle,
packet, coexistence, cleanup, and lint gates passed, the release host built, and
physical-reboot `prepare` reached committed automatic-start readiness. The
immediate protected `cleanup` then timed out waiting for independent terminal
absence even though the public management command returned an accepted
uninstall. Packaging and upload were skipped on both architectures, so there is
still no qualified artifact and no physical Windows host transaction has been
attempted.

PR #285 moved the same release-host `prepare -> cleanup` preflight onto PR
native jobs and added bounded terminal diagnostics. Run `30543502731` reproduced
the failure identically on AMD64 and ARM64: SCM service absent, owner record
absent, service process absent, but active-install record and installed
executable still present after 30 seconds. The installed executable had invoked
its own `manage uninstall`; native delete-pending evidence was accepted before
the external filesystem reached terminal absence. The correction refuses
self-uninstall in the product controller and makes the protected harness invoke
the exact hash-verified source artifact outside the installed payload. PR and
main native jobs now prove that external-controller boundary before packaging;
artifact upload remains main-only.

PR #285 merged as `be460249494da8439ca0a4787cc1465263a06a91`.
Exact-main CI `30546039967`, audit `30546036589`, and native Windows run
`30546036086` passed. Native jobs `90882304030` (AMD64) and `90882304237`
(ARM64) both proved external-controller cleanup and uploaded commit-bound
qualification bundles. The ARM64 bundle was selected by exact run, commit, and
architecture; all three payload hashes and sizes matched its manifest before
and after transfer to the disposable guest. The guest then exposed the
separate dynamic-CRT portability defect described above, before any service or
product state was committed.

PR #283 merged the commit-bound physical reboot bundle workflow as
`3fad7d49de41eac41d3babb835828ccaed7642f1`. Exact-main run
`30539745019` passed every preceding native Windows lifecycle, packet,
coexistence, cleanup, and lint step on AMD64 and ARM64, then failed the
non-mutating network snapshot before the release-host preflight could install
the service. `Get-RegistryValue` returned a registry `REG_BINARY` through the
PowerShell pipeline, which expanded the original `System.Byte[]` into
`System.Object[]`; `Get-RegistryBinaryValueBase64` correctly rejected that
changed type. The same behavior was reproduced read-only on the disposable
Parallels Windows 11 ARM64 host: direct `System.Byte[]`, captured
`System.Object[]`, and comma-preserved `System.Byte[]`. Packaging and upload
were skipped on both architectures, so no artifact was selected and no
physical-host mutation was attempted.

Last exact-main evidence audit: 2026-08-01, through product merge
`3126f8404419403aee0eac0585a112c20b66cb78` (PR #292). Exact-main CI
`30591198059`, audit `30591198060`, and native AMD64/ARM64 run `30591198068`
passed on that SHA. The sole protected account-backed qualification
`30591636334` also passed and produced artifact `8778619390`; its controlled
workstation transaction and exact rollback are recorded at the top of this
checkpoint. The latest physical Windows reboot proof remains the PR #287 ARM64
transaction. This is not a physical AMD64 reboot claim; architecture-dependent
binary and lifecycle preflight passed natively on AMD64 and ARM64, while the
OS-level physical power-state transaction ran on the available disposable
ARM64 host.

Previous exact-main evidence audit: 2026-07-30, through product merge
`0ed37e7b828bb642700d6191e10206061c27c525` (PR #277). Exact-main
native AMD64/ARM64 run `30505427268`, CI `30505427291`, and audit
`30505427304` passed on that SHA. Native jobs `90754032083` and
`90754032064` proved exact production-host termination, public recovery,
process-instance replacement resilient to PID reuse, repeated-recovery
idempotence, independent-owner preservation, crash-budget reset, and exact
uninstall on both architectures. The rejected revisions and complete evidence
boundary are recorded in
[RESILIENCE.md](RESILIENCE.md#windows-production-host-evidence).

Previous exact-main evidence audit: 2026-07-30, through product merge
`ae4d47efdf8b3d15f5242eb767a809b5c775e75e` (PR #275). Exact-main
native AMD64/ARM64 run `30501851242`, CI `30501851261`, and audit
`30501851254` passed on that SHA. Native jobs `90743016854` and
`90743016815` proved byte-distinct generation 1 and generation 2 copies of
the real `slipstream-windows-service.exe` through their public
`manage install/uninstall` CLI against the same exact owned SCM name and
machine runtime root. Generation 2 started only after generation 1 proved its
SCM registration, content-addressed payload, owner record, and active-install
record absent while retaining the matching durable absent intent. An
independent sentinel inside the production-secured runtime root survived both
uninstalls, and both architectures finished with exact terminal absence.

Previous exact-main evidence audit: 2026-07-30, through product merge
`7f265549d727db93b8c0a7861808cc5f59784527` (PR #273). Exact-main native
AMD64/ARM64 run `30497886810`, CI `30497886818`, and audit `30497886814`
passed on that SHA. Native jobs `90730822239` and `90730822057` proved
disposable same-name Windows service-generation recovery: generation 1 and
generation 2 used the same exact owned SCM name and runtime root but
byte-distinct payloads. Generation 2 started only after generation 1 proved
SCM, installed payload, and durable lifecycle records absent; an independent
sentinel survived both cycles. CI jobs `90730821810`, `90730821828`, and
`90730821876` repeated the full Windows contract, packaged macOS lifecycle,
and common checks.

The first reviewed PR head was correctly rejected on both native architectures:
the exact-absence helper matched the struct-like
`WindowsServiceObservation::Absent` as a unit variant. PR #273 changed the
helper to compare against the canonical `WindowsServiceObservation::absent()`
value and then passed both native architectures without reruns. The gate did
not compose production networking or mutate routes, DNS, proxy/PAC/VPN,
drivers, or external services.

Previous exact-main evidence audit: 2026-07-30, through product merge
`3a26653a2b221d757834cdb8ceb53f95c4589906` (PR #271). Exact-main native
AMD64/ARM64 run `30494843668`, CI `30494843656`, and audit `30494843671`
passed on that SHA. The merge freezes a disposable same-name Wintun
capture-generation contract: generation 1 must remove its exact route,
address, session, and adapter before generation 2 may reuse that owned name,
while the pre-existing system route remains identical before, between, and
after both cycles. The native run proved this on both architectures together
with the earlier route-churn, independent VPN-like owner, packet handoff, and
exact-cleanup gates. CI repeated the complete Windows contract suite and the
packaged macOS lifecycle. The gate did not reinstall the driver, mutate default
routes, DNS, proxy/PAC/VPN, or external network owners, and did not compose
production Windows networking.

The first PR attempt exposed a fixture defect before product evidence was
accepted: `WindowsOwnedRouteTransitionIssuer::new` received the fixed route
epoch where it expected the capture generation, so the generation-2 proof
failed with `capture-generation issuer changed its generation`. PR #271
corrected the argument order and added a static regression for the exact
constructor call. The final PR head and exact-main AMD64/ARM64 jobs passed
without reruns.

The next M4 work is the remaining disposable Windows resilience
qualification: sleep/wake, full updater/uninstall orchestration, and broader
external network-tool coexistence. Explicit production-host process crash,
public recovery, and the bounded physical ARM64 reboot transaction are covered
independently of the earlier Wintun-child and generation-replacement gates.
Each gate must prove exact cleanup and preserve independently owned network
state before production service-host composition can begin. That later
composition must reuse the frozen capture, flow-binding, byte-owner,
selected-stack, connector, and Wintun ownership contracts rather than bypassing
them, remain disabled by default, and prove exact compensation before any
user-facing Windows preview is allowed.

Protected owned-Geph run `30429690683` was dispatched exactly once for previous
main `3b9075d8b63e12e9ce93b2a3ac973005f3d43c13`. Packaged resources, the
daemon-free boundary, owned-Geph initial, trayless, and KeepAlive-recovered
payload, and final cleanup all passed. Every
payload phase returned HTTP 200 over TLS 1.3 with `67973` bytes, and system
network state was not mutated. The second Chromium scenario timed out after one
root request with no reload or subresource request, so no qualified artifact
was published and no workstation installation was attempted.

The failure was in the disposable incomplete-response fixture, not Geph or
product routing. Its HTTP/1.1 handler advertised `Connection: close` and a
larger `Content-Length`, but `BaseHTTPRequestHandler` does not infer
`close_connection` from response headers. A keep-alive client therefore waited
on an open socket instead of receiving EOF and emitting the expected
incomplete-response event. PR #258 now closes the handler connection explicitly
and freezes the real TLS/HTTP regression. The next authorized protected action
is one run after the next UTC-day account reset. Installation remains
prohibited until that run passes both Chromium scenarios and publishes its
exact artifact.

Earlier protected run `30397332251` exposed a coordination defect rather than a
routing regression. The owned-Geph producer published `ready`, then a late
broker abort made it clean user resources while the Chromium consumer still
owned the root daemon and native-host manifest. This produced secondary
boundary and missing-manifest errors. PR #252 now retains a late abort until
the consumer publishes the exact private `release`, then reports the original
fail-closed reason and begins producer cleanup. Its PR gates passed, and
exact-main CI `30399287525` plus audit `30399287465` passed for
`c9d3117fe2ab37946522ddcd16cddb64efe4b55d`.

After the UTC-day reset, protected run `30411915972` was dispatched exactly once
on docs checkpoint main `bebb6776b554a01a7885b889d6d98c2a405d570c`.
Packaged-resource and daemon-free boundaries passed. Owned Geph returned the
same complete Steam payload initially, without the tray, and after KeepAlive
recovery: HTTP 200, TLS 1.3, and `68103` bytes in each phase. The frozen
regional-denial browser scenario completed before the harness entered
`incomplete_response`.

The second scenario made one root request and no reload or subresource request.
Chrome's documented `webRequest.onErrorOccurred` details omit `method` and
`parentFrameId`, while the v2 builder required both fields directly on that
final event. Synthetic unit tests had supplied an impossible event shape, so
the real event was silently rejected before native messaging. The exact
correction correlates a browser-owned top-level GET from `onBeforeRequest` to
the final event by opaque request ID, tab, and normalized hostname, using only
ephemeral `storage.session` state without path or query. The always-run cleanup
passed, system network state was not mutated, no artifact was published, and no
workstation install was attempted.

PR #254 merged that evidence-scoped browser correction plus redirect-safe
candidate cleanup as `45db4321bafe244c87986c4c08daf1c3afaf8bf2`, and both
its PR gates and exact-main gates passed. Protected run `30411915972` already
used the current UTC-day account-backed cycle before exposing the corrected
defect. Repeating the finite upstream authentication path before the next UTC
reset would be a prohibited hot-loop. The next authorized action is therefore
exactly one protected run after that reset for the then-current live `main`,
after verifying that it contains product merge
`45db4321bafe244c87986c4c08daf1c3afaf8bf2` and has green exact-main CI/audit.
No workstation install is authorized until the full run proves owned-Geph
payload, both Chromium semantic scenarios, exact cleanup, and publishes its
exact qualified artifact.

The full local suite passed with `840` Python tests and `32` subtests before
PR #248 merged. Exact-main CI run `30378302132` and audit run `30378302209`
passed. The one protected run `30379005119` then passed on the exact main SHA:
real owned-Geph Steam payload completed initially, without the tray, and after
LaunchAgent recovery; sandboxed Chromium produced one semantic callback and
one reload with complete CSS, JavaScript, image, and styled-DOM evidence; final
cleanup removed every owned user and system component without changing system
network state.

Protected artifact `8696275919`,
`Slipstream-owned-geph-qualified-8436ddfcfda6d3657912ec05674fb16ad17750d3`,
matched GitHub SHA-256
`d1929ddfc190450bc390026fc4af73bfc71b0510de110b288a363b6e42d0c1ec`.
Its inner app archive matched SHA-256
`fc6b974d544b43ee8335251a5fdf3ecec30a8171a9d9d9a400438260ae22f6bf`.

A controlled workstation transaction installed that exact app after preserving
the previous app, user runtime, LaunchAgent, owned-Geph identity, and external
network state. The installed root daemon matched the bundle SHA-256, StatusV2
was active with all ten canaries healthy, and DNS `111.88.96.50/51`, proxy/PAC,
default route, global PF rules, and the existing owned-Geph PID/hash remained
unchanged. Discord updater returned HTTP 200 with payload; Discord gateway
completed TLS/HTTP; YouTube control returned a 1.33 MB page and `yt-dlp`
downloaded a real Googlevideo media fragment; ChatGPT returned HTTP; and
CrystalIDEA, Modrinth, and Weather returned complete payloads.

The first `xpersonatoy.com` request nevertheless ended with curl error 18,
`Transferred a partial file`. The transaction immediately rolled back. A
post-rollback direct request reproduced the underlying network failure more
severely: it timed out after 35 seconds with only 13,672 bytes. This proves the
host needs alternate-route recovery. Once response bytes have reached the
client, however, the encrypted request cannot be assumed replay-safe and the
same connection cannot be moved to another backend. The runtime may retain this
evidence only for a subsequent client connection; a browser companion may
request one bounded reload only through an explicit replay-safe signal.

Main contains additive semantic-signal v2 without a hostname rule or a frozen
v1 change. Protected run `30393151116` showed that
`webNavigation.onErrorOccurred` did not expose the fixture's post-commit body
truncation. PR #251 replaced the Chromium and macOS Safari event sources with
read-only `webRequest.onErrorOccurred`,
scoped to HTTPS `main_frame` GET requests with frame ID `0` and no parent. The
same two exact incomplete-response error values, fixed v2 payload, owned-Geph
complete HTTP proof, static-policy precedence, Discord/YouTube exclusion, and
one same-host reload remain unchanged. The harness now identifies the failing
scenario and its bounded request counters. Local, PR, and exact-main gates
passed. The upstream broker rate limit blocked its sole account-backed
protected run before the two browser scenarios could qualify, so no exact
artifact was published or installed.

Rollback removed and disabled the exact root daemon, removed its plist,
listener, runtime, token, status, socket, attestation, and witness, and emptied
only `com.apple/slipstream`. The previous app was restored at SHA-256
`3931c16e158a223c0cdcb533bf77698e89e5df3f80015ead153dace86ff2a710`
and relaunched without reinstalling the daemon. Owned Geph remains PID `52893`
with its previous hash. DNS, proxy/PAC, default route, global PF rules, and
external anchors match the preflight snapshot. The next product gap is generic
incomplete-response evidence that advances a subsequent connection, plus an
explicit replay-safe companion path where available. No host-specific rule is
authorized by this evidence.

The following paragraphs retain earlier transaction history.

The single protected run `30318687293` then passed on that exact main SHA. It
proved account-backed owned-Geph initial, trayless, and recovered HTTPS payload;
sandboxed Chrome for Testing in the console user's Aqua session; one semantic
signal, one reload, CSS, JavaScript, image, styled DOM, and browser-ready
callback; and complete final cleanup. The run left no root daemon, private PF
state, token, loopback lease, status, semantic socket, learned route, Chrome
profile, native-host manifest, owned-Geph process or LaunchAgent, Keychain item,
or app runtime. System network state was unchanged.

Artifact `8673106618`,
`Slipstream-packaged-lifecycle-dde722435887154632dc4a0d9ba69ec9fc1f9f17`,
was downloaded by exact artifact ID and matched GitHub's SHA-256
`1cee7cbd6c825e133522b9fbe2d56e9b60c13aefc5c6ecd30299b4037497e347`.
A controlled workstation preflight found the earlier `0.1.9` app, root daemon,
and owned-Geph LaunchAgent already active. It preserved the existing app before
staging the qualified bundle and confirmed user DNS `111.88.96.50/51`, proxy
and PAC off, no active VPN default route, and healthy StatusV2. The first
bounded prompt expired while the user was away and performed no privileged
mutation. Two later user-present attempts exposed defects in the temporary
workstation transaction rather than a protected-gate or product-route failure.
The first privileged attempt had not copied the previous bundled daemon into
its rollback snapshot. It removed the newly installed daemon and restored the
old app, but could not reinstall the previous root daemon. The second attempt
started from that safe daemon-free baseline and installed the exact qualified
daemon, but the unprivileged coordinator tried to hash its deliberately
unreadable installed binary and received `Permission denied`.

The second attempt immediately requested rollback. The privileged transaction
uninstalled the new daemon, cleared only `com.apple/slipstream`, disabled the
exact launchd label, removed the plist, token, status, socket, and root runtime,
restored and relaunched the previous app exactly, and published
`root-rolled-back`. There was no rollback-failed marker. User DNS remained
`111.88.96.50/51`, proxy/PAC remained off, the existing owned-Geph PID and hash
were unchanged, and the restored tray executable matched the previous SHA-256.
Post-rollback direct probes received HTTP from ChatGPT and CrystalIDEA; Discord
timed out directly, as expected without Slipstream local bypass. The qualified
app is not installed, no root daemon or private PF runtime remains, and no
further workstation retry is permitted until privileged artifact attestation is
performed inside a disposable privileged transaction.

The current root-attestation change moves installed-daemon hashing and identity
verification into the privileged installer. It atomically publishes a bounded,
root-owned evidence record only after the installed path, SHA-256, owner, mode,
launchd PID, exclusive listener, fresh StatusV2 state, and private-PF state
agree. The tray validates that record against its bundled daemon without
opening the root-owned installed binary. Injected attestation failure enters
the same exact uninstall path and must leave a daemon-free baseline. This
change is not qualified until its pull-request packaged lifecycle and
exact-main gates pass; it has not been installed on the primary workstation.
PR #245 CI run
`30349298867` rejected the first implementation because mode `0700` also
prevented the intentionally console-user baseline child from traversing and
executing the frozen daemon. Both lifecycle jobs kept PF dormant and the
workstation was untouched. Follow-up run `30350707555` rejected execute-only
mode `0711` because the PyInstaller bootloader reads its own executable while
starting. It also kept PF dormant and touched no workstation. The current
follow-up restores root-only `0700/0600` installed identities and moves
console-user DNS and HTTPS qualification to fixed macOS `dscacheutil` and
`curl` children, so baseline health no longer depends on executing or reading
the installed daemon. Run `30352115171` proved those fixed children and the
before/after-PF HTTPS baseline in both lifecycle jobs, but rejected the
attestation harness after a legitimate `dormant` to `active` transition: the
root evidence retained its coherent time-of-install `dormant` snapshot while
the later lifecycle assertion incorrectly required it to equal the current
`active` status. Both jobs completed exact cleanup and the workstation remained
untouched. The current patch retries only an incoherent transition snapshot and
checks later daemon/PF state independently from the immutable install evidence.
That follow-up passed all PR jobs in CI run `30353331745` and dependency audit
run `30353331739`, including successful privileged commit, daemon-free injected
rollback, browser restarts, tray crash/restart, two wake/network-change cycles,
and exact sentinel/global-PF preservation. Merge then remained correctly
blocked by two unresolved review findings: reboot would erase evidence stored
under `/var/run`, and stale evidence could outlive a manually removed installed
runtime. The current review follow-up moves schema-v2 evidence to persistent
root-owned system Application Support and creates a sibling root-only hard-link
witness for the installed inode. The tray validates its exact device, inode,
mode, owner, and minimum link count without reading daemon bytes; removal or
replacement of the installed path therefore forces reinstall. This follow-up
must repeat the full PR gates before review resolution or merge. No workstation
component has been launched or changed.

PR #245 subsequently merged and all exact-main/protected gates listed above
passed. A bounded workstation transaction then preserved the previous app and
owned Geph, installed and attested the exact qualified daemon, reached fresh
active StatusV2, and proved private-PF commit without changing global PF owners,
DNS `111.88.96.50/51`, proxy, PAC, or VPN state. Discord gateway/updater,
YouTube control and real media, ChatGPT transport, and CrystalIDEA returned
payload.

The first generic unknown-host smoke, Modrinth, timed out during TLS. Root-log
evidence showed `geo-exit backend unavailable` at `17:31:20` and the exact
owned SOCKS backend up again at `17:31:23`. Complete exact-host evidence and
current backend readiness were conflated: the request could not survive that
transition, and the previous 30-second backend hold could still reject page
resources after an independent exact-host payload proof. No host rule was
added.

The transaction immediately performed exact rollback on that first failure.
The root daemon, launchd service, plist, private PF state, token, status, socket,
attestation, witness, and installed root runtime are absent; the service label
is disabled. The previous `0.1.9` app executable is restored at SHA-256
`3931c16e158a223c0cdcb533bf77698e89e5df3f80015ead153dace86ff2a710`.
The pre-existing owned-Geph LaunchAgent remains running as PID `52893`. Current
DNS is still `111.88.96.50/51`, and proxy/PAC remain off. No root daemon or
qualified new tray is running.

PR #246 implemented the generic re-admission correction. Only an
unknown host with the already-complete frozen local proof may wait up to five
seconds for a transient exact-owned `:9954` recovery. It actively probes that
owner-exact backend rather than depending on the five-second network monitor,
and rechecks listener conflicts throughout the wait. Its replay-safe request
may perform a bounded payload qualification during an older global hold; a
successful real payload clears that hold for following page resources. The
request also survives a concurrent background confirmation. Ordinary timeout,
missing or expired proof, protected/direct/static policy, external Geph,
listener conflict, failed payload, and network-wide failure remain
non-authorizing. Its PR, exact-main, and protected account-backed gates passed;
the later controlled workstation attempt and exact rollback are recorded in
the current section above.

## Resume Protocol

Before continuing existing work, including after context compaction or a bare
"continue" request:

1. Inspect the current worktree, branch, HEAD, and remote tracking state.
2. Inspect open and recently merged PRs plus the required CI jobs for the
   current HEAD.
3. Read this file, [ROADMAP.md](ROADMAP.md), and
   [DECISIONS.md](DECISIONS.md).
4. If commits landed after the evidence audit, inspect their diff and update
   the checkpoint before relying on its milestone labels.
5. Derive the next action from a concrete missing invariant or gate. Do not
   accept a milestone number from conversation or an old compaction summary as
   proof.
6. Prefer taking the verified action over repeating the roadmap. Update this
   file in the same PR whenever the milestone status or next action changes.

## Verified Checkpoint

| Milestone | Status | Evidence and remaining gap |
|---|---|---|
| M0 - Safe Base | Root daemon, private PF ownership, and exact launchd cleanup qualified on main | PR #220 closed the retained KeepAlive uninstall boundary with exact service-target bootout, plist fallback, bounded absence polling, and the prohibition on signalling any PID while launchd remains loaded. Packaged lifecycle passed on PR and exact main. Physical lid/default-route and broader split/per-app VPN qualification remain external gates. |
| M1 - Autonomous Routing V1 | Core routing and the extensionless automatic original-navigation path qualify on exact main; one controlled workstation transaction remains | PRs #219-#335 cover generic transport recovery, strict semantic qualification, owner-only daemon IPC, exact-host owned-Geph confirmation and re-admission, bounded automatic retry, exact worker/browser/profile cleanup, persistent privileged artifact attestation, and protected exact-artifact publication. Exact main `fcbcedaa4e812e5080a00ce3d7f4bb8e89c6aff5` passed CI `31587057669`, audit `31587057685`, native Windows `31587057755`, and protected run `31587594114`. That run proved the extensionless `original -> worker -> original` path, all styled resources, the semantic matrix, account-backed owned-Geph lifecycle, cleanup, and system-network non-mutation. The sole current transaction candidate is artifact `9137909918`; older artifact `8827417897` is historical and has no installation authority. Chrome Web Store publication is no longer an M1 prerequisite because the qualified local worker requires no extension setup. Any later controlled transaction must use only `9137909918` and roll back on the first failed smoke. Discord, YouTube, and Googlevideo remain local-only. |
| M2 - Contracts And Code | Partial | `slipstream-core` now owns policy classification, recovery, StatusV2, route-policy manifests and bundles, plus activation and rollback reducers. Python executes signed policy activation through that contract. Python PF/Geph orchestration and Rust tray runtime, installer, summary, and menu orchestration remain coupled. |
| M3 - Release-Grade macOS | Partial | Pinned dependencies, strict Clippy, explicit target, SBOM, manifest, audit, attestations, and preview releases are implemented. Stable publication is intentionally closed until Developer ID signing, hardened runtime, notarization, stapling, key custody, and rollback qualification exist. |
| M4 - Cross-Platform Core | Windows packet handoff plus bounded route, capture, generation, production-host crash, and physical ARM64 reboot resilience are exact-main green | Pure policy, recovery, StatusV2, signed-policy, activation, packet-flow, capture, flow-binding, byte-owner, selected-stack, connector, Wintun ownership, exact-route, coexistence, and cleanup contracts are qualified. PRs #267-#279 established packet handoff, route invalidation, capture/service generation, crash recovery, and boot admission. PR #287 merged the exact payload-release correction as `8ef9fb3d3d4643f056793578511b693ef68b3fe5`; exact-main native AMD64/ARM64 run `30554494634`, CI `30554495633`, and audit `30554495985` passed. Its exact ARM64 artifact passed the two-phase physical Parallels reboot and exact uninstall transaction. This is physical ARM64 evidence plus native AMD64/ARM64 binary and lifecycle preflight, not a physical AMD64 reboot claim. The evaluation stack remains development-only and the production SCM host remains no-network. Sleep/wake, full updater/uninstall orchestration, and broader external network-tool coexistence remain required before production service-host networking composition. Android/Linux adapters and the iOS feasibility gate remain later. |

The exact-main
[CI run 30230210126](https://github.com/aiwaki/slipstream/actions/runs/30230210126)
passed the ordinary checks but failed the Safari build's retained
LaunchServices-registration gate after compilation. PR #227 repaired that
bounded cleanup proof, and the exact merged commit passed `checks`,
`windows-adapter-contract`, and `packaged-app-lifecycle` in
[CI run 30231226271](https://github.com/aiwaki/slipstream/actions/runs/30231226271).
Its dependency and vendored-Geph audits passed in
[audit run 30231226301](https://github.com/aiwaki/slipstream/actions/runs/30231226301).
The following entries retain historical gate evidence for the components they
describe; they are not the current-main locator.
The Windows ownership collector and its disposable owner-only fixture passed in
[PR #147 CI run 29592866727](https://github.com/aiwaki/slipstream/actions/runs/29592866727),
alongside the required checks and packaged lifecycle job; its dependency audit
passed in
[run 29592866706](https://github.com/aiwaki/slipstream/actions/runs/29592866706).
The merged collector passed again on main in
[CI run 29594236053](https://github.com/aiwaki/slipstream/actions/runs/29594236053),
and its dependency audit passed in
[run 29594235966](https://github.com/aiwaki/slipstream/actions/runs/29594235966).
The native Windows payload transaction, disposable rollback cases, and strict
lint passed in
[PR #148 CI run 29597856734](https://github.com/aiwaki/slipstream/actions/runs/29597856734).
The merged payload transaction passed again on main in
[CI run 29598632346](https://github.com/aiwaki/slipstream/actions/runs/29598632346),
and its dependency audit passed in
[run 29598632248](https://github.com/aiwaki/slipstream/actions/runs/29598632248).
The lifecycle-state contract, protected filesystem transaction, disposable
interruption/compensation cases, and strict Windows lint passed in
[PR #149 CI run 29603653185](https://github.com/aiwaki/slipstream/actions/runs/29603653185).
The merged lifecycle-state implementation passed again on main in
[CI run 29605608961](https://github.com/aiwaki/slipstream/actions/runs/29605608961),
and its dependency audit passed in
[run 29605608707](https://github.com/aiwaki/slipstream/actions/runs/29605608707).
The exiting-Safari lifecycle regression and packaged smoke passed in
[PR #150 CI run 29604297728](https://github.com/aiwaki/slipstream/actions/runs/29604297728).
The action-specific Windows SCM gate, exact native registration/removal,
machine-wide lifecycle serialization, bounded stop wait, strict lint, required
checks, and packaged lifecycle passed in
[PR #151 CI run 29612116541](https://github.com/aiwaki/slipstream/actions/runs/29612116541).
That run also qualified independent owner/DACL verification for every returned
kernel-object handle and rejection of a permissive pre-created mutex.
Its dependency and vendored-Geph audits passed in
[run 29612116544](https://github.com/aiwaki/slipstream/actions/runs/29612116544).
The merged SCM implementation passed again on main in
[CI run 29612504541](https://github.com/aiwaki/slipstream/actions/runs/29612504541),
and its dependency audit passed in
[run 29612504538](https://github.com/aiwaki/slipstream/actions/runs/29612504538).
The single-lock native compositor, disposable real-service lifecycle, bounded
crash recovery, exact uninstall ordering, and injected post-commit compensation
passed in
[PR #152 CI run 29614734338](https://github.com/aiwaki/slipstream/actions/runs/29614734338).
That run executed the gated full-lifecycle test as one real Windows test rather
than filtering or skipping it. The dependency and vendored-Geph audits passed
in
[run 29614734358](https://github.com/aiwaki/slipstream/actions/runs/29614734358).
The command-wide Windows controller, exact evidence reconstruction, idempotent
same-identity install, and failed-then-resumed crash recovery across separate
controller processes passed in
[PR #153 CI run 29618202282](https://github.com/aiwaki/slipstream/actions/runs/29618202282).
Its dependency and vendored-Geph audits passed in
[run 29618202290](https://github.com/aiwaki/slipstream/actions/runs/29618202290).
The production Windows service host, exact command/result contract, bounded SCM
stop/shutdown state machine, current-executable staging, repeatable management
commands from separate processes, PID replacement after restart, exact terminal
uninstall, and strict Windows lint passed in
[PR #154 CI run 29620298459](https://github.com/aiwaki/slipstream/actions/runs/29620298459).
Its dependency and vendored-Geph audits passed in
[run 29620298461](https://github.com/aiwaki/slipstream/actions/runs/29620298461).
The exact merged PR #154 commit passed again on main in
[CI run 29620781624](https://github.com/aiwaki/slipstream/actions/runs/29620781624),
and its dependency and vendored-Geph audits passed in
[run 29620781600](https://github.com/aiwaki/slipstream/actions/runs/29620781600).
The active-table request admission, protected-host reclassification, and exact
data-plane effect recovery cursors passed in
[PR #155 CI run 29623740312](https://github.com/aiwaki/slipstream/actions/runs/29623740312).
The exact merged PR #155 commit passed all required jobs in that same main run,
and its dependency and vendored-Geph audits passed in
[run 29623740325](https://github.com/aiwaki/slipstream/actions/runs/29623740325).
The worker-host composition, Windows-only production build, deterministic
startup/drain/deadline vectors, and real SCM stop path passed in
[PR #156 CI run 29625004279](https://github.com/aiwaki/slipstream/actions/runs/29625004279).
The exact merged PR #156 commit passed again on main in
[CI run 29625340050](https://github.com/aiwaki/slipstream/actions/runs/29625340050),
and its dependency and vendored-Geph audits passed in
[run 29625340061](https://github.com/aiwaki/slipstream/actions/runs/29625340061).
The active-policy-bound direct connector, exact data-plane effect bridge, and
real Windows loopback connect/payload/reset/cancel/deadline/shutdown fixture
passed in
[PR #157 CI run 29627204384](https://github.com/aiwaki/slipstream/actions/runs/29627204384).
Its dependency and vendored-Geph audits passed in
[run 29627204387](https://github.com/aiwaki/slipstream/actions/runs/29627204387).
The exact merged PR #157 commit passed again on main in
[CI run 29627636788](https://github.com/aiwaki/slipstream/actions/runs/29627636788),
and its dependency and vendored-Geph audits passed in
[run 29627636787](https://github.com/aiwaki/slipstream/actions/runs/29627636787).
The owned-client ingress, deterministic first-delivery/no-progress boundaries,
and exact native Windows relay passed in
[PR #158 CI run 29630565455](https://github.com/aiwaki/slipstream/actions/runs/29630565455).
The exact merged PR #158 commit passed all required jobs again on main in
[CI run 29630725442](https://github.com/aiwaki/slipstream/actions/runs/29630725442),
and its dependency and vendored-Geph audits passed in
[run 29630725439](https://github.com/aiwaki/slipstream/actions/runs/29630725439).
The technology-neutral capture-source lifecycle, one-shot resource ownership,
absolute deadline preservation, duplicate-resource rejection, failure-atomic
handoff, and bounded shutdown passed in
[PR #160 CI run 29632297457](https://github.com/aiwaki/slipstream/actions/runs/29632297457).
Its dependency and vendored-Geph audits passed in
[run 29632297449](https://github.com/aiwaki/slipstream/actions/runs/29632297449).
The exact merged PR #160 commit passed all required jobs again on main in
[CI run 29632468996](https://github.com/aiwaki/slipstream/actions/runs/29632468996),
and its dependency and vendored-Geph audits passed in
[run 29632468994](https://github.com/aiwaki/slipstream/actions/runs/29632468994).
The checkpoint commit in PR #161 passed all required jobs again on main in
[CI run 29632983193](https://github.com/aiwaki/slipstream/actions/runs/29632983193),
and its dependency and vendored-Geph audits passed in
[run 29632983199](https://github.com/aiwaki/slipstream/actions/runs/29632983199).
The WFP mechanism decision, management-callout ownership correction, and
filter-first fail-open ordering in PR #162 passed all required jobs again on
main in
[CI run 29633994824](https://github.com/aiwaki/slipstream/actions/runs/29633994824),
and its dependency and vendored-Geph audits passed in
[run 29633994821](https://github.com/aiwaki/slipstream/actions/runs/29633994821).
The exact WFP wire/handoff merge in PR #163 passed all required jobs again on
main in
[CI run 29635704622](https://github.com/aiwaki/slipstream/actions/runs/29635704622),
and its dependency and vendored-Geph audits passed in
[run 29635704616](https://github.com/aiwaki/slipstream/actions/runs/29635704616).
The pure WFP runtime lifecycle, monotonic attempt binding, over-capacity stream
rejection, retained-resource teardown, and non-replaying effect recovery in
PR #164 passed all required jobs in
[CI run 29637212615](https://github.com/aiwaki/slipstream/actions/runs/29637212615),
and its dependency and vendored-Geph audits passed in
[run 29637212612](https://github.com/aiwaki/slipstream/actions/runs/29637212612).
The exact merged PR #164 commit passed again on main in
[CI run 29637402421](https://github.com/aiwaki/slipstream/actions/runs/29637402421),
and its dependency and vendored-Geph audits passed in
[run 29637402397](https://github.com/aiwaki/slipstream/actions/runs/29637402397).
The WFP management-session contract, same-generation proof invalidation,
failure-atomic dynamic transaction, Windows native compile/lint, and exact
empty-session qualification in PR #165 passed all required jobs in
[CI run 29639374347](https://github.com/aiwaki/slipstream/actions/runs/29639374347),
and its dependency and vendored-Geph audits passed in
[run 29639374357](https://github.com/aiwaki/slipstream/actions/runs/29639374357).
The exact merged PR #165 commit passed again on main in
[CI run 29639553087](https://github.com/aiwaki/slipstream/actions/runs/29639553087),
including one explicitly asserted WFP qualification test, and its dependency
and vendored-Geph audits passed in
[run 29639553086](https://github.com/aiwaki/slipstream/actions/runs/29639553086).
The PR #166 checkpoint commit passed all required jobs again on main in
[CI run 29640104120](https://github.com/aiwaki/slipstream/actions/runs/29640104120),
and its dependency and vendored-Geph audits passed in
[run 29640104123](https://github.com/aiwaki/slipstream/actions/runs/29640104123).
The official signed Wintun artifact admission, opaque resolver-evidence
binding, frozen IANA IPv6 allocation snapshot, and non-authorizing exact-route
contract in PR #167 passed all required jobs again on the exact merge commit in
[CI run 29646370056](https://github.com/aiwaki/slipstream/actions/runs/29646370056),
and its dependency and vendored-Geph audits passed in
[run 29646370093](https://github.com/aiwaki/slipstream/actions/runs/29646370093).
The PR #168 checkpoint merge passed all required jobs again on the exact main
commit in
[CI run 29646801180](https://github.com/aiwaki/slipstream/actions/runs/29646801180),
and its dependency and vendored-Geph audits passed in
[run 29646801183](https://github.com/aiwaki/slipstream/actions/runs/29646801183).
The native Wintun collector admitted both official AMD64 and ARM64 artifacts,
rejected a tampered DLL, and retained the read-only handle without loading the
adapter in
[PR #169 CI run 29648242778](https://github.com/aiwaki/slipstream/actions/runs/29648242778).
Its dependency and vendored-Geph audits passed in
[run 29648242770](https://github.com/aiwaki/slipstream/actions/runs/29648242770).
The exact merged PR #169 commit passed all required jobs again on main in
[CI run 29648441001](https://github.com/aiwaki/slipstream/actions/runs/29648441001),
and its dependency and vendored-Geph audits passed in
[run 29648440999](https://github.com/aiwaki/slipstream/actions/runs/29648440999).
The complete shared-destination conflict gate from PR #170 passed `checks`,
`windows-adapter-contract`, and `packaged-app-lifecycle` on the exact merge
commit in
[CI run 29650142948](https://github.com/aiwaki/slipstream/actions/runs/29650142948),
and its dependency and vendored-Geph audits passed in
[run 29650142955](https://github.com/aiwaki/slipstream/actions/runs/29650142955).
The macOS uninstall/drain safety change in PR #171 passed `checks`,
`windows-adapter-contract`, and the disposable `packaged-app-lifecycle` gate in
[CI run 29656556574](https://github.com/aiwaki/slipstream/actions/runs/29656556574).
Its dependency and vendored-Geph audits passed in
[run 29656556559](https://github.com/aiwaki/slipstream/actions/runs/29656556559).
The primary workstation remained uninstalled throughout that qualification.

The clean-install local-bypass repair and optional-backend state guards in
[PR #172](https://github.com/aiwaki/slipstream/pull/172) passed `checks`,
`windows-adapter-contract`, and `packaged-app-lifecycle` on the exact merge
commit in
[CI run 29663263685](https://github.com/aiwaki/slipstream/actions/runs/29663263685).
Its dependency and vendored-Geph audits passed in
[run 29663263691](https://github.com/aiwaki/slipstream/actions/runs/29663263691).
The packaged gate proved active local bypass without a Geph account or
listener and preserved the independent PF sentinel.

The exact artifact from that run was then installed twice on the primary
workstation. Both installs immediately coincided with broad HTTPS failures
before the tray was launched, while app-owned Geph was disabled. Both manual
uninstalls restored a process-free daemon state with no listener, runtime
install, or PF token and left the user's `111.88.96.50` / `111.88.96.51` DNS
and system proxy settings unchanged. The app bundle itself was not removed.
`Reconnecting 5/5` was also observed after cleanup, so that symptom is not yet
attributed exclusively to an active Slipstream PF path; the reproducible
install trigger still makes this build unsafe to reinstall.

The doc-only checkpoint rerun then reproduced the same class of failure in the
disposable packaged gate: Safari reported `You Are Not Connected to the
Internet` at `before-tray-start` while the private PF anchor was active in
[CI run 29666303800](https://github.com/aiwaki/slipstream/actions/runs/29666303800).
This confirms that the unsafe baseline is in the daemon data plane rather than
the tray, Geph account state, or the workstation's DNS configuration.

[PR #174](https://github.com/aiwaki/slipstream/pull/174) fixed the independent
tray-uninstall defect by moving app-bundle removal into a validated one-shot
launchd worker. Its complete CI, including `packaged-app-lifecycle`, passed in
[run 29665174375](https://github.com/aiwaki/slipstream/actions/runs/29665174375).

[PR #175](https://github.com/aiwaki/slipstream/pull/175) repaired the daemon
baseline without changing protected routing policy. Direct, unknown, non-TLS,
and no-SNI/ECH connections now relay the exact pre-PF destination without
alternate DNS, desync, or a first-payload gate. Recovery is deferred to a later
client retry and is armed only by an observed stall, repeated clean EOF, or
server-first zero-byte close; healthy low-volume streams do not feed it.
Orderly client EOF is preserved as a bounded TCP half-close. All required
checks passed on the exact reviewed head, including the packaged Safari,
Chrome, PF-sentinel, and lifecycle gate in
[CI run 29667950857](https://github.com/aiwaki/slipstream/actions/runs/29667950857).
The formerly failing `before-tray-start` Safari stage passed. The repair was
squash-merged as `a26e467`; that exact main commit passed
[CI run 29668308779](https://github.com/aiwaki/slipstream/actions/runs/29668308779)
and
[dependency-audit run 29668308760](https://github.com/aiwaki/slipstream/actions/runs/29668308760).
It has not been installed on the primary workstation.

[PR #176](https://github.com/aiwaki/slipstream/pull/176) recorded that
qualification boundary without changing runtime behavior and was merged as
`1f4cdd0`; its exact main commit passed CI and dependency audit.

[PR #177](https://github.com/aiwaki/slipstream/pull/177) then added the
automatic startup guard. It proves a small neutral HTTPS baseline through the
console user's current system route before PF and repeats only the same proven
numeric destinations after PF. A failed post-arm proof rolls back only
Slipstream-owned state. If PF cleanup itself is temporarily unavailable, the
daemon keeps its listener and runtime alive while retrying cleanup instead of
leaving a redirect to a dead listener. Install, reinstall, and uninstall also
use failure-atomic ordering. The exact merge commit `f5541a0` passed the full
disposable Safari, Chrome, PF-sentinel, and packaged lifecycle gate.

[PR #178](https://github.com/aiwaki/slipstream/pull/178) closed the remaining
macOS loopback gap. It clears only `PFI_IFLAG_SKIP` under a durable root-owned
`0600` lease, restores and verifies the original `lo0 (skip)` state before
releasing the owned PF token, quiesces the `KeepAlive` daemon before signalling
verified owned processes, and moves tray recovery behind the installed daemon
ownership boundary. The redirect excludes `127.0.0.0/8`, and the active monitor
revalidates loopback visibility if another PF reload changes it. Both the PR and
the exact main commit `162cc8e` passed the disposable private-PF sentinel and
packaged lifecycle. The primary workstation had remained uninstalled since the
unsafe baseline incident until the controlled validation below.

[PR #179](https://github.com/aiwaki/slipstream/pull/179) refreshed this
checkpoint without changing runtime behavior and merged as `c07ade34`; the
exact main commit passed required CI and dependency audit. Its packaged artifact
was then used for one controlled workstation validation. Preflight proved the
daemon job, owned Geph job, listeners, status, PF token, loopback lease, and
private anchor absent; the user's DNS and proxy settings were left unchanged.
The app bundle was replaced atomically with the exact signed artifact, but the
first daemon install timed out with `status missing`. The session log reached
the standalone Telegram-proxy check and no later startup line. Live diagnosis
showed the first synchronous system resolver call could stall while a later
neutral target remained reachable. The prepared rollback removed every owned
root runtime artifact and listener without a connection outage. The app bundle
remains present but unlaunched and inert; the root daemon is absent and
disabled, owned Geph is absent, and Slipstream PF is not active.

[PR #180](https://github.com/aiwaki/slipstream/pull/180) bounded that startup
path and merged as `140598b`. The daemon now publishes an atomic, probe-free
`dormant` StatusV2 snapshot after binding its listener and before Geph, DNS, or
PF qualification. System-DNS lookups run as the console user in killable child
processes under one total preflight budget; diagnostic refresh uses the same
bounded helper. The packaged lifecycle installs a scoped resolver blackhole for
the first neutral target and proves that status precedes the stalled query, a
later target can activate routing, no helper survives, and cleanup preserves
the independent PF sentinel. The exact main commit passed all required jobs in
[CI run 29707822352](https://github.com/aiwaki/slipstream/actions/runs/29707822352)
and dependency audit in
[run 29707822353](https://github.com/aiwaki/slipstream/actions/runs/29707822353).
That exact artifact is downloaded and signature-verified, but it has not been
launched or installed on the primary workstation. It was later disqualified
because this workflow had downloaded the superseded `geph-vendor-0.3.0`
artifact rather than the release revision recorded in the repository.

[PR #181](https://github.com/aiwaki/slipstream/pull/181) made all build,
qualification, and release workflows derive the immutable Geph tag from
`vendor/geph/VERSION` and `vendor/geph/SOURCE.json.release_revision`. Release
asset downloads now use bounded retries, require a complete requested asset
set, and never publish partial output. The exact merge commit `27363cd3` passed
all required jobs, including the disposable packaged lifecycle with
`geph-vendor-0.3.0-r1`, in
[CI run 29709766877](https://github.com/aiwaki/slipstream/actions/runs/29709766877),
and its dependency and vendored-Geph audits passed in
[run 29709766891](https://github.com/aiwaki/slipstream/actions/runs/29709766891).
No application or privileged component was launched on the primary workstation.

[PR #182](https://github.com/aiwaki/slipstream/pull/182) refreshed this
checkpoint after the revisioned artifact correction. [PR
#183](https://github.com/aiwaki/slipstream/pull/183) added the pure capture-only
Windows v2 classifier, and its exact merge commit passed all required jobs in
[CI run 29710542922](https://github.com/aiwaki/slipstream/actions/runs/29710542922)
plus dependency audit in
[run 29710542945](https://github.com/aiwaki/slipstream/actions/runs/29710542945).
[PR #184](https://github.com/aiwaki/slipstream/pull/184) made every owned-Geph
cleanup stage independent so a Keychain error cannot skip later runtime,
listener, sentinel, or root-boundary cleanup. Its exact main commit passed all
required jobs in
[CI run 29711400231](https://github.com/aiwaki/slipstream/actions/runs/29711400231)
and dependency audit in
[run 29711400215](https://github.com/aiwaki/slipstream/actions/runs/29711400215).
The protected `geph-qualification` environment is limited to protected
branches and now has the account secret required by its manual gate. Exact-main
run `31587594114` consumed that gate successfully; no missing-secret action or
repeat qualification remains open.

[PR #185](https://github.com/aiwaki/slipstream/pull/185) added the first native
Wintun lifecycle subgate. The exact admitted 0.14.1 DLL, unique adapter, minimum
128 KiB session, and adapter-removal proof passed on both native x64 and ARM64
Windows runners in
[run 29712583287](https://github.com/aiwaki/slipstream/actions/runs/29712583287).
The fixture configured no address or route and did not touch DNS, proxy, PAC,
VPN, or the Wintun driver. Its exact merge commit `d35ab35` passed the same
native x64 and ARM64 gate in
[run 29713033740](https://github.com/aiwaki/slipstream/actions/runs/29713033740),
all required checks and packaged lifecycle in
[run 29713033745](https://github.com/aiwaki/slipstream/actions/runs/29713033745),
and dependency audit in
[run 29713033754](https://github.com/aiwaki/slipstream/actions/runs/29713033754).

[PR #186](https://github.com/aiwaki/slipstream/pull/186) added the separate
abrupt-owner cleanup proof. The exact child-process adapter/session fixture
passed on native x64 and ARM64 runners in
[run 29713791755](https://github.com/aiwaki/slipstream/actions/runs/29713791755).
It used no process-name search, adapter or driver deletion, address, route, DNS,
proxy, PAC, VPN, or production-host composition. Its exact merge commit
`6c3759e` passed the same native gate in
[run 29714575179](https://github.com/aiwaki/slipstream/actions/runs/29714575179),
all required checks and packaged lifecycle in
[run 29714575187](https://github.com/aiwaki/slipstream/actions/runs/29714575187),
and dependency audit in
[run 29714575209](https://github.com/aiwaki/slipstream/actions/runs/29714575209).

The pure Windows packet-egress v1 contract now freezes the admission boundary
needed before a native loop-avoidance fixture. A plan requires short-lived
route evidence collected before capture plus an exact owned capture-route
activation from that baseline epoch to the current epoch. The transition must
retain the capture generation, destination, exact host prefix, and capture
interface identity; any later route-epoch change invalidates the plan. The
egress LUID/index identity and currently selected source address must still
match the baseline, alongside the public destination, source family, and
containing baseline route prefix. The capture interface is rejected. The plan
records the Windows IPv4/IPv6
per-socket interface value but performs no route query, socket operation,
adapter effect, route mutation, backend choice, or production composition.
The exact merge commit `1765398` passed the native x64 and ARM64 lifecycle gate
in
[run 29718757015](https://github.com/aiwaki/slipstream/actions/runs/29718757015),
all required checks and packaged lifecycle in
[run 29718757005](https://github.com/aiwaki/slipstream/actions/runs/29718757005),
and dependency audit in
[run 29718756994](https://github.com/aiwaki/slipstream/actions/runs/29718756994).

One earlier ARM64 attempt in
[run 29715892426](https://github.com/aiwaki/slipstream/actions/runs/29715892426)
reached the broad 20-minute job timeout inside the abrupt-owner cleanup step
without phase output. Later exact-head and exact-main runs passed, so this is
recorded as a flaky, insufficiently bounded qualification gate rather than
routing-runtime evidence. [PR #188](https://github.com/aiwaki/slipstream/pull/188)
bounds the exact-child wait, removes blocking cleanup from `Drop`, streams phase
output, and gives that step its own four-minute ceiling. Its exact merge commit
`f373339` passed native x64 and ARM64 qualification in
[run 29719510753](https://github.com/aiwaki/slipstream/actions/runs/29719510753),
all required checks and packaged lifecycle in
[run 29719510754](https://github.com/aiwaki/slipstream/actions/runs/29719510754),
and dependency audit in
[run 29719510744](https://github.com/aiwaki/slipstream/actions/runs/29719510744).
[PR #189](https://github.com/aiwaki/slipstream/pull/189) added the isolated
read-only Windows route/source observer. Its exact merge commit `b71042b` passed
the observer step and the existing Wintun lifecycle on native x64 and ARM64 in
[run 29721672134](https://github.com/aiwaki/slipstream/actions/runs/29721672134),
all required checks and packaged lifecycle in
[run 29721672179](https://github.com/aiwaki/slipstream/actions/runs/29721672179),
and dependency audit in
[run 29721672104](https://github.com/aiwaki/slipstream/actions/runs/29721672104).

[PR #190](https://github.com/aiwaki/slipstream/pull/190) sealed the
Windows route-transition issuer behind opaque, native-timestamped route
observations. Its exact merge commit `44afffc` passed the issuer and existing
Wintun lifecycle gates on native x64 and ARM64 in
[run 29726460677](https://github.com/aiwaki/slipstream/actions/runs/29726460677),
all required checks and packaged lifecycle in
[run 29726460692](https://github.com/aiwaki/slipstream/actions/runs/29726460692),
and dependency audit in
[run 29726460674](https://github.com/aiwaki/slipstream/actions/runs/29726460674).
The first ARM64 attempt for the PR in
[run 29725545540](https://github.com/aiwaki/slipstream/actions/runs/29725545540)
printed the exact crash-cleanup test's passing result, then remained inside the
PowerShell `Tee-Object` pipeline until the four-minute step timeout. Attempt 2
and exact-main both passed. This is a repeated qualification-harness failure,
not packet-runtime evidence; the current follow-up replaces that object
pipeline with a retained exact process handle, file-backed live output, and an
inner monotonic deadline before route-owner work resumes.

[PR #191](https://github.com/aiwaki/slipstream/pull/191) replaced that fragile
pipeline with the retained-process harness. Its exact merge commit `8d00c2a`
passed native AMD64/ARM64 packet qualification in
[run 29729362857](https://github.com/aiwaki/slipstream/actions/runs/29729362857),
all required checks and packaged lifecycle in
[run 29729362904](https://github.com/aiwaki/slipstream/actions/runs/29729362904),
and dependency audit in
[run 29729362872](https://github.com/aiwaki/slipstream/actions/runs/29729362872).

[PR #192](https://github.com/aiwaki/slipstream/pull/192) is the first
feature-gated exact-route ownership qualification. Its initial native run
[29730828356](https://github.com/aiwaki/slipstream/actions/runs/29730828356)
created the retained route on both AMD64 and ARM64, but the fresh
`GetBestRoute2` observation then failed with Win32 code `1232`: the unique bare
Wintun adapter had no usable source address. The correction keeps address
ownership outside the route owner and production host. The native fixture now
creates only `192.0.2.1/32` on its unique disposable adapter and polls the exact
row until its DAD state is `Preferred`, its `/32` and interface/address key are
unchanged, and `SkipAsSource` is false. It then runs the route qualification,
explicitly removes the address, and requires bounded absence before accepting
the route result. Its exact code head passed native AMD64 and ARM64 in
[run 29734712632](https://github.com/aiwaki/slipstream/actions/runs/29734712632),
all required checks and packaged lifecycle in
[run 29734712671](https://github.com/aiwaki/slipstream/actions/runs/29734712671),
and dependency audit in
[run 29734712698](https://github.com/aiwaki/slipstream/actions/runs/29734712698).
Both architectures proved route, address, adapter, and session cleanup.

[PR #193](https://github.com/aiwaki/slipstream/pull/193) adds the first
feature-gated socket-selection effect without adding production networking. Its
IPv4 UDP fixture proves that ordinary route selection points at the competing
Wintun `/32`, then sets `IP_UNICAST_IF` to the retained baseline interface,
reads the same host-order index back, binds the retained baseline source, and
connects without calling a send or receive API. Probe failure still runs the
owned exact-route cleanup and baseline recovery observation before it is
returned. The active-probe entrypoint itself requires the third socket-binding
CI gate; the probe-free exact-route wrapper retains the original two-gate
admission. The exact PR head passed the selected fixture and
all existing packet gates on native AMD64 and ARM64 in
[run 29739433700](https://github.com/aiwaki/slipstream/actions/runs/29739433700),
all required checks and packaged lifecycle in
[run 29739433665](https://github.com/aiwaki/slipstream/actions/runs/29739433665),
and dependency audit in
[run 29739433660](https://github.com/aiwaki/slipstream/actions/runs/29739433660).
Its exact merge commit `b3572863` passed again on native AMD64 and ARM64 in
[run 29741495033](https://github.com/aiwaki/slipstream/actions/runs/29741495033),
all required checks and packaged lifecycle in
[run 29741495030](https://github.com/aiwaki/slipstream/actions/runs/29741495030),
and dependency audit in
[run 29741495046](https://github.com/aiwaki/slipstream/actions/runs/29741495046).

## Next Verified Action

Merge PR #336, which records PR #335 and protected run
`31587594114` only after all six checks and exact-head review pass. The complete
automatic local-browser implementation and protected exact-artifact gate are
then qualified. Do not repeat the protected run or install its artifact during
this documentation transaction. Any later workstation transaction must use
only artifact `9137909918`, preserve external DNS/proxy/PAC/VPN/PF owners,
retain Discord, YouTube, and Googlevideo on local bypass, and roll back on the
first failed required smoke. Continue the next independent product milestone
from live `main` only after this evidence checkpoint merges.

Safari may advance through deterministic source, Swift contract tests, and
unsigned packaging, but the signed app-extension sandbox/socket path must be
proven on a disposable build before it is bundled, enabled, or described as
runtime-ready.

Continue M4 on disposable systems. PRs #193 and #194 proved no-payload IPv4
and IPv6 socket selection under competing exact Wintun routes on exact main,
native AMD64 and ARM64, while removing every owned route, address, session,
and adapter. PR #195's exact main passed one synthetic IPv4 UDP datagram into
the owned capture ring and one synthetic response injected back to the same
socket under one strict deadline on native AMD64 and ARM64. It has no external
endpoint, backend, default route, production host, DNS, proxy, PAC, or VPN
effect. PR #196's exact main passed the equivalent closed IPv6 proof with its
mandatory UDP checksum in the audited runs recorded above. PR #197's exact main
then constrained `GetBestRoute2` to the retained baseline source/LUID while the
owned exact route was active, preserved kernel-selected synthetic VPN evidence,
and exposed field-specific mismatch codes before any active probe. PR #198's
exact main commit `c036fa1cad5bb95439f2ce98ad095267dfdd34a0` passed the bounded
pre-existing IPv4 UDP flow gate on native AMD64 and ARM64 in
[run 29962673071](https://github.com/aiwaki/slipstream/actions/runs/29962673071),
all required checks and packaged lifecycle in
[run 29962673111](https://github.com/aiwaki/slipstream/actions/runs/29962673111),
and dependency audit in
[run 29962673054](https://github.com/aiwaki/slipstream/actions/runs/29962673054).
The gate uses two owned IPv4 Wintun adapters, one owned non-default `/24`
baseline route, and one exact `/32` capture route. A connected UDP socket first
completes a checksum-valid closed baseline round trip. Under activation it must
either keep using that baseline path, or cause the active probe to fail so the
owner removes only the exact route and the same socket completes a bounded
baseline retry. Every acquired route and address reaches explicit verified
cleanup before any result is accepted. This closes only the first IPv4 UDP
subgate; PR #200 below subsequently closes TCP pre-existing-flow activation.
Crash-safe capture removal is closed by PR #202. At that checkpoint,
independent external-network-owner coexistence remained separate; PR #204 below
closes one bounded VPN-like route-owner case. Broader physical, full-tunnel,
split, and per-app vendor VPN qualification remains separate from the next
packet-to-flow contract and from production composition. A partial DNS cache is
never treated as complete attribution.
External DNS, VPN, proxy, PAC, and unrelated PF state remain read-only.

PR #200 is the independent IPv4 TCP pre-existing-flow gate. Its qualified code
head `d384817c7e64d79806c6ac18eab9a6f4803f3092` passed native AMD64 and ARM64
twice in
[run 29965217892](https://github.com/aiwaki/slipstream/actions/runs/29965217892),
all required checks and packaged lifecycle in
[run 29965217886](https://github.com/aiwaki/slipstream/actions/runs/29965217886),
and dependency audit in
[run 29965217897](https://github.com/aiwaki/slipstream/actions/runs/29965217897).
The final PR head repeated the native proof on both architectures before merge.
The exact main commit `8cac5602eaccd992a1f2a5e86bb2510aac789a9a` then passed native AMD64 and
ARM64 in
[run 29966086550](https://github.com/aiwaki/slipstream/actions/runs/29966086550),
all required checks and packaged lifecycle in
[run 29966086559](https://github.com/aiwaki/slipstream/actions/runs/29966086559),
and dependency audit in
[run 29966086558](https://github.com/aiwaki/slipstream/actions/runs/29966086558).
The gate establishes one real Windows TCP stream through the owned baseline Wintun ring,
requires a checksum-valid SYN/SYN-ACK/final-ACK exchange and a payload round
trip before activation, then accepts only baseline continuity or fail-closed
exact-route rollback followed by retransmission recovery. The same stream must
also complete another baseline exchange after route removal. Its first native
revision exposed that `peer_addr()` alone can become observable before Windows
has completed the handshake; the corrected candidate requires the captured
final ACK with exact sequence and acknowledgment numbers before treating the
stream as established. TCP pre-existing-flow activation is now closed. PR #202
subsequently closed bounded crash-safe removal of capture ownership without
inferring external-VPN coexistence from that result.

PR #202's crash-removal gate keeps the baseline adapter, exact source, and
non-default `/24` in the parent while an exact child process owns the
capture adapter, source, and production-gated `/32`. An atomic marker is
published only from the active probe. The parent independently observes the
active capture identity, terminates only that retained child handle, and then
requires bounded adapter, address, and `/32` absence plus exact baseline route
recovery. It uses no external endpoint, backend, default route, production-host
composition, DNS, proxy, PAC, VPN, broad process kill, or driver mutation.
PR #202 head passed this proof on native AMD64 and ARM64 in
[run 29967959561](https://github.com/aiwaki/slipstream/actions/runs/29967959561),
all required checks and packaged lifecycle in
[run 29967959616](https://github.com/aiwaki/slipstream/actions/runs/29967959616),
and dependency audit in
[run 29967959553](https://github.com/aiwaki/slipstream/actions/runs/29967959553).
The exact merge commit `ebe9f9c70b378f688badf6ba35cd96dd200d0bb4`
repeated native AMD64 and ARM64 qualification in
[run 29968586744](https://github.com/aiwaki/slipstream/actions/runs/29968586744),
all required checks and packaged lifecycle in
[run 29968586745](https://github.com/aiwaki/slipstream/actions/runs/29968586745),
and dependency audit in
[run 29968586782](https://github.com/aiwaki/slipstream/actions/runs/29968586782).
Crash-safe capture removal is closed. At that merge boundary, independent
external-network-owner coexistence was the next native gate; PR #204 below
closes its bounded synthetic route-owner case.

PR #204 narrowed that gate to independently owned route state. An exact
child process owns a uniquely named Wintun adapter,
the synthetic VPN-like source `198.18.0.2/32`, and a non-default public `/24`.
The parent owns a separate capture adapter and only the production-gated
destination `/32`. It must prove the child, adapter, address, and broader route
remain unchanged during activation, exact-route recovery, and Slipstream's own
capture cleanup. Ordinary route selection must return to the child-owned source
and interface before the parent releases it; the child then removes only its
own resources. No default route, real VPN endpoint or protocol, external
payload, backend, production-host composition, DNS, proxy, PAC, driver, or
broad process effect is present. Exact merge commit
`8c1addbcfeb93f6cbd64cac07b29b98f7aae4bbb` passed native AMD64 and ARM64 in
[run 29971683285](https://github.com/aiwaki/slipstream/actions/runs/29971683285),
all required checks and packaged lifecycle in
[run 29971683270](https://github.com/aiwaki/slipstream/actions/runs/29971683270),
and dependency audit in
[run 29971683269](https://github.com/aiwaki/slipstream/actions/runs/29971683269).
The independent VPN-like route-owner gate is closed. It does not qualify every
physical, full-tunnel, split, or per-app vendor VPN.

The versioned pure packet-to-flow v1 contract now lives after isolated capture
classification and egress admission in merged PR #206 at exact main commit
`e8cb475fc65a375d0dd57f757e2f5bc575a4fcde`. It keeps bounded TCP/UDP flow
ownership, backpressure, half-close/reset, timeout, route-class dispatch, and
cleanup outside the production SCM host and performs no socket, route, adapter,
DNS, proxy, PAC, VPN, or packet effect. Capture v3 preserves the client's
original destination port without changing frozen v2 policy semantics. Keyed
events update only one bounded flow, data-plane session/request ownership is
unique until generation retirement, admission consumes a binding minted from
the still-opening accepted data-plane session rather than an unrelated raw ID,
backend opening revalidates a fresh capability for that same current session,
retained command batches resume from an exact failure cursor without replay,
and a rejected reused request cancels only its exact new data-plane session.
Required CI and the disposable native AMD64/ARM64 workflow run this complete
packet-flow contract before the existing Wintun gates. Exact main
`c154f2d880d1d4aad34c83c813a03f11006b5d4e` passed that matrix in
[run 30465700678](https://github.com/aiwaki/slipstream/actions/runs/30465700678).
Capture v4 and userspace-flow-binding v1 now retain and validate the original
client source address/port without patching frozen capture v3 or packet-flow
v1. The binding requires exact generation, flow ID, transport, destination
address/port, IP family, active policy, and expiry agreement, and explicitly
keeps the original client source separate from the outbound egress source. It
also retains the exact admission capability, so byte ownership cannot open from
an independently valid same-key transition for another destination or request;
the complete backend-open and idle-deadline command set must match as well.
The bounded byte-owner bridge now retains exact flow, direction, sequence, and
payload bytes after successful packet-flow-v1 acceptance. Every active
transition must preserve the complete admission capability retained by the
immutable tuple binding and exactly equal a fresh reduction from its supplied
full predecessor and configuration. A bounded full-registry cursor advances on
exact unrelated transitions too, preventing a stale target-only snapshot from
rolling back another flow. It releases bytes
only after one injected atomic effect succeeds, retains the exact suffix on
failure, and accepts staging only from the exact current packet-flow predecessor
with the matching queue delta and transition-issued forwarding authorization.
Client payload queued before backend readiness remains non-forwardable until an
exact one-to-one `BackendReady` command set authorizes it. Ordinary terminal
cleanup removes only its exact flow; explicit generation retirement is
high-watermark bounded. Before either path releases bytes, its transition must
exactly equal a fresh reduction from the supplied full registry. Delivery preflights the exact acknowledgement from the
current full registry before invoking the effect, including its global
monotonic watermark. Generic reconciliation rejects `Forwarded` while an owner
exists, so it cannot skip the effect. A final acknowledgement that makes a
gracefully closed flow terminal also releases its empty owner immediately,
including when bounded terminal-history pruning removes that exact flow from
the reducer output. A separate test-only effect-evaluation crate now exercises
that owner against pinned `smoltcp` through a deterministic in-memory Layer 3
pair. IPv4/IPv6 TCP/UDP payloads cross in both directions, and an injected
pre-mutation failure retains the exact payload for one successful retry without
linking `smoltcp` into the Windows adapter. Bounded IPv6 fragment input is now
qualified separately in that isolated stack-selection harness. Its additive
capture-fragment composition classifies before state, binds assemblies to exact
capture identity and tuple, and expires them no later than the five-second
evidence deadline. An additive native connector contract now transfers one
exact client frame atomically into a bounded connector queue. Numeric loopback
TCP proves complete retention after failure-before-progress and exact suffix
retention after partial writes; numeric loopback UDP proves one complete
datagram. Every write revalidates the exact flow key, backend, and transport, while Discord,
YouTube, and UDP remain excluded from Geph. An additive composition now proves
selected-stack output reaches the connector queue and retains bounded native
backend reads until the selected stack accepts one exact frame. Flow, backend,
transport, and reverse sequence identity are revalidated before mutation, and
pre-mutation failures preserve the current byte owner. PR #263 added the first
test-only Wintun-to-stack packet handoff: a real OS IPv4 UDP request crosses an
exact owned route into Wintun, enters the pinned selected stack as the exact
captured Layer 3 packet, and returns to the OS only from the stack-emitted
response packet. The boundary is fixed-MTU, fixed-queue, bounded-poll, and
fail-closed. It merged as `105551ec27f8139e455783b7ae2bf89d63812166`;
exact-main native run `30472082661` passed on both AMD64 and ARM64, CI
`30472083693` passed including the packaged lifecycle, and audit `30472083055`
passed. The implementation remains a development-only qualification dependency
and does not compose networking into the production SCM host.

PR #265 completed the additive IPv6 UDP gate without changing frozen IPv4 v1.
A separate `raw_packet_udp_ipv6_v1` boundary validates one raw IPv6 UDP request
through pinned `smoltcp`, emits one checksum-valid fixed-MTU response, and
exposes bounded structured failures. The disposable Windows `/128` route proof
retains the exact captured packet and injects only that selected-stack response;
its manual IPv6 response builder is removed. It merged as
`9979889d82316f21701f1ef8304ffe3b8a11bb7d`; exact-main native run
`30476588359` passed on AMD64 and ARM64, CI `30476589552` passed including the
packaged lifecycle, and audit `30476588735` passed. The dependency remains
qualification-only and the production SCM host remains closed.

PR #267 completed the additive IPv4 TCP Wintun-to-selected-stack gate. A real
Windows TCP socket supplies the SYN, handshake ACK, and request payload; the
selected stack emits the SYN-ACK and response packets injected through the same
owned Wintun session. The proof contains no manual handshake or response packet
builder and preserves the exact route, address, session, and adapter cleanup
requirements. It merged as `0a787ee284c6e12fe9394a707ceaaff9e13deacf`;
exact-main native run `30481891835` passed on AMD64 and ARM64, CI
`30481892061` passed including packaged lifecycle, and audit `30481891839`
passed. The next independent M4 gate is bounded production service-host
composition; the existing production host remains no-network until that gate
passes.

## External Gates

- Qualify a physical default-route change and lid-close/wake cycle on a
  disposable Mac.
- Add Developer ID signing, hardened runtime, notarization, stapling, policy-key
  custody, and cross-version rollback before opening the stable channel.
- The local Parallels Windows 11 ARM64 VM has minimal Rust 1.97.1 but no Windows
  SDK or Visual Studio Build Tools; native compilation therefore remains a CI
  gate until that disposable VM is provisioned deliberately. The official
  ARM64 Wintun DLL hash and embedded signature were inspected there without
  loading it. A Fedora VM is also available for the later Linux adapter.

## Update Rule

Keep this file short and current. A PR that closes a listed gap, changes the
next verified action, or adds a new release/safety gate must update this
checkpoint. If live evidence contradicts it, stop, investigate the difference,
and correct the file rather than improvising a narrative.

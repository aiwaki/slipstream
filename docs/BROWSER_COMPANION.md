# Browser Companion

> **P0 macOS update (2026-08-13):** the headed/LaunchServices production worker
> described in the historical sections below is superseded. Production now
> launches only the app-bundled, version- and SHA-pinned Chrome for Testing
> headless shell directly from
> `Contents/Resources/chromium-headless-shell/chrome-headless-shell`. It creates
> no Aqua LaunchAgent, installed-Chrome process, Dock/window/focus event, user
> browser profile, extension, or Web Store dependency. Existing extension and
> LaunchServices material below remains qualification history, not the current
> production architecture. The old transport-idle broker is permanently
> disabled. The replacement exact-host pre-routing path is implemented in the
> `.23` candidate source, requires signed foreground-browser provenance, and is
> not release-ready until packaged visibility, live-site, transport, and
> idle-soak gates pass. Bundling the runtime is not itself a claim about the
> currently installed `.22`.

Slipstream's transport layer can see connection failure, but it cannot infer
that a successfully rendered page says the service is unavailable in the
current region. The browser companion supplies that missing semantic evidence
without decrypting HTTPS or adding per-site rules.

The daemon has browser-independent fallbacks for incomplete responses and
service-root regional denial. If an eligible unknown host establishes an exact
public `system/plain` route, a background certificate-validating `GET /` may
inspect at most `128 KiB` from that same IP. It sends no browser cookies, path,
query, storage, or external-resource requests. A complete response whose
decoded identity-representation body contains a strong generic regional-denial
marker may only request a second independent
confirmation through verified owned Geph; the current client stream is never
replayed or changed. The transport path also has separate bounded framing
evidence for incomplete bodies.

These fallbacks can prepare a proven route for a later request, but they cannot
read the actual tab's path, cookies, or encrypted DOM. P0 exact-host preflight
may classify only its separate bounded service-root navigation. Arbitrary
account- or path-specific denial therefore remains outside the claimed
extensionless coverage; Slipstream does not compensate with TLS MITM.

## Chromium Preview

The preview under `browser-companion/chromium/` is a Manifest V3 extension with
three permissions: `nativeMessaging`, `storage`, and read-only `webRequest`.
Its HTTPS host access is used only to observe top-level document requests and
their final errors; the extension does not block, redirect, or modify requests.
`storage.session` retains only an opaque request ID, tab ID, normalized
hostname, and expiry. It never retains a path or query, and the record is
removed on the request's final completion or error.

1. A top-frame content script observes the first ten seconds of an HTTPS page.
   It checks the title, visible dialogs, and a bounded sparse-page snapshot
   locally for strong regional-denial language. The frozen contract includes
   the observed `This content is no longer available in your area` page without
   naming `weather.com` in routing policy.
2. The content script sends only a fixed category and confidence. It cannot
   provide a hostname, URL, or page text.
3. The service worker derives the normalized hostname from Chrome's
   browser-owned sender metadata and creates the frozen semantic-signal v1
   object.
4. Chrome starts Slipstream's native messaging mode only through the exact
   `dev.slipstream.semantic` host manifest and stable extension origin.
5. The native host validates the signal again, forwards the exact bounded bytes
   to the owner-only daemon socket, and accepts only the fixed private response
   shape.
6. Static routing policy still wins. An eligible unknown hostname is learned
   only if a separate exact-host HTTPS request through the currently
   ownership-verified bundled Geph returns a usable response without the same
   regional-denial semantics.
7. When that confirmation is scheduled, the content script performs one
   bounded reload after seven seconds, and only if the tab is still on the same
   hostname. Rejection, cooldown, navigation, or an unavailable daemon produces
   no reload loop.

The additive semantic-signal v2 path handles a different failure class without
changing v1. Chrome's browser-owned `webRequest.onBeforeRequest` event records
an HTTPS `main_frame` GET with frame ID `0` and no parent, keyed by the opaque
request ID. The matching `onErrorOccurred` event is accepted only for exact
`net::ERR_CONTENT_LENGTH_MISMATCH` or
`net::ERR_INCOMPLETE_CHUNKED_ENCODING` failures on the same tab and normalized
HTTPS hostname. This correlation is required because Chrome's documented final
error event does not carry `method` or `parentFrameId`; requiring those fields
on that event silently rejected real errors even though synthetic tests
supplied them.
`webRequest` is used because Chromium guarantees a final `onCompleted` or
`onErrorOccurred` event for each observed request, while `webNavigation`
reports only an aborted navigation and did not report the protected fixture's
post-commit body truncation. Chromium documents error strings as
version-sensitive, so the two-value allowlist is frozen and the protected
current-Chrome gate is required to detect upstream drift.
Ordinary CI also launches stable Chrome for Testing with a fresh private
profile, a deterministic truncated HTTPS response, and an owner-only fixed
native stub. That gate proves the real `webRequest` event, exact v2 signal, one
reload, mandatory CSS/JavaScript/image resources, and browser-ready callback
without Geph, PF, the daemon, or system network mutation. The protected
account-backed gate remains authoritative for the complete product path. The
fresh-profile harness first opens an owner-only extension page. The disposable
worker acknowledges through the owner-only native stub after its listeners are
registered. A bounded retry covers the short interval before a newly installed
worker can receive its first message, and only then does the page navigate to
the fixture. This prevents
Chrome's command-line startup race from being mistaken for a missing
`webRequest` event; the readiness acknowledgement and trace exist only in the
CI copy, while the product observer itself is unchanged.
The extension converts either error locally into the fixed
`incomplete_response` category; the raw error and URL never cross native
messaging. Static direct, direct-first, local-bypass, and reviewed geo-exit
policy still wins. For an eligible unknown host, the daemon performs a distinct
bounded request through the ownership-verified bundled Geph and requires a
syntactically complete HTTP response: an exact `Content-Length`, a terminal
chunked body, or a complete connection-close body. A partial, oversized,
timed-out, compressed-denial, or non-success response fails closed. Only a
successful confirmation permits one 250 ms same-host top-level reload; the
request that already failed is never replayed by the transparent proxy.

The extension does not transmit path, query, page text, cookies, storage,
forms, account data, browser error strings, full URLs, or arbitrary script
output. It does not change DNS, proxy, PAC, VPN, PF, or browser settings.

## Safari Preview

The Safari preview under `browser-companion/safari/` reuses the same bounded
detector and dual-reader service-worker contract. Safari supplies messages only
to the native app extension embedded in its containing app, so there is no
Chrome-style external native-host origin to register. The service worker
derives the hostname from Safari-owned top-level sender or read-only
`webRequest` metadata. The native extension accepts either exact frozen
eight-field signal, forwards one little-endian bounded frame to the owner-only
daemon socket, and returns only the fixed four-field private response. Apple
currently ignores the application identifier argument to `sendNativeMessage`
and dispatches to that embedded native extension; Slipstream nevertheless
keeps the argument equal to the generated containing-app bundle identifier and
enforces the equality in tests.

The source is packaged with Apple's `safari-web-extension-packager`, falling
back to its Xcode 15 name `safari-web-extension-converter`. The repository build
creates a fresh Xcode project, inserts the reviewed Swift bridge, and compiles
an unsigned macOS 13 app plus `.appex`. Xcode registers normal app build
products with LaunchServices even when signing is disabled, so the script
unregisters only its exact generated containing app, including its embedded
`.appex`, on every exit:

```bash
bash scripts/build_safari_companion.sh /tmp/slipstream-safari-companion
```

This build does not install, launch, enable, or sign the extension, and it does
not retain LaunchServices registration. It is a compile and packaging
qualification only. Apple requires a containing app and app extension for
native messaging; secure distribution requires a signed container. Sandbox
access from a real Safari extension to the owner-only daemon socket must be
proven on a disposable signed build before the companion can ship.

## Native Host Lifecycle

The tray registers the native host only when its executable is inside a real
`Slipstream.app/Contents/MacOS/` bundle. Development binaries are ignored. The
user-specific Google Chrome manifest is written atomically with mode `0600` and
contains one exact `allowed_origins` entry. Confirmed uninstall removes only a
manifest whose name, type, and origin identify it as Slipstream-owned; a
foreign file or symlink is refused without blocking removal of the application.

The extension is not published to the Chrome Web Store. For development, load
`browser-companion/chromium/` with Chrome's **Load unpacked** action after
starting a packaged Slipstream app. The public key in `manifest.json` keeps the
preview extension ID stable. This manual development step is not an acceptable
installed-product workflow. Production must provide an owned automatic local
integration that arrives with Slipstream and needs no separate browser setup.
A local browser worker is equivalent only if it preserves the same bounded
signal authority and automatically completes the original user-visible
navigation; successfully loading a separate synthetic page is not sufficient.
The disposable CI gate proves browser behavior but not that delivery boundary.

The ordinary macOS Chromium CI gate has a unified-headless mode for the
first worker qualification slice. It runs the reviewed extension without an
visible browser window or `--no-sandbox`; on macOS LaunchServices supplies the
application bootstrap context required for sandboxed helpers to reach Chrome's
Mach rendezvous service. Direct binary LaunchAgent attempts failed even with an
Aqua session declaration. The gate requires the exact native-message boundary
and styled resource callback, and reports
launch-to-worker, launch-to-semantic, de-duplicated physical footprint, and
aggregate owned-process RSS measurements. Its conservative regression budgets
are 15 seconds, 25 seconds, and 768 MiB of physical footprint respectively.
Aggregate RSS is diagnostic only because it counts shared mappings once per
Chrome process. This is qualification infrastructure, not yet an installed
runtime component and not authority over an unrelated user tab.

Ordinary CI run `31533358388`, job `93918488548`, passed on Chrome for Testing
151: worker readiness was 5,476 ms, semantic-ready was 6,495 ms, physical
footprint was 374,369 KiB, and aggregate RSS was 1,234,672 KiB across four
samples. The real incomplete-frame event crossed native messaging, triggered
one reload, and reached the CSS, JavaScript, and image callback. The result
qualifies the worker mechanism and measurement boundary only; it does not yet
prove installed delivery or correlation to another browser's original relay.

## Chrome Web Store Package

Build the deterministic source-only upload archive and provenance record with:

```bash
python3 scripts/package_chromium_companion.py \
  --output /tmp/slipstream-chromium-store
```

The builder accepts only the frozen runtime files, `manifest.json`, and the
reviewed 128-pixel icon. It validates Manifest V3 identity, permissions, host
access, service worker and content-script declarations, the public-key-derived
extension ID, and the native host's exact name and allowed origin. Symlinks,
unexpected files, oversized inputs, dynamic code generation, remote
`importScripts`, and runtime `fetch` are rejected. Archive entries are sorted,
uncompressed, and timestamped consistently; the adjacent provenance JSON pins
the archive and every packaged file by SHA-256.

[`PRIVACY.md`](../browser-companion/chromium/PRIVACY.md) records the reviewed
local-only data flow, retention, and user controls. [`STORE_LISTING.md`](../browser-companion/chromium/STORE_LISTING.md)
contains the store description, prominent disclosure, permission
justifications, and reviewer notes. These are source-of-truth inputs, not proof
of publication. Publisher upload, store review, public listing/privacy URLs,
and a clean branded-Chrome install/enabled proof remain manual external gates.
The first dashboard upload must stop before review and prove that its Item ID
and public key match the committed manifest identity. Any mismatch requires a
reviewed native-host/origin update and complete requalification; it must never
be papered over by accepting a second origin.

## Protected Chromium Qualification

The manual, main-only `owned-geph-qualification` workflow composes the
Chromium preview with the existing protected account-backed Geph gate. It
starts the packaged tray and its exact user LaunchAgent, then runs a separate
root-only harness against the packaged daemon.

The browser side uses GUI Chrome for Testing in the disposable runner's user
session, fresh owner-only profiles, the unpacked frozen-origin extension, the
packaged Rust native host, and the daemon's owner-only semantic socket. Branded
Chrome 137 and later ignore the unpacked-extension `--load-extension` switch, so
it cannot drive this automation gate. The harness copies the exact installed
native-host manifest into the fresh profile's `NativeMessagingHosts` directory;
it does not synthesize or relax the manifest. The harness writes one
owner-private temporary plist and bootstraps it under the exact
`gui/<console-uid>` domain. User launchd runs `/usr/bin/open -n -W`, which asks
LaunchServices to create sandboxed Chrome in the console user's actual Aqua
application session and keeps the exact launcher job alive until that
application exits. When Chrome for Testing is distributed as a valid
`Contents/` tree under an extensionless architecture directory, the harness
copies the complete validated bundle into one real `.app` inside the fresh
owner-private profile. LaunchServices, process admission, diagnostics, and
cleanup then resolve only against the copied executable and copied helper
family. Neither a whole-bundle symlink nor a real `.app` whose `Contents` links
back to the extensionless source is sufficient. The first form is canonicalized
back to the extensionless path; protected run `30316469657` showed that the
second form starts the main process but leaves its sandboxed helpers unable to
join the main process's Mach rendezvous service, so Chrome's network service
terminates before semantic completion. The private copy disappears with the
profile only after exact process absence is proven. Protected runs
`30295751995` and `30298855867` isolated the earlier LaunchServices requirements
while independently passing the complete owned-Geph lifecycle and final system
cleanup. Protected runs
`30279476090` and `30282319977` proved that
direct browser execution from an Aqua LaunchAgent, with or without
`SessionCreate`, gives sandboxed network-service children Mach lookup error
`1100`. Run `30284938688` proved that `--no-sandbox` merely changed this to
`1102`; the direct-launch bootstrap namespace was still wrong. The sandbox
opt-out is therefore removed. The harness cannot execute outside its
root/macOS/GitHub/disposable guard.
The bootstrap command itself is inside the exact-target cleanup boundary, so a
job accepted before a command error is still killed, booted out, and verified.
Root execution followed by `launchctl asuser` and a manual UID/GID drop was
explicitly rejected after protected runs still produced Mach lookup error
`1100`. No shell or `sudo` is involved in the browser launch. A browser process
is owned only when its UID, Chrome bundle executable family, and exact unique
owner-only profile argument match. Its proven process group is then retained
so same-UID helpers from the same bundle remain owned even when they omit the
browser-only profile switch. Cleanup revalidates the complete observed process
identity immediately before each signal, boots out only the unique temporary
launcher label, retries that exact target after a transient failure, and
verifies browser, launcher, and process-group absence. Launcher and browser
stderr are captured before profile removal. When bootstrap submitted a
LaunchServices request before launcher
identity could be verified, browser absence must remain stable for a bounded
quiet window before the fresh profile can be removed. The same post-bootout
window is required when the launcher was verified but browser admission timed
out. If either proof fails, the profile is retained rather than inferring
descendant cleanup. A scoped local
HTTPS fixture mapped only inside each browser profile serves two independent
generic scenarios. The frozen v1 scenario serves a strong regional-denial page
first and a styled page on the next request. The additive v2 scenario aborts
the first top-level response after declaring a longer `Content-Length`, then
serves a complete styled page on the next request. The daemon does not trust
either fixture: each generic hostname must independently complete the matching
real HTTPS confirmation through the ownership-verified account-backed Geph.
Success requires the learned exact-host route, exactly one browser reload, a
marked nonblank DOM, fetched CSS, JavaScript, and image resources, and one
same-origin `/ready` callback emitted by page JavaScript only after those
resources are usable. Headless execution is also excluded because an
earlier protected run rendered the page without activating the MV3
native-messaging path. The daemon never accepts fixture output as route proof.

Protected run `30301572440` stopped before this browser phase because its sole
Steam HTTPS canary timed out. The user-level gate now rotates through a bounded
set of independent real HTTPS payload canaries; SOCKS CONNECT or TLS alone
still cannot pass. If tray startup fails before the browser harness assumes
ownership, cleanup removes the Chromium native-host manifest only after
verifying its owner, mode, packaged executable path, host name, transport, and
frozen extension origin. A foreign manifest is never removed.

Protected run `30393151116` on main `49a79d0332e96c067acdaeaf9983433f8fcaff7d`
proved the owned-Geph Steam payload initially, without the tray, and after
KeepAlive recovery, but the incomplete-response browser scenario timed out.
The runner then completed exact user/system cleanup and published no artifact.
The failure showed that `webNavigation.onErrorOccurred` is not a sufficient
runtime signal for a top-level response body truncated after navigation commit;
the Chromium preview now uses the narrower read-only `webRequest` observer
described above. The harness reports the scenario and bounded fixture counters
on future timeouts.

Protected run `30411915972` on exact main
`bebb6776b554a01a7885b889d6d98c2a405d570c` passed packaged-resource and
daemon-free boundaries, then proved the owned-Geph Steam payload initially,
without the tray, and after KeepAlive recovery (`68103` bytes and HTTP 200 in
all three phases). The frozen regional-denial browser scenario completed before
the harness entered the additive incomplete-response scenario. That second
scenario recorded one root request and no reload or subresources. Current
Chrome's final error event omitted the two fields that the v2 builder required,
so the signal was discarded before native messaging. The always-run cleanup
passed, system network state was not mutated, no artifact was published, and no
workstation install was attempted. The request-ID correlation above is the
evidence-scoped correction; another protected run is required on its exact
merged main SHA.

The fixture uses an untrusted one-day certificate accepted only by the
disposable Chrome process. It does not install a certificate, alter system DNS,
or add a production daemon override. Cleanup must remove the root daemon,
private PF anchor, enable token, semantic socket, temporary learned-route file,
fresh browser profile, native host manifest, owned Geph LaunchAgent, Keychain
item, and user runtime. This protected workflow is completion evidence only
after it passes on the exact merged main commit.

## Verification

```bash
node --check browser-companion/chromium/content.js
node --check browser-companion/chromium/service-worker.js
node --check browser-companion/safari/service-worker.js
node --test browser-companion/chromium/tests/*.test.mjs
swift test --package-path browser-companion/safari
bash scripts/build_safari_companion.sh /tmp/slipstream-safari-companion
cargo test --manifest-path app-tauri/src-tauri/Cargo.toml native_messaging
python3 -m unittest scripts.test_browser_companion
python3 scripts/chromium_semantic_packaged_smoke.py --dry-run
```

The tests cover the observed denial phrase, multiple languages, ordinary
non-geographic errors, rich-page false-positive bounds, the two exact
incomplete-navigation error classes, complete versus truncated HTTP framing,
same-host reload ownership, exact sender ownership, forbidden extra fields,
stable Chromium identity, native framing, Chromium origin authentication, both
manifests' permissions, private responses, atomic registration, owned
uninstall, and an unsigned Safari app-extension build.

## Remaining Gates

- The extensionless production path, owner-only job/result socket, exact-host
  cache/coalescing, one-tree headless launcher, bounded cleanup, and pinned
  runtime are implemented. They become release evidence only when the exact
  merged-main candidate passes packaged lifecycle and visibility checks.
- The same immutable candidate must then pass protected account-backed
  owned-Geph qualification and protected release readiness: clean-profile
  Safari and Chrome live-origin scenarios for all four failure classes,
  dual-stack PF/NATLOOK and QUIC v1/v2 mechanics, and a measured 30-minute idle
  soak with zero window, Dock, focus, GUI Chrome, LaunchAgent, or retained
  profile event. Inconclusive origins cannot become false passes.
- Chrome Web Store packaging, the unpacked Chromium extension, and the unsigned
  Safari extension remain historical/research qualification surfaces. They are
  not installed-product dependencies or `.23` release gates. Shipping either
  extension later would require its own signed, sandboxed, clean-install and
  exact-uninstall qualification.
- Semantic matching remains deliberately conservative. New languages or phrase
  families require generic positive and negative fixtures, never hostname
  rules.

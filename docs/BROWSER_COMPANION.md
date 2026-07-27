# Browser Companion

Slipstream's transport layer can see connection failure, but it cannot infer
that a successfully rendered page says the service is unavailable in the
current region. The browser companion supplies that missing semantic evidence
without decrypting HTTPS or adding per-site rules.

## Chromium Preview

The preview under `browser-companion/chromium/` is a Manifest V3 extension with
one permission: `nativeMessaging`.

1. A top-frame content script observes the first ten seconds of an HTTPS page.
   It checks the title, visible dialogs, and a bounded sparse-page snapshot
   locally for strong regional-denial language.
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

The extension does not transmit path, query, page text, cookies, storage,
forms, account data, or arbitrary script output. It does not change DNS,
proxy, PAC, VPN, PF, or browser settings.

## Safari Preview

The Safari preview under `browser-companion/safari/` reuses the same bounded
detector and service-worker contract. Safari supplies messages only to the
native app extension embedded in its containing app, so there is no
Chrome-style external native-host origin to register. The service worker still
derives the hostname from Safari-owned top-level sender metadata; the native
extension accepts exactly the frozen eight-field signal, forwards one
little-endian bounded frame to the owner-only daemon socket, and returns only
the fixed four-field private response. Apple currently ignores the application
identifier argument to `sendNativeMessage` and dispatches to that embedded
native extension; Slipstream nevertheless keeps the argument equal to the
generated containing-app bundle identifier and enforces the equality in tests.

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

The extension is not yet published to the Chrome Web Store. For development,
load `browser-companion/chromium/` with Chrome's **Load unpacked** action after
starting a packaged Slipstream app. The public key in `manifest.json` keeps the
preview extension ID stable. Production distribution in branded Chrome requires
a reviewed Chrome Web Store package; the disposable CI gate does not replace
that distribution path.

## Protected Chromium Qualification

The manual, main-only `owned-geph-qualification` workflow composes the
Chromium preview with the existing protected account-backed Geph gate. It
starts the packaged tray and its exact user LaunchAgent, then runs a separate
root-only harness against the packaged daemon.

The browser side uses GUI Chrome for Testing in the disposable runner's user
session, a fresh owner-only profile, the unpacked frozen-origin extension, the
packaged Rust native host, and the daemon's owner-only semantic socket. Branded
Chrome 137 and later ignore the unpacked-extension `--load-extension` switch, so
it cannot drive this automation gate. The harness copies the exact installed
native-host manifest into the fresh profile's `NativeMessagingHosts` directory;
it does not synthesize or relax the manifest. The harness writes one
owner-private temporary plist and bootstraps it under the exact
`gui/<console-uid>` domain. User launchd starts Chrome with `Aqua` and
`Interactive` session constraints and `SessionCreate=true`, which asks launchd
to create the security audit session required by Chrome's sandboxed
network-service children. Protected runs `30279476090` and `30282319977`
proved that neither the exact user LaunchAgent alone nor the same job with
`SessionCreate` lets sandboxed Chrome children resolve their Mach rendezvous
service on the GitHub-hosted runner. The protected workflow therefore passes an
explicit disposable-CI-only `--no-sandbox` switch. The harness defaults to a
sandboxed browser everywhere else and cannot execute at all outside its
root/macOS/GitHub/disposable guard. A successful hosted run qualifies the
companion, route, and complete-page composition, not the production Chrome
sandbox; that requires a real Aqua or self-hosted runner.
The bootstrap command itself is inside the exact-target cleanup boundary, so a
job accepted before a command error is still killed, booted out, and verified.
Root execution followed by `launchctl asuser` and a manual UID/GID drop was
explicitly rejected after protected runs still produced Mach lookup error
`1100`. No shell or `sudo` is involved. Cleanup sends signals and `bootout`
only to the unique temporary job label, retries the same target after a
transient failure, then verifies both launchd absence and that no console-user
member remains in its recorded process group. The fresh profile and its plist
are removed only after both proofs succeed. If bootstrap never yields a
verified process group, the profile is retained even after launchd absence;
the harness does not infer descendant cleanup. A scoped local HTTPS fixture
mapped only inside that browser profile serves a strong
regional-denial page first and a styled page on the next request. Headless
execution is also excluded because an
earlier protected run rendered the page without activating the MV3
native-messaging path. The daemon does not trust the fixture: confirmation is a
separate real HTTPS request for the same generic hostname through the
ownership-verified account-backed Geph. Success requires the learned exact-host
route, exactly one browser reload, a marked nonblank DOM, fetched CSS,
JavaScript, and image resources, and one same-origin `/ready` callback emitted
by page JavaScript only after those resources are usable.

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
non-geographic errors, rich-page false-positive bounds, exact sender ownership,
forbidden extra fields, stable Chromium identity, native framing, Chromium
origin authentication, both manifests' permissions, private responses, atomic
registration, owned uninstall, and an unsigned Safari app-extension build.

## Remaining Gates

- Chrome Web Store packaging, privacy disclosure, and update provenance.
- The Chrome for Testing packaged Chromium harness must pass on an exact merged
  main commit before the preview is considered runtime-qualified. Branded
  Chrome still requires reviewed Chrome Web Store distribution.
- Safari requires a signed container, browser enablement, and a disposable
  runtime proof that the sandboxed app extension can reach the owner-only
  daemon socket. The unsigned source and package build exist, but are not
  bundled into Slipstream or installed on user machines.
- Semantic matching remains deliberately conservative. New languages or phrase
  families require generic positive and negative fixtures, never hostname
  rules.

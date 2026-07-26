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
preview extension ID stable.

## Verification

```bash
node --check browser-companion/chromium/content.js
node --check browser-companion/chromium/service-worker.js
node --test browser-companion/chromium/tests/*.test.mjs
cargo test --manifest-path app-tauri/src-tauri/Cargo.toml native_messaging
python3 -m unittest scripts.test_browser_companion
```

The tests cover the observed weather.com denial phrase, multiple languages,
ordinary non-geographic errors, rich-page false-positive bounds, exact sender
ownership, forbidden extra fields, stable extension identity, native framing,
origin authentication, manifest permissions, private responses, atomic
registration, and owned uninstall.

## Remaining Gates

- Chrome Web Store packaging, privacy disclosure, and update provenance.
- A disposable packaged-app test with real Chrome, the registered host, daemon
  socket, owned Geph confirmation, one reload, and successful styled DOM.
- Safari requires a separately signed Safari Web Extension container and
  browser-specific lifecycle qualification. The detector and frozen signal
  contract are reusable, but the Chromium artifact does not run in Safari.
- Semantic matching remains deliberately conservative. New languages or phrase
  families require generic positive and negative fixtures, never hostname
  rules.

# Chrome Web Store Listing Draft

This file is the reviewed source for the Chrome Web Store dashboard. It is not
included in the executable extension ZIP.

## Name

Slipstream Browser Companion

## Short Description

Helps local Slipstream recover stalled, incomplete, or region-denied HTTPS
navigations.

## Single-Purpose Description

Slipstream Browser Companion connects Chrome to the Slipstream application
installed on this Mac. When one top-level HTTPS navigation stalls before its
first document, ends with one of Chrome's narrowly accepted incomplete-response
errors, or displays a fixed regional-access-denial pattern, the extension sends
a bounded signal to the local app. Slipstream independently confirms that the
exact site works through the user's owned recovery path before the extension
may reload that tab once.

The extension does not change search, inject ads, modify page content, read
form values, or send analytics. Discord and YouTube remain excluded from
Slipstream's geo-exit recovery.

## Prominent Data Disclosure

With your consent, this extension locally examines the status of top-level
HTTPS navigations and a bounded portion of visible page text to detect the
three recovery conditions described above. It sends only the normalized site
hostname, a fixed detection category, confidence/timing fields, and a generated
signal ID to the Slipstream application on this computer.

It does not send visible page text, full URLs, paths, queries, cookies,
credentials, form values, request/response bodies, screenshots, or browsing
history to Slipstream's developer or any third party. Install the extension
only if you consent to this on-device processing and local native-messaging
transfer.

## Permission Justifications

- `nativeMessaging`: required to send the bounded recovery signal to the
  locally installed Slipstream app.
- `storage`: required only for short-lived `storage.session` correlation
  across a Manifest V3 service-worker restart.
- `webRequest`: required to observe terminal lifecycle events for one
  top-level HTTPS request. No blocking or header access is used.
- `https://*/*`: the affected site is not known in advance. Static policy and
  local runtime gates decide whether a signal is eligible; the extension does
  not read HTTP bodies or modify requests.

## Developer Dashboard Privacy Answers

- Website content: handled locally for the fixed regional-denial detector.
- Web browsing activity: the normalized hostname and top-level navigation
  lifecycle are handled locally for the single recovery purpose.
- Personally identifiable information: not collected.
- Authentication, financial, health, personal communications, location, and
  form data: not collected.
- Sale, advertising, creditworthiness, or unrelated use: none.
- Transfer to third parties: none.
- Remote code: none; all executable JavaScript is inside the submitted ZIP.

The public privacy-policy URL must render
[`PRIVACY.md`](PRIVACY.md) without requiring authentication.

## Reviewer Notes

The native application must already be installed. The extension ID derived
from the committed manifest key is
`cecdingohhpfggapnlbghppcegbaciam`, matching the native host's sole allowed
origin. The native response can request only a bounded same-tab reload or no
action.

Build the upload ZIP and its deterministic provenance record with:

```bash
python3 scripts/package_chromium_companion.py --output /tmp/slipstream-chromium-store
```

Before submission, the publisher must still supply the dashboard's store icon,
screenshots, category, support URL, public privacy URL, distribution scope, and
the prominent disclosure above, then complete Google's manual review. The
repository does not automate publisher-account access or submission.

For the first dashboard upload, stop before review and compare both the
dashboard Item ID and its **View public key** value with the committed manifest
key and derived extension ID above. A mismatch means the native host would not
accept the store-installed extension. Do not publish or weaken the allowed
origin. Bind the repository to the dashboard-issued identity in a reviewed
change, rebuild the app and extension together, and repeat every exact-main and
protected qualification gate first.

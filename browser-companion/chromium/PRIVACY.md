# Slipstream Browser Companion Privacy Notice

Effective: 2026-08-11

## Single Purpose

Slipstream Browser Companion helps the locally installed Slipstream application
recover an HTTPS top-level navigation that is incomplete, remains pending
before its first document, or displays one of Slipstream's fixed
regional-access-denial patterns.

## Data Handled On This Device

To provide that feature, the extension handles:

- the browser-owned hostname and status of a top-level HTTPS navigation;
- an ephemeral request ID, tab ID, loading state, and timing information used
  to correlate one browser event;
- a bounded portion of visible page text, processed locally only to test the
  fixed regional-denial detector; and
- a generated signal ID, fixed detection category, confidence value, and
  observation time.

The extension sends only the normalized hostname, fixed category, bounded
timing/confidence fields, top-level flag, and generated signal ID to the
Slipstream native application on the same computer. It does not send page
text, full URLs, paths, queries, request or response bodies, cookies,
credentials, form values, personal communications, or page screenshots to the
native application.

## Collection, Sharing, And Remote Services

The extension does not send data to Slipstream's developer, analytics
providers, advertisers, or any other third party. It contains no advertising,
tracking, telemetry, account login, or remote-hosted executable code. Its only
application channel is Chrome native messaging to the locally installed
Slipstream application.

After an eligible signal, the local Slipstream application may independently
test the exact hostname through its existing direct, local-bypass, or
user-configured owned-Geph paths. Those application probes are governed by
Slipstream's routing policy; the extension does not make remote requests
itself.

## Retention

Browser-side correlation state is kept only in extension memory or
`storage.session`, is bounded by short expiry windows, and is removed on
completion, redirect, expiry, or browser-session end. Visible page text is not
stored. The local Slipstream application may retain a temporary exact-host
routing result for its bounded route TTL; it does not receive the page text or
full URL.

## Permissions

- `nativeMessaging`: send one bounded signal to the local Slipstream
  application and receive only a fixed reload/no-action response.
- `storage`: preserve short-lived correlation state across a Manifest V3
  service-worker restart.
- `webRequest` and `https://*/*`: observe top-level HTTPS navigation
  lifecycle events needed for the single recovery purpose. The extension does
  not block, redirect, rewrite, or read HTTP headers or bodies.

## Choice And Control

Installing or enabling the extension activates this local processing.
Disabling or uninstalling the extension stops it. Removing Slipstream removes
the owned native-host registration; a foreign or modified registration is
left untouched rather than deleted.

Security issues should be reported through the private process in
[`SECURITY.md`](../../SECURITY.md).

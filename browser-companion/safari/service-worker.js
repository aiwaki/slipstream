"use strict";

importScripts("service-worker-core.js");

const runtime = globalThis.browser?.runtime ?? globalThis.chrome?.runtime;
const tabs = globalThis.browser?.tabs ?? globalThis.chrome?.tabs;
const webNavigation =
  globalThis.browser?.webNavigation ?? globalThis.chrome?.webNavigation;
const core = globalThis.SlipstreamServiceWorkerCore;
const CONTAINING_APP_ID = "dev.slipstream.Slipstream-Safari-Companion";

function sendToNative(signal) {
  return Promise.resolve(runtime.sendNativeMessage(CONTAINING_APP_ID, signal));
}

runtime.onMessage.addListener((message, sender, sendResponse) => {
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);
  const signal = core.buildSemanticSignal(
    message,
    sender,
    Date.now(),
    randomBytes
  );
  if (!signal) {
    return;
  }
  sendToNative(signal)
    .then((response) => sendResponse(core.reloadInstruction(response, signal)))
    .catch(() => sendResponse(null));
  return true;
});

if (webNavigation?.onErrorOccurred && tabs?.get && tabs?.reload) {
  webNavigation.onErrorOccurred.addListener(
    (details) => {
      const randomBytes = new Uint8Array(16);
      crypto.getRandomValues(randomBytes);
      const signal = core.buildIncompleteResponseSignal(
        details,
        Date.now(),
        randomBytes
      );
      if (!signal) {
        return;
      }
      sendToNative(signal)
        .then((response) => core.reloadInstruction(response, signal))
        .then((instruction) => {
          if (!instruction) {
            return;
          }
          setTimeout(() => {
            Promise.resolve(tabs.get(details.tabId))
              .then((tab) => {
                if (core.tabStillOnSignalHost(tab, signal)) {
                  return tabs.reload(details.tabId);
                }
                return undefined;
              })
              .catch(() => {});
          }, instruction.delay_ms);
        })
        .catch(() => {});
    },
    { url: [{ schemes: ["https"] }] }
  );
}

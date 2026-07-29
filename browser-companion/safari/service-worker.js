"use strict";

importScripts("service-worker-core.js");

const runtime = globalThis.browser?.runtime ?? globalThis.chrome?.runtime;
const tabs = globalThis.browser?.tabs ?? globalThis.chrome?.tabs;
const webRequest =
  globalThis.browser?.webRequest ?? globalThis.chrome?.webRequest;
const storageSession =
  globalThis.browser?.storage?.session ?? globalThis.chrome?.storage?.session;
const core = globalThis.SlipstreamServiceWorkerCore;
const CONTAINING_APP_ID = "dev.slipstream.Slipstream-Safari-Companion";
const incompleteResponseTracker =
  core.createIncompleteResponseTracker(storageSession);

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

if (
  webRequest?.onBeforeRequest &&
  webRequest?.onCompleted &&
  webRequest?.onErrorOccurred &&
  tabs?.get &&
  tabs?.reload
) {
  webRequest.onBeforeRequest.addListener(
    (details) => {
      incompleteResponseTracker.remember(details, Date.now()).catch(() => {});
    },
    {
      urls: ["https://*/*"],
      types: ["main_frame"]
    }
  );
  webRequest.onCompleted.addListener(
    (details) => {
      incompleteResponseTracker.discard(details).catch(() => {});
    },
    {
      urls: ["https://*/*"],
      types: ["main_frame"]
    }
  );
  webRequest.onErrorOccurred.addListener(
    (details) => {
      incompleteResponseTracker
        .take(details)
        .then((candidate) => {
          const randomBytes = new Uint8Array(16);
          crypto.getRandomValues(randomBytes);
          return core.buildIncompleteResponseSignal(
            details,
            candidate,
            Date.now(),
            randomBytes
          );
        })
        .then((signal) => {
          if (!signal) {
            return null;
          }
          return sendToNative(signal).then((response) => ({
            instruction: core.reloadInstruction(response, signal),
            signal
          }));
        })
        .then((result) => {
          if (!result?.instruction) {
            return;
          }
          const { instruction, signal } = result;
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
    {
      urls: ["https://*/*"],
      types: ["main_frame"]
    }
  );
}

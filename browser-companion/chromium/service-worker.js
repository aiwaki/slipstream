"use strict";

importScripts("service-worker-core.js");

const NATIVE_HOST = "dev.slipstream.semantic";
const core = globalThis.SlipstreamServiceWorkerCore;

function sendToNative(signal) {
  return chrome.runtime.sendNativeMessage(NATIVE_HOST, signal);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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

chrome.webRequest.onErrorOccurred.addListener(
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
          chrome.tabs
            .get(details.tabId)
            .then((tab) => {
              if (core.tabStillOnSignalHost(tab, signal)) {
                return chrome.tabs.reload(details.tabId);
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

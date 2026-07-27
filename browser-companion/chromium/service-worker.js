"use strict";

importScripts("service-worker-core.js");

const NATIVE_HOST = "dev.slipstream.semantic";
const core = globalThis.SlipstreamServiceWorkerCore;

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
  chrome.runtime
    .sendNativeMessage(NATIVE_HOST, signal)
    .then((response) => sendResponse(core.reloadInstruction(response)))
    .catch(() => sendResponse(null));
  return true;
});

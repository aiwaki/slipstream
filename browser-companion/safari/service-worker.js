"use strict";

importScripts("service-worker-core.js");

const runtime = globalThis.browser?.runtime ?? globalThis.chrome?.runtime;
const core = globalThis.SlipstreamServiceWorkerCore;
const CONTAINING_APP_ID = "dev.slipstream.Slipstream-Safari-Companion";

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
  Promise.resolve(runtime.sendNativeMessage(CONTAINING_APP_ID, signal))
    .then((response) => sendResponse(core.reloadInstruction(response)))
    .catch(() => sendResponse(null));
  return true;
});

"use strict";

importScripts("service-worker-core.js");

const NATIVE_HOST = "dev.slipstream.semantic";
const core = globalThis.SlipstreamServiceWorkerCore;
const incompleteResponseTracker = core.createIncompleteResponseTracker(
  chrome.storage.session
);

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

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    incompleteResponseTracker.remember(details, Date.now()).catch(() => {});
  },
  {
    urls: ["https://*/*"],
    types: ["main_frame"]
  }
);

chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    incompleteResponseTracker.discard(details).catch(() => {});
  },
  {
    urls: ["https://*/*"],
    types: ["main_frame"]
  }
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    incompleteResponseTracker.discard(details).catch(() => {});
  },
  {
    urls: ["https://*/*"],
    types: ["main_frame"]
  }
);

chrome.webRequest.onErrorOccurred.addListener(
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

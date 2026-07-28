import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const coreSource = await readFile(
  new URL("../service-worker-core.js", import.meta.url),
  "utf8"
);
const workerSource = await readFile(
  new URL("../service-worker.js", import.meta.url),
  "utf8"
);

function createWorker({
  nativeResponse = {
    schema_version: 1,
    accepted: true,
    action: "confirm_exact_host_geo_exit"
  },
  currentTabUrl = "https://partial.example/page"
} = {}) {
  const calls = {
    native: [],
    reload: [],
    timeout: [],
    webRequestListener: null
  };
  const chrome = {
    runtime: {
      onMessage: {
        addListener() {}
      },
      sendNativeMessage(host, signal) {
        calls.native.push({ host, signal });
        return Promise.resolve(nativeResponse);
      }
    },
    tabs: {
      get() {
        return Promise.resolve({ url: currentTabUrl });
      },
      reload(tabId) {
        calls.reload.push(tabId);
        return Promise.resolve();
      }
    },
    webRequest: {
      onErrorOccurred: {
        addListener(listener, filter) {
          calls.webRequestListener = listener;
          calls.webRequestFilter = filter;
        }
      }
    }
  };
  const context = vm.createContext({
    URL,
    Uint8Array,
    chrome,
    console,
    crypto: {
      getRandomValues(bytes) {
        bytes.fill(0x2a);
        return bytes;
      }
    },
    Date: {
      now() {
        return 1_700_000_000_000;
      }
    },
    importScripts() {},
    setTimeout(callback, delay) {
      calls.timeout.push(delay);
      callback();
      return 1;
    }
  });
  vm.runInContext(coreSource, context, {
    filename: "service-worker-core.js"
  });
  vm.runInContext(workerSource, context, {
    filename: "service-worker.js"
  });
  return { calls, listener: calls.webRequestListener };
}

async function settleWorkerPromises() {
  await Promise.resolve();
  await Promise.resolve();
  await new Promise((resolve) => setImmediate(resolve));
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

test("incomplete top-frame request confirms and reloads the same host once", async () => {
  const { calls, listener } = createWorker();

  listener({
    error: "net::ERR_CONTENT_LENGTH_MISMATCH",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 17,
    url: "https://Partial.Example/download?secret=ignored"
  });
  await settleWorkerPromises();

  assert.deepEqual(plain(calls.webRequestFilter), {
    urls: ["https://*/*"],
    types: ["main_frame"]
  });
  assert.equal(calls.native.length, 1);
  assert.equal(calls.native[0].host, "dev.slipstream.semantic");
  assert.deepEqual(plain(calls.native[0].signal), {
    schema_version: 2,
    signal_id: "2a".repeat(16),
    source: "browser_extension",
    host: "partial.example",
    category: "incomplete_response",
    confidence_bps: 10000,
    observed_at_unix_ms: 1_700_000_000_000,
    top_level: true
  });
  assert.deepEqual(calls.timeout, [250]);
  assert.deepEqual(calls.reload, [17]);
});

test("accepted confirmation does not reload after the tab changes host", async () => {
  const { calls, listener } = createWorker({
    currentTabUrl: "https://other.example/"
  });

  listener({
    error: "net::ERR_INCOMPLETE_CHUNKED_ENCODING",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 18,
    url: "https://partial.example/"
  });
  await settleWorkerPromises();

  assert.equal(calls.native.length, 1);
  assert.deepEqual(calls.reload, []);
});

test("rejected confirmation never schedules a reload", async () => {
  const { calls, listener } = createWorker({
    nativeResponse: {
      schema_version: 1,
      accepted: false,
      action: "none"
    }
  });

  listener({
    error: "net::ERR_CONTENT_LENGTH_MISMATCH",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 19,
    url: "https://partial.example/"
  });
  await settleWorkerPromises();

  assert.equal(calls.native.length, 1);
  assert.deepEqual(calls.timeout, []);
  assert.deepEqual(calls.reload, []);
});

test("ambiguous request errors never cross native messaging", async () => {
  const { calls, listener } = createWorker();

  listener({
    error: "net::ERR_CONNECTION_RESET",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 20,
    url: "https://partial.example/"
  });
  await settleWorkerPromises();

  assert.deepEqual(calls.native, []);
  assert.deepEqual(calls.reload, []);
});

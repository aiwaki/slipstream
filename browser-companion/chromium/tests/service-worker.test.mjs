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
    beforeRequestListener: null,
    completedListener: null,
    errorListener: null
  };
  const sessionValues = {};
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
    storage: {
      session: {
        get(key) {
          return Promise.resolve(
            Object.hasOwn(sessionValues, key)
              ? { [key]: sessionValues[key] }
              : {}
          );
        },
        remove(key) {
          delete sessionValues[key];
          return Promise.resolve();
        },
        set(entries) {
          Object.assign(sessionValues, entries);
          return Promise.resolve();
        }
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
      onBeforeRequest: {
        addListener(listener, filter) {
          calls.beforeRequestListener = listener;
          calls.beforeRequestFilter = filter;
        }
      },
      onCompleted: {
        addListener(listener, filter) {
          calls.completedListener = listener;
          calls.completedFilter = filter;
        }
      },
      onErrorOccurred: {
        addListener(listener, filter) {
          calls.errorListener = listener;
          calls.errorFilter = filter;
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
  return {
    before: calls.beforeRequestListener,
    calls,
    completed: calls.completedListener,
    error: calls.errorListener
  };
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
  const { before, calls, error } = createWorker();

  before({
    requestId: "request-17",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 17,
    url: "https://Partial.Example/download?secret=ignored"
  });
  await settleWorkerPromises();
  error({
    requestId: "request-17",
    error: "net::ERR_CONTENT_LENGTH_MISMATCH",
    type: "main_frame",
    frameId: 0,
    tabId: 17,
    url: "https://Partial.Example/download?secret=ignored"
  });
  await settleWorkerPromises();

  assert.deepEqual(plain(calls.beforeRequestFilter), {
    urls: ["https://*/*"],
    types: ["main_frame"]
  });
  assert.deepEqual(plain(calls.errorFilter), {
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
  const { before, calls, error } = createWorker({
    currentTabUrl: "https://other.example/"
  });

  before({
    requestId: "request-18",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 18,
    url: "https://partial.example/"
  });
  await settleWorkerPromises();
  error({
    requestId: "request-18",
    error: "net::ERR_INCOMPLETE_CHUNKED_ENCODING",
    type: "main_frame",
    frameId: 0,
    tabId: 18,
    url: "https://partial.example/"
  });
  await settleWorkerPromises();

  assert.equal(calls.native.length, 1);
  assert.deepEqual(calls.reload, []);
});

test("rejected confirmation never schedules a reload", async () => {
  const { before, calls, error } = createWorker({
    nativeResponse: {
      schema_version: 1,
      accepted: false,
      action: "none"
    }
  });

  before({
    requestId: "request-19",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 19,
    url: "https://partial.example/"
  });
  await settleWorkerPromises();
  error({
    requestId: "request-19",
    error: "net::ERR_CONTENT_LENGTH_MISMATCH",
    type: "main_frame",
    frameId: 0,
    tabId: 19,
    url: "https://partial.example/"
  });
  await settleWorkerPromises();

  assert.equal(calls.native.length, 1);
  assert.deepEqual(calls.timeout, []);
  assert.deepEqual(calls.reload, []);
});

test("ambiguous request errors never cross native messaging", async () => {
  const { before, calls, error } = createWorker();

  before({
    requestId: "request-20",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 20,
    url: "https://partial.example/"
  });
  await settleWorkerPromises();
  error({
    requestId: "request-20",
    error: "net::ERR_CONNECTION_RESET",
    type: "main_frame",
    frameId: 0,
    tabId: 20,
    url: "https://partial.example/"
  });
  await settleWorkerPromises();

  assert.deepEqual(calls.native, []);
  assert.deepEqual(calls.reload, []);
});

test("a completed request cannot be reused as an incomplete candidate", async () => {
  const { before, calls, completed, error } = createWorker();
  const request = {
    requestId: "request-21",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 21,
    url: "https://partial.example/"
  };

  before(request);
  await settleWorkerPromises();
  completed({
    requestId: request.requestId,
    type: "main_frame",
    frameId: 0,
    tabId: request.tabId,
    url: request.url
  });
  await settleWorkerPromises();
  error({
    requestId: request.requestId,
    error: "net::ERR_CONTENT_LENGTH_MISMATCH",
    type: "main_frame",
    frameId: 0,
    tabId: request.tabId,
    url: request.url
  });
  await settleWorkerPromises();

  assert.deepEqual(calls.native, []);
  assert.deepEqual(calls.reload, []);
});

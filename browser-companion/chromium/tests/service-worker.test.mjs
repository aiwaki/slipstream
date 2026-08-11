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
  currentTab = {
    status: "complete",
    url: "https://partial.example/page"
  }
} = {}) {
  let nowUnixMs = 1_700_000_000_000;
  const calls = {
    native: [],
    reload: [],
    timeout: [],
    pendingTimeouts: [],
    beforeRequestListener: null,
    beforeRedirectListener: null,
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
        return Promise.resolve(currentTab);
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
      onBeforeRedirect: {
        addListener(listener, filter) {
          calls.beforeRedirectListener = listener;
          calls.beforeRedirectFilter = filter;
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
        return nowUnixMs;
      }
    },
    importScripts() {},
    setTimeout(callback, delay) {
      calls.timeout.push(delay);
      if (delay === 8000) {
        calls.pendingTimeouts.push(callback);
      } else {
        callback();
      }
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
    advanceClock(milliseconds) {
      nowUnixMs += milliseconds;
    },
    calls,
    completed: calls.completedListener,
    error: calls.errorListener,
    redirect: calls.beforeRedirectListener
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
  assert.deepEqual(plain(calls.beforeRedirectFilter), {
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
  assert.deepEqual(calls.timeout, [8000, 250]);
  assert.deepEqual(calls.reload, [17]);
});

test("accepted confirmation does not reload after the tab changes host", async () => {
  const { before, calls, error } = createWorker({
    currentTab: {
      status: "complete",
      url: "https://other.example/"
    }
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
  assert.deepEqual(calls.timeout, [8000]);
  assert.deepEqual(calls.reload, []);
});

test("still-pending about:blank navigation sends one privacy-bounded v3 signal", async () => {
  const { advanceClock, before, calls } = createWorker({
    nativeResponse: {
      schema_version: 1,
      accepted: true,
      action: "retry_pending_navigation"
    },
    currentTab: {
      status: "loading",
      url: "about:blank",
      pendingUrl: "https://Pending.Example/private?secret=yes"
    }
  });

  before({
    requestId: "request-pending",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 31,
    url: "https://Pending.Example/private?secret=yes"
  });
  await settleWorkerPromises();
  advanceClock(8000);
  calls.pendingTimeouts[0]();
  await settleWorkerPromises();

  assert.equal(calls.native.length, 1);
  assert.deepEqual(plain(calls.native[0].signal), {
    schema_version: 3,
    signal_id: "2a".repeat(16),
    source: "browser_extension",
    host: "pending.example",
    category: "navigation_pending",
    confidence_bps: 10000,
    observed_at_unix_ms: 1_700_000_008_000,
    request_started_at_unix_ms: 1_700_000_000_000,
    top_level: true
  });
  assert.deepEqual(calls.reload, []);
});

test("committed, completed, and cross-host tabs never send pending signals", async () => {
  for (const currentTab of [
    { status: "complete", url: "https://pending.example/" },
    {
      status: "loading",
      url: "about:blank",
      pendingUrl: "https://other.example/"
    },
    { status: "loading", url: "https://pending.example/" }
  ]) {
    const { advanceClock, before, calls } = createWorker({ currentTab });
    before({
      requestId: `request-${calls.timeout.length}`,
      type: "main_frame",
      method: "GET",
      frameId: 0,
      parentFrameId: -1,
      tabId: 32,
      url: "https://pending.example/"
    });
    await settleWorkerPromises();
    advanceClock(8000);
    calls.pendingTimeouts[0]();
    await settleWorkerPromises();
    assert.deepEqual(calls.native, []);
  }
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

test("a redirected request cannot leave a reusable incomplete candidate", async () => {
  const { before, calls, error, redirect } = createWorker();
  const request = {
    requestId: "request-22",
    type: "main_frame",
    method: "GET",
    frameId: 0,
    parentFrameId: -1,
    tabId: 22,
    url: "https://partial.example/"
  };

  before(request);
  redirect({
    requestId: request.requestId,
    type: "main_frame",
    frameId: 0,
    tabId: request.tabId,
    url: request.url,
    redirectUrl: "custom-scheme://finished"
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

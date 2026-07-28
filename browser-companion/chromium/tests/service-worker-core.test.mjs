import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";

const context = vm.createContext({ URL, Uint8Array });
const source = fs.readFileSync(
  new URL("../service-worker-core.js", import.meta.url),
  "utf8"
);
vm.runInContext(source, context);
const core = context.SlipstreamServiceWorkerCore;

const message = {
  type: "slipstream.regional_access_denied",
  confidence_bps: 9800
};
const sender = {
  frameId: 0,
  tab: {
    url: "https://Weather.COM/private/path?account=secret"
  }
};

test("derives only hostname from the browser-owned top-level sender", () => {
  const signal = core.buildSemanticSignal(
    message,
    sender,
    1_000_000,
    new Uint8Array(16).fill(10)
  );

  assert.deepEqual(Object.keys(signal).sort(), [
    "category",
    "confidence_bps",
    "host",
    "observed_at_unix_ms",
    "schema_version",
    "signal_id",
    "source",
    "top_level"
  ]);
  assert.equal(signal.host, "weather.com");
  assert.equal(signal.signal_id, "0a".repeat(16));
  assert.equal(JSON.stringify(signal).includes("/private/path"), false);
  assert.equal(JSON.stringify(signal).includes("account=secret"), false);
});

test("rejects content-script attempts to provide host, URL, or text", () => {
  for (const extra of [
    { host: "attacker.example" },
    { url: "https://attacker.example/" },
    { text: "regional denial" }
  ]) {
    assert.equal(
      core.buildSemanticSignal(
        { ...message, ...extra },
        sender,
        1_000_000,
        new Uint8Array(16)
      ),
      null
    );
  }
});

test("rejects subframes, non-HTTPS pages, IP literals, and low confidence", () => {
  assert.equal(
    core.buildSemanticSignal(
      message,
      { ...sender, frameId: 2 },
      1_000_000,
      new Uint8Array(16)
    ),
    null
  );
  for (const url of ["http://example.com/", "https://127.0.0.1/"]) {
    assert.equal(
      core.buildSemanticSignal(
        message,
        { frameId: 0, tab: { url } },
        1_000_000,
        new Uint8Array(16)
      ),
      null
    );
  }
  assert.equal(
    core.buildSemanticSignal(
      { ...message, confidence_bps: 8999 },
      sender,
      1_000_000,
      new Uint8Array(16)
    ),
    null
  );
});

test("requests one bounded reload only after confirmation was scheduled", () => {
  const signal = core.buildSemanticSignal(
    message,
    sender,
    1_000_000,
    new Uint8Array(16).fill(10)
  );
  const instruction = core.reloadInstruction({
    schema_version: 1,
    accepted: true,
    action: "confirm_exact_host_geo_exit",
    reason: "accepted"
  }, signal);
  assert.equal(instruction.action, "reload_after_confirmation");
  assert.equal(instruction.delay_ms, 7000);
  for (const response of [
    null,
    { schema_version: 1, accepted: false, action: "none" },
    { schema_version: 1, accepted: true, action: "none" },
    {
      schema_version: 2,
      accepted: true,
      action: "confirm_exact_host_geo_exit"
    }
  ]) {
    assert.equal(core.reloadInstruction(response, signal), null);
  }
});

test("maps only exact top-level incomplete-response browser errors to v2", () => {
  for (const error of [
    "net::ERR_CONTENT_LENGTH_MISMATCH",
    "net::ERR_INCOMPLETE_CHUNKED_ENCODING"
  ]) {
    const signal = core.buildIncompleteResponseSignal(
      {
        tabId: 7,
        frameId: 0,
        url: "https://Example.NET/private/path?token=secret",
        error
      },
      1_000_000,
      new Uint8Array(16).fill(11)
    );

    assert.equal(signal.schema_version, 2);
    assert.equal(signal.category, "incomplete_response");
    assert.equal(signal.host, "example.net");
    assert.equal(signal.confidence_bps, 10000);
    assert.equal(JSON.stringify(signal).includes("ERR_"), false);
    assert.equal(JSON.stringify(signal).includes("/private/path"), false);
    assert.equal(JSON.stringify(signal).includes("token=secret"), false);
  }
});

test("rejects ambiguous, subframe, non-HTTPS, and IP navigation errors", () => {
  const base = {
    tabId: 7,
    frameId: 0,
    url: "https://example.net/",
    error: "net::ERR_CONTENT_LENGTH_MISMATCH"
  };
  for (const details of [
    { ...base, frameId: 2 },
    { ...base, tabId: -1 },
    { ...base, url: "http://example.net/" },
    { ...base, url: "https://127.0.0.1/" },
    { ...base, error: "net::ERR_CONNECTION_CLOSED" },
    { ...base, error: "net::ERR_HTTP2_PROTOCOL_ERROR" }
  ]) {
    assert.equal(
      core.buildIncompleteResponseSignal(
        details,
        1_000_000,
        new Uint8Array(16)
      ),
      null
    );
  }
});

test("v2 reload follows completed confirmation and remains same-host scoped", () => {
  const signal = core.buildIncompleteResponseSignal(
    {
      tabId: 7,
      frameId: 0,
      url: "https://example.net/",
      error: "net::ERR_CONTENT_LENGTH_MISMATCH"
    },
    1_000_000,
    new Uint8Array(16).fill(12)
  );
  const instruction = core.reloadInstruction(
    {
      schema_version: 1,
      accepted: true,
      action: "confirm_exact_host_geo_exit",
      reason: "accepted"
    },
    signal
  );

  assert.equal(instruction.delay_ms, 250);
  assert.equal(
    core.tabStillOnSignalHost(
      { url: "https://example.net/another/path?private=yes" },
      signal
    ),
    true
  );
  assert.equal(
    core.tabStillOnSignalHost({ url: "https://other.example/" }, signal),
    false
  );
});

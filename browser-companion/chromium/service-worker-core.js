(function initializeSlipstreamServiceWorkerCore(scope) {
  "use strict";

  const MESSAGE_TYPE = "slipstream.regional_access_denied";
  const INCOMPLETE_RESPONSE_ERRORS = Object.freeze([
    "net::ERR_CONTENT_LENGTH_MISMATCH",
    "net::ERR_INCOMPLETE_CHUNKED_ENCODING"
  ]);
  const MIN_CONFIDENCE_BPS = 9000;
  const MAX_CONFIDENCE_BPS = 10000;
  const CONFIRMATION_RELOAD_DELAY_MS = 7000;
  const COMPLETED_CONFIRMATION_RELOAD_DELAY_MS = 250;

  function exactMessage(message) {
    if (!message || typeof message !== "object" || Array.isArray(message)) {
      return false;
    }
    const keys = Object.keys(message).sort();
    return (
      keys.length === 2 &&
      keys[0] === "confidence_bps" &&
      keys[1] === "type" &&
      message.type === MESSAGE_TYPE &&
      Number.isInteger(message.confidence_bps) &&
      message.confidence_bps >= MIN_CONFIDENCE_BPS &&
      message.confidence_bps <= MAX_CONFIDENCE_BPS
    );
  }

  function normalizedHttpsHostname(url) {
    if (typeof url !== "string") {
      return null;
    }
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return null;
    }
    if (parsed.protocol !== "https:" || !parsed.hostname) {
      return null;
    }
    const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
    if (
      host.length > 253 ||
      host.includes(":") ||
      /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)
    ) {
      return null;
    }
    return host;
  }

  function browserOwnedHostname(sender) {
    if (!sender || sender.frameId !== 0 || !sender.tab) {
      return null;
    }
    return normalizedHttpsHostname(sender.tab.url);
  }

  function signalId(randomBytes) {
    if (!(randomBytes instanceof Uint8Array) || randomBytes.length !== 16) {
      return null;
    }
    return Array.from(randomBytes, (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");
  }

  function buildSemanticSignal(message, sender, nowUnixMs, randomBytes) {
    if (!exactMessage(message)) {
      return null;
    }
    const host = browserOwnedHostname(sender);
    const id = signalId(randomBytes);
    if (
      !host ||
      !id ||
      !Number.isSafeInteger(nowUnixMs) ||
      nowUnixMs <= 0
    ) {
      return null;
    }
    return {
      schema_version: 1,
      signal_id: id,
      source: "browser_extension",
      host,
      category: "regional_access_denied",
      confidence_bps: message.confidence_bps,
      observed_at_unix_ms: nowUnixMs,
      top_level: true
    };
  }

  function buildIncompleteResponseSignal(details, nowUnixMs, randomBytes) {
    if (
      !details ||
      typeof details !== "object" ||
      Array.isArray(details) ||
      details.frameId !== 0 ||
      !Number.isInteger(details.tabId) ||
      details.tabId < 0 ||
      !INCOMPLETE_RESPONSE_ERRORS.includes(details.error)
    ) {
      return null;
    }
    const host = normalizedHttpsHostname(details.url);
    const id = signalId(randomBytes);
    if (
      !host ||
      !id ||
      !Number.isSafeInteger(nowUnixMs) ||
      nowUnixMs <= 0
    ) {
      return null;
    }
    return {
      schema_version: 2,
      signal_id: id,
      source: "browser_extension",
      host,
      category: "incomplete_response",
      confidence_bps: MAX_CONFIDENCE_BPS,
      observed_at_unix_ms: nowUnixMs,
      top_level: true
    };
  }

  function reloadInstruction(nativeResponse, signal) {
    if (
      !nativeResponse ||
      typeof nativeResponse !== "object" ||
      Array.isArray(nativeResponse) ||
      nativeResponse.schema_version !== 1 ||
      nativeResponse.accepted !== true ||
      nativeResponse.action !== "confirm_exact_host_geo_exit" ||
      !signal ||
      ![1, 2].includes(signal.schema_version)
    ) {
      return null;
    }
    return {
      action: "reload_after_confirmation",
      delay_ms:
        signal.schema_version === 2
          ? COMPLETED_CONFIRMATION_RELOAD_DELAY_MS
          : CONFIRMATION_RELOAD_DELAY_MS
    };
  }

  function tabStillOnSignalHost(tab, signal) {
    return Boolean(
      tab &&
        signal &&
        typeof signal.host === "string" &&
        normalizedHttpsHostname(tab.url) === signal.host
    );
  }

  scope.SlipstreamServiceWorkerCore = Object.freeze({
    buildIncompleteResponseSignal,
    buildSemanticSignal,
    browserOwnedHostname,
    exactMessage,
    normalizedHttpsHostname,
    reloadInstruction,
    signalId,
    tabStillOnSignalHost
  });
})(globalThis);

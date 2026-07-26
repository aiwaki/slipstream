(function initializeSlipstreamServiceWorkerCore(scope) {
  "use strict";

  const MESSAGE_TYPE = "slipstream.regional_access_denied";
  const MIN_CONFIDENCE_BPS = 9000;
  const MAX_CONFIDENCE_BPS = 10000;
  const CONFIRMATION_RELOAD_DELAY_MS = 7000;

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

  function browserOwnedHostname(sender) {
    if (
      !sender ||
      sender.frameId !== 0 ||
      !sender.tab ||
      typeof sender.tab.url !== "string"
    ) {
      return null;
    }
    let parsed;
    try {
      parsed = new URL(sender.tab.url);
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

  function reloadInstruction(nativeResponse) {
    if (
      !nativeResponse ||
      typeof nativeResponse !== "object" ||
      Array.isArray(nativeResponse) ||
      nativeResponse.schema_version !== 1 ||
      nativeResponse.accepted !== true ||
      nativeResponse.action !== "confirm_exact_host_geo_exit"
    ) {
      return null;
    }
    return {
      action: "reload_after_confirmation",
      delay_ms: CONFIRMATION_RELOAD_DELAY_MS
    };
  }

  scope.SlipstreamServiceWorkerCore = Object.freeze({
    buildSemanticSignal,
    browserOwnedHostname,
    exactMessage,
    reloadInstruction,
    signalId
  });
})(globalThis);

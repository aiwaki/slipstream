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
  const INCOMPLETE_RESPONSE_CANDIDATE_TTL_MS = 5 * 60 * 1000;
  const PENDING_NAVIGATION_DELAY_MS = 8000;
  const INCOMPLETE_RESPONSE_STORAGE_PREFIX =
    "slipstream.incomplete-response.";

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

  function incompleteResponseCandidate(details, nowUnixMs) {
    if (
      !details ||
      typeof details !== "object" ||
      Array.isArray(details) ||
      typeof details.requestId !== "string" ||
      !details.requestId ||
      details.type !== "main_frame" ||
      details.method !== "GET" ||
      details.frameId !== 0 ||
      (details.parentFrameId !== undefined && details.parentFrameId !== -1) ||
      !Number.isInteger(details.tabId) ||
      details.tabId < 0 ||
      !Number.isSafeInteger(nowUnixMs) ||
      nowUnixMs <= 0
    ) {
      return null;
    }
    const host = normalizedHttpsHostname(details.url);
    if (!host) {
      return null;
    }
    return {
      request_id: details.requestId,
      tab_id: details.tabId,
      host,
      request_started_at_unix_ms: nowUnixMs,
      expires_at_unix_ms:
        nowUnixMs + INCOMPLETE_RESPONSE_CANDIDATE_TTL_MS
    };
  }

  function incompleteResponseStorageKey(requestId) {
    if (typeof requestId !== "string" || !requestId) {
      return null;
    }
    return `${INCOMPLETE_RESPONSE_STORAGE_PREFIX}${requestId}`;
  }

  function validIncompleteResponseCandidate(candidate, details, nowUnixMs) {
    if (
      !candidate ||
      typeof candidate !== "object" ||
      Array.isArray(candidate) ||
      Object.keys(candidate).sort().join(",") !==
        "expires_at_unix_ms,host,request_id,request_started_at_unix_ms,tab_id" ||
      candidate.request_id !== details.requestId ||
      candidate.tab_id !== details.tabId ||
      candidate.host !== normalizedHttpsHostname(details.url) ||
      !Number.isSafeInteger(candidate.request_started_at_unix_ms) ||
      candidate.request_started_at_unix_ms <= 0 ||
      !Number.isSafeInteger(candidate.expires_at_unix_ms) ||
      candidate.expires_at_unix_ms < nowUnixMs
    ) {
      return false;
    }
    return true;
  }

  function tabHasPendingNavigation(tab, candidate) {
    return Boolean(
      tab &&
        candidate &&
        tab.status === "loading" &&
        normalizedHttpsHostname(tab.pendingUrl) === candidate.host
    );
  }

  function buildPendingNavigationSignal(
    candidate,
    tab,
    nowUnixMs,
    randomBytes
  ) {
    if (
      !candidate ||
      typeof candidate !== "object" ||
      Array.isArray(candidate) ||
      Object.keys(candidate).sort().join(",") !==
        "expires_at_unix_ms,host,request_id,request_started_at_unix_ms,tab_id" ||
      !Number.isSafeInteger(nowUnixMs) ||
      nowUnixMs <= 0 ||
      !Number.isSafeInteger(candidate.request_started_at_unix_ms) ||
      candidate.request_started_at_unix_ms <= 0 ||
      nowUnixMs - candidate.request_started_at_unix_ms <
        PENDING_NAVIGATION_DELAY_MS ||
      candidate.expires_at_unix_ms < nowUnixMs ||
      !tabHasPendingNavigation(tab, candidate)
    ) {
      return null;
    }
    const id = signalId(randomBytes);
    if (!id) {
      return null;
    }
    return {
      schema_version: 3,
      signal_id: id,
      source: "browser_extension",
      host: candidate.host,
      category: "navigation_pending",
      confidence_bps: MAX_CONFIDENCE_BPS,
      observed_at_unix_ms: nowUnixMs,
      request_started_at_unix_ms: candidate.request_started_at_unix_ms,
      top_level: true
    };
  }

  function buildIncompleteResponseSignal(
    details,
    candidate,
    nowUnixMs,
    randomBytes
  ) {
    if (
      !details ||
      typeof details !== "object" ||
      Array.isArray(details) ||
      typeof details.requestId !== "string" ||
      !details.requestId ||
      details.type !== "main_frame" ||
      details.frameId !== 0 ||
      !Number.isInteger(details.tabId) ||
      details.tabId < 0 ||
      !INCOMPLETE_RESPONSE_ERRORS.includes(details.error) ||
      !Number.isSafeInteger(nowUnixMs) ||
      nowUnixMs <= 0 ||
      !validIncompleteResponseCandidate(candidate, details, nowUnixMs)
    ) {
      return null;
    }
    const host = normalizedHttpsHostname(details.url);
    const id = signalId(randomBytes);
    if (!host || !id) {
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

  function createIncompleteResponseTracker(storageSession) {
    const memory = new Map();
    let pending = Promise.resolve();
    const durable =
      storageSession &&
      typeof storageSession.get === "function" &&
      typeof storageSession.set === "function" &&
      typeof storageSession.remove === "function"
        ? storageSession
        : null;

    function enqueue(operation) {
      const result = pending.then(operation, operation);
      pending = result.then(
        () => undefined,
        () => undefined
      );
      return result;
    }

    function remember(details, nowUnixMs) {
      return enqueue(async () => {
        const candidate = incompleteResponseCandidate(details, nowUnixMs);
        const key = incompleteResponseStorageKey(details?.requestId);
        if (!candidate || !key) {
          return false;
        }
        memory.set(key, candidate);
        if (durable) {
          await durable.set({ [key]: candidate });
        }
        return true;
      });
    }

    function take(details) {
      return enqueue(async () => {
        const key = incompleteResponseStorageKey(details?.requestId);
        if (!key) {
          return null;
        }
        let candidate = memory.get(key) ?? null;
        memory.delete(key);
        if (!candidate && durable) {
          const stored = await durable.get(key);
          candidate = stored?.[key] ?? null;
        }
        if (durable) {
          await durable.remove(key);
        }
        return candidate;
      });
    }

    function peek(details) {
      return enqueue(async () => {
        const key = incompleteResponseStorageKey(details?.requestId);
        if (!key) {
          return null;
        }
        let candidate = memory.get(key) ?? null;
        if (!candidate && durable) {
          const stored = await durable.get(key);
          candidate = stored?.[key] ?? null;
        }
        return candidate;
      });
    }

    function discard(details) {
      return enqueue(async () => {
        const key = incompleteResponseStorageKey(details?.requestId);
        if (!key) {
          return;
        }
        memory.delete(key);
        if (durable) {
          await durable.remove(key);
        }
      });
    }

    return Object.freeze({ discard, peek, remember, take });
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
    buildPendingNavigationSignal,
    buildSemanticSignal,
    browserOwnedHostname,
    createIncompleteResponseTracker,
    exactMessage,
    incompleteResponseCandidate,
    incompleteResponseStorageKey,
    normalizedHttpsHostname,
    pendingNavigationDelayMs: PENDING_NAVIGATION_DELAY_MS,
    reloadInstruction,
    signalId,
    tabHasPendingNavigation,
    tabStillOnSignalHost
  });
})(globalThis);

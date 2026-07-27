(function startSlipstreamContentObserver() {
  "use strict";

  if (window.top !== window || !globalThis.SlipstreamRegionalDenialDetector) {
    return;
  }

  const detector = globalThis.SlipstreamRegionalDenialDetector;
  const STOP_AFTER_MS = 10000;
  const DEBOUNCE_MS = 350;
  const MAX_EVALUATIONS = 8;
  const MAX_BODY_TEXT_CHARS = 16000;
  const MAX_DIALOG_TEXT_CHARS = 8192;
  const MAX_TEXT_NODES = 512;
  let sent = false;
  let timer = null;
  let observer = null;
  let evaluations = 0;

  function boundedVisibleText(root, limit) {
    let text = "";
    let visited = 0;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      visited += 1;
      if (visited > MAX_TEXT_NODES) {
        return { text, truncated: true };
      }
      const node = walker.currentNode;
      const parent = node.parentElement;
      if (
        !parent ||
        parent.closest(
          'script, style, noscript, template, [hidden], [aria-hidden="true"]'
        )
      ) {
        continue;
      }
      const value = node.textContent || "";
      if (!value.trim()) {
        continue;
      }
      const remaining = limit - text.length;
      if (remaining <= 0) {
        return { text, truncated: true };
      }
      text += ` ${value.slice(0, remaining)}`;
      if (value.length > remaining) {
        return { text, truncated: true };
      }
    }
    return { text, truncated: false };
  }

  function visibleDialogText() {
    const dialogs = document.querySelectorAll(
      '[role="dialog"], [aria-modal="true"]'
    );
    let text = "";
    for (const dialog of dialogs) {
      const style = getComputedStyle(dialog);
      if (
        style.display === "none" ||
        style.visibility === "hidden" ||
        Number(style.opacity) === 0
      ) {
        continue;
      }
      const remaining = MAX_DIALOG_TEXT_CHARS - text.length;
      if (remaining <= 0) {
        break;
      }
      const collected = boundedVisibleText(dialog, remaining);
      text += collected.text;
      if (collected.truncated) {
        break;
      }
    }
    return text;
  }

  function snapshot() {
    const body = document.body;
    const linkCount = document.links ? document.links.length : 0;
    const formCount = document.forms ? document.forms.length : 0;
    const bodyText =
      body && linkCount <= 40 && formCount <= 4
        ? boundedVisibleText(body, MAX_BODY_TEXT_CHARS)
        : { text: "", truncated: true };
    return {
      title: document.title || "",
      dialogText: visibleDialogText(),
      bodyText: bodyText.text,
      bodyTextTruncated: bodyText.truncated,
      linkCount,
      formCount
    };
  }

  function stop() {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
  }

  function evaluate() {
    timer = null;
    evaluations += 1;
    if (sent || evaluations > MAX_EVALUATIONS) {
      stop();
      return;
    }
    const result = detector.detectRegionalDenial(snapshot());
    if (!result) {
      return;
    }
    sent = true;
    stop();
    const observedHost = location.hostname;
    chrome.runtime.sendMessage({
      type: "slipstream.regional_access_denied",
      confidence_bps: result.confidenceBps
    }).then((instruction) => {
      if (
        !instruction ||
        instruction.action !== "reload_after_confirmation" ||
        !Number.isInteger(instruction.delay_ms) ||
        instruction.delay_ms < 1000 ||
        instruction.delay_ms > 10000
      ) {
        return;
      }
      setTimeout(() => {
        if (location.hostname === observedHost) {
          location.reload();
        }
      }, instruction.delay_ms);
    }).catch(() => {});
  }

  function schedule() {
    if (sent || timer !== null) {
      return;
    }
    timer = setTimeout(evaluate, DEBOUNCE_MS);
  }

  observer = new MutationObserver(schedule);
  if (document.documentElement) {
    observer.observe(document.documentElement, {
      childList: true,
      characterData: true,
      subtree: true
    });
  }
  schedule();
  setTimeout(schedule, 1200);
  setTimeout(schedule, 3500);
  setTimeout(schedule, 7500);
  setTimeout(stop, STOP_AFTER_MS);
})();

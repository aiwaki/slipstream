import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = fs.readFileSync(
  new URL("../detector.js", import.meta.url),
  "utf8"
);
const context = vm.createContext({});
vm.runInContext(source, context);
const detector = context.SlipstreamRegionalDenialDetector;

function snapshot(bodyText, overrides = {}) {
  return {
    title: "",
    dialogText: "",
    bodyText,
    linkCount: 0,
    formCount: 0,
    ...overrides
  };
}

test("detects the observed weather.com regional denial without a host rule", () => {
  const result = detector.detectRegionalDenial(
    snapshot("This content is no longer available in your area")
  );
  assert.equal(result.category, "regional_access_denied");
  assert.ok(result.confidenceBps >= 9500);
});

test("detects multiple languages through the same semantic category", () => {
  for (const text of [
    "Сервис недоступен в вашем регионе",
    "Ce contenu n'est pas disponible dans votre région",
    "Dieser Inhalt ist in deiner Region nicht verfügbar",
    "Este contenido no está disponible en tu región"
  ]) {
    assert.equal(
      detector.detectRegionalDenial(snapshot(text)).category,
      "regional_access_denied"
    );
  }
});

test("does not confuse ordinary availability or authentication errors with geography", () => {
  for (const text of [
    "This content is available in your area",
    "Access denied. Please sign in.",
    "The product is unavailable while inventory is updated.",
    "Our article explains why video can be blocked on regional networks."
  ]) {
    assert.equal(detector.detectRegionalDenial(snapshot(text)), null);
  }
});

test("accepts a bounded visible modal on an otherwise rich page", () => {
  const result = detector.detectRegionalDenial(
    snapshot("catalog ".repeat(10000), {
      dialogText: "This service is not available in your country",
      linkCount: 300
    })
  );
  assert.equal(result.category, "regional_access_denied");
});

test("does not scan a rich body without a dedicated title or dialog", () => {
  const result = detector.detectRegionalDenial(
    snapshot(
      `This content is not available in your region. ${"article ".repeat(3000)}`,
      { linkCount: 200 }
    )
  );
  assert.equal(result, null);
});

test("rejects a body snapshot truncated by the incremental collector", () => {
  assert.equal(
    detector.detectRegionalDenial(
      snapshot("This content is no longer available in your area", {
        bodyTextTruncated: true
      })
    ),
    null
  );
});

test("detects a sparse generic edge security denial without a host or vendor rule", () => {
  const result = detector.detectEdgeAccessDenial(
    snapshot(
      "Sorry, you have been blocked. You are unable to access this website. " +
        "This website is using a security service to protect itself from online attacks."
    )
  );
  assert.equal(result.category, "edge_access_denied");
  assert.ok(result.confidenceBps >= 9600);
});

test("separates challenges, authentication, and rate limits from edge denial", () => {
  for (const text of [
    "Access denied. Please sign in to continue.",
    "Verify that you are human to complete this security challenge.",
    "Too many requests. You have been rate limited by our security service."
  ]) {
    assert.equal(
      detector.detectEdgeAccessDenial(snapshot(text)).category,
      "challenge_or_auth"
    );
  }
});

test("does not learn from an ordinary access error or rich security article", () => {
  for (const candidate of [
    snapshot("Access denied."),
    snapshot("Our security service documentation explains how a firewall works."),
    snapshot(
      `Sorry, you have been blocked. ${"security article ".repeat(3000)}`,
      { linkCount: 200 }
    )
  ]) {
    assert.equal(detector.detectEdgeAccessDenial(candidate), null);
  }
});

test("semantic dispatcher preserves regional priority and emits fixed categories", () => {
  assert.equal(
    detector.detectSemanticDenial(
      snapshot("This content is no longer available in your area")
    ).category,
    "regional_access_denied"
  );
  assert.equal(
    detector.detectSemanticDenial(
      snapshot(
        "Your request was blocked by the security service protecting this website."
      )
    ).category,
    "edge_access_denied"
  );
});

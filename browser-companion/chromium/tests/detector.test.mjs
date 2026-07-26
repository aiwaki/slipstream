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

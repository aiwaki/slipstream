import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const {expression} = JSON.parse(readFileSync(0, 'utf8'));
let passed = 0;
const asset = 'https://fixture.invalid/style.css?private-token';
const entry = (name = asset) => Object.freeze({
  name, encodedBodySize: 73640, decodedBodySize: 838287, transferSize: 73940,
  responseEnd: 2746.9, domContentLoadedEventEnd: 0, loadEventEnd: 0,
});
const style = (extra = {}) => Object.freeze({
  tagName: 'LINK', href: asset, sheet: null, disabled: false, media: '', inBody: true, ...extra,
});
const script = (extra = {}) => Object.freeze({
  tagName: 'SCRIPT', src: '', type: '', async: false, defer: false, inBody: true, ...extra,
});
function observe({nodes = [], resources = [], navigation = entry(), overrides = {}} = {}) {
  const calls = [];
  const forbidden = () => { throw new Error('unexpected effect'); };
  const context = {
    URL, Map,
    document: Object.freeze({
      baseURI: 'https://fixture.invalid/',
      body: Object.freeze({contains: node => node.inBody}),
      querySelectorAll: selector => {
        assert.equal(selector, 'link[rel~="stylesheet"], script');
        return Object.freeze(nodes);
      },
    }),
    location: Object.freeze({origin: 'https://fixture.invalid'}),
    performance: Object.freeze({getEntriesByType: type => {
      calls.push(type);
      if (type === 'resource') return Object.freeze(resources);
      assert.equal(type, 'navigation');
      return navigation ? [navigation] : [];
    }}),
    matchMedia: media => ({matches: media !== 'print'}),
    fetch: forbidden, XMLHttpRequest: forbidden, WebSocket: forbidden,
    setTimeout: forbidden, setInterval: forbidden,
    ...overrides,
  };
  const result = JSON.parse(JSON.stringify(vm.runInNewContext(expression, context, {timeout: 1000})));
  assert.ok(calls.length <= 2);
  assert.ok(JSON.stringify(result).length < 12000);
  assert.ok(!JSON.stringify(result).includes('private-token'));
  assert.ok(!JSON.stringify(result).includes('https://'));
  return result;
}

// Full body received while an early stylesheet has no completion evidence.
{
  const r = observe({nodes: [style(), script()]});
  assert.equal(r.navigation.decoded_bytes, 838287);
  assert.equal(r.navigation.response_end_ms, 2746);
  assert.equal(r.navigation.dom_content_loaded_end_ms, 0);
  assert.equal(r.stylesheets_attached, 0);
  assert.equal(r.missing_nodes[0].timing, null);
  assert.equal(r.last_scanned_node.external, false);
  assert.equal(r.last_scanned_node.classic_script, true);
  passed++;
}
// Attached style and timed script; cross-origin addresses never leave the page.
{
  const foreign = 'https://other.invalid/private-token.js';
  const r = observe({nodes: [style({sheet: {}}), script({src: foreign, defer: true})],
    resources: [entry(), entry(foreign)]});
  assert.equal(r.stylesheets_attached, 1);
  assert.equal(r.external_scripts_with_timing, 1);
  assert.equal(r.last_scanned_node.same_origin, false);
  assert.equal(r.last_scanned_node.defer, true);
  assert.deepEqual(r.missing_nodes, []);
  passed++;
}
// A failed load may have timing too. Do not label responseEnd as success.
{
  const r = observe({nodes: [style()], resources: [entry()]});
  assert.equal(r.missing_nodes[0].sheet_attached, false);
  assert.equal(r.missing_nodes[0].timing.response_end_ms, 2746);
  assert.equal('complete' in r.missing_nodes[0], false);
  // Chromium can attach a parsed prefix even after a framing error. Attachment
  // alone is also only evidence, not a success/usable classification.
  const attachedPrefix = observe({nodes: [style({sheet: {}})], resources: [entry()]});
  assert.equal(attachedPrefix.stylesheets_attached, 1);
  assert.deepEqual(attachedPrefix.missing_nodes, []);
  assert.equal('usable' in attachedPrefix, false);
  passed++;
}
// Disabled/irrelevant styles are observable but not reported as unresolved.
{
  const r = observe({nodes: [style({disabled: true}), style({media: 'print'})]});
  assert.equal(r.stylesheets_observed, 2);
  assert.deepEqual(r.missing_nodes, []);
  passed++;
}
// Work and output bounds are independent of how large the page becomes.
{
  const r = observe({nodes: Array.from({length: 300}, () => style()),
    resources: Array.from({length: 1100}, (_, i) => entry('https://unused.invalid/' + i))});
  assert.equal(r.stylesheets_observed, 128);
  assert.equal(r.missing_nodes.length, 16);
  assert.equal(r.last_scanned_node.ordinal, 127);
  assert.equal(r.node_count, 300);
  assert.equal(r.resource_count, 1100);
  assert.ok(r.nodes_truncated && r.resources_truncated && r.missing_nodes_truncated);
  passed++;
}
// A single unreadable node does not discard independently collected transport data.
{
  const bad = {tagName: 'LINK', get href() { throw new Error('private-token'); }};
  const r = observe({nodes: [style({sheet: {}}), bad]});
  assert.equal(r.navigation.decoded_bytes, 838287);
  assert.deepEqual(r.last_scanned_node, {ordinal: 1, observation_unavailable: true});
  passed++;
}
// Missing / failed APIs mean unknown, not a navigation failure or zero bytes.
{
  const r = observe({navigation: null});
  assert.equal(r.navigation, null);
  const unavailable = observe({overrides: {performance: {
    getEntriesByType() { throw new Error('private-token'); },
  }}});
  assert.equal(unavailable, null);
  passed++;
}
// Preserve real zero values; nonnumeric/negative/nonfinite values are unknown.
{
  const r = observe({navigation: {
    encodedBodySize: true, decodedBodySize: Infinity, transferSize: 0,
    responseEnd: -1, domContentLoadedEventEnd: 1e30, loadEventEnd: 2.9,
  }});
  assert.deepEqual(r.navigation, {encoded_bytes: null, decoded_bytes: null,
    transfer_bytes: 0, response_end_ms: null, dom_content_loaded_end_ms: 60000,
    load_event_end_ms: 2});
  passed++;
}
console.log(JSON.stringify({cases_passed: passed}));

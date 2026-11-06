import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const {expression, browser_expression} = JSON.parse(readFileSync(0, 'utf8'));
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
  assert.ok(JSON.stringify(result).length < 16000);
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
  assert.equal(r.stylesheets_observed, 264);
  assert.equal(r.missing_nodes.length, 16);
  assert.equal(r.last_scanned_node.ordinal, 299);
  assert.equal(r.nodes_observed, 264);
  assert.deepEqual(r.tail_nodes.map(node => node.ordinal), [292, 293, 294, 295, 296, 297, 298, 299]);
  assert.equal(r.node_count, 300);
  assert.equal(r.resource_count, 1100);
  assert.ok(r.nodes_truncated && r.resources_truncated && r.missing_nodes_truncated);
  passed++;
}
// The failed Safari sample had 167 nodes; the old prefix omitted its parser tail.
{
  const nodes = Array.from({length: 167}, () => style({sheet: {}}));
  nodes[166] = style();
  const r = observe({nodes});
  assert.equal(r.nodes_observed, 167);
  assert.equal(r.nodes_truncated, false);
  assert.equal(r.stylesheets_attached, 166);
  assert.equal(r.missing_nodes.at(-1).ordinal, 166);
  assert.equal(r.tail_nodes.at(-1).sheet_attached, false);
  passed++;
}
// A large prefix of untimed async scripts must not hide an unresolved CSS tail.
{
  const nodes = Array.from({length: 300}, () => script({src: asset, async: true}));
  nodes[299] = style();
  nodes[298] = script({src: asset});
  const r = observe({nodes});
  assert.equal(r.missing_nodes[0].ordinal, 299);
  assert.equal(r.missing_nodes[1].ordinal, 298);
  assert.equal(r.missing_nodes[1].classic_script, true);
  assert.equal(r.tail_nodes.length, 8);
  assert.equal(r.nodes_truncated, true);
  assert.equal(r.missing_nodes.length, 16);
  passed++;
}
// An unobservable tail node remains explicit; it cannot become an empty tail.
{
  const nodes = Array.from({length: 600}, () => script());
  nodes[599] = {tagName: 'SCRIPT', get src() { throw new Error('private-token'); }};
  const r = observe({nodes});
  assert.deepEqual(r.tail_nodes.at(-1), {ordinal: 599, observation_unavailable: true});
  assert.equal(r.nodes_attempted, 264);
  assert.equal(r.nodes_observed, 263);
  assert.equal(r.nodes_unavailable, 1);
  assert.ok(r.nodes_truncated);
  passed++;
}
// A failed middle-node read must not claim full coverage just because the tail is healthy.
{
  const nodes = Array.from({length: 167}, () => style({sheet: {}}));
  nodes[100] = {tagName: 'LINK', get href() { throw new Error('private-token'); }};
  const r = observe({nodes});
  assert.equal(r.nodes_attempted, 167);
  assert.equal(r.nodes_observed, 166);
  assert.equal(r.nodes_unavailable, 1);
  assert.equal(r.nodes_truncated, false);
  assert.deepEqual(r.missing_nodes, []);
  assert.equal(r.tail_nodes.at(-1).sheet_attached, true);
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
// Execute the complete producer as well as its transport fragment: an extra
// top-level key used to make the strict Python consumer reject every snapshot.
const browserEvidence = [];
for (const clockUnavailable of [false, true]) {
  const content = 'Starrtoy ' + 'Product description. '.repeat(60);
  const body = {innerText: content, contains: () => false,
    getBoundingClientRect: () => ({width: 800, height: 600})};
  const context = {
    TextEncoder, URL, Map, Symbol, Uint32Array,
    document: {
      documentElement: {outerHTML: '<html><body><main>' + content + '</main></body></html>'},
      baseURI: 'https://xpersonatoy.com/', body, title: 'Starrtoy', readyState: 'complete',
      querySelector: selector => selector === 'main' ? body : null,
      querySelectorAll: () => [],
    },
    location: {origin: 'https://xpersonatoy.com', hostname: 'xpersonatoy.com',
      protocol: 'https:', pathname: '/', search: '', hash: ''},
    isSecureContext: true,
    addEventListener: () => {},
    crypto: {getRandomValues: array => array.fill(7)},
    getComputedStyle: () => ({display: 'block', visibility: 'visible', opacity: '1'}),
    performance: {
      now: () => { if (clockUnavailable) throw new Error('private-clock-error'); return 25; },
      getEntriesByType: type => type === 'navigation' ? [{...entry(),
        nextHopProtocol: 'h2', responseStart: 10, domContentLoadedEventEnd: 20}] : [],
    },
  };
  context.window = context;
  const evidence = JSON.parse(JSON.stringify(vm.runInNewContext(browser_expression, context, {timeout: 1000})));
  assert.equal(evidence.signals.sample_duration_ms, clockUnavailable ? null : 0);
  assert.equal(Object.hasOwn(evidence, 'sample_duration_ms'), false);
  assert.equal(JSON.stringify(evidence).includes('private-clock-error'), false);
  browserEvidence.push(evidence);
  passed++;
}
console.log(JSON.stringify({cases_passed: passed, browser_evidence: browserEvidence}));

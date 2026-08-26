import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const [indexPage, component, poller, stylesheet, locale] = await Promise.all([
  readFile(new URL('../../src_assets/common/assets/web/index.html', import.meta.url), 'utf8'),
  readFile(new URL('../../src_assets/common/assets/web/VddStatus.vue', import.meta.url), 'utf8'),
  readFile(new URL('../../src_assets/common/assets/web/vdd_status_poller.js', import.meta.url), 'utf8'),
  readFile(new URL('../../src_assets/common/assets/web/sunshine.css', import.meta.url), 'utf8'),
  readFile(new URL('../../src_assets/common/assets/web/public/assets/locale/en.json', import.meta.url), 'utf8'),
]);

test('Windows dashboard mounts a lifecycle-owned VDD status surface', () => {
  assert.match(indexPage, /v-if="platform === 'windows'"/);
  assert.match(component, /fetch\('\.\/api\/vdd\/status'/);
  assert.match(component, /mounted\(\)/);
  assert.match(component, /beforeUnmount\(\)/);
  assert.match(component, /visibilitychange/);
  assert.match(component, /this\.poller\?\.stop\(\)/);
  assert.match(poller, /this\.inFlight/);
  assert.match(poller, /AbortController/);
  assert.doesNotMatch(indexPage, /api\/vdd\/install/);
});

test('VDD status is a compact semantic ledger backed by every production field', () => {
  assert.match(component, /<section[^>]+aria-labelledby=/);
  assert.match(component, /<dl class="vdd-status__details">/);
  assert.match(component, /status\.installed/);
  assert.match(component, /status\.compatible/);
  assert.match(component, /status\.deviceHealthy/);
  assert.match(component, /status\.problem/);
  assert.match(component, /status\.generation/);
  assert.match(component, /mode\.hdr/);
  assert.match(component, /mode\.bitDepth/);
  assert.match(component, /status\.directFrameBound/);
  assert.match(component, /status\.quarantined/);
  assert.match(component, /status\.fallback/);
  assert.match(component, /captureUnavailable/);
  assert.match(component, /!this\.status\.directFrameBound/);
  assert.match(component, /this\.captureUnavailable\) return this\.\$t\('index\.vdd_unavailable_state'\)/);
  assert.match(component, /status\.diagnostic/);
  assert.match(component, /status\?\.deliveryPolicy/);
  assert.doesNotMatch(component, /<button/);
});

test('VDD surface reuses semantic theme tokens and narrows to one column', () => {
  const start = stylesheet.indexOf('/* Lumen Virtual Display status */');
  const end = stylesheet.indexOf('/* ==========================================================================\n   Utility Classes', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const statusStyles = stylesheet.slice(start, end);
  assert.match(statusStyles, /var\(--color-surface\)/);
  assert.match(statusStyles, /var\(--color-bg-subtle\)/);
  assert.match(statusStyles, /grid-template-columns: repeat\(3, minmax\(0, 1fr\)\)/);
  assert.match(statusStyles, /@media \(max-width: 768px\)[\s\S]*grid-template-columns: 1fr/);
  assert.doesNotMatch(statusStyles, /#[0-9a-f]{3,8}\b/i);
  assert.doesNotMatch(statusStyles, /transition:\s*all/);
});

test('English VDD labels are present and expose no raw status keys', () => {
  const messages = JSON.parse(locale).index;
  for (const key of [
    'vdd_title',
    'vdd_driver',
    'vdd_display',
    'vdd_capture',
    'vdd_direct_frames',
    'vdd_desktop_capture',
    'vdd_policy_latency',
    'vdd_policy_quality',
    'vdd_restart_required',
    'vdd_streaming_policy',
    'vdd_windows_problem',
  ]) {
    assert.equal(typeof messages[key], 'string', key);
    assert.notEqual(messages[key].length, 0, key);
  }
});

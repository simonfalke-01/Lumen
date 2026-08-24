import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const pinPage = await readFile(
  new URL('../../src_assets/common/assets/web/pin.html', import.meta.url),
  'utf8',
);

test('PIN UI lists and disambiguates pending requests', () => {
  assert.match(pinPage, /apiFetch\("\.\/api\/pin"\)/);
  assert.match(pinPage, /pendingRequests\.length > 1/);
  assert.match(pinPage, /request\.source/);
  assert.match(pinPage, /request\.clientFingerprint/);
  assert.match(pinPage, /request\.ageSeconds/);
  assert.match(pinPage, /<select[^>]+required>/);
  assert.match(pinPage, /requests\.length > 1 && !previouslyHadMultipleRequests/);
});

test('PIN UI preserves the single-request flow and submits its request ID', () => {
  assert.match(pinPage, /requests\.length === 1/);
  assert.match(pinPage, /this\.selectedRequestId = requests\[0\]\.requestId/);
  assert.match(pinPage, /requestId: this\.selectedRequestId/);
  assert.match(pinPage, /:disabled="!selectedRequestId"/);
});

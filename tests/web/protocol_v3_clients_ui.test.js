import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const clientsPage = await readFile(
  new URL('../../src_assets/common/assets/web/clients.html', import.meta.url),
  'utf8',
);
const viteConfig = await readFile(new URL('../../vite.config.js', import.meta.url), 'utf8');

test('protocol-v3 clients page ships the complete invitation lifecycle', () => {
  assert.match(clientsPage, /api\/protocol-v3\/invitation/);
  assert.match(clientsPage, /drawInvitationQr/);
  assert.match(clientsPage, /issueInvitation/);
  assert.match(clientsPage, /revokeInvitation/);
  assert.match(clientsPage, /navigator\.clipboard\.writeText/);
  assert.match(clientsPage, /textarea[^>]+readonly/);
});

test('protocol-v3 clients page exposes paired-client administration without hover-only actions', () => {
  assert.match(clientsPage, /api\/protocol-v3\/clients/);
  assert.match(clientsPage, /setClientEnabled/);
  assert.match(clientsPage, /toggleClientPermission/);
  assert.match(clientsPage, /pendingRevokeId/);
  assert.match(clientsPage, /confirm_revoke/);
  assert.match(clientsPage, /form-check-input/);
});

test('clients page is a production Vite entry', () => {
  assert.match(viteConfig, /clients:\s*resolve\(assetsSrcPath, 'clients\.html'\)/);
});

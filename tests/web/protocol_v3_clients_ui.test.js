import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const clientsPage = await readFile(
  new URL('../../src_assets/common/assets/web/clients.html', import.meta.url),
  'utf8',
);
const networkConfig = await readFile(
  new URL('../../src_assets/common/assets/web/configs/tabs/Network.vue', import.meta.url),
  'utf8',
);
const clientState = await readFile(
  new URL('../../src_assets/common/assets/web/protocol_v3_client_state.js', import.meta.url),
  'utf8',
);
const englishLocale = JSON.parse(await readFile(
  new URL('../../src_assets/common/assets/web/public/assets/locale/en.json', import.meta.url),
  'utf8',
));
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
  assert.match(clientsPage, /setClientPermission/);
  assert.match(clientsPage, /pendingRevokeId/);
  assert.match(clientsPage, /confirm_revoke/);
  assert.match(clientsPage, /form-check-input/);
});

test('permission controls model effective loading, error, and authorization state', () => {
  assert.match(clientsPage, /allowedPermissions: null/);
  assert.match(clientsPage, /permissionPolicyLoading: true/);
  assert.match(clientsPage, /permissionPolicyError: ''/);
  assert.match(clientsPage, /clientPermissionDisabled/);
  assert.match(clientsPage, /clientActionError/);
  assert.match(clientsPage, /permissionsValid/);
  assert.match(clientsPage, /role="status"/);
  assert.match(clientsPage, /clientMutationPending/);
  assert.match(clientsPage, /response\.status === 401 \|\| response\.status === 403/);
  assert.doesNotMatch(clientsPage, /approvedPermissions \|\| 0x17/);
  assert.match(englishLocale.clients.permission_policy_unavailable, /remain disabled/);
});

test('permission mutations are immediate, rollback-safe, and preserve host policy', () => {
  const optimisticUpdate = clientState.indexOf('Object.assign(client, patch)');
  const request = clientState.indexOf('await request(patch)');
  const rollback = clientState.indexOf('Object.assign(client, previous)');
  assert.ok(optimisticUpdate >= 0 && optimisticUpdate < request);
  assert.ok(rollback > request);
  assert.match(clientsPage, /\$event\.target\.checked/);
  assert.match(clientsPage, /permissionPolicyRestricted/);
  assert.match(clientsPage, /buildClientPermissionUpdate/);
  assert.match(clientsPage, /isCurrentClientRefresh/);
  assert.match(clientsPage, /revokeProtocolV3Invitation/);
  assert.match(clientsPage, /clients\.permission_policy_configure/);
  assert.match(englishLocale.clients.permission_policy_configure, /Network configuration/);
});

test('Network configuration uses writable models for both optional permission bits', () => {
  assert.match(networkConfig, /protocolV3MicrophonePermission = protocolV3PermissionModel\(3\)/);
  assert.match(networkConfig, /protocolV3QuitPermission = protocolV3PermissionModel\(5\)/);
  assert.match(networkConfig, /v-model="protocolV3MicrophonePermission"/);
  assert.match(networkConfig, /v-model="protocolV3QuitPermission"/);
  assert.doesNotMatch(networkConfig, /\^ \(1 << bit\)/);
});

test('clients page is a production Vite entry', () => {
  assert.match(viteConfig, /clients:\s*resolve\(assetsSrcPath, 'clients\.html'\)/);
});

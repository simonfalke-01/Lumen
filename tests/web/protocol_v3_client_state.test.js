import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildClientPermissionUpdate,
  isCurrentClientRefresh,
  normalizeProtocolV3Client,
  persistOptimisticClientPatch,
  protocolV3AdminErrorKey,
  revokeProtocolV3Invitation,
} from '../../src_assets/common/assets/web/protocol_v3_client_state.js';

test('normalizes client API masks and fails closed on invalid permissions', () => {
  assert.deepEqual(normalizeProtocolV3Client({ clientId: 'valid', permissions: '63' }), {
    clientId: 'valid',
    permissions: 63,
    permissionsValid: true,
    pending: false,
  });
  assert.deepEqual(normalizeProtocolV3Client({ clientId: 'invalid', permissions: null }), {
    clientId: 'invalid',
    permissions: 0,
    permissionsValid: false,
    pending: false,
  });
  assert.equal(normalizeProtocolV3Client({ permissions: 0xff }).permissionsValid, false);
  assert.equal(normalizeProtocolV3Client({ permissions: 0x40 }).permissionsValid, false);
  assert.equal(normalizeProtocolV3Client({ permissions: 0 }).permissionsValid, false);
});

test('atomically clamps persisted grants when the host ceiling is lowered', () => {
  assert.deepEqual(buildClientPermissionUpdate(0x3f, 0x17, 3, false), { permissions: 0x17, error: null });
  assert.deepEqual(buildClientPermissionUpdate(0x3f, 0x17, 5, false), { permissions: 0x17, error: null });
  assert.deepEqual(buildClientPermissionUpdate(0x17, 0x1f, 3, true), { permissions: 0x1f, error: null });
  assert.deepEqual(buildClientPermissionUpdate(0x17, 0x17, 3, true), { permissions: null, error: 'unauthorized' });
  assert.deepEqual(buildClientPermissionUpdate(null, 0x3f, 3, false), { permissions: null, error: 'invalid' });
  assert.deepEqual(buildClientPermissionUpdate(0x3f, undefined, 3, false), { permissions: null, error: 'invalid' });
  assert.deepEqual(buildClientPermissionUpdate(0x01, 0x17, 0, false), { permissions: null, error: 'empty' });
  assert.deepEqual(buildClientPermissionUpdate(0x08, 0x17, 3, false), { permissions: null, error: 'empty' });
});

test('maps both authorization statuses to the specific localized error key', () => {
  assert.equal(protocolV3AdminErrorKey(401), 'clients.admin_unauthorized');
  assert.equal(protocolV3AdminErrorKey(403), 'clients.admin_unauthorized');
  assert.equal(protocolV3AdminErrorKey(500), 'clients.request_failed');
});

test('invitation DELETE requires explicit status true before callers clear state', async () => {
  const rejectionError = new Error('invitation remains active');
  await assert.rejects(
    revokeProtocolV3Invitation(async () => ({ status: false }), rejectionError),
    rejectionError,
  );
  assert.deepEqual(await revokeProtocolV3Invitation(async () => ({ status: true }), rejectionError), { status: true });
});

test('optimistic API mutation remains visible and commits status true', async () => {
  const client = { permissions: 0x17, pending: false };
  let resolveRequest;
  const request = new Promise(resolve => { resolveRequest = resolve; });
  const mutation = persistOptimisticClientPatch(
    client,
    { permissions: 0x1f },
    () => request,
    new Error('rejected'),
  );
  assert.deepEqual(client, { permissions: 0x1f, pending: true });
  resolveRequest({ status: true });
  assert.deepEqual(await mutation, { status: true });
  assert.deepEqual(client, { permissions: 0x1f, pending: false });
});

test('HTTP 200 status false and request errors both roll back optimistic state', async () => {
  const rejected = { enabled: true, pending: false };
  const rejectionError = new Error('host rejected update');
  await assert.rejects(
    persistOptimisticClientPatch(rejected, { enabled: false }, async () => ({ status: false }), rejectionError),
    rejectionError,
  );
  assert.deepEqual(rejected, { enabled: true, pending: false });

  const malformed = { enabled: true, pending: false };
  await assert.rejects(
    persistOptimisticClientPatch(malformed, { enabled: false }, async () => null, rejectionError),
    rejectionError,
  );
  assert.deepEqual(malformed, { enabled: true, pending: false });

  const missing = { enabled: true, pending: false };
  await assert.rejects(
    persistOptimisticClientPatch(missing, { enabled: false }, async () => undefined, rejectionError),
    rejectionError,
  );
  assert.deepEqual(missing, { enabled: true, pending: false });

  const failed = { permissions: 0x17, pending: false };
  await assert.rejects(
    persistOptimisticClientPatch(failed, { permissions: 0x1f }, async () => { throw new Error('offline'); }, rejectionError),
    /offline/,
  );
  assert.deepEqual(failed, { permissions: 0x17, pending: false });
});

test('refresh results apply only when no row mutation advanced the revision', () => {
  assert.equal(isCurrentClientRefresh(4, 4), true);
  assert.equal(isCurrentClientRefresh(4, 5), false);
});

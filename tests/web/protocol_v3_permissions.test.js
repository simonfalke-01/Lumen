import assert from 'node:assert/strict';
import test from 'node:test';

import {
  hasProtocolV3Permission,
  normalizeInvitationPermissionMask,
  normalizeProtocolV3PermissionMask,
  PROTOCOL_V3_DEFINED_PERMISSION_MASK,
  PROTOCOL_V3_REQUIRED_PERMISSION_MASK,
  setProtocolV3Permission,
} from '../../src_assets/common/assets/web/protocol_v3_permissions.js';

test('normalizes API and configuration permission masks to defined bits', () => {
  assert.equal(normalizeProtocolV3PermissionMask('63'), PROTOCOL_V3_DEFINED_PERMISSION_MASK);
  assert.equal(normalizeProtocolV3PermissionMask(255), PROTOCOL_V3_DEFINED_PERMISSION_MASK);
  assert.equal(normalizeProtocolV3PermissionMask(null), null);
  assert.equal(normalizeProtocolV3PermissionMask(undefined), null);
  assert.equal(normalizeProtocolV3PermissionMask(''), null);
  assert.equal(normalizeProtocolV3PermissionMask(Number.NaN), null);
  assert.equal(normalizeProtocolV3PermissionMask(-1), null);
  assert.equal(normalizeProtocolV3PermissionMask(1.5), null);
});

test('tests permissions without treating invalid API state as authorized', () => {
  assert.equal(hasProtocolV3Permission(0x08, 3), true);
  assert.equal(hasProtocolV3Permission(0, 3), false);
  assert.equal(hasProtocolV3Permission('invalid', 3), false);
});

test('normalizes invitation masks with mandatory permissions intact', () => {
  assert.equal(normalizeInvitationPermissionMask(undefined), PROTOCOL_V3_REQUIRED_PERMISSION_MASK);
  assert.equal(normalizeInvitationPermissionMask(0x28), PROTOCOL_V3_DEFINED_PERMISSION_MASK);
  assert.equal(normalizeInvitationPermissionMask(0), PROTOCOL_V3_REQUIRED_PERMISSION_MASK);
});

test('sets optional permissions immediately while preserving required bits', () => {
  const microphone = setProtocolV3Permission(
    PROTOCOL_V3_REQUIRED_PERMISSION_MASK,
    3,
    true,
    PROTOCOL_V3_REQUIRED_PERMISSION_MASK,
  );
  assert.equal(microphone, 0x1f);
  assert.equal(
    setProtocolV3Permission(microphone, 3, false, PROTOCOL_V3_REQUIRED_PERMISSION_MASK),
    PROTOCOL_V3_REQUIRED_PERMISSION_MASK,
  );
  assert.equal(setProtocolV3Permission('invalid', 5, true), 0x20);
  assert.equal(setProtocolV3Permission(0xff, 5, false), 0x1f);
});

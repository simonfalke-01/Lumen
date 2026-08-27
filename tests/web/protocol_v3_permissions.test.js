import assert from 'node:assert/strict';
import test from 'node:test';

import {
  hasProtocolV3Permission,
  normalizeConfiguredInvitationPermissionMask,
  normalizeInvitationPermissionMask,
  normalizeProtocolV3ConfigPermissionMask,
  normalizeProtocolV3PermissionMask,
  PROTOCOL_V3_DEFINED_PERMISSION_MASK,
  PROTOCOL_V3_REQUIRED_PERMISSION_MASK,
  setProtocolV3Permission,
} from '../../src_assets/common/assets/web/protocol_v3_permissions.js';

test('normalizes API and configuration permission masks to defined bits', () => {
  assert.equal(normalizeProtocolV3PermissionMask('63'), PROTOCOL_V3_DEFINED_PERMISSION_MASK);
  assert.equal(normalizeProtocolV3PermissionMask(0xff), null);
  assert.equal(normalizeProtocolV3PermissionMask(0x40), null);
  assert.equal(normalizeProtocolV3PermissionMask(null), null);
  assert.equal(normalizeProtocolV3PermissionMask(undefined), null);
  assert.equal(normalizeProtocolV3PermissionMask(''), null);
  assert.equal(normalizeProtocolV3PermissionMask(Number.NaN), null);
  assert.equal(normalizeProtocolV3PermissionMask(-1), null);
  assert.equal(normalizeProtocolV3PermissionMask(1.5), null);
});

test('normalizes raw configuration bytes separately from strict client masks', () => {
  assert.equal(normalizeProtocolV3ConfigPermissionMask('255'), PROTOCOL_V3_DEFINED_PERMISSION_MASK);
  assert.equal(normalizeProtocolV3ConfigPermissionMask(0x40), 0);
  assert.equal(normalizeProtocolV3ConfigPermissionMask(null), null);
  assert.equal(normalizeProtocolV3ConfigPermissionMask(undefined), null);
  assert.equal(normalizeProtocolV3ConfigPermissionMask(''), null);
  assert.equal(normalizeProtocolV3ConfigPermissionMask(-1), null);
  assert.equal(normalizeProtocolV3ConfigPermissionMask(1.5), null);
  assert.equal(normalizeProtocolV3ConfigPermissionMask(0x100), null);
  assert.equal(normalizeConfiguredInvitationPermissionMask('255'), PROTOCOL_V3_DEFINED_PERMISSION_MASK);
  assert.equal(normalizeConfiguredInvitationPermissionMask(0x40), PROTOCOL_V3_REQUIRED_PERMISSION_MASK);
  assert.equal(normalizeConfiguredInvitationPermissionMask(undefined), PROTOCOL_V3_REQUIRED_PERMISSION_MASK);
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
  assert.equal(setProtocolV3Permission('invalid', 5, true), null);
  assert.equal(setProtocolV3Permission(0xff, 5, false), null);
});

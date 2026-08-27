/** Required browse, start, input, and stop permissions for every invitation. */
export const PROTOCOL_V3_REQUIRED_PERMISSION_MASK = 0x17

/** All protocol-v3 permissions currently defined by the host. */
export const PROTOCOL_V3_DEFINED_PERMISSION_MASK = 0x3f

/**
 * Normalize a permission-mask value received from configuration or an API.
 *
 * @param {unknown} value Candidate numeric permission mask.
 * @returns {number|null} A bounded mask, or `null` when the value is invalid.
 */
export function normalizeProtocolV3PermissionMask(value) {
  if (value === null || value === undefined || value === '') return null
  const mask = Number(value)
  if (!Number.isSafeInteger(mask) || mask < 0) return null
  if (mask > PROTOCOL_V3_DEFINED_PERMISSION_MASK) return null
  return mask
}

/**
 * Normalize a raw one-byte permission value accepted by host configuration.
 *
 * Configuration parsing accepts values through 255 and masks undefined bits,
 * unlike strict client/admin API masks which must already contain defined bits only.
 *
 * @param {unknown} value Candidate raw configuration permission mask.
 * @returns {number|null} Effective defined permission bits, or `null` when invalid.
 */
export function normalizeProtocolV3ConfigPermissionMask(value) {
  if (value === null || value === undefined || value === '') return null
  const mask = Number(value)
  if (!Number.isSafeInteger(mask) || mask < 0 || mask > 0xff) return null
  return mask & PROTOCOL_V3_DEFINED_PERMISSION_MASK
}

/**
 * Test whether a protocol-v3 permission mask contains a bit.
 *
 * @param {unknown} mask Candidate permission mask.
 * @param {number} bit Zero-based permission bit.
 * @returns {boolean} Whether the normalized mask contains the permission.
 */
export function hasProtocolV3Permission(mask, bit) {
  const normalized = normalizeProtocolV3PermissionMask(mask)
  return normalized !== null && (normalized & (1 << bit)) !== 0
}

/**
 * Return an invitation mask with every mandatory permission restored.
 *
 * @param {unknown} mask Candidate invitation permission mask.
 * @returns {number} A valid invitation permission mask.
 */
export function normalizeInvitationPermissionMask(mask) {
  const normalized = normalizeProtocolV3PermissionMask(mask)
  return (normalized ?? PROTOCOL_V3_REQUIRED_PERMISSION_MASK) | PROTOCOL_V3_REQUIRED_PERMISSION_MASK
}

/**
 * Return an effective configured invitation mask with mandatory bits restored.
 *
 * @param {unknown} mask Raw configuration permission mask.
 * @returns {number} Effective configured invitation mask.
 */
export function normalizeConfiguredInvitationPermissionMask(mask) {
  const normalized = normalizeProtocolV3ConfigPermissionMask(mask)
  return (normalized ?? PROTOCOL_V3_REQUIRED_PERMISSION_MASK) | PROTOCOL_V3_REQUIRED_PERMISSION_MASK
}

/**
 * Set one protocol-v3 permission while preserving any required permissions.
 *
 * @param {unknown} mask Current permission mask.
 * @param {number} bit Zero-based permission bit to change.
 * @param {boolean} enabled Desired permission state.
 * @param {number} requiredMask Permissions that cannot be cleared.
 * @returns {number|null} The updated bounded permission mask, or `null` for invalid state.
 */
export function setProtocolV3Permission(mask, bit, enabled, requiredMask = 0) {
  const normalized = normalizeProtocolV3PermissionMask(mask)
  if (normalized === null) return null
  const permission = 1 << bit
  const updated = enabled ? normalized | permission : normalized & ~permission
  return (updated | requiredMask) & PROTOCOL_V3_DEFINED_PERMISSION_MASK
}

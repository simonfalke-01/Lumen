/** Every permission bit defined by LSP wire version 1. */
export const LSP_DEFINED_PERMISSION_MASK = 0xff

/**
 * Normalize an LSP permission mask received from configuration or the admin API.
 *
 * @param {unknown} value Candidate permission mask.
 * @returns {number|null} A defined LSP/1 mask, or `null` when invalid.
 */
export function normalizeLspPermissionMask(value) {
  if (value === null || value === undefined || value === '') return null
  const mask = Number(value)
  if (!Number.isSafeInteger(mask) || mask < 0 || mask > LSP_DEFINED_PERMISSION_MASK) return null
  return mask
}

/**
 * Test whether a validated LSP permission mask contains one permission bit.
 *
 * @param {unknown} mask Candidate permission mask.
 * @param {number} bit Zero-based LSP/1 permission bit.
 * @returns {boolean} Whether the permission is granted.
 */
export function hasLspPermission(mask, bit) {
  const normalized = normalizeLspPermissionMask(mask)
  return normalized !== null && (normalized & (1 << bit)) !== 0
}

/**
 * Build a nonempty LSP trusted-client permission update.
 *
 * @param {unknown} currentMask Current trusted-client permission mask.
 * @param {number} bit Zero-based LSP/1 permission bit.
 * @param {boolean} enabled Desired permission state.
 * @returns {{permissions: number|null, error: string|null}} Valid update or a stable error kind.
 */
export function buildLspPermissionUpdate(currentMask, bit, enabled) {
  const current = normalizeLspPermissionMask(currentMask)
  if (current === null || bit < 0 || bit > 7) return { permissions: null, error: 'invalid' }
  const permission = 1 << bit
  const permissions = enabled ? current | permission : current & ~permission
  if (permissions === 0) return { permissions: null, error: 'empty' }
  return { permissions, error: null }
}

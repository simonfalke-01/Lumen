import {
  normalizeProtocolV3PermissionMask,
  setProtocolV3Permission,
} from './protocol_v3_permissions.js'

/**
 * Normalize one paired-client record received from the admin API.
 *
 * @param {object} client Raw API client record.
 * @returns {object} UI record with explicit validity and pending state.
 */
export function normalizeProtocolV3Client(client) {
  const permissions = normalizeProtocolV3PermissionMask(client.permissions)
  return {
    ...client,
    permissions: permissions ?? 0,
    permissionsValid: permissions !== null && permissions !== 0,
    pending: false,
  }
}

/**
 * Build a fail-closed permission update within the host's effective ceiling.
 *
 * Existing grants above a lowered ceiling are removed atomically before the
 * requested bit is changed.
 *
 * @param {unknown} currentPermissions Persisted client permission mask.
 * @param {unknown} allowedPermissions Effective host permission ceiling.
 * @param {number} bit Zero-based permission bit being changed.
 * @param {boolean} enabled Desired permission state.
 * @returns {{permissions: number|null, error: string|null}} Bounded update result.
 */
export function buildClientPermissionUpdate(currentPermissions, allowedPermissions, bit, enabled) {
  const current = normalizeProtocolV3PermissionMask(currentPermissions)
  const allowed = normalizeProtocolV3PermissionMask(allowedPermissions)
  if (current === null || allowed === null) return { permissions: null, error: 'invalid' }
  if (enabled && (allowed & (1 << bit)) === 0) return { permissions: null, error: 'unauthorized' }
  const permissions = setProtocolV3Permission(current & allowed, bit, enabled)
  if (permissions === 0) return { permissions: null, error: 'empty' }
  return { permissions, error: null }
}

/**
 * Select the localized admin API error key for an HTTP status.
 *
 * @param {number} status HTTP response status.
 * @returns {string} Translation key for the visible error.
 */
export function protocolV3AdminErrorKey(status) {
  return status === 401 || status === 403 ? 'clients.admin_unauthorized' : 'clients.request_failed'
}

/**
 * Revoke an invitation only when the API confirms the mutation.
 *
 * @param {() => Promise<object>} request Invitation DELETE callback.
 * @param {Error} rejectionError Localized error for HTTP 200 `status:false`.
 * @returns {Promise<object>} Successful API result.
 */
export async function revokeProtocolV3Invitation(request, rejectionError) {
  const result = await request()
  if (!result?.status) throw rejectionError
  return result
}

/**
 * Persist an optimistic row patch and restore the prior state on any rejection.
 *
 * @param {object} client Mutable paired-client UI record.
 * @param {object} patch Optimistic fields sent to the API.
 * @param {(patch: object) => Promise<object>} request API request callback.
 * @param {Error} rejectionError Localized error used for HTTP 200 `status:false`.
 * @returns {Promise<object>} Successful API result.
 */
export async function persistOptimisticClientPatch(client, patch, request, rejectionError) {
  const previous = Object.fromEntries(Object.keys(patch).map(key => [key, client[key]]))
  Object.assign(client, patch)
  client.pending = true
  try {
    const result = await request(patch)
    if (!result?.status) throw rejectionError
    client.pending = false
    return result
  } catch (error) {
    Object.assign(client, previous)
    client.pending = false
    throw error
  }
}

/**
 * Test whether a refresh result predates a row mutation.
 *
 * @param {number} refreshRevision Mutation revision captured before refresh.
 * @param {number} currentRevision Current mutation revision.
 * @returns {boolean} Whether the refresh result may replace the client rows.
 */
export function isCurrentClientRefresh(refreshRevision, currentRevision) {
  return refreshRevision === currentRevision
}

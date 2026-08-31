import { normalizeLspPermissionMask } from './lsp_permissions.js'

/**
 * Normalize one trusted-client record received from the LSP admin API.
 *
 * @param {object} client Raw API client record.
 * @returns {object|null} Safe mutable UI record, or `null` for malformed input.
 */
export function normalizeLspClient(client) {
  const permissions = normalizeLspPermissionMask(client?.permissions)
  const clientId = typeof client?.clientId === 'string' && /^[0-9a-f]{32}$/.test(client.clientId)
    ? client.clientId
    : null
  const generation = Number(client?.revocationGeneration)
  if (clientId === null || permissions === null || permissions === 0 ||
      !Number.isSafeInteger(generation) || generation <= 0 || typeof client?.enabled !== 'boolean') {
    return null
  }
  return {
    clientId,
    permissions,
    revocationGeneration: generation,
    enabled: client.enabled,
    pending: false,
  }
}

/**
 * Select a visible localized error key for an LSP administration response.
 *
 * @param {number} status HTTP status code.
 * @returns {string} Translation key for the actionable error.
 */
export function lspAdminErrorKey(status) {
  if (status === 401 || status === 403) return 'lsp_clients.admin_unauthorized'
  if (status === 503) return 'lsp_clients.runtime_unavailable'
  if (status === 404) return 'lsp_clients.client_not_found'
  return 'lsp_clients.request_failed'
}

/**
 * Persist an optimistic client update and restore the exact prior state on failure.
 *
 * @param {object} client Mutable trusted-client UI record.
 * @param {object} patch Optimistic enabled/permission fields.
 * @param {(patch: object) => Promise<object>} request Admin API request callback.
 * @param {Error} rejectionError Error used when the API reports no mutation.
 * @returns {Promise<object>} Confirmed API result.
 */
export async function persistLspClientPatch(client, patch, request, rejectionError) {
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
 * Test whether a client-list refresh predates an in-flight mutation.
 *
 * @param {number} refreshRevision Revision captured before the request.
 * @param {number} currentRevision Current local mutation revision.
 * @returns {boolean} Whether the refresh may replace the visible collection.
 */
export function isCurrentLspClientRefresh(refreshRevision, currentRevision) {
  return refreshRevision === currentRevision
}

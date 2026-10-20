/**
 * Typed client for Lumen's administration API (`/api/v1`).
 *
 * Authentication is a session cookie set by `POST /api/v1/session`. Every request also sends
 * `X-Lumen-Request: 1`; the server rejects state-changing requests without it, which a
 * cross-site form or image request cannot add.
 */

export type Protocol = 'lsp' | 'gamestream'

/** Device permissions granted by pairing; GameStream devices have no permission model. */
export type Permission =
  | 'browse'
  | 'start'
  | 'input'
  | 'microphone'
  | 'stop'
  | 'quit'
  | 'controller-output'
  | 'clipboard'

export interface Session {
  username: string
}

export interface Status {
  hostName: string
  version: string
  lsp: { enabled: boolean; listening: boolean; port: number }
  stream: { appName: string; startedAt: number | null } | null
  restartRequired: boolean
}

export interface PairingRequest {
  id: string
  deviceName: string
  /** False when the name comes from the network and has not been verified by PIN. */
  nameVerified: boolean
  fingerprint: string
  permissions: Permission[]
  expiresAt: number
  state: 'awaiting-pin' | 'verifying' | 'ready' | 'cooldown'
}

export interface Device {
  id: string
  protocol: Protocol
  name: string
  enabled: boolean
  permissions: Permission[] | null
}

export type AppKind = 'desktop' | 'steam' | 'app'

export interface PrepCommand {
  do: string
  undo: string
  elevated: boolean
}

export interface App {
  id: string
  name: string
  kind: AppKind
  command: string
  workingDirectory: string
  hasImage: boolean
  prepCommands: PrepCommand[]
  detachedCommands: string[]
  elevated: boolean
  autoDetach: boolean
  waitAll: boolean
  exitTimeoutSeconds: number
  excludeGlobalPrepCommands: boolean
  running: boolean
}

export type AppInput = Omit<App, 'id' | 'kind' | 'hasImage' | 'running'>

export type SettingValue = string | number | boolean

export interface Settings {
  values: Record<string, SettingValue>
  defaults: Record<string, SettingValue>
}

export interface LogChunk {
  text: string
  next: number
}

/** A failed request, with the server's message when it sent one. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
  }
}

async function request<T>(method: string, path: string, body?: unknown, contentType = 'application/json'): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api/v1${path}`, {
      method,
      credentials: 'same-origin',
      headers: {
        'X-Lumen-Request': '1',
        ...(body === undefined ? {} : { 'Content-Type': contentType }),
      },
      body: body === undefined ? undefined : contentType === 'application/json' ? JSON.stringify(body) : (body as BodyInit),
    })
  } catch {
    throw new ApiError(0, 'Lumen isn’t responding.')
  }
  if (response.status === 204) {
    return undefined as T
  }
  const text = await response.text()
  const json = text ? (JSON.parse(text) as unknown) : undefined
  if (!response.ok) {
    const message =
      json && typeof json === 'object' && 'error' in json && typeof json.error === 'string'
        ? json.error
        : `Request failed (${response.status}).`
    throw new ApiError(response.status, message)
  }
  return json as T
}

export const api = {
  session: () => request<Session>('GET', '/session'),
  signIn: (username: string, password: string) => request<Session>('POST', '/session', { username, password }),
  signOut: () => request<void>('DELETE', '/session'),
  setupRequired: () => request<{ required: boolean }>('GET', '/setup'),
  setup: (username: string, password: string) => request<Session>('POST', '/setup', { username, password }),
  changeCredentials: (currentPassword: string, username: string, password: string) =>
    request<void>('PUT', '/account', { currentPassword, username, password }),

  status: () => request<Status>('GET', '/status'),
  stopStream: () => request<void>('POST', '/stream/stop'),
  restart: () => request<void>('POST', '/restart'),

  pairingRequests: () => request<{ requests: PairingRequest[] }>('GET', '/pairing'),
  /** The PIN travels as a six-byte text body so the server can wipe it after use. */
  submitPairingPin: (id: string, pin: string) =>
    request<void>('POST', `/pairing/${encodeURIComponent(id)}/pin`, pin, 'text/plain'),
  rejectPairing: (id: string) => request<void>('DELETE', `/pairing/${encodeURIComponent(id)}`),
  pairGameStream: (pin: string, name: string) => request<void>('POST', '/pairing/gamestream', { pin, name }),

  devices: () => request<{ devices: Device[] }>('GET', '/devices'),
  updateDevice: (device: Device, change: Partial<Pick<Device, 'name' | 'enabled' | 'permissions'>>) =>
    request<Device>('PATCH', `/devices/${device.protocol}/${encodeURIComponent(device.id)}`, change),
  removeDevice: (device: Device) =>
    request<void>('DELETE', `/devices/${device.protocol}/${encodeURIComponent(device.id)}`),

  apps: () => request<{ apps: App[] }>('GET', '/apps'),
  createApp: (app: AppInput) => request<App>('POST', '/apps', app),
  updateApp: (id: string, app: AppInput) => request<App>('PUT', `/apps/${encodeURIComponent(id)}`, app),
  removeApp: (id: string) => request<void>('DELETE', `/apps/${encodeURIComponent(id)}`),
  setAppImage: (id: string, png: Blob) => request<void>('PUT', `/apps/${encodeURIComponent(id)}/image`, png, 'image/png'),
  removeAppImage: (id: string) => request<void>('DELETE', `/apps/${encodeURIComponent(id)}/image`),
  appImageURL: (id: string) => `/api/v1/apps/${encodeURIComponent(id)}/image`,

  settings: () => request<Settings>('GET', '/settings'),
  /** A null value resets the setting to its default. */
  updateSettings: (changes: Record<string, SettingValue | null>) =>
    request<Settings>('PATCH', '/settings', changes),

  logs: (after: number) => request<LogChunk>('GET', `/logs?after=${after}`),
  rotateIdentity: () => request<void>('POST', '/identity/rotate'),
}

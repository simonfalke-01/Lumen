/**
 * In-memory stand-in for `/api/v1`, used only by `vite dev` to render the panel without a host.
 * It is never part of a build. Data is fictional and resets when the dev server restarts.
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Plugin } from 'vite'

type Json = Record<string, unknown>

const state = {
  signedIn: false,
  hostName: 'Studio PC',
  stream: { appName: 'Desktop', startedAt: Math.floor(Date.now() / 1000) - 1260 } as Json | null,
  requests: [
    {
      id: '6f1c2a8e9b0d4e5f8a7b6c5d4e3f2a1b',
      deviceName: 'MacBook Pro',
      nameVerified: false,
      fingerprint: '9c41d2e07a3b58f6c1e9d0a4b7f3e2c8d5a6b9e0f1c2d3e4a5b6c7d8e9f0a1b2',
      permissions: ['browse', 'start', 'input', 'stop', 'controller-output', 'clipboard'],
      expiresAt: Math.floor(Date.now() / 1000) + 110,
      state: 'awaiting-pin',
    },
  ] as Json[],
  devices: [
    { id: 'a1b2c3d4e5f60718293a4b5c6d7e8f90', protocol: 'lsp', name: 'MacBook Pro', enabled: true, permissions: ['browse', 'start', 'input', 'stop', 'controller-output', 'clipboard'] },
    { id: 'b2c3d4e5f60718293a4b5c6d7e8f90a1', protocol: 'lsp', name: 'Living room Mac mini', enabled: false, permissions: ['browse', 'start', 'input', 'stop'] },
    { id: 'C7F3A9E2-1B4D-4E8A-9C6F-2D5B8A1E4F70', protocol: 'gamestream', name: 'Steam Deck', enabled: true, permissions: null },
  ] as Json[],
  apps: [
    { id: '1', name: 'Desktop', kind: 'desktop', command: '', workingDirectory: '', hasImage: false, prepCommands: [], detachedCommands: [], elevated: false, autoDetach: true, waitAll: true, exitTimeoutSeconds: 5, excludeGlobalPrepCommands: false, running: true },
    { id: '2', name: 'Steam Big Picture', kind: 'steam', command: 'steam://open/bigpicture', workingDirectory: '', hasImage: false, prepCommands: [{ do: '', undo: 'steam://close/bigpicture', elevated: false }], detachedCommands: [], elevated: false, autoDetach: true, waitAll: true, exitTimeoutSeconds: 5, excludeGlobalPrepCommands: false, running: false },
    { id: '3', name: 'Blender', kind: 'app', command: '"C:\\Program Files\\Blender Foundation\\Blender 4.2\\blender.exe"', workingDirectory: '', hasImage: false, prepCommands: [], detachedCommands: [], elevated: false, autoDetach: true, waitAll: true, exitTimeoutSeconds: 5, excludeGlobalPrepCommands: false, running: false },
  ] as Json[],
  settings: {
    host_name: 'Studio PC', lsp_enabled: true, lsp_port: 48030, lsp_profile: 'adaptive-low-latency', lsp_competition_capacity_mbps: 0,
    encoder: 'nvenc', port: 47989, upnp: false, origin_web_ui_allowed: 'lan', audio_sink: '', client_microphone: true,
    client_microphone_sink: 'steam', lumen_vdd_policy: 'disabled', min_log_level: 'info', nvenc_preset: 1, max_bitrate: 0,
  } as Json,
  defaults: {
    host_name: '', system_tray: true, min_log_level: 'info', lsp_enabled: true, lsp_port: 48030, lsp_profile: 'adaptive-low-latency',
    lsp_competition_capacity_mbps: 0, port: 47989, address_family: 'ipv4', bind_address: '', upnp: false, external_ip: '',
    origin_web_ui_allowed: 'lan', encoder: '', adapter_name: '', output_name: '', max_bitrate: 0, minimum_fps_target: 0,
    lumen_vdd_policy: 'optional', dd_configuration_option: 'disabled', dd_resolution_option: 'auto', dd_refresh_rate_option: 'auto',
    dd_hdr_option: 'auto', nvenc_preset: 1, nvenc_twopass: 'quarter_res', nvenc_spatial_aq: false, nvenc_latency_over_power: true,
    stream_audio: true, audio_sink: '', virtual_sink: '', client_microphone: false, client_microphone_sink: 'steam', keyboard: true,
    mouse: true, controller: true, gamepad_backend: 'auto', high_resolution_scrolling: true, native_pen_touch: true,
    key_rightalt_to_key_win: false, fps: '[10,30,60,90,120]', qp: 28,
  } as Json,
  nextLog: 0,
  restartRequired: false,
  restartingUntil: 0,
}

const logLines = [
  'Info: Lumen version: 0.1.0-alpha.2',
  'Info: LSP listening on UDP port 48030',
  'Info: Registered Lumen mDNS service',
  'Warning: config: unknown nvenc_twopass value: half',
  'Info: Clipboard sharing active for the stream owner',
  'Error: Couldn’t open the audio device: device unavailable',
]

function send(response: ServerResponse, status: number, body?: unknown) {
  response.statusCode = status
  if (body === undefined) {
    response.end()
    return
  }
  response.setHeader('Content-Type', 'application/json')
  response.end(JSON.stringify(body))
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of request) chunks.push(chunk as Buffer)
  return Buffer.concat(chunks).toString('utf8')
}

export function devApi(): Plugin {
  return {
    name: 'lumen-dev-api',
    configureServer(server) {
      server.middlewares.use(async (request, response, next) => {
        const url = new URL(request.url ?? '/', 'http://localhost')
        if (!url.pathname.startsWith('/api/v1/')) return next()
        const path = url.pathname.slice('/api/v1'.length)
        const method = request.method ?? 'GET'
        const body = method === 'GET' ? '' : await readBody(request)
        const json = (): Json => (body ? (JSON.parse(body) as Json) : {})
        await new Promise((resolve) => setTimeout(resolve, 120))

        if (path === '/setup') return send(response, 200, { required: false })
        if (path === '/session' && method === 'POST') {
          const { username, password } = json()
          if (username === 'admin' && password === 'password') {
            state.signedIn = true
            return send(response, 200, { username })
          }
          return send(response, 401, { error: 'The username or password is incorrect.' })
        }
        if (path === '/session' && method === 'DELETE') {
          state.signedIn = false
          return send(response, 204)
        }
        if (Date.now() < state.restartingUntil) {
          response.destroy()
          return
        }
        if (!state.signedIn) return send(response, 401, { error: 'Sign in to continue.' })
        if (path === '/session') return send(response, 200, { username: 'admin' })

        if (path === '/status') {
          return send(response, 200, {
            hostName: state.hostName,
            version: '0.1.0-alpha.2',
            lsp: { enabled: true, listening: true, port: 48030 },
            stream: state.stream,
            restartRequired: state.restartRequired,
          })
        }
        if (path === '/stream/stop') {
          state.stream = null
          for (const app of state.apps) app.running = false
          return send(response, 204)
        }
        if (path === '/restart') {
          // Simulate the process going away for two seconds and coming back clean.
          state.restartingUntil = Date.now() + 2000
          state.restartRequired = false
          return send(response, 204)
        }
        if (path === '/pairing') return send(response, 200, { requests: state.requests })
        const pin = path.match(/^\/pairing\/([^/]+)\/pin$/)
        if (pin) {
          if (body !== '123456') return send(response, 422, { error: 'That PIN doesn’t match. Check the PIN shown on the device.' })
          const pairing = state.requests.find((entry) => entry.id === pin[1])
          state.requests = state.requests.filter((entry) => entry.id !== pin[1])
          if (pairing) state.devices.push({ id: String(pairing.id), protocol: 'lsp', name: pairing.deviceName, enabled: true, permissions: pairing.permissions })
          return send(response, 204)
        }
        const reject = path.match(/^\/pairing\/([^/]+)$/)
        if (reject && method === 'DELETE') {
          state.requests = state.requests.filter((entry) => entry.id !== reject[1])
          return send(response, 204)
        }
        if (path === '/pairing/gamestream') return send(response, 204)
        if (path === '/devices') return send(response, 200, { devices: state.devices })
        const device = path.match(/^\/devices\/(lsp|gamestream)\/([^/]+)$/)
        if (device) {
          const index = state.devices.findIndex((entry) => entry.id === device[2] && entry.protocol === device[1])
          if (index < 0) return send(response, 404, { error: 'That device no longer exists.' })
          if (method === 'DELETE') {
            state.devices.splice(index, 1)
            return send(response, 204)
          }
          state.devices[index] = { ...state.devices[index], ...json() }
          return send(response, 200, state.devices[index])
        }
        if (path === '/apps' && method === 'GET') return send(response, 200, { apps: state.apps })
        if (path === '/apps' && method === 'POST') {
          const app = { ...json(), id: String(Date.now()), kind: 'app', hasImage: false, running: false }
          state.apps.push(app)
          return send(response, 200, app)
        }
        const app = path.match(/^\/apps\/([^/]+)$/)
        if (app) {
          const index = state.apps.findIndex((entry) => entry.id === app[1])
          if (index < 0) return send(response, 404, { error: 'That app no longer exists.' })
          if (method === 'DELETE') {
            state.apps.splice(index, 1)
            return send(response, 204)
          }
          state.apps[index] = { ...state.apps[index], ...json() }
          return send(response, 200, state.apps[index])
        }
        if (path === '/settings' && method === 'GET') return send(response, 200, { values: state.settings, defaults: state.defaults })
        if (path === '/settings' && method === 'PATCH') {
          Object.assign(state.settings, json())
          state.restartRequired = true
          return send(response, 200, { values: state.settings, defaults: state.defaults })
        }
        if (path === '/logs') {
          const after = Number(url.searchParams.get('after') ?? 0)
          const lines = after === 0 ? logLines : []
          return send(response, 200, { text: lines.map((line) => `[2026-10-15 01:12:0${lines.indexOf(line)}.000]: ${line}`).join('\n'), next: after + lines.length })
        }
        if (path === '/identity/rotate') return send(response, 204)
        return send(response, 404, { error: 'Not found.' })
      })
    },
  }
}

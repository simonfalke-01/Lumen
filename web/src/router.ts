/** Minimal history router: real URLs, Back/Forward, and refresh restore the same page and tab. */
import { useSyncExternalStore } from 'react'

export type Page = '/' | '/devices' | '/apps' | '/settings' | '/logs'

export const pages: readonly { path: Page; label: string }[] = [
  { path: '/', label: 'Overview' },
  { path: '/devices', label: 'Devices' },
  { path: '/apps', label: 'Apps' },
  { path: '/settings', label: 'Settings' },
  { path: '/logs', label: 'Logs' },
]

export interface Location {
  page: Page
  /** The segment after the page, such as a settings tab; empty when absent. */
  section: string
}

function subscribe(onChange: () => void) {
  window.addEventListener('popstate', onChange)
  return () => window.removeEventListener('popstate', onChange)
}

let cachedPath = ''
let cachedLocation: Location = { page: '/', section: '' }

function currentLocation(): Location {
  const path = window.location.pathname
  if (path === cachedPath) return cachedLocation
  const [first = '', second = ''] = path.split('/').filter(Boolean)
  const page = `/${first}` as Page
  cachedPath = path
  cachedLocation = pages.some((entry) => entry.path === page) ? { page, section: second } : { page: '/', section: '' }
  return cachedLocation
}

export function useLocation(): Location {
  return useSyncExternalStore(subscribe, currentLocation)
}

/** Navigate within the panel. Tab changes replace the entry and keep the scroll position. */
export function navigate(path: string, options?: { replace?: boolean; keepScroll?: boolean }) {
  if (path === window.location.pathname) return
  if (options?.replace) window.history.replaceState(null, '', path)
  else window.history.pushState(null, '', path)
  window.dispatchEvent(new PopStateEvent('popstate'))
  if (!options?.keepScroll) window.scrollTo({ top: 0 })
}

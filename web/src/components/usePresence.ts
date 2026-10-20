import { useEffect, useState } from 'react'

export type PresenceState = 'entering' | 'open' | 'exiting'

/**
 * Keep an element mounted through its exit animation. The element animates on
 * `data-presence`; the timeout matches the exit duration token, and reduced
 * motion skips the wait entirely.
 */
export function usePresence(open: boolean, exitMs: number): { mounted: boolean; state: PresenceState } {
  const [mounted, setMounted] = useState(open)
  const [state, setState] = useState<PresenceState>(open ? 'open' : 'exiting')

  useEffect(() => {
    if (open) {
      setMounted(true)
      setState('entering')
      const frame = requestAnimationFrame(() => setState('open'))
      return () => cancelAnimationFrame(frame)
    }
    setState('exiting')
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const timer = window.setTimeout(() => setMounted(false), reduce ? 0 : exitMs)
    return () => window.clearTimeout(timer)
  }, [open, exitMs])

  return { mounted, state }
}

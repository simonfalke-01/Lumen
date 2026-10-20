import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from './api'

export interface Resource<T> {
  data: T | undefined
  /** Set when the latest load failed; earlier data stays visible as the last trustworthy state. */
  error: ApiError | undefined
  reload: () => Promise<void>
  setData: (update: (current: T | undefined) => T | undefined) => void
}

/** Loads data once, optionally polls, and never discards good data because a refresh failed. */
export function useResource<T>(load: () => Promise<T>, pollMilliseconds?: number): Resource<T> {
  const [data, setDataState] = useState<T>()
  const [error, setError] = useState<ApiError>()
  const loadRef = useRef(load)
  loadRef.current = load

  const reload = useCallback(async () => {
    try {
      setDataState(await loadRef.current())
      setError(undefined)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught : new ApiError(0, 'Something went wrong.'))
    }
  }, [])

  useEffect(() => {
    void reload()
    if (!pollMilliseconds) return
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void reload()
    }, pollMilliseconds)
    return () => window.clearInterval(timer)
  }, [reload, pollMilliseconds])

  const setData = useCallback((update: (current: T | undefined) => T | undefined) => setDataState(update), [])
  return { data, error, reload, setData }
}

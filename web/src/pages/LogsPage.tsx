import { useEffect, useMemo, useRef, useState } from 'react'
import { SearchField, Input, ToggleButton, ToggleButtonGroup } from 'react-aria-components'
import { api } from '../api'
import { InlineAlert } from '../components/ui'

type Level = 'all' | 'warning' | 'error'
const maximumLines = 5000

export function LogsPage() {
  const [lines, setLines] = useState<string[]>([])
  const [error, setError] = useState<string>()
  const [level, setLevel] = useState<Level>('all')
  const [query, setQuery] = useState('')
  const offset = useRef(0)
  const viewport = useRef<HTMLDivElement>(null)
  const pinnedToBottom = useRef(true)

  useEffect(() => {
    let cancelled = false
    const poll = async () => {
      try {
        const chunk = await api.logs(offset.current)
        if (cancelled) return
        offset.current = chunk.next
        setError(undefined)
        if (chunk.text) {
          setLines((current) => [...current, ...chunk.text.split('\n').filter(Boolean)].slice(-maximumLines))
        }
      } catch {
        if (!cancelled) setError('Couldn’t load new log lines. Retrying.')
      }
    }
    void poll()
    const timer = window.setInterval(poll, 2000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [])

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return lines.filter((line) => {
      if (level === 'error' && !/\]: (Error|Fatal):/.test(line)) return false
      if (level === 'warning' && !/\]: (Warning|Error|Fatal):/.test(line)) return false
      return !needle || line.toLowerCase().includes(needle)
    })
  }, [lines, level, query])

  // Follow new lines only while the reader is already at the bottom.
  useEffect(() => {
    const element = viewport.current
    if (element && pinnedToBottom.current) element.scrollTop = element.scrollHeight
  }, [visible])

  return (
    <div className="page">
      <header className="page__header">
        <h1 className="page__title">Logs</h1>
        <a className="link" href="/api/v1/logs/download" download="lumen.log">
          Download
        </a>
      </header>
      <div className="toolbar">
        <ToggleButtonGroup
          className="segmented"
          selectionMode="single"
          disallowEmptySelection
          selectedKeys={[level]}
          onSelectionChange={(keys) => setLevel([...keys][0] as Level)}
          aria-label="Show"
        >
          <ToggleButton id="all" className="segmented__item">All</ToggleButton>
          <ToggleButton id="warning" className="segmented__item">Warnings</ToggleButton>
          <ToggleButton id="error" className="segmented__item">Errors</ToggleButton>
        </ToggleButtonGroup>
        <SearchField className="search" aria-label="Filter logs" value={query} onChange={setQuery}>
          <Input className="input" placeholder="Filter" />
        </SearchField>
      </div>
      {error && <InlineAlert tone="warning">{error}</InlineAlert>}
      <div
        ref={viewport}
        className="log-view"
        role="log"
        aria-label="Lumen log"
        tabIndex={0}
        onScroll={(event) => {
          const element = event.currentTarget
          pinnedToBottom.current = element.scrollHeight - element.scrollTop - element.clientHeight < 24
        }}
      >
        {visible.length === 0 ? (
          <p className="quiet">{lines.length === 0 ? 'No log lines yet.' : 'No lines match.'}</p>
        ) : (
          visible.map((line, index) => (
            <div key={index} className={`log-line ${/\]: (Error|Fatal):/.test(line) ? 'log-line--error' : /\]: Warning:/.test(line) ? 'log-line--warning' : ''}`}>
              {line}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

import { ChevronDown } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Button as AriaButton, Link, Menu, MenuItem, MenuTrigger, Popover, RouterProvider } from 'react-aria-components'
import { api, type Session, type Status } from './api'
import { AccountDialog } from './pages/AccountDialog'
import { AppsPage } from './pages/AppsPage'
import { DevicesPage } from './pages/DevicesPage'
import { LogsPage } from './pages/LogsPage'
import { OverviewPage } from './pages/OverviewPage'
import { SettingsPage } from './pages/SettingsPage'
import { SignInPage } from './pages/SignInPage'
import { navigate, pages, useLocation } from './router'
import { RestartBar } from './components/RestartBar'
import { useResource } from './useResource'

type Gate = { kind: 'loading' } | { kind: 'setup' } | { kind: 'signIn' } | { kind: 'ready'; session: Session }

export function App() {
  const [gate, setGate] = useState<Gate>({ kind: 'loading' })

  const resolve = useCallback(async () => {
    try {
      if ((await api.setupRequired()).required) {
        setGate({ kind: 'setup' })
        return
      }
      setGate({ kind: 'ready', session: await api.session() })
    } catch {
      // Not signed in, or Lumen is unreachable; the sign-in page reports which on submit.
      setGate({ kind: 'signIn' })
    }
  }, [])

  useEffect(() => {
    void resolve()
  }, [resolve])

  return (
    <RouterProvider navigate={navigate}>
      {gate.kind === 'loading' ? null : gate.kind === 'ready' ? (
        <Shell session={gate.session} onSignedOut={() => setGate({ kind: 'signIn' })} />
      ) : (
        <SignInPage
          mode={gate.kind === 'setup' ? 'setup' : 'signIn'}
          onSignedIn={(session) => setGate({ kind: 'ready', session })}
        />
      )}
    </RouterProvider>
  )
}

function Shell({ session, onSignedOut }: { session: Session; onSignedOut: () => void }) {
  const location = useLocation()
  const status = useResource<Status>(api.status, 3000)
  const [accountOpen, setAccountOpen] = useState(false)
  // Later hides the bar until the next saved change; restarting holds it through the restart.
  const [restartDeferred, setRestartDeferred] = useState(false)
  const [restarting, setRestarting] = useState(false)

  useEffect(() => {
    if (restarting && status.data && !status.data.restartRequired && !status.error) setRestarting(false)
  }, [restarting, status.data, status.error])

  // Give up waiting if Lumen doesn't come back, so the offline notice can explain why.
  useEffect(() => {
    if (!restarting) return
    const timer = window.setTimeout(() => setRestarting(false), 60_000)
    return () => window.clearTimeout(timer)
  }, [restarting])

  const restart = async () => {
    setRestarting(true)
    try {
      await api.restart()
    } catch {
      setRestarting(false)
    }
  }

  const settingsChanged = async () => {
    setRestartDeferred(false)
    await status.reload()
  }

  // A 401 on any poll means the session expired; return to sign in instead of failing quietly.
  useEffect(() => {
    if (status.error?.status === 401) onSignedOut()
  }, [status.error, onSignedOut])

  const signOut = async () => {
    await api.signOut().catch(() => undefined)
    onSignedOut()
  }

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Lumen">
        <div className="sidebar__host">
          <span className="sidebar__product">Lumen</span>
          <span className="sidebar__host-name">{status.data?.hostName ?? ''}</span>
        </div>
        <ul className="sidebar__links">
          {pages.map((entry) => (
            <li key={entry.path}>
              <Link
                href={entry.path}
                className="sidebar__link"
                aria-current={location.page === entry.path ? 'page' : undefined}
              >
                {entry.label}
              </Link>
            </li>
          ))}
        </ul>
        <MenuTrigger>
          <AriaButton className="sidebar__account">
            <span>{session.username}</span>
            <ChevronDown size={14} aria-hidden />
          </AriaButton>
          <Popover className="popover" placement="top start" offset={4}>
            <Menu className="menu">
              <MenuItem className="menu__item" onAction={() => setAccountOpen(true)}>
                Change Password…
              </MenuItem>
              <MenuItem className="menu__item" onAction={() => void signOut()}>
                Sign Out
              </MenuItem>
            </Menu>
          </Popover>
        </MenuTrigger>
      </nav>

      <main className="content">
        {status.error && status.error.status !== 401 && !restarting && (
          <div className="offline-rail" role="alert">
            {status.error.message} Showing the last known state.
          </div>
        )}
        {location.page === '/' && <OverviewPage status={status} />}
        {location.page === '/devices' && <DevicesPage />}
        {location.page === '/apps' && <AppsPage />}
        {location.page === '/settings' && <SettingsPage section={location.section} onChanged={settingsChanged} />}
        {location.page === '/logs' && <LogsPage />}
        <RestartBar
          open={restarting || (!!status.data?.restartRequired && !restartDeferred)}
          restarting={restarting}
          onRestart={() => void restart()}
          onLater={() => setRestartDeferred(true)}
        />
      </main>

      <AccountDialog isOpen={accountOpen} onOpenChange={setAccountOpen} username={session.username} />
    </div>
  )
}

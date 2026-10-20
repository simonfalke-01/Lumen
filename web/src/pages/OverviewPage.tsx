import { useEffect, useState } from 'react'
import { Button as AriaButton, Disclosure, DisclosurePanel, Form, Heading } from 'react-aria-components'
import { api, ApiError, type PairingRequest, type Status } from '../api'
import { Button, ConfirmDialog, InlineAlert, TextField } from '../components/ui'
import { permissionSummary } from '../permissions'
import type { Resource } from '../useResource'
import { useResource } from '../useResource'

export function OverviewPage({ status }: { status: Resource<Status> }) {
  const pairing = useResource(api.pairingRequests, 2000)
  const requests = pairing.data?.requests ?? []

  return (
    <div className="page">
      <h1 className="page__title">Overview</h1>

      {requests.length > 0 && (
        <section className="section" aria-labelledby="pairing-heading">
          <h2 id="pairing-heading" className="section__title">
            Pairing requests
          </h2>
          <ul className="ledger">
            {requests.map((request) => (
              <PairingRequestRow key={request.id} request={request} onDone={pairing.reload} />
            ))}
          </ul>
        </section>
      )}

      {status.data && (
        <section className="section" aria-labelledby="stream-heading">
          <h2 id="stream-heading" className="section__title">
            Stream
          </h2>
          <StreamState status={status} />
        </section>
      )}

      {status.data && (
        <section className="section" aria-labelledby="host-heading">
          <h2 id="host-heading" className="section__title">
            Host
          </h2>
          <dl className="facts">
            <div>
              <dt>Lumen streaming</dt>
              <dd>
                {!status.data.lsp.enabled
                  ? 'Off'
                  : status.data.lsp.listening
                    ? `Listening on UDP ${status.data.lsp.port}`
                    : `Not listening on UDP ${status.data.lsp.port}`}
              </dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>{status.data.version}</dd>
            </div>
          </dl>
        </section>
      )}
    </div>
  )
}

function StreamState({ status }: { status: Resource<Status> }) {
  const [confirmOpen, setConfirmOpen] = useState(false)
  const stream = status.data?.stream
  const [now, setNow] = useState(() => Date.now() / 1000)

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now() / 1000), 30_000)
    return () => window.clearInterval(timer)
  }, [])

  if (!status.data) return null
  if (!stream) return <p className="quiet">Nothing is streaming.</p>

  const minutes = stream.startedAt ? Math.max(1, Math.round((now - stream.startedAt) / 60)) : null
  return (
    <div className="ledger__row">
      <div className="ledger__main">
        <span className="ledger__name">{stream.appName}</span>
        {minutes !== null && <span className="ledger__meta">{formatDuration(minutes)}</span>}
      </div>
      <Button tone="secondary" onPress={() => setConfirmOpen(true)}>
        Stop Stream
      </Button>
      <ConfirmDialog
        title={`Stop ${stream.appName}?`}
        message="The device is disconnected and the app is closed on this PC. Unsaved work in the app is lost."
        confirmLabel="Stop Stream"
        isOpen={confirmOpen}
        onOpenChange={setConfirmOpen}
        onConfirm={async () => {
          await api.stopStream()
          await status.reload()
        }}
      />
    </div>
  )
}

function formatDuration(minutes: number) {
  if (minutes < 60) return `${minutes} min`
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  return rest ? `${hours} h ${rest} min` : `${hours} h`
}

function PairingRequestRow({ request, onDone }: { request: PairingRequest; onDone: () => Promise<void> }) {
  const [pin, setPin] = useState('')
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const waiting = request.state === 'verifying'
  const coolingDown = request.state === 'cooldown'

  const submit = async () => {
    if (!/^\d{6}$/.test(pin)) {
      setError('Enter the six-digit PIN shown on the device.')
      return
    }
    setBusy(true)
    setError(undefined)
    try {
      await api.submitPairingPin(request.id, pin)
      setPin('')
      await onDone()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Pairing failed. Try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="pairing">
      <div className="pairing__identity">
        <span className="ledger__name">{request.deviceName}</span>
        {!request.nameVerified && <span className="ledger__meta">Name not yet verified</span>}
      </div>
      <Form
        className="pairing__form"
        onSubmit={(event) => {
          event.preventDefault()
          void submit()
        }}
      >
        <TextField
          label="PIN"
          value={pin}
          onChange={(value) => setPin(value.replace(/\D/g, '').slice(0, 6))}
          inputMode="numeric"
          autoComplete="one-time-code"
          placeholder="000000"
          monospace
          isDisabled={waiting || coolingDown}
        />
        <Button tone="primary" type="submit" isPending={busy || waiting} isDisabled={coolingDown}>
          Pair
        </Button>
        <Button tone="quiet" onPress={() => void api.rejectPairing(request.id).then(onDone)}>
          Reject
        </Button>
      </Form>
      {error && <InlineAlert tone="danger">{error}</InlineAlert>}
      {coolingDown && <p className="quiet">Too many attempts. Try again in a few seconds.</p>}
      <Disclosure className="disclosure">
        <Heading className="disclosure__heading">
          <AriaButton slot="trigger" className="disclosure__trigger">
            Details
          </AriaButton>
        </Heading>
        <DisclosurePanel className="disclosure__panel">
          <dl className="facts">
            <div>
              <dt>Access</dt>
              <dd>{permissionSummary(request.permissions)}</dd>
            </div>
            <div>
              <dt>Device key</dt>
              <dd className="mono">{groupFingerprint(request.fingerprint)}</dd>
            </div>
          </dl>
        </DisclosurePanel>
      </Disclosure>
    </li>
  )
}

function groupFingerprint(hex: string) {
  return (hex.toUpperCase().match(/.{1,8}/g) ?? []).join(' ')
}

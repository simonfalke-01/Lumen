import { useState } from 'react'
import { Form } from 'react-aria-components'
import { api, ApiError } from '../api'
import { Button, Dialog, InlineAlert, TextField } from '../components/ui'

export function AccountDialog({
  isOpen,
  onOpenChange,
  username,
}: {
  isOpen: boolean
  onOpenChange: (open: boolean) => void
  username: string
}) {
  const [current, setCurrent] = useState('')
  const [name, setName] = useState(username)
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const mismatch = confirmation.length > 0 && confirmation !== password
  const valid = current && name.trim() && password && !mismatch

  return (
    <Dialog title="Change Password" isOpen={isOpen} onOpenChange={onOpenChange} width="small">
      {(close) => (
        <Form
          className="dialog__form"
          onSubmit={(event) => {
            event.preventDefault()
            if (!valid) return
            setBusy(true)
            setError(undefined)
            api
              .changeCredentials(current, name.trim(), password)
              .then(() => {
                setCurrent('')
                setPassword('')
                setConfirmation('')
                close()
              })
              .catch((caught) => setError(caught instanceof ApiError ? caught.message : 'The password wasn’t changed.'))
              .finally(() => setBusy(false))
          }}
        >
          {error && <InlineAlert tone="danger">{error}</InlineAlert>}
          <TextField label="Current password" type="password" value={current} onChange={setCurrent} autoComplete="current-password" autoFocus isRequired />
          <TextField label="Username" value={name} onChange={setName} autoComplete="username" isRequired />
          <TextField label="New password" type="password" value={password} onChange={setPassword} autoComplete="new-password" isRequired />
          <TextField
            label="Confirm new password"
            type="password"
            value={confirmation}
            onChange={setConfirmation}
            autoComplete="new-password"
            isInvalid={mismatch}
            errorMessage="The passwords don’t match."
            isRequired
          />
          <footer className="dialog__actions">
            <Button tone="secondary" onPress={close}>
              Cancel
            </Button>
            <Button tone="primary" type="submit" isDisabled={!valid} isPending={busy}>
              Change Password
            </Button>
          </footer>
        </Form>
      )}
    </Dialog>
  )
}

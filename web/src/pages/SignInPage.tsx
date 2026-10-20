import { useState } from 'react'
import { Form } from 'react-aria-components'
import { api, ApiError, type Session } from '../api'
import { Button, InlineAlert, TextField } from '../components/ui'

/** Sign in, or create the administrator account on first run. */
export function SignInPage({ mode, onSignedIn }: { mode: 'signIn' | 'setup'; onSignedIn: (session: Session) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const setup = mode === 'setup'
  const mismatch = setup && confirmation.length > 0 && confirmation !== password

  const submit = async () => {
    if (mismatch) return
    setBusy(true)
    setError(undefined)
    try {
      onSignedIn(setup ? await api.setup(username, password) : await api.signIn(username, password))
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Lumen isn’t responding.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="sign-in">
      <Form
        className="sign-in__form"
        onSubmit={(event) => {
          event.preventDefault()
          void submit()
        }}
      >
        <h1 className="sign-in__title">{setup ? 'Create an administrator' : 'Sign in to Lumen'}</h1>
        {error && <InlineAlert tone="danger">{error}</InlineAlert>}
        <TextField label="Username" value={username} onChange={setUsername} autoComplete="username" isRequired autoFocus />
        <TextField
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete={setup ? 'new-password' : 'current-password'}
          isRequired
        />
        {setup && (
          <TextField
            label="Confirm password"
            type="password"
            value={confirmation}
            onChange={setConfirmation}
            autoComplete="new-password"
            isRequired
            isInvalid={mismatch}
            errorMessage="The passwords don’t match."
          />
        )}
        <Button tone="primary" type="submit" isPending={busy} isDisabled={mismatch}>
          {setup ? 'Create Account' : 'Sign In'}
        </Button>
      </Form>
    </div>
  )
}

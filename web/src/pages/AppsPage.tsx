import { Gamepad2, Monitor, MoreHorizontal, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import {
  Button as AriaButton,
  Disclosure,
  DisclosurePanel,
  FileTrigger,
  Form,
  Heading,
  Menu,
  MenuItem,
  MenuTrigger,
  Popover,
  Separator,
} from 'react-aria-components'
import { api, ApiError, type App, type AppInput, type PrepCommand } from '../api'
import { Button, ConfirmDialog, Dialog, IconButton, InlineAlert, Switch, TextField } from '../components/ui'
import { useResource } from '../useResource'

type AppDialog = { kind: 'edit'; app: App | null } | { kind: 'remove'; app: App } | null

export function AppsPage() {
  const apps = useResource(api.apps)
  const [dialog, setDialog] = useState<AppDialog>(null)
  const list = apps.data?.apps ?? []

  return (
    <div className="page">
      <header className="page__header">
        <h1 className="page__title">Apps</h1>
        <Button tone="primary" onPress={() => setDialog({ kind: 'edit', app: null })}>
          Add App…
        </Button>
      </header>

      {apps.error && !apps.data && <InlineAlert tone="danger">{apps.error.message}</InlineAlert>}
      {apps.data && list.length === 0 && <p className="quiet">No apps. Add one to make it available to your devices.</p>}

      {list.length > 0 && (
        <ul className="ledger" aria-label="Apps">
          {list.map((app) => (
            <li key={app.id} className="ledger__row">
              <AppIcon app={app} />
              <div className="ledger__main">
                <span className="ledger__name">{app.name}</span>
                {app.command && <span className="ledger__meta mono truncate">{app.command}</span>}
              </div>
              {app.running && <span className="badge badge--live">Running</span>}
              <MenuTrigger>
                <AriaButton className="icon-button" aria-label={`Actions for ${app.name}`}>
                  <MoreHorizontal size={16} aria-hidden />
                </AriaButton>
                <Popover className="popover" placement="bottom end" offset={4}>
                  <Menu className="menu">
                    <MenuItem className="menu__item" onAction={() => setDialog({ kind: 'edit', app })}>
                      Edit…
                    </MenuItem>
                    <Separator className="menu__separator" />
                    <MenuItem className="menu__item menu__item--danger" onAction={() => setDialog({ kind: 'remove', app })}>
                      Remove…
                    </MenuItem>
                  </Menu>
                </Popover>
              </MenuTrigger>
            </li>
          ))}
        </ul>
      )}

      {dialog?.kind === 'edit' && (
        <AppEditor app={dialog.app} onClose={() => setDialog(null)} onSaved={apps.reload} />
      )}
      {dialog?.kind === 'remove' && (
        <ConfirmDialog
          title={`Remove ${dialog.app.name}?`}
          message="Devices can no longer start it. The program itself stays installed on this PC."
          confirmLabel="Remove"
          isOpen
          onOpenChange={(open) => !open && setDialog(null)}
          onConfirm={async () => {
            await api.removeApp(dialog.app.id)
            await apps.reload()
          }}
        />
      )}
    </div>
  )
}

function AppIcon({ app }: { app: App }) {
  if (app.hasImage) {
    return <img className="app-icon" src={`${api.appImageURL(app.id)}?v=${encodeURIComponent(app.id)}`} alt="" />
  }
  return (
    <span className="app-icon" aria-hidden>
      {app.kind === 'desktop' ? <Monitor size={18} /> : app.kind === 'steam' ? <Gamepad2 size={18} /> : app.name.charAt(0).toUpperCase()}
    </span>
  )
}

const blankApp: AppInput = {
  name: '',
  command: '',
  workingDirectory: '',
  prepCommands: [],
  detachedCommands: [],
  elevated: false,
  autoDetach: true,
  waitAll: true,
  exitTimeoutSeconds: 5,
  excludeGlobalPrepCommands: false,
}

function AppEditor({ app, onClose, onSaved }: { app: App | null; onClose: () => void; onSaved: () => Promise<void> }) {
  const [draft, setDraft] = useState<AppInput>(() => (app ? { ...blankApp, ...app } : blankApp))
  const [image, setImage] = useState<{ file: File; preview: string } | 'remove' | null>(null)
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const set = <K extends keyof AppInput>(key: K, value: AppInput[K]) => setDraft((current) => ({ ...current, [key]: value }))
  const valid = draft.name.trim().length > 0

  const save = async (close: () => void) => {
    setBusy(true)
    setError(undefined)
    try {
      const input = { ...draft, name: draft.name.trim() }
      const saved = app ? await api.updateApp(app.id, input) : await api.createApp(input)
      if (image === 'remove') await api.removeAppImage(saved.id)
      else if (image) await api.setAppImage(saved.id, image.file)
      await onSaved()
      close()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The app wasn’t saved.')
    } finally {
      setBusy(false)
    }
  }

  const imagePreview = image && image !== 'remove' ? image.preview : image !== 'remove' && app?.hasImage ? api.appImageURL(app.id) : null

  return (
    <Dialog title={app ? `Edit ${app.name}` : 'Add App'} isOpen onOpenChange={(open) => !open && onClose()} width="large">
      {(close) => (
        <Form
          className="dialog__form"
          onSubmit={(event) => {
            event.preventDefault()
            if (valid) void save(close)
          }}
        >
          {error && <InlineAlert tone="danger">{error}</InlineAlert>}
          <TextField label="Name" value={draft.name} onChange={(value) => set('name', value)} autoFocus isRequired maxLength={256} />
          <TextField
            label="Command"
            value={draft.command}
            onChange={(value) => set('command', value)}
            description="Leave empty to stream the desktop."
            monospace
          />
          <TextField
            label="Working directory"
            value={draft.workingDirectory}
            onChange={(value) => set('workingDirectory', value)}
            monospace
          />

          <div className="field">
            <span className="field__label">Image</span>
            <div className="image-field">
              {imagePreview ? <img className="image-field__preview" src={imagePreview} alt="" /> : <span className="image-field__empty">None</span>}
              <FileTrigger
                acceptedFileTypes={['image/png']}
                onSelect={(files) => {
                  const file = files?.[0]
                  if (file) setImage({ file, preview: URL.createObjectURL(file) })
                }}
              >
                <Button tone="secondary">Choose PNG…</Button>
              </FileTrigger>
              {imagePreview && (
                <Button tone="quiet" onPress={() => setImage('remove')}>
                  Remove Image
                </Button>
              )}
            </div>
          </div>

          <Disclosure className="disclosure">
            <Heading className="disclosure__heading">
              <AriaButton slot="trigger" className="disclosure__trigger">
                Advanced
              </AriaButton>
            </Heading>
            <DisclosurePanel className="disclosure__panel">
              <div className="stack">
                <PrepCommandsEditor value={draft.prepCommands} onChange={(value) => set('prepCommands', value)} />
                <CommandListEditor value={draft.detachedCommands} onChange={(value) => set('detachedCommands', value)} />
                <Switch isSelected={draft.elevated} onChange={(value) => set('elevated', value)}>
                  Run as administrator
                </Switch>
                <Switch isSelected={draft.waitAll} onChange={(value) => set('waitAll', value)}>
                  Keep streaming until every process it starts has exited
                </Switch>
                <Switch isSelected={draft.autoDetach} onChange={(value) => set('autoDetach', value)}>
                  Detach if the command exits immediately
                </Switch>
                <Switch
                  isSelected={draft.excludeGlobalPrepCommands}
                  onChange={(value) => set('excludeGlobalPrepCommands', value)}
                >
                  Skip the global prep commands
                </Switch>
                <TextField
                  label="Seconds to wait for the app to quit"
                  value={String(draft.exitTimeoutSeconds)}
                  onChange={(value) => set('exitTimeoutSeconds', Math.max(0, Number(value.replace(/\D/g, '')) || 0))}
                  inputMode="numeric"
                />
              </div>
            </DisclosurePanel>
          </Disclosure>

          <footer className="dialog__actions">
            <Button tone="secondary" onPress={close}>
              Cancel
            </Button>
            <Button tone="primary" type="submit" isDisabled={!valid} isPending={busy}>
              {app ? 'Save' : 'Add App'}
            </Button>
          </footer>
        </Form>
      )}
    </Dialog>
  )
}

function PrepCommandsEditor({ value, onChange }: { value: PrepCommand[]; onChange: (value: PrepCommand[]) => void }) {
  const update = (index: number, change: Partial<PrepCommand>) =>
    onChange(value.map((entry, position) => (position === index ? { ...entry, ...change } : entry)))
  return (
    <fieldset className="list-editor">
      <legend className="field__label">Prep commands</legend>
      {value.map((entry, index) => (
        <div key={index} className="list-editor__row">
          <TextField label="Before streaming" value={entry.do} onChange={(text) => update(index, { do: text })} monospace />
          <TextField label="After streaming" value={entry.undo} onChange={(text) => update(index, { undo: text })} monospace />
          <IconButton label="Remove prep command" onPress={() => onChange(value.filter((_, position) => position !== index))}>
            <Trash2 size={16} />
          </IconButton>
        </div>
      ))}
      <Button tone="quiet" onPress={() => onChange([...value, { do: '', undo: '', elevated: false }])}>
        <Plus size={14} aria-hidden /> Add Prep Command
      </Button>
    </fieldset>
  )
}

function CommandListEditor({ value, onChange }: { value: string[]; onChange: (value: string[]) => void }) {
  return (
    <fieldset className="list-editor">
      <legend className="field__label">Background commands</legend>
      {value.map((entry, index) => (
        <div key={index} className="list-editor__row">
          <TextField
            label={`Background command ${index + 1}`}
            value={entry}
            onChange={(text) => onChange(value.map((current, position) => (position === index ? text : current)))}
            monospace
          />
          <IconButton label="Remove background command" onPress={() => onChange(value.filter((_, position) => position !== index))}>
            <Trash2 size={16} />
          </IconButton>
        </div>
      ))}
      <Button tone="quiet" onPress={() => onChange([...value, ''])}>
        <Plus size={14} aria-hidden /> Add Background Command
      </Button>
    </fieldset>
  )
}
